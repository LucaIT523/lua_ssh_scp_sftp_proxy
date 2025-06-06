--tds protocol parser and encoder
require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local ok,cjson=pcall(require,"cjson")
local tableUtils=require "strmproxy.utils.tableUtils"
local orderTable=tableUtils.OrderedTable
local extends=tableUtils.extends
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local unicode = require "strmproxy.utils.unicode"
local tdsToken = require "strmproxy.tds.token"
local TokenType=tdsToken.TokenType
local sqlVersion = require "strmproxy.tds.version"
local TokenType=tdsToken.TokenType
local _M={}

_M.Packet={
    desc="BasePacket",
    parseHeader=function(self,headerBytes,cursor) 
        self.code,self.status,self.dataLength,self.channel,self.packetID,self.window,cursor=string.unpack(">BBI2I2BB",headerBytes,cursor) 
        return cursor
    end,
    
    packHeader=function(self,payloadLen)
        return string.pack(">BBI2I2BB",self.code,self.status,payloadLen+8,self.channel,self.packetID,self.window)
    end,
    
    pack=function(self) 
        local payloadBytes=self:packPayload()
        local headerBytes=self:packHeader(#payloadBytes)
        self.allBytes=headerBytes..payloadBytes
        logger.dbgWithTitle("packing",self.allBytes:hex32F())
        return self.allBytes
    end,
    
    --skipHeaderCursor indicates that header was parsed, just skip the header part and directly parse payload part
    parse=function(self,allBytes,pos)
        pos=self:parseHeader(allBytes)
        self:parsePayload(allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
    
    parsePayload=function(allBytes,pos) end,
    
    new=function(self,o) 
        local o=o or {}
        return orderTable.new(self,o)
    end
}

_M.SQLBatch={
    code=0x01,
    parsePayload=function(self,bytes,cursor)
        local headerLength=string.byte(bytes,cursor)
        self.sql=unicode.utf16to8(bytes:sub(cursor+headerLength))
    end,
    
    packPayload=function(self)
        error("not implemented")
    end   
}
extends(_M.SQLBatch,_M.Packet)

local function calcPass(password,enc)
    local mask = enc and 0x5a or 0xa5
    return password:gsub(".", function(i)
        local c = bit.bxor(string.byte( i ), mask)
        local m1= bit.band(bit.rshift( c,4 ) , 0x0F)
        local m2= bit.band(bit.lshift( c ,4 ) , 0xF0)
        return string.pack("<B", bit.bor(m1 , m2) )
    end)
end

_M.Login7={
    code=0x10,
    desc="Login7",  
    parsePayload=function(self,bytes,cursor)
        local pos = cursor
        self.loginPacketLength,pos                  = string.unpack("<I4",bytes,pos)
        self.TDSVersion,pos                         = string.unpack(">c4",bytes,pos)
        self.PacketSize,pos                         = string.unpack("<I4",bytes,pos)
        self.ClientProgVer,pos                      = string.unpack(">c4",bytes,pos)
        self.ClientPID ,pos                         = string.unpack("<I4",bytes,pos)
        self.ConnectionID,pos                       = string.unpack("<I4",bytes,pos)
        self.OptionFlags1,pos                       = string.unpack("B",bytes,pos)
        self.OptionFlags2,pos                       = string.unpack("B",bytes,pos)
        self.OptionFlags3,pos                       = string.unpack("B",bytes,pos)
        self.TypeFlag,pos                           = string.unpack("B",bytes,pos)
        self.ClientTimeZone,pos                     = string.unpack("<I4",bytes,pos)
        self.ClientLCID,pos                         = string.unpack("<I4",bytes,pos)
        local clientNameOffset,clientNameLength,pos = string.unpack("<I2I2",bytes,pos)
        local nameOffset,nameLength,pos             = string.unpack("<I2I2",bytes,pos)
        local passOffset,passLength,pos             = string.unpack("<I2I2",bytes,pos)
        local appNameOffset,appNameLength,pos       = string.unpack("<I2I2",bytes,pos)
        local serverNameOffset,serverNameLength,pos = string.unpack("<I2I2",bytes,pos)
        local unUsedOffset,unUsedLength,pos         = string.unpack("<I2I2",bytes,pos)
        local cltIntNameOffset,cltIntNameLength,pos = string.unpack("<I2I2",bytes,pos)
        local langOffset,langLength,pos             = string.unpack("<I2I2",bytes,pos)
        local databaseOffset,databaseLength,pos     = string.unpack("<I2I2",bytes,pos)
        --6 bytes MAC
        self.clientId,pos  = string.unpack("<c6",bytes,pos)
        --local ibSSPI,cbSSPI,ibAtchDbFile,cchAtchDbFile,ibChpwd,cchChapwd,cbSSPILong=string.unpack("<I2I2I2I2I2I2I4",bytes,pos)
        self.iDontCare     = string.unpack("c16",bytes,pos)
        self.clientName    = unicode.utf16to8(string.unpack("c"..clientNameLength*2,bytes,cursor+clientNameOffset))
        self.username      = unicode.utf16to8(string.unpack("c"..nameLength*2,bytes,cursor+nameOffset))
        self.password      = unicode.utf16to8(calcPass(string.unpack("c"..passLength*2,bytes,cursor+passOffset),false))
        self.appName       = unicode.utf16to8(string.unpack("c"..appNameLength*2,bytes,cursor+appNameOffset))
        self.serverName    = unicode.utf16to8(string.unpack("c"..serverNameLength*2,bytes,cursor+serverNameOffset))
        self.unUsed        = string.unpack("c"..unUsedLength,bytes,cursor+unUsedOffset)
        self.libName       = unicode.utf16to8(string.unpack("c"..cltIntNameLength*2,bytes,cursor+cltIntNameOffset))
        self.locale        = unicode.utf16to8(string.unpack("c"..langLength*2,bytes,cursor+langOffset))
        local database,pos = string.unpack("c"..databaseLength*2,bytes,cursor+databaseOffset)
        self.database      = unicode.utf16to8(database)
        self.remain        = bytes:sub(pos)
    end,
    
    packPayload=function(self)
        --pointer to real data
        local dataOffset = 94
        self.loginPacketLength = dataOffset + 2 * ( self.clientName:len() +self.username:len()+ self.password:len()+self.appName:len() + self.serverName:len() + self.libName:len() + self.database:len() )+self.unUsed:len()+self.remain:len()
        local data={
            string.pack("<I4",self.loginPacketLength),
            string.pack(">c4",self.TDSVersion),
            string.pack("<I4",self.PacketSize),
            string.pack(">c4",self.ClientProgVer),
            string.pack("<I4",self.ClientPID ),
            string.pack("<I4",self.ConnectionID),
            string.pack("<B",self.OptionFlags1),
            string.pack("<B",self.OptionFlags2),
            string.pack("<B",self.TypeFlag),
            string.pack("<B",self.OptionFlags3),
            string.pack("<I4",self.ClientTimeZone),
            string.pack("<I4",self.ClientLCID),
            string.pack("<I2I2",dataOffset,self.clientName:len())
        }
        dataOffset=dataOffset+2*self.clientName:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.username:len())
        dataOffset=dataOffset+2*self.username:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.password:len())
        dataOffset=dataOffset+2*self.password:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.appName:len())
        dataOffset=dataOffset+2*self.appName:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.serverName:len())
        dataOffset=dataOffset+2*self.serverName:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.unUsed:len())
        dataOffset=dataOffset+self.unUsed:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.libName:len())
        dataOffset=dataOffset+2*self.libName:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.locale:len())
        dataOffset=dataOffset+2*self.locale:len()
        data[#data+1]=string.pack("<I2I2",dataOffset,self.database:len())
        dataOffset=dataOffset+2*self.database:len()
        --MAC
        data[#data+1]=string.pack("<c6",self.clientId)
        --string.pack("<I2I2I2I2I2I2I4",ibSSPI,cbSSPI,ibAtchDbFile,cchAtchDbFile,ibChpwd,cchChapwd,cbSSPILong)
        data[#data+1]=string.pack("c16",self.iDontCare)
        data[#data+1]=unicode.utf8to16(self.clientName)
        data[#data+1]=unicode.utf8to16(self.username)
        data[#data+1]=calcPass(unicode.utf8to16(self.password),true)
        data[#data+1]=unicode.utf8to16(self.appName)
        data[#data+1]=unicode.utf8to16(self.serverName)
        data[#data+1]=self.unUsed
        data[#data+1]=unicode.utf8to16(self.libName)
        data[#data+1]=unicode.utf8to16(self.database)
        data[#data+1]=self.remain
        return table.concat(data)
    end
}
extends(_M.Login7,_M.Packet)

_M.Prelogin={
    code=0x12,
    desc="PreLogin",
    -- if arg[i] then
    OPTION_TYPE = {
        Version    = 0x00,
        Encryption = 0x01,
        InstOpt    = 0x02,
        ThreadId   = 0x03,
        MARS       = 0x04,
        TraceId    = 0x05,
        Terminator = 0xFF,
    },
    parsePayload=function(self,bytes,cursor)
        local status, pos = false, cursor
        local preLoginPacket = _M.Prelogin:new()
        local i=0
        self.options={}

        while true do
            local optionType, optionPos, optionLength, optionData, expectedOptionLength, _
            if pos > #bytes then
                logger.err("MSSQL: Could not extract optionType." )
                return false, "Invalid pre-login response"
            end
            optionType, pos = string.unpack("B", bytes, pos)
            if optionType == _M.Prelogin.OPTION_TYPE.Terminator then
                status = true
                break
            end
            if pos + 4 > #bytes + 1 then
                logger.err("MSSQL: Could not unpack optionPos and optionLength." )
                return false, "Invalid pre-login response"
            end
            optionPos, optionLength, pos = string.unpack(">I2I2", bytes, pos)
            optionData = bytes:sub( cursor + optionPos, cursor + optionPos + optionLength - 1 )
            if #optionData ~= optionLength then
                logger.err("MSSQL: Could not read sufficient bytes from version data." )
                return false, "Invalid pre-login response"
            end
            if optionType == _M.Prelogin.OPTION_TYPE.Version then
                local major, minor, build, subBuild = string.unpack(">BBI2I2", optionData)
                local version = sqlVersion:new()
                version:SetVersion( major, minor, build, subBuild, "SSNetLib" )
                self.options["Version"] = version
                --https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868
            elseif optionType == _M.Prelogin.OPTION_TYPE.Encryption then
                self.options["Encryption"] = string.unpack("B", optionData)
            elseif optionType == _M.Prelogin.OPTION_TYPE.InstOpt then
                self.options["InstOpt"] = string.unpack("z", optionData)
            elseif optionType == _M.Prelogin.OPTION_TYPE.ThreadId then
                self.options["ThreadId"] = optionLength>0 and string.unpack(">I" .. optionLength, optionData) or ""
            elseif optionType == _M.Prelogin.OPTION_TYPE.MARS then
                self.options["MARS"] = string.unpack("B", optionData)
            elseif optionType==_M.Prelogin.OPTION_TYPE.TraceId then
                self.options["TraceId"] = optionData
            else
                self.options["T"..tostring(optionType)]=string.unpack("c"..optionLength, optionData)
                -- Added for Login MSSQL Server
                local key = "T" .. tostring(optionType)
                if not _M.Prelogin.OPTION_TYPE[key] then
                    _M.Prelogin.OPTION_TYPE[key] = optionType
                    -- logger.dbg("> Added new OPTION_TYPE: " .. key .. " with value " .. tostring(optionType))
                end
            end
            i = i + 1
        end
        self.optionSize = i
        self.status = status and 1 or 0
    end,
    
    packPayload=function(self)
        local options = {}
        local optionLength, optionType = 0, 0
        local offset = self.optionSize*5+1
        local data
        local i = 1

        local getOptionList = function(tbl)
            local optList = {}
            for k in pairs(_M.Prelogin.OPTION_TYPE) do
                table.insert(optList, k)
            end
            local compareByValue = function(k1, k2)
                return tbl[k1] < tbl[k2]
            end
            table.sort(optList, compareByValue)
            return optList
        end
        local preLogOpts = getOptionList(_M.Prelogin.OPTION_TYPE)

        -- logger.dbg("\r\n>self.options: " .. tableUtils.printTableF(self.options))
        -- logger.dbg("\r\n>_M.Prelogin.OPTION_TYPE:" .. tableUtils.printTableF(_M.Prelogin.OPTION_TYPE))
        -- logger.dbg("\r\n> preLogOpts: ("..#preLogOpts..") " .. tableUtils.printTableF(preLogOpts))
        
        for idx=1, #preLogOpts do
            local k = preLogOpts[idx]
            local v = self.options[k]
            -- logger.dbg("> k: ", k, " , v: ", tostring(v))
            if not v then goto continue end

            optionType = _M.Prelogin.OPTION_TYPE[k]
            -- logger.dbg("> optionType: ", tostring(optionType))
            if optionType == _M.Prelogin.OPTION_TYPE.Terminator then
                break
            end
            if optionType == _M.Prelogin.OPTION_TYPE.Version then
                data = string.pack(">BBI2I2", v.major, v.minor, v.build, v.subBuild )
            elseif optionType == _M.Prelogin.OPTION_TYPE.Encryption then
                data = string.pack("B", v)
            elseif optionType == _M.Prelogin.OPTION_TYPE.InstOpt then
                data = string.pack("z", v)
            elseif optionType == _M.Prelogin.OPTION_TYPE.ThreadId then
                data = (v=="" and "" or string.pack(">I4", v))
            elseif optionType == _M.Prelogin.OPTION_TYPE.MARS then
                data = string.pack("B", v)
            elseif optionType == _M.Prelogin.OPTION_TYPE.TraceId then
                data = v
            else
                -- data=("c"..#data):pack(v)
                -- Added for Login MSSQL Server
                if (k == "T"..optionType) and (v ~= nil) then
                    -- logger.dbg("> v: (", type(v), ") ", (v and tostring(v) or "nil"))
                    -- logger.dbg("> _M.Prelogin.OPTION_TYPE.", k, ": ", string.format("0x%0x",_M.Prelogin.OPTION_TYPE[k]))
                    data = string.pack("c"..(#v), v)
                    -- remove k
                    _M.Prelogin.OPTION_TYPE[k] = nil
                    -- logger.dbg("> Removed new OPTION_TYPE: " .. k .. " with value " .. tostring(optionType))
                else
                    data=string.pack("c"..(data and #data or #v), v)
                end
                
            end
            optionLength = #data
            options[i] = string.pack(">BI2I2", optionType, offset, optionLength)
            options[self.optionSize+1+i] = data
            offset = offset + optionLength -- next option start point
            i = i + 1

            ::continue::
        end
        options[self.optionSize+1] = string.pack("B", _M.Prelogin.OPTION_TYPE.Terminator)
        return table.concat(options)
    end,
}
extends(_M.Prelogin,_M.Packet)

--this packet extends PreloginPacket
_M.PreloginResponse={
    code=0x04,
    desc="PreLoginResponse",
    preCode=_M.Prelogin.code
}
extends(_M.PreloginResponse,_M.Prelogin)

_M.LoginResponse={
    code=0x04,
    preCode=_M.Login7.code,
    desc="LoginResponse",
    parsePayload=function(self,bytes,cursor)   
        local pos=cursor
        while pos<=#bytes do
            local tokenType=bytes:byte(pos)
            local token
            token,pos=tdsToken.doParse(tokenType,bytes,pos)
            if token.type==TokenType.LoginAck.code then
                self.success=true
                self.TDSVersion=token.TDSVersion
                self.progName=token.progName
                self.interface=token.interface
                self.serverVersion=token.serverVersion
            end
            if token.type==TokenType.Error.code then
                self.errNo=token.number
                self.message=token.message
            end
        end
    end
}
extends(_M.LoginResponse,_M.Packet)

_M.SQLResponse={
    code=0x04,
    preCode=_M.SQLBatch.code,
    desc="SQLResponse",
    new=function(self,param) 
        local o=param or {}
        o.tokens={}
        return setmetatable(o, {__index=self})
    end,
    parsePayload=function(self,bytes,cursor)
        local pos=cursor
        local tokenType=bytes:byte(pos)
        while tokenType ~= TokenType.Done.code and tokenType ~= TokenType.DoneProc.code and tokenType ~= TokenType.DoneInProc.code do
            local token,err
            if tokenType==TokenType.Row.code or tokenType==TokenType.NBCRow.code  then
                token=tdsToken.RowToken:new()			
                pos,err=token:parse(bytes,pos,self.columnToken.colList)
                
            else
                token,pos,err=tdsToken.doParse(tokenType,bytes,pos)
                if tokenType==TokenType.ColMetaData.code then
                    self.columnToken=token
                elseif tokenType==TokenType.Error.code then
                    self.errToken=token
                end
            end
            
            if err then logger.err("err happend when parsing sqlresponse token ",err) break end
            tokenType=bytes:byte(pos)
            self.tokens[#(self.tokens)+1]=token
        end
    end,
    packPayload=function(self,bytes,cursor)
        local buf={}
        for i,v in self.tokens do
            buf[#buf+1]=v.pack()
        end
        return table.concat(buf)
    end,
    tostring=function(self)
        local res={}
        for i=1,#self.tokens do
            res[i]=self.tokens[i]:tostring()
        end
        return table.concat(res,"\r\n")
    end
}
extends(_M.SQLResponse,_M.Packet)


_M.RemoteProcedureCall={
    code=0x03,
    parsePayload=function(self,bytes,cursor)
        local len=string.byte(bytes,cursor)
        cursor = cursor + len
        len = string.byte(bytes:sub(cursor, cursor + 2)) * 2
        cursor = cursor + 2
        local procedure = bytes:sub(cursor, cursor + len - 1)
        cursor = cursor + len + 2
        len = string.byte(bytes:sub(cursor, cursor + 1)) * 2
        cursor = cursor + 1 
        local paramName = bytes:sub(cursor, cursor + len - 1)
        cursor = cursor + len + 11 
        local paramValue = bytes:sub(cursor)
        self.rpc = {
            procedure = unicode.utf16to8(procedure),
            paramName = unicode.utf16to8(paramName),
            paramValue = unicode.utf16to8(paramValue)
        }
    end,
    
    packPayload=function(self)
        error("not implemented")
    end   
}
extends(_M.RemoteProcedureCall,_M.Packet)

function _M.packErrorResponse(message,errNo)
    local errToken=tdsToken.ErrorToken:new({
    --about error number check https://docs.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver15
        number=errNo or 15343, state=1, class=16,message=message, serverName="GATEWAY", procName="", lineNo=1
    })
    local buf=errToken:pack()..string.char( 0xfd,0x02,0x00,0xfd,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    local p=_M.Packet:new({code=4,status=1,channel=53,packetID=1,window=0})
    return p:packHeader(#buf)..buf  
end



----------------------test starts from here------------------
_M.unitTest={}
function _M.unitTest.headerTest()
    local tds7PreloginBytes=string.fromhex("120100580000010000001f000601002500010200260001030027000404002b000105002c0024ff0b001976000000006016000000ec2f0228b3392c4cae4c21d02f494f60d342ed1afdee6848b07fb65cf4a095be02000000")
    local packet=_M.Packet:new()
    packet:parseHeader(tds7PreloginBytes)
    local dataLength=packet.dataLength
    assert(packet.dataLength==88,packet.dataLength)
    assert(packet.status==1,packet.status)
    assert(packet.code==18,packet.code)
    assert(packet.channel==0,packet,channel)
    assert(packet.window==0,packet.window)
end

function _M.unitTest.PreloginPacketTest()
    local tds7PreloginBytes=string.fromhex("120100580000010000001f000601002500010200260001030027000404002b000105002c0024ff0b001976000000006016000000ec2f0228b3392c4cae4c21d02f494f60d342ed1afdee6848b07fb65cf4a095be02000000")
    local packet=require("strmproxy.tds.parser"):new().C2PParser:parse(tds7PreloginBytes)
    assert(packet.options["Encryption"]==0,packet.options["Encryption"])
    assert(packet.options["Version"].versionNumber=="11.00.6518.00",packet.options["Version"].versionNumber)
    assert(packet.options["Version"].brandedVersion=="2012",packet.options["Version"].brandedVersion)
    assert(packet.options["InstOpt"]=="",packet.options["InstOpt"])
    assert(packet.options["ThreadId"]==1612054528,packet.options["ThreadId"])
    assert(packet.options["MARS"]==0,packet.options["MARS"])
    assert(packet.options["TraceId"]==string.fromhex("ec2f0228b3392c4cae4c21d02f494f60d342ed1afdee6848b07fb65cf4a095be02000000"),packet.options["TraceId"]) 
    packet.options.Encryption=2 
    packet:pack()
    tds7PreloginBytes=packet.allBytes
    local packet=require("strmproxy.tds.parser"):new().C2PParser:parse(tds7PreloginBytes)
    assert(packet.options["Encryption"]==2,packet.options["Encryption"])
    assert(packet.options["Version"].versionNumber=="11.00.6518.00",packet.options["Version"].versionNumber)
    assert(packet.options["Version"].brandedVersion=="2012",packet.options["Version"].brandedVersion)
    assert(packet.options["InstOpt"]=="",packet.options["InstOpt"])
    assert(packet.options["ThreadId"]==1612054528,packet.options["ThreadId"])
    assert(packet.options["MARS"]==0,packet.options["MARS"])
    assert(packet.options["TraceId"]==string.fromhex("ec2f0228b3392c4cae4c21d02f494f60d342ed1afdee6848b07fb65cf4a095be02000000"),packet.options["TraceId"]) 

end

function _M.unitTest.PreloginResponseTest()
    local preloginRespBytes=string.fromhex("040100300000010000001f000601002500010200260001030027000004002700010500280000ff0b000c380000020000")
    local packet=require("strmproxy.tds.parser"):new().S2PParser:parse(preloginRespBytes,nil,_M.Prelogin.code)
    assert(packet.options["Encryption"]==2,packet.options["Encryption"])
    assert(packet.options["Version"].versionNumber=="11.00.3128.00",packet.options["Version"].versionNumber)
    assert(packet.options["Version"].brandedVersion=="2012",packet.options["Version"].brandedVersion)
    assert(packet.options["InstOpt"]=="",packet.options["InstOpt"])
    assert(packet.options["ThreadId"]=="",packet.options["ThreadId"])
    assert(packet.options["MARS"]==0,packet.options["MARS"])
    assert(packet.options["TraceId"]=="",packet.options["TraceId"]) 
    packet.options.Encryption=0
    packet:pack()
    preloginRespBytes=packet.allBytes
    local packet=require("strmproxy.tds.parser"):new().S2PParser:parse(preloginRespBytes,nil,_M.Prelogin.code)
    assert(packet.options["Encryption"]==0,packet.options["Encryption"])
    assert(packet.options["Version"].versionNumber=="11.00.3128.00",packet.options["Version"].versionNumber)
    assert(packet.options["Version"].brandedVersion=="2012",packet.options["Version"].brandedVersion)
    assert(packet.options["InstOpt"]=="",packet.options["InstOpt"])
    assert(packet.options["ThreadId"]=="",packet.options["ThreadId"])
    assert(packet.options["MARS"]==0,packet.options["MARS"])
    assert(packet.options["TraceId"]=="",packet.options["TraceId"]:hex()) 
end

function _M.unitTest.SQLBatchTest()
    local sqlbatchBytes=string.fromhex("0101004200000100160000001200000002000000000000000000010000005300450054002000440041005400450046004f0052004d0041005400200079006d006400")
    local packet=require("strmproxy.tds.parser"):new().C2PParser:parse(sqlbatchBytes)
    print(packet.sql)
    assert(packet.sql=="SET DATEFORMAT ymd",packet.sql:hexF())
end

function _M.unitTest.calcPassTest()
    local pass="aA123.."
    print(unicode.utf8to16(pass):hex())
    local encodePass=calcPass(unicode.utf8to16(pass),true)
    assert(encodePass==string.fromhex(" B3 A5 B1 A5 B6 A5 86 A5 96 A5 47 A5 47 A5"))
    assert(pass==unicode.utf16to8(calcPass(encodePass)),false)
end

function _M.unitTest.Login7Test()
    local login7bytes=string.fromhex("100100e000000100d80000000400007400000000000000070059000000000000e003001020feffff040800005e000f007c000200800007008e0007009c000900ae000400b2000400ba000000ba0006009aa81b19eb3c00000000c600000000000000000000004400450053004b0054004f0050002d0050004e004f00300036004c00430073006100b1a5b3a5b6a586a596a547a547a54e006100760069006300610074003100320037002e0030002e0030002e003100c60000004f004400420043006d00610073007400650072000901000000010a01000000010100000000ff")
    local packet=require("strmproxy.tds.parser"):new().C2PParser:parse(login7bytes)
    assert(packet.username=="sa",packet.username)
    assert(packet.clientName=="DESKTOP-PNO06LC",packet.clientName)
    assert(packet.appName=="Navicat",packet.appName)
    assert(packet.serverName=="127.0.0.1",packet.serverName)
    assert(packet.libName=="ODBC",packet.libName)
    assert(packet.password=="Aa123..",packet.password)
    assert(packet.database=="master",packet.database)
    length=packet.loginPacketLength
    packet.username="sb"
    packet.password="Aa123.."
    packet:pack()
    print(packet.allBytes:compare16F(login7bytes))
    local login7bytes=packet.allBytes
    local packet=require("strmproxy.tds.parser"):new().C2PParser:parse(login7bytes)
    assert(packet.loginPacketLength==length,packet.loginPacketLength.." "..length)
    assert(packet.username=="sb",packet.username)
    assert(packet.clientName=="DESKTOP-PNO06LC",packet.clientName)
    assert(packet.appName=="Navicat",packet.appName)
    assert(packet.serverName=="127.0.0.1",packet.serverName)
    assert(packet.libName=="ODBC",packet.libName)
    assert(packet.password=="Aa123..",packet.password)
    assert(packet.database=="master",packet.database)
end

function _M.unitTest.LoginResponseTest()
    local bytes=string.fromhex("0401013d00340100e31b0001066d0061007300740065007200066d0061007300740065007200ab54004516000002001500f25d065c70656e63935e0a4e0b4e8765f46639653a4e200027006d0061007300740065007200270002300e4a004100590058005f00520045004d004f00540045004100500050000001000000e3080007050408d0000000e30b000204807b534f2d4e876500ab48004716000001000f00f25d065ced8b008abe8b6e7ff46639653a4e2000807b534f2d4e876502300e4a004100590058005f00520045004d004f00540045004100500050000001000000ad36000174000004164d006900630072006f0073006f00660074002000530051004c002000530065007200760065007200000000000b000c38e3130004043400300039003600043400300039003600fd000000000000000000000000")
    local packet=require("strmproxy.tds.parser"):new().S2PParser:parse(bytes,nil,_M.Login7.code)
    assert(packet.success)
end

function _M.unitTest.SQLResponseTest()
    local bytes=string.fromhex("040100d90035010081020000000000210062491f00000c500072006f0064007500630074004c006500760065006c0000000000210062491f000007450064006900740069006f006e00d10f000000e7070408d0000000015300500031006b000000e7070408d00000000145006e00740065007200700072006900730065002000450064006900740069006f006e003a00200043006f00720065002d006200610073006500640020004c006900630065006e00730069006e00670020002800360034002d006200690074002900fd1000c1000100000000000000")

    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    print (packet:tostring():ascii())
    
    local bytes=string.fromhex("040100cf003601008106000000000008007f0269006400000000000900a7ff000408d00000046e0061006d0065000000000008003803610067006500000000000900680106670065006e00640065007200000000000900e7ffff0408d000000469006e0066006f000000000009002a00046400610074006500d21001000000000000000100610100000001010699df0062410bd102000000000000000100620000000001000c000000000000000c0000006800610068006100680061000000000000fd1000c1000200000000000000")
    
    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    print (packet:tostring():ascii())
    --[[
    a1      int             0       0     0    -1   0                               0   0   0   0   0   sys    
    a2      int             0       0    -1     0   0                               0   0   0   0   0   sys    
    a3      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a4      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a5      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a6      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a7      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a8      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a9      varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a10     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a11     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a12     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a13     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS_KS_WS     0   0   0   0   0   sys    
    a14     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a15     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a16     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a17     varchar         255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a18     bigint          0       0    -1     0   0                               0   0   0   0   0   sys    
    a19     binary          255     0    -1     0   0                               0   0   0   0   0   sys    
    a20     bit             0       0    -1     0   0                               0   0   0   0   0   sys    
    a21     char            8       0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a22     date            0       0    -1     0   0                               0   0   0   0   0   sys    
    a23     datetime        0       0    -1     0   0                               0   0   0   0   0   sys    
    a24     datetime2       7       0    -1     0   0                               0   0   0   0   0   sys    
    a25     datetimeoffset  7       0    -1     0   0                               0   0   0   0   0   sys    
    a26     decimal         18      0    -1     0   0                               0   0   0   0   0   sys    
    a27     float           53      0    -1     0   0                               0   0   0   0   0   sys    
    a28     money           0       0    -1     0   0                               0   0   0   0   0   sys    
    a29     nchar           8       0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    a30     numeric         18      0    -1     0   0                               0   0   0   0   0   sys    
    a31     nvarchar        255     0    -1     0   0   Chinese_PRC_CI_AS           0   0   0   0   0   sys    
    ]]
    local bytes=string.fromhex("0401047700340100811f0000000000080038026100310000000000090026040261003200000000000900a7ff000408d000000261003300000000000900a7ff000408d000000261003400000000000900a7ff000408d000000261003500000000000900a7ff000408d000000261003600000000000900a7ff000408d000000261003700000000000900a7ff000408d000000261003800000000000900a7ff000408d000000261003900000000000900a7ff000408d0000003610031003000000000000900a7ff000408d0000003610031003100000000000900a7ff000408d0000003610031003200000000000900a7ff00040810000003610031003300000000000900a7ff000408d0000003610031003400000000000900a7ff000408d0000003610031003500000000000900a7ff000408d0000003610031003600000000000900a7ff000408d0000003610031003700000000000900260803610031003800000000000900adff0003610031003900000000000900680103610032003000000000000900af08000408d000000361003200310000000000090028036100320032000000000009006f08036100320033000000000009002a07036100320034000000000009002b07036100320035000000000009006a111200036100320036000000000009006d08036100320037000000000009006e0803610032003800000000000900ef10000408d00000036100320039000000000009006c11120003610033003000000000000900e7fe010408d0000003610033003100d2fcfffe4f20000000040a1a00000300613137100061006100205f094e62006200200020000501837d0000d2f8fd0720210000000401000000070079616e6778696e020032330100080079616e6778696e200363410b0808ac0000f850e30008007230f8785c410b0a00854a43795d410b0000050115cd5b0708ec51b81e85ebf13f080000000020120a001000610061006100200020002000200020000c0061007300386e0f6264006100d2b8af7d5f22000000041600000008007a68616e676e616e0100310100320200323208120000000000000008808bc11a7763410b050101000000d27cff8760230000000463c554000200736101000800d1eef6ce202020200357410b08fcab0000a855e3000a000cde467957410b00000501d2040000080000000000d0844008000000006c49341b100062006200620020002000200020002000d2bed57e1f2400000002003233020032330300613132010073030061313708007cbc1d7757410b050116000000040053626b62d2fcdee75f25000000046f000000040064617364020064730101080020202020202020200501d5000000d24afee71f6f00000001003101003102006666020061380200613901010800b0a4b4f2202020200501150000000c00610061006100610078007800d2fefda77fde00000003006131300101080056d0cdb3d476202008fcab0000585ae300d2fc6be57f71f25b2e049a0200000300613131030061313302003636081200000000000000010108002020202020202020fd1000c1000900000000000000")
    
    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    assert(#(packet.tokens)==10,#(packet.tokens))
    print("3,27:"..packet.tokens[3].rowData[27])
    print (packet:tostring():ascii())
    --ssvar test
    local bytes=string.fromhex("040100d90034010081020000000000210062491f00000c500072006f0064007500630074004c006500760065006c0000000000210062491f000007450064006900740069006f006e00d10f000000e7070408d0000000015300500031006b000000e7070408d00000000145006e00740065007200700072006900730065002000450064006900740069006f006e003a00200043006f00720065002d006200610073006500640020004c006900630065006e00730069006e00670020002800360034002d006200690074002900fd1000c1000100000000000000")
    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    assert(#(packet.tokens)==2,#(packet.tokens))
    print (packet:tostring():ascii())
    
end

function _M.unitTest.SQLResponseErrorTest()
    local bytes=string.fromhex("0401006a00350100aa5200d000000001101400f95b618c0d5420002700670075006500730074002e00750073006500720027002000e065486502300e4a004100590058005f00520045004d004f00540045004100500050000001000000fd0200fd000000000000000000")	
    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    assert(packet.errToken.number==208,packet.errToken.number)
    assert(packet.errToken.state==1,packet.errToken.state)
    assert(packet.errToken.class==16,packet.errToken.class)
    assert(packet.errToken.serverName=="JAYX_REMOTEAPP",packet.errToken.serverName)
    assert(packet.errToken.procName=="",packet.errToken.procName)
    assert(packet.errToken.lineNo==1,packet.errToken.LineNo)
    local bytes=_M.packErrorResponse("hahaha")
    local packet=require("strmproxy.tds.parser"):new(true).S2PParser:parse(bytes,nil,_M.SQLBatch.code)
    assert(packet.errToken.number==15343,packet.errToken.number)
    assert(packet.errToken.state==1,packet.errToken.state)
    assert(packet.errToken.class==16,packet.errToken.class)
    assert(packet.errToken.message=="hahaha",packet.errToken.message)
    assert(packet.errToken.serverName=="GATEWAY",packet.errToken.serverName)
    assert(packet.errToken.procName=="",packet.errToken.procName)
    assert(packet.errToken.lineNo==1,packet.errToken.LineNo)
end


function _M.test()
    for k,v in pairs(_M.unitTest) do
        print("------------running  "..k)
        v()
        print("------------"..k.."  finished")
    end
end

return _M