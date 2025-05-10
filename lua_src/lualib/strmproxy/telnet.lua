require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local event=require "strmproxy.utils.event"
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local telnetPacket=require "strmproxy.telnet.telnetPackets"
local tableUtils=require "strmproxy.utils.tableUtils"
local _M = {}
_M._PROTOCAL ='telnet'


local  LOGIN_IDENTIFY_KEY = "login: "
local  PW_IDENTIFY_KEY = "password: "


function _M.new(self,options)	
    local o= setmetatable({},{__index=self})
	options=options or {}

    o.UserNameBeforeAuthEvent=event:newReturnEvent(o,"UserNameBeforeAuthEvent")
    o.PasswordBeforeAuthEvent=event:newReturnEvent(o,"PasswordBeforeAuthEvent")
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent")  

    o.ctx={}
    o.c2p_stage="INIT"
    o.cmd_stage="INIT"

    o.username=""
    o.password=""
    o.command=""
    o.response=""

    local telnetParser=require ("strmproxy.telnet.parser"):new()
    o.C2PParser=telnetParser.C2PParser
    o.C2PParser.events.Login:addHandler(o,_M.LoginHandler)
    o.C2PParser.events.Passwd:addHandler(o,_M.PasswdHandler)
    o.C2PParser.events.Command:addHandler(o,_M.CommandHandler)

    o.S2PParser=telnetParser.S2PParser
    o.S2PParser.events.LoginOk:addHandler(o,_M.LoginOkHandler)
    o.S2PParser.events.LoginFail:addHandler(o,_M.LoginFailHandler)
    o.S2PParser.events.Response:addHandler(o,_M.ResponseHandler)

    -- Added an option to choose parsing ---------------------------------------
    o.C2PParser.skip_parse=false
    o.S2PParser.skip_parse=false

    return o
end

function _M:LoginHandler(src,p)
  
end

function _M:PasswdHandler(src,p)

    
end

function _M:CommandHandler(src,p)

    if self.CommandEnteredEvent:hasHandler() then
        self.CommandEnteredEvent:trigger({}, self.ctx)
    end  
    
end

function _M:LoginOkHandler(src,p)

    if self.AuthSuccessEvent:hasHandler() then
        self.AuthSuccessEvent:trigger({}, self.ctx)
    end  
    
end

function _M:LoginFailHandler(src,p)

    if self.AuthFailEvent:hasHandler() then
        self.AuthFailEvent:trigger({}, self.ctx)
    end  
    
end

function _M:ResponseHandler(src,p)

    if self.CommandFinishedEvent:hasHandler() then
        self.CommandFinishedEvent:trigger({}, self.ctx)
    end  
    
end


----------------implement processor methods---------------------

function _M.processUpRequest(self)
    local allBytes,err=self.channel.c2pSock:receiveany(1024 * 10)
    if err then return nil,err end

    if self.c2p_stage == "LOGINUSER_START" and #allBytes == 3 and string.byte(allBytes, 1) == 0xFF and string.byte(allBytes, 2) == 0xFD and string.byte(allBytes, 3) == 0x01 then
        self.c2p_stage = "LOGINUSER"
        return allBytes
    end 

    if self.c2p_stage == "LOGINUSER" then
        if #allBytes == 2 and string.byte(allBytes, 1) == 0x0D and string.byte(allBytes, 2) == 0x0A then
            self.c2p_stage = "LOGINPW_START"
            self.username = self.UserNameBeforeAuthEvent:trigger(self.username, self.ctx)
            allBytes = self.username .. "\r\n"
        else
            self.username = self.username .. allBytes
            allBytes = ""
        end 
        return allBytes
    end

    if self.c2p_stage == "LOGINPW" then
        if #allBytes == 2 and string.byte(allBytes, 1) == 0x0D and string.byte(allBytes, 2) == 0x0A then
            self.c2p_stage = "LOGINEND"
            self.password = self.PasswordBeforeAuthEvent:trigger(self.password, self.ctx)
            allBytes = self.password .. "\r\n"
        else
            self.password = self.password .. allBytes    
            allBytes = ""
        end 
        return allBytes
    end

    if self.c2p_stage == "LOGINOK" then
        if #allBytes == 2 and string.byte(allBytes, 1) == 0x0D and string.byte(allBytes, 2) == 0x0A then
            self.cmd_stage = "CMDEND"
            -- log command
            self.command = self.CommandEnteredEvent:trigger(self.command, self.ctx)
            allBytes = self.command .. "\r\n"

        else
            local rspData = self.response
            if #rspData > 0 then
                -- log response
                self.CommandFinishedEvent:trigger(self.response, self.ctx)
            end

            self.cmd_stage = "INIT"
            self.command = self.command .. allBytes
            self.response = ""
            self.channel.c2pSock:send(allBytes)
            allBytes = ""
        end 
        return allBytes
    end


    local key = -1
    local p = self.C2PParser:parse(allBytes, nil, key)
    return allBytes
end

function _M.processDownRequest(self)
    local allBytes,err=self.channel.p2sSock:receiveany(1024 * 10)
    if err then return nil,err end

    if self.c2p_stage == "INIT" then
        local length = string.len(allBytes)
        -- Extract the last 7 characters
        if length > 6 then
            local last_seven = string.sub(allBytes, length - 6)
            last_seven = string.lower(last_seven)
            if last_seven == LOGIN_IDENTIFY_KEY then
                self.c2p_stage = "LOGINUSER_START"
            end    
        end    
        return allBytes
    end

    if self.c2p_stage == "LOGINPW_START" then

        allBytes = allBytes:gsub(self.username, " ")

        local length = string.len(allBytes)
        -- Extract the last 10 characters
        if length > 9 then
            local last_seven = string.sub(allBytes, length - 9)
            last_seven = string.lower(last_seven)
            if last_seven == PW_IDENTIFY_KEY then
                self.c2p_stage = "LOGINPW"
            end    
        end 

        if #allBytes > 3 and (string.byte(allBytes, #allBytes - 1) == 0x24 or string.byte(allBytes, #allBytes - 1) == 0x23) and string.byte(allBytes, #allBytes) == 0x20 then
            self.c2p_stage = "LOGINOK"
            self.AuthSuccessEvent:trigger({username = self.username, password=""}, self.ctx)
            self.CommandFinishedEvent:trigger(self.response, self.ctx)
            self.response = ""

        end  
        return allBytes
    end

    if self.c2p_stage == "LOGINEND" then
        local startIndex, endIndex = allBytes:find(" incorrect")
        if startIndex then 
            self.c2p_stage = "LOGINUSER"
            self.AuthFailEvent:trigger({username = self.username, password=self.password}, self.ctx)
            -- iniit 
            self.username = ""
            self.password = ""
            self.response = ""
            return allBytes
        end

        self.response = self.response .. allBytes
        if #allBytes > 3 and (string.byte(allBytes, #allBytes - 1) == 0x24 or string.byte(allBytes, #allBytes - 1) == 0x23) and string.byte(allBytes, #allBytes) == 0x20 then
            self.c2p_stage = "LOGINOK"
            self.AuthSuccessEvent:trigger({username = self.username, password=self.password}, self.ctx)
            self.CommandFinishedEvent:trigger(self.response, self.ctx)
            self.response = ""

        end    
        return allBytes
    end

    if self.c2p_stage == "LOGINOK" and self.cmd_stage == "CMDEND" then
        if #allBytes > #(self.command) and #(self.command) > 0 then
            local prixCmd = string.sub(allBytes, 1, #(self.command))
            if prixCmd == self.command then
                allBytes = string.sub(allBytes, #(self.command) + 1)
                self.command = ""
            end 
        end
        self.response = self.response .. allBytes
    end    

    local key = -1
    local p = self.S2PParser:parse(allBytes,nil, key)

    return allBytes
end


return _M