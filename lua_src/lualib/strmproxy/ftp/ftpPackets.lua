require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local tableUtils=require "strmproxy.utils.tableUtils"
local orderTable=tableUtils.OrderedTable
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local unicode = require "strmproxy.utils.unicode"
local extends=tableUtils.extends

local bit = require "bit"
local resty_sha256 = require "resty.sha256"
local sub = string.sub
local tcp = ngx.socket.tcp
local strbyte = string.byte
local strchar = string.char
local strfind = string.find
local strupper = string.upper
local format = string.format
local strrep = string.rep
local strsub = string.sub
local null = ngx.null
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local sha1 = ngx.sha1_bin
local concat = table.concat
local setmetatable = setmetatable
local error = error
local tonumber = tonumber
local to_int = math.floor

local has_rsa, resty_rsa = pcall(require, "resty.rsa")

local COM_NORMAL = 0x01
local COM_USER   = 0x02
local COM_PASS   = 0x03
local COM_PASV   = 0x04
local COM_AUTH   = 0x05

local RES_NORMAL   = 0x11
local RES_LOGIN_OK = 0x12
local RES_LOGIN_FAIL  = 0x13
local RES_NEED_PASSWD = 0x14
local RES_PASSIVE  = 0x15
local RES_AUTH     = 0x16

local ftpCms = {
    "NOP",
    "RNTO",
    "RNFR",
    "XPWD",
    "MDTM",
    "REST",
    "APPE",
    "MKD",
    "RMD",
    "DELE",
    "ALLO",
    "STOR",
    "SIZE", 
    "CDUP", 
    "CWD", 
    "TYPE", 
    "SYST",
    "MFMT",
    "MODE",
    "XRMD",
    "ADAT",
    "PROT",
    "PBSZ",
    "MLSD",
    "LIST", 
    "XCWD", 
    "NOOP",
    "AUTH",
    "OPTS",
    "EPRT",
    "PASS",
    "QUIT",
    "PWD",
    "RETR",
    "USER",
    "NLST",
    "CLNT",
    "FEAT",
    "ABOR",
    "HELP",
    "XMKD",
    "MLST",
    "STRU",
    "PASV",
    "EPSV",
    "PORT",
    "STAT",
}

local CMD_USER = "USER"
local CMD_PASS = "PASS"
local CMD_AUTH = "AUTH"
local CMD_PASV = "PASV"

local REPL_LOGINOK = "230"
local REPL_LOGINFAIL = "530"
local REPL_PASSWD = "331"
local REPL_PASV = "227"
local REPL_AUTH = "234"

local _M={}

_M.Packet={
    desc="BasePacket",
    
    getResponseCode=function(allBytes)
        local args, err = string.split(allBytes, " ")
        if (err) then
            ngx.log(ngx.ERR, "Split Error ")
            return self
        end
        local response = args[1]
        local code = RES_NORMAL
        if (response == REPL_LOGINOK) then 
            code = RES_LOGIN_OK
        elseif (response == REPL_LOGINFAIL) then
            code = RES_LOGIN_FAIL
        elseif (response == REPL_PASSWD) then
            code = RES_NEED_PASSWD
        elseif (response == REPL_AUTH) then
            code = RES_AUTH
        elseif (response == REPL_PASV) then
            code = RES_PASSIVE
        else
            code = RES_NORMAL
        end
        return code
    end,

    getCommandCode=function(allBytes)
        local args, err = string.split(allBytes, " ")
        if (err) then
            ngx.log(ngx.ERR, "Split Error ")
            return self
        end
        local command = strupper(args[1])
        
        local code = COM_NORMAL
        if (command == CMD_USER) then 
            code = COM_USER
        elseif (command == CMD_PASS) then
            code = COM_PASS
        elseif (command == CMD_AUTH) then
            code = COM_AUTH
        elseif (command == CMD_PASV) then
            code = COM_PASV
        else
            code = COM_NORMAL
        end
        return code
    end,

    parse=function(self,allBytes,pos)
        local args, err = string.split(allBytes, " ")
        if (err) then
            ngx.log(ngx.ERR, "Split Error ")
            return self
        end
        local code = args[1]
        if (#args == 0) then
            code = allBytes
        end
        local e = strfind(code, "\r\n")
        if e then e = e - 1 end
        code = strsub(code, 1, e)  
        
        pos = #code + 1
        self.code = strupper(code)
        if (#allBytes > pos) then
            local e = strfind(allBytes, "\r\n")
            if e then e = e - 1 end
            local a = strsub(allBytes, pos, pos)
            while (strsub(allBytes, pos, pos) == " ") do
                pos = pos + 1
            end
            self.param = string.sub(allBytes, pos, e)
        else
            self.param = ""
        end

        self:parseLine(allBytes, pos)
        self.allBytes=allBytes
        return self
    end,

    parseLine= function(self, allBytes, pos) return self end,

    makePacket = function(self, code, message)
        return code .. " " .. message .. "\r\n"
    end,
   
    new=function(self,o) 
        local o=o or {}
        return orderTable.new(self,o)
    end
}

_M.Command={
    code=COM_NORMAL,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Command,_M.Packet)

_M.Login={
    code=COM_USER,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Login,_M.Packet)

_M.Passwd={
    code=COM_PASS,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Passwd,_M.Packet)

_M.Passive={
    code=COM_PASV,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Passive,_M.Packet)

_M.Auth={
    code=COM_AUTH,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Auth,_M.Packet)

_M.Response={
    code=RES_NORMAL,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.Response,_M.Packet)

_M.LoginOk={
    code=RES_LOGIN_OK,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.LoginOk,_M.Packet)

_M.LoginFail={
    code=RES_LOGIN_FAIL,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.LoginFail,_M.Packet)

_M.PasswdResponse={
    code=RES_NEED_PASSWD,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.PasswdResponse,_M.Packet)

_M.PassiveResponse={
    code=RES_PASSIVE,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.PassiveResponse,_M.Packet)

_M.AuthResponse={
    code=RES_AUTH,
    parseLine=function(self,allBytes,pos)
        return self
    end,
}
extends(_M.AuthResponse,_M.Packet)

return _M