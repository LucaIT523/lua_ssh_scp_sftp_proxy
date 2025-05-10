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

local _M={}

_M.Packet={
    desc="BasePacket",

    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,

    new=function(self,o) 
        local o=o or {}
        return orderTable.new(self,o)
    end
}


_M.Login={
    code=0x01,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.Login,_M.Packet)

_M.Passwd={
    code=0x02,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.Passwd,_M.Packet)

_M.Command={
    code=0x03,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.Command,_M.Packet)


_M.Response={
    code=0x04,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.Response,_M.Packet)

_M.LoginOk={
    code=0x05,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.LoginOk,_M.Packet)

_M.LoginFail={
    code=0x06,
    parse=function(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
}
extends(_M.LoginFail,_M.Packet)

return _M