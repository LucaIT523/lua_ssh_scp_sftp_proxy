local P=require "strmproxy.telnet.telnetPackets"
local parser=require("strmproxy.parser")
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end

local _M={}
----------------------build parser---------------------------
--config c2p parsers

local c2pConf={
    {key=P.Login.code,  parser=P.Login, eventName="Login"},
    {key=P.Passwd.code,  parser=P.Passwd, eventName="Passwd"},
	{key=P.Command.code,  parser=P.Command, eventName="Command"},

}

--config s2p parsers
local s2pConf={
    {key=P.Response.code,  parser=P.Response, eventName="Response"},
    {key=P.LoginOk.code,  parser=P.LoginOk, eventName="LoginOk"},
    {key=P.LoginFail.code,  parser=P.LoginFail, eventName="LoginFail"},    
}

function _M:new()
	local o= setmetatable({},{__index=self})

	local C2PParser=parser:new()
	C2PParser:registerMulti(c2pConf)
	C2PParser:registerDefaultParser(P.Packet)
	o.C2PParser=C2PParser

	local S2PParser=parser:new()
	S2PParser:registerMulti(s2pConf)
	S2PParser:registerDefaultParser(P.Packet)
	o.S2PParser=S2PParser
	return o
end

return _M