--tds protocol parser and encoder
local P=require "strmproxy.tds.tdsPackets"
local parser=require("strmproxy.parser")
local _M={}
----------------------build parser---------------------------
--config c2p parsers

local c2pConf={
	{key=P.Login7.code,    parser=P.Login7,   eventName="Login7"},
	{key=P.SQLBatch.code,  parser=P.SQLBatch, eventName="SQLBatch"},
	{key=P.Prelogin.code,  parser=P.Prelogin, eventName="Prelogin"},
	{key=P.RemoteProcedureCall.code,  parser=P.RemoteProcedureCall, eventName="RemoteProcedureCall"}
}

--config s2p parsers
local s2pConf={
	{key=P.Prelogin.code,  parser=P.PreloginResponse, eventName="PreloginResponse"},
	{key=P.Login7.code,    parser=P.LoginResponse,    eventName="LoginResponse"},
	--ssl login response
	{key=0x17,             parser=P.LoginResponse,    eventName="SSLLoginResponse"},
	{key=P.SQLBatch.code,  parser=P.SQLResponse,      eventName="SQLResponse"},
	{key=P.RemoteProcedureCall.code,  parser=P.SQLResponse,      eventName="RPCResponse"},
}

function _M:new(catchReply)
	local o= setmetatable({},{__index=self})
	local C2PParser=parser:new()
	C2PParser.keyGenerator=function(allBytes) return allBytes:byte(1) end
	C2PParser:registerMulti(c2pConf)
	C2PParser:registerDefaultParser(P.Packet)
	o.C2PParser=C2PParser
	local S2PParser=parser:new()
	S2PParser:registerMulti(s2pConf)
	if not catchReply then
		S2PParser:unregister(P.SQLBatch.code,"SQLResponse") 
		S2PParser:register(P.SQLBatch.code,nil,nil,"SQLResponse") 
	end
	S2PParser:registerDefaultParser(P.Packet)
	o.S2PParser=S2PParser
	return o
end

return _M


