local P=require "strmproxy.mysql.mysqlPackets"
local parser=require("strmproxy.parser")
local _M={}


local c2pConf={
    {key=P.Login.code,  parser=P.Login, eventName="Login"},
	{key=P.SQLQuery.code,  parser=P.SQLQuery, eventName="SQLQuery"},
    {key=P.QUIT.code,  parser=P.QUIT, eventName="QUIT"},
}

--config s2p parsers
local s2pConf={
    {key=P.Welcome.code,  parser=P.Welcome, eventName="WelcomeResponse"},
	{key=P.LoginResponse.code,  parser=P.LoginResponse, eventName="LoginResponse"},
    {key=P.SQLResponse.code,  parser=P.SQLResponse,      eventName="SQLResponse"}
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
