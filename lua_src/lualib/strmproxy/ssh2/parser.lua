--ssh2.0 protocol parser 
local logger = require "strmproxy.utils.compatibleLog"
local P=require "strmproxy.ssh2.ssh2Packets"
local parser=require("strmproxy.parser")
local _M={}

local conf={
    {key=P.PktType.KeyXInit,    parserName="KeyXInit",    parser=P.KeyXInit,    eventName="KeyXInitEvent"},
    {key=P.PktType.DHKeyXInit,  parserName="DHKeyXInit",  parser=P.DHKeyXInit,  eventName="DHKeyXInitEvent"},
    {key=P.PktType.DHKeyXReply, parserName="DHKeyXReply", parser=P.DHKeyXReply, eventName="DHKeyXReplyEvent"},
    {key=P.PktType.AuthReq,     parserName="AuthReq",     parser=P.AuthReq,     eventName="AuthReqEvent"},
    {key=P.PktType.AuthFail,    parserName="AuthFail",    parser=P.AuthFail,    eventName="AuthFailEvent"},
    {key=P.PktType.ChannelData, parserName="ChannelData", parser=P.ChannelData, eventName="ChannelDataEvent"},
    {key=P.PktType.Disconnect,  parserName="Disconnect",  parser=P.Disconnect,  eventName="DisconnectEvent"},
    {key=P.PktType.NewKeys,     eventName="NewKeysEvent"},
    {key=P.PktType.AuthSuccess, eventName="AuthSuccessEvent"}
}
local keyG=function(allBytes) return allBytes:byte(6) end

function _M:new()

    local o= setmetatable({},{__index=self})
    local C2PParser=parser:new()
    C2PParser.keyGenerator=keyG
    C2PParser:registerMulti(conf)
    C2PParser:registerDefaultParser(P.Base)
    o.C2PParser=C2PParser

    local S2PParser=parser:new()	
    S2PParser.keyGenerator=keyG
    S2PParser:registerMulti(conf)
    S2PParser:registerDefaultParser(P.Base)
    o.S2PParser=S2PParser
    return o
end

return _M

