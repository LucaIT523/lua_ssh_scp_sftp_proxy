require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local format = string.format
local event=require "strmproxy.utils.event"
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local mysqlPacket=require "strmproxy.mysql.mysqlPackets"
local tableUtils=require "strmproxy.utils.tableUtils"
local U = require('strmproxy.mysql.utils')
local max_packet_size = 1024 * 1024 -- default 1 MB

local _M = {}

_M._PROTOCAL ='mysql'

function _M.new(self,options)
    local o= setmetatable({},{__index=self})
    options=options or {}
    o.disableSSL=true
    if options.disableSSL~=nil then o.disableSSL=options.disableSSL end
    o.max_packet_size = 1024 * 1024 -- default 1 MB
    if options.max_packet_size~=nil then o.max_packet_size=options.max_packet_size end

    o.c2p_stage="INIT"
    o.p2s_stage="INIT"
    
    o.p2c_seq=0
    o.c2p_seq=0
    o.s2p_seq=0
    o.p2s_seq=0

    o.OnConnectEvent=event:newReturnEvent(o,"OnConnectEvent")
    o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")
	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent")  
    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")
    o.ctx={}
    -- local parser=require ("strmproxy.mysql.parser"):new(o)
    local parser=require ("strmproxy.mysql.parser"):new()
    o.C2PParser=parser.C2PParser
    o.C2PParser.events.SQLQuery:addHandler(o,_M.SQLQueryHandler)
    o.C2PParser.events.Login:addHandler(o,_M.LoginHandler)
    o.C2PParser.events.QUIT:addHandler(o,_M.SQLQueryHandler)
    o.S2PParser=parser.S2PParser
    o.S2PParser.events.WelcomeResponse:addHandler(o,_M.OnConnectHandler)
    o.S2PParser.events.LoginResponse:addHandler(o,_M.LoginResponseHandler)
    o.S2PParser.events.SQLResponse:addHandler(o,_M.SQLResponseHandler)
    return o
end

function _M:OnConnectHandler(src,p)
    -- ngx.log(ngx.ERR, format("OnConnectHandler: %s", cjson.encode(p.server_info)))
    if self.OnConnectEvent:hasHandler() then
        local cmd,err=self.OnConnectEvent:trigger(p.server_info,self.ctx)
        if err then
            self.channel:c2pSend(mysqlPacket.packErrorResponse(err.message,err.code))
            p.allBytes=nil
            return
        end
    end
    if (p.success) then
        self.c2p_stage = "LOGIN"
        self.server_info = p.server_info
    else
        ngx.exit(0)
    end
end

function _M:LoginHandler(src,p)
    -- ngx.log(ngx.ERR, format("LoginHandler: %s", cjson.encode(p.client_info)))
    self.ctx.client_info = client_info
    local cred
    if self.BeforeAuthEvent:hasHandler() then
        cred=self.BeforeAuthEvent:trigger({username=p.username,password=p.password},self.ctx)
    end    
	if self.OnAuthEvent:hasHandler() then
		local ok,err,cred=self.OnAuthEvent:trigger({username=p.username,password=p.password},self.ctx)
		if not ok then
			self.channel:c2pSend(U._make_err_response(err.no, err.msg, err.sqlstate))
			p.allBytes=nil
			return
		end
	end
    if cred and (p.username~=cred.username or p.password~=cred.password) then
        p.username=cred.username
        p.password=cred.password
        -- p:pack()
    end
    self.ctx.username=p.username
    self.ctx.client=p.client_info
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end

function _M:LoginResponseHandler(src,p)
    -- ngx.log(ngx.DEBUG, format("LoginResponseHandler: %s", cjson.encode(p.success)))
    -- ngx.log(ngx.DEBUG, format("LoginResponseHandler: %s", cjson.encode(p.err)))
    if p.success then
		if self.AuthSuccessEvent:hasHandler() then
			self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
		end
	else
		if self.AuthFailEvent:hasHandler() then
			self.AuthFailEvent:trigger({username=self.ctx.username,message="["..p.err.errno.."]"..p.err.msg},self.ctx)
		end
	end
end

----------------parser event handlers----------------------
function _M:SQLQueryHandler(src,p)
    -- ngx.log(ngx.NOTICE, format("SQLQueryHandler: %s", p.sql))
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger(p.sql,self.ctx)
        if err then
            self.channel:c2pSend(U._make_err_response(err.no,err.msg, err.sqlstate))
            if cmd then 
                p.allBytes=cmd
            end
            return
        end
    end
    self.ctx.sql=p.sql
end


----------------parser event handlers----------------------
function _M:SQLResponseHandler(src,p)
    -- ngx.log(ngx.ERR, format("SQLResponseHandler: %s %s", p.type, cjson.encode(p.res)))
    if self.CommandFinishedEvent:hasHandler() then
        local cmd,err=self.CommandFinishedEvent:trigger(p, self.ctx)
        if err then
            self.channel:c2pSend(U._make_err_response(err.no,err.msg, err.sqlstate))
            if cmd then 
                p.allBytes=cmd
            end
            return
        end
    end
end

----------------implement processor methods---------------------
local function recv(self,readMethod)
    local headerBytes,err,partial=readMethod(self.channel,4)
    if(err) then
        logger.err("err when reading header",err)
        return partial,err 
    end
    
    local packet=mysqlPacket.Packet:new()
    local pos=packet:parseHeader(headerBytes)
    local payloadBytes,err,allBytes
    local dataLength = packet.dataLength
    if (dataLength == 0) then
        return nil
    end
    if (dataLength > self.max_packet_size) then
        return nil
    end

    payloadBytes,err=readMethod(self.channel,dataLength)
    if (self.p2s_stage == "INIT") then
        payloadBytes = U.disable_ssl_and_compression(payloadBytes)
    end
    allBytes=headerBytes..payloadBytes
    
    return allBytes
end

function _M.processUpRequest(self)
    local readMethod=self.channel.c2pRead
    local allBytes,err=recv(self,readMethod)
    local key
    if err then return nil,err end
    if (self.c2p_stage == "LOGIN") then
        key = mysqlPacket.Login.code
        self.p2s_stage = "LOGIN"
    elseif (self.c2p_stage == "QUERY") then
        key = mysqlPacket.SQLQuery.code
    else
        key = -1
    end

    local p=self.C2PParser:parse(allBytes, nil, key)
    return p.allBytes
end

function _M.processDownRequest(self)
    local readMethod=self.channel.p2sRead
    local allBytes,err=recv(self,readMethod)
    if err then return nil,err end
    local key
    if (self.p2s_stage == "INIT")  then
        key = mysqlPacket.Welcome.code
    elseif (self.p2s_stage == "LOGIN") then
        key = mysqlPacket.LoginResponse.code
        self.p2s_stage = "QUERY"
        self.c2p_stage = "QUERY"
    else
        key = mysqlPacket.SQLResponse.code
    end
    local p =self.S2PParser:parse(allBytes,nil,key)
    return allBytes
end

return _M
