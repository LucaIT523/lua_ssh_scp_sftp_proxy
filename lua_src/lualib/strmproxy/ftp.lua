require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local format = string.format
local event=require "strmproxy.utils.event"
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local tableUtils=require "strmproxy.utils.tableUtils"
local ftpPacket=require "strmproxy.ftp.ftpPackets"
local socket=require "strmproxy.sslwrapper.socket"
local sslsocket=require "strmproxy.sslwrapper.sslsocket"

local _M = {}

_M._PROTOCAL ='FTP'

function _M.new(self,options)
    local o= setmetatable({},{__index=self})
    options=options or {}
    o.disableSSL=true
    if options.disableSSL~=nil then o.disableSSL=options.disableSSL end
    if options.sslParams~=nil then o.sslParams=options.sslParams end
    
    o.p2c_seq=0
    o.c2p_seq=0
    o.s2p_seq=0
    o.p2s_seq=0
    o.data_port = {60001, 60100}
    o.data_port_ssl = {60101, 60200}

    if (options.data_port ~= nil) then o.data_port = options.data_port end
    if (options.data_port_ssl ~= nil) then o.data_port_ssl = options.data_port_ssl end

    o.OnConnectEvent=event:newReturnEvent(o,"OnConnectEvent")
    o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")
	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent")  
    o.FTPDataEvent=event:new(o,"FTPDataEvent")  
    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")
    o.ctx={}
    -- local parser=require ("strmproxy.ftp.parser"):new(o)
    local parser=require ("strmproxy.ftp.parser"):new()
    o.C2PParser=parser.C2PParser
    o.C2PParser.events.Login:addHandler(o,_M.LoginHandler)
    o.C2PParser.events.Passwd:addHandler(o,_M.PasswdHandler)
    -- o.C2PParser.events.Passive:addHandler(o,_M.PassiveHandler)
    -- o.C2PParser.events.Auth:addHandler(o,_M.AuthHandler)
    o.C2PParser.events.Command:addHandler(o,_M.CommandHandler)
    o.S2PParser=parser.S2PParser
    o.S2PParser.events.LoginOk:addHandler(o,_M.LoginOkHandler)
    o.S2PParser.events.LoginFail:addHandler(o,_M.LoginFailHandler)
    o.S2PParser.events.Response:addHandler(o,_M.ResponseHandler)
    o.S2PParser.events.PasswdResponse:addHandler(o,_M.PasswdResponseHandler)
    o.S2PParser.events.PassiveResponse:addHandler(o,_M.PassiveResponseHandler)
    o.S2PParser.events.AuthResponse:addHandler(o,_M.AuthResponseHandler)
    return o
end
----------------parser event handlers----------------------

function _M:LoginHandler(src,p)
    local cred
    self.ctx.username = p.param
    if self.BeforeAuthEvent:hasHandler() then
        cred=self.BeforeAuthEvent:trigger({username=p.param, code=p.code, packet=p},self.ctx)
    end    
	if self.OnAuthEvent:hasHandler() then
		local ok,message,cred=self.OnAuthEvent:trigger({username=p.param, code=p.code, packet=p},self.ctx)
		if not ok then
			p.allBytes=ftpPacket.Packet:makePacket("530", "Not logged in.")
			return
		end
	end
    if cred and (self.ctx.username~=cred.username) then
        p.allBytes = ftpPacket.Packet:makePacket("USER", cred.username)
    end
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end


function _M:PasswdHandler(src,p)
    -- logger.ntc(format("PasswdHandler: %s : %s", p.code, p.param))
    local cred
    self.ctx.passwd = p.param
    if self.BeforeAuthEvent:hasHandler() then
        cred=self.BeforeAuthEvent:trigger({passwd=p.param, code=p.code, packet=p},self.ctx)
    end    
	if self.OnAuthEvent:hasHandler() then
		local ok,message,cred=self.OnAuthEvent:trigger({username=p.param, code=p.code, packet=p},self.ctx)
		if not ok then
			p.allBytes=ftpPacket.Packet:makePacket("530", "Not logged in.")
			return
		end
	end
    if cred and (self.ctx.passwd~=cred.passwd) then
        p.allBytes = ftpPacket.Packet:makePacket(p.code, cred.passwd)
    end
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end


function _M:PassiveHandler(src,p)
    -- logger.ntc(format("PassiveHandler: %s", p.code))
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger({cmd = p.code, param=p.param}, self.ctx)
        if err then
            p.allBytes=ftpPacket.Packet:makePacket(err.code, err.message)
            self.channel:c2pSend(p.allBytes)
            p.allBytes = nil
            return
        end
    end  
end

function _M:AuthHandler(src,p)
    --logger.ntc(format("AuthHandler: %s %s", p.code, p.param))
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger({cmd = p.code, param=p.param}, self.ctx)
        if err then
            p.allBytes=ftpPacket.Packet:makePacket(err.code, err.message)
            self.channel:c2pSend(p.allBytes)
            p.allBytes = nil
            return
        end
    end  
end

function _M:CommandHandler(src,p)
    --logger.ntc(format("CommandHandler: %s %s", p.code, p.param))
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger({cmd = p.code, param=p.param}, self.ctx)
        if err then
            p.allBytes=ftpPacket.Packet:makePacket(err.code, err.message)
            self.channel:c2pSend(p.allBytes)
            p.allBytes = cmd
            return
        end
    end  
end

function _M:LoginOkHandler(src,p)
    -- logger.ntc(format("LoginOkHandler: %s : %s", p.code, p.param))
    if self.AuthSuccessEvent:hasHandler() then
        self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
    end
end


function _M:LoginFailHandler(src,p)
    -- logger.ntc(format("LoginFailHandler: %s : %s", p.code, p.param))
    if self.AuthFailEvent:hasHandler() then
        self.AuthFailEvent:trigger({username=self.ctx.username,code=p.code, param=p.param},self.ctx)
    end
end

function _M:ResponseHandler(src,p)
    --logger.ntc(format("ResponseHandler: %s : %s", p.code, p.param))
    if self.co_data then
        local co_data = self.co_data
        self.co_data = nil
        ngx.thread.wait(co_data)
    end
    if self.CommandFinishedEvent:hasHandler() then
        self.CommandFinishedEvent:trigger({code=p.code, param=p.param},self.ctx)
    end
end


function _M:PasswdResponseHandler(src,p)
    -- logger.ntc(format("PasswdResponseHandler: %s : %s", p.code, p.param))
end

function _M:FindEmptyPort(useSSL)
    local sharedData = ngx.shared.ftp
    local port1, port2, p
    
    if (useSSL) then
        port1 = self.data_port_ssl[1]
        port2 = self.data_port_ssl[2]
    else
        port1 = self.data_port[1]
        port2 = self.data_port[2]
    end
    sharedData:flush_expired()
    for p=tonumber(port1), tonumber(port2) do
        local key = format("ftp%d", p)
        if (sharedData:get(key) == nil) then
            return p
        end
    end
    return 0
end

function _M:SetDataPort(port, up_port, up_ip)
    local sharedData = ngx.shared.ftp
    local key = format("ftp%d", port)
    
    local ctx = cjson.encode({port=up_port, ip=up_ip, user=self.ctx.username, client=ngx.var.remote_addr})
    sharedData:set(key, ctx, 1000) -- set expire time as 1 second
end

local function FTPdata_pump(self, src, dst, direction)
    while true do
        local bytes, err = src:receiveany(1024 * 10)
        if self.FTPDataEvent:hasHandler() then
            self.FTPDataEvent:trigger({bytes=bytes, direction=direction, err=err}, self.ctx)
        end
        if bytes then
            bytes, err = dst:send(bytes)
        end
        if err then
            break
        end
    end
    if err then 
        --
    end
    if self.ssl and not dst.sslSock then
        sslsocket:SSL_shutdown(dst)
    else
        dst:shutdown("send")
    end
end

function _M:PassiveResponseHandler(src,p)
    -- logger.ntc(format("PassiveResponseHandler: %s : %s", p.code, p.param))
    if self.CommandFinishedEvent:hasHandler() then
        self.CommandFinishedEvent:trigger({code=p.code, param=p.param},self.ctx)
    end
    local line = p.param
    local m, err = ngx.re.match(line, [[(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)]],
                                "jo")
    if not m then
        return nil, "pasv: can't parse ip and port from peer"
    end
    local data_port = tonumber(m[5] * 256) + tonumber(m[6])

    local ip = { m[1], ".", m[2], ".", m[3], ".", m[4] }
    local server = nil

    if (self.ssl) then
        server = sslsocket:server()
    else
        server = socket:server()
    end
    
    local m, err = ngx.re.match(ngx.var.server_addr, [[(\d+).(\d+).(\d+).(\d+)]], "jo")
    local p1 = tonumber(server.port) / 256
    local p2 = tonumber(server.port) % 256
    p.allBytes = ftpPacket.Packet:makePacket("227", format("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", m[1], m[2], m[3], m[4],p1, p2))
    -- self.sslWrapper.unixSock:send(bytes .. "\r\n")
    local co_data = ngx.thread.spawn(function(self, server)
            local conn, err = server:accept()
            local upsock = ngx.socket.tcp()
            upsock:connect(table.concat(ip), data_port)
            if self.ssl then 
                -- local session = self.wrapper:get_session()
                -- server:set_session(session)
                server:dohandshake()
                upsock:sslhandshake(self.sslsession, nil, nil)
            else
                server:close()
                server = conn
            end

            local co_c2s = ngx.thread.spawn(FTPdata_pump, self, server, upsock, "from client to server")
            local co_s2c = ngx.thread.spawn(FTPdata_pump, self, upsock, server, "from server to client")
            
            ngx.thread.wait(co_c2s)
            ngx.thread.wait(co_s2c)
            upsock:close()
            server:close()
        end, 
        self,
        server
    )
    self.co_data = co_data
    
end

function _M:AuthResponseHandler(src,p)
    --logger.ntc(format("AuthResponseHandler: %s : %s", p.code, p.param))
    if self.CommandFinishedEvent:hasHandler() then
        self.CommandFinishedEvent:trigger({code=p.code, param=p.param},self.ctx)
    end
    self.ssl = true
    self.sslsession = self.channel.p2sSock:sslhandshake(nil, nil, self.ssl_verify)
    local wrapper = sslsocket:wrapper(self.channel.c2pSock)
    self.wrapper = wrapper
    self.channel.c2pSock = wrapper
    self.wrapper.baseSock:send(p.allBytes .. "\r\n")
    p.allBytes = nil    
end

----------------implement processor methods---------------------
local function recv(self,readMethod)
    local allBytes = "";
    local eol = false;
    local allBytes,err,partial=readMethod(self.channel,"*l")
    if(err) then
        logger.err("err when reading line",err)
        if allBytes == nil then
            allBytes = ""
        end
        return allBytes .. partial,err 
    end
    return allBytes
end

function _M.processUpRequest(self)
    local allBytes,err
    if not self.ssl then
        allBytes,err= self.channel.c2pSock:receiveany(1024 * 10)
        if self.ssl then
            self.wrapper.wrapSock:send(allBytes)
            return nil
        end
    else
        allBytes,err = self.wrapper:receiveany(1024 * 10)
    end
    local key
    if err then return nil,err end

    local packet=ftpPacket.Packet:new()
    key = packet.getCommandCode(allBytes)

    local p=self.C2PParser:parse(allBytes, nil, key)
    return p.allBytes
end

function _M.processDownRequest(self)
    local readMethod=self.channel.p2sRead
    local allBytes,err=recv(self,readMethod)
    local key
    if err then return nil,err end
    
    local packet=ftpPacket.Packet:new()
    key = packet.getResponseCode(allBytes)
    local p=self.S2PParser:parse(allBytes, nil, key)

    if p.allBytes == nil then 
        return nil
    end
    return p.allBytes .. "\r\n"
end

return _M