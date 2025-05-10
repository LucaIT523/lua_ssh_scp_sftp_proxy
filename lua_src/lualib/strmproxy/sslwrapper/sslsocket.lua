local socket = require("strmproxy.sslwrapper.socket")
local luassl = require "ssl"
local sslhelper = require "strmproxy.sslwrapper.sslhelper"
local openssl=require "resty.openssl.ssl"
local get_socket_ssl = require("resty.openssl.auxiliary.nginx").get_socket_ssl

local format = string.format
local SSL_do_handshake = sslhelper.SSL_do_handshake
local SSL_get_ctx = sslhelper.SSL_get_ctx
local SSL_shutdown = sslhelper.SSL_shutdown
local SSL_get_session = sslhelper.SSL_get_session
local SSL_set_session = sslhelper.SSL_set_session
local SSL_get_error = sslhelper.SSL_get_error
local SSL_get_fd = sslhelper.SSL_get_fd
local SSL_pending = sslhelper.SSL_pending
local SSL_has_pending = sslhelper.SSL_has_pending

local tcp = ngx.socket.tcp
local setmetatable = setmetatable
local spawn = ngx.thread.spawn
local wait = ngx.thread.wait
local kill = ngx.thread.kill

local rpoll = require("posix.poll").rpoll

local function pump(self, src, dst, dicrection)
    local bytes, err
    
    while self.continue do
        bytes, err = src:receiveany(1024 * 10)
        if err then
            break
        end
        if bytes then
            if #bytes == 0 then
                err = "closed"
                break
            end
            local sent, err = dst:send(bytes)
            if err then 
                break
            end
        else
            break
        end
    end
    dst:shutdown("send")
    if err then
        return nil, err
    else
        return nil
    end
end


local _M = {}

function _M:new()
    local o = {}
    o.done_handshake = false
    o.continue = true
    setmetatable(o, { __index = self })
    return o
end

function _M:server(address, port, cert, key, ca)
    if not cert then cert = ngx.var.ssl_certificate end
    if not key then key = ngx.var.ssl_certificate_key end
    if not ca then ca = ngx.var.ssl_ca_certificate end
    -- print("\027[1;7;31m> ngx.var.ssl_certificate     \027[0m: ",ngx.var.ssl_certificate    )
    -- print("\027[1;7;31m> ngx.var.ssl_certificate_key \027[0m: ",ngx.var.ssl_certificate_key)
    -- print("\027[1;7;31m> ngx.var.ssl_ca_certificate  \027[0m: ",ngx.var.ssl_ca_certificate )

    if not cert or not key or not ca then
        local err = "No certificate or private key specified"
        return nil, err
    end
    
    local params = {
        mode = "server",
        protocol = "any",
        key = key,
        certificate = cert,
        cafile = ca,
        options = "all",
    }
    
    local ctx = assert(luassl.newcontext(params))
    
    local srvSock = socket.server(address, port)
    
    self.port = srvSock.port
    local self = _M:new()
    
    self.ctx = ctx
    self.srvSock = srvSock
    return self
end

function _M:shutdown()
    local ctx = SSL_get_ctx(self.sslSock)
    local rc = SSL_shutdown(ctx.ssl)
end

function _M:SSL_shutdown(sock)
    local sslctx = get_socket_ssl(sock)
    local ok = SSL_shutdown(sslctx)
end

function _M:close()
    if self.srvSock then
        self.srvSock:close()
        self.srvSock = nil
    end
    if self.sslSock then
        self.sslSock:close()
    end
    if self.co_b2w then
        wait(self.co_b2w)
    end
    if self.co_w2b then
        wait(self.co_w2b)
    end
    if self.wrapSock then
        self.wrapSock:close()
    end
end

function _M:accept()
    local srvSock = self.srvSock
    local conn, err = srvSock:accept()
    srvSock:close()
    self.srvSock = nil
    if err then
        return nil, err
    end
    
    local sslSock, err = luassl.wrap(conn, self.ctx)
    if err then
        conn:close()
        return nil, err
    end
    self.sslSock = sslSock
    local fd = sslSock:getfd()
    self.rawSock = socket:fromfd(fd)
    return self
end

function _M:wrapper(baseSock, cert, key, ca)

    if not cert then cert = ngx.var.ssl_certificate end
    if not key then key = ngx.var.ssl_certificate_key end
    if not ca then ca = ngx.var.ssl_ca_certificate end

    if not cert or not key or not ca then
        local err = "No certificate or private key specified"
        return nil, err
    end

    local self, err = _M:server("127.0.0.1", nil, cert, key, ca)
    if not self then
        return nil, err
    end

    if baseSock ~= nil then
        self.baseSock = baseSock
    end

    local wrapSock = tcp()
    wrapSock:connect("127.0.0.1", self.port)
    local ok, err = self:accept()
    if err then
        self:close()
        return nil, err
    end
    wrapSock:settimeouts(10000 , 10000 , 3600000)
    self.wrapSock = wrapSock
    return self
end
function _M:dohandshake()
    return self.sslSock:dohandshake()
end

function _M:receive(length)
    if not self.done_handshake then
        if self.baseSock and self.wrapSock then
            self.co_b2w = spawn(pump, self, self.baseSock, self.wrapSock, "base->wrap")
            self.co_w2b = spawn(pump, self, self.wrapSock, self.baseSock, "wrap->base")
        end
        while true do
            local rc, err = self.rawSock:wait()
            if rc ~= 1 then
                return nil, err
            end
            local ctx = SSL_get_ctx(self.sslSock)
            local rc = SSL_do_handshake(ctx.ssl)
            if rc == 1 then
                self.done_handshake = true
                ctx.state = 2
                break
            else
                local err = SSL_get_error(ctx.ssl, rc)
                if err == 0 then
                    self.done_handshake = true
                    ctx.state = 2
                    break
                end
                if err ~= 2 and err ~= 3 then
                    return nil, "Hand shake err"
                end
            end
        end
    end
    local rc, err = self.rawSock:wait()
    if rc ~= 1 then
        return nil, err
    end
    return self.sslSock:receive(length)
end

function _M:receiveany(length)
    local ctx = SSL_get_ctx(self.sslSock)
    if not self.done_handshake then
        if self.baseSock and self.wrapSock then
            self.co_b2w = spawn(pump, self, self.baseSock, self.wrapSock, "base->wrap")
            self.co_w2b = spawn(pump, self, self.wrapSock, self.baseSock, "wrap->base")
        end
        while true do
            local rc, err = self.rawSock:wait()
            if rc ~= 1 then
                return nil, err
            end
            
            local rc = SSL_do_handshake(ctx.ssl)
            if rc == 1 then
                self.done_handshake = true
                ctx.state = 2
                break
            else
                local err = SSL_get_error(ctx.ssl, rc)
                if err == 0 then
                    self.done_handshake = true
                    ctx.state = 2
                    break
                end
                if err ~= 2 and err ~= 3 then
                    return nil, "Hand shake err"
                end
            end
        end
    end
    while true do
        ngx.sleep(0.001)
        if self.sslSock:dirty() then
            break
        end
        local rc = rpoll(self.sslSock:getfd(), 1)
        if rc == 1 then
            break
        elseif rc ~=0 then
            return nil, err
        end
    end
    local read = 0
    local bytes, err = self.sslSock:receive(1)
    if err then 
        return bytes, err
    end
    read = read + 1
    while self.sslSock:dirty() and read < length do
        local byte, err = self.sslSock:receive(1)
        if err then 
            break
        end
        if byte then
            read = read + 1
            bytes = bytes .. byte
        end
    end
    return bytes, err
end

function _M:send(bytes)
    return self.sslSock:send(bytes)
end

function _M:get_session()
    local ctx = SSL_get_ctx(self.sslSock)
    return SSL_get_session(ctx.ssl)
end

function _M:set_session(session)
    local ctx = SSL_get_ctx(self.sslSock)
    return SSL_set_session(ctx.ssl, session)
end

return _M