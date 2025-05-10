local logger = require "strmproxy.utils.compatibleLog"
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end

local posix = require("posix.sys.socket")
local unistd = require("posix.unistd")
local rpoll = require("posix.poll").rpoll

local _M={}

_M._VERSION = '0.01'

function _M:new(family)
    local o={}
    
    family = family or posix.AF_INET
    o.family = family

    local sockfd, errmsg = assert(posix.socket(family, posix.SOCK_STREAM, 0))
    if sockfd == nil then
        return nil, errmsg
    end
    o.sockfd = sockfd
    o.blockreceive = false

    setmetatable(o, { __index = self })
    return o
end

function _M:fromfd(fd)
    local o={}

    local sockaddr, err = posix.getsockname(fd)
    if err then
        return nil, err
    end

    o.family = sockaddr.family
    o.sockfd = fd    

    setmetatable(o, { __index = self })
    return o
end

function _M:tcp()
    return _M:new(posix.AF_INET)
end

function _M:unix()
    return _M:new(posix.AF_UNIX)
end

function _M:server(address, port)
    local self = _M:tcp()
    if not address then address = "0.0.0.0" end
    if not port then
        while true do
            port = math.random(43300, 43350)
            local ok, err, errcode = self:bind(address, port)
            if not err then break end
        end
    else
        local ok, err, errcode = self:bind(address, port)
        if err then 
            self:close()
            return nil, err
        end
    end
    local ok, err = self:listen()
    if err then
        self:close()
        return nil, err
    end
    self.port = port
    return self
end

function _M:connect(address, port)
    local to = {family=self.family}
    if self.family == posix.AF_UNIX then
        if not address then
            return nil, "bad args"
        end
        to.path = address
    elseif self.family == posix.AF_INET then
        if not address or not port then
            return nil, "bad args"
        end
        to.addr = address
        to.port = port
        to.socktype = posix.SOCK_STREAM
        to.protocol = posix.IPPROTO_TCP
    else
        return nil, "Protocol not yet supported"
    end

    return posix.connect(self.sockfd, to)    
end

function _M:wait()
    local rc, err
    while true do
        if (self.blockreceive) then
            return -1, "suspend"
        end
        rc = rpoll(self.sockfd, 1)
        ngx.sleep(0.001)
        if rc == 1 then
            return rc
        elseif rc ~= 0 then
            return rc, err
        end
    end
end

function _M:receive(length)
    length = length or (1024 * 10)
    local rc, err, bytes
    while true do
        rc = rpoll(self.sockfd, 1)
        ngx.sleep(0.001)
        if (self.blockreceive) then
            return nil
        end
        if rc == 1 then
            bytes, err = posix.recv(self.sockfd, length)
            if bytes and #bytes == 0 then
                return nil, "closed"
            end
            if not err then
                return bytes
            end
            return bytes, err
        elseif rc ~= 0 then
            -- err
            return nil, err
        end
    end
end

function _M:receiveany(length)
    return self:receive(length)
end

function _M:send(bytes)
    return posix.send(self.sockfd, bytes)
end

function _M:close()
    return unistd.close(self.sockfd)
end

function _M:shutdown(mode)
    local how = posix.SHUT_RDWR
    if mode == "send" then
        how = posix.SHUT_WR
    elseif mode == "receive" then
        how = posix.SHUT_RD
    end

    return posix.shutdown(self.sockfd, how)
end

function _M:listen(backlog)
    backlog = backlog or 5
    return posix.listen(self.sockfd, backlog)
end

function _M:bind(address, port)
    local sockaddr = {}
    sockaddr.family = self.family
    if self.family == posix.AF_UNIX then
        if not address then
            return nil, "bad args"
        end
        sockaddr.path = address
    else
        if not port then
            return nil, "bad args"
        end
        if not address then
            options.addr = "0.0.0.0"
        end
        sockaddr.addr = address
        sockaddr.port = port
    end
    return posix.bind(self.sockfd, sockaddr)
end

function _M:accept()
    local rc
    while true do
        rc = rpoll(self.sockfd, 1)
        ngx.sleep(0.001)
        if rc == 1 then
            break
        end
    end
    local conn, from, errno = posix.accept(self.sockfd)
    if (errno) then
        return nil, from
    end
    local peer, err = _M:fromfd(conn)
    if err then
        return nil, err
    end
    return peer
end

function _M:getsockname()
    local me, err = posix.getsockname(self.sockfd)
    if err then
        return nil, nil, err
    end
    return me.addr, me.port
end

function _M:getpeername()
    local peer, err = posix.getsockname(self.sockfd)
    if err then
        return nil, nil, err
    end
    return peer.addr, peer.port
end

function _M:getfd()
    return self.sockfd
end

function _M:setfd(fd)
    self.sockfd = fd
end

function _M:stopreceive()
    self.blockreceive = true
end

function _M:resumereceive()
    self.blockreceive = false
end

return _M

