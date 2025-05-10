local resolver = require "strmproxy.dns.resolver"
local server = require "strmproxy.dns.server"
local cjson = require "cjson"
local logger = require "strmproxy.utils.compatibleLog"
local cache = ngx.shared.dns_cache
local sockLogger = require "resty.logger.socket"
local format = string.format




local _M = {}
local dns
local config
local my_replace_ip = ""
local mode_udp = 0

-- Blocklist for domains
local blocklist = {
    ["example.com"] = true,
    ["test.com"] = true,
}


function _M:config(dns_config)
    config = dns_config or {
        nameservers = {"8.8.8.8"},
        retrans = 3,
        timeout = 1500,
    }
end

function _M:redirect_all(ip)
    my_replace_ip = ip
end

function _M:set_mode(is_tcp)
    mode_udp = is_tcp
end

if not sockLogger.initted() then
    local ok, err = sockLogger.init {
        -- logger server address
        host        = '127.0.0.1',
        port        = 12080,
        flush_limit = 10,
        drop_limit  = 567800,
    }
    if not ok then
        logger.err("failed to initialize the logger: ", err)
    end
else
    logger.err("logger module already initialized")
end

local function dnsLog(data)
--[[
    if sockLogger then
        data = "DNS> " ..  data
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
]]
    local f = assert(io.open("/var/log/openresty/stream_capture_command.log", "a"))
    if f then
        data = "DNS> " ..  data
        f:write(data .. "\n")
        f:close()
    end    
end


local function receive_data()
    local data, err = ngx.ctx.socket:receive()
    if not data then
        logger.inf("---dns---failed to receive data: ", err)
        return nil
    end
    return data
end

local function process_request(data)
    dns = server:new();
    local request, err = dns:decode_request(data)

    if not request then
        logger.inf("---dns---failed to decode request: ", err)
        return nil, nil, "failed to decode request"
    end

    return request.questions[1].qname, request.questions[1].qtype
end


local function create_answers(answers)
    for _, ans in ipairs(answers) do
        if ans.type == server.TYPE_A then
            dns:create_a_answer(ans.name, ans.ttl, ans.address)
        elseif ans.type == server.TYPE_CNAME then
            dns:create_cname_answer(ans.name, ans.ttl, ans.cname)
        end
    end
end

local function resolve_dns(qname, qtype)
    local r, err = resolver:new(config)
    if not r then
        logger.inf("failed to instantiate the resolver: ", err)
        dnsLog("failed to instantiate the resolver")
        return nil
    end

    local answers, err

    if mode_udp == 0 then
        answers, err = r:query(qname, { qtype = qtype })
    else
        answers, err = r:tcp_query(qname, { qtype = qtype })
    end    

    if not answers then
        logger.inf("failed to query the DNS server: ", err)
        dnsLog("failed to query the DNS server")
        return nil
    end

    --local cache_key = qname .. ":" .. qtype
    logger.inf("---dns---resolve_dns() qname : ", qname)
    for _, answer in ipairs(answers) do
        if answer.address then
            logger.inf("---dns---resolve_dns() answer.address : ", answer.address)
            if my_replace_ip ~= "" then
                answer.address = my_replace_ip
            end

            dnsLog("answer ip : " .. answer.address)

        elseif answer.cname then
            logger.inf("---dns---resolve_dns() CNAME Record : ", answer.cname)
        end
    end

    create_answers(answers)
end

local function send_response(response)
    local bytes, err = ngx.ctx.socket:send(response)
    if not bytes then
        logger.inf("---dns---failed to send response: ", err)
    end
end
-- Function to block queries based on the blocklist
local function block_query(query_name)
    if blocklist[query_name] then
        logger.inf("---dns---Blocked query for: ", query_name)
        return true
    end
    return false
end


function _M:run()

    ngx.ctx.socket = ngx.req.socket()
    if not ngx.ctx.socket  then
        logger.inf("---dns---failed to get the request socket: ")
        return nil
    end


    local data = receive_data()

    if data then
        local qname, qtype, err = process_request(data)
        logger.inf("---dns---qname : ", qname)
        logger.inf("---dns---qtype : ", qtype)
        dnsLog("query " .. qname)
        dnsLog("qtype " .. qtype)

        -- Block query if in the blocklist
        if block_query(qname) then
            local response = string.char(0x81, 0x83) -- Response with error code (REFUSED)
            send_response(response)
            return
        end
        -- ok
        if err == nil  then
            resolve_dns(qname, qtype)
            local response = dns:encode_response()
            send_response(response)
        end

    end
end

return _M

