ngx.log(ngx.DEBUG,"logserver Triggerred")
--[[ 
local reqsock, err = ngx.req.socket(true)
reqsock:settimeout(200)
while(not err) do
    local command,err=reqsock:receive()
    if(err) then ngx.exit(0) end
    local f = assert(io.open("/var/log/openresty/suproxy_commands.log", "a"))
    if(command) then
        f:write(command .. "\n")
        f:close()
    end
end
]]

local cmd_log = ngx.var.pg_stream_reqres_log

local reqsock, err = ngx.req.socket(true)
if not reqsock then
    ngx.log(ngx.ERR, "[SUPROXY RECORD LOG] Failed to get request socket: ", err)
    return ngx.exit(500)
end

reqsock:settimeout(15000)
while true do
    local command, err = reqsock:receive()
    if not command then
        if err == "timeout" then
            ngx.log(ngx.ERR, "Socket read timed out")
        else
            ngx.log(ngx.ERR, "Socket receive error: ", err)
        end
        return ngx.exit(500)
    else
        if 0 < #command then
            -- ngx.log(ngx.DEBUG, "[SUPROXY RECORD LOG] command: ", command)zl
            -- local f = assert(io.open("/var/log/openresty/suproxy_commands.log", "a"))
            local f, err = assert(io.open(cmd_log, "a"))
            if not f then
                ngx.log(ngx.ERR, "[SUPROXY RECORD LOG] Failed to open log file", (err and (":" .. err) or ""))
                return ngx.exit(500)
            else
                -- f:write(command)
                f:write(command .. "\n")
                f:close()
            end
        end
    end
end
