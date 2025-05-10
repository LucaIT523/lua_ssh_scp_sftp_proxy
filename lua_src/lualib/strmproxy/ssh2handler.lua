local logger = require "strmproxy.utils.compatibleLog"
local sockLogger = require "resty.logger.socket"
local format = string.format

local _M = {}


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

local function sshLog(data)

    if sockLogger then
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
end

local function sshOnConnect(context, source, session)
    if session then
        local log = format("SSH connect from %s:%s to %s:%s\r\n", session.clientIP, session.clientPort, session.srvIP, session.srvPort)
        sshLog(log)
    else
        logger.dbg("session is nil")
    end
end

local function sshOnLogin(context, source, credential, session)

    local username = credential.username
    local password = credential.password
    local log = format("SSH Login ID: %s %s\r\n", username, password and (", PW: " .. password) or "")
    logger.dbg(">[sshOnLogin] ", log)
    sshLog(log)

    return credential
end

local function sshOnLoginSuccess(context, source, username, session)

    local client = session.client or "unknown"
    local version = session.clientVersion or ""
    local log = format("SSH Login OK\r\n%s\r\n%s", client, version)
    logger.dbg(">[sshOnLoginSuccess] " .. log)
    sshLog(log)

end

local function sshOnLoginFail(context, source, failInfo, session)
    -- local log = format("login auth info. username: %s, message: %s\r\n", failInfo.username, failInfo.message)
    local log = format("SSH Login %s\r\n", failInfo.message or "")
    logger.dbg(">[sshOnLoginFail] ", log)
    sshLog(log)
end
--[[ 
local function sshOnAuthenticator(context, source, credential, session)
    local result = credential.username and credential.password
    local message = (not result) and "login with " .. credential.username .. " failed"
    logger.dbg(">[sshOnAuthenticator] username: " .. credential.username .. ", PW: " .. credential.password)
    sshLog("login username: " .. credential.username .. "\r\n")
    -- sshLog("login username: " .. credential.username .. ", PW: " .. credential.password .. "\r\n")
    return result, message
end
 ]]
local function sshOnCommand(context, source, command, session)
    local curtm  = os.date("%Y/%m/%d.%H:%M:%S", ngx.time())
    local user   = (session.username and (session.username .. (session.username == "root" and " #" or " $")) or "unknown $")
    local prompt = format("\r\n[%s %s:%s] %s %s\r\n", curtm, session.clientIP, session.clientPort, user, command)

    sshLog(prompt)
    --  filter forbidden command
    local taboolist = {"forbidden", "fxxk"}
    for _, word in ipairs(taboolist) do
        if command:match(word) then
            local message = format("\"%s\" is not allowed. \"%s(%s:%s)\" session will exit.", word, session.username, session.clientIP, session.clientPort)
            logger.inf(">[sshOnCommand] ", message)
            -- sshLog(command)
            sshLog(message)
            return nil, { message, code = 1234 }
        end
    end

    return command
end

local function sshOnResponse(context, source, reply, session)
    if #reply > 0 then
        local res = format("%s\r\n", reply:sub(1, #reply))
        -- logger.inf(">[sshOnResponse] ", res)
        sshLog(res)
    end
end




_M.sshOnConnect       = sshOnConnect
_M.sshOnLogin         = sshOnLogin
_M.sshOnLoginSuccess  = sshOnLoginSuccess
_M.sshOnLoginFail     = sshOnLoginFail
-- _M.sshOnAuthenticator = sshOnAuthenticator
_M.sshOnCommand       = sshOnCommand
_M.sshOnResponse      = sshOnResponse
_M.sshLog      = sshLog

return _M