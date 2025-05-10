local logger=require "strmproxy.utils.compatibleLog"
local format = string.format
local sockLogger = require "resty.logger.socket"

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

local function tnsLog(data)
    if sockLogger then
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
end

local function tnsAuthLog(username, content, session)
    local curtm  = os.date("%Y/%m/%d %H:%M:%S", ngx.time())
    local client = format("%s [%s:%s] ", curtm, session.clientIP, session.clientPort)
    local user   = username and (username .. " Oracle SQL> ") or "unknown Oracle SQL> "
    local rs     = format("%s%s\r\n%s\r\n", client, user, content)
    -- tnsLog(string.format("[logAuth] username: %s, %s\r\n", username, session.username))
    tnsLog(rs)
end

local function tnsOnConnect(context, source, session)
    if session then
        local rs = format("Oracle connect from %s:%s to %s:%s\r\n", session.clientIP, session.clientPort, session.srvIP, session.srvPort)
        tnsAuthLog(nil, rs, session)
    else
        logger.dbg("session is nil")
    end
end

-- Change the user inputted username and password
local function tnsOnLogin(context, source, credential, session)
    local username = credential.username
    local password = credential.password
    local log = format("Login ID: %s %s", username, password and (", password hash: " .. password) or "")
    logger.dbg(">[tdsOnLogin] ", log)
    tnsLog(log .. "\r\n")
    -- tnsLog("login username: " .. credential.username .. ", PW: " .. credential.password .. "\r\n")
    return credential
end

local function tnsOnLoginSuccess(context, source, username, session)
    local client = session.client or "unknown"
    local version = session.clientVersion or ""
    local log = format("Oracle Login OK username: %s %s %s", username, client, version)
    logger.dbg(">[tnsOnLoginSuccess] " .. log)
    tnsAuthLog(username, log, session)
end

local function tnsOnLoginFail(context, eventSource, failInfo, session)
    local log = format("Oracle Login Fail %s %s", session.username, failInfo.message or "")
    logger.dbg(">[tnsOnLoginFail] ", log)
    -- tnsAuthLog(failInfo.username, "auth message: " .. failInfo.message, session)
    tnsLog(">[tnsOnLoginFail] " .. log)
end
--[[ 
local function tnsOnAuthenticator(context, source, credential, session)
    -- local result = credential.username and credential.password
    local auth_message = (credential.username) and "login user: " .. credential.username or ""
    logger.dbg(">[tnsOnAuthenticator] " .. auth_message .. (credential.password and "password: " .. credential.password or ""))
    -- logger.dbg(">[tnsOnAuthenticator] username: " .. credential.username)
    tnsLog(">[tnsOnAuthenticator] " .. auth_message .. "\r\n")
    -- tnsLog("login username: " .. credential.username .. ", PW: " .. credential.password .. "\r\n")
    -- return result, message
    return true, auth_message
end
 ]]
local function tnsOnCommand(context, source, command, session)
    local curtm  = os.date("%Y/%m/%d %H:%M:%S", ngx.time())
    local user   = (session.username or "unknown")
    local prompt = format("\n%s [%s:%s] %s Oracle SQL> %s\r\n", curtm, session.clientIP, session.clientPort, user, command)
    
    logger.dbg(">[tnsOnCommand] ", prompt)

    --  filter forbidden command
    local taboolist = {"forbidden", "fxxk"}
    for _, word in ipairs(taboolist) do
        if word and command:match(word) then
            local message = format("\"%s\" is not allowed. \"%s(%s:%s)\" session will exit.", word, session.username, session.clientIP, session.clientPort)
            logger.inf(">[tnsOnCommand] ", message)
            -- tnsLog(command)
            tnsLog(message)
            return nil, { message, code = 1234 }
        end
    end

    tnsLog(prompt)
    
    return command
end

local function tnsOnResponse(context, source, command, reply, session)
    if #reply > 0 then
        local res = reply:sub(1, #reply)
        -- logger.dbg("\027[7;31m> [tnsOnResponse] res:\027[0m ", res)
        -- tnsLog(res .. "\r\n")
        tnsLog("cmd: " .. command .. "\r\n")
        tnsLog("rep: " .. reply .. "\r\n")
    end
end

local function tnsOnMSSQLData(context,eventSource, packet, session)
    local log
    local res = {}
    if packet.err and err ~= "closed" then 
        log = format("user: %s, ftpdata: err: %s", session.username, packet.err)
    end
    if packet.err and err == "closed" then 
        log = format("user: %s, ftpdata: closed", session.username)
    end
    if packet.bytes then 
        --log = format("user: %s, ftpdata: \r\n%s\r\n", session.username, packet.bytes)
        log = format("user: %s, ftpdata: %d bytes", session.username, #packet.bytes)
    end
    if packet.direction then 
        log = log .. " (" .. packet.direction ..")"
    end
    logger.ntc(format("[StrmProxy] FTP %s", log))
end

_M.tnsOnConnect       = tnsOnConnect
_M.tnsOnLogin         = tnsOnLogin
_M.tnsOnLoginSuccess  = tnsOnLoginSuccess
_M.tnsOnLoginFail     = tnsOnLoginFail
-- _M.tnsOnAuthenticator = tnsOnAuthenticator
_M.tnsOnCommand       = tnsOnCommand
_M.tnsOnResponse      = tnsOnResponse
-- _M.tnsOnSQLData       = tnsOnMSSQLDat

return _M