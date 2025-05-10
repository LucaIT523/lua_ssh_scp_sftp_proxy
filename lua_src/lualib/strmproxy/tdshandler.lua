local logger=require "strmproxy.utils.compatibleLog"
local sockLogger = require "resty.logger.socket"
local tableUtils=require "strmproxy.utils.tableUtils"
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

local function tdsLog(data)
    if sockLogger then
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
end

local function tdsOnConnect(context, source, session)
    if session then
        local log = format("MSSQL connect from %s:%s to %s:%s\r\n", session.clientIP, session.clientPort, session.srvIP, session.srvPort)
        tdsLog(log)
    else
        logger.dbg("session is nil")
    end
end

local function tdsOnLogin(context, source, credential, session)
    local username = credential.username
    local password = credential.password
    -- local log = format("MSSQL Login ID: %s %s\r\n", username, password and (", PW: " .. password) or "")
    local log = format("MSSQL Login ID: %s\r\n", username)
    logger.dbg(">[tdsOnLogin] ", log)
    tdsLog(log)
    return credential
end

local function tdsOnLoginSuccess(context, source, username, session)
    -- local client = session.client or "unknown"
    local username = session.username or ""
    local version = session.clientVersion or ""
    local log = format("MSSQL Login OK %s %s\r\n", username, version)
    logger.dbg(">[tdsOnLoginSuccess] " .. log)
    tdsLog(log)
end

local function tdsOnLoginFail(context, eventSource, failInfo, session)
    local log = format("MSSQL Login %s\r\n", failInfo.message or "")
    logger.dbg(">[tdsOnLoginFail] ", log)
    tdsLog(log)
end
--[[ 
local function tdsOnAuthenticator(context, source, credential, session)
    -- local result = credential.username and credential.password
    local message = (not credential.username) and "login with " .. credential.username .. " failed"
    logger.dbg(">[tdsOnAuthenticator] username: " .. credential.username .. ", PW: " .. credential.password)
    tdsLog("login username: " .. credential.username .. "\r\n")
    -- tdsLog("login username: " .. credential.username .. ", PW: " .. credential.password .. "\r\n")
    return result, message
end
 ]]
local function tdsOnCommand(context, source, command, session)
    if #command > 0 then
        local curtm    = os.date("%Y/%m/%d.%H:%M:%S", ngx.time())
        local username = session.username or "unknown"
        local prompt   = format("%s [%s:%s] %s MSSQL REQ> %s\r\n", curtm, session.clientIP, session.clientPort, username, command)
        
        -- logger.dbg("\027[7;33m>[tdsOnCommand] ", prompt, "\027[0m")
        tdsLog(prompt)
    
        --  filter forbidden command
        local taboolist = {"forbidden", "fxxk"}
        for _, word in ipairs(taboolist) do
            if command:match(word) then
                local message = format(">[tdsOnCommand] \"%s\" is not allowed. \"%s(%s:%s)\" session will exit.", word, username, session.clientIP, session.clientPort)
                logger.inf(">[tdsOnCommand] ", message)
                -- tdsLog(command)
                tdsLog(message)
                return nil, { message, code = 1234 }
            end
        end
    end
    return command
end

local function tdsOnResponse(context, source, command, reply, session)
    if #reply > 0 then
        local curtm    = os.date("%Y/%m/%d.%H:%M:%S", ngx.time())
        local username = session.username or "unknown"
        local dash     = "\r\n--------------------------------------------------------------------------------\r\n"
        local res      = format("%s [%s:%s] %s MSSQL RES> %s", curtm, session.srvIP, session.srvPort, username, dash..reply..dash)
        -- local res = format("%s\r\n", reply:sub(1, #reply))
        -- logger.dbg("\027[1;33m>[tdsOnResponse]\r\n context: \027[2m(", type(context), ") ", tableUtils.printTableF(context), "\027[0m")
        -- logger.dbg("\027[1;33m>[tdsOnResponse]\r\n source : \027[2m(", type(source) , ") ", tableUtils.printTableF(source) , "\027[0m")
        -- logger.dbg("\027[1;33m>[tdsOnResponse]\r\n session: \027[2m(", type(session), ") ", tableUtils.printTableF(session), "\027[0m")
        -- logger.dbg("\027[1;33m>[tdsOnResponse]\r\n command: \027[2m(", type(command), ") ", command, "\027[0m")
        -- logger.dbg("\027[1;33m>[tdsOnResponse] reply: \027[2m(", type(reply)  , ")\r\n", res  , "\027[0m")
        tdsLog(res)
    end
end

local function tdsOnMSSQLData(context,eventSource, packet, session)
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

_M.tdsOnConnect       = tdsOnConnect
_M.tdsOnLogin         = tdsOnLogin
_M.tdsOnLoginSuccess  = tdsOnLoginSuccess
_M.tdsOnLoginFail     = tdsOnLoginFail
-- _M.tdsOnAuthenticator = tdsOnAuthenticator
_M.tdsOnCommand       = tdsOnCommand
_M.tdsOnResponse      = tdsOnResponse
-- _M.tdsOnSQLData       = tdsOnMSSQLDat

return _M