local logger=require "strmproxy.utils.compatibleLog"
local ok,cjson=pcall(require,"cjson")
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

local function telnetLog(data)

    if sockLogger then
        data = data .. "\r\n"
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
end

local function telnetOnConnect(context,eventSource, connInfo)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        connInfo.clientIP..":"..connInfo.clientPort.."\t",
        "connect to ",
        connInfo.srvIP..":"..connInfo.srvPort.."\r\n"
    }
    logger.ntc( table.concat(rs))
end


local function telnetOnLoginUser(context,eventSource, username, session)

    local log
    local new_user = "ubuntu" 

    if username == "ddd" then
        log = format("telnet> username changed from %s to %s", username, new_user)
        telnetLog(log)
        username = new_user
    end
    return username
end

local function telnetOnLoginPass(context,eventSource, pass, session)

    local log
    local new_pw = "ubuntu" 

    if pass == "ddd" then
        log = format("telnet> password changed from %s to %s", pass, new_pw)
        telnetLog(log)
        pass = new_pw
    end
    return pass
end

local function telnetOnLoginSuccess(context,eventSource, cred, session)
    local log
    log = format("telnet> Login OK (user : %s , pw : %s)", cred.username, cred.password)
    telnetLog(log)
end

local function telnetOnLoginFail(context,eventSource, cred, session)
    local log
    log = format("telnet> Login Faild (user : %s , pw : %s)", cred.username, cred.password)
    telnetLog(log)
end

local function telnetOnCommand(context,eventSource, command, session)
    local log

    if command == "CCC" then
        log = format("telnet> (Command blocked) %s", command)
        command = ""
    elseif command == "PPP" then
        log = format("telnet> (Command blocked) %s", command)
        command = ""
    else
        log = format("telnet> %s", command)
    end

    telnetLog(log)
    return command
end

local function telnetOnResponse(context,eventSource, response, session)
    telnetLog(response)
end



_M.telnetOnConnect = telnetOnConnect
_M.telnetOnLoginUser = telnetOnLoginUser
_M.telnetOnLoginPass = telnetOnLoginPass
_M.telnetOnLoginSuccess = telnetOnLoginSuccess
_M.telnetOnLoginFail = telnetOnLoginFail
_M.telnetOnCommand = telnetOnCommand
_M.telnetOnResponse = telnetOnResponse

return _M