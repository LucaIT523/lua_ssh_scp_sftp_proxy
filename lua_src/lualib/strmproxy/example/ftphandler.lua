local logger=require "strmproxy.utils.compatibleLog"
local format = string.format

local function OnConnect(context,eventSource, connInfo)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        connInfo.clientIP..":"..connInfo.clientPort.."\t",
        "connect to ",
        connInfo.srvIP..":"..connInfo.srvPort.."\r\n"
    }
    logger.ntc( table.concat(rs))
end

local function OnLogin(context,eventSource, cred, session)
    local log
    if cred.code == "USER" then
        if cred.username == "bbb" then
            cred.username = "u"
            log = format("username changed from %s to %s", session.username, cred.username)
        else
            log = format("login with username %s", cred.username)
        end
    elseif cred.code == "PASS" then
        if cred.passwd == "bbb" then
            cred.passwd = "aaa"
            log = format("password changed from %s to %s", session.passwd, cred.passwd)
        else
            log = format("login with passwd %s", cred.passwd)
        end
    end
    logger.ntc(format("[StrmProxy] FTP %s", log))
    return cred
end


local function OnLoginSuccess(context,eventSource, username, session)
    local log
    log = format("Login OK (user : %s)", session.username)
    logger.ntc(format("[StrmProxy] FTP %s", log))
end

local function OnLoginFail(context,eventSource, username, session)
    local log
    log = format("Login Fail (user : %s)", session.username)
    logger.ntc(format("[StrmProxy] FTP %s", log))
end

local function OnCommand(context,eventSource, command, session)
    local log
    local res = {}
    log = format("user: %s, command: %s, param: %s", session.username, command.cmd, command.param)
    if command.cmd == "CCC" then
        res.code = "500"
        res.message = "Wrong command"
        res.cmd = nil
        log = log .. " (Command blocked)"
    end
    if command.cmd == "PPP" then
        res.code = "500"
        res.message = "Wrong command"
        log = log .. " (Command blocked)"
        res.cmd = "QUIT\r\n"        
    end
    logger.ntc(format("[StrmProxy] FTP %s", log))
    if res.code then
        return res.cmd, res
    end
    return command
end

local function OnResponse(context,eventSource, response, session)
    local log
    local res = {}
    log = format("user: %s, response: %s, message: %s", session.username, response.code, response.param)
    
    logger.ntc(format("[StrmProxy] FTP %s", log))
end

local function OnFTPData(context,eventSource, packet, session)
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

return {
    OnConnect = OnConnect,
    OnLogin = OnLogin,
    OnLoginSuccess = OnLoginSuccess,
    OnLoginFail = OnLoginFail,
    OnCommand = OnCommand,
    OnResponse = OnResponse,
    OnFTPData = OnFTPData,
}