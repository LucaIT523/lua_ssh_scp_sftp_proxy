local logger=require "strmproxy.utils.compatibleLog"
-- sessiom Man init ------------------------------------------------------------
local sessionManager = require("strmproxy.session.sessionManager"):new {
    --redis server address
    ip="127.0.0.1",
    port=6379,
    expire = -1,
    extend = false
}

local switch = {}

-- SSH
switch[62222] = function()
    local sshHandlers = require "strmproxy.ssh2handler"
    local ssh = require("strmproxy.ssh2"):new()
    local cmd = require("strmproxy.ssh2.commandCollector"):new()
    ssh.BeforeAuthEvent:addHandler(ssh, sshHandlers.sshOnLogin)
    -- ssh.OnAuthEvent:addHandler(ssh, sshHandlers.sshOnAuthenticator)
    ssh.AuthSuccessEvent:addHandler(ssh, sshHandlers.sshOnLoginSuccess)
    ssh.AuthFailEvent:addHandler(ssh, sshHandlers.sshOnLoginFail)
    cmd.CommandEnteredEvent:addHandler(ssh, sshHandlers.sshOnCommand)
    cmd.CommandFinishedEvent:addHandler(ssh, sshHandlers.sshOnResponse)
    ssh.C2PDataEvent:addHandler(cmd, cmd.handleDataUp)
    ssh.S2PDataEvent:addHandler(cmd, cmd.handleDataDown)

    local SSH_UPSTREAM = {{ip="10.0.20.213", port=22}}
    package.loaded.SSH_UPSTREAM = require("strmproxy.balancer.balancer"):new(SSH_UPSTREAM)
    -- local channel = require("strmproxy.channel"):new(package.loaded.SSH_UPSTREAMS, ssh, { sessionMan = sessionManager })
    local channel = require("strmproxy.channel"):new(package.loaded.SSH_UPSTREAM, ssh)
    channel.OnConnectEvent:addHandler(channel, sshHandlers.sshOnConnect)
    channel:run()
end

-- FTP
switch[62021]=function()
    local ftpHandlers =require "strmproxy.ftphandler"
    local ftp=require("strmproxy.ftp"):new()
    ftp.BeforeAuthEvent:addHandler(ftp, ftpHandlers.ftpOnLogin)
    ftp.AuthSuccessEvent:addHandler(ftp, ftpHandlers.ftpOnLoginSuccess)
    ftp.AuthFailEvent:addHandler(ftp, ftpHandlers.ftpOnLoginFail)
    ftp.CommandEnteredEvent:addHandler(ftp, ftpHandlers.ftpOnCommand)
    ftp.CommandFinishedEvent:addHandler(ftp, ftpHandlers.ftpOnResponse)
    ftp.FTPDataEvent:addHandler(ftp, ftpHandlers.ftpOnFTPData)

    local FTP_UPSTREAM = {{ip="10.0.20.213", port=21}}
    -- local FTP_UPSTREAM = {{ip="192.168.30.16", port=21}}
    package.loaded.FTP_UPSTREAM=require ("strmproxy.balancer.balancer"):new(FTP_UPSTREAM)
    -- local channel=require("strmproxy.channel"):new(package.loaded.FTP_UPSTREAM,ftp, { sessionMan = sessionManager })
    local channel=require("strmproxy.channel"):new(package.loaded.FTP_UPSTREAM,ftp)
    channel.OnConnectEvent:addHandler(channel, ftpHandlers.OnConnect)
    channel:run()
end

-- MSSQL TDS processor
switch[61433] = function()
    local tdsHandlers =require "strmproxy.tdshandler"
    --[[ To intercept the login username on an MSSQL server, disableSSL = true ]]
    local tds = require("strmproxy.tds"):new({ disableSSL = true, catchReply = true })
    tds.BeforeAuthEvent:addHandler(tds, tdsHandlers.tdsOnLogin)
    -- tds.OnAuthEvent:addHandler(tds, tdsHandlers.tdsOnAuthenticator)
    tds.AuthSuccessEvent:addHandler(tds, tdsHandlers.tdsOnLoginSuccess)
    tds.AuthFailEvent:addHandler(tds, tdsHandlers.tdsOnLoginFail)
    tds.CommandEnteredEvent:addHandler(tds, tdsHandlers.tdsOnCommand)
    tds.CommandFinishedEvent:addHandler(tds, tdsHandlers.tdsOnResponse)

    local MYSQL_UPSTREAM = {{ip="10.0.20.213", port=1433, id = "srv_sql", gid = "MySqlServer"}}
    package.loaded.MYSQL_UPSTREAM = require("strmproxy.balancer.balancer"):new(MYSQL_UPSTREAM)
    -- local channel = require("strmproxy.channel"):new(package.loaded.MYSQL_UPSTREAM, tds, { sessionMan = sessionManager })
    local channel = require("strmproxy.channel"):new(package.loaded.MYSQL_UPSTREAM, tds)
    channel.OnConnectEvent:addHandler(channel, tdsHandlers.tdsOnConnect)
    channel:run()
end

-- Oracle TNS processor
switch[61521] = function()
    local tnsHandlers =require "strmproxy.tnshandler"
    local tns = require("strmproxy.tns"):new { oracleVersion = 11, swapPass = true }
    tns.BeforeAuthEvent:addHandler(tns, tnsHandlers.tnsOnLogin)
    -- tns.OnAuthEvent:addHandler(tns, tnsHandlers.tnsOnAuthenticator)
    tns.AuthSuccessEvent:addHandler(tns, tnsHandlers.tnsOnLoginSuccess)
    tns.AuthFailEvent:addHandler(tns, tnsHandlers.tnsOnLoginFail)
    tns.CommandEnteredEvent:addHandler(tns, tnsHandlers.tnsOnCommand)
    tns.CommandFinishedEvent:addHandler(tns, tnsHandlers.tnsOnResponse)

    local ORACLE_UPSTREAM = {{ip="10.0.20.213", port=1521, id = "srv_oracle", gid = "OracleServer"}}
    package.loaded.ORACLE_UPSTREAM = require("strmproxy.balancer.balancer"):new(ORACLE_UPSTREAM)
    -- local channel = require("strmproxy.channel"):new(package.loaded.ORACLE_UPSTREAM, tns, { sessionMan = sessionManager })
    local channel = require("strmproxy.channel"):new(package.loaded.ORACLE_UPSTREAM, tns)
    channel.OnConnectEvent:addHandler(channel, tnsHandlers.tnsOnConnect)
    channel:run()
end

-- MySQL/MariaDB
switch[63306]=function()
    local mysqlHandlers =require "strmproxy.mysqlhandler"
    local mysql=require("strmproxy.mysql"):new()
    mysql.BeforeAuthEvent:addHandler(mysql, mysqlHandlers.mysqlOnLogin)
    mysql.AuthSuccessEvent:addHandler(mysql, mysqlHandlers.mysqlOnLoginSuccess)
    mysql.AuthFailEvent:addHandler(mysql, mysqlHandlers.mysqlOnLoginFail)
    mysql.CommandEnteredEvent:addHandler(mysql, mysqlHandlers.mysqlOnCommand)
    mysql.CommandFinishedEvent:addHandler(mysql, mysqlHandlers.mysqlOnResponse)

    local MYSQL_UPSTREAM = {{ip="10.0.20.213", port=3306, id = "srv_mysql", gid = "MySQLServer"}}
    package.loaded.MYSQL_UPSTREAM=require ("strmproxy.balancer.balancer"):new(MYSQL_UPSTREAM)
    local channel=require("strmproxy.channel"):new(package.loaded.MYSQL_UPSTREAM,mysql)
    channel.OnConnectEvent:addHandler(channel, mysqlHandlers.mysqlOnConnect)
    channel:run()
end

--[[ 
--Demo for LDAP processor
switch[389] = function()
    local ldap = require("strmproxy.ldap"):new()
    ldap.AuthSuccessEvent:addHandler(ldap, logAuth)
    ldap.AuthFailEvent:addHandler(ldap, logAuthFail)
    ldap.CommandEnteredEvent:addHandler(ldap, commandFilter)
    ldap.CommandFinishedEvent:addHandler(ldap, logCmd)
    ldap.BeforeAuthEvent:addHandler(ldap, getCredential)
    ldap.OnAuthEvent:addHandler(ldap, authenticator)
    ldap.c2pParser.events.SearchRequest:addHandler(ldap, ldap_SearchRequestHandler)
    --change to your own upstreams
    local channel = require("strmproxy.channel"):new(
        {{ip="192.168.46.128", port=389, id = "ldap1", gid = "ldapServer"}},
        ldap, { sessionMan = sessionManager })
    channel.OnConnectEvent:addHandler(channel, logConnect)
    channel:run()
end
 ]]

local fSwitch = switch[tonumber(ngx.var.server_port)]
if fSwitch then
    fSwitch()
end
