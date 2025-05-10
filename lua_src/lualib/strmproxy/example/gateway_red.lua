----------------socket logger init-----------------------
local logger = require "resty.logger.socket"

if not logger.initted() then
	local ok, err = logger.init{
		-- logger server address
		host = '127.0.0.1',
		port = 12080,
		flush_limit = 10,
		drop_limit = 567800,
	}
	if not ok then
		ngx.log(ngx.ERR, "failed to initialize the logger: ",err)
		return
	end
end

local function log(username,content,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username and username.."\t" or "UNKNOWN ",
        content.."\r\n"
    }
    local bytes, err = logger.log(table.concat(rs))
    if err then
        ngx.log(ngx.ERR, "failed to log command: ", err)
    end
end
----------------------sessiom Man init----------------------------
local sessionManager= require ("strmproxy.session.sessionManager"):new{
	--redis server address
	ip="127.0.0.1",
	port=6379,
	expire=-1,
	extend=false
}

local switch={}
switch[2222]=function()
    local Handlers =require "ftphandler"
    local OnConnect = Handlers.OnConnect
    local OnLogin = Handlers.OnLogin
    local OnLoginSuccess = Handlers.OnLoginSuccess
    local OnLoginFail = Handlers.OnLoginFail
    local OnCommand = Handlers.OnCommand
    local OnResponse = Handlers.OnResponse
    local OnFTPData = Handlers.OnFTPData

    local ftp=require("strmproxy.ftp"):new()
    package.loaded.my_FTPServerB=package.loaded.my_FTPServerB or
	--change to your own upstreams 
	require ("strmproxy.balancer.balancer"):new{
        {ip="192.168.1.1",port=21,id="srv21",gid="ftpServer"},
    }
    
    local channel=require("strmproxy.channel"):new(package.loaded.my_FTPServerB,ftp)
    ftp.BeforeAuthEvent:addHandler(ftp, OnLogin)
    ftp.AuthSuccessEvent:addHandler(ftp, OnLoginSuccess)
    ftp.AuthFailEvent:addHandler(ftp, OnLoginFail)
    ftp.CommandEnteredEvent:addHandler(ftp, OnCommand)
    ftp.CommandFinishedEvent:addHandler(ftp, OnResponse)
    ftp.FTPDataEvent:addHandler(ftp, OnFTPData)
    channel.OnConnectEvent:addHandler(channel, OnConnect)
    channel:run()
end
--Demo for MySQL processor
switch[3336]=function()
    
    local Handlers =require "mysqlhandler"
    local OnConnect = Handlers.OnConnect
    local OnLogin = Handlers.OnLogin
    local OnLoginSuccess = Handlers.OnLoginSuccess
    local OnLoginFail = Handlers.OnLoginFail
    local OnCommand = Handlers.OnCommand
    local OnResponse = Handlers.OnResponse


    local mysql=require("strmproxy.mysql"):new()
    package.loaded.my_SQLServerB=package.loaded.my_SQLServerB or
	--change to your own upstreams 
	require ("strmproxy.balancer.balancer"):new{
        {ip="192.168.1.1",port=3306,id="srv3306",gid="mysqlServer"},
    }
    
    local channel=require("strmproxy.channel"):new(package.loaded.my_SQLServerB,mysql)
    mysql.BeforeAuthEvent:addHandler(mysql, OnLogin)
    mysql.AuthSuccessEvent:addHandler(mysql, OnLoginSuccess)
    mysql.AuthFailEvent:addHandler(mysql, OnLoginFail)
    mysql.CommandEnteredEvent:addHandler(mysql, OnCommand)
    mysql.CommandFinishedEvent:addHandler(mysql, OnResponse)
    
    channel.OnConnectEvent:addHandler(channel, OnConnect)

    channel:run()
end

local fSwitch = switch[tonumber(ngx.var.server_port)]

if fSwitch then  
    fSwitch() 
end 

