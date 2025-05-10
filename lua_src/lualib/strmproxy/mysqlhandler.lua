local logger=require "strmproxy.utils.compatibleLog"
local format = string.format
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local strbyte = string.byte
local strchar = string.char
local strfind = string.find
local format = string.format
local strrep = string.rep
local strsub = string.sub
local strupper = string.upper
local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

local U = require "strmproxy.mysql.utils"

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

local function mysqlLog(data)
    if sockLogger then
        local bytes, err = sockLogger.log(data)
        if err then
            logger.err("failed to log reply: ", err)
        end
    else
        logger.dbg( data)
    end
end

local function mysqlOnConnect(context, source, session)
    if session then
        local log = format("MySQL/MariaDB connect from %s:%s to %s:%s\r\n", session.clientIP, session.clientPort, session.srvIP, session.srvPort)
        mysqlLog(log)
    else
        logger.dbg("session is nil")
    end
end

local function mysqlOnLogin(context, source, credential, session)
    local username = credential.username
    local password = credential.password
    local log = format("Login ID: %s %s", username, password and (", password hash: " .. password) or "")
    logger.dbg(">[mysqlOnLogin] " .. log)
    mysqlLog(log .. "\r\n")
    return credential
end

local function mysqlOnLoginSuccess(context, source, username, session)
    local client = session.client or "unknown"
    local version = session.clientVersion or ""
    local log = format("MySQL/MariaDB Login OK\r\n%s\r\n%s", client, version)
    logger.dbg(">[mysqlOnLoginSuccess] " .. log)
    mysqlLog(log)
end

local function mysqlOnLoginFail(context,source, username, session)
    local log = format("Mysql/MariaDB Login Fail %s %s", session.username, failInfo.message or "")
    logger.ntc("[mysqlOnLoginFail] %s", log)
    mysqlLog(log)
end

local function mysqlOnCommand(context, source, command, session)
    local curtm    = os.date("%Y/%m/%d.%H:%M:%S", ngx.time())
    local username = session.username or "unknown"
    
    if not command then
        return
    end
    local prompt = format("\r\n%s [%s:%s] %s Mysql/MariaDB SQL> %s\r\n", curtm, session.clientIP, session.clientPort, username, command)

    mysqlLog(prompt)

    logger.ntc(format("[mysqlOnCommand] %s", prompt))
    local m = string.split(command, " ")
    local sqlcmd = m[1]
    if #m == 0 then
        sqlcmd = command
    end
    if strupper(sqlcmd) == "UPDATE" then
        local err = {}
        err.no = 1142
        err.msg = format("%s command denied to user '%s'@'%s'", strupper(sqlcmd), session.username, ngx.var.remote_addr)
        err.sqlstate = 42000
        return nil, err
    end
    if strupper(sqlcmd) == "CREATE" then
        local err = {}
        err.no = 1142
        err.msg = format("%s command denied to user '%s'@'%s'", strupper(sqlcmd), session.username, ngx.var.remote_addr)
        err.sqlstate = 42000
        local cmd = U._make_quit_request()
        return cmd, err
    end

    return nil
end

local function mysqlOnResponse(context, source, packet, session)
    local printBuf = function(...) return ngx.log(ngx.DEBUG, "\027[7;34m>\027[0;2m " .. table.concat({...}) .. "\027[0m") end
    
    local log, sql_res
    local res = {}
    if packet.type == U.RESP_ERR then
        log = format("result: (type: %s) err: %s\r\n", packet.type, cjson.encode(packet.err))
        logger.ntc(format("[mysqlOnResponse] MySQL %s", log))
        -- mysqlLog(packet.err.msg)
    elseif packet.type ~= U.RESP_DATA and packet.type ~= U.RESP_EOF then
        log = format("result: (type: %s) %s\r\n", packet.type, cjson.encode(packet.res))
        logger.ntc(format("[mysqlOnResponse] MySQL %s", log))
    end

    while true do
        local pktno = packet.pktno
        if packet.type == U.RESP_DATA then
            local data = packet.res.packet
            -- logger.ntc(format("packet no %d", pktno))
            if (packet.pktno == 1) then
                local field_count = strbyte(data, 1, 1)
                session.sqlres = {}
                session.sqlres.field_count = field_count
                session.sqlres.rows = nil
                session.sqlres.col_count = 0
                session.sqlres.row_count = 0
                -- logger.ntc(format("result count: %d", field_count))
                session.sqlres.cols = new_tab(field_count, 0)
                session.sqlres.eof = nil
            elseif (pktno > 1 and session.sqlres) then
                if session.sqlres.col_count < session.sqlres.field_count then
                    --logger.ntc(format("read cols: %d", session.sqlres.col_count))
                    local col, err, errno, sqlstate = U._parse_field_packet(data)
                    if not col then
                        logger.ntc(format("_parse_field_packet err: %s", err))
                        break
                    end
                    -- logger.ntc(format("read cols: %s", cjson.encode(col)))
                    session.sqlres.col_count = session.sqlres.col_count + 1
                    session.sqlres.cols[session.sqlres.col_count] = col
                elseif session.sqlres.rows and not session.sqlres.eof then
                    -- logger.ntc(format("read rows: %d", session.sqlres.row_count))
                    local row = U._parse_row_data_packet(data, session.sqlres.cols)
                    -- logger.ntc(format("read row: %s", cjson.encode(row)))
                    session.sqlres.row_count = session.sqlres.row_count + 1
                    session.sqlres.rows[session.sqlres.row_count] = row
                else
                    -- logger.ntc(format("empty action"))
                end
            end
        end

        if packet.type == U.RESP_EOF then
            if pktno > 1 and not session.sqlres.rows then
                -- logger.ntc(format("eof read cols"))
                session.sqlres.rows = new_tab(4, 0)
                session.sqlres.row_count = 0
            elseif pktno > 1 then
                session.sqlres.eof = true
                -- logger.ntc(format("eof read rows"))
                session.result = session.sqlres.rows
                session.sqlres = nil
                
                local sql_result = cjson.encode(session.result)
                logger.ntc(format("sql:%s\nresult: %s", session.sql, sql_result))
                mysqlLog(sql_result)
            else
                --logger.ntc(format("empty eof"))
            end
        end
        break
    end
end

_M.mysqlOnConnect      = mysqlOnConnect
_M.mysqlOnLogin        = mysqlOnLogin
_M.mysqlOnLoginSuccess = mysqlOnLoginSuccess
_M.mysqlOnLoginFail    = mysqlOnLoginFail
_M.mysqlOnCommand      = mysqlOnCommand
_M.mysqlOnResponse     = mysqlOnResponse
-- _M.mysqlOnFTPData      = mysqlOnFTPData

return _M