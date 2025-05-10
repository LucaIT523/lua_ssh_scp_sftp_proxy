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


local function OnConnect(context,eventSource, connInfo)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        connInfo.clientIP..":"..connInfo.clientPort.."\t",
        "connect to ",
        connInfo.srvIP..":"..connInfo.srvPort
    }
    logger.ntc( table.concat(rs))
end

local function OnLogin(context,eventSource, cred, session)
    local log
    log = format("login with  username: %s, password hash: %s", cred.username, cred.password)
    logger.ntc(format("[StrmProxy] MySQL %s", log))
    return cred
end


local function OnLoginSuccess(context,eventSource, username, session)
    local log
    log = format("Login OK (user : %s)", session.username)
    logger.ntc(format("[StrmProxy] MySQL/MariaDB %s", log))
end

local function OnLoginFail(context,eventSource, username, session)
    local log
    log = format("Login Fail (user : %s)", session.username)
    logger.ntc(format("[StrmProxy] MySQL/MariaDB %s", log))
end

local function OnCommand(context,eventSource, sql, session)
    local log
    if not sql then
        return
    end
    log = format("SQL [%s] (user : %s)", sql, session.username)
    logger.ntc(format("[StrmProxy] MySQL/MariaDB %s", log))
    local m = string.split(sql, " ")
    local sqlcmd = m[1]
    if #m == 0 then
        sqlcmd = sql
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

local function OnResponse(context,eventSource, packet, session)
    local log
    local res = {}
    if packet.type == U.RESP_ERR then
        log = format("result: (type: %s) err: %s\r\n", packet.type, cjson.encode(packet.err))
        logger.ntc(format("[StrmProxy] MySQL %s", log))
    elseif packet.type ~= U.RESP_DATA and packet.type ~= U.RESP_EOF then
        log = format("result: (type: %s) %s\r\n", packet.type, cjson.encode(packet.res))
        logger.ntc(format("[StrmProxy] MySQL %s", log))
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
            elseif (pktno > 1) then
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

                logger.ntc(format("sql:%s\nresult: %s", session.sql, cjson.encode(session.result)))
            else
                --logger.ntc(format("empty eof"))
            end
        end
        break
    end
    
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