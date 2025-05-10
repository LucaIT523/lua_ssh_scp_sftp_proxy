require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local ok,cjson=pcall(require,"cjson")
local tableUtils=require "strmproxy.utils.tableUtils"
local orderTable=tableUtils.OrderedTable
local extends=tableUtils.extends
if not ok then cjson = require("strmproxy.utils.json") end
local logger=require "strmproxy.utils.compatibleLog"
local unicode = require "strmproxy.utils.unicode"

local bit = require "bit"
local resty_sha256 = require "resty.sha256"
local sub = string.sub
local tcp = ngx.socket.tcp
local strbyte = string.byte
local strchar = string.char
local strfind = string.find
local format = string.format
local strrep = string.rep
local null = ngx.null
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local sha1 = ngx.sha1_bin
local concat = table.concat
local setmetatable = setmetatable
local error = error
local tonumber = tonumber
local to_int = math.floor

local has_rsa, resty_rsa = pcall(require, "resty.rsa")

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

-- refer to https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
-- CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG
-- | CLIENT_CONNECT_WITH_DB | CLIENT_ODBC | CLIENT_LOCAL_FILES
-- | CLIENT_IGNORE_SPACE | CLIENT_PROTOCOL_41 | CLIENT_INTERACTIVE
-- | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_RESERVED
-- | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS
local DEFAULT_CLIENT_FLAGS = 0x3f7cf
local CLIENT_CONNECT_WITH_DB = 0x00000008
local CLIENT_SSL = 0x00000800
local CLIENT_PLUGIN_AUTH = 0x00080000
local CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
local DEFAULT_AUTH_PLUGIN = "mysql_native_password"

local SERVER_MORE_RESULTS_EXISTS = 8

local MY_RND_MAX_VAL = 0x3FFFFFFF
local MIN_PROTOCOL_VER = 10

local LEN_NATIVE_SCRAMBLE = 20
local LEN_OLD_SCRAMBLE = 8

-- 16MB - 1, the default max allowed packet size used by libmysqlclient
local FULL_PACKET_SIZE = 16777215

-- the following charset map is generated from the following mysql query:
--   SELECT CHARACTER_SET_NAME, ID
--   FROM information_schema.collations
--   WHERE IS_DEFAULT = 'Yes' ORDER BY id;
local CHARSET_MAP = {
    _default  = 0,
    big5      = 1,
    dec8      = 3,
    cp850     = 4,
    hp8       = 6,
    koi8r     = 7,
    latin1    = 8,
    latin2    = 9,
    swe7      = 10,
    ascii     = 11,
    ujis      = 12,
    sjis      = 13,
    hebrew    = 16,
    tis620    = 18,
    euckr     = 19,
    koi8u     = 22,
    gb2312    = 24,
    greek     = 25,
    cp1250    = 26,
    gbk       = 28,
    latin5    = 30,
    armscii8  = 32,
    utf8      = 33,
    ucs2      = 35,
    cp866     = 36,
    keybcs2   = 37,
    macce     = 38,
    macroman  = 39,
    cp852     = 40,
    latin7    = 41,
    utf8mb4   = 45,
    cp1251    = 51,
    utf16     = 54,
    utf16le   = 56,
    cp1256    = 57,
    cp1257    = 59,
    utf32     = 60,
    binary    = 63,
    geostd8   = 92,
    cp932     = 95,
    eucjpms   = 97,
    gb18030   = 248
}

-- mysql field value type converters
local converters = new_tab(0, 9)

for i = 0x01, 0x05 do
    -- tiny, short, long, float, double
    converters[i] = tonumber
end
converters[0x00] = tonumber  -- decimal
-- converters[0x08] = tonumber  -- long long
converters[0x09] = tonumber  -- int24
converters[0x0d] = tonumber  -- year
converters[0xf6] = tonumber  -- newdecimal


local function _get_byte2(data, i)
    local a, b = strbyte(data, i, i + 1)
    return bor(a, lshift(b, 8)), i + 2
end

local function _get_byte3(data, i)
    local a, b, c = strbyte(data, i, i + 2)
    return bor(a, lshift(b, 8), lshift(c, 16)), i + 3
end


local function _get_byte4(data, i)
    local a, b, c, d = strbyte(data, i, i + 3)
    return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24)), i + 4
end


local function _get_byte8(data, i)
    local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)

    -- XXX workaround for the lack of 64-bit support in bitop:
    -- XXX return results in the range of signed 32 bit numbers
    local lo = bor(a, lshift(b, 8), lshift(c, 16))
    local hi = bor(e, lshift(f, 8), lshift(g, 16), lshift(h, 24))
    return lo + 16777216 * d + hi * 4294967296, i + 8

    -- return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24), lshift(e, 32),
               -- lshift(f, 40), lshift(g, 48), lshift(h, 56)), i + 8
end


local function _set_byte2(n)
    return strchar(band(n, 0xff), band(rshift(n, 8), 0xff))
end


local function _set_byte3(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff))
end


local function _set_byte4(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff),
                   band(rshift(n, 24), 0xff))
end

local function _from_cstring(data, i)
    local last = strfind(data, "\0", i, true)
    if not last then
        return nil, nil
    end

    return sub(data, i, last - 1), last + 1
end


local function _to_cstring(data)
    return data .. "\0"
end


local function _dump(data)
    local len = #data
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = format("%x", strbyte(data, i))
    end
    return concat(bytes, " ")
end

local function _dump2(data, len)
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = format("%x", strbyte(data, i))
    end
    return concat(bytes, " ")
end

local function _dumphex(data)
    local len = #data
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = tohex(strbyte(data, i), 2)
    end
    return concat(bytes, " ")
end


local function _dumphex2(data, len)
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = tohex(strbyte(data, i), 2)
    end
    return concat(bytes, " ")
end

local function _pwd_hash(password)
    local add = 7

    local hash1 = 1345345333
    local hash2 = 0x12345671

    local len = #password
    for i = 1, len do
        -- skip spaces and tabs in password
        local byte = strbyte(password, i)
        if byte ~= 32 and byte ~= 9 then -- not ' ' or '\t'
            hash1 = bxor(hash1, (band(hash1, 63) + add) * byte
                                + lshift(hash1, 8))

            hash2 = bxor(lshift(hash2, 8), hash1) + hash2

            add = add + byte
        end
    end

    -- remove sign bit (1<<31)-1)
    return band(hash1, 0x7FFFFFFF), band(hash2, 0x7FFFFFFF)
end


local function _random_byte(seed1, seed2)
    seed1 = (seed1 * 3 + seed2) % MY_RND_MAX_VAL
    seed2 = (seed1 + seed2 + 33) % MY_RND_MAX_VAL

    return to_int(seed1 * 31 / MY_RND_MAX_VAL), seed1, seed2
end


local function _compute_old_token(password, scramble)
    if password == "" then
        return ""
    end

    scramble = sub(scramble, 1, LEN_OLD_SCRAMBLE)

    local hash_pw1, hash_pw2 = _pwd_hash(password)
    local hash_sc1, hash_sc2 = _pwd_hash(scramble)

    local seed1 = bxor(hash_pw1, hash_sc1) % MY_RND_MAX_VAL
    local seed2 = bxor(hash_pw2, hash_sc2) % MY_RND_MAX_VAL
    local rand_byte

    local bytes = new_tab(LEN_OLD_SCRAMBLE, 0)
    for i = 1, LEN_OLD_SCRAMBLE do
        rand_byte, seed1, seed2 = _random_byte(seed1, seed2)
        bytes[i] = rand_byte + 64
    end

    rand_byte = _random_byte(seed1, seed2)
    for i = 1, LEN_OLD_SCRAMBLE do
        bytes[i] = strchar(bxor(bytes[i], rand_byte))
    end

    return _to_cstring(concat(bytes))
end


local function _compute_sha256_token(password, scramble)
    if password == "" then
        return ""
    end

    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil, "failed to create the sha256 object"
    end

    if not sha256:update(password) then
        return nil, "failed to update string to sha256"
    end

    local message1 = sha256:final()

    sha256:reset()

    if not sha256:update(message1) then
        return nil, "failed to update string to sha256"
    end

    local message1_hash = sha256:final()

    sha256:reset()

    if not sha256:update(message1_hash) then
        return nil, "failed to update string to sha256"
    end

    if not sha256:update(scramble) then
        return nil, "failed to update string to sha256"
    end

    local message2 = sha256:final()

    local n = #message2
    local bytes = new_tab(n, 0)
    for i = 1, n do
        bytes[i] = strchar(bxor(strbyte(message1, i), strbyte(message2, i)))
    end

    return concat(bytes)
end

local function _compute_token(password, scramble)
    if password == "" then
        return ""
    end

    scramble = sub(scramble, 1, LEN_NATIVE_SCRAMBLE)

    local stage1 = sha1(password)
    local stage2 = sha1(stage1)
    local stage3 = sha1(scramble .. stage2)
    local n = #stage1
    local bytes = new_tab(n, 0)
    for i = 1, n do
        bytes[i] = strchar(bxor(strbyte(stage3, i), strbyte(stage1, i)))
    end

    return concat(bytes)
end



local function _from_length_coded_bin(data, pos)
    local first = strbyte(data, pos)

    --print("LCB: first: ", first)

    if not first then
        return nil, pos
    end

    if first >= 0 and first <= 250 then
        return first, pos + 1
    end

    if first == 251 then
        return null, pos + 1
    end

    if first == 252 then
        pos = pos + 1
        return _get_byte2(data, pos)
    end

    if first == 253 then
        pos = pos + 1
        return _get_byte3(data, pos)
    end

    if first == 254 then
        pos = pos + 1
        return _get_byte8(data, pos)
    end

    return nil, pos + 1
end


local function _from_length_coded_str(data, pos)
    local len
    len, pos = _from_length_coded_bin(data, pos)
    if not len or len == null then
        return null, pos
    end

    return sub(data, pos, pos + len - 1), pos + len
end


local function _parse_ok_packet(packet)
    local res = new_tab(0, 5)
    local pos

    res.affected_rows, pos = _from_length_coded_bin(packet, 2)

    --print("affected rows: ", res.affected_rows, ", pos:", pos)

    res.insert_id, pos = _from_length_coded_bin(packet, pos)

    --print("insert id: ", res.insert_id, ", pos:", pos)

    res.server_status, pos = _get_byte2(packet, pos)

    --print("server status: ", res.server_status, ", pos:", pos)

    res.warning_count, pos = _get_byte2(packet, pos)

    --print("warning count: ", res.warning_count, ", pos: ", pos)

    local message = _from_length_coded_str(packet, pos)
    if message and message ~= null then
        res.message = message
    end

    --print("message: ", res.message, ", pos:", pos)

    return res
end


local function _parse_eof_packet(packet)
    local pos = 2

    local warning_count, pos = _get_byte2(packet, pos)
    local status_flags = _get_byte2(packet, pos)

    return warning_count, status_flags
end

local function _parse_err_packet(packet)
    local errno, pos = _get_byte2(packet, 2)
    local marker = sub(packet, pos, pos)
    local sqlstate
    if marker == '#' then
        -- with sqlstate
        pos = pos + 1
        sqlstate = sub(packet, pos, pos + 5 - 1)
        pos = pos + 5
    end

    local message = sub(packet, pos)
    return errno, message, sqlstate
end

local function _make_err_packet(errno, errmsg, sqlstate, pktno)
    local bytes = strchar(0xff) -- Packet Type is ERR
    bytes =  bytes .. _set_byte2(errno)
    if sqlstate then 
        bytes = bytes .. format("#%04d", sqlstate)
    end
    bytes = bytes .. errmsg
    local length = #bytes
    local pktno = pktno or 1
    bytes = _set_byte3(length).. strchar(pktno) .. bytes
    return bytes
end

local function _parse_result_set_header_packet(packet)
    local field_count, pos = _from_length_coded_bin(packet, 1)

    local extra
    extra = _from_length_coded_bin(packet, pos)

    return field_count, extra
end


local function _parse_field_packet(data)
    local col = new_tab(0, 2)
    local catalog, db, table, orig_table, orig_name, charsetnr, length
    local pos
    catalog, pos = _from_length_coded_str(data, 1)

    --print("catalog: ", col.catalog, ", pos:", pos)

    db, pos = _from_length_coded_str(data, pos)
    table, pos = _from_length_coded_str(data, pos)
    orig_table, pos = _from_length_coded_str(data, pos)
    col.name, pos = _from_length_coded_str(data, pos)

    orig_name, pos = _from_length_coded_str(data, pos)

    pos = pos + 1 -- ignore the filler

    charsetnr, pos = _get_byte2(data, pos)

    length, pos = _get_byte4(data, pos)

    col.type = strbyte(data, pos)

    --[[
    pos = pos + 1

    col.flags, pos = _get_byte2(data, pos)

    col.decimals = strbyte(data, pos)
    pos = pos + 1

    local default = sub(data, pos + 2)
    if default and default ~= "" then
        col.default = default
    end
    --]]

    return col
end

local function _parse_row_data_packet(data, cols, compact)
    local pos = 1
    local ncols = #cols
    local row
    if compact then
        row = new_tab(ncols, 0)
    else
        row = new_tab(0, ncols)
    end
    for i = 1, ncols do
        local value
        value, pos = _from_length_coded_str(data, pos)
        local col = cols[i]
        local typ = col.type
        local name = col.name

        --print("row field value: ", value, ", type: ", typ)

        if value ~= null then
            local conv = converters[typ]
            if conv then
                value = conv(value)
            end
        end

        if compact then
            row[i] = value

        else
            row[name] = value
        end
    end

    return row
end

local _M={}

_M.Packet={
    desc="BasePacket",
    parseHeader=function(self,headerBytes,cursor)
        self.dataLength, cursor = _get_byte3(headerBytes, 1)
        self.packet_no = strbyte(headerBytes, cursor)
        return cursor
    end,
    
    --skipHeaderCursor indicates that header was parsed, just skip the header part and directly parse payload part
    parse=function(self,allBytes,pos)
        pos=self:parseHeader(allBytes)
        self:parsePayload(allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
    
    parsePayload=function(self,allbytes,pos) 
        ngx.log(ngx.ERR, "Packet:parsePayload ")
        return  self 
    end,

    makeErrorResponse=function(errno, errmsg, sqlstate)
        return _make_err_packet(errno, errmsg, sqlstate)
    end,
   
    new=function(self,o) 
        local o=o or {}
        return orderTable.new(self,o)
    end,
}

local COM_LOGIN = 0x00
local COM_QUIT  = 0x01
local COM_INIT_DB  = 0x02
local COM_QUERY = 0x03
local COM_FIELD_LIST = 0x04
local COM_STATISTICS = 0x08
local COM_DEBUG = 0x0D
local COM_PING = 0x0E
local COM_CHANGE_USER = 0x11
local COM_STMT_PREPARE = 0x16

local COM_RESET_CONNECTION = 0x1F
local COM_SET_OPTION = 0x1A

local RES_WELCOME = 0x10
local RES_LOGIN = 0x11
local RES_QUERY = 0x13


local _get_req = function(packet)
    local data = string.sub(packet, 5)

    return data
end
_M.Login={
    code=COM_LOGIN,
    parsePayload=function(self,bytes,cursor)
        local packet = _get_req(bytes)
        local pos = 1
        self.success = false
        self.client_info = {}
        self.client_info.capabilities, pos = _get_byte4(packet, pos)
        self.client_info.cli_max_packet_size, pos = _get_byte4(packet, pos)
        self.client_info.char_set = strbyte(packet, pos)
        pos = pos + 20 -- skip filler(19 + 1)
        self.client_info.extends_capabilities, pos = _get_byte4(packet, pos)
        self.username, pos = _from_cstring(packet, pos)
        self.password = ""        
        local passwd_length = strbyte(packet, pos)
        
        if (passwd_length > 0) then
            local passwd = ""
            for i = pos + 1, pos + passwd_length do
                local b = format("%02x", strbyte(packet, i))
                passwd = passwd .. b
            end
            self.password = passwd
            pos = pos + passwd_length + 1
        end
        if band(self.client_info.capabilities, CLIENT_CONNECT_WITH_DB) > 0 then
            self.client_info.dabatase, pos = _from_cstring(packet, pos)
        end
        if band(self.client_info.capabilities, CLIENT_PLUGIN_AUTH) > 0 then
            self.client_info.plugin, pos = _from_cstring(packet, pos)
        end
        return self
    end,
    
}
extends(_M.Login,_M.Packet)

_M.SQLQuery={
    code=COM_QUERY,
    parsePayload=function(self,bytes,cursor)
        local packet = _get_req(bytes)
        self.success = true

        local pkt_type = strbyte(packet, 1)
        
        if (pkt_type ~= COM_QUERY) then
            if (pkt_type == COM_QUIT) then
                self.sql = "QUIT"
                return self
            elseif pkt_type == COM_INIT_DB then
                local dbname = sub(packet, 2)
                self.sql = "USE " .. dbname
                self.database = dbname
                return self
            else
                self.success = false
                return self
            end
        end

        local query = sub(packet, 2)
        self.sql = query
        return self
    end,
    
}
extends(_M.SQLQuery,_M.Packet)


_M.QUIT={
    code=COM_QUIT,
    parsePayload=function(self,bytes,cursor)
        local packet = _get_req(bytes)
        self.success = true

        local pkt_type = strbyte(packet, 1)
        
        if (pkt_type ~= COM_QUIT) then
            self.success = false
            return self
        end

        local query = "QUIT"
        self.sql = query
        return self
    end,
    
}
extends(_M.QUIT,_M.Packet)

_M.RESP_OK = "OK"
_M.RESP_AUTHMOREDATA = "AUTHMOREDATA"
_M.RESP_LOCALINFILE = "LOCALINFILE"
_M.RESP_EOF = "EOF"
_M.RESP_ERR = "ERR"
_M.RESP_DATA = "DATA"

_M.READ_INIT = "READ INIT"
_M.READ_HDR  = "READ HEADER"
_M.READ_ROWS = "READ ROWS"
_M.READ_COLS = "READ COLS"

local _get_reponse = function(packet)
    local data = string.sub(packet, 5)
    local field_count = strbyte(data, cursor)
    local pktno = strbyte(packet, 4)

    local typ
    if field_count == 0x00 then
        typ = _M.RESP_OK
    --elseif field_count == 0x01 then
    --    typ = _M.RESP_AUTHMOREDATA
    elseif field_count == 0xfb then
        typ = _M.RESP_LOCALINFILE
    elseif field_count == 0xfe then
        typ = _M.RESP_EOF
    elseif field_count == 0xff then
        typ = _M.RESP_ERR
    else
        typ = _M.RESP_DATA
    end

    return data, typ, pktno
end

function _M.packErrorResponse(message,errNo)

end


_M.Welcome={
    code=RES_WELCOME,
    parsePayload=function(self,allbytes,cursor)
        self.success = false
        self.err = {}
        self.err.errno = 0
        local packet, typ, pktno = _get_reponse(allbytes)
        self.pktno = pktno
        if typ == _M.RESP_ERR then
            self.success = false            
            self.err.errno, self.err.msg, self.err.sqlstate = _parse_err_packet(packet)
            return self
        end
        self.server_info = {}
        local protocol_ver = tonumber(strbyte(packet,1))
        if not protocol_ver then
            self.err.msg = "bad handshake initialization packet: bad protocol version"
            ngx.log(ngx.ERR, self.err.msg)
            return self
        end
        if protocol_ver < MIN_PROTOCOL_VER then
            self.err.msg = "unsupported protocol version " .. protocol_ver
                            .. ", version " .. MIN_PROTOCOL_VER
                            .. " or higher is required"
            ngx.log(ngx.ERR, self.err.msg)
            return self
        end

        self.server_info.protocol_ver = protocol_ver
        local server_ver, pos = _from_cstring(packet, 2)
        if not server_ver then
            self.err.msg = "bad handshake initialization packet: bad server version"
            return self
        end
        self.server_info.server_ver = server_ver
        local thread_id, pos = _get_byte4(packet, pos)
        local scramble = sub(packet, pos, pos + 8 - 1)
        if not scramble then
            return nil, nil, "1st part of scramble not found"
        end
        pos = pos + 9 -- skip filler(8 + 1)
        -- two lower bytes
        local capabilities  -- server capabilities
        capabilities, pos = _get_byte2(packet, pos)
        self.server_info._server_lang = strbyte(packet, pos)
        pos = pos + 1
        self.server_info._server_status, pos = _get_byte2(packet, pos)
        local more_capabilities
        more_capabilities, pos = _get_byte2(packet, pos)
        self.server_info.capabilities = bor(capabilities, lshift(more_capabilities, 16))
        pos = pos + 11 -- skip length of auth-plugin-data(1) and reserved(10)
        local scramble_part2 = sub(packet, pos, pos + 12 - 1)
        if not scramble_part2 then
            return nil, nil, "2nd part of scramble not found"
        end
        pos = pos + 13
        local plugin, _
        if band(self.server_info.capabilities, CLIENT_PLUGIN_AUTH) > 0 then
            plugin, _ = _from_cstring(packet, pos)
            if not plugin then
                -- EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
                -- \NUL otherwise
                plugin = sub(packet, pos)
            end
    
        else
            plugin = DEFAULT_AUTH_PLUGIN
        end

        self.server_info.plugin = plugin
        self.success = true
        return self
    end,
}
extends(_M.Welcome,_M.Packet)

_M.LoginResponse={
    code=RES_LOGIN,
    parsePayload=function(self,allbytes,cursor)
        self.success = false
        self.err = {}
        self.err.errno = 0
        local packet, typ = _get_reponse(allbytes)
        if typ == _M.RESP_ERR then
            self.success = false            
            self.err.errno, self.err.msg, self.err.sqlstate = _parse_err_packet(packet)
            return self
        end
        
        if typ == _M.RESP_OK then
            self.success = true            
            return self
        end
        self.success = true
        return self
    end,
}
extends(_M.LoginResponse,_M.Packet)

_M.SQLResponse={
    code=RES_QUERY,
    parsePayload=function(self,bytes,cursor)
        self.success = true
        self.err = {}
        self.err.errno = 0
        local packet, typ, pktno = _get_reponse(bytes)
        
        self.pktno = pktno

        self.type = typ

        if typ == _M.RESP_ERR then
            self.success = false            
            self.err.errno, self.err.msg, self.err.sqlstate = _parse_err_packet(packet)
        elseif typ == _M.RESP_OK then
            self.res = _parse_ok_packet(packet)
        elseif typ == _M.RESP_EOF then
            local warning_count, status_flags = _parse_eof_packet(packet)
            self.res = {warning_count=warning_count, status_flags=status_flags}
        elseif typ == _M.RESP_DATA then
            self.res = {packet = packet}
        else

        end
        return self
    end,
}
extends(_M.SQLResponse,_M.Packet)

return _M