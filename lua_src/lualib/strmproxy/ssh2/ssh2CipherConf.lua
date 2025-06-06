local bn = require "resty.openssl.bn"
local rand= require  "resty.openssl.rand"
local tableUtils = require "strmproxy.utils.tableUtils"
local log = require "strmproxy.utils.compatibleLog"

local _M={}

_M.EncAlg={
    {name="aes128-ctr",cipherStr="aes-128-ctr"},
    {name="aes128-cbc",cipherStr="aes-128-cbc"}
    --{name="aes192-ctr",cipherStr="aes-192-ctr"},
    --{name="aes192-cbc",cipherStr="aes-192-cbc"},
    --{name="aes256-ctr",cipherStr="aes-256-ctr"},
    --{name="aes256-cbc",cipherStr="aes-256-cbc"},
    --{name="chacha20-poly1305",cipherStr="chacha20-poly1305"}
}
function _M.EncAlg:getList()
    local rs={}
    for i,v in ipairs(self) do
        rs[#rs+1]=v.name
    end
    return table.concat(rs,",")
end

--[[
_M.HmacAlg={
    {name="'hmac-sha2-256'",cipherStr="'hmac-sha2-256'"},
    {name="'hmac-sha2-512'",cipherStr="'hmac-sha2-512'"},
    {name="'hmac-sha1'",cipherStr="'hmac-sha1'"}
}
function _M.HmacAlg:getList()
    local rs={}
    for i,v in ipairs(self) do
        rs[#rs+1]=v.name
    end
    return table.concat(rs,",")
end
]]

_M.DHAlg={}
--http://ietf.org/rfc/rfc3526.txt
_M.DHAlg[#(_M.DHAlg)+1]={
    name="diffie-hellman-group14-sha256",
    p=bn.from_binary(string.fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    ]])),
    shaAlg="sha256"}
_M.DHAlg[#(_M.DHAlg)+1]={
    name="diffie-hellman-group14-sha1",
    p=bn.from_binary(string.fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    ]])),
    shaAlg="sha1"
}
_M.DHAlg[#(_M.DHAlg)+1]={
    name="diffie-hellman-group1-sha1",
    p=bn.from_binary(string.fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
    ]])),
    shaAlg="sha1"
}
function _M.DHAlg:getList()
    local rs={}
    for i,v in ipairs(self) do
        rs[#rs+1]=v.name
    end
    return table.concat(rs,",")
end

--todo should be random bytes
_M.y=bn.from_binary(rand.bytes(1024))
_M.x=bn.from_binary(rand.bytes(1024))

--key pair used for KEX
-- _M.pubkey=
-- [[
-- -----BEGIN RSA PUBLIC KEY-----
-- MIIBCgKCAQEAyfPdItqWAL0kLjr4C9FJUm1nyRqNePUfAEHZqH+zQDnUmRUnJc/t
-- YvViQwoBS4O21LbEJJJyA2UQ3LsiCj6l511uTJKjs43jS8uufLamnZkovfnj766V
-- AQuGLb/LL28kbDNrjEBILG7Z1SjKOMcj8ltt5Jno3hy8QbufK+9nk1AyjvJy2xxg
-- mAUYOXxI8hYOmIybdL06sKmnqn3CcBjHm5al426f91BgZk0uiaK+8Tq3fVi36fss
-- o5ZGI3V64zRF+FCE80RvGW3S4ErUm95+SwLRjVav6keCQXYfVHiQ9sacLxjuVve4
-- /UKjlFztG8+U/ZrIO5GgHEEc8px2s5mqMwIDAQAB
-- -----END RSA PUBLIC KEY-----
-- ]]
-- _M.privkey=
-- [[
-- -----BEGIN RSA PRIVATE KEY-----
-- MIIEowIBAAKCAQEAyfPdItqWAL0kLjr4C9FJUm1nyRqNePUfAEHZqH+zQDnUmRUn
-- Jc/tYvViQwoBS4O21LbEJJJyA2UQ3LsiCj6l511uTJKjs43jS8uufLamnZkovfnj
-- 766VAQuGLb/LL28kbDNrjEBILG7Z1SjKOMcj8ltt5Jno3hy8QbufK+9nk1AyjvJy
-- 2xxgmAUYOXxI8hYOmIybdL06sKmnqn3CcBjHm5al426f91BgZk0uiaK+8Tq3fVi3
-- 6fsso5ZGI3V64zRF+FCE80RvGW3S4ErUm95+SwLRjVav6keCQXYfVHiQ9sacLxju
-- Vve4/UKjlFztG8+U/ZrIO5GgHEEc8px2s5mqMwIDAQABAoIBAFsWEZxhyJxGsuXj
-- FPOHjrGNxOzQfBSdQkFEch5sknWaX8g34TNNx/0FPi+MeK8Nlk30rRztrFzZnbRg
-- 9uZ2ATAMVO5WiV031tfd4zI+04FrjhO5fNQjAvO4tek2gzc+wsfGnXBhoevgh4F7
-- 51GaiB0MndEolf5wKXzgWddgIHAxQ3pgqTqBhCvr0h/U0VxGkntqqEDIzRKohB0D
-- hd5MXP9hCdTTOud9Kfy/2DKl0a8UWC6N5oyT1EhmGI011Fpc3J+svIbd9fPnRo4B
-- RoAaiKWezYOja6ruRYZo9+GBtjznV1IGlK9EttMv9W5MbCDyFGU4/MoNmal9pAUz
-- +HrX/aECgYEA7fG5QWYY6YLCs5UEpwC6jxD5uTXR8LA5JP8VxNLHA4/HCY3nXThC
-- 800iEWfdgLtdN3H95KslW+E7WLoT7hdONZKKcGq6zBywa4JawUXt8jMravhN17os
-- 6DTEOHtUE6WETUslJhK0o3232h8wo2dZ99lPiA00Uk8nKUku0CMVULECgYEA2Ub4
-- iUZKpCHGJ+HjnKINbua36TATBEVY3myr8XBwHDJIAB+LyK+DwJ9QiXJDKnlDGsa8
-- XEdYaRkUYNIcZgVnTF4s3O1BuGFXBbc7Av+Z85zLtSo/1kDn9YI92Los9APPffdu
-- UMtbIj9eXqtzVg1DjWcbhZQZAi8uONGEvh+CQiMCgYBIlayFnreKxDDQx2yb5UUD
-- z5HeReS9H4TPHGFvoTzEgV+eMoOZlEgYIDd8R8ryMjXFbCifUPYciSCpeFoMD1/0
-- R7ejg2toSHgo06MLwmFLuQBNqWFVpZ19WFtjP3vuYldxnLLAYoRoOzmSeGFF94ki
-- alAwmJaVZT/1ADYfmBQwgQKBgFRokd0ihZTF2ilcRARxoC5ZS1E37+tU1XVzWkjt
-- mWAa2IXTu4Y3SUPnoG4FCbrSaRNZ6Ysf3GTX7Wa/uXCY4Mx2OY+KTGHIzvnVeQNt
-- MO3HGAxFYY9mn7Zs5oHvsc8KO+1/1kdk+P6RB6RXjvL7LCceyz5VjnGeyqIgIyWJ
-- MB1pAoGBAN2ztGq/yOpNwiCrxeeDpoFe7iQHznaXIgK7yA+uFFUUT58/bl87kq9/
-- huKG4OgDnZ+iHeSk9CFNseGZHIdcliTDGnud7ipOCFJCzjtlCcM/oHl1hL7oCJUL
-- GrUlhvtkRKRV96mCDIEGxKCB0xzqjXKAgzTGApCQ9RUKG5EbNSnC
-- -----END RSA PRIVATE KEY-----
-- ]]

local def_pubkey =
[[
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyfPdItqWAL0kLjr4C9FJUm1nyRqNePUfAEHZqH+zQDnUmRUnJc/t
YvViQwoBS4O21LbEJJJyA2UQ3LsiCj6l511uTJKjs43jS8uufLamnZkovfnj766V
AQuGLb/LL28kbDNrjEBILG7Z1SjKOMcj8ltt5Jno3hy8QbufK+9nk1AyjvJy2xxg
mAUYOXxI8hYOmIybdL06sKmnqn3CcBjHm5al426f91BgZk0uiaK+8Tq3fVi36fss
o5ZGI3V64zRF+FCE80RvGW3S4ErUm95+SwLRjVav6keCQXYfVHiQ9sacLxjuVve4
/UKjlFztG8+U/ZrIO5GgHEEc8px2s5mqMwIDAQAB
-----END RSA PUBLIC KEY-----
]]

local def_privkey=
[[
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyfPdItqWAL0kLjr4C9FJUm1nyRqNePUfAEHZqH+zQDnUmRUn
Jc/tYvViQwoBS4O21LbEJJJyA2UQ3LsiCj6l511uTJKjs43jS8uufLamnZkovfnj
766VAQuGLb/LL28kbDNrjEBILG7Z1SjKOMcj8ltt5Jno3hy8QbufK+9nk1AyjvJy
2xxgmAUYOXxI8hYOmIybdL06sKmnqn3CcBjHm5al426f91BgZk0uiaK+8Tq3fVi3
6fsso5ZGI3V64zRF+FCE80RvGW3S4ErUm95+SwLRjVav6keCQXYfVHiQ9sacLxju
Vve4/UKjlFztG8+U/ZrIO5GgHEEc8px2s5mqMwIDAQABAoIBAFsWEZxhyJxGsuXj
FPOHjrGNxOzQfBSdQkFEch5sknWaX8g34TNNx/0FPi+MeK8Nlk30rRztrFzZnbRg
9uZ2ATAMVO5WiV031tfd4zI+04FrjhO5fNQjAvO4tek2gzc+wsfGnXBhoevgh4F7
51GaiB0MndEolf5wKXzgWddgIHAxQ3pgqTqBhCvr0h/U0VxGkntqqEDIzRKohB0D
hd5MXP9hCdTTOud9Kfy/2DKl0a8UWC6N5oyT1EhmGI011Fpc3J+svIbd9fPnRo4B
RoAaiKWezYOja6ruRYZo9+GBtjznV1IGlK9EttMv9W5MbCDyFGU4/MoNmal9pAUz
+HrX/aECgYEA7fG5QWYY6YLCs5UEpwC6jxD5uTXR8LA5JP8VxNLHA4/HCY3nXThC
800iEWfdgLtdN3H95KslW+E7WLoT7hdONZKKcGq6zBywa4JawUXt8jMravhN17os
6DTEOHtUE6WETUslJhK0o3232h8wo2dZ99lPiA00Uk8nKUku0CMVULECgYEA2Ub4
iUZKpCHGJ+HjnKINbua36TATBEVY3myr8XBwHDJIAB+LyK+DwJ9QiXJDKnlDGsa8
XEdYaRkUYNIcZgVnTF4s3O1BuGFXBbc7Av+Z85zLtSo/1kDn9YI92Los9APPffdu
UMtbIj9eXqtzVg1DjWcbhZQZAi8uONGEvh+CQiMCgYBIlayFnreKxDDQx2yb5UUD
z5HeReS9H4TPHGFvoTzEgV+eMoOZlEgYIDd8R8ryMjXFbCifUPYciSCpeFoMD1/0
R7ejg2toSHgo06MLwmFLuQBNqWFVpZ19WFtjP3vuYldxnLLAYoRoOzmSeGFF94ki
alAwmJaVZT/1ADYfmBQwgQKBgFRokd0ihZTF2ilcRARxoC5ZS1E37+tU1XVzWkjt
mWAa2IXTu4Y3SUPnoG4FCbrSaRNZ6Ysf3GTX7Wa/uXCY4Mx2OY+KTGHIzvnVeQNt
MO3HGAxFYY9mn7Zs5oHvsc8KO+1/1kdk+P6RB6RXjvL7LCceyz5VjnGeyqIgIyWJ
MB1pAoGBAN2ztGq/yOpNwiCrxeeDpoFe7iQHznaXIgK7yA+uFFUUT58/bl87kq9/
huKG4OgDnZ+iHeSk9CFNseGZHIdcliTDGnud7ipOCFJCzjtlCcM/oHl1hL7oCJUL
GrUlhvtkRKRV96mCDIEGxKCB0xzqjXKAgzTGApCQ9RUKG5EbNSnC
-----END RSA PRIVATE KEY-----
]]

local function load_key(filepath, default_key)
    log.dbg("> load key: ", filepath)
    local file, err = io.open(filepath, "r")
    if not file then
        -- ngx.log(ngx.ERR, "Failed to open ", filepath, err and " err: " .. err or "")
        return default_key
    end
    
    local data = file:read("*a")
    
    file:close()
    
    return data
end

_M.pubkey=load_key(ngx.var.ssh_rsa_public_key, def_pubkey)
_M.privkey=load_key(ngx.var.ssh_rsa_private_key, def_privkey)

return _M