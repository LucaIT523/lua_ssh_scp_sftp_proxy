--function scandir(directory)
--    local i, t, popen = 0, {}, io.popen
--    local pfile = popen('dir  "'..directory..'*.lua" /b')
--    for filename in pfile:lines() do
--        i = i + 1
--        t[i] = filename
--    end
--    pfile:close()
--    return t
--end
--local currentDir=debug.getinfo(1).source:sub(1,#debug.getinfo(1).source-8)
--print(currentDir)
--local files=scandir("C:\\env\\openresty-1.15.8.3-win64\\lualib\\gateway\\")
--for i,v in ipairs (files) do
--  print(v)
--  local mod=require("strmproxy."..v:sub(1,#v-4))
--  if mod.test then
--    mod.test()
--  end
--end
print("start testing")
local m=require "strmproxy.utils.compatibleLog"
m.test()
m=require "strmproxy.utils.datetime"
m.test()
m=require "strmproxy.utils.event"
m.test()
m=require "strmproxy.utils.pureluapack"
m.test()
m=require "strmproxy.utils.tableUtils"
m.test()
m=require "strmproxy.utils.unicode"
m.test()
m=require "strmproxy.tns.tnsPackets"
m.test()
m=require "strmproxy.tds.tdsPackets"
m.test()
m=require "strmproxy.ssh2.shellCommand"
m.test()
m=require "strmproxy.ldap.ldapPackets"
m.test()
m=require "strmproxy.balancer.balancer"
m.test()

print("All test finished without error")