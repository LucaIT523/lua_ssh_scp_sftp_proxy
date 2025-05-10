local tableUtils=require "strmproxy.utils.tableUtils"
local _M={}

_M.STDERR ={code=0x00,ngxCode=0x00,desc="STDERR"}
_M.EMERG  ={code=0x01,ngxCode=0x01,desc="EMERG" }
_M.ALERT  ={code=0x02,ngxCode=0x02,desc="ALERT" }
_M.CRIT   ={code=0x03,ngxCode=0x03,desc="CRIT"  }
_M.ERR    ={code=0x04,ngxCode=0x04,desc="ERR"   }
_M.WARN   ={code=0x05,ngxCode=0x05,desc="WARN"  }
_M.NOTICE ={code=0x06,ngxCode=0x06,desc="NOTICE"}
_M.INFO   ={code=0x07,ngxCode=0x07,desc="INFO"  }
_M.DEBUG  ={code=0x08,ngxCode=0x08,desc="DEBUG" }

local _ngxMapping={
    [0x00]=_M.STDERR, [0x01]=_M.EMERG , [0x02]=_M.ALERT , 
    [0x03]=_M.CRIT  , [0x04]=_M.ERR   , [0x05]=_M.WARN  , 
    [0x06]=_M.NOTICE, [0x07]=_M.INFO  , [0x08]=_M.DEBUG , 
}

local _logLevel=_M.DEBUG

function _M.logInner(level,stackUpLevel,...)
    level=level or _M.NOTICE
    stackUpLevel=stackUpLevel or 2
    local args={...}
    local func=debug.getinfo(stackUpLevel).short_src ..":"..debug.getinfo(stackUpLevel).currentline
    local ok,ngxLog=pcall(require,"ngx.errlog")
    if ok and ngxLog then 
         ngxLog.raw_log(level.ngxCode,func..": "..tableUtils.concat(args)) 
    elseif level.code<=_logLevel.code then
        print(level.desc,func,":",tableUtils.concat(args)) 
    end
end
--[[
function _M.logInner(level,stackUpLevel,...)
    level=level or _M.NOTICE
    stackUpLevel=stackUpLevel or 2
    local args={...}
    local traceInfo = debug.getinfo(stackUpLevel, "Sln")
    local file      = traceInfo.source:match("([^/]+)$")
    local line      = traceInfo.currentline
    local func      = _M.traceCallStack(stackUpLevel)
    local traceInfo = string.format("[\027[1;3m%s:\027[33m%d:%s\027[0m]%s", file, line, func, tableUtils.concat(args))
    local ok,ngxLog = pcall(require,"ngx.errlog")
    if ok and ngxLog then 
        ngxLog.raw_log(level.ngxCode,traceInfo) 
    elseif level.code <= _logLevel.code then
        print(level.desc,traceInfo) 
    end
end
]]

function _M.log(level,...)
    _M.logInner(level,3,...)
end

function _M.logWithTitle(level,title,...)
    local l=(80-#title)/2
    local l=l >= 0 and l or 0
    _M.logInner(level,3,"\r\n"..string.rep("-",l)..title..string.rep("-",l).."\r\n",...)
end

 function _M.getLogLevel()
    local ok,ret=pcall(require,"ngx.errlog")
    if ok then _logLevel= _ngxMapping[ret.get_sys_filter_level()] end
    return _logLevel
end

function _M.setLogLevel(level)
    _logLevel=level
    local ok,ret=pcall(require,"ngx.errlog")
    if ok then 
        local status,err=ret.set_filter_level(level.ngxCode)
        if not status then
            ngx.log(ngx.ERR, err)
        end
    end
end

function _M.stderr(...) _M.logInner(_M.STDERR,3,...) end
function _M.emrg(...) _M.logInner(_M.EMERG,3,...) end
function _M.alrt(...) _M.logInner(_M.ALERT,3,...) end
function _M.cri(...) _M.logInner(_M.CRIT,3,...) end
function _M.err(...) _M.logInner(_M.ERR,3,...) end
function _M.wrn(...) _M.logInner(_M.WARN,3,...) end
function _M.ntc(...) _M.logInner(_M.NOTICE,3,...) end
function _M.inf(...) _M.logInner(_M.INFO,3,...) end
function _M.dbg(...) _M.logInner(_M.DEBUG,3,...) end

function _M.dbgWithTitle(title,...)
    local l = (80-#title)/2
    local dash = string.rep("-", (l>=0 and l or 0))
    _M.logInner(_M.DEBUG,3,dash.."["..title.."]"..dash.."\r\n", ...)
end

function _M.errWithTitle(title,...)
    local l = (80-#title)/2
    local dash = string.rep("-", (l>=0 and l or 0))
    _M.logInner(_M.ERR,3,dash.."["..title.."]"..dash.."\r\n", ...)
end

function _M.traceCallStack(stackUpLevel)
    local _func_
    local level = stackUpLevel or 3
    local info

    if "on" == ngx.var.trace_call_stack then
        local callstack = {}
        
        while true do
            info = debug.getinfo(level, "n")
            if not info then
                break
            end
            if info.what == "C" then
                -- print("[C]")
                table.insert(callstack, "[C]")
            elseif info.name then
                -- print(info.name)
                table.insert(callstack, info.name)
            end
            level = level + 1
        end
    
        local len = #callstack
        for i, _ in ipairs(callstack) do
            if not _func_ then
                if len == 1 then
                    _func_ = "\027[35m@"
                    break
                end
                _func_ = "\027[34m" .. callstack[len]
            else
                if len == 1 then
                    break
                end
                _func_ = _func_ .. "\027[31m<-\027[32m" .. callstack[len]
            end
            len = len - 1
        end
    else
        level = level + 1
        info = debug.getinfo(level, "n")
        if info.what == "C" then
            _func_ = "[C]"
        elseif info.name then
            _func_ = info.name
        end
        _func_ = _func_ and ("\027[32m" .. _func_) or "\027[36m@handler"
    end
    _func_ = _func_ .. "\027[0m"

    return _func_
end

_M.unitTest={}

function _M.test()
    _M.setLogLevel(_M.ERR)
    _M.log(_M.DEBUG,"abc",1,nil,{})
    _M.logWithTitle(_M.ERR,"abc",1,nil,{},6)
    _M.setLogLevel(_M.DEBUG)
    _M.log(_M.DEBUG,"abc",1,nil,{})
    _M.logWithTitle(_M.ERR,"abc",1,nil,{},6)
end

return _M
