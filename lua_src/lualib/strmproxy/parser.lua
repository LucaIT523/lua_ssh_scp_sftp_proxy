require "strmproxy.utils.stringUtils"
local event=require "strmproxy.utils.event"
local logger=require "strmproxy.utils.compatibleLog"
local tableUtils=require "strmproxy.utils.tableUtils"

local _M={}

function _M:new()
    local o=setmetatable({},{__index=self})
    o.events={}
    o.parserList={}
    o.defaultParseEvent=event:newReturnEvent(nil,"defaultParseEvent")

    -- Added an option to choose parsing ---------------------------------------
    o.skip_parse=false
    -------------------------------------- Added an option to choose parsing ---
    return o
end

function _M:register(key,parserName,parser,eventName,e)
    assert(not self.parserList[key],string.format("unable to register parser %s, key already registered",key))
    if eventName then 
        assert(not self.events[eventName],string.format("unable to register event %s, event already registered",eventName)) 
        e=e or event:new(nil,eventName) 
        self.events[eventName]=e
    end
    self.parserList[key]={parser=parser,parserName=parserName,event=e}
end

function _M:unregister(key,eventName)
    self.parserList[key]=nil
    if eventName then
        self.events[eventName]=nil
    end
end

function _M:getParser(key)
    return self.parserList[key]
end

function _M:registerMulti(t)
    for i,v in ipairs(t) do
        local parserName
        if v.parser then parserName=v.parserName or v.parser.desc or tostring(v.parser) end
        self:register(v.key,parserName,v.parser,v.eventName,v.e)
    end
end

function _M:registerDefaultParser(parser)
    assert(parser,"default parser can not be null")
    self.defaultParser=parser
end

function _M.printPacket(packet,allBytes,key,parserName,...)
    if "on" == ngx.var.debug_packet then
        local args={...}
        local log
        if not parserName then
            log = string.format("packet with key (%s) doesn't have parser ", key)
        else
            log = string.format("packet with key (%s) will be parsed by parser '%s'", key, (parserName or "Unknown"))
        end
        logger.dbgWithTitle(log)
        -- logger.dbg("\r\npacket:" .. tableUtils.printTableF(packet,{ascii=true,excepts={"allBytes"}}))
        logger.dbg("\r\n PPPPPPPPPPPPPPPPPPP   common packet:" .. tableUtils.printTable(packet,{skip_array=true, skip_allBytes=false}))
    end
end

--static method to  parse all kinds of packets
function _M:parse(allBytes, pos, key, ...)
    if true == self.skip_parse then
        logger.dbg("> skip parsing")
        return packet
    end
    
    pos=pos or 1
    assert(allBytes,"bytes stream can not be null")
    
    if not key then key=self.keyGenerator end
    if type(key)=="function" then
        key=key(allBytes,pos,...)
    end
    assert(key,"key can not be null")
    local packet={}
    packet.allBytes=allBytes
    local parser, event, newBytes, parserName
    if self.parserList[key] then
        parser=self.parserList[key].parser
        parserName=self.parserList[key].parserName
        if self.parserList[key].event then
            event = self.parserList[key].event
        end
    end

    if not parser and self.defaultParser then
        parser=self.defaultParser
        parserName="Default Parser"
    end
    
    event = event or self.defaultParseEvent

    local args={...}
    local ok=true 
    local ret
    if parser then
        logger.dbg(">[parse] parserName: ", parserName)
        ok, ret = xpcall(
            function()
                -- logger.dbg( debug.traceback())
                return parser:new(nil,unpack(args)):parse(allBytes,pos,unpack(args))
            end,
            function(err)
                -- logger.err(err)
                logger.err(">[parse] ERROR: " .. err)
                logger.err( debug.traceback())
            end,
            "error when parsing."
        )

        if ok then
            packet = ret
            -- if logger.getLogLevel().code>=logger.DEBUG.code then
                _M.printPacket(packet,allBytes,key,parserName,...)
            -- end
        end
    end

    packet.__key = packet.__key or key

    if ok and event and event:hasHandler() then
        logger.dbg(">[parse] triggered event: ", event.name)
        xpcall(
            function()
                return event:trigger(packet, allBytes, key, unpack(args))
            end,
            function(err)
                -- logger.err(err)
                logger.err(">[parse] ERROR: " .. err)
                logger.err(debug.traceback())
            end,
            "error when exe parser handler "
        )
    end

    return packet
end

_M.doParse=doParse
return _M