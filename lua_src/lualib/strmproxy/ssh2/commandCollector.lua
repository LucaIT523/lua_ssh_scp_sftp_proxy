local ssh2Packet=require "strmproxy.ssh2.ssh2Packets"
local sc=require"strmproxy.ssh2.shellCommand"
local event=require "strmproxy.utils.event"
local logger=require "strmproxy.utils.compatibleLog"

local _M={}

function _M:new() 
    local o=setmetatable({}, {__index=self})
    o.reply=""
    o.commandReply=""
    o.welcome=""
    o.command=sc:new()
    o.firstReply=true
    o.BeforeWelcomeEvent=event:newReturnEvent(o,"BeforeWelcomeEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent")
    return o
end

local function removeANSIEscape(str)
    return str:gsub(string.char(0x1b).."[%[%]%(][0-9%:%;%<%=%>%?]*".."[@A-Z%[%]%^_`a-z%{%|%}%~]","")
end

local function removeUnprintableAscii(str)
    local filterAsciiCharacters = function(x)
            if (string.byte(x)<=31 or string.byte(x)==127) and (string.byte(x)~=0x0d) then 
                return ""
            end
            return x
        end
    return str:gsub(".", filterAsciiCharacters)
end

function _M:handleDataUp(processor,packet,ctx)
    self.waitForWelcome=false
    --[[ 
    logger.dbg(">[handleDataUp] waitForReply: " .. tostring(self.waitForReply))
    self.waitForWelcome=false
    if self.waitForReply then
        self.waitForReply=false
        if self.commandReply and self.commandReply ~="" then
            logger.dbg("--------------\r\n",self.commandReply)
            local reply=removeANSIEscape(self.commandReply)
            self.CommandFinishedEvent:trigger(self.lastCommand,reply,ctx)
        end
    end
    ]]
    self.reply=""
    self.commandReply=""
    local channel=packet.channel
    local letter=packet.data
    local ascii = string.byte(letter,1)
    -- logger.dbg("-------------letter---------------", letter:hex())
    --up(0x1b,0x5b,0x41) down(0x1b,0x5b,0x42) arrow
    if letter==string.char(0x1b,0x5b,0x41) or letter==string.char(0x1b,0x5b,0x42) then
        self.upArrowClicked=true
        self.command:clear()
    --ctrl+u
    elseif letter==string.char(0x15) then
        self.command:removeBefore(nil,all)
    --left arrow or ctrl+b
    elseif letter==string.char(0x1b,0x5b,0x44) or letter==string.char(2) then
        self.command:moveCursor(-1)
    --right arrow or ctrl+f
    elseif letter==string.char(0x1b,0x5b,0x43) or letter==string.char(6) then
        self.command:moveCursor(1)
    --home or ctrl+a
    elseif letter==string.char(0x1b,0x5b,0x31,0x7e) or letter==string.char(1) then
        self.command:home()
    --end or ctrl+e
    elseif letter==string.char(0x1b,0x5b,0x34,0x7e) or letter==string.char(5) then
        self.command:toEnd()
    --delete or control+d
    elseif letter==string.char(0x1b,0x5b,0x33,0x7e) or letter==string.char(4) then
        self.command:removeAfter()
    --tab 
    elseif letter==string.char(0x09) then
        self.tabClicked=true
    --backspace
    elseif letter==string.char(0x7f) or letter==string.char(8)  then
        self.command:removeBefore()
    --ctrl+c
    elseif letter==string.char(0x03) then
        self.command:clear()
    --ctrl+? still needs further process
    elseif letter==string.char(0x1f) then
        self.tabClicked=true
    --enter
    elseif letter==string.char(0x0d) then
        if (0 < self.command:getLength()) then
            local cmdstr=self.command:toString()
            logger.dbg("\027[4;33m[handleDataUp] command: \027[0m", cmdstr)
            self.command:clear()
            self.lastCommand = cmdstr
            --[[ self.waitForReply = true ]]
            -- logger.dbg("\027[1;33m[handleDataUp] cmdstr: \027[0m", cmdstr)
            -- logger.inf("-------MY----------- commandCollector.lua CommandEnteredEvent handleDataUp", cmdstr)
            local newcmd,err=self.CommandEnteredEvent:trigger(cmdstr, ctx)
            if err then
                local toSend=ssh2Packet.ChannelData:new{
                    channel=256,
                    data=table.concat{"\r\n",err.message,"\r\n"}
                }:pack().allBytes
                processor:sendDown(toSend)
                --0x05 0x15 move cursor to the end and delete all
                packet.data=string.char(5,0x15,0x0d)
                packet:pack()
            elseif newcmd~=cmdstr then
                --0x05 0x15 for move cursor to the end and delete all
                packet.data=string.char(5,0x15)..newcmd.."\n"
                packet:pack()
            end
        end
        --[[ elseif (string.byte(letter,1)>31 and string.byte(letter,1)<127)) or string.byte(letter,1)>=128 then ]]
    elseif (31 < ascii and ascii < 127) or      -- ASCII printable characters
    (128 <= ascii and ascii <= 255) then -- Extended printable ASCII characters
        self.command:append(letter)
    end
    return packet
end

local function processReply(self,reply)
    if not reply then return end
    -- logger.dbg("\027[4;32m>[processReply] reply: \027[0m", reply)
    --found OSC command ESC]0; means new prompt should be display
    local endPos=reply:find(string.char(0x1b,0x5d,0x30,0x3b))
    if not endPos then endPos=reply:find("[.*@.*:.*]?[%s]?%[?.*@.*%]?[\\$#][%s]?") end
    if not endPos then endPos=reply:find("mysql>[%s]?") end
    if endPos then
        -- logger.dbg(">[processReply] - endPos: ", endPos)
        --[[ self.lastPrompt=reply:sub(endPos) ]]
        self.commandReply=self.commandReply .. reply:sub(1, endPos - 1)
        --[[ return self.lastPrompt,self.commandReply ]]

        self.CommandFinishedEvent:trigger(removeANSIEscape(self.commandReply), ctx)
        self.lastCommand = ""
        self.commandReply = ""
    else
        -- logger.dbg(">[processReply] = endPos: nil")
        self.commandReply = self.commandReply .. reply
    end
end

function _M:handleDataDown(processor,packet,ctx)
    local reply=packet.data
    --up arrow
    if self.upArrowClicked then
        --command may have leading 0x08 bytes, trim it
        self.command:append(removeUnprintableAscii(removeANSIEscape(reply)))
        self.upArrowClicked=false

    --tab 
    elseif self.tabClicked then
        self.command:append(removeUnprintableAscii(reply),self.commandPtr)
        self.tabClicked=false

    --prompt received
    elseif reply then
        processReply(self, reply)

    --welcome screen
    elseif self.firstReply and self.BeforeWelcomeEvent:hasHandler() then
        self.firstReply=false
        local welcome,prepend=self.BeforeWelcomeEvent:trigger(ctx)
        if welcome then
            local prompt,orignalWelcome=processReply(self,reply)
            if not prompt then self.waitForWelcome=true end
            self.prepend=prepend
            local data={
                welcome,
                prepend and self.commandReply or "",
                (not prepend) and (prompt or ">") or ""
            }
            packet.data=table.concat(data)
            packet:pack()	
        end
    elseif self.waitForWelcome then
        local prompt,orignalWelcome=processReply(self,reply)
        if not self.prepend then
            if prompt then 
                packet.data=prompt
                packet:pack() 
            else
                packet.allBytes=nil
            end
        end
    end
    return packet
end


return _M