local logger = require "strmproxy.utils.compatibleLog"
local format = string.format
local sshHandlers = require "strmproxy.ssh2handler"



local M = {}
M.__index = M

-- Create a new instance
function M:new()
    local self = setmetatable({}, M)

    self.CurStep = 0
    self.UpAndDown = 0
    self.TargetPath = ""
    self.CopyLoop = 0

    return self
end

local function splitBySpace(input)
    local result = {}
    for word in string.gmatch(input, "[^%s]+") do
        table.insert(result, word)
    end
    return result
end

local function sendCopyLoopLog(input, UpAndDown, TargetPath)


    local logdata = ""
    local filename = ""

    local items = splitBySpace(input)
    filename = items[3]

    if UpAndDown == 1 then
        logdata = "upload " .. TargetPath .. "/" .. filename
    end

    if UpAndDown == 2 then
        logdata = "download " .. TargetPath .. "/" .. filename
    end

    logdata = "scp> " .. logdata .. "\r\n"
    sshHandlers.sshLog(logdata)
    
end

local function checkFilterPath(ServerPath, UpAndDown)
    local   sts = true

    local lower_ServerPath = string.lower(ServerPath)
    local start_pos, end_pos = string.find(lower_ServerPath, "/home/ubuntu/sec")
    if start_pos then
        sts = false
    end    

    start_pos, end_pos = string.find(lower_ServerPath, "securityfile")
    if start_pos then
        sts = false
    end    

    -- output log data
    if sts == false then
        local logdata = ""
        if UpAndDown == 1 then
            logdata = "upload denided" .. ServerPath
        end
        if UpAndDown == 2 then
            logdata = "download denided" .. ServerPath
        end

        logdata = "scp> " .. logdata .. "\r\n"
        sshHandlers.sshLog(logdata)
    end

    return sts
end

function M:analiysis(DataPacket)

    if #DataPacket < 5 then
        return true
    end

    local startIndex, endIndex = DataPacket:find("scp -")
    local subDataPacket = ""
    local H_KEY = 0

    -- get t/f/r /home/ubuntu/aaa.txt
    if startIndex then 
        subDataPacket = DataPacket:sub(startIndex + 5, #DataPacket)
        H_KEY = string.byte(subDataPacket, 1)

    end

    -- -r option
    if startIndex and H_KEY == 114 then 
        local OPT_KEY = string.byte(subDataPacket, 4)
        -- -t
        if OPT_KEY == 116 then 
            self.CopyLoop = 1 
            self.CurStep = 1
            self.UpAndDown = 1
            self.TargetPath = subDataPacket:sub(5, #subDataPacket)
            return checkFilterPath(self.TargetPath, self.UpAndDown)
        end
        
        -- -f
        if OPT_KEY == 102 then
            self.CopyLoop = 1 
            self.CurStep = 1
            self.UpAndDown = 2
            self.TargetPath = subDataPacket:sub(5, #subDataPacket)
            return checkFilterPath(self.TargetPath, self.UpAndDown)
        end    
    end
    
    -- -t option upload
    if startIndex and H_KEY == 116 then 
        self.CopyLoop = 0 
        self.CurStep = 1
        self.UpAndDown = 1
        self.TargetPath = subDataPacket:sub(2, #subDataPacket)
        return checkFilterPath(self.TargetPath, self.UpAndDown)
    end

    -- -f option download
    if startIndex  and H_KEY == 102 then 
        self.CopyLoop = 0 
        self.CurStep = 1
        self.UpAndDown = 2
        self.TargetPath = subDataPacket:sub(2, #subDataPacket)
        return checkFilterPath(self.TargetPath, self.UpAndDown)
    end

    -- step 2
    if self.CurStep == 1 and self.CopyLoop == 0 then
        
        startIndex, endIndex = DataPacket:find("C0666")

        if startIndex then
            self.CurStep = 2
            return true
        end
        startIndex, endIndex = DataPacket:find("C0664")
        if startIndex then
            self.CurStep = 2
            return true
        end
        -- error
        startIndex, endIndex = DataPacket:find(".scp:")
        if startIndex then
            self.CopyLoop = 0 
            self.CurStep = 0
            self.UpAndDown = 0
            self.TargetPath = ""
            return true
        end

    end

    -- step 2 from copy loop
    if self.CopyLoop == 1 then
    
        startIndex, endIndex = DataPacket:find("C0666")

        if startIndex then
            self.CurStep = 2
            sendCopyLoopLog(DataPacket, self.UpAndDown, self.TargetPath);
            return true
        end

        startIndex, endIndex = DataPacket:find("C0664")
        if startIndex then
            self.CurStep = 2
            sendCopyLoopLog(DataPacket, self.UpAndDown, self.TargetPath);
            return true
        end
        -- error
        startIndex, endIndex = DataPacket:find(".scp:")
        if startIndex then
            self.CopyLoop = 0 
            self.CurStep = 0
            self.UpAndDown = 0
            self.TargetPath = ""
            return true
        end

    end 
    
    -- step 3
    if self.CurStep == 2 then

        local logdata = ""
        startIndex, endIndex = DataPacket:find("exit-")

        if startIndex and self.CopyLoop == 0 then
            if self.UpAndDown == 1 then
                logdata = "upload " .. self.TargetPath
            end


            if self.UpAndDown == 2 then
                logdata = "download " .. self.TargetPath
            end

            logdata = "scp> " .. logdata .. "\r\n"
            sshHandlers.sshLog(logdata)

            self.CopyLoop = 0 
            self.CurStep = 0
            self.UpAndDown = 0
            self.TargetPath = ""
        elseif startIndex  then
            self.CopyLoop = 0 
            self.CurStep = 0
            self.UpAndDown = 0
            self.TargetPath = ""
        end
    end

    return true
    
end



return M