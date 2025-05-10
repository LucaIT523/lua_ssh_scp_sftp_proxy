local logger = require "strmproxy.utils.compatibleLog"
local format = string.format
local sshHandlers = require "strmproxy.ssh2handler"



local M = {}
M.__index = M

-- Create a new instance
function M:new()
    local self = setmetatable({}, M)

    -- self.packet header
    self.MKDIR_KEY = 0x0E
    self.RMDIR_KEY = 0x0F
    self.RM_KEY = 0x0D
    self.OPEN_KEY = 0x03
    self.CLOSE_KEY = 0x04
    self.READ_KEY = 0x05
    self.WRITE_KEY = 0x06

    self.ERR_KEY = 0x65
    self.ERR_POS = 4
    self.ERR_DATA_POS = 18
    self.REAL_POS = 10

    self.ErrData = ""
    self.TargetPath = ""

    -- self.StartOpt = 0
    -- 1 -> MKDIR , 2 -> RMDIR, 3 -> RM, 4 -> get, put
    self.KindOpt = 0
    self.CurStep = 0
    self.UpAndDown = 0

    self.DirStep = 2
    self.CopyStep = 4

    return self
end

function M:getTargetPath(DataPacket)
    if not DataPacket or type(DataPacket) ~= "string" then
        return nil, "Invalid DataPacket"
    end

    local startIndex = 10
    local length = string.byte(DataPacket, 9)

    if #DataPacket < startIndex + length - 1 then
        return nil
    end

    local targetPath = DataPacket:sub(startIndex, startIndex + length - 1)
    self.TargetPath = targetPath

    return true

end

local function checkFilterPath(ServerPath, Command)
    local   sts = true
    local   logdata = ""

    if #ServerPath < 1 then
        return sts
    end

    local lower_ServerPath = string.lower(ServerPath)
    local start_pos, end_pos = string.find(lower_ServerPath, "security")
    if start_pos then
        sts = false
        logdata = "sftp> " .. "(Command Blocked)" .. ServerPath .. "\r\n"
        sshHandlers.sshLog(logdata)
    end    

    -- -- RMDIR_KEY
    -- if Command == 0x0F then
    --      sts = false
    --      logdata = "sftp> " .. "(RMDIR Blocked)" .. ServerPath .. "\r\n"
    --      sshHandlers.sshLog(logdata)
    -- end

    return sts
end


function M:analiysis(DataPacket)

    if #DataPacket < 10 then
        return true
    end

    local H_KEY = string.byte(DataPacket, 1)
    local E_KEY = string.byte(DataPacket, 5)

    if H_KEY == self.MKDIR_KEY then
        if self:getTargetPath(DataPacket) then
            self.KindOpt = 1
            self.CurStep = 1
        end
        return checkFilterPath(self.TargetPath, H_KEY)

    elseif H_KEY == self.RMDIR_KEY then
        if self:getTargetPath(DataPacket) then
            self.KindOpt = 2
            self.CurStep = 1
        end
        return checkFilterPath(self.TargetPath, H_KEY)

    elseif H_KEY == self.RM_KEY then
        if self:getTargetPath(DataPacket) then
            self.KindOpt = 3
            self.CurStep = 1
        end
        return checkFilterPath(self.TargetPath, H_KEY)

    elseif H_KEY == self.OPEN_KEY then
        if self:getTargetPath(DataPacket) then
            self.KindOpt = 4
            self.CurStep = 1
        end    
        return checkFilterPath(self.TargetPath, H_KEY)

    elseif H_KEY == self.READ_KEY then
        self.KindOpt = 4
        self.CurStep = 2
        self.UpAndDown = 2
        return true

    elseif H_KEY == self.WRITE_KEY then
        self.KindOpt = 4
        self.CurStep = 2
        self.UpAndDown = 1
        return true

    elseif H_KEY == self.CLOSE_KEY then
        self.KindOpt = 4
        self.CurStep = 3
        return true

    end

    -- MKDIR, RMDIR, RM
    if E_KEY == self.ERR_KEY and self.KindOpt <= 3 and self.CurStep == 1 then
        
        -- if Success
        local subStr = DataPacket:sub(18, 24)
        local logdata = ""

        if subStr == "Success" then
            if self.KindOpt == 1 then
                logdata = "mkdir " .. self.TargetPath
            end
            if self.KindOpt == 2 then
                logdata = "rmdir " .. self.TargetPath
            end
            if self.KindOpt == 3 then
                logdata = "rm " .. self.TargetPath
            end

            logdata = "sftp> " .. logdata .. "\r\n"
            sshHandlers.sshLog(logdata)
            
        -- if Error
        else 
        end

        self.KindOpt = 0
        self.CurStep = 0
        self.UpAndDown = 0

        return true
    end

    -- PUT , GET
    if E_KEY == self.ERR_KEY and self.KindOpt == 4 and self.CurStep == 3 then
        
        -- if Success
        local subStr = DataPacket:sub(18, 24)
        local logdata = ""

        if subStr == "Success" then
            if self.UpAndDown == 1 then
                logdata = "put " .. self.TargetPath
            end
            if self.UpAndDown == 2 then
                logdata = "get " .. self.TargetPath
            end

            logdata = "sftp> " .. logdata .. "\r\n"
            sshHandlers.sshLog(logdata)
            
        -- if Error
        else 
        end

        self.KindOpt = 0
        self.CurStep = 0
        self.UpAndDown = 0

        return true
    end
end

return M