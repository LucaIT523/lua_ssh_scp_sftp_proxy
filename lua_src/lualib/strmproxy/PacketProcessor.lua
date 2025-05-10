local logger = require "strmproxy.utils.compatibleLog"


local PacketProcessor = {}
PacketProcessor.__index = PacketProcessor

-- Create a new instance
function PacketProcessor:new()
    local self = setmetatable({}, PacketProcessor)
    -- self.packet = packet
    self.headerLength = 14 -- Fixed header length
    self.paddingLength = 0 -- Initial padding length
    self.dataLength = 0    -- Data length
    self.SCPStart = 0    -- Data length
    return self
end

-- Read packet length and padding length, and extract data
function PacketProcessor:process(packet, Opt , realPacketLen)
    if Opt == 0 then
        return nil
    end

    if #packet < self.headerLength then
        return nil
    end

    -- Read packet length and padding length
    self.dataLength = realPacketLen --string.byte(packet, 4) -- 4th byte: packet length
    self.paddingLength = string.byte(packet, 5) -- 5th byte: padding length

    -- Calculate start and end positions of the data
    local dataStart = self.headerLength + 1
    local dataEnd = self.dataLength - self.paddingLength

    if dataEnd > #packet then
        return nil
    end

    if dataEnd < dataStart + 1 then
        return nil
    end

    -- Extract data
    return true, packet:sub(dataStart, dataEnd)
end

function PacketProcessor:StartSCP(Opt)
    self.SCPStart = Opt
end

return PacketProcessor
