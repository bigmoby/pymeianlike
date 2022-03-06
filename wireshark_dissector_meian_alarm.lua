----------------------------------------
-- script-name: meian.lua
--
-- author: Andrea Tuccia <andrea at tuccia dot it>
--
-- Meain TCP protocol Wireshark dissector
-- Copyright (C) 2018, Andrea Tuccia
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <http://www.gnu.org/licenses/>.
--
-- Version: 0.1
--
-- Proof-of-concept Meian alarms TCP protocol dissector for Wireshark.
--
----------------------------------------


-- Create Meian alarm protocol and its fields
p_meian = Proto ("iAlarm","iAlarm TCP Protocol")

print("Dissector iAlarm TCP Protocol")

local xml_field = Field.new("data")

-- Dissector function
function p_meian.dissector (buf, pkt, root)
    -- Validate packet length
    if buf:len() == 0 then return end
    pkt.cols.protocol = p_meian.name

    -- Decode data
    local hexkey = ByteArray.new("0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12")
    local key = ByteArray.tvb(hexkey, "iAlarm keys table")
    local ascii = ""
    local hex = ""

    -- Skip keepalive header, doesn't contain any data
    if (buf(0,4):string()) == "%maI" then
        return
    end
    -- Skip first 16 bytes (header)
    start = 16
    -- Skip last 4 bytes (footer)
    endPosition = buf:len() - 5
    -- Decrypt XOR circular keys table
    -- and save results as ascii and hex

    for index = start, endPosition do
        local c = buf(index, 1):uint()
        local ki = index - 16
        -- Circular 0x7f bytes table
        ki = bit.band(ki, 0x7f)
        local k = key(ki, 1):uint()
        -- XOR with key
        d = bit32.bxor(c, k)
        hex = hex .. string.format("%x", d)
        ascii = ascii .. string.format("%c", d)
    end

    print("=====>>>> Print buffer")
    print(ascii)

    -- Create subtree
    subtree = root:add(p_meian, buf(0))

    -- Add data to subtree
    subtree:add(ascii)
    -- Push notifications
    if (buf(0,4):string()) == "@alA" then
        subtree:append_text(" (push notification)")
    end
    -- Description of payload
    subtree:append_text(" (decrypted)")

    -- Call XML Dissector with decrypted data
    local b = ByteArray.new(hex)
    local tvb = ByteArray.tvb(b, "XML TVB")
    Dissector.get("xml"):call(tvb, pkt, root)

end

-- Initialization routine
function p_meian.init()
end

-- Register a chained dissector for port 18034
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(18034)
tcp_dissector_table:add(18034, p_meian)