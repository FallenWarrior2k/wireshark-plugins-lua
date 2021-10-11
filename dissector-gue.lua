-- General protocol info: https://datatracker.ietf.org/doc/html/draft-ietf-intarea-gue
-- Extensions (not implemented yet): https://datatracker.ietf.org/doc/html/draft-ietf-intarea-gue-extensions
local gue_proto = Proto("GUE", "Generic UDP Encapsulation")

local field_variant = ProtoField.uint8(
    "gue.var",
    "Variant",
    base.DEC,
    {[0] = "Full GUE Header", [1] = "Direct IP Encapsulation"},
    -- First two bits (technically only second bit, but it's defined as two bits wide)
    0xC0
)
-- Third bit (if variant is 0)
local field_control = ProtoField.bool("gue.control", "Control Message", 8, nil, 0x20)
-- Remaining 5 bits of first byte
local field_hlen = ProtoField.uint8("gue.hlen", "Length of Header Extension Fields", base.DEC, nil, 0x1F)
local field_proto = ProtoField.uint8("gue.proto", "Protocol")
local field_ctype = ProtoField.uint8(
    "gue.ctype",
    "Control Message Type",
    base.RANGE_STRING,
    {
        {0, 0, "Control Message"},
        {1, 254, "Reserved"},
        {255, 255, "Experiment"}
    }
)
local field_flags = ProtoField.uint16("gue.flags", "Flags", base.HEX)

gue_proto.fields = { field_variant, field_control, field_hlen, field_proto, field_ctype, field_flags }

-- Cache these locally so we don't have to look them up every time
local ip_dissector = Dissector.get("ip")
local ip6_dissector = Dissector.get("ipv6")
local ip_dissector_table = DissectorTable.get("ip.proto")

function gue_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    -- GUE packets are always at least 4 bytes:
    -- - Variant: 2 bits
    -- - C-bit (control message indicator): 1 bit
    -- - Header length (in 4-byte words): 5 bit (=> max length: 128 bytes)
    -- - Protocol/control message type: 1 byte
    -- - Flags: 2 bytes
    if length <= 4 then
        return
    end

    local header = buffer(0, 4)
    local first_byte = header(0, 1)
    local variant = first_byte:bitfield(0, 2)

    -- Invalid variant
    if bit.band(variant, 2) ~= 0 then
        return
    end

    -- Variant 0: indicates control message
    -- Variant 1: indicates IPv6
    local control_or_ip6 = first_byte:bitfield(2, 1) == 1

    local tree_name_prefix = gue_proto.description
    local msg_type = ""
    if variant == 1 then
        msg_type = "Direct IP Encapsulation"
    -- Variant is 0; this differentiates between control and data messages
    elseif control_or_ip6 then
        msg_type = "Control message"
    else
        msg_type = "Data message"
    end

    local tree_name = string.format("%s (%s)", gue_proto.description, msg_type)
    local subtree = tree:add(gue_proto, header, tree_name)
    -- I don't know if I need to explicitly pass the bit fields or if the bitmask takes care of that
    -- For now they're there for safety
    -- TODO: Generate some test packets to test this
    subtree:add(field_variant, first_byte, variant)

    -- Full GUE header
    if variant == 0 then
        local is_control = control_or_ip6
        -- Important: Header length does not include first four bytes, only extension fields
        local hlen = first_byte:bitfield(3, 5)
        local hlen_bytes = hlen * 4

        local proto_or_ctype = header(1, 1)
        local flags = header(2, 2)

        subtree:add(field_control, first_byte, is_control)
        subtree:add(field_hlen, first_byte, hlen_bytes):append_text(string.format(" bytes (%d words)", hlen))

        if is_control then
            -- TODO: Test this branch
            -- Set protocol column
            -- No need to to this anywhere else as it'd be overwritten by subdissectors anyway
            pinfo.cols.protocol = gue_proto.name
            -- TODO: Set info column to a suitable value

            subtree:add(field_ctype, proto_or_ctype)
            -- TODO
        else
            -- Encapsulated protocol (IANA number)
            -- Have to figure out a way to map this to a readable value because I don't have ipproto.h
            subtree:add(field_proto, proto_or_ctype)

            -- The contents of the data message
            local body = buffer(hlen_bytes + 4):tvb()

            -- Dissect the contents
            local proto = proto_or_ctype:uint()
            -- TODO: Handle errors from underlying dissector
            -- Presumably requires a check for 0, but I'd have to generate some test data first
            ip_dissector_table:try(proto, body, pinfo, tree)
        end

        -- TODO: Handle flags and extension fields
        -- https://datatracker.ietf.org/doc/html/draft-ietf-intarea-gue-extensions-06
        subtree:add(field_flags, flags)
    -- Direct IP encapsulation
    elseif variant == 1 then
        -- TODO: Test this
        local is_ip6 = control_or_ip6
        if is_ip6 then
            ip6_dissector(buffer, pinfo, tree)
        else
            ip_dissector(buffer, pinfo, tree)
        end
    end
end

-- TODO: Heuristics maybe?
-- Port number: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
DissectorTable.get("udp.port"):add(6080, gue_proto)
