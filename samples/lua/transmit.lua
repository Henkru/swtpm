-- Query PCR 16 before and after an external PCR_Extend without intercepting
-- these additional PCR_Read commands or modifying the external exchange.
local read_pcr16 = string.pack(">I2I4I4I4I2I1", 0x8001, 20, 0x17e, 1, 0x000b, 3)
                   .. "\0\0\1"

local function read_pcr()
    local response, rc = tpm.transmit(read_pcr16)
    assert(rc == 0, "additional PCR_Read failed")
    -- Compare the selected SHA-256 digest, excluding the global PCR counter.
    return response:sub(-32)
end

return {
    api_version = 1,
    on_request = function(ctx, request)
        if ctx.command_code == 0x182 then
            ctx.state.before = read_pcr()
        end
    end,
    on_response = function(ctx, response)
        if ctx.state.before then
            local after = read_pcr()
            tpm.log(after == ctx.state.before and "PCR 16 unchanged" or "PCR 16 changed")
        end
    end,
}
