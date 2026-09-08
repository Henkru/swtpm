-- Ask the backend for eight bytes, then replace that exchange's payload.
return {
    api_version = 1,
    on_request = function(ctx, request)
        if ctx.command_code == 0x17b and #request == 12
            and string.unpack(">I2", request) == 0x8001 then
            local requested = string.unpack(">I2", request, 11)
            if requested > 8 then
                ctx.state.modified = true
                ctx.state.original_requested = requested
                return { action = "replace",
                         bytes = request:sub(1, 10) .. string.pack(">I2", 8) }
            end
        end
    end,
    on_response = function(ctx, response)
        if ctx.state.modified and ctx.effective_command_code == 0x17b
            and ctx.response_source == "tpm" and #response >= 12 then
            local tag, size, rc, count = string.unpack(">I2I4I4I2", response)
            if tag == 0x8001 and rc == 0 and size == #response
                and #response == 12 + count then
                return { action = "replace",
                         bytes = response:sub(1, 12) .. string.rep("\0", count) }
            end
        end
    end,
}
