-- Answer GetRandom without executing it. The response hook still runs once.
return {
    api_version = 1,
    on_request = function(ctx, request)
        if ctx.command_code == 0x17b and #request == 12
            and string.unpack(">I2", request) == 0x8001 then
            local count = math.min(string.unpack(">I2", request, 11), 8)
            ctx.state.synthetic = ctx.id
            return { action = "respond",
                     bytes = string.pack(">I2I4I4I2", 0x8001, 12 + count, 0, count)
                         .. string.rep("\0", count) }
        end
    end,
    on_response = function(ctx, response)
        if ctx.state.synthetic then
            assert(ctx.id == ctx.state.synthetic)
            assert(ctx.response_source == "lua" and not ctx.backend_executed)
            assert(ctx.effective_request == nil)
        end
    end,
}
