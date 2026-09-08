return {
    api_version = 1,
    on_request = function(ctx, request)
        return { action = "pass" }
    end,
    on_response = function(ctx, response)
        return { action = "pass" }
    end,
}
