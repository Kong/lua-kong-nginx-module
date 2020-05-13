local _M = {}


local ffi = require("ffi")
local get_request = require("resty.core.base").get_request


if ngx.config.subsystem == "http" then
    ffi.cdef([[
    int ngx_http_lua_kong_ffi_recreate_request(ngx_http_request_t *r);
    ]])
end


local get_phase = ngx.get_phase
local C = ffi.C


function _M.update_proxy_request()
    if ngx.config.subsystem == "http" then
        if get_phase() ~= "balancer" then
            error("API disabled in the current context", 2)
        end

        local r = get_request()

        local ret = C.ngx_http_lua_kong_ffi_recreate_request(r)
        if ret == ngx.OK then
            return true
        end

        error("could not recreate request", 2)
    end

    return true
end


return _M
