local ffi              = require "ffi"
local base             = require "resty.core.base"

local get_request      = base.get_request
local errmsg           = base.get_errmsg_ptr()
local C                = ffi.C
local ffi_str          = ffi.string
local subsystem        = ngx.config.subsystem
local NGX_ERROR        = ngx.ERROR

local error            = error


local get_last_peer_connection_cached


if subsystem == "http" then
    require "resty.core.phase"  -- for ngx.get_phase
    ffi.cdef[[
    int ngx_http_lua_kong_ffi_get_last_peer_connection_cached(ngx_http_request_t *r,
        char **err);
    ]]
    
    get_last_peer_connection_cached = function()
        local ngx_phase = ngx.get_phase
        if ngx_phase() ~= "balancer" then
            error("get_last_peer_connection_cached() can only be called in balancer phase")
        end
    
        local r = get_request()
        if not r then
            error("no request found")
        end
    
        local rc = C.ngx_http_lua_kong_ffi_get_last_peer_connection_cached(r, errmsg)
    
        if rc == NGX_ERROR then
            error(ffi_str(errmsg[0]), 2)
        end
    
        return rc == 1
    end
end

return {
    get_last_peer_connection_cached = get_last_peer_connection_cached,
}
