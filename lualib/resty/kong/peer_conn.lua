local ffi              = require "ffi"
local C                = ffi.C
local base             = require "resty.core.base"
local ffi_str          = ffi.string
local orig_get_request = base.get_request
local get_phase        = ngx.get_phase
local error            = error
local NGX_ERROR        = ngx.ERROR

ffi.cdef[[
int
ngx_http_lua_kong_ffi_get_last_peer_connection_cached(ngx_http_request_t *r,
    char **err);
]]

local errmsg = base.get_errmsg_ptr()

local function get_request()
    local r = orig_get_request()

    if not r then
        error("no request found")
    end

    return r
end


local function get_last_peer_connection_cached()
    if get_phase() ~= "balancer" then
        error("get_last_peer_connection_cached() can only be called in balancer phase")
    end

    local r = get_request()

    local rc = C.ngx_http_lua_kong_ffi_get_last_peer_connection_cached(r, errmsg)

    if rc == NGX_ERROR then
        error(ffi_str(errmsg[0]), 2)
    end

    return rc
end

return {
    get_last_peer_connection_cached = get_last_peer_connection_cached,
}
