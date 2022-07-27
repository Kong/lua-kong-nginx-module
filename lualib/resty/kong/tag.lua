local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_str = ffi.string
local get_request = base.get_request
local subsystem = ngx.config.subsystem


local ngx_lua_kong_get_static_tag


if subsystem == "http" then

    ffi.cdef[[
    ngx_str_t * ngx_http_lua_kong_ffi_get_static_tag(ngx_http_request_t *r);
    ]]

    ngx_lua_kong_get_static_tag = C.ngx_http_lua_kong_ffi_get_static_tag

elseif subsystem == "stream" then

    ffi.cdef[[
    ngx_str_t * ngx_stream_lua_kong_ffi_get_static_tag(ngx_stream_request_t *r);
    ]]

    ngx_lua_kong_get_static_tag = C.ngx_stream_lua_kong_ffi_get_static_tag

end

local function get()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local tag = ngx_lua_kong_get_static_tag(r)

    if tag and tag.len > 0 then
        return ffi_str(tag.data, tag.len)
    end

    return nil
end


return {
    get = get,
}
