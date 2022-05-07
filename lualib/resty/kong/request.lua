local ffi = require "ffi"
local base = require "resty.core.base"
local get_request = base.get_request

local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string

local subsystem = ngx.config.subsystem

local get_header
if subsystem == "http" then
    ffi.cdef[[
        ngx_str_t *ngx_http_lua_kong_request_get_header(ngx_http_request_t *r, ngx_str_t name, size_t search_limit);
    ]]
    function get_header(name, limit)
        local r = get_request()
        local name_ffi = ffi_new("ngx_str_t")
        name_ffi.data = name
        name_ffi.len = #name
        local ret = C.ngx_http_lua_kong_request_get_header(r, name_ffi, limit or 100)
        if ret ~= nil then
            return ffi_str(ret.data, ret.len)
        end
    end
end

return {
    get_header = get_header
}