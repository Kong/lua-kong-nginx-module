local ffi = require "ffi"
local base = require "resty.core.base"
local get_request = base.get_request

local type = type
local assert = assert

local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string

local subsystem = ngx.config.subsystem

local get_header


if subsystem == "http" then
    ffi.cdef[[
        ngx_str_t* ngx_http_lua_kong_ffi_request_get_header(
            ngx_http_request_t *r, ngx_str_t name, size_t search_limit);
    ]]

    local DEFAULT_HEADER_LIMIT = 100

    local name_str = ffi_new("ngx_str_t")

    get_header = function(name, limit)
        assert(type(name) == "string" and name ~= "",
               "name must be a string")

        local limit = limit or DEFAULT_HEADER_LIMIT
        assert(type(limit) == "number" and limit >= 0,
               "limit must be a number")

        local r = get_request()

        name_str.data = name
        name_str.len = #name

        local value = C.ngx_http_lua_kong_ffi_request_get_header(r, name_str,
                                                                 limit)
        -- same behavior as ngx.var.http_xxx
        if value == nil then
            return
        end

        return ffi_str(value.data, value.len)
    end
end


if subsystem == "stream" then
    get_header = function() end
end


return {
    get_header = get_header,
}
