local ffi = require "ffi"
local base = require "resty.core.base"
base.allows_subsystem('http')


local error = error
local tonumber = tonumber


local C = ffi.C
local ffi_str = ffi.string
local get_request = base.get_request


ffi.cdef[[
int ngx_http_lua_kong_ffi_req_is_https(ngx_http_request_t *r);
int ngx_http_lua_kong_ffi_req_has_args(ngx_http_request_t *r);
int ngx_http_lua_kong_ffi_req_get_server_port(ngx_http_request_t *r);
ngx_str_t * ngx_http_lua_kong_ffi_req_get_args(ngx_http_request_t *r);
ngx_str_t * ngx_http_lua_kong_ffi_req_get_request_uri(ngx_http_request_t *r);
]]


local function is_https()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local flag = C.ngx_http_lua_kong_ffi_req_is_https(r)

    return tonumber(flag) == 1
end


local function get_scheme()
    return is_https() and "https" or "http"
end


local function has_args()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local flag = C.ngx_http_lua_kong_ffi_req_has_args(r)

    return tonumber(flag) == 1
end


local function get_args()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local args = C.ngx_http_lua_kong_ffi_req_get_args(r)

    if args.len == 0 then
        return ""
    end

    return ffi_str(args.data, args.len)
end


return {
    is_https = is_https,
    get_scheme = get_scheme,
}
