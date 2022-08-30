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
int ngx_http_lua_kong_ffi_req_is_args(ngx_http_request_t *r);
int ngx_http_lua_kong_ffi_req_server_port(ngx_http_request_t *r);

ngx_str_t * ngx_http_lua_kong_ffi_req_args(ngx_http_request_t *r);
ngx_str_t * ngx_http_lua_kong_ffi_req_request_uri(ngx_http_request_t *r);
]]


local function is_https()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local flag = C.ngx_http_lua_kong_ffi_req_is_https(r)

    return tonumber(flag) == 1
end


local function scheme()
    return is_https() and "https" or "http"
end


local function is_args()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local flag = C.ngx_http_lua_kong_ffi_req_is_args(r)

    return tonumber(flag) == 1
end


local function args()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local args = C.ngx_http_lua_kong_ffi_req_args(r)

    return ffi_str(args.data, args.len)
end


local function request_uri()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local request_uri = C.ngx_http_lua_kong_ffi_req_request_uri(r)

    return ffi_str(request_uri.data, request_uri.len)
end


local function server_port()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local port = C.ngx_http_lua_kong_ffi_req_server_port(r)
    if port < 0 then
        return nil
    end

    return tonumber(port)
end


return {
    is_https    = is_https,
    scheme      = scheme,
    is_args     = is_args,
    args        = args,
    request_uri = request_uri,
    server_port = server_port,
}
