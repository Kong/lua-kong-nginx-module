local ffi = require("ffi")
local base = require("resty.core.base")

local C = ffi.C
local ffi_string = ffi.string
local ffi_gc = ffi.gc
local FFI_ERROR = base.FFI_ERROR
local FFI_DONE = base.FFI_DONE
local FFI_OK = base.FFI_OK
local FFI_AGAIN = base.FFI_AGAIN
local FFI_NO_REQ_CTX = base.FFI_NO_REQ_CTX
local get_request = base.get_request
local error = error
local assert = assert
local type = type
local pcall = pcall
local select = select
local co_yield = coroutine._yield
local table_new = require("table.new")
local table_clear = require("table.clear")

ffi.cdef[[
typedef struct ngx_http_lua_socket_tcp_upstream_s
    ngx_http_lua_socket_tcp_upstream_t;

int ngx_http_lua_ffi_socket_tcp_tlshandshake(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, void *sess,
    int enable_session_reuse, ngx_str_t *server_name, int verify,
    int ocsp_status_req, void *chain, void *pkey,
    char **errmsg);
int ngx_http_lua_ffi_socket_tcp_get_tlshandshake_result(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, void **sess,
    char **errmsg, int *openssl_error_code);
void ngx_http_lua_ffi_tls_free_session(void *sess);
]]


local SOCKET_CTX_INDEX = 1


local errmsg = base.get_errmsg_ptr()
local session_ptr = ffi.new("void *[1]")
local server_name_str = ffi.new("ngx_str_t[1]")
local openssl_error_code = ffi.new("int[1]")
local cached_options = table_new(0, 4)


local function tlshandshake(self, options)
    if not options then
        table_clear(cached_options)
        options = cached_options

    elseif type(options) ~= "table" then
        error("bad options table type")
    end

    local r = get_request()

    if not r then
        error("no request found")
    end

    local reused_session = options.reused_session
    session_ptr[0] = type(reused_session) == "cdata" and reused_session or nil

    if options.server_name then
        server_name_str[0].data = options.server_name
        server_name_str[0].len = #options.server_name

    else
        server_name_str[0].data = nil
        server_name_str[0].len = 0
    end

    local client_cert = options.client_cert
    local client_priv_key = options.client_priv_key
    if client_cert then
        if not client_priv_key then
            error("client certificate supplied without "
                  .. "corresponding private key", 2)
        end

        if type(client_cert) ~= "cdata"
           or type(client_priv_key) ~= "cdata"
        then
            error("wrong type of client certificate or private key supplied", 2)
        end
    end

    local rc =
        C.ngx_http_lua_ffi_socket_tcp_tlshandshake(r, self[SOCKET_CTX_INDEX],
                                                   session_ptr[0],
                                                   reused_session ~= false,
                                                   server_name_str,
                                                   options.verify and 1 or 0,
                                                   options.ocsp_status_req
                                                       and 1 or 0,
                                                   client_cert,
                                                   client_priv_key,
                                                   errmsg)

    if rc == FFI_NO_REQ_CTX then
        error("no request ctx found", 2)
    end

::again::

    if rc == FFI_ERROR then
        if openssl_error_code[0] ~= 0 then
            return nil, openssl_error_code[0] .. ": " .. ffi_string(errmsg[0])
        end

        return nil, ffi_string(errmsg[0])
    end

    if rc == FFI_DONE then
        return options.reused_session
    end

    if rc == FFI_OK then
        if options.reused_session == false then
            return true
        end

        rc = C.ngx_http_lua_ffi_socket_tcp_get_tlshandshake_result(r,
            self[SOCKET_CTX_INDEX], session_ptr, errmsg, openssl_error_code)

        assert(rc == FFI_OK)

        if session_ptr[0] == nil then
            return session_ptr[0]
        end

        return ffi_gc(session_ptr[0], C.ngx_http_lua_ffi_tls_free_session)
    end

    assert(rc == FFI_AGAIN)

    co_yield()

    rc = C.ngx_http_lua_ffi_socket_tcp_get_tlshandshake_result(r,
        self[SOCKET_CTX_INDEX], session_ptr, errmsg, openssl_error_code)

    assert(rc == FFI_OK or rc  == FFI_ERROR)

    goto again
end


local function sslhandshake(self, reused_session, server_name, ssl_verify,
    send_status_req, ...)

    local n = select("#", ...)
    if not self or n > 1 then
        error("ngx.socket sslhandshake: expecting 1 ~ 5 "
              .. "arguments (including the object), but seen " .. n)
    end

    cached_options.reused_session = reused_session
    cached_options.server_name = server_name
    cached_options.verify = ssl_verify
    cached_options.ocsp_status_req = send_status_req

    local res, err = tlshandshake(self, cached_options)
    table_clear(cached_options)

    return res, err
end


do
    local old_socket_tcp = ngx.socket.tcp

    function ngx.socket.tcp()
        local ok, sock = pcall(old_socket_tcp)
        if not ok then
            error(sock, 2)
        end

        sock.tlshandshake = tlshandshake
        sock.sslhandshake = sslhandshake

        return sock
    end
end


return {
    version = base.version
}
