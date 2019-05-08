-- Copyright 2019 Kong Inc.

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--    http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.


local _M = {}


local ffi = require("ffi")
local bit = require("bit")
local base = require("resty.core.base")
base.allows_subsystem('http')


ffi.cdef([[
typedef uintptr_t       ngx_uint_t;
typedef uint8_t         u_char;

const char *ngx_http_lua_kong_ffi_request_client_certificate(
    ngx_http_request_t *r);
int ngx_http_lua_kong_ffi_get_full_client_certificate_chain(
    ngx_http_request_t *r, char *buf, size_t *buf_len);
const char *ngx_http_lua_kong_ssl_set_session_flags(ngx_http_request_t *r,
    ngx_uint_t flags);
u_char *ngx_http_lua_kong_ssl_get_session_id(ngx_http_request_t *r, size_t *len,
    char **errmsg);
]])


local get_phase = ngx.get_phase
local getfenv = getfenv
local error = error
local tostring = tostring
local select = select
local C = ffi.C
local ffi_string = ffi.string
local get_string_buf = base.get_string_buf
local size_ptr = base.get_size_ptr()
local bor = bit.bor
local errmsg = base.get_errmsg_ptr()
local to_hex = require("resty.string").to_hex


local DEFAULT_CERT_CHAIN_SIZE = 10240
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR
local NGX_AGAIN = ngx.AGAIN
local NGX_DONE = ngx.DONE
local NGX_DECLINED = ngx.DECLINED


function _M.request_client_certificate()
    if get_phase() ~= 'ssl_cert' then
        error("API disabled in the current context", 2)
    end

    local r = getfenv(0).__ngx_req
    -- no need to check if r is nil as phase check above
    -- already ensured it

    local errmsg = C.ngx_http_lua_kong_ffi_request_client_certificate(r)
    if errmsg == nil then
        return true
    end

    return nil, ffi_string(errmsg)
end


do
    local NGX_HTTP_LUA_KONG_SSL_NO_SESSION_CACHE = 0x00000001
    local NGX_HTTP_LUA_KONG_SSL_NO_SESSION_TICKET = 0x00000002


    function _M.supress_session_reuse(...)
        if get_phase() ~= 'ssl_cert' then
            error("api disabled in the current context", 2)
        end

        local r = getfenv(0).__ngx_req
        local flags = 0

        for i = 1, select("#", ...) do
            local opt = select(i, ...)
            if opt == 'no_cache' then
                flags = bor(flags, NGX_HTTP_LUA_KONG_SSL_NO_SESSION_CACHE)

            elseif opt == 'no_ticket' then
                flags = bor(flags, NGX_HTTP_LUA_KONG_SSL_NO_SESSION_TICKET)

            else
                error("invalid option: " .. tostring(opt), 2)
            end
        end

        local errmsg = C.ngx_http_lua_kong_ssl_set_session_flags(r, flags)
        if errmsg == nil then
            return true
        end

        return nil, ffi_string(errmsg)
    end
end


function _M.get_session_id()
    if get_phase() ~= 'ssl_cert' then
        error("api disabled in the current context", 2)
    end

    local r = getfenv(0).__ngx_req

    local buf = C.ngx_http_lua_kong_ssl_get_session_id(r, size_ptr, errmsg)
    if buf == nil then
        if errmsg[0] == nil then
            -- no session id is present
            return nil
        end

        return nil, ffi_string(errmsg[0])
    end

    return to_hex(ffi_string(buf, size_ptr[0]))
end


do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['balancer'] = true,
        ['access'] = true,
        ['content'] = true,
        ['log'] = true,
    }

    function _M.get_full_client_certificate_chain()
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        local r = getfenv(0).__ngx_req

        size_ptr[0] = DEFAULT_CERT_CHAIN_SIZE

::again::

        local buf = get_string_buf(size_ptr[0])

        local ret = C.ngx_http_lua_kong_ffi_get_full_client_certificate_chain(
            r, buf, size_ptr)
        if ret == NGX_OK then
            return ffi_string(buf, size_ptr[0])
        end

        if ret == NGX_ERROR then
            return nil, "error while obtaining client certificate chain"
        end

        if ret == NGX_ABORT then
            return nil,
                   "connection is not TLS or TLS support for Nginx not enabled"
        end

        if ret == NGX_DECLINED then
            return nil
        end

        if ret == NGX_AGAIN then
            goto again
        end

        error("unknown return code: ", tostring(ret))
    end
end


return _M
