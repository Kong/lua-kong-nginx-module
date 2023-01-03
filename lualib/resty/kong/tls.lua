-- Copyright 2019-2020 Kong Inc.

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
local base = require("resty.core.base")

local get_phase = ngx.get_phase
local type = type
local error = error
local tostring = tostring
local C = ffi.C
local ffi_string = ffi.string
local get_string_buf = base.get_string_buf
local size_ptr = base.get_size_ptr()
local orig_get_request = base.get_request
local subsystem = ngx.config.subsystem
base.allows_subsystem('http', 'stream')

local kong_lua_kong_ffi_get_full_client_certificate_chain
local kong_lua_kong_ffi_disable_session_reuse
local kong_lua_kong_ffi_set_upstream_client_cert_and_key
local kong_lua_kong_ffi_set_upstream_ssl_trusted_store
local kong_lua_kong_ffi_set_upstream_ssl_verify
local kong_lua_kong_ffi_set_upstream_ssl_verify_depth

if subsystem == "http" then
    ffi.cdef([[
    int ngx_http_lua_kong_ffi_get_full_client_certificate_chain(
        ngx_http_request_t *r, char *buf, size_t *buf_len);
    const char *ngx_http_lua_kong_ffi_disable_session_reuse(ngx_http_request_t *r);
    int ngx_http_lua_kong_ffi_set_upstream_client_cert_and_key(ngx_http_request_t *r,
        void *_chain, void *_key);
    int ngx_http_lua_kong_ffi_set_upstream_ssl_trusted_store(ngx_http_request_t *r,
        void *_store);
    int ngx_http_lua_kong_ffi_set_upstream_ssl_verify(ngx_http_request_t *r,
        int verify);
    int ngx_http_lua_kong_ffi_set_upstream_ssl_verify_depth(ngx_http_request_t *r,
        int depth);
    ]])

    kong_lua_kong_ffi_get_full_client_certificate_chain = C.ngx_http_lua_kong_ffi_get_full_client_certificate_chain
    kong_lua_kong_ffi_disable_session_reuse = C.ngx_http_lua_kong_ffi_disable_session_reuse
    kong_lua_kong_ffi_set_upstream_client_cert_and_key = C.ngx_http_lua_kong_ffi_set_upstream_client_cert_and_key
    kong_lua_kong_ffi_set_upstream_ssl_trusted_store = C.ngx_http_lua_kong_ffi_set_upstream_ssl_trusted_store
    kong_lua_kong_ffi_set_upstream_ssl_verify = C.ngx_http_lua_kong_ffi_set_upstream_ssl_verify
    kong_lua_kong_ffi_set_upstream_ssl_verify_depth = C.ngx_http_lua_kong_ffi_set_upstream_ssl_verify_depth

elseif subsystem == 'stream' then
    ffi.cdef([[
    int ngx_stream_lua_kong_ffi_proxy_ssl_disable(ngx_stream_lua_request_t *r);
    int ngx_stream_lua_kong_ffi_get_full_client_certificate_chain(ngx_stream_lua_request_t *r,
        char *buf, size_t *buf_len);
    const char *ngx_stream_lua_kong_ffi_disable_session_reuse(ngx_stream_lua_request_t *r);
    int ngx_stream_lua_kong_ffi_set_upstream_client_cert_and_key(ngx_stream_lua_request_t *r,
        void *_chain, void *_key);
    int ngx_stream_lua_kong_ffi_set_upstream_ssl_trusted_store(ngx_stream_lua_request_t *r,
        void *_store);
    int ngx_stream_lua_kong_ffi_set_upstream_ssl_verify(ngx_stream_lua_request_t *r,
        int verify);
    int ngx_stream_lua_kong_ffi_set_upstream_ssl_verify_depth(ngx_stream_lua_request_t *r,
        int depth);
    ]])

    kong_lua_kong_ffi_get_full_client_certificate_chain = C.ngx_stream_lua_kong_ffi_get_full_client_certificate_chain
    kong_lua_kong_ffi_disable_session_reuse = C.ngx_stream_lua_kong_ffi_disable_session_reuse
    kong_lua_kong_ffi_set_upstream_client_cert_and_key = C.ngx_stream_lua_kong_ffi_set_upstream_client_cert_and_key
    kong_lua_kong_ffi_set_upstream_ssl_trusted_store = C.ngx_stream_lua_kong_ffi_set_upstream_ssl_trusted_store
    kong_lua_kong_ffi_set_upstream_ssl_verify = C.ngx_stream_lua_kong_ffi_set_upstream_ssl_verify
    kong_lua_kong_ffi_set_upstream_ssl_verify_depth = C.ngx_stream_lua_kong_ffi_set_upstream_ssl_verify_depth
else
    error("unknown subsystem: " .. subsystem)
end


local DEFAULT_CERT_CHAIN_SIZE = 10240
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR
local NGX_AGAIN = ngx.AGAIN
local NGX_DECLINED = ngx.DECLINED
local NGX_ABORT = -6


local function get_request()
    local r = orig_get_request()

    if not r then
        error("no request found")
    end

    return r
end

function _M.disable_session_reuse()
    if get_phase() ~= 'ssl_cert' then
        error("API disabled in the current context")
    end

    local r = get_request()

    local errmsg = kong_lua_kong_ffi_disable_session_reuse(r)
    if errmsg == nil then
        return true
    end

    return nil, ffi_string(errmsg)
end


do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['balancer'] = true,
        ['access'] = true,
        ['content'] = true,
        ['log'] = true,
        ['preread'] = true,
    }

    function _M.get_full_client_certificate_chain()
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        local r = get_request()

        size_ptr[0] = DEFAULT_CERT_CHAIN_SIZE

::again::

        local buf = get_string_buf(size_ptr[0])

        local ret = kong_lua_kong_ffi_get_full_client_certificate_chain(
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

        error("unknown return code: " .. tostring(ret))
    end
end


do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['balancer'] = true,
        ['access'] = true,
        ['preread'] = true,
    }

    function _M.set_upstream_cert_and_key(chain, key)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        if not chain or not key then
            error("chain and key must not be nil", 2)
        end

        local r = get_request()

        local ret = kong_lua_kong_ffi_set_upstream_client_cert_and_key(
            r, chain, key)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "error while setting upstream client cert and key"
        end

        error("unknown return code: " .. tostring(ret))
    end

    do
        local store_lib = require("resty.openssl.x509.store")

        function _M.set_upstream_ssl_trusted_store(store)
            if not ALLOWED_PHASES[get_phase()] then
                error("API disabled in the current context", 2)
            end

            if not store_lib.istype(store) then
                error("store expects a resty.openssl.x509.store" ..
                    " object but found " .. type(store), 2)
            end

            local r = get_request()

            local ret = kong_lua_kong_ffi_set_upstream_ssl_trusted_store(
                r, store.ctx)
            if ret == NGX_OK then
                return true
            end

            if ret == NGX_ERROR then
                return nil, "error while setting upstream trusted store"
            end

            error("unknown return code: " .. tostring(ret))
        end
    end

    function _M.set_upstream_ssl_verify(verify)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        if type(verify) ~= 'boolean' then
            error("verify expects a boolean but found " .. type(verify), 2)
        end

        local r = get_request()

        local ret = kong_lua_kong_ffi_set_upstream_ssl_verify(
            r, verify)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "error while setting upstream ssl verify mode"
        end

        error("unknown return code: " .. tostring(ret))
    end

    function _M.set_upstream_ssl_verify_depth(depth)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        if type(depth) ~= 'number' then
            error("depth expects a number but found " .. type(depth), 2)
        end

        if depth < 0 then
            error("depth expects a non-negative integer but found " .. tostring(depth), 2)
        end

        local r = get_request()

        local ret = kong_lua_kong_ffi_set_upstream_ssl_verify_depth(
            r, depth)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "error while setting upstream ssl verify depth"
        end

        error("unknown return code: " .. tostring(ret))
    end
end

if ngx.config.subsystem == "stream" then
    do
        local ALLOWED_PHASES = {
            ['preread'] = true,
            ['balancer'] = true,
        }

        function _M.disable_proxy_ssl()
            if not ALLOWED_PHASES[get_phase()] then
                error("API disabled in the current context", 2)
            end

            local r = get_request()

            local ret = C.ngx_stream_lua_kong_ffi_proxy_ssl_disable(r)
            if ret == NGX_OK then
                return true
            end

            if ret == NGX_ERROR then
                return nil, "error while disabling upstream TLS handshake"
            end

            error("unknown return code: " .. tostring(ret))
        end
    end
end


return _M
