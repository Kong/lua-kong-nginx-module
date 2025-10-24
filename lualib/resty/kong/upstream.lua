-- Copyright 2019-2025 Kong Inc.

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
local select = select
base.allows_subsystem("http")

ffi.cdef([[
int
ngx_http_lua_ffi_set_next_upstream(ngx_http_request_t *r, uint32_t next_upstream, char **err);
const uint32_t ngx_http_lua_kong_next_upstream_mask_error;
const uint32_t ngx_http_lua_kong_next_upstream_mask_timeout;
const uint32_t ngx_http_lua_kong_next_upstream_mask_invalid_header;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_500;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_502;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_503;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_504;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_403;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_404;
const uint32_t ngx_http_lua_kong_next_upstream_mask_http_429;
const uint32_t ngx_http_lua_kong_next_upstream_mask_off;
const uint32_t ngx_http_lua_kong_next_upstream_mask_non_idempotent;
]])

local type = type
local C = ffi.C
local get_request = base.get_request
local ffi_str = ffi.string

local NGX_OK = ngx.OK

local next_upstream_table = {
    error = C.ngx_http_lua_kong_next_upstream_mask_error,
    timeout = C.ngx_http_lua_kong_next_upstream_mask_timeout,
    invalid_header = C.ngx_http_lua_kong_next_upstream_mask_invalid_header,
    http_500 = C.ngx_http_lua_kong_next_upstream_mask_http_500,
    http_502 = C.ngx_http_lua_kong_next_upstream_mask_http_502,
    http_503 = C.ngx_http_lua_kong_next_upstream_mask_http_503,
    http_504 = C.ngx_http_lua_kong_next_upstream_mask_http_504,
    http_403 = C.ngx_http_lua_kong_next_upstream_mask_http_403,
    http_404 = C.ngx_http_lua_kong_next_upstream_mask_http_404,
    http_429 = C.ngx_http_lua_kong_next_upstream_mask_http_429,
    off = C.ngx_http_lua_kong_next_upstream_mask_off,
    non_idempotent = C.ngx_http_lua_kong_next_upstream_mask_non_idempotent,
}

function _M.set_next_upstream(...)
    local nargs = select("#", ...)
    if nargs == 0 then
        return "no argument"
    end

    local r = get_request()
    if not r then
        return "no request found"
    end

    local arg_table = { ... }
    local next_upstream = 0
    for i = 1, nargs do
        local v = arg_table[i]
        if type(v) ~= "string" then
            return "argument #" .. i .. " is not a string"
        end

        local next_upstream_value = next_upstream_table[v]
        if not next_upstream_value then
            return "argument #" .. i .. " is not a valid argument"
        end

        next_upstream = bit.bor(next_upstream, next_upstream_value)
    end

    local err = ffi.new("char *[1]")
    local rc = C.ngx_http_lua_ffi_set_next_upstream(r, next_upstream, err)

    if rc ~= NGX_OK then
        return "failed to set upstream next: " .. ffi_str(err[0])
    end

    return nil
end

return _M
