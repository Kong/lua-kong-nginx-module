-- Copyright 2019-2022 Kong Inc.

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
base.allows_subsystem("http")


ffi.cdef([[
int ngx_http_lua_kong_ffi_set_log_level(ngx_http_request_t *r, int level);
]])


local get_phase = ngx.get_phase
local type = type
local error = error
local tostring = tostring
local C = ffi.C
local get_request = base.get_request


local NGX_OK    = ngx.OK
local NGX_EMERG = ngx.EMERG
local NGX_DEBUG = ngx.DEBUG


local ALLOWED_PHASES = {
    ["balancer"] = true,
    ["rewrite"] = true,
    ["access"] = true,
    ["content"] = true,
    ["timer"] = true,
}

function _M.set_log_level(level)
    if not ALLOWED_PHASES[get_phase()] then
        error("API disabled in the current context", 2)
    end

    local type_level = type(level)
    if type_level ~= "number" then
        error("incorrect level, expects a number, got " .. type_level, 2)
    end

    if level < NGX_EMERG or level > NGX_DEBUG then
        error("invalid level " .. tostring(level), 2)
    end

    local r = get_request()

    if not r then
        error("could not get current request")
    end

    local ret = C.ngx_http_lua_kong_ffi_set_log_level(r, level)

    if ret == NGX_OK then
        return true
    end

    error("unknown return code: " .. tostring(ret))
end


return _M
