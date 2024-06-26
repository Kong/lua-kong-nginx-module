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
int
ngx_http_lua_kong_ffi_set_dynamic_log_level(int log_level, int timeout);

int
ngx_http_lua_kong_ffi_get_dynamic_log_level(ngx_http_request_t *r,
    int *current_log_level, int *timeout, int *original_log_level);
]])


local type          = type
local error         = error
local tostring      = tostring
local C             = ffi.C
local math_floor    = math.floor
local assert        = assert

local NGX_OK        = ngx.OK


function _M.set_log_level(level, timeout)
    assert(type(level) == "number", "level must be a number")
    assert(math_floor(level) == level, "level must be an integer")
    assert(type(timeout) == "number", "timeout must be a number")
    assert(math_floor(timeout) == timeout, "timeout must be an integer")
    assert(timeout >= 0, "timeout must be equal to or greater than 0")

    local rc = C.ngx_http_lua_kong_ffi_set_dynamic_log_level(level, timeout)

    if rc ~= NGX_OK then
        error("failed to set dynamic log level: " .. tostring(rc))
    end

    return true
end


do
    local tonumber = tonumber
    local get_request = base.get_request

    local current_log_level = ffi.new("int[1]")
    local original_log_level = ffi.new("int[1]")
    local timeout = ffi.new("int[1]")

    function _M.get_log_level()
        local rc = C.ngx_http_lua_kong_ffi_get_dynamic_log_level(get_request(),
                                                                 current_log_level,
                                                                 timeout,
                                                                 original_log_level)
        if rc ~= NGX_OK then
            error("failed to get dynamic log level: " .. tostring(rc))
        end

        return tonumber(current_log_level[0]), tonumber(timeout[0]),
               tonumber(original_log_level[0])
    end
end


return _M
