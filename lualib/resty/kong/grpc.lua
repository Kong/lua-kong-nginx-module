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
local base = require("resty.core.base")
base.allows_subsystem('http')


ffi.cdef([[
int ngx_http_lua_kong_ffi_set_grpc_authority(ngx_http_request_t *r,
    const char *buf, size_t buf_len);
]])


local error = error
local C = ffi.C
local get_request = base.get_request
local get_phase = ngx.get_phase


local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR


do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['access'] = true,
    }

    function _M.set_authority(authority)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        local r = get_request()

        local ret = C.ngx_http_lua_kong_ffi_set_grpc_authority(r,
                                                               authority,
                                                               #authority)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "no memory"
        end

        error("unknown return code: " .. tostring(ret))
    end
end


return _M
