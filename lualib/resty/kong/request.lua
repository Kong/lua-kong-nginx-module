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
base.allows_subsystem("http")


ffi.cdef([[
int
ngx_http_lua_kong_ffi_req_had_body(ngx_http_request_t *r);
]])


local C           = ffi.C
local error       = error
local get_request = base.get_request
local http_version = ngx.req.http_version


function _M.had_body()
    local r = get_request()

    if not r then
        error("no request found")
    end

    if http_version() == 3.0 then
        error("had_body() does not support HTTP/3 yet")
    end

    local res = C.ngx_http_lua_kong_ffi_req_had_body(r)

    if res < 0 then
        return nil, "pending"
    end

    return res == 1
end


return _M
