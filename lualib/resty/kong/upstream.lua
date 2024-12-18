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
ngx_http_lua_ffi_set_next_upstream(ngx_http_request_t *r, uint32_t next_upstream, char **err);
]])

local type = type
local C = ffi.C
local get_request = base.get_request
local ffi_str = ffi.string

local NGX_OK = ngx.OK

local next_upstream_table = {
	error = 0x00000002,
	timeout = 0x00000004,
	invalid_header = 0x00000008,
	http_500 = 0x00000010,
	http_502 = 0x00000020,
	http_503 = 0x00000040,
	http_504 = 0x00000080,
	http_403 = 0x00000100,
	http_404 = 0x00000200,
	http_429 = 0x00000400,
	updating = 0x00000800,
	off = 0x00001000,
	non_idempotent = 0x00004000,
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
