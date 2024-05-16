local ffi                   = require "ffi"
local base                  = require "resty.core.base"

local C                     = ffi.C
local error                 = error
local assert                = assert
local ffi_new               = ffi.new
local ffi_string            = ffi.string
local get_request           = base.get_request
local get_string_buf        = base.get_string_buf
local get_string_buf_size   = base.get_string_buf_size

local NGX_OK                    = ngx.OK
local NGX_AGAIN                 = ngx.AGAIN
local NGX_ERROR                 = ngx.ERROR
local DEFAULT_VALUE_BUF_SIZE    = 16 * 1024 -- 16KB


ffi.cdef[[
int64_t
ngx_http_lua_ffi_header_bulk_carrier_init();

int64_t
ngx_http_lua_kong_ffi_get_response_headers(ngx_http_request_t *r,
    int32_t* value_offsets,
    uint8_t* buf,
    uint32_t buf_len);
]]

local _M = {}


function _M.init()
    local rc = C.ngx_http_lua_ffi_header_bulk_carrier_init()
    assert(rc == NGX_OK, "failed to init bulk carrier")
end

function _M.get_response_headers()
    local r = get_request()
    local value_offsets = ffi_new("int32_t[?]", 64)
    local buf_size = DEFAULT_VALUE_BUF_SIZE
    local buf = get_string_buf(buf_size)

    local rc = C.ngx_http_lua_kong_ffi_get_response_headers(r, value_offsets, buf, buf_size)
    assert(rc == NGX_OK, "failed to get response headers: " .. rc)

    local values = {}
    for i = 0, 62 do
        local offset = value_offsets[i]
        if offset == -1 then
            goto continue
        end

        local next_offset = value_offsets[i + 1]

        local value = ffi_string(buf + offset, next_offset - offset)
        table.insert(values, value)

        ::continue::
    end

    return values
end


return _M
