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
local new_tab               = require("table.new")

local NGX_OK                    = ngx.OK
local NGX_AGAIN                 = ngx.AGAIN
local NGX_ERROR                 = ngx.ERROR
local DEFAULT_VALUE_BUF_SIZE    = 16 * 1024 -- 16KB

local REQ_HDR_IDX               = {}
local RESP_HDR_IDX              = {}


ffi.cdef[[
void
ngx_http_lua_kong_ffi_get_req_bulk_name(uint32_t index,
    uint8_t** buf,
    uint32_t* len);

void
ngx_http_lua_kong_ffi_get_resp_bulk_name(uint32_t index,
    uint8_t** buf,
    uint32_t* len);

uint32_t
ngx_http_lua_kong_ffi_get_value_offset_length();

int64_t
ngx_http_lua_kong_ffi_fetch_analytics_bulk(ngx_http_request_t *r,
    int32_t* value_offsets,
    uint8_t* buf,
    uint32_t buf_len,
    uint32_t* req_hdrs,
    uint32_t* resp_hdrs);
]]

local _M = {}


function _M.init()
    local buf = ffi.new("uint8_t*[?]", 1)
    local len = ffi.new("uint32_t[?]", 1)
    local idx = 0

    while true do
        C.ngx_http_lua_kong_ffi_get_req_bulk_name(idx, buf, len)
        if len[0] == 0 then
            break
        end

        REQ_HDR_IDX[idx] = ffi_string(buf[0], len[0])
        idx = idx + 1
    end

    idx = 0
    while true do
        C.ngx_http_lua_kong_ffi_get_resp_bulk_name(idx, buf, len)
        if len[0] == 0 then
            break
        end

        RESP_HDR_IDX[idx] = ffi_string(buf[0], len[0])
        idx = idx + 1
    end
end

local value_offset_length = C.ngx_http_lua_kong_ffi_get_value_offset_length()
local value_offsets = ffi_new("int32_t[?]", value_offset_length)
local req_hdrs = ffi_new("uint32_t[?]", 1)
local resp_hdrs = ffi_new("uint32_t[?]", 1)
function _M.get_response_headers()
    local r = get_request()
    local buf_size = DEFAULT_VALUE_BUF_SIZE
    local buf = get_string_buf(buf_size)

    local rc = C.ngx_http_lua_kong_ffi_fetch_analytics_bulk(r, value_offsets, buf, buf_size, req_hdrs, resp_hdrs)
    assert(rc == NGX_OK, "failed to get response headers")

    local request_headers = new_tab(0, 8)
    local response_headers = new_tab(0, 64)
    local remaining_req_hdrs = req_hdrs[0]
    local remaining_resp_hdrs = resp_hdrs[0]
    local bulk = {
        request_headers = request_headers,
        response_headers = response_headers,
    }

    for i = 0, value_offset_length - 1, 2 do
        local offset = value_offsets[i]
        if offset == -1 then
            goto continue
        end

        local tab, hdr_name
        if remaining_req_hdrs ~= 0 then
            tab = request_headers
            hdr_name = assert(REQ_HDR_IDX[i / 2], "failed to get request header name")
            remaining_req_hdrs = remaining_req_hdrs - 1
        else
            tab = response_headers
            hdr_name = assert(RESP_HDR_IDX[i / 2], "failed to get response header name")
            remaining_resp_hdrs = remaining_resp_hdrs - 1
        end

        tab[hdr_name] = ffi_string(buf + offset, value_offsets[i + 1])

        ::continue::
    end

    assert(remaining_req_hdrs == 0, "failed to parse all request headers")
    assert(remaining_resp_hdrs == 0, "failed to parse all response headers")

    return bulk
end


return _M
