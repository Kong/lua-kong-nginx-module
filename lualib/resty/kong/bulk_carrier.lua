assert(ngx.config.subsystem == "http", "bulk carrier is only available in the HTTP subsystem")

local ffi                   = require("ffi")
local base                  = require("resty.core.base")
local tablepool             = require("tablepool")
local buffer                = require("string.buffer")

local C                     = ffi.C
local assert                = assert
local get_request           = base.get_request
local tablepool_fetch       = tablepool.fetch
local tablepool_release     = tablepool.release
local new_tab               = require("table.new")

local NGX_OK                    = ngx.OK
local NGX_AGAIN                 = ngx.AGAIN

local INIT_BUFF_SIZE                = 4096
local BUF_SIZE_WARN_THRESHOLD       = 1024 * 1024 * 4 -- 4MBytes
local INVALID_HEADER_NAME_ERR       = "invalid header name: %s, " ..
                                      "header names must be lowercase," ..
                                      "alphanumeric strings or underscores"


ffi.cdef[[
void *
ngx_http_lua_kong_ffi_bulk_carrier_new();

void
ngx_http_lua_kong_ffi_bulk_carrier_free(void *bc);

uint32_t
ngx_http_lua_kong_ffi_bulk_carrier_register_header(
    void *bc,
    const unsigned char *header_name,
    uint32_t header_name_len,
    int32_t is_request_header);

int32_t
ngx_http_lua_kong_ffi_bulk_carrier_finalize_registration(
    void *bc);

int32_t
ngx_http_lua_kong_ffi_bulk_carrier_fetch(ngx_http_request_t *r,
    void *bc,
    unsigned char *buf,
    uint32_t buf_len,
    uint32_t **request_header_fetch_info,
    uint32_t **response_header_fetch_info);
]]

local _M = {}
local _MT = { __index = _M }

local function is_acceptable_header_name(name)
    -- A header name is not acceptable if it violates any of the following rules:
    -- * All alpha characters must be lowercase
    -- * All non-alpha characters must be numbers or underscores
    return name:match("^[a-z0-9_]+$")
end

function _M.new(request_headers, response_headers)
    local self = {
        name = name,
        bc = C.ngx_http_lua_kong_ffi_bulk_carrier_new(),
        request_header_idx2name = new_tab(#request_headers * 3, 0),
        response_header_idx2name = new_tab(#response_headers * 3, 0),
        request_header_count = #request_headers,
        response_header_count = #response_headers,
        buffer = buffer.new(INIT_BUFF_SIZE),
        tablepool_name = nil,
    }

    assert(self.bc ~= nil, "failed to create bulk carrier")
    self.bc = ffi.gc(self.bc, C.ngx_http_lua_kong_ffi_bulk_carrier_free)

    self.tablepool_name = "bulk_carrier_" ..
                          table.concat(request_headers, "_") ..
                          "_" ..
                          table.concat(response_headers, "_")

    for _k, v in ipairs(request_headers) do
        if not is_acceptable_header_name(v) then
            return nil, INVALID_HEADER_NAME_ERR:format(v)
        end

        local header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
            self.bc,
            v,
            #v,
            1
        )
        if header_idx == 0 then
            return nil, "failed to register request header: " .. v
        end

        self.request_header_idx2name[header_idx] = v

        local v_dash = v:gsub("_", "-")
        if v_dash ~= v then
            ngx.log(ngx.DEBUG,"header name " .. v .. " contains underscores, registering dashed version as well: " .. v_dash)
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_dash,
                #v_dash,
                1
            )
            assert(header_idx ~= 0, "failed to register request header (dashed): " .. v_dash)

            self.request_header_idx2name[header_idx] = v
        end
    end

    for _k, v in ipairs(response_headers) do
        if not is_acceptable_header_name(v) then
            return nil, INVALID_HEADER_NAME_ERR:format(v)
        end

        local header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
            self.bc,
            v,
            #v,
            0
        )
        if header_idx == 0 then
            return nil, "failed to register response header: " .. v
        end

        self.response_header_idx2name[header_idx] = v

        local v_dash = v:gsub("_", "-")
        if v_dash ~= v then
            ngx.log(ngx.DEBUG,"header name " .. v .. " contains underscores, registering dashed version as well: " .. v_dash)
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_dash,
                #v_dash,
                0
            )
            assert(header_idx ~= 0, "failed to register response header (dashed): " .. v_dash)

            self.response_header_idx2name[header_idx] = v
        end
    end

    local rc = C.ngx_http_lua_kong_ffi_bulk_carrier_finalize_registration(self.bc)
    if rc ~= NGX_OK then
        return nil, "failed to finalize registration"
    end

    return setmetatable(self, _MT)
end


local p_request_header_fetch_info = ffi.new("uint32_t*[1]")
local p_response_header_fetch_info = ffi.new("uint32_t*[1]")
function _M:fetch()
    local r = get_request()
    local buf = self.buffer
    local buf_ptr, buf_len

::again::
    buf:reset()
    buf_ptr, buf_len = buf:ref()

    local rc = C.ngx_http_lua_kong_ffi_bulk_carrier_fetch(
        r,
        self.bc,
        buf_ptr,
        buf_len,
        p_request_header_fetch_info,
        p_response_header_fetch_info
    )

    if rc == NGX_AGAIN then
        ngx.log(
            ngx.INFO,
            string.format(
                "[bulk carrier] buffer too small, resizing from %d to %d",
                buf_len,
                buf_len * 2
            )
        )

        local _, new_buf_len = buf:reserve(buf_len * 2)
        assert(
            new_buf_len >= buf_len * 2,
            string.format(
                "[bulk carrier] failed to resize buffer from %d to %d",
                buf_len,
                buf_len * 2
            )
        )

        if new_buf_len >= BUF_SIZE_WARN_THRESHOLD then
            ngx.log(
                ngx.WARN, -- TODO: NOTICE OR WARN?
                string.format(
                    "[bulk carrier] buffer size is too large," ..
                    "which may indicate a problem with the bulk carrier " ..
                    "as it is not expected to handle such large header values." ..
                    "Current buffer size: %d bytes",
                    new_buf_len
                )
            )
        end

        goto again
    end

    if rc ~= NGX_OK then
        return nil, "failed to fetch headers"
    end

    local nrec = self.request_header_count + self.response_header_count
    local request_headers = tablepool_fetch(self.tablepool_name, 0, nrec)
    local response_headers = tablepool_fetch(self.tablepool_name, 0, nrec)
    local request_header_idx2name = self.request_header_idx2name
    local response_header_idx2name = self.response_header_idx2name

    local request_header_fetch_info = p_request_header_fetch_info[0]
    local response_header_fetch_info = p_response_header_fetch_info[0]

    for i = 0, self.request_header_count * 2 - 1, 2 do
        local hdr_idx = request_header_fetch_info[i]
        if hdr_idx == 0 then
            break
        end

        local hdr_v_len = request_header_fetch_info[i + 1]
        local hdr_name = request_header_idx2name[hdr_idx]

        request_headers[hdr_name] = buf:get(hdr_v_len)
    end

    for i = 0, self.response_header_count * 2 - 1, 2 do
        local hdr_idx = response_header_fetch_info[i]
        if hdr_idx == 0 then
            break
        end

        local hdr_v_len = response_header_fetch_info[i + 1]
        local hdr_name = response_header_idx2name[hdr_idx]

        response_headers[hdr_name] = buf:get(hdr_v_len)
    end

    return request_headers, response_headers
end


function _M:recycle(request_headers, response_headers, no_clear)
    no_clear = no_clear or false
    tablepool_release(self.tablepool_name, request_headers, no_clear)
    tablepool_release(self.tablepool_name, response_headers, no_clear)
end


return _M
