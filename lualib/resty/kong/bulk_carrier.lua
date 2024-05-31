local ffi                   = require("ffi")
local base                  = require("resty.core.base")
local tablepool             = require("tablepool")

local C                     = ffi.C
local assert                = assert
local ffi_string            = ffi.string
local get_request           = base.get_request
local get_string_buf        = base.get_string_buf
local get_string_buf_size   = base.get_string_buf_size
local tablepool_fetch       = tablepool.fetch
local tablepool_release     = tablepool.release
local new_tab               = require("table.new")

local NGX_OK                    = ngx.OK
local NGX_AGAIN                 = ngx.AGAIN
local NGX_ERROR                 = ngx.ERROR


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

function _M.new(request_headers, response_headers)
    local self = {
        bc = C.ngx_http_lua_kong_ffi_bulk_carrier_new(),
        request_header_idx2name = new_tab(#request_headers * 3, 0),
        response_header_idx2name = new_tab(#response_headers * 3, 0),
        request_header_count = #request_headers,
        response_header_count = #response_headers,
        tablepool_name = nil,
    }

    assert(self.bc ~= nil, "failed to create bulk carrier")

    self.tablepool_name = "bulk_carrier_" ..
                          table.concat(request_headers, "_") ..
                          "_" ..
                          table.concat(response_headers, "_")

    for _k, v in ipairs(request_headers) do
        v = v:lower()

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

        local v_underscore = v:gsub("-", "_")
        if v_underscore ~= v then
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_underscore,
                #v_underscore,
                1
            )
            if header_idx == 0 then
                return nil, "failed to register request header (underscored): " .. v_underscore
            end

            self.request_header_idx2name[header_idx] = v
        end

        local v_dash = v:gsub("_", "-")
        if v_dash ~= v then
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_dash,
                #v_dash,
                1
            )
            if header_idx == 0 then
                return nil, "failed to register request header (dashed): " .. v_dash
            end

            self.request_header_idx2name[header_idx] = v
        end
    end

    for _k, v in ipairs(response_headers) do
        v = v:lower()

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

        local v_underscore = v:gsub("-", "_")
        if v_underscore ~= v then
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_underscore,
                #v_underscore,
                0
            )
            if header_idx == 0 then
                return nil, "failed to register response header (underscored): " .. v_underscore
            end

            self.response_header_idx2name[header_idx] = v
        end

        local v_dash = v:gsub("_", "-")
        if v_dash ~= v then
            header_idx = C.ngx_http_lua_kong_ffi_bulk_carrier_register_header(
                self.bc,
                v_dash,
                #v_dash,
                0
            )
            if header_idx == 0 then
                return nil, "failed to register response header (dashed): " .. v_dash
            end

            self.response_header_idx2name[header_idx] = v
        end
    end

    local rc = C.ngx_http_lua_kong_ffi_bulk_carrier_finalize_registration(self.bc)
    if rc ~= NGX_OK then
        return nil, "failed to finalize registration"
    end

    ffi.gc(self.bc, C.ngx_http_lua_kong_ffi_bulk_carrier_free)

    return setmetatable(self, { __index = _M })
end


local p_request_header_fetch_info = ffi.new("uint32_t*[1]")
local p_response_header_fetch_info = ffi.new("uint32_t*[1]")
function _M:fetch()
    local r = get_request()
    local buf_size = get_string_buf_size()
    local buf = get_string_buf(buf_size)

::again::
    local rc = C.ngx_http_lua_kong_ffi_bulk_carrier_fetch(
        r,
        self.bc,
        buf,
        buf_size,
        p_request_header_fetch_info,
        p_response_header_fetch_info
    )

    if rc == NGX_AGAIN then
        buf = ffi_string(buf, buf_size * 2)
        buf_size = buf_size * 2
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
    local buf_offset = 0

    for i = 0, self.request_header_count * 2 - 1, 2 do
        local header_idx = request_header_fetch_info[i]
        if header_idx == 0 then
            break
        end

        local header_value_len = request_header_fetch_info[i + 1]
        local header_name = request_header_idx2name[header_idx]
        local header_value = ffi_string(buf + buf_offset, header_value_len)
        buf_offset = buf_offset + header_value_len

        request_headers[header_name] = header_value
    end

    for i = 0, self.response_header_count * 2 - 1, 2 do
        local header_idx = response_header_fetch_info[i]
        if header_idx == 0 then
            break
        end

        local header_value_len = response_header_fetch_info[i + 1]

        local header_name = response_header_idx2name[header_idx]
        local header_value = ffi_string(buf + buf_offset, header_value_len)
        buf_offset = buf_offset + header_value_len

        response_headers[header_name] = header_value
    end

    return request_headers, response_headers
end


function _M:recycle(request_headers, response_headers)
    tablepool_release(self.tablepool_name, request_headers)
    tablepool_release(self.tablepool_name, response_headers)
end


return _M
