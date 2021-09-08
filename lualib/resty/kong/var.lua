local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local type = type
local error = error
local tostring = tostring
local tonumber = tonumber
local getmetatable = getmetatable
local get_request = base.get_request
local get_size_ptr = base.get_size_ptr
local subsystem = ngx.config.subsystem
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR
local NGX_DECLINED = ngx.DECLINED


local variable_index = {}
local metatable_patched

local ngx_lua_kong_ffi_var_get_by_index
local ngx_lua_kong_ffi_var_set_by_index
local ngx_lua_kong_ffi_var_load_indexes


if subsystem == "http" then
    ffi.cdef[[
    int ngx_http_lua_kong_ffi_var_get_by_index(ngx_http_request_t *r,
        unsigned int var_index, char **value, size_t *value_len, char **err);

    int ngx_http_lua_kong_ffi_var_set_by_index(ngx_http_request_t *r,
        unsigned int index, const unsigned char *value, size_t value_len,
        char **err);

    unsigned int ngx_http_lua_kong_ffi_var_load_indexes(ngx_str_t **names);
    ]]

    ngx_lua_kong_ffi_var_get_by_index = C.ngx_http_lua_kong_ffi_var_get_by_index
    ngx_lua_kong_ffi_var_set_by_index = C.ngx_http_lua_kong_ffi_var_set_by_index
    ngx_lua_kong_ffi_var_load_indexes = C.ngx_http_lua_kong_ffi_var_load_indexes
end


local value_ptr = ffi_new("unsigned char *[1]")
local errmsg = base.get_errmsg_ptr()

local function load_indexes()
    if ngx.get_phase() ~= "init" then
        error("load_indexes can only be called in init phase")
    end

    local count = ngx_lua_kong_ffi_var_load_indexes(nil)
    count = tonumber(count)

    local names_buf = ffi_new("ngx_str_t *[?]", count)

    local rc = ngx_lua_kong_ffi_var_load_indexes(names_buf)

    if rc == NGX_OK then
        for i = 0, count-1 do
            local name = ffi_str(names_buf[i].data, names_buf[i].len)
            variable_index[name] = i
        end
    end

    return variable_index
end

local function var_get_by_index(index)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local value_len = get_size_ptr()

    local rc = ngx_lua_kong_ffi_var_get_by_index(r, index, value_ptr, value_len, errmsg)

    if rc == NGX_OK then
        return ffi_str(value_ptr[0], value_len[0])
    end

    if rc == NGX_DECLINED then
        return nil
    end

    if rc == NGX_ERROR then
        error(ffi_str(errmsg[0]), 2)
    end
end

local function var_set_by_index(index, value)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local value_len
    if value == nil then
        value_len = 0
    else
        if type(value) ~= 'string' then
            value = tostring(value)
        end
        value_len = #value
    end

    local rc = ngx_lua_kong_ffi_var_set_by_index(r, index, value,
                                                 value_len, errmsg)

    if rc == NGX_OK then
        return
    end

    if rc == NGX_ERROR then
        error(ffi_str(errmsg[0]), 2)
    end
end

local function patch_metatable()
    if ngx.get_phase() ~= "init" then
        error("patch_metatable can only be called in init phase")
    end

    if metatable_patched then
        error("patch_metatable should only be called once")
    end

    patch_metatable = true

    load_indexes()

    local mt = getmetatable(ngx.var)
    local orig_get = mt.__index
    local orig_set = mt.__newindex

    mt.__index = function(self, name)
        local index = variable_index[name]
        if index then
            return var_get_by_index(index)
        end

        return orig_get(self, name)
    end

    mt.__newindex = function(self, name, value)
        local index = variable_index[name]
        if index then
            return var_set_by_index(index, value)
        end

        return orig_set(self, name, value)
    end
end

if subsystem == "stream" then
    patch_metatable = function() end
    load_indexes = function() end
end


return {
    patch_metatable = patch_metatable,
    load_indexes = load_indexes,
}
