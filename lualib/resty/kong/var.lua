local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local type = type
local error = error
local tostring = tostring
local setmetatable = setmetatable
local getmetatable = getmetatable
local get_request = base.get_request
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local new_tab = base.new_tab
local subsystem = ngx.config.subsystem


local variable_index = {}

local ngx_lua_kong_ffi_var_get_by_index
local ngx_lua_kong_ffi_var_set_by_index
local ngx_lua_kong_ffi_var_load_index


if subsystem == "http" then
    ffi.cdef[[
    int ngx_http_lua_kong_ffi_var_get_by_index(ngx_http_request_t *r,
        unsigned int var_index, char **value, size_t *value_len, char **err);

    int ngx_http_lua_kong_ffi_var_set_by_index(ngx_http_request_t *r,
        unsigned int index, const unsigned char *value, size_t value_len,
        char **err);

    int ngx_http_lua_kong_ffi_var_load_indexes(ngx_str_t **names,
        unsigned int *count, char **err);
    ]]

    ngx_lua_kong_ffi_var_get_by_index = C.ngx_http_lua_kong_ffi_var_get_by_index
    ngx_lua_kong_ffi_var_set_by_index = C.ngx_http_lua_kong_ffi_var_set_by_index
    ngx_lua_kong_ffi_var_load_indexes = C.ngx_http_lua_kong_ffi_var_load_indexes

elseif subsystem == "stream" then
    -- TODO
    ffi.cdef[[
    ]]
end


local value_ptr = ffi_new("unsigned char *[1]")
local errmsg = base.get_errmsg_ptr()

local function load_indexes(count)
    count = count or 100
    local names_buf = ffi_new("ngx_str_t *[?]", count)
    local count_ptr = ffi_new("unsigned int [1]")
    count_ptr[0] = count

    local rc = ngx_lua_kong_ffi_var_load_indexes(names_buf,
                                                 count_ptr, err_msg)
    -- ngx.log(ngx.WARN, "rc = ", rc)

    if rc == 0 then -- NGX_OK
        count = tonumber(count_ptr[0])
        for i=0,count do
            local name = ffi_str(names_buf[i].data, names_buf[i].len)
            variable_index[name] = i
        end
    end

    if rc == -1 then  -- NGX_ERROR
        error(ffi_str(errmsg[0]), 2)
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

    if rc == 0 then -- NGX_OK
        return ffi_str(value_ptr[0], value_len[0])
    end

    if rc == -5 then  -- NGX_DECLINED
        return nil
    end

    if rc == -1 then  -- NGX_ERROR
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

    -- ngx.log(ngx.WARN, "rc = ", rc)

    if rc == 0 then -- NGX_OK
        return
    end

    if rc == -1 then  -- NGX_ERROR
        error(ffi_str(errbuf, errlen[0]), 2)
    end
end

local function patch_metatable()
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

    --setmetatable(ngx.var, mt)
end


return {
    patch_metatable = patch_metatable,
    load_indexes = load_indexes,
}
