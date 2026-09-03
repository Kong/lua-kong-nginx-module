local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local var = ngx.var
local req = ngx.req
local type = type
local error = error
local assert = assert
local tostring = tostring
local tonumber = tonumber
local getmetatable = getmetatable
local orig_get_request = base.get_request
local get_size_ptr = base.get_size_ptr
local get_phase = ngx.get_phase
local subsystem = ngx.config.subsystem
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR
local NGX_DECLINED = ngx.DECLINED


local variable_index = {}
local cookie_indexes = {}
local metatable_patched
local str_replace_char
local replace_dashes_lower

local find = string.find

local HTTP_PREFIX = "http_"

--Add back if stream module is implemented to aid readability
--see bottom of: https://luajit.org/ext_ffi_tutorial.html
--local ngx_lua_kong_ffi_var_get_by_index
--local ngx_lua_kong_ffi_var_set_by_index
--local ngx_lua_kong_ffi_var_load_indexes


if subsystem == "http" then
    ffi.cdef[[
    int ngx_http_lua_kong_ffi_var_get_by_index(ngx_http_request_t *r,
        unsigned int var_index, char **value, size_t *value_len, char **err);

    int ngx_http_lua_kong_ffi_var_set_by_index(ngx_http_request_t *r,
        unsigned int index, const unsigned char *value, size_t value_len,
        char **err);

    int ngx_http_lua_kong_ffi_var_invalidate_by_index(ngx_http_request_t *r,
        unsigned int index, char **err);

    unsigned int ngx_http_lua_kong_ffi_var_load_indexes(ngx_str_t **names);
    ]]

    --Add back if stream module is implemented to aid readability
    --see bottom of: https://luajit.org/ext_ffi_tutorial.html
    --ngx_lua_kong_ffi_var_get_by_index = C.ngx_http_lua_kong_ffi_var_get_by_index
    --ngx_lua_kong_ffi_var_set_by_index = C.ngx_http_lua_kong_ffi_var_set_by_index
    --ngx_lua_kong_ffi_var_load_indexes = C.ngx_http_lua_kong_ffi_var_load_indexes
    
    str_replace_char = require("resty.core.utils").str_replace_char
    replace_dashes_lower = function(str)
        return str_replace_char(str:lower(), "-", "_")
    end
end


local value_ptr = ffi_new("unsigned char *[1]")
local errmsg = base.get_errmsg_ptr()


local function get_request()
    local r = orig_get_request()

    if not r then
        error("no request found")
    end

    return r
end

local function load_indexes()
    if get_phase() ~= "init" then
        error("load_indexes can only be called in init phase")
    end

    --Add back if stream module is implemented to aid readability
    --see bottom of: https://luajit.org/ext_ffi_tutorial.html
    --local count = ngx_lua_kong_ffi_var_load_indexes(nil)
    local count = C.ngx_http_lua_kong_ffi_var_load_indexes(nil)
    count = tonumber(count)

    local names_buf = ffi_new("ngx_str_t *[?]", count)

    --Add back if stream module is implemented to aid readability
    --see bottom of: https://luajit.org/ext_ffi_tutorial.html
    --local rc = ngx_lua_kong_ffi_var_load_indexes(names_buf)
    local rc = C.ngx_http_lua_kong_ffi_var_load_indexes(names_buf)

    if rc == NGX_OK then
        for i = 0, count - 1 do
            local name = ffi_str(names_buf[i].data, names_buf[i].len)
            variable_index[name] = i
        end
    end

    -- one Cookie header feeds every $cookie_* variable, so rewriting it
    -- makes all of them stale at once
    cookie_indexes = {}

    for name, index in pairs(variable_index) do
        if find(name, "cookie_", 1, true) == 1 then
            cookie_indexes[#cookie_indexes + 1] = index
        end
    end

    return variable_index
end


local function var_get_by_index(index)
    local r = get_request()

    local value_len = get_size_ptr()

    --Add back if stream module is implemented to aid readability
    --see bottom of: https://luajit.org/ext_ffi_tutorial.html
    --local rc = ngx_lua_kong_ffi_var_get_by_index(r, index, value_ptr, value_len, errmsg)
    local rc = C.ngx_http_lua_kong_ffi_var_get_by_index(r, index, value_ptr,
                                                        value_len, errmsg)

    if rc == NGX_OK then
        local value = ffi_str(value_ptr[0], value_len[0])
        return value
    end

    if rc == NGX_DECLINED then
        return nil
    end

    assert(rc == NGX_ERROR)
    error(ffi_str(errmsg[0]), 2)
end


local function var_invalidate_by_index(index)
    local r = get_request()

    local rc = C.ngx_http_lua_kong_ffi_var_invalidate_by_index(r, index,
                                                               errmsg)
    if rc == NGX_OK then
        return
    end

    assert(rc == NGX_ERROR)
    error(ffi_str(errmsg[0]), 2)
end


local function var_set_by_index(index, value)
    local r = get_request()

    local value_len
    if value == nil then
        value_len = 0

    else
        if type(value) ~= 'string' then
            value = tostring(value)
        end

        value_len = #value
    end

    --Add back if stream module is implemented to aid readability
    --see bottom of: https://luajit.org/ext_ffi_tutorial.html
    --local rc = ngx_lua_kong_ffi_var_set_by_index(r, index, value,
    --                                             value_len, errmsg)
    local rc = C.ngx_http_lua_kong_ffi_var_set_by_index(r, index, value,
                                                        value_len, errmsg)

    if rc == NGX_OK then
        return
    end

    assert(rc == NGX_ERROR)
    error(ffi_str(errmsg[0]), 2)
end


-- Rewriting a request header leaves the variables fed by it holding the
-- value they cached before the rewrite, so drop those cached values. Only
-- for this request: dropping the index instead, as this once did, would send
-- every later request in the worker down the slower unindexed read as well.
--
-- $args and its relatives need nothing here, even though set_uri_args
-- changes them: nginx marks them non-cacheable, so an indexed read of one
-- re-reads it anyway. $host needs nothing either, because lua-nginx-module
-- invalidates that one itself whenever the Host header is written.
local function invalidate_request_header_vars(name)
    name = replace_dashes_lower(name)

    local index = variable_index[HTTP_PREFIX .. name]
    if index then
        var_invalidate_by_index(index)
    end

    if name == "content_type" or name == "content_length" then
        -- a variable of its own, named exactly like the header
        index = variable_index[name]
        if index then
            var_invalidate_by_index(index)
        end

    elseif name == "cookie" then
        for i = 1, #cookie_indexes do
            var_invalidate_by_index(cookie_indexes[i])
        end
    end
end


local function patch_functions()
    local orig_set_header = req.set_header

    req.set_header = function(name, value)
        invalidate_request_header_vars(name)
        return orig_set_header(name, value)
    end

    local orig_clear_header = req.clear_header

    req.clear_header = function(name)
        invalidate_request_header_vars(name)
        return orig_clear_header(name)
    end
end


local function patch_metatable()
    if get_phase() ~= "init" then
        error("patch_metatable can only be called in init phase")
    end

    if metatable_patched then
        error("patch_metatable should only be called once")
    end

    metatable_patched = true

    load_indexes()

    local mt = getmetatable(var)
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

    patch_functions()
end


local function set_by_name(name, value)
    local index = assert(variable_index[name], "nginx variable is not indexed")
    return var_set_by_index(index, value)
end


local function get_by_name(name)
    local index = assert(variable_index[name], "nginx variable is not indexed")
    return var_get_by_index(index)
end


if subsystem == "stream" then
    patch_metatable = function() end
    load_indexes = function() end
    set_by_name = function() end
    get_by_name = function() end
end


return {
    patch_metatable = patch_metatable,
    load_indexes = load_indexes,
    set = set_by_name,
    get = get_by_name,
}
