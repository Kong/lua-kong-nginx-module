local ffi = require "ffi"
local base = require "resty.core.base"

base.allows_subsystem("http")

local C = ffi.C
local ffi_new = ffi.new

local type = type
local str_sub   = string.sub
local get_phase = ngx.get_phase

ffi.cdef[[
void
ngx_http_lua_kong_ffi_socket_close_unix_listening(ngx_str_t *sock_name);
]]

local UNIX_PREFIX = "unix:"

local function close_listening(sock_name)
    if get_phase() ~= "init_worker" then
        return nil, "close_listening can only be called in init_worker phase"
    end

    if type(sock_name) == "string" then
        if str_sub(sock_name, 1, #UNIX_PREFIX) ~= UNIX_PREFIX then
            return nil, "sock_name must start with " .. UNIX_PREFIX
        end

        sock_name = str_sub(sock_name, #UNIX_PREFIX + 1)

        local sock_name_str = ffi_new("ngx_str_t[1]")

        sock_name_str[0].data = sock_name
        sock_name_str[0].len = #sock_name

        C.ngx_http_lua_kong_ffi_socket_close_unix_listening(sock_name_str)

        return true
    end

    if type(sock_name) == "number" then
        return nil, "inet port is not supported now"
    end

    return nil, "sock_name must be number or string"
end


return {
    close_listening = close_listening,
}
