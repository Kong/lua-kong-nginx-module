local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C

local str_sub   = string.sub
local get_phase = ngx.get_phase
local subsystem = ngx.config.subsystem

if subsystem == "http" then
    ffi.cdef[[
    void
    ngx_http_lua_kong_ffi_socket_close_unix_listening(ngx_str_t *sock_name);
    ]]
end

local sock_name_str = ffi_new("ngx_str_t[1]")

local function close_unix_listening(sock_name)
    if get_phase() ~= "init_worker" then
        return nil, "close can only be called in init_worker phase"
    end

    if type(sock_name) ~= "string" then
        return nil, "sock_name must be a string"
    end

    if str_sub(sock_name, 5) ~= "unix:" then
        return nil, "sock_name must start with 'unix:'"
    end

    sock_name = str_sub(sock_name, 5)

    sock_name_str[0].data = sock_name
    sock_name_str[0].len = #sock_name

    C.ngx_http_lua_kong_ffi_socket_close_unix_listening(sock_name)

    return true
end

if subsystem == "stream" then
    close_unix_listening = function() end
end


return {
    close_unix_listening = close_unix_listening,
}
