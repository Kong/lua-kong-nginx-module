local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C

local get_phase = ngx.get_phase
local subsystem = ngx.config.subsystem
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR

if subsystem == "http" then
    ffi.cdef[[
    void
    ngx_http_lua_kong_ffi_socket_close_listening(unsigned short port);
    ]]
end

local function close_listening(port)
    if get_phase() ~= "init_worker" then
        return nil, "close can only be called in init_worker phase"
    end

    if type(port) ~= "number" then
        return nil, "port must be a number"
    end

    if port < 0 or port > 65535 then
        return nil, "port must between 0 and 65535"
    end

    C.ngx_http_lua_kong_ffi_socket_close_listening(port)

    return true
end

if subsystem == "stream" then
    close_listening = function() end
end


return {
    close_listening = close_listening,
}
