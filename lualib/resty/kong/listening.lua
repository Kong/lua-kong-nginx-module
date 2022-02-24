local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C

local get_phase = ngx.get_phase
local subsystem = ngx.config.subsystem
local NGX_OK = ngx.OK
local NGX_ERROR = ngx.ERROR

if subsystem == "http" then
    ffi.cdef[[
    int
    ngx_http_lua_kong_ffi_close_listening_socket(unsigned short port);
    ]]
end

local function close(port)
    if get_phase() ~= "init_worker" then
        return nil, "close can only be called in init_worker phase"
    end

    if type(port) ~= "number" then
        return nil, "port must be a number"
    end

    if port < 0 or port > 65535 then
        return nil, "port must between 0 and 65535"
    end

    local rc = C.ngx_http_lua_kong_ffi_close_listening_socket(port)

    if rc ~= NGX_OK then
        return nil, "close listening socket failed"
    end

    return true
end

if subsystem == "stream" then
    close = function() end
end


return {
    close = close,
}
