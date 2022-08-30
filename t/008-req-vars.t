# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: var.https, var.scheme
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local req = require "resty.kong.req"

            assert(ngx.var.https == "")
            assert(not req.is_https())
            ngx.say(req.is_https())

            assert(ngx.var.scheme == req.scheme())
            ngx.say(ngx.var.scheme)
            ngx.say(req.scheme())
        }
    }
--- request
GET /test
--- response_body
false
http
http
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: no args: var.is_args, var.args
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local req = require "resty.kong.req"

            assert(not req.is_args())
            assert(req.args() == "")

            ngx.say("is_args:", req.is_args())
            ngx.say("args:", req.args())
        }
    }
--- request
GET /test
--- response_body
is_args:false
args:
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: has args: var.is_args, var.args
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local req = require "resty.kong.req"

            assert(req.is_args())
            ngx.say("is_args:", req.is_args())
            ngx.say("args:", req.args())
        }
    }
--- request
GET /test?a=1&b=2
--- response_body
is_args:true
args:a=1&b=2
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: var.request_uri
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local req = require "resty.kong.req"

            assert(req.request_uri())
            ngx.say("uri:", req.request_uri())
        }
    }
--- request
GET /test?a=1&b=2
--- response_body
uri:/test?a=1&b=2
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: var.server_port
--- ONLY
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local req = require "resty.kong.req"

            assert(req.server_port() == tonumber(ngx.var.server_port))

            ngx.say("port:", req.server_port())
        }
    }
--- request
GET /test
--- response_body
port:1984
--- no_error_log
[error]
[crit]
[alert]



