# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 9 + 4 + 3);

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: set indexed variables to nil
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        set $var 32;
        content_by_lua '
            ngx.say("old: ", ngx.var.var)
            ngx.var.var = nil
            ngx.say("new: ", ngx.var.var)
        ';
    }
--- request
GET /test
--- response_body
old: 32
new: nil
--- error_log
get variable value '32' by index



=== TEST 2: set variables with set_handler to nil
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $args;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua '
            ngx.say("old: ", ngx.var.args)
            ngx.var.args = nil
            ngx.say("new: ", ngx.var.args)
        ';
    }
--- request
GET /test?hello=world
--- response_body
old: hello=world
new: nil
--- error_log
get variable value 'hello=world' by index



=== TEST 3: reference nonexistent variable
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        set $var 32;
        content_by_lua '
            ngx.say("value: ", ngx.var.notfound)
        ';
    }
--- request
GET /test
--- response_body
value: nil



=== TEST 4: no-hash variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $proxy_host;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        proxy_pass http://127.0.0.1:$server_port/foo;
        header_filter_by_lua '
            ngx.header["X-My-Host"] = ngx.var.proxy_host
        ';
    }

    location = /foo {
        echo foo;
    }
--- request
GET /test
--- response_headers
X-My-Host: foo
--- response_body
foo
--- SKIP



=== TEST 5: variable name is caseless
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        set $Var 32;
        content_by_lua '
            ngx.say("value: ", ngx.var.VAR)
        ';
    }
--- request
GET /test
--- response_body
value: 32



=== TEST 6: true $invalid_referer variable value in Lua
github issue #239
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $invalid_referer;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /t {
        valid_referers www.foo.com;
        content_by_lua '
            ngx.say("invalid referer: ", ngx.var.invalid_referer)
            ngx.exit(200)
        ';
        #echo $invalid_referer;
    }

--- request
GET /t
--- more_headers
Referer: http://www.foo.com/

--- response_body
invalid referer: 

--- no_error_log
[error]

--- error_log
get variable value '' by index


=== TEST 7: false $invalid_referer variable value in Lua
github issue #239
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $invalid_referer;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /t {
        valid_referers www.foo.com;
        content_by_lua '
            ngx.say("invalid referer: ", ngx.var.invalid_referer)
            ngx.exit(200)
        ';
        #echo $invalid_referer;
    }

--- request
GET /t
--- more_headers
Referer: http://www.bar.com

--- response_body
invalid referer: 1

--- no_error_log
[error]

--- error_log
get variable value '1' by index


=== TEST 8: $proxy_host & $proxy_port & $proxy_add_x_forwarded_for
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $proxy_host;
    lua_kong_load_var_index $proxy_port;
    lua_kong_load_var_index $proxy_add_x_forwarded_for;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /t {
        proxy_pass http://127.0.0.1:$server_port/back;
        header_filter_by_lua_block {
            ngx.header["Proxy-Host"] = ngx.var.proxy_host
            ngx.header["Proxy-Port"] = ngx.var.proxy_port
            ngx.header["Proxy-Add-X-Forwarded-For"] = ngx.var.proxy_add_x_forwarded_for
        }
    }

    location = /back {
        echo hello;
    }
--- request
GET /t
--- raw_response_headers_like
Proxy-Host: 127.0.0.1\:\d+\r
Proxy-Port: \d+\r
Proxy-Add-X-Forwarded-For: 127.0.0.1\r
--- response_body
hello
--- no_error_log
[error]



=== TEST 9: get a bad variable name
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        set $true 32;
        content_by_lua '
            ngx.say("value: ", ngx.var[true])
        ';
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_log
bad variable name
--- error_code: 500



=== TEST 10: set a bad variable name
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        set $true 32;
        content_by_lua '
            ngx.var[true] = 56
        ';
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_log
bad variable name
--- error_code: 500



=== TEST 11: set a variable that is not changeable
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $query_string;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.var.query_string = 56
        ';
    }
--- request
GET /test?hello
--- response_body_like: 500 Internal Server Error
--- error_log
variable not changeable
--- error_code: 500



=== TEST 12: get a variable in balancer_by_lua_block
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $port;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- http_config
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = ngx.var.port;
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
        }
    }
    server {
        # this is the real entry point
        listen 8091;
        location / {
            content_by_lua_block{
                ngx.print("this is backend peer 8091")
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        location / {
            content_by_lua_block{
                ngx.print("this is backend peer 8092")
            }
        }
    }
--- config
    location =/balancer {
        set $port '';
        set_by_lua_block $port {
            local args, _ = ngx.req.get_uri_args()
            local port = args['port']
            return port
        }
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer?port=8091", "GET /balancer?port=8092"]
--- response_body eval
["this is backend peer 8091", "this is backend peer 8092"]

=== TEST 13: patch metatable does not invalidate function req.set_uri_args
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    # this is not required, but set explictly in tests
    lua_kong_load_var_index $args;

    init_by_lua_block {
        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    set $args 'foo=bar';

    location /t {
        content_by_lua_block {
            local a = ngx.var.args
            ngx.req.set_uri_args(a .. "&added=yes")
            ngx.say(ngx.var.args)
        }
    }

--- request
GET /t
--- response_body_like
foo=bar&added=yes

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]
