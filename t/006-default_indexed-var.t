# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 8) + 8;

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: directive works well
--- http_config
    lua_kong_load_default_var_indexes;

--- config
    location = /test {
        content_by_lua '
            ngx.say("ok")
        ';
    }
--- request
GET /test
--- response_body
ok
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: variable $is_args$args
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua '
            ngx.say("var: ", ngx.var.is_args, ngx.var.args)
        ';
    }
--- request
GET /test?hello=world
--- response_body
var: ?hello=world
--- error_log
get variable value '?' by index
get variable value 'hello=world' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: variable $scheme$host$request_uri
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.scheme, " ",
                    ngx.var.host, " ",
                    ngx.var.request_uri)
        ';
    }
--- request
GET /test
--- response_body
http localhost /test
--- error_log
get variable value 'http' by index
get variable value 'localhost' by index
get variable value '/test' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: variable $http_xxx
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.http_authorization, " ",
                    ngx.var.http_connection, " ",
                    ngx.var.http_host, " ",
                    ngx.var.http_kong_debug, " ",
                    ngx.var.http_proxy, " ",
                    ngx.var.http_proxy_connection, " ",
                    ngx.var.http_te, " ",
                    ngx.var.http_upgrade
                    )
        ';
    }
--- request
GET /test
--- more_headers
authorization: auth
connection: close
host: test.com
kong-debug: 1
proxy: 111
proxy-connection: 222
te: 333
upgrade: 444
--- response_body
auth close test.com 1 111 222 333 444
--- error_log
get variable value 'auth' by index
get variable value 'close' by index
get variable value 'test.com' by index
get variable value '1' by index
get variable value '111' by index
get variable value '222' by index
get variable value '333' by index
get variable value '444' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: variable $http_x_forwarded_xxx
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.http_x_forwarded_for, " ",
                    ngx.var.http_x_forwarded_host, " ",
                    ngx.var.http_x_forwarded_path, " ",
                    ngx.var.http_x_forwarded_port, " ",
                    ngx.var.http_x_forwarded_prefix, " ",
                    ngx.var.http_x_forwarded_proto
                    )
        ';
    }
--- request
GET /test
--- more_headers
x-forwarded-for: 111
x-forwarded-host: 222
x-forwarded-path: 333
x-forwarded-port: 444
x-forwarded-prefix: 555
x-forwarded-proto: 666
--- response_body
111 222 333 444 555 666
--- error_log
get variable value '111' by index
get variable value '222' by index
get variable value '333' by index
get variable value '444' by index
get variable value '555' by index
get variable value '666' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: request variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.request_method, " ",
                    ngx.var.request_length, " ",
                    ngx.var.request_uri, " ",
                    ngx.var.request_time, " ",
                    ngx.var.server_addr, " ",
                    ngx.var.server_port
                    )
        ';
    }
--- request
GET /test
--- response_body
GET 58 /test 0.000 127.0.0.1 1984
--- error_log
get variable value 'GET' by index
get variable value '58' by index
get variable value '/test' by index
get variable value '0.000' by index
get variable value '127.0.0.1' by index
get variable value '1984' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 7: upstream variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.upstream_http_connection, " ",
                    ngx.var.upstream_http_trailer, " ",
                    ngx.var.upstream_http_upgrade, " ",
                    ngx.var.upstream_status
                    )
        ';
    }
--- request
GET /test
--- response_body
nil nil nil nil
--- error_log
get variable value is declined by index
get variable value is declined by index
get variable value is declined by index
get variable value is declined by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: ssl/https variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.https, " ",
                    ngx.var.ssl_cipher, " ",
                    ngx.var.ssl_client_raw_cert, " ",
                    ngx.var.ssl_client_verify, " ",
                    ngx.var.ssl_protocol, " ",
                    ngx.var.ssl_server_name
                    )
        ';
    }
--- request
GET /test
--- response_body
 nil nil nil nil nil
--- error_log
get variable value '' by index
get variable value is declined by index
get variable value is declined by index
get variable value is declined by index
get variable value is declined by index
get variable value is declined by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: reomte variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_default_var_indexes;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;
--- config
    location = /test {
        content_by_lua '
            ngx.say(ngx.var.remote_addr, " ",
                    type(ngx.var.remote_port), " ",
                    ngx.var.realip_remote_addr, " ",
                    type(ngx.var.realip_remote_port)
                    )
        ';
    }
--- request
GET /test
--- more_headers
X-Real-IP: 1.2.3.4
--- response_body
1.2.3.4 string 127.0.0.1 string
--- error_log
get variable value '1.2.3.4' by index
get variable value '127.0.0.1' by index
--- no_error_log
[error]
[crit]
[alert]
--- ONLY



