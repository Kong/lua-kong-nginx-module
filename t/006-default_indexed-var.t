# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 6) + 4;

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
    #lua_kong_load_var_index $http_authorization;
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
proxy: xxx
proxy-connection: xxx
te: xxx
upgrade: xxx
--- response_body
auth close test.com 1 xxx xxx xxx xxx
--- error_log
get variable value 'auth' by index
get variable value 'close' by index
get variable value 'test.com' by index
get variable value '1' by index
get variable value 'xxx' by index
get variable value 'xxx' by index
get variable value 'xxx' by index
get variable value 'xxx' by index
--- no_error_log
[error]
[crit]
[alert]
--- ONLY

