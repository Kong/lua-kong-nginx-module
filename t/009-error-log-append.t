use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5) - 2;

#no_diff();
no_long_string();
#master_on();
#workers(2);
check_accum_error_log();
run_tests();

__DATA__


=== TEST 1: value is appended correctly to error logs
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set $my_var "yay!";
        lua_kong_error_log_request_id $my_var;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_log eval
qr/log_msg.*kong_request_id: yay!$/
--- no_error_log
[error]
[crit]
[alert]


=== TEST 2: value is appended correctly to error logs when a runtime error occurs
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set $req_id 123456;
        lua_kong_error_log_request_id "$req_id";

        content_by_lua_block {
            error("error_message")
        }
    }
--- request
GET /test
--- error_code: 500
--- error_log eval
qr/.*kong_request_id: 123456.*$/


=== TEST 3: scoping: value is appended correctly to error logs
based on the location where the directive is defined
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /append_req_id {
        set $req_id_a 123456;
        lua_kong_error_log_request_id $req_id_a;

        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
    location = /append_method {
        set $req_id_b 654321;
        lua_kong_error_log_request_id $req_id_b;

        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- pipelined_requests eval
["GET /append_req_id", "GET /append_method"]
--- error_code eval
[200, 200, 200]
--- error_log eval
[ "kong_request_id: 123456", "kong_request_id: 654321" ]
--- no_error_log
[error]
[crit]
[alert]


=== TEST 4: scoping: value is NOT appended to error logs
for the location where the directive is NOT defined
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /append {
        set $req_id 123456;
        lua_kong_error_log_request_id $req_id;

        content_by_lua_block {
            ngx.log(ngx.ERR, "log_msg")
            ngx.exit(200)
        }
    }

    location = /no_append {
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /no_append
--- error_code: 200
--- no_error_log eval
qr/log_msg.*kong_request_id/


=== TEST 5: scoping: value is appended correctly to error logs
when the directive is in the main configuration
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_error_log_request_id $req_id;
--- config
    set $req_id 123456;
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*kong_request_id: 123456$/
--- no_error_log
[error]
[crit]
[alert]


=== TEST 6: scoping: value is appended correctly to error logs
and the local directive overrides the global one
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_error_log_request_id $req_id_global;
--- config
    set $req_id_global global;
    set $req_id_local local;

    location = /test {
        lua_kong_error_log_request_id $req_id_local;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*kong_request_id: local$/
--- no_error_log eval
qr/log_msg.*kong_request_id: global$/
