use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5) -2;

#no_diff();
no_long_string();
#master_on();
#workers(2);
check_accum_error_log();
run_tests();

__DATA__

=== TEST 0: Dummy: remove this test and the SKIP section from all tests below
once nginx is patched in kong and the feature can be tested
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            ngx.exit(200)
        }
    }
--- request
GET /test
--- no_error_log
[error]
[crit]
[alert]


=== TEST 1: value is appended correctly to error logs, plain text
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set $my_var "yay!";
        lua_kong_error_log_append "appended text";
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_log eval
qr/log_msg.*appended text$/
--- no_error_log
[error]
[crit]
[alert]


=== TEST 2: value is appended correctly to error logs, with variables
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set $my_var "yay!";
        lua_kong_error_log_append "start, my_var=$my_var, method=$request_method, end";
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_log eval
qr/log_msg.*start, my_var=yay!, method=GET, end$/
--- no_error_log
[error]
[crit]
[alert]


=== TEST 3: value is appended correctly to error logs when a runtime error occurs
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set $req_id 123456;
        lua_kong_error_log_append "req_id=$req_id";

        content_by_lua_block {
            error("error_message")
        }
    }
--- request
GET /test
--- error_code: 500
--- error_log eval
qr/.*req_id=123456.*$/


=== TEST 4: scoping: value is appended correctly to error logs
based on the location where the directive is defined
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /append_req_id {
        set $req_id 123456;
        lua_kong_error_log_append "req_id=$req_id";

        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
    location = /append_method {
        lua_kong_error_log_append "method=$request_method";

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
[ "req_id=123456", "method=GET" ]
--- no_error_log
[error]
[crit]
[alert]


=== TEST 5: scoping: value is NOT appended to error logs
for the location where the directive is NOT defined
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /append {
        lua_kong_error_log_append "appended";

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
qr/log_msg.*appended/


=== TEST 6: scoping: value is appended correctly to error logs
when the directive is in the main configuration
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_error_log_append "log_suffix";
--- config
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
qr/log_msg.*log_suffix$/
--- no_error_log
[error]
[crit]
[alert]


=== TEST 7: scoping: value is appended correctly to error logs
and the local directive overrides the global one
--- SKIP
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_error_log_append "global_suffix";
--- config
    location = /test {
        lua_kong_error_log_append "local_suffix";
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*local_suffix$/
--- no_error_log eval
qr/log_msg.*global_suffix$/
