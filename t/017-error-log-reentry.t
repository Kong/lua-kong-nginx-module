use Test::Nginx::Socket::Lua;

plan tests => repeat_each() * (blocks() * 5);

run_tests();

__DATA__


=== TEST 1: a request ID variable that logs while it is read does not recurse
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        set_by_lua_block $req_id {
            ngx.log(ngx.ERR, "logged while reading the request id")
            return "later"
        }

        lua_kong_error_log_request_id $req_id;

        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*request_id: "later"$/
--- no_error_log
[crit]
[alert]
[emerg]
