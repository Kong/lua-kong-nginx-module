# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 9);

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: get hashed header
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local get_header = require("resty.kong.request").get_header
            ngx.say(get_header("Content-Type"))
            ngx.say(get_header("content-Type"))
            ngx.say(get_header("Content_Type"))
            ngx.say(get_header("referer"))
        }
    }
--- request
GET /test
--- more_headers
Content-type: text/plain
Referer: http://www.foo.com/
--- response_body
text/plain
text/plain
text/plain
http://www.foo.com/
--- error_log
found content-type by hash, value is text/plain
found content-type by hash, value is text/plain
found content-type by hash, value is text/plain
found referer by hash, value is http://www.foo.com/
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: linear search header
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local get_header = require("resty.kong.request").get_header
            ngx.say(get_header("X-TEST"))
            ngx.say(get_header("x-TEST"))
            ngx.say(get_header("x-test"))
            ngx.say(get_header("x_test"))
            ngx.say(get_header("hello_WORLD"))
        }
    }
--- request
GET /test
--- more_headers
Content-type: text/plain
X-TEST: test
Hello-World: 111
--- response_body
test
test
test
test
111
--- error_log
found x-test by linear search, value is test
found x-test by linear search, value is test
found x-test by linear search, value is test
found x-test by linear search, value is test
found hello-world by linear search, value is 111
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: get header with limit
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local get_header = require("resty.kong.request").get_header
            ngx.say(get_header("Content-Type", 6))
            ngx.say(get_header("content_Type", 6))
            ngx.say(get_header("X-TEST", 6) == nil)
        }
    }
--- request
GET /test
--- more_headers
Content-Type: text/plain
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
X-TEST: test
--- response_body
text/plain
text/plain
true
--- error_log
found content-type by hash, value is text/plain
found content-type by hash, value is text/plain
not found x-test by linear search
--- no_error_log
[error]
[crit]
[alert]
