# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2) - 12;

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: get_header
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local get_header = require("resty.kong.request").get_header
            ngx.say(get_header("Content-Type"))
            ngx.say(get_header("content-Type"))
            ngx.say(get_header("Content_Type"))
            ngx.say(get_header("X-TEST"))
        }
    }
--- request
GET /test
--- more_headers
Content-type: text/plain
X-TEST: test
Referer: http://www.foo.com/
--- response_body
text/plain
text/plain
text/plain
test
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: get_header limit
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local get_header = require("resty.kong.request").get_header
            ngx.say(get_header("Content-Type",3))
            ngx.say(get_header("content-Type",3))
            ngx.say(get_header("Content_Type",3))
            ngx.say(get_header("X-TEST",3) == nil)
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
text/plain
true

--- no_error_log
[error]
[crit]
[alert]
