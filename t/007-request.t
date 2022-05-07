# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 8) - 12;

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
            ngx.say(get_header(""))
            ngx.say(get_header("Cache-Control"))
            ngx.say(get_header("Cache_control"))
            ngx.say(get_header("X-TEST"))
        }
    }
--- request
GET /test
--- more_headers
Cache-control: public, max-age=315360000
X-TEST: test
Referer: http://www.foo.com/
--- response_body
public, max-age=315360000
public, max-age=315360000
public, max-age=315360000
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
            ngx.say(get_header("Cache-control",3))
            ngx.say(get_header("cache-Control",3))
            ngx.say(get_header("Cache_Control",3))
            ngx.say(get_header("X-TEST",3) == nil)
        }
    }
--- request
GET /test
--- more_headers
Cache-control: public, max-age=315360000
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
Referer: http://www.foo.com/
X-TEST: test
--- response_body
public, max-age=315360000
public, max-age=315360000
public, max-age=315360000
true

--- no_error_log
[error]
[crit]
[alert]
