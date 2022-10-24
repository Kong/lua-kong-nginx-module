# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5) + 2;

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: directive works well
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        lua_kong_set_static_tag "it works";
        content_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.say(tag.get())
        }
    }
--- request
GET /test
--- response_body
it works
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: default tag is nil
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.say("value:", tag.get())
        }
    }
--- request
GET /test
--- response_body
value:nil
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: set tag for internal location block
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        lua_kong_set_static_tag "test-tag";
        content_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.say("value:", tag.get())

            local res = ngx.location.capture("/inner")
            ngx.say(res.body)
        }
    }
    location = /inner {
        internal;
        lua_kong_set_static_tag "inner-tag";
        content_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.print("value:", tag.get())
        }
    }
--- request
GET /test
--- response_body
value:test-tag
value:inner-tag
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: set tag for nested location block
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location /test {
        lua_kong_set_static_tag "test-tag";

        location /test/nested {
            lua_kong_set_static_tag "nested-tag";
            content_by_lua_block {
                local tag = require "resty.kong.tag"
                ngx.say("value:", tag.get())
            }
        }
    }
--- request
GET /test/nested
--- response_body
value:nested-tag
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: works well in header_filter and body_filter
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location /test {
        lua_kong_set_static_tag "test-tag";

        content_by_lua_block {
            ngx.say("hello")
        }

        header_filter_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.header['tag'] = tag.get()
        }

        body_filter_by_lua_block {
            local tag = require "resty.kong.tag"
            ngx.arg[1] = tag.get() .. '\n'
            ngx.arg[2] = true
        }
    }
--- request
GET /test
--- response_headers
tag: test-tag
--- response_body
test-tag
--- no_error_log
[error]
[crit]
[alert]



