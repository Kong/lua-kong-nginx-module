# vim:set ft= ts=4 sw=4 et:

# HTTP/1.x coverage; the HTTP/2 cases live in 014-req-had-body-http2.t.
# TEST 6/7: rb->received is maintained by the h2/h3 body filters only, so an
# empty chunked request is still reported as having a body.

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

no_long_string();

run_tests();

__DATA__

=== TEST 1: GET without body
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.say(request.had_body())
        }
    }
--- request
GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: POST with Content-Length, body not read yet
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.say(request.had_body())
        }
    }
--- request
POST /t
invalid
--- response_body
true
--- error_code: 200
--- no_error_log
[error]



=== TEST 3: POST with Content-Length: 0
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.say(request.had_body())
        }
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Connection: close\r
Content-Length: 0\r
\r
"
--- response_body
false
--- error_code: 200
--- no_error_log
[error]



=== TEST 4: chunked body without Content-Length, body not read yet
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.say(request.had_body())
            ngx.say("content_length: ", ngx.var.content_length or "nil")
        }
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Connection: close\r
Transfer-Encoding: chunked\r
\r
7\r
invalid\r
0\r
\r
"
--- response_body
true
content_length: nil
--- error_code: 200
--- no_error_log
[error]



=== TEST 5: chunked body without Content-Length, body already read
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.req.read_body()
            ngx.say(request.had_body())
            ngx.say("body: ", ngx.req.get_body_data() or "nil")
        }
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Connection: close\r
Transfer-Encoding: chunked\r
\r
7\r
invalid\r
0\r
\r
"
--- response_body
true
body: invalid
--- error_code: 200
--- no_error_log
[error]



=== TEST 6: empty chunked body, body not read yet (HTTP/1.x cannot tell)
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.say(request.had_body())
        }
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Connection: close\r
Transfer-Encoding: chunked\r
\r
0\r
\r
"
--- response_body
true
--- error_code: 200
--- no_error_log
[error]



=== TEST 7: empty chunked body, body already read (HTTP/1.x cannot tell)
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.req.read_body()
            ngx.say(request.had_body())
            ngx.say("body: ", ngx.req.get_body_data() or "nil")
        }
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Connection: close\r
Transfer-Encoding: chunked\r
\r
0\r
\r
"
--- response_body
true
body: nil
--- error_code: 200
--- no_error_log
[error]



=== TEST 8: GET with read_body(), body reading is skipped entirely
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local request = require("resty.kong.request")
            ngx.req.read_body()
            ngx.say(request.had_body())
        }
    }
--- request
GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]
