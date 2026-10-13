use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(2);

no_long_string();

run_tests();

__DATA__

=== TEST 1: a valid header value becomes $kong_request_id
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc123
--- response_body
abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: a missing header generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: the header is ignored when the directive is not set
--- config
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: every allowed character is accepted
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: AZaz09+/=-
--- response_body
AZaz09+/=-
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: a UUID is accepted
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: 123e4567-e89b-12d3-a456-426614174000
--- response_body
123e4567-e89b-12d3-a456-426614174000
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: a one character value is accepted
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: a
--- response_body
a
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 7: a value of 128 characters is accepted
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers eval
"x-message-id: " . ("a" x 128) . "\n"
--- response_body eval
("a" x 128) . "\n"
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: a value of 129 characters generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers eval
"x-message-id: " . ("a" x 129) . "\n"
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: an empty value generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id:
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 10: a value with a space generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc 123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 11: a value with an underscore generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc_123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 12: a value with a dot generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc.123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 13: a value with a colon generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc:123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 14: a value with a comma generates an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: abc,123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 15: the header name is matched without regard to case
--- config
    lua_kong_request_id_header X-Message-Id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-MESSAGE-id: mixed-case-1
--- response_body
mixed-case-1
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 16: repeated headers generate an identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: first
X-Message-Id: second
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 17: other headers do not affect the identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id-other: wrong
x-trace-id: wrong
x-message-id: right
--- response_body
right
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 18: the identifier does not change when a handler clears the header
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        rewrite_by_lua_block {
            ngx.req.clear_header("x-message-id")
        }
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: pinned-1
--- response_body
pinned-1
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 19: the identifier does not change when a handler replaces the header
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        rewrite_by_lua_block {
            ngx.req.set_header("x-message-id", "replaced")
        }
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: pinned-2
--- response_body
pinned-2
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 20: a header added by a handler does not become the identifier
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        rewrite_by_lua_block {
            ngx.req.set_header("x-message-id", "late")
        }
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 21: the identifier is the same on every read
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            local first = ngx.var.kong_request_id
            local second = ngx.var.kong_request_id
            ngx.say(first == second)
        }
    }
--- request
GET /t
--- response_body
true
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 22: the error log carries the header value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_error_log_request_id $kong_request_id;
    location /t {
        content_by_lua_block {
            ngx.log(ngx.ERR, "boom")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- more_headers
x-message-id: trace-22
--- response_body
ok
--- error_code: 200
--- error_log eval
qr/boom.*request_id: "trace-22"/
--- no_error_log eval
qr/http request line: "GET \/t HTTP\/1\.1", request_id:/



=== TEST 23: the error log carries a generated identifier for an invalid value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_error_log_request_id $kong_request_id;
    location /t {
        content_by_lua_block {
            ngx.log(ngx.ERR, "boom")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- more_headers
x-message-id: not valid
--- response_body
ok
--- error_code: 200
--- error_log eval
qr/boom.*request_id: "[0-9a-f]{32}"/



=== TEST 24: the upstream request carries the header value
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        proxy_set_header X-Kong-Request-Id $kong_request_id;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    location /echo {
        content_by_lua_block {
            ngx.say(ngx.req.get_headers()["x-kong-request-id"])
        }
    }
--- request
GET /t
--- more_headers
x-message-id: upstream-24
--- response_body
upstream-24
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 25: the identifier survives an internal redirect
--- config
    lua_kong_request_id_header x-message-id;
    error_page 404 /err;
    location = /err {
        internal;
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
    location /t {
        return 404;
    }
--- request
GET /t
--- more_headers
x-message-id: redirect-25
--- response_body
redirect-25
--- error_code: 404
--- no_error_log
[error]
[crit]
[alert]



=== TEST 26: the directive applies to the server that sets it only
--- http_config
    server {
        listen $TEST_NGINX_SERVER_PORT;
        server_name other.test;
        location /t {
            content_by_lua_block {
                ngx.say(ngx.var.kong_request_id)
            }
        }
    }
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
Host: other.test
x-message-id: scoped-26
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 27: the directive in the http block applies to every server
--- http_config
    lua_kong_request_id_header x-message-id;
--- config
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: http-27
--- response_body
http-27
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 28: a server can use another header than the http block
--- http_config
    lua_kong_request_id_header x-message-id;
--- config
    lua_kong_request_id_header x-trace-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: wrong
x-trace-id: right-28
--- response_body
right-28
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 29: the indexed variable API returns the header value
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: indexed-29
--- response_body
indexed-29
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 30: an invalid header name is rejected
--- config
    lua_kong_request_id_header "x message";
--- must_die
--- error_log
invalid header name "x message"



=== TEST 31: an empty header name is rejected
--- config
    lua_kong_request_id_header "";
--- must_die
--- error_log
invalid header name ""



=== TEST 32: a header name with a colon is rejected
--- config
    lua_kong_request_id_header "x-message-id:";
--- must_die
--- error_log
invalid header name "x-message-id:"



=== TEST 33: a repeated directive in one context is rejected
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header x-trace-id;
--- must_die
--- error_log
is duplicate



=== TEST 34: the directive is not allowed in a location
--- config
    location /t {
        lua_kong_request_id_header x-message-id;
    }
--- must_die
--- error_log
directive is not allowed here
