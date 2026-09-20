use Test::Nginx::Socket::Lua;

repeat_each(2);
plan 'no_plan';

our $HttpConfig = <<'NGINX';
    upstream dynamic_backend {
        server 127.0.0.1;
        balancer_by_lua_block {
            local b = require "ngx.balancer"
            ngx.ctx.attempt = (ngx.ctx.attempt or 0) + 1
            if ngx.ctx.attempt == 1 then
                assert(b.set_current_peer("127.0.0.1", $TEST_NGINX_RAND_PORT_1))
                assert(b.set_more_tries(1))
            else
                local state, code = b.get_last_failure()
                ngx.ctx.last_state = state
                ngx.ctx.last_code = code
                assert(b.set_current_peer("127.0.0.1", $TEST_NGINX_RAND_PORT_2))
            end
        }
    }
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        location / {
            content_by_lua_block {
                if ngx.var.arg_delay then ngx.sleep(0.05) end
                ngx.status = tonumber(ngx.var.arg_code) or 401
                ngx.header["WWW-Authenticate"] = 'Bearer realm="provider"'
                ngx.say("upstream error")
            }
        }
    }
    server {
        listen $TEST_NGINX_RAND_PORT_2;
        location / {
            content_by_lua_block {
                if ngx.var.arg_exhaust then
                    ngx.status = tonumber(ngx.var.arg_code) or 401
                    ngx.header["WWW-Authenticate"] = 'Bearer realm="provider"'
                    ngx.say("upstream error")
                else
                    ngx.req.read_body()
                    ngx.header["X-Echo-Body"] = ngx.req.get_body_data()
                    ngx.say("ok")
                end
            }
        }
    }
NGINX

our $Config = <<'NGINX';
    location /t {
        access_by_lua_block {
            local set = require("resty.kong.upstream").set_next_upstream
            local args = ngx.req.get_uri_args()
            if args.enable then
                local options = { "http_" .. (args.code or "401") }
                if args.post then options[#options + 1] = "non_idempotent" end
                if args.off then options[#options + 1] = "off" end
                assert(set(unpack(options)) == nil)
            end
            if args.replace then assert(set("error", "timeout") == nil) end
            if args.invalid then
                assert(set("http_600") ~= nil)
            end
        }
        header_filter_by_lua_block {
            ngx.header["X-Attempts"] = ngx.ctx.attempt
            ngx.header["X-Last-Failure"] = ngx.ctx.last_state and
                (ngx.ctx.last_state .. ":" .. ngx.ctx.last_code)
        }
        proxy_pass http://dynamic_backend;
    }
NGINX

run_tests();

__DATA__
=== TEST 1: custom 401 retries without marking peer failed
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1
--- response_body
ok
--- response_headers
X-Attempts: 2
X-Last-Failure: next:401
--- no_error_log
[error]

=== TEST 2: custom code is opt-in and isolated between requests
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- pipelined_requests eval
["GET /t?enable=1", "GET /t"]
--- error_code eval
[200, 401]
--- response_body eval
["ok\n", "upstream error\n"]
--- no_error_log
[error]

=== TEST 3: exhaustion retains status and final upstream response
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&exhaust=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 2
WWW-Authenticate: Bearer realm="provider"
--- no_error_log
[error]

=== TEST 4: replacing criteria clears custom statuses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&replace=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 5: off overrides custom criteria
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&off=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 6: a failed setter preserves previous criteria
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&invalid=1
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: arbitrary 418 needs no per-status nginx macro
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&code=418
--- response_body
ok
--- response_headers
X-Last-Failure: next:418
--- no_error_log
[error]

=== TEST 8: arbitrary 529 retains status and marks peer failed
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&code=529
--- response_body
ok
--- response_headers
X-Last-Failure: failed:529
--- no_error_log
[error]

=== TEST 9: native 429 retains failure accounting
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&code=429
--- response_body
ok
--- response_headers
X-Last-Failure: failed:429
--- no_error_log
[error]

=== TEST 10: POST is not retried without non_idempotent
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
POST /t?enable=1
payload
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 11: non_idempotent permits POST retry
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
POST /t?enable=1&post=1
payload
--- response_body
ok
--- response_headers
X-Attempts: 2
X-Echo-Body: payload
--- no_error_log
[error]

=== TEST 12: retry timeout is respected
--- http_config eval: $::HttpConfig
--- config eval: "proxy_next_upstream_timeout 1ms;\n" . $::Config
--- request
GET /t?enable=1&delay=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 13: retry count is respected
--- http_config eval: $::HttpConfig
--- config eval: "proxy_next_upstream_tries 1;\n" . $::Config
--- request
GET /t?enable=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 14: reject invalid status formats and non-error statuses
--- config
    location /t {
        content_by_lua_block {
            local set = require("resty.kong.upstream").set_next_upstream
            for _, value in ipairs({ "http_200", "http_399", "http_600",
                                     "http_0401", "http_401x", "http_4e2", 401 }) do
                assert(set(value) ~= nil, tostring(value))
            end
            assert(set() ~= nil)
            assert(set("http_400", "http_402", "http_599") == nil)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 15: 400, 402 and the upper boundary are supported
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- pipelined_requests eval
["GET /t?enable=1&code=400", "GET /t?enable=1&code=402", "GET /t?enable=1&code=599"]
--- error_code eval
[200, 200, 200]
--- response_body eval
["ok\n", "ok\n", "ok\n"]
--- no_error_log
[error]

=== TEST 16: custom 5xx exhaustion returns the original status
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&code=529&exhaust=1
--- error_code: 529
--- response_body
upstream error
--- response_headers
X-Attempts: 2
--- no_error_log
[error]

=== TEST 17: non-buffered POST cannot be replayed even with non_idempotent
--- http_config eval: $::HttpConfig
--- config eval: "proxy_request_buffering off;\n" . $::Config
--- raw_request eval
["POST /t?enable=1&post=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n" . ("x" x 100), "x" x 9900]
--- raw_request_middle_delay: 0.1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 18: off overrides native criteria as well
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t?enable=1&code=500&off=1
--- error_code: 500
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 19: a new custom set replaces the previous set
--- http_config eval: $::HttpConfig
--- config eval
$::Config =~ s/if args.replace then assert\(set\("error", "timeout"\) == nil\) end/if args.replace then assert(set("http_402") == nil) end/r
--- request
GET /t?enable=1&replace=1
--- error_code: 401
--- response_body
upstream error
--- response_headers
X-Attempts: 1
--- no_error_log
[error]

=== TEST 20: multiple custom statuses are copied independently of Lua GC
--- http_config eval: $::HttpConfig
--- config eval
$::Config =~ s/assert\(set\(unpack\(options\)\) == nil\)/assert(set("http_400", "http_401", "http_402", "http_401") == nil); collectgarbage("collect")/r
--- pipelined_requests eval
["GET /t?enable=1&code=400", "GET /t?enable=1&code=401", "GET /t?enable=1&code=402"]
--- error_code eval
[200, 200, 200]
--- response_body eval
["ok\n", "ok\n", "ok\n"]
--- no_error_log
[error]
