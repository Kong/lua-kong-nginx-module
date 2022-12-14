# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

log_level('notice');

plan tests => repeat_each() * (blocks() * 3) + 18;

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: sanity: handles incorrect log level type
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level("debug")
        }
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
incorrect level, expects a number, got string

=== TEST 2: sanity: handles invalid log level number: 0 (zero)
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(0)
        }
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
invalid level 0

=== TEST 3: sanity: handles negative log level number
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(-1)
        }
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
invalid level -1

=== TEST 4: works for a single request
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.say("before notice log")
            ngx.log(ngx.NOTICE, "notice log, ", 1234, 3.14159)
            ngx.say("after notice log")
            log.set_log_level(ngx.DEBUG)
            ngx.say("before debug log")
            ngx.log(ngx.DEBUG, "debug log, ", 5678, 4.62345)
            ngx.say("after debug log")
        }
    }
--- request
GET /test
--- response_body
before notice log
after notice log
before debug log
after debug log
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):4: notice log, 12343.14159/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):8: debug log, 56784.62345/,
]

=== TEST 5: persists across multiple subrequests
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.say("t1 before notice log")
            ngx.log(ngx.NOTICE, "t1 notice log, ", 1234, 3.14159)
            ngx.say("t1 after notice log")
            log.set_log_level(ngx.DEBUG)
            ngx.say("t1 before debug log")
            ngx.log(ngx.DEBUG, "t1 debug log, ", 5678, 4.62345)
            ngx.say("t1 after debug log")
        }
    }

    location = /t2 {
        content_by_lua_block {
            ngx.say("t2 before debug log")
            ngx.log(ngx.DEBUG, "t2 debug log, ", 123, 2.91835)
            ngx.say("t2 after debug log")
        }
    }

    location = /test {
        echo_location /t1;
        echo_location /t2;
    }
--- request
GET /test
--- response_body
t1 before notice log
t1 after notice log
t1 before debug log
t1 after debug log
t2 before debug log
t2 after debug log
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):4: t1 notice log, 12343.14159/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):8: t1 debug log, 56784.62345/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):3: t2 debug log, 1232.91835/,
]

=== TEST 6: persists across multiple pipelined requests
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local errlog = require("ngx.errlog")
            local log = require("resty.kong.log")

            local log_level = errlog.get_sys_filter_level()
            ngx.say("t1 log level before set_log_level: ", log_level)

            log.set_log_level(ngx.DEBUG)

            log_level = errlog.get_sys_filter_level()
            ngx.say("t1 log level after set_log_level: ", log_level)
        }
    }

    location = /t2 {
        content_by_lua_block {
            local errlog = require "ngx.errlog"

            local log_level = errlog.get_sys_filter_level()
            ngx.say("t2 log level after set_log_level: ", log_level)
        }
    }
--- pipelined_requests eval
["GET /t1", "GET /t2"]
--- error_code eval
[200, 200]
--- response_body eval
["t1 log level before set_log_level: 6
t1 log level after set_log_level: 8
","t2 log level after set_log_level: 8
"]

=== TEST 7: works on balancer phase with different servers, level increased
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = ngx.var.port;
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
        }
    }
    server {
        # this is the real entry point
        listen 8091;
        location / {
            content_by_lua_block {
                local errlog = require("ngx.errlog")
                local log = require("resty.kong.log")

                local log_level = errlog.get_sys_filter_level()
                ngx.say("t1 log level before set_log_level: ", log_level)

                log.set_log_level(ngx.CRIT)

                log_level = errlog.get_sys_filter_level()
                ngx.say("t1 log level after set_log_level: ", log_level)
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        location / {
            content_by_lua_block {
                local errlog = require "ngx.errlog"

                local log_level = errlog.get_sys_filter_level()
                ngx.say("t2 log level after set_log_level: ", log_level)
            }
        }
    }
--- config
    location = /balancer {
        set $port '';
        set_by_lua_block $port {
            local args, _ = ngx.req.get_uri_args()
            local port = args['port']
            return port
        }
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer?port=8091", "GET /balancer?port=8092"]
--- error_code eval
[200, 200]
--- response_body eval
["t1 log level before set_log_level: 6
t1 log level after set_log_level: 3
","t2 log level after set_log_level: 3
"]

=== TEST 8: works on timer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        error_log logs/error.log notice;

        content_by_lua_block {
            ngx.timer.at(0, function()
                local log = require("resty.kong.log")
                ngx.log(ngx.NOTICE, "timer notice log")
                log.set_log_level(ngx.DEBUG)
                ngx.log(ngx.DEBUG, "timer debug log")
            end)
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):4: timer notice log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):6: timer debug log/,
]
--- no_error_log
content debug log

=== TEST 9: sanity: handles another invalid log level number
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(9)
        }
    }
--- request
GET /test
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
invalid level 9

=== TEST 10: persists after being called on timer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local errlog = require("ngx.errlog")
            local log_level = errlog.get_sys_filter_level()
            ngx.say("t1 log level before timer: ", log_level)

            ngx.timer.at(0, function()
                local log = require("resty.kong.log")
                log.set_log_level(ngx.DEBUG)
            end)

            ngx.sleep(0.01)
            log_level = errlog.get_sys_filter_level()
            ngx.say("t1 log level after timer: ", log_level)
        }
    }

    location = /t2 {
        content_by_lua_block {
            local errlog = require("ngx.errlog")
            local log_level = errlog.get_sys_filter_level()
            ngx.say("t2 log level: ", log_level)
        }
    }
--- pipelined_requests eval
["GET /t1", "GET /t2"]
--- error_code eval
[200, 200]
--- response_body eval
["t1 log level before timer: 6
t1 log level after timer: 6
","t2 log level: 8
"]

=== TEST 11: works on balancer phase with timers using different listeners
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = ngx.var.port;
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
        }
    }
    server {
        # this is the real entry point
        listen 8091;
        location / {
            content_by_lua_block {
                local errlog = require("ngx.errlog")
                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level before timer: ", log_level)

                ngx.timer.at(0, function()
                    local log = require("resty.kong.log")
                    log.set_log_level(ngx.DEBUG)
                end)

                ngx.sleep(0.01)
                log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level after timer: ", log_level)
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        location / {
            content_by_lua_block {
                local errlog = require "ngx.errlog"

                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8092 log level: ", log_level)
            }
        }
    }
--- config
    location = /balancer {
        set $port '';
        set_by_lua_block $port {
            local args, _ = ngx.req.get_uri_args()
            local port = args['port']
            return port
        }
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer?port=8091", "GET /balancer?port=8092"]
--- error_code eval
[200, 200]
--- response_body eval
["listener 8091 log level before timer: 6
listener 8091 log level after timer: 6
","listener 8092 log level: 8
"]

=== TEST 12: works with multiple listeners having one error_log per listener
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = ngx.var.port;
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
        }
    }
    server {
        # this is the real entry point
        listen 8091;
        error_log logs/error.log notice;

        location / {
            content_by_lua_block {
                local errlog = require("ngx.errlog")
                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level before timer: ", log_level)

                ngx.timer.at(0, function()
                    local log = require("resty.kong.log")
                    log.set_log_level(ngx.DEBUG)
                end)

                ngx.sleep(0.01)
                log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level after timer: ", log_level)
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        error_log logs/error.log notice;

        location / {
            content_by_lua_block {
                local errlog = require "ngx.errlog"

                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8092 log level: ", log_level)
            }
        }
    }
--- config
    location = /balancer {
        set $port '';
        set_by_lua_block $port {
            local args, _ = ngx.req.get_uri_args()
            local port = args['port']
            return port
        }
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer?port=8091", "GET /balancer?port=8092"]
--- error_code eval
[200, 200]
--- response_body eval
["listener 8091 log level before timer: 6
listener 8091 log level after timer: 6
","listener 8092 log level: 8
"]

=== TEST 13: works with raw_log API
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local errlog = require("ngx.errlog")
            local log = require("resty.kong.log")
            ngx.say("before notice log")
            ngx.log(ngx.NOTICE, "errlog notice, ", 1234, 3.14159)
            ngx.say("after notice log")
            log.set_log_level(ngx.DEBUG)
            ngx.say("before debug log")
            errlog.raw_log(ngx.DEBUG, "errlog debug")
            ngx.say("after debug log")
        }
    }
--- request
GET /test
--- response_body
before notice log
after notice log
before debug log
after debug log
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):5: errlog notice, 12343.14159/,
qr/\[debug\] \S+: \S+ errlog debug/,
]

=== TEST 14: works with multiple listeners, different error_log per listener
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = ngx.var.port;
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
        }
    }
    server {
        # this is the real entry point
        listen 8091;
        error_log logs/first.log notice;

        location / {
            content_by_lua_block {
                local errlog = require("ngx.errlog")
                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level before timer: ", log_level)

                ngx.timer.at(0, function()
                    local log = require("resty.kong.log")
                    log.set_log_level(ngx.DEBUG)
                end)

                ngx.sleep(0.01)
                log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8091 log level after timer: ", log_level)
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        error_log logs/second.log notice;

        location / {
            content_by_lua_block {
                local errlog = require "ngx.errlog"

                local log_level = errlog.get_sys_filter_level()
                ngx.say("listener 8092 log level: ", log_level)
            }
        }
    }
--- config
    location = /balancer {
        set $port '';
        set_by_lua_block $port {
            local args, _ = ngx.req.get_uri_args()
            local port = args['port']
            return port
        }
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer?port=8091", "GET /balancer?port=8092"]
--- error_code eval
[200, 200]
--- response_body eval
["listener 8091 log level before timer: 6
listener 8091 log level after timer: 6
","listener 8092 log level: 8
"]

=== TEST 15: works with pending (old) timers
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        error_log logs/error.log notice;

        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.timer.at(0, function()
                ngx.log(ngx.DEBUG, "timer debug log")
            end)
            log.set_log_level(ngx.DEBUG)
            ngx.sleep(0.01)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):4: timer debug log/,
]

=== TEST 16: works on rewrite phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        rewrite_by_lua_block {
            local log = require("resty.kong.log")
            ngx.say("before notice log")
            ngx.log(ngx.NOTICE, "notice log, ", 1234, 3.14159)
            ngx.say("after notice log")
            log.set_log_level(ngx.DEBUG)
            ngx.say("before debug log")
            ngx.log(ngx.DEBUG, "debug log, ", 5678, 4.62345)
            ngx.say("after debug log")
        }
    }
--- request
GET /test
--- response_body
before notice log
after notice log
before debug log
after debug log
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] rewrite_by_lua\(nginx\.conf:\d+\):4: notice log, 12343.14159/,
qr/\[debug\] \S+: \S+ \[lua\] rewrite_by_lua\(nginx\.conf:\d+\):8: debug log, 56784.62345/,
]

=== TEST 17: works on timer phase inside init_worker
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.at(0, function()
            local log = require("resty.kong.log")
            ngx.log(ngx.NOTICE, "timer notice log")
            log.set_log_level(ngx.DEBUG)
            ngx.log(ngx.DEBUG, "timer debug log")
        end)
        ngx.log(ngx.DEBUG, "init_worker debug log")
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] init_worker_by_lua:4: timer notice log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:6: timer debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):2: content debug log/,
]
--- no_error_log
init_worker debug log

=== TEST 18: works on init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.log(ngx.NOTICE, "timer notice log")
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG)
        ngx.log(ngx.DEBUG, "timer debug log")
    }

--- config
    location = /test {
        return 200;
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[notice\] \S+: \S+ \[lua\] init_worker_by_lua:2: timer notice log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:5: timer debug log/,
]

=== TEST 19: with error_log file inherited from upper context, setting log level on init_worker affects other later phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG)
        ngx.log(ngx.DEBUG, "timer debug log")
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:4: timer debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):2: content debug log/,
]

=== TEST 20: with explicit error_log file per context, setting log level on init_worker does not affect other later phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    error_log logs/error.log notice;

    init_worker_by_lua_block {
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG)
        ngx.log(ngx.DEBUG, "timer debug log")
    }

--- config
    location = /test {
        error_log logs/error.log notice;

        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:4: timer debug log/,
]
--- no_error_log
content debug log

=== TEST 21: setting log level on content phase does not affect log level of timers running in init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.NOTICE, "timer notice log")
            ngx.log(ngx.DEBUG, "timer debug log")
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG)
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- error_code: 200
--- wait: 0.2
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):4: content debug log/,
qr/\[notice\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer notice log/,
]
--- no_error_log
timer debug log

=== TEST 22: changes log level of all timers of init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer1 debug log")
        end)

        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer2 debug log")
        end)

        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- wait: 0.20
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer1 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:7: timer2 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):2: content debug log/,
]

=== TEST 23: inside a timer, we can change log level of all other timers of init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer1 debug log")
        end)

        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer2 debug log")
        end)

        ngx.timer.at(0, function()
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG)
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")
        }
    }
--- request
GET /test
--- wait: 0.20
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer1 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:7: timer2 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):2: content debug log/,
]

=== TEST 24: inside a timer, we can change log level of all other timers, including those of other phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer1 debug log")
        end)

        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer2 debug log")
        end)

        ngx.timer.every(0.01, function()
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG)
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0, function()
                ngx.log(ngx.DEBUG, "content debug log")
            end)
        }
    }
--- request
GET /test
--- wait: 0.11
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer1 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:7: timer2 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):3: content debug log/,
]

=== TEST 25: inside a timer, we can change log level of old ngx.timer.every timers (rely on fake requests every time they expire)
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer1 debug log")
        end)

        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "timer2 debug log")
        end)

        ngx.timer.every(0.2, function()
            ngx.log(ngx.NOTICE, "timer3 notice")
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG)
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0.25, function()
                ngx.log(ngx.DEBUG, "content debug log")
            end)
        }
    }
--- request
GET /test
--- wait: 0.3
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer1 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:7: timer2 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):3: content debug log/,
]

=== TEST 26: inside a timer, we can change log level of pending ngx.timer.at timer
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.at(0.2, function()
            ngx.log(ngx.DEBUG, "timer1 debug log")
        end)

        ngx.timer.every(0.1, function()
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG)
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0.25, function()
                ngx.log(ngx.DEBUG, "content debug log")
            end)
        }
    }
--- request
GET /test
--- wait: 0.3
--- error_code: 200
--- error_log eval
[
qr/\[debug\] \S+: \S+ \[lua\] init_worker_by_lua:3: timer1 debug log/,
qr/\[debug\] \S+: \S+ \[lua\] content_by_lua\(nginx\.conf:\d+\):3: content debug log/,
]
