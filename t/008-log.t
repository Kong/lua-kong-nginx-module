# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

plan tests => repeat_each() * (blocks() * 4) + 8;

#no_diff();
#no_long_string();
#master_on();
#workers(2);
check_accum_error_log();
run_tests();

__DATA__

=== TEST 1: set_log_level with invalid parameters
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            if pcall(log.set_log_level, 9999, 10) then
                ngx.say("error")
            end

            if pcall(log.set_log_level, "error", 10) then
                ngx.say("error")
            end

            if pcall(log.set_log_level, 3.14, 10) then
                ngx.say("error")
            end

            if pcall(log.set_log_level, ngx.ERR, "string") then
                ngx.say("error")
            end

            if pcall(log.set_log_level, ngx.ERR, -1) then
                ngx.say("error")
            end

            if pcall(log.set_log_level, ngx.ERR, 3.14) then
                ngx.say("error")
            end

            ngx.say("ok")
        }
    }
--- request
GET /test
--- response_body
ok
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: set_log_level and get_log_level
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            log.set_log_level(ngx.DEBUG, 2)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 2)
            assert(orig_log == ngx.WARN)

            ngx.sleep(3)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.WARN)
            assert(timeout == 0)
            assert(orig_log == ngx.WARN)

            ngx.say("ok")
        }
    }
--- timeout: 5s
--- request
GET /test
--- response_body
ok
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: timeout
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            log.set_log_level(ngx.DEBUG, 2)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 2)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me")

            ngx.sleep(3)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.WARN)
            assert(timeout == 0)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can't see me")
            ngx.say("ok")
        }
    }
--- timeout: 5s
--- request
GET /test
--- error_log
you can see me



=== TEST 4: works for a single request
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- log_level: alert
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.log(ngx.ERR, "you can't see error")
            log.set_log_level(ngx.ERR, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.ERR)
            assert(timeout == 30)
            assert(orig_log == ngx.ALERT)

            ngx.log(ngx.ERR, "you can see error")

            ngx.log(ngx.DEBUG, "you can't see debug")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.ALERT)

            ngx.log(ngx.DEBUG, "you can see debug")

            ngx.say("ok")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
["you can see error", "you can see debug"]
--- no_error_log eval
["you can't see error", "you can't see debug"]



=== TEST 5: persists across multiple subrequests
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "debug t1")
            ngx.say("ok")
        }
    }

    location = /t2 {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "debug t2")
            ngx.say("ok")
        }
    }

    location = /test {
        echo_location /t1;
        echo_location /t2;
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
["debug t1", "debug t2"]



=== TEST 6: persists across multiple pipelined requests
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "debug log in t1")
            ngx.say("ok")
        }
    }

    location = /t2 {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "debug log in t2")
            ngx.say("ok")
        }
    }
--- pipelined_requests eval
["GET /t1", "GET /t2"]
--- error_code eval
[200, 200]
--- error_log eval
["debug log in t1", "debug log in t2"]



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
                local log = require("resty.kong.log")
                log.set_log_level(ngx.DEBUG, 30)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(timeout == 30)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "debug log on port 8091")
                ngx.say("ok")
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        location / {
            content_by_lua_block {
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "debug log on port 8092")
                ngx.say("ok")
            }
        }
    }
--- config
    location ~ /balancer/(?<target_port>\d+) {
        set $port $target_port;
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer/8091", "GET /balancer/8092"]
--- error_code eval
[200, 200]
--- error_log eval
["debug log on port 8091", "debug log on port 8092"]



=== TEST 8: works on timer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        error_log logs/error.log warn;

        content_by_lua_block {
            ngx.log(ngx.DEBUG, "content debug log")

            ngx.timer.at(0, function()
                local log = require("resty.kong.log")
                ngx.log(ngx.DEBUG, "you can't see me")
                log.set_log_level(ngx.DEBUG, 30)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(timeout == 30)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me")
            end)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log
you can see me
--- no_error_log eval
["content debug log", "you can't see me"]



=== TEST 9: persists after being called on timer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /t1 {
        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.log(ngx.DEBUG, "you can't see me t1")

            ngx.timer.at(0, function()
                log.set_log_level(ngx.DEBUG, 30)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(timeout == 30)
                assert(orig_log == ngx.WARN)
            end)

            ngx.sleep(0.1)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me t1")
        }
    }

    location = /t2 {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me t2")
        }
    }
--- pipelined_requests eval
["GET /t1", "GET /t2"]
--- error_code eval
[200, 200]
--- error_log eval
["you can see me t1", "you can see me t2"]



=== TEST 10: works on balancer phase with timers using different listeners
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
                local log = require("resty.kong.log")
                ngx.log(ngx.DEBUG, "you can't see me 8091")

                ngx.timer.at(0, function()
                    log.set_log_level(ngx.DEBUG, 30)

                    local cur_log, timeout, orig_log = log.get_log_level()
                    assert(cur_log == ngx.DEBUG)
                    assert(timeout == 30)
                    assert(orig_log == ngx.WARN)
                end)

                ngx.sleep(0.1)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me 8091")
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        location / {
            content_by_lua_block {
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me 8092")
            }
        }
    }
--- config
    location ~ /balancer/(?<target_port>\d+) {
        set $port $target_port;
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer/8091", "GET /balancer/8092"]
--- error_code eval
[200, 200]
--- error_log eval
["you can see me 8091", "you can see me 8092"]
--- no_error_log
you can't see me 8091



=== TEST 11: works with multiple listeners having one error_log per listener
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
                local log = require("resty.kong.log")
                ngx.log(ngx.DEBUG, "you can't see me 8091")

                ngx.timer.at(0, function()
                    log.set_log_level(ngx.DEBUG, 30)

                    local cur_log, timeout, orig_log = log.get_log_level()
                    assert(cur_log == ngx.DEBUG)
                    assert(timeout == 30)
                    assert(orig_log == ngx.NOTICE)
                end)

                ngx.sleep(0.1)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.NOTICE)

                ngx.log(ngx.DEBUG, "you can see me 8091")
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        error_log logs/error.log notice;

        location / {
            content_by_lua_block {
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.NOTICE)

                ngx.log(ngx.DEBUG, "you can see me 8092")
            }
        }
    }
--- config
    location ~ /balancer/(?<target_port>\d+) {
        set $port $target_port;
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer/8091", "GET /balancer/8092"]
--- error_code eval
[200, 200]
--- error_log eval
["you can see me 8091", "you can see me 8092"]
--- no_error_log
you can't see me 8091



=== TEST 12: works with raw_log API
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")
            local errlog = require("ngx.errlog")
            errlog.raw_log(ngx.DEBUG, "you can't see me")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            errlog.raw_log(ngx.DEBUG, "you can see me")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log
you can see me
--- no_error_log
you can't see me



=== TEST 13: works with multiple listeners, different error_log per listener
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
        error_log logs/first.log warn;

        location = /check {
            content_by_lua_block {
                if not os.execute("grep -q 'you can see me 8091' logs/first.log") then
                    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
                end

                if not os.execute("grep -q 'you can see me 8092' logs/second.log") then
                    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
                end

                if os.execute("grep -q 'you can't see me logs/first.log") or 
                   os.execute("grep -q 'you can't see me logs/second.log")
                then
                    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
                end

                ngx.say("ok")
            }
        }

        location / {
            content_by_lua_block {
                local log = require("resty.kong.log")
                ngx.log(ngx.DEBUG, "you can't see me 8091")

                ngx.timer.at(0, function()
                    log.set_log_level(ngx.DEBUG, 30)

                    local cur_log, timeout, orig_log = log.get_log_level()
                    assert(cur_log == ngx.DEBUG)
                    assert(timeout == 30)
                    assert(orig_log == ngx.WARN)
                end)

                ngx.sleep(0.1)

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me 8091")
            }
        }
    }
    server {
        # this is the real entry point
        listen 8092;
        error_log logs/second.log warn;

        location / {
            content_by_lua_block {
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me 8092")
            }
        }
    }
--- config
    location ~ /balancer/(?<target_port>\d+) {
        set $port $target_port;
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer/8091", "GET /balancer/8092"]
--- error_code eval
[200, 200, 200]



=== TEST 14: works with pending (old) timers
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        error_log logs/error.log warn;

        content_by_lua_block {
            local log = require("resty.kong.log")
            ngx.timer.at(0, function()
                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me")
            end)
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.sleep(0.1)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log
you can see me



=== TEST 15: works on rewrite phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- config
    location = /test {
        rewrite_by_lua_block {
            local log = require("resty.kong.log")

            ngx.log(ngx.DEBUG, "you can't see me")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me")
        }

        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log
you can see me
--- no_error_log
you can't see me



=== TEST 16: works on timer phase inside init_worker
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        ngx.timer.at(0, function()
            local log = require("resty.kong.log")
            ngx.log(ngx.DEBUG, "you can't see me timer init_worker")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me timer init_worker")
        end)
        ngx.log(ngx.DEBUG, "you can't see me init_worker")
    }

--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me content")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
["you can see me content", "you can see me timer init_worker"]
--- no_error_log
you can't see me init_worker



=== TEST 17: works on init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        ngx.log(ngx.DEBUG, "you can't see me")
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG, 30)

        local cur_log, timeout, orig_log = log.get_log_level()
        assert(cur_log == ngx.DEBUG)
        assert(timeout == 30)
        assert(orig_log == ngx.WARN)

        ngx.log(ngx.DEBUG, "you can see me")
    }
--- config
    location = /test {
        return 200;
    }
--- request
GET /test
--- error_code: 200
--- error_log
you can see me
--- no_error_log
you can't see me



=== TEST 18: with error_log file inherited from upper context, setting log level on init_worker affects other later phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        ngx.log(ngx.DEBUG, "you can't see me init_worker")
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG, 30)

        local cur_log, timeout, orig_log = log.get_log_level()
        assert(cur_log == ngx.DEBUG)
        assert(timeout == 30)
        assert(orig_log == ngx.WARN)

        ngx.log(ngx.DEBUG, "you can see me init_worker")
    }
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me content")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
["you can see me content", "you can see me init_worker"]
--- no_error_log
you can't see me init_worker



=== TEST 19: with explicit error_log file per context, setting log level on init_worker does not affect other later phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    error_log logs/error.log warn;
    init_worker_by_lua_block {
        ngx.log(ngx.DEBUG, "you can't see me init_worker")
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG, 30)

        local cur_log, timeout, orig_log = log.get_log_level()
        assert(cur_log == ngx.DEBUG)
        assert(timeout == 30)
        assert(orig_log == ngx.WARN)

        ngx.log(ngx.DEBUG, "you can see me init_worker")
    }
--- config
    location = /test {
        error_log logs/error.log warn;
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me content")
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
["you can see me content", "you can see me init_worker"]
--- no_error_log
you can't see me init_worker



=== TEST 20: changes log level of all timers of init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer1")
        end)
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer2")
        end)
        local log = require("resty.kong.log")
        log.set_log_level(ngx.DEBUG, 30)

        local cur_log, timeout, orig_log = log.get_log_level()
        assert(cur_log == ngx.DEBUG)
        assert(timeout == 30)
        assert(orig_log == ngx.WARN)
    }
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me content")
        }
    }
--- request
GET /test
--- wait: 0.20
--- error_code: 200
--- error_log eval
["you can see me timer1", "you can see me timer2", "you can see me content"]



=== TEST 21: inside a timer, we can change log level of all other timers of init_worker phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer1")
        end)
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer2")
        end)
        ngx.timer.at(0, function()
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me timer3")
        end)
    }
--- config
    location = /test {
        content_by_lua_block {
            local log = require("resty.kong.log")

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me content")
        }
    }
--- request
GET /test
--- wait: 0.20
--- error_code: 200
--- error_log eval
[
    "you can see me timer1",
    "you can see me timer2",
    "you can see me timer3",
    "you can see me content"
]



=== TEST 22: inside a timer, we can change log level of all other timers, including those of other phases
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer1")
        end)
        ngx.timer.every(0.05, function()
            ngx.log(ngx.DEBUG, "you can see me timer2")
        end)
        ngx.timer.at(0, function()
            local log = require("resty.kong.log")
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me timer3")
        end)
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0, function()
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me content timer")
            end)
        }
    }
--- request
GET /test
--- wait: 0.20
--- error_code: 200
--- error_log eval
[
    "you can see me timer1",
    "you can see me timer2",
    "you can see me timer3",
    "you can see me content timer"
]



=== TEST 23: inside a timer, we can change log level of pending ngx.timer.at timer
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
        local log = require("resty.kong.log")

        ngx.timer.at(0.2, function()
            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me timer at")
        end)
        ngx.timer.every(0.1, function()
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me timer every")
        end)
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0.25, function()
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me content timer at")
            end)
        }
    }
--- request
GET /test
--- wait: 0.5
--- error_code: 200
--- error_log eval
[
    "you can see me timer every",
    "you can see me timer at",
    "you can see me content timer at"
]



=== TEST 24: inside a timer, we can change log level of old running ngx.timer.at timer
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    init_worker_by_lua_block {
        local log = require("resty.kong.log")

        ngx.timer.at(0.1, function()
            ngx.log(ngx.DEBUG, "you can't see me init_worker") -- should not be printed
            ngx.update_time()
            ngx.sleep(1) -- wait for the log level change

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(orig_log == ngx.WARN)

            ngx.log(ngx.DEBUG, "you can see me init_worker") -- should be printed
        end)

        ngx.timer.at(0.2, function()
            log.set_log_level(ngx.DEBUG, 30)

            local cur_log, timeout, orig_log = log.get_log_level()
            assert(cur_log == ngx.DEBUG)
            assert(timeout == 30)
            assert(orig_log == ngx.WARN)
        end)
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.timer.at(0.25, function()
                local log = require("resty.kong.log")

                local cur_log, timeout, orig_log = log.get_log_level()
                assert(cur_log == ngx.DEBUG)
                assert(orig_log == ngx.WARN)

                ngx.log(ngx.DEBUG, "you can see me content")
            end)
        }
    }
--- request
GET /test
--- wait: 2
--- error_code: 200
--- error_log eval
[
    "you can see me init_worker",
    "you can see me content"
]
--- no_log eval
"you can't see me init_worker"
