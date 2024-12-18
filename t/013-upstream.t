# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
log_level('info');

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 2) + 8;

#no_diff();
#no_long_string();
run_tests();

__DATA__
=== TEST 1: default behavior
--- http_config
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port
            ngx.ctx.count = (ngx.ctx.count or 0) + 1
            if ngx.ctx.count == 1 then
                port = $TEST_NGINX_RAND_PORT_1
            elseif ngx.ctx.count == 2 then
                port = $TEST_NGINX_RAND_PORT_2
            elseif ngx.ctx.count == 3 then
                port = $TEST_NGINX_RAND_PORT_3
            else
                port = $TEST_NGINX_RAND_PORT_4
            end
            ngx.log(ngx.ERR, "balancer_by_lua_block: host: ", host, ", port: ", port, ", count: ", ngx.ctx.count)
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
            balancer.set_more_tries(4)
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_1;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_2;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_3;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_4;
        location / {
            content_by_lua_block{
                ngx.print("this is backend peer $TEST_NGINX_RAND_PORT_4")
            }
        }
    }
--- config
    location =/balancer {
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer", "GET /balancer"]
--- error_code eval
[404, 404]

=== TEST 2: proxy_next_upstream directive behavior
--- http_config
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port
            ngx.ctx.count = (ngx.ctx.count or 0) + 1
            if ngx.ctx.count == 1 then
                port = $TEST_NGINX_RAND_PORT_1
            elseif ngx.ctx.count == 2 then
                port = $TEST_NGINX_RAND_PORT_2
            elseif ngx.ctx.count == 3 then
                port = $TEST_NGINX_RAND_PORT_3
            else
                port = $TEST_NGINX_RAND_PORT_4
            end
            ngx.log(ngx.ERR, "balancer_by_lua_block: host: ", host, ", port: ", port, ", count: ", ngx.ctx.count)
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
            balancer.set_more_tries(4)
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_1;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_2;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_3;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_4;
        location / {
            content_by_lua_block{
                ngx.print("this is backend peer $TEST_NGINX_RAND_PORT_4")
            }
        }
    }
--- config
    proxy_next_upstream error timeout http_404;
    location =/balancer {
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer", "GET /balancer"]
--- response_body eval
["this is backend peer \$TEST_NGINX_RAND_PORT_4", "this is backend peer \$TEST_NGINX_RAND_PORT_4"]

=== TEST 3: lua resty.kong.upstream.set_upstream_next() behavior
--- timeout: 1000
--- http_config
    upstream balancer {
        server 127.0.0.1;
        balancer_by_lua_block {
            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port
            ngx.ctx.count = (ngx.ctx.count or 0) + 1
            if ngx.ctx.count == 1 then
                port = $TEST_NGINX_RAND_PORT_1
            elseif ngx.ctx.count == 2 then
                port = $TEST_NGINX_RAND_PORT_2
            elseif ngx.ctx.count == 3 then
                port = $TEST_NGINX_RAND_PORT_3
            else
                port = $TEST_NGINX_RAND_PORT_4
            end
            ngx.log(ngx.ERR, "balancer_by_lua_block: host: ", host, ", port: ", port, ", count: ", ngx.ctx.count)
            local ok, err = balancer.set_current_peer(host, port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end
            balancer.set_more_tries(4)
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_1;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_2;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_3;
        location / {
            content_by_lua_block{
                ngx.exit(404)
            }
        }
    }
    server {
        # this is the real entry point
        listen $TEST_NGINX_RAND_PORT_4;
        location / {
            content_by_lua_block{
                ngx.print("this is backend peer $TEST_NGINX_RAND_PORT_4")
            }
        }
    }
--- config
    access_by_lua_block {
        local upstream = require "resty.kong.upstream"
        upstream.set_upstream_next("error", "timeout", "http_404")
    }
    location =/balancer {
        proxy_pass http://balancer;
    }
--- pipelined_requests eval
["GET /balancer", "GET /balancer"]
--- response_body eval
["this is backend peer \$TEST_NGINX_RAND_PORT_4", "this is backend peer \$TEST_NGINX_RAND_PORT_4"]
