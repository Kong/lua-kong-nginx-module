# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(3);

plan tests => repeat_each() * (blocks() * 2);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: overwrite Host header on retry
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen 20666;
        server_name "pittsburgh.test" default_server;
        return 500;
    }

    server {
        listen 20666;
        server_name "punxsutawney.test";
        location / {
            echo "OK, campers, rise and shine";
        }
    }

    proxy_next_upstream_tries 10;
    proxy_next_upstream error http_500;
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            local b = require "ngx.balancer"

            if not ngx.ctx.tries then
                ngx.ctx.tries = 0
            end

            if ngx.ctx.tries > 0 then
                local kb = require("resty.kong.balancer")
                ngx.var.upstream_host = "punxsutawney.test"
                kb.update_proxy_request()
            end

            ngx.ctx.tries = ngx.ctx.tries + 1
            b.set_more_tries(1)
            assert(b.set_current_peer("127.0.0.1", 20666))
        }
    }


--- config

    location /t {
        proxy_pass http://backend/;
        set $upstream_host '';
        proxy_set_header Host $upstream_host;
        access_by_lua_block {
            ngx.var.upstream_host = "strike"
        }
    }

--- request
GET /t

--- more_headers
Host: thereandback.test

--- response_body_like
OK, campers, rise and shine

--- error_code: 200
