# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

log_level('info');
repeat_each(1);

plan tests => repeat_each() * (blocks() * 2);

my $pwd = cwd();

no_long_string();
run_tests();


__DATA__

=== TEST 1: sanity
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- http_config
    lua_shared_dict request_counter 1m;
    upstream my_upstream {
        server 127.0.0.1;
        balancer_by_lua_block {
            local peer_conn = require("resty.kong.peer_conn")
            local last_peer_connection_cached = peer_conn.get_last_peer_connection_cached()
            ngx.log(ngx.INFO, "last_peer_connection_cached ", tostring(last_peer_connection_cached))

            local balancer = require "ngx.balancer"
            local host = "127.0.0.1"
            local port = 8090;

            local pool = host .. "|" .. port
            local pool_opts = {
                pool = pool,
                pool_size = 512,
            }

            local ok, err = balancer.set_current_peer(host, port, pool_opts)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(500)
            end

            balancer.set_timeouts(60000, 60000, 60000)

            local ok, err = balancer.enable_keepalive(60, 100)
            if not ok then
                ngx.log(ngx.ERR, "failed to enable keepalive: ", err)
                return ngx.exit(500)
            end
        }
    }

    server {
        listen 0.0.0.0:8090;
        location /hello {
            content_by_lua_block{                
                local request_counter = ngx.shared.request_counter
                local first_request = request_counter:get("first_request")
                if first_request == nil then
                    request_counter:set("first_request", "yes")
                    ngx.say("hello")
                else
                    ngx.exit(ngx.HTTP_CLOSE)
                end
            }
        }
    }
--- config
    location /hello {
        proxy_pass http://my_upstream;
        proxy_set_header Connection "keep-alive";
    }
    
    location = /t {
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()
            local uri = "http://127.0.0.1:" .. ngx.var.server_port
                        .. "/hello"
            local res, err = httpc:request_uri(uri)
            if not res then
                ngx.say(err)
                return
            end

            res, err = httpc:request_uri(uri)
            if not res then
                ngx.say(err)
                return
            end
        }
    }
--- request
GET /t
--- error_code eval
[200, 502]
--- grep_error_log eval
qr/last_peer_connection_cached \d+/
--- grep_error_log_out
last_peer_connection_cached 0
last_peer_connection_cached 0
last_peer_connection_cached 1
