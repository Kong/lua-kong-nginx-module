# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();

run_tests();

__DATA__

=== TEST 1: no proxy protocol, returns remote_addr
--- http_config
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
--- config
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_client_addr)
        }
    }
--- request
GET /t
--- response_body
127.0.0.1
--- no_error_log
[error]
[crit]
[alert]


=== TEST 2: proxy_protocol_addr set, remote_addr trusted, returns proxy_protocol_addr
--- http_config
    server {
        listen 1985 proxy_protocol;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;

        location /pp {
            content_by_lua_block {
                ngx.say(ngx.var.kong_client_addr)
            }
        }
    }
--- config
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(5000)
            assert(sock:connect("127.0.0.1", 1985))

            sock:send("PROXY TCP4 192.168.1.1 127.0.0.1 12345 1985\r\n"
                   .. "GET /pp HTTP/1.0\r\nHost: localhost\r\n\r\n")

            local data = assert(sock:receive("*a"))
            sock:close()

            local body = data:match("\r\n\r\n(.+)")
            ngx.print(body)
        }
    }
--- request
GET /t
--- response_body
192.168.1.1
--- no_error_log
[error]
[crit]
[alert]


=== TEST 3: proxy_protocol_addr same as remote_addr, returns remote_addr
--- http_config
    server {
        listen 1985 proxy_protocol;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;

        location /pp {
            content_by_lua_block {
                ngx.say(ngx.var.kong_client_addr)
            }
        }
    }
--- config
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(5000)
            assert(sock:connect("127.0.0.1", 1985))

            sock:send("PROXY TCP4 127.0.0.1 127.0.0.1 12345 1985\r\n"
                   .. "GET /pp HTTP/1.0\r\nHost: localhost\r\n\r\n")

            local data = assert(sock:receive("*a"))
            sock:close()

            local body = data:match("\r\n\r\n(.+)")
            ngx.print(body)
        }
    }
--- request
GET /t
--- response_body
127.0.0.1
--- no_error_log
[error]
[crit]
[alert]


=== TEST 4: proxy_protocol_addr set, remote_addr NOT trusted, returns remote_addr
--- http_config
    server {
        listen 1985 proxy_protocol;
        set_real_ip_from 10.0.0.0/8;
        real_ip_header proxy_protocol;

        location /pp {
            content_by_lua_block {
                ngx.say(ngx.var.kong_client_addr)
            }
        }
    }
--- config
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(5000)
            assert(sock:connect("127.0.0.1", 1985))

            sock:send("PROXY TCP4 192.168.1.1 127.0.0.1 12345 1985\r\n"
                   .. "GET /pp HTTP/1.0\r\nHost: localhost\r\n\r\n")

            local data = assert(sock:receive("*a"))
            sock:close()

            local body = data:match("\r\n\r\n(.+)")
            ngx.print(body)
        }
    }
--- request
GET /t
--- response_body
127.0.0.1
--- no_error_log
[error]
[crit]
[alert]
