# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

master_on();
workers(2);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5) - 2;

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: unix domain socket works well
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        location / {
            content_by_lua_block {
                ngx.say("unix ok")
            }
        }
    }

--- config
    location = /test {
        content_by_lua_block {
            local sock = ngx.socket.tcp()

            sock:settimeout(500)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end
            ngx.say("connect unix ok")
        }
    }
--- request
GET /test
--- response_body
connect unix ok
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: enable unix domain socket in worker #1
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    init_worker_by_lua_block {
      if ngx.worker.id() ~= 1 then
        require("resty.kong.socket").close_listening("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
      end
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        location / {
            content_by_lua_block {
                ngx.say("unix ok #", ngx.worker.id())
            }
        }
    }

--- config
    location = /test {
        content_by_lua_block {
            local sock = ngx.socket.tcp()

            sock:settimeout(200)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end
            ngx.say("connect unix ok")

            local req = "GET /HTTP/1.1\r\nHost: test.com\r\n\r\n"
            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send http request: ", err)
                return
            end
            ngx.say("send unix ok")

            local line, err = sock:receive()
            if not line then
                ngx.say("failed to receive unix request: ", err)
                return
            end
            ngx.say("receive unix ok")
            ngx.say(line)

            sock:close()
        }
    }
--- request
GET /test
--- response_body
connect unix ok
send unix ok
receive unix ok
unix ok #1
--- no_error_log
[crit]
[alert]



