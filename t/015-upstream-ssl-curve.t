# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 7);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();

run_tests();

__DATA__

=== TEST 1: $kong_upstream_ssl_curve reports the negotiated group
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    server_tokens off;
    location /t {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        proxy_ssl_server_name on;
        proxy_ssl_name upstream.example.com;
        proxy_ssl_session_reuse off;
        # offer one group only, so the negotiated one is known
        proxy_ssl_conf_command Groups X25519;

        header_filter_by_lua_block {
            ngx.header["X-Upstream-Curve"] = ngx.var.kong_upstream_ssl_curve
                                             or "none"
        }
    }

--- request
GET /t
--- response_body
ok
--- response_headers
X-Upstream-Curve: X25519
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 2: the value follows the group that was offered
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    server_tokens off;
    location /t {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        proxy_ssl_server_name on;
        proxy_ssl_name upstream.example.com;
        proxy_ssl_session_reuse off;
        proxy_ssl_conf_command Groups P-256;

        # P-256 carries a NID, so nginx names it from OBJ_nid2sn(), which
        # spells this group prime256v1. The downstream $ssl_curve does the
        # same.
        header_filter_by_lua_block {
            ngx.header["X-Upstream-Curve"] = ngx.var.kong_upstream_ssl_curve
                                             or "none"
        }
    }

--- request
GET /t
--- response_body
ok
--- response_headers
X-Upstream-Curve: prime256v1
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 3: absent when the upstream connection carries no TLS
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        server_name   upstream.example.com;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    server_tokens off;
    location /t {
        proxy_pass http://unix:$TEST_NGINX_HTML_DIR/upstream.sock;

        header_filter_by_lua_block {
            ngx.header["X-Upstream-Curve"] = ngx.var.kong_upstream_ssl_curve
                                             or "none"
        }
    }

--- request
GET /t
--- response_body
ok
--- response_headers
X-Upstream-Curve: none
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 4: absent in the access phase, before the upstream connection exists
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    server_tokens off;
    location /t {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        proxy_ssl_server_name on;
        proxy_ssl_name upstream.example.com;
        proxy_ssl_session_reuse off;
        proxy_ssl_conf_command Groups X25519;

        access_by_lua_block {
            ngx.say(ngx.var.kong_upstream_ssl_curve
                    or "no upstream curve in the access phase")
        }

        header_filter_by_lua_block {
            ngx.header["X-Upstream-Curve"] = ngx.var.kong_upstream_ssl_curve
                                             or "none"
        }
    }

--- request
GET /t
--- response_body
no upstream curve in the access phase
--- response_headers
X-Upstream-Curve: none
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 5: readable in the log phase with lua_kong_load_var_index default
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    server_tokens off;
    location /t {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        proxy_ssl_server_name on;
        proxy_ssl_name upstream.example.com;
        proxy_ssl_session_reuse off;
        proxy_ssl_conf_command Groups X25519;

        # The upstream connection goes back to the keepalive pool before the
        # log phase runs, so the value has to be read while it is still up.
        # Reading it in header_filter caches it in the variable index, which
        # is what a logging consumer relies on.
        header_filter_by_lua_block {
            local _ = ngx.var.kong_upstream_ssl_curve
        }

        log_by_lua_block {
            ngx.log(ngx.INFO, "upstream curve: ",
                    ngx.var.kong_upstream_ssl_curve or "none")
        }
    }

--- request
GET /t
--- response_body
ok
--- error_log
upstream curve: X25519
--- no_error_log
[error]
[crit]
[alert]
[emerg]
