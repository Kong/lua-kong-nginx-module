# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_process_enabled(1);

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: upstream TLS proxying works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'it works!';
        }
    }
--- stream_config
    upstream foo {
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    }
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;

    proxy_pass foo;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- no_error_log
[error]



=== TEST 2: upstream plaintext proxying works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        server_name   example.com;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'it works!';
        }
    }
--- stream_config
    upstream foo {
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    }
--- stream_server_config
    proxy_ssl off;
    proxy_pass foo;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- no_error_log
[error]



=== TEST 3: upstream TLS proxying inhibit works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;

        server_tokens off;
    }
--- stream_config
    proxy_ssl_session_reuse off;
--- stream_server_config
    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        assert(tls.disable_proxy_ssl())
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
--- stream_response_like: ^.+400 The plain HTTP request was sent to HTTPS port.+$
--- no_error_log
[error]
