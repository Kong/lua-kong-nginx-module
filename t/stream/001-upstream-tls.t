# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4) - 30;

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: upstream TLS proxying works
--- stream_server_config
    proxy_pass mockbin.com:443;
    proxy_ssl on;
    proxy_ssl_server_name on;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: mockbin.com\r\n\r\n"
--- stream_response_like: ^HTTP/1.1 200 OK
--- no_error_log
[error]



=== TEST 2: upstream plaintext proxying works
--- stream_server_config
    proxy_pass mockbin.com:80;
    proxy_ssl off;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: mockbin.com\r\n\r\n"
--- stream_response_like: ^HTTP/1.1 200 OK
--- no_error_log
[error]



=== TEST 3: upstream TLS proxying inhibit works
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- stream_server_config
    proxy_pass mockbin.com:443;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        assert(tls.disable_proxy_ssl())
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: mockbin.com\r\n\r\n"
--- stream_response_like: ^.+400 The plain HTTP request was sent to HTTPS port.+$
--- no_error_log
[error]



=== TEST 4: not sending client certificate, upstream returns 400
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;
        ssl_client_certificate ../../cert/ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'it works!';
        }
    }
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;
    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;

--- stream_request eval
"GET / HTTP/1.0\r\nHost: mockbin.com\r\n\r\n"

--- stream_response_like
^.+No required SSL certificate was sent.+

--- error_log
client sent no required SSL certificate

--- no_error_log
[error]


=== TEST 5: sending client certificate using resty.kong.tls.set_upstream_cert_and_key in access phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;
        ssl_client_certificate ../../cert/ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'it works!';
        }
    }
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")
        local ssl = require("ngx.ssl")

        local f = assert(io.open("t/cert/client_example.com.crt"))
        local cert_data = f:read("*a")
        f:close()

        local chain = assert(ssl.parse_pem_cert(cert_data))

        f = assert(io.open("t/cert/client_example.com.key"))
        local key_data = f:read("*a")
        f:close()

        local key = assert(ssl.parse_pem_priv_key(key_data))

        local ok, err = tls.set_upstream_cert_and_key(chain, key)
        if not ok then
            ngx.say("set_upstream_cert_and_key failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"


=== TEST 6: sending client certificate using resty.kong.tls.set_upstream_cert_and_key in balancer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;
        ssl_client_certificate ../../cert/ca.crt;
        ssl_verify_client on;

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

        balancer_by_lua_block {
            collectgarbage() -- to make leak check mode pass

            local tls = require("resty.kong.tls")
            local ssl = require("ngx.ssl")

            local f = assert(io.open("t/cert/client_example.com.crt"))
            local cert_data = f:read("*a")
            f:close()

            local chain = assert(ssl.parse_pem_cert(cert_data))

            f = assert(io.open("t/cert/client_example.com.key"))
            local key_data = f:read("*a")
            f:close()

            local key = assert(ssl.parse_pem_priv_key(key_data))

            local ok, err = tls.set_upstream_cert_and_key(chain, key)
            if not ok then
                ngx.say("set_upstream_cert_and_key failed: ", err)
            end
        }
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

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"

=== TEST 7: repeatedly calling resty.kong.tls.set_upstream_cert_and_key does not leaks memory
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;
        ssl_client_certificate ../../cert/ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'it works!';
        }
    }
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")
        local ssl = require("ngx.ssl")

        local f = assert(io.open("t/cert/client_example.com.crt"))
        local cert_data = f:read("*a")
        f:close()

        local chain = assert(ssl.parse_pem_cert(cert_data))

        f = assert(io.open("t/cert/client_example.com.key"))
        local key_data = f:read("*a")
        f:close()

        local key = assert(ssl.parse_pem_priv_key(key_data))

        for i = 1, 1000 do
            local ok, err = tls.set_upstream_cert_and_key(chain, key)
            if not ok then
                ngx.say("set_upstream_cert_and_key failed: ", err)
                break
            end
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"


=== TEST 8: setting proxy_ssl_verify with invalid verify chain, verify failed
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
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/client_example.com.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
receive stream response error: connection reset by peer

--- error_log
upstream SSL certificate verify error: (2:unable to get issuer certificate)



=== TEST 9: proxy_ssl_verify not set, turn on with tls.set_upstream_ssl_verify
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
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify(false)
        if not ok then
            ngx.say("set_upstream_ssl_verify failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- no_error_log
skip overriding upstream SSL configuration



=== TEST 10: proxy_ssl_verify not set, turn on with tls.set_upstream_ssl_verify
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
--- stream_server_config
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify(true)
        if not ok then
            ngx.say("set_upstream_ssl_verify failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
receive stream response error: connection reset by peer

--- error_log
upstream SSL certificate verify error: (20:unable to get local issuer certificate)



=== TEST 11: proxy_ssl_verify not set, turn on with tls.set_upstream_ssl_verify in balancer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;
        ssl_client_certificate ../../cert/ca.crt;
        ssl_verify_client on;

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

        balancer_by_lua_block {
            collectgarbage() -- to make leak check mode pass

            local tls = require("resty.kong.tls")

            local ok, err = tls.set_upstream_ssl_verify(true)
            if not ok then
                ngx.say("set_upstream_ssl_verify failed: ", err)
            end
        }
    }
--- stream_server_config
    proxy_ssl_name example.com;
    proxy_ssl on;

    proxy_pass foo;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
receive stream response error: connection reset by peer

--- error_log
upstream SSL certificate verify error: (20:unable to get local issuer certificate)



=== TEST 12: setting insufficient verify depth with tls.set_upstream_ssl_verify_depth, verify failed
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
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 100;
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        -- verify depth 0 means only self signed cert is allowed
        local ok, err = tls.set_upstream_ssl_verify_depth(0)
        if not ok then
            ngx.say("set_upstream_ssl_verify_depth failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
receive stream response error: connection reset by peer

--- error_log
upstream SSL certificate verify error: (22:certificate chain too long)



=== TEST 13: setting deeper verify depth with tls.set_upstream_ssl_verify_depth, verify pass
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
--- stream_server_config
    proxy_ssl_trusted_certificate ../../cert/ca.crt;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 0;
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify_depth(1)
        if not ok then
            ngx.say("set_upstream_ssl_verify_depth failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- error_log
X509_check_host(): match



=== TEST 14: sending client certificate using resty.kong.tls.set_upstream_cert_and_key in access phase
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
--- stream_server_config
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify(true)
        if not ok then
            ngx.say("set_upstream_ssl_verify failed: ", err)
        end

        local store = require("resty.openssl.x509.store")
        local x509 = require("resty.openssl.x509")
        local s = assert(store.new())
        for _, f in ipairs({ "client_example.com", "intermediate" }) do
            local f = assert(io.open("t/cert/" .. f .. ".crt"))
            local cert_data = f:read("*a")
            f:close()
            assert(s:add(x509.new(cert_data)))
        end
        local ok, err = tls.set_upstream_ssl_trusted_store(s)
        if not ok then
            ngx.say("set_upstream_ssl_trusted_store failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
receive stream response error: connection reset by peer

--- error_log
upstream SSL certificate verify error: (2:unable to get issuer certificate)



=== TEST 15: setting trusted store with tls.set_upstream_ssl_trusted_store, verify passed
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
--- stream_server_config
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify(true)
        if not ok then
            ngx.say("set_upstream_ssl_verify failed: ", err)
        end

        local store = require("resty.openssl.x509.store")
        local x509 = require("resty.openssl.x509")
        local s = assert(store.new())
        for _, f in ipairs({ "intermediate", "ca" }) do
            local f = assert(io.open("t/cert/" .. f .. ".crt"))
            local cert_data = f:read("*a")
            f:close()
            assert(s:add(x509.new(cert_data)))
        end
        local ok, err = tls.set_upstream_ssl_trusted_store(s)
        if not ok then
            ngx.say("set_upstream_ssl_trusted_store failed: ", err)
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- error_log
X509_check_host(): match



=== TEST 16: setting trusted store multiple times tls.set_upstream_ssl_trusted_store, no leak detected
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
--- stream_server_config
    proxy_ssl_name example.com;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        local ok, err = tls.set_upstream_ssl_verify(true)
        if not ok then
            ngx.say("set_upstream_ssl_verify failed: ", err)
        end

        local store = require("resty.openssl.x509.store")
        local x509 = require("resty.openssl.x509")
        local s = assert(store.new())
        for _, f in ipairs({ "intermediate", "ca" }) do
            local f = assert(io.open("t/cert/" .. f .. ".crt"))
            local cert_data = f:read("*a")
            f:close()
            assert(s:add(x509.new(cert_data)))
        end
        for i=0,3 do
            local ok, err = tls.set_upstream_ssl_trusted_store(s)
            if not ok then
                ngx.say("set_upstream_ssl_trusted_store failed: ", err)
                return
            end
        end
    }

    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl_session_reuse off;

--- stream_request eval
"GET /foo HTTP/1.0\r\nHost: example.com\r\n\r\n"

--- stream_response_like
it works!

--- error_log
X509_check_host(): match
