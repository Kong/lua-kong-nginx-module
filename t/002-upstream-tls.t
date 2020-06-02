# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 6);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: not sending client certificate, upstream returns 400
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
--- config
    server_tokens off;

    location /t {
        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
.+No required SSL certificate was sent.+

--- error_log
client sent no required SSL certificate while reading client request headers

--- error_code: 400
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: sending client certificate using resty.kong.tls.set_upstream_cert_and_key in access phase
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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
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

        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: sending client certificate using resty.kong.tls.set_upstream_cert_and_key in balancer phase
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
--- config
    server_tokens off;

    location /t {
        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://foo/foo;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: repeatedly calling resty.kong.tls.set_upstream_cert_and_key does not leaks memory
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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
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

        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
verify:1, error:0, depth:0, subject:"/C=US/ST=California/O=Kong Testing/CN=foo@example.com", issuer:"/C=US/ST=California/O=Kong Testing/CN=Kong Testing Intermidiate CA"

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: setting proxy_ssl_verify with invalid verify chain, verify failed
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        # this should have result in the ssl verify to fail
        proxy_ssl_trusted_certificate ../../cert/client_example.com.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
.+502 Bad Gateway.+

--- error_log
upstream SSL certificate verify error: (2:unable to get issuer certificate)

--- error_code: 502
--- no_error_log
[crit]
[alert]
[warn]



=== TEST 6: setting proxy_ssl_verify with invalid verify chain, turn off with tls.set_upstream_ssl_verify
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local tls = require("resty.kong.tls")

            local ok, err = tls.set_upstream_ssl_verify(false)
            if not ok then
                ngx.say("set_upstream_ssl_verify failed: ", err)
            end
        }
        # this should have result in the ssl verify to fail
        proxy_ssl_trusted_certificate ../../cert/client_example.com.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_code: 200
--- no_error_log
skip overriding upstream SSL configuration
[error]
[crit]
[alert]



=== TEST 7: proxy_ssl_verify not set, turn on with tls.set_upstream_ssl_verify
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local tls = require("resty.kong.tls")

            local ok, err = tls.set_upstream_ssl_verify(true)
            if not ok then
                ngx.say("set_upstream_ssl_verify failed: ", err)
            end
        }
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
.+502 Bad Gateway.+

--- error_log
upstream SSL certificate verify error: (20:unable to get local issuer certificate)

--- error_code: 502
--- no_error_log
[crit]
[alert]
[warn]



=== TEST 8: proxy_ssl_verify not set, turn on with tls.set_upstream_ssl_verify in balancer phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        proxy_pass https://foo/foo;
    }

--- request
GET /t
--- response_body_like
.+502 Bad Gateway.+

--- error_log
upstream SSL certificate verify error: (20:unable to get local issuer certificate)

--- error_code: 502
--- no_error_log
[crit]
[alert]
[warn]



=== TEST 9: setting insufficient verify depth with tls.set_upstream_ssl_verify_depth, verify failed
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local tls = require("resty.kong.tls")

            -- verify depth 0 means only self signed cert is allowed
            local ok, err = tls.set_upstream_ssl_verify_depth(0)
            if not ok then
                ngx.say("set_upstream_ssl_verify_depth failed: ", err)
            end
        }
        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 100;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
.+502 Bad Gateway.+

--- error_log
upstream SSL certificate verify error: (22:certificate chain too long)

--- error_code: 502
--- no_error_log
[crit]
[alert]
[warn]



=== TEST 10: setting deeper verify depth with tls.set_upstream_ssl_verify_depth, verify pass
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local tls = require("resty.kong.tls")

            local ok, err = tls.set_upstream_ssl_verify_depth(1)
            if not ok then
                ngx.say("set_upstream_ssl_verify_depth failed: ", err)
            end
        }
        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 0;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
X509_check_host(): match

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 11: setting incorrect trusted store with tls.set_upstream_ssl_trusted_store, verify failed
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

     location /t {
        access_by_lua_block {
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
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_name example.com;
    }

--- request
GET /t
--- response_body_like
.+502 Bad Gateway.+

--- error_log
upstream SSL certificate verify error: (2:unable to get issuer certificate)

--- error_code: 502
--- no_error_log
[crit]
[alert]
[warn]



=== TEST 12: setting trusted store with tls.set_upstream_ssl_trusted_store, verify passed
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

     location /t {
        access_by_lua_block {
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
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_name example.com;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
X509_check_host(): match

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 13: setting trusted store multiple times tls.set_upstream_ssl_trusted_store, no leak detected
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

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
--- config
    server_tokens off;

     location /t {
        access_by_lua_block {
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
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_name example.com;
    }

--- request
GET /t
--- response_body_like
it works!

--- error_log
X509_check_host(): match

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]
