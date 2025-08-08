# vim:set ft= ts=4 sw=4 et fdm=marker:
# modified from https://github.com/openresty/lua-nginx-module/blob/master/t/045-ngx-var.t
# with index always turned on
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 8) - 10;

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: sanity: directive works well
--- http_config
    lua_kong_load_var_index default;

--- config
    location = /test {
        content_by_lua_block {
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



=== TEST 2: variable $is_args, $args
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.say("var: ", ngx.var.is_args, ngx.var.args)
        }
    }
--- request
GET /test?hello=world
--- response_body
var: ?hello=world
--- error_log
get variable value '?' by index
get variable value 'hello=world' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: variable $scheme, $host, $request_uri
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.scheme, " ",
                    ngx.var.host, " ",
                    ngx.var.request_uri)
        }
    }
--- request
GET /test
--- response_body
http localhost /test
--- error_log
get variable value 'http' by index
get variable value 'localhost' by index
get variable value '/test' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: variable $http_xxx
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.http_authorization, " ",
                    ngx.var.http_connection, " ",
                    ngx.var.http_host, " ",
                    ngx.var.http_kong_debug, " ",
                    ngx.var.http_proxy, " ",
                    ngx.var.http_proxy_connection, " ",
                    ngx.var.http_te, " ",
                    ngx.var.http_upgrade
                    )
        }
    }
--- request
GET /test
--- more_headers
authorization: auth
connection: close
host: test.com
kong-debug: 1
proxy: 111
proxy-connection: 222
te: 333
upgrade: 444
--- response_body
auth close test.com 1 111 222 333 444
--- error_log
get variable value 'auth' by index
get variable value 'close' by index
get variable value 'test.com' by index
get variable value '1' by index
get variable value '111' by index
get variable value '222' by index
get variable value '333' by index
get variable value '444' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: variable $http_x_forwarded_xxx
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.http_x_forwarded_for, " ",
                    ngx.var.http_x_forwarded_host, " ",
                    ngx.var.http_x_forwarded_path, " ",
                    ngx.var.http_x_forwarded_port, " ",
                    ngx.var.http_x_forwarded_prefix, " ",
                    ngx.var.http_x_forwarded_proto
                    )
        }
    }
--- request
GET /test
--- more_headers
x-forwarded-for: 111
x-forwarded-host: 222
x-forwarded-path: 333
x-forwarded-port: 444
x-forwarded-prefix: 555
x-forwarded-proto: 666
--- response_body
111 222 333 444 555 666
--- error_log
get variable value '111' by index
get variable value '222' by index
get variable value '333' by index
get variable value '444' by index
get variable value '555' by index
get variable value '666' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: request variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.request_method, " ",
                    ngx.var.request_length, " ",
                    ngx.var.request_uri, " ",
                    ngx.var.server_addr, " ",
                    ngx.var.server_port
                    )
        }
    }
--- request
GET /test
--- response_body
GET 58 /test 127.0.0.1 1984
--- error_log
get variable value 'GET' by index
get variable value '58' by index
get variable value '/test' by index
get variable value '127.0.0.1' by index
get variable value '1984' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 7: upstream variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.upstream_http_connection, " ",
                    ngx.var.upstream_http_trailer, " ",
                    ngx.var.upstream_http_upgrade, " ",
                    ngx.var.upstream_status
                    )
        }
    }
--- request
GET /test
--- response_body
nil nil nil nil
--- error_log
variable value is not found by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: ssl/https variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.https, " ",
                    ngx.var.ssl_cipher, " ",
                    ngx.var.ssl_client_raw_cert, " ",
                    ngx.var.ssl_client_verify, " ",
                    ngx.var.ssl_protocol, " ",
                    ngx.var.ssl_server_name
                    )
        }
    }
--- request
GET /test
--- response_body
 nil nil nil nil nil
--- error_log
get variable value '' by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: reomte variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.remote_addr, " ",
                    ngx.var.remote_port
                    )
        }
    }
--- request
GET /test
--- response_body_like
127.0.0.1 \d+$
--- error_log
get variable value '127.0.0.1' by index
--- no_error_log
[error]
[crit]
[alert]


=== TEST 10: realip variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;
--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.remote_addr, " ",
                    ngx.var.realip_remote_addr, " ",
                    ngx.var.realip_remote_port
                    )
        }
    }
--- request
GET /test
--- more_headers
X-Real-IP: 1.2.3.4
--- response_body_like
^1.2.3.4 127.0.0.1 \d+$
--- error_log
get variable value '1.2.3.4' by index
get variable value '127.0.0.1' by index
--- no_error_log
[error]
[crit]
[alert]


=== TEST 11: http2 variable
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
--- config
    location = /test {
        content_by_lua_block {
            ngx.say("http2:", ngx.var.http2)
        }
    }
--- request
GET /test
--- response_body
http2:
--- error_log
get variable value '' by index
--- no_error_log
[error]
[crit]
[alert]

=== TEST 12: variable $content_type, $bytes_sent
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.content_type, " ",
                    ngx.var.bytes_sent)
        }
    }
--- request
GET /test
--- more_headers
content-type: plain
--- response_body
plain 0
--- error_log
get variable value 'plain' by index
get variable value '0' by index
--- no_error_log
[error]
[crit]
[alert]

=== TEST 13: variable $http_x_kong_request_debug, $http_x_kong_request_debug_token, $http_x_kong_request_debug_log
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.http_x_kong_request_debug, " ",
                    ngx.var.http_x_kong_request_debug_token, " ",
                    ngx.var.http_x_kong_request_debug_log)
        }
    }
--- request
GET /test
--- more_headers
x-kong-request-debug: true
x-kong-request-debug-token: 12345
x-kong-request-debug-log: false
--- response_body
true 12345 false
--- error_log
get variable value 'true' by index
get variable value '12345' by index
get variable value 'false' by index
--- no_error_log
[error]
[crit]
[alert]

=== TEST 14: upstream timing variables
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;
    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }

--- config
    location = /test {
        content_by_lua_block {
            ngx.say(ngx.var.upstream_start_timestamp_us, " ",
                    ngx.var.upstream_connect_timestamp_us, " ",
                    ngx.var.upstream_request_timestamp_us, " ",
                    ngx.var.upstream_header_timestamp_us, " ",
                    ngx.var.upstream_response_timestamp_us)
        }
    }
--- request
GET /test
--- response_body
nil nil nil nil nil
--- error_log
variable value is not found by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
variable value is not found by index
--- no_error_log
[error]
[crit]
[alert]




=== TEST 15: Test ngx.var.kong_upstream_ssl_protocol works well in header_filter phase, cannot get ngx.var.kong_upstream_ssl_protocol in access phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("testtes") -- clear warning
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
        proxy_ssl_protocols TLSv1.2;

        access_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.say("Upstream TLS version: ", upstream_tls_version)
            else
                ngx.say("No upstream TLS version available in access phase")
            end
        }

        header_filter_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.header["X-Upstream-Ssl"] = upstream_tls_version
            end
        }
    }

--- request
GET /t
--- response_body
No upstream TLS version available in access phase
--- response_header
X-Upstream-Ssl: TLSv1.2
--- no_error_log
[error]
[crit]
[alert]
[emerg]




=== TEST 16: Test ngx.var.kong_upstream_ssl_protocol works well in body_filter phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("testtes") -- clear warning
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
        proxy_ssl_protocols TLSv1.2;

        body_filter_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.arg[1] = upstream_tls_version .. "\n"
            end
        }
    }

--- request
GET /t
--- response_body
TLSv1.2
--- no_error_log
[error]
[crit]
[alert]
[emerg]




=== TEST 17: Test ngx.var.kong_upstream_ssl_server_raw_cert works in header_filter phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                local blanks = string.rep(" ", 1346) -- clear warning
                ngx.say(blanks) --- simulate a large response to contain the cert
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

        body_filter_by_lua_block {
            ngx.arg[1] = ngx.header["X-Upstream-Cert"] .. "\n"
            ngx.arg[2] = true -- signal that the body has been modified
        }

        header_filter_by_lua_block {
            local cert = ngx.var.kong_upstream_ssl_server_raw_cert
            if cert then
                ngx.header["X-Upstream-Cert"] = cert
            else
                ngx.header["X-Upstream-Cert"] = "nil"
            end
        }
    }

--- request
GET /t
--- response_body
-----BEGIN CERTIFICATE-----%0AMIIDlTCCAn2gAwIBAgIUEYBZNDoOJlmg1B3lCS0WCk8bd2gwDQYJKoZIhvcNAQEN%0ABQAwWjEQMA4GA1UEAwwHeHh4LmNvbTELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkpT%0AMRAwDgYDVQQHDAdKaWFuZ3N1MQwwCgYDVQQKDANBQUExDDAKBgNVBAsMA0JCQjAe%0AFw0yNTA4MDQxMjUyNDRaFw0zNTA4MDIxMjUyNDRaMFoxEDAOBgNVBAMMB3h4eC5j%0Ab20xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJKUzEQMA4GA1UEBwwHSmlhbmdzdTEM%0AMAoGA1UECgwDQUFBMQwwCgYDVQQLDANCQkIwggEiMA0GCSqGSIb3DQEBAQUAA4IB%0ADwAwggEKAoIBAQDTuNAcos+LA//fjl1qr3lUOAIQczp9wN3hoQ1v/Yt9m+4rLJcu%0AdewGT0o+tOMXAHYVo3KyRfVTdpGNUAZBOpLC5x20LYhzGOM9vL+VnZ/jci7poPsF%0AynNWLd/JGUOlv68JHyNFG+ghIgEym/Lu4qAC5REvyO7D988zzvOEY9gTV33VRRph%0A+OI//eSqEfGKj4s2Yfg9aXMD2gK+ORtJx1bMo98p35plyYQWm3kQWq/pUm+7LXbR%0Aq7Zp7I611G0XDdSVAt/+SzhNUKOxyMSrpGUdlRxQsR7OhwITiOxN4Pp4lhlQRHFA%0AT8sQum/+SrVeXtAdZnJEn0Aj2y+P70+vhjUTAgMBAAGjUzBRMB0GA1UdDgQWBBTn%0AJn6CXjeLpRXdqpCUqofdgDMh8zAfBgNVHSMEGDAWgBTnJn6CXjeLpRXdqpCUqofd%0AgDMh8zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQDJfIOc/uv0%0AQ2Ob/EjXas8x1kLst9ktT8XiAYg1P8y2KZJGnJ/M0bEgyJGNdXJMfQjEntbjwLm9%0AL0qdROfKb1WeKWfCXI49gNmErtddHUAhHLIlm9W8hCGE6yH7VsEfE/6e2L4qV6RO%0AtWmGu5ZTAMi2mInJsFojq+q4IQAeXeEigde5i83TjRi9o56f7TcAcnTBhuXNPAuK%0AULzbPEqPUw5Au6EsW2Y9X3Vg/qRsMLEJBk+2QVaG11lOIYEVgW+LbX7HywGf6E43%0A+U4EWZfeqaMsiYgh1ah3H9JD6RIxoy6VaOV88lnGs/Qi5faP5Z4rIoDTo1wsfCwE%0AMQVJX0HYQMLS%0A-----END CERTIFICATE-----%0A
--- no_error_log
[error]
[crit]
[alert]
[emerg]




=== TEST 18: Test ngx.var.kong_upstream_ssl_server_raw_cert works in body_filter phase
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                local blanks = string.rep(" ", 1301) -- clear warning
                ngx.say(blanks) --- simulate a large response to contain the cert
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

        body_filter_by_lua_block {
            local cert = ngx.var.kong_upstream_ssl_server_raw_cert
            if cert then
                ngx.arg[1] = cert -- replace the body with the cert
                ngx.arg[2] = true -- signal that the body has been modified
            end
        }
    }

--- request
GET /t
--- response_body
-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUEYBZNDoOJlmg1B3lCS0WCk8bd2gwDQYJKoZIhvcNAQEN
BQAwWjEQMA4GA1UEAwwHeHh4LmNvbTELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkpT
MRAwDgYDVQQHDAdKaWFuZ3N1MQwwCgYDVQQKDANBQUExDDAKBgNVBAsMA0JCQjAe
Fw0yNTA4MDQxMjUyNDRaFw0zNTA4MDIxMjUyNDRaMFoxEDAOBgNVBAMMB3h4eC5j
b20xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJKUzEQMA4GA1UEBwwHSmlhbmdzdTEM
MAoGA1UECgwDQUFBMQwwCgYDVQQLDANCQkIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDTuNAcos+LA//fjl1qr3lUOAIQczp9wN3hoQ1v/Yt9m+4rLJcu
dewGT0o+tOMXAHYVo3KyRfVTdpGNUAZBOpLC5x20LYhzGOM9vL+VnZ/jci7poPsF
ynNWLd/JGUOlv68JHyNFG+ghIgEym/Lu4qAC5REvyO7D988zzvOEY9gTV33VRRph
+OI//eSqEfGKj4s2Yfg9aXMD2gK+ORtJx1bMo98p35plyYQWm3kQWq/pUm+7LXbR
q7Zp7I611G0XDdSVAt/+SzhNUKOxyMSrpGUdlRxQsR7OhwITiOxN4Pp4lhlQRHFA
T8sQum/+SrVeXtAdZnJEn0Aj2y+P70+vhjUTAgMBAAGjUzBRMB0GA1UdDgQWBBTn
Jn6CXjeLpRXdqpCUqofdgDMh8zAfBgNVHSMEGDAWgBTnJn6CXjeLpRXdqpCUqofd
gDMh8zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQDJfIOc/uv0
Q2Ob/EjXas8x1kLst9ktT8XiAYg1P8y2KZJGnJ/M0bEgyJGNdXJMfQjEntbjwLm9
L0qdROfKb1WeKWfCXI49gNmErtddHUAhHLIlm9W8hCGE6yH7VsEfE/6e2L4qV6RO
tWmGu5ZTAMi2mInJsFojq+q4IQAeXeEigde5i83TjRi9o56f7TcAcnTBhuXNPAuK
ULzbPEqPUw5Au6EsW2Y9X3Vg/qRsMLEJBk+2QVaG11lOIYEVgW+LbX7HywGf6E43
+U4EWZfeqaMsiYgh1ah3H9JD6RIxoy6VaOV88lnGs/Qi5faP5Z4rIoDTo1wsfCwE
MQVJX0HYQMLS
-----END CERTIFICATE-----
--- no_error_log
[error]
[crit]
[alert]
[emerg]




=== TEST 19: Test ngx.var.kong_upstream_ssl_protocol can get in log phase after accessed in header_filter phase with lua_kong_load_var_index set to default
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;
    lua_kong_load_var_index default;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("testtes") -- clear warning
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
        proxy_ssl_protocols TLSv1.2;

        header_filter_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.header["X-Upstream-Ssl"] = upstream_tls_version
            else
                ngx.header["X-Upstream-Ssl"] = "No upstream TLS version available"
            end
        }

        log_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.log(ngx.INFO, "Upstream TLS version: " .. upstream_tls_version)
            else
                ngx.log(ngx.INFO, "No upstream TLS version available in log phase")
            end
        }
    }

--- request
GET /t
--- error_log
Upstream TLS version: TLSv1.2
--- no_error_log
[error]
[crit]
[alert]
[emerg]




=== TEST 20: Test ngx.var.kong_upstream_ssl_protocol cannot get in access phase and log phase even if with lua_kong_load_var_index set to default
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_ssl_protocols SSLV3 TLSv1 TLSv1.1 TLSv1.2;
    lua_kong_load_var_index default;

    # This is the upstream server
    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name   upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("testtes") -- clear warning
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
        proxy_ssl_protocols TLSv1.2;

        access_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.say("Upstream TLS version: ", upstream_tls_version)
            else
                ngx.say("No upstream TLS version available in access phase")
            end
        }

        log_by_lua_block {
            local upstream_tls_version = ngx.var.kong_upstream_ssl_protocol
            if upstream_tls_version then
                ngx.log(ngx.INFO, "Upstream TLS version: " .. upstream_tls_version)
            else
                ngx.log(ngx.INFO, "No upstream TLS version available in log phase")
            end
        }
    }

--- request
GET /t
--- response_body
No upstream TLS version available in access phase
--- error_log
No upstream TLS version available in log phase
--- no_error_log
[error]
[crit]
[alert]
[emerg]
