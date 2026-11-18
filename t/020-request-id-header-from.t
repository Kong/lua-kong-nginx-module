use Test::Nginx::Socket::Lua;

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5 - 7);

no_long_string();

run_tests();

__DATA__

=== TEST 1: a listed peer keeps the header value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: a peer inside a listed CIDR keeps the header value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.0/8;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: an unlisted peer gets a generated ID
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 10.0.0.0/8;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: without the directive no peer is trusted
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: listing every address trusts every peer
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 0.0.0.0/0;
    lua_kong_request_id_header_from ::/0;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: a peer that matches the second entry keeps the header value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 10.0.0.0/8;
    lua_kong_request_id_header_from 127.0.0.1;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 7: a host name is resolved when nginx reads the configuration
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from localhost;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: the peer is tested before realip replaces the address
--- config
    set_real_ip_from 127.0.0.1;
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
X-Real-IP: 1.2.3.4
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: a forged real IP does not make the peer listed
--- config
    set_real_ip_from 127.0.0.1;
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 1.2.3.4;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
X-Real-IP: 1.2.3.4
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 10: a unix socket peer is listed with unix:
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/listed.sock;
        lua_kong_request_id_header x-message-id;
        lua_kong_request_id_header_from unix:;
        location / {
            content_by_lua_block {
                ngx.say(ngx.var.kong_request_id)
            }
        }
    }
--- config
    location /t {
        proxy_set_header x-message-id message-id-abc123;
        proxy_pass http://unix:$TEST_NGINX_HTML_DIR/listed.sock:/;
    }
--- request
GET /t
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 11: a unix socket peer is not listed by an IP entry
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/unlisted.sock;
        lua_kong_request_id_header x-message-id;
        lua_kong_request_id_header_from 127.0.0.1;
        location / {
            content_by_lua_block {
                ngx.say(ngx.var.kong_request_id)
            }
        }
    }
--- config
    location /t {
        proxy_set_header x-message-id message-id-abc123;
        proxy_pass http://unix:$TEST_NGINX_HTML_DIR/unlisted.sock:/;
    }
--- request
GET /t
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 12: a server inherits the list of the http block
--- http_config
    lua_kong_request_id_header_from 127.0.0.1;
--- config
    lua_kong_request_id_header x-message-id;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 13: the list of a server replaces the list of the http block
--- http_config
    lua_kong_request_id_header_from 127.0.0.1;
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 10.0.0.0/8;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 14: a listed peer still needs a valid value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: bad~value
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 15: a listed peer without the header gets a generated ID
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 16: the ID survives an internal redirect after realip replaced the address
--- config
    set_real_ip_from 127.0.0.1;
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /a {
        rewrite ^ /b last;
    }
    location /b {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /a
--- more_headers
x-message-id: message-id-abc123
X-Real-IP: 1.2.3.4
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 17: a subrequest gets the ID of its main request after realip replaced the address
--- config
    set_real_ip_from 127.0.0.1;
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1;
    location /sub {
        internal;
        content_by_lua_block {
            ngx.print(ngx.var.kong_request_id)
        }
    }
    location /t {
        content_by_lua_block {
            local res = ngx.location.capture("/sub")
            ngx.say(ngx.var.kong_request_id, " ", res.body)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
X-Real-IP: 1.2.3.4
--- response_body
message-id-abc123 message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 18: a value that is not an address or a host name is rejected
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from not.an.address.invalid;
--- must_die
--- error_log
in lua_kong_request_id_header_from "not.an.address.invalid"



=== TEST 19: the directive is not allowed in a location
--- config
    location /t {
        lua_kong_request_id_header_from 127.0.0.1;
    }
--- must_die
--- error_log
directive is not allowed here



=== TEST 20: a CIDR with meaningless low bits is accepted
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_from 127.0.0.1/8;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
