use Test::Nginx::Socket::Lua;
use File::Temp qw(tempdir);

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

sub nginx_has_realip_is_trusted {
    my $bin = $ENV{TEST_NGINX_BINARY} || 'nginx';
    my $dir = tempdir(CLEANUP => 1);
    mkdir("$dir/logs");
    open(my $fh, '>', "$dir/nginx.conf") or die "cannot write the probe config: $!";
    print $fh "error_log stderr;\n"
        . "events {}\n"
        . "http {\n"
        . "    map \$realip_is_trusted \$probe { default 0; }\n"
        . "}\n";
    close($fh);
    my $out = `$bin -t -p $dir -c $dir/nginx.conf 2>&1`;
    return $out =~ /unknown "realip_is_trusted" variable/ ? 0 : 1;
}

repeat_each(2);

if (nginx_has_realip_is_trusted()) {
    plan tests => repeat_each() * (blocks() * 5);
} else {
    plan skip_all => 'nginx has no $realip_is_trusted variable';
}

no_long_string();

run_tests();

__DATA__

=== TEST 1: a trusted peer without a real-IP header is trusted
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 127.0.0.1;
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



=== TEST 2: a trusted peer is still trusted after realip replaces the address
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 127.0.0.1;
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



=== TEST 3: an untrusted peer gets a generated ID
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 10.0.0.0/8;
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



=== TEST 4: an untrusted peer gets a generated ID even with X-Real-IP
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 10.0.0.0/8;
    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.kong_request_id)
        }
    }
--- request
GET /t
--- more_headers
x-message-id: message-id-abc123
X-Real-IP: 127.0.0.1
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: no set_real_ip_from means nobody is trusted
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
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



=== TEST 6: trusting every peer accepts the header
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 0.0.0.0/0;
    set_real_ip_from ::/0;
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



=== TEST 7: without the directive the header is accepted from any peer
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



=== TEST 8: the directive set to off accepts the header from an untrusted peer
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only off;
    set_real_ip_from 10.0.0.0/8;
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



=== TEST 9: a server inherits the directive from the http block
--- http_config
    lua_kong_request_id_header_trusted_only on;
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



=== TEST 10: a server overrides the directive of the http block
--- http_config
    lua_kong_request_id_header_trusted_only on;
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only off;
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



=== TEST 11: a trusted peer still needs a valid value
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 127.0.0.1;
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



=== TEST 12: a unix socket peer is trusted with set_real_ip_from unix:
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/trusted.sock;
        lua_kong_request_id_header x-message-id;
        lua_kong_request_id_header_trusted_only on;
        set_real_ip_from unix:;
        location / {
            content_by_lua_block {
                ngx.say(ngx.var.kong_request_id)
            }
        }
    }
--- config
    location /t {
        proxy_set_header x-message-id message-id-abc123;
        proxy_pass http://unix:$TEST_NGINX_HTML_DIR/trusted.sock:/;
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



=== TEST 13: a unix socket peer is not trusted without set_real_ip_from unix:
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/untrusted.sock;
        lua_kong_request_id_header x-message-id;
        lua_kong_request_id_header_trusted_only on;
        set_real_ip_from 127.0.0.1;
        location / {
            content_by_lua_block {
                ngx.say(ngx.var.kong_request_id)
            }
        }
    }
--- config
    location /t {
        proxy_set_header x-message-id message-id-abc123;
        proxy_pass http://unix:$TEST_NGINX_HTML_DIR/untrusted.sock:/;
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



=== TEST 14: the pinned ID survives an internal redirect for a trusted peer
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 127.0.0.1;
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



=== TEST 15: a rule only in the location does not count
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    location /t {
        set_real_ip_from 127.0.0.1;
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



=== TEST 16: the server rule decides when the location has its own rule
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 127.0.0.1;
    location /t {
        set_real_ip_from 10.0.0.0/8;
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



=== TEST 17: a rule in the http block is inherited by the server
--- http_config
    set_real_ip_from 127.0.0.1;
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
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



=== TEST 18: a server rule that does not match is not overridden by a location rule that does
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
    set_real_ip_from 10.0.0.0/8;
    location /t {
        set_real_ip_from 127.0.0.1;
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
