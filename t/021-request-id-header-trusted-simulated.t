use Test::Nginx::Socket::Lua;
use File::Temp qw(tempdir);

sub realip_is_trusted_state {
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
    return 'absent' if $out =~ /unknown "realip_is_trusted" variable/;
    return 'present' if $out =~ /test is successful/;
    die "the probe failed: $out";
}

repeat_each(2);

if (realip_is_trusted_state() eq 'absent') {
    plan tests => repeat_each() * (blocks() * 5);
} else {
    plan skip_all => 'nginx has a $realip_is_trusted variable, t/020 covers it';
}

no_long_string();

run_tests();

__DATA__

=== TEST 1: a trusted peer keeps the header value
--- http_config
    map $remote_addr $realip_is_trusted { default 0; 127.0.0.1 1; }
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



=== TEST 2: an untrusted peer gets a generated ID
--- http_config
    map $remote_addr $realip_is_trusted { default 0; 10.0.0.1 1; }
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



=== TEST 3: without the directive an untrusted peer keeps the header value
--- http_config
    map $remote_addr $realip_is_trusted { default 0; }
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



=== TEST 4: the directive set to off lets an untrusted peer keep the header value
--- http_config
    map $remote_addr $realip_is_trusted { default 0; }
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



=== TEST 5: a server inherits the directive from the http block
--- http_config
    map $remote_addr $realip_is_trusted { default 0; }
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



=== TEST 6: a server overrides the directive of the http block
--- http_config
    map $remote_addr $realip_is_trusted { default 0; }
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



=== TEST 7: a trusted peer still needs a valid value
--- http_config
    map $remote_addr $realip_is_trusted { default 0; 127.0.0.1 1; }
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
x-message-id: bad~value
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: a trusted peer without the header gets a generated ID
--- http_config
    map $remote_addr $realip_is_trusted { default 0; 127.0.0.1 1; }
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
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: the trust decision is taken at the start of the request
--- http_config
    map $uri $realip_is_trusted { default 0; /a 1; }
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
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
--- response_body
message-id-abc123
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 10: a later change of the trust value does not change the ID
--- http_config
    map $uri $realip_is_trusted { default 0; /b 1; }
--- config
    lua_kong_request_id_header x-message-id;
    lua_kong_request_id_header_trusted_only on;
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
--- response_body_like eval
qr/\A[0-9a-f]{32}\n\z/
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]
