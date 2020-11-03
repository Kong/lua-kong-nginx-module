# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: not overriding gRPC :authority pseudo-header, uses "localhost" which is set by default for Unix sockets
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock http2;
        server_name   example.com;

        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo ':authority: $http_host';
        }
    }
--- config
    server_tokens off;

    location /t {
        grpc_pass unix:/$TEST_NGINX_HTML_DIR/nginx.sock;
    }

--- request
GET /t
--- response_body
:authority: localhost

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: overriding gRPC :authority pseudo-header
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock http2;
        server_name   example.com;

        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo ':authority: $http_host';
        }
    }
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local grpc = require("resty.kong.grpc")

            assert(grpc.set_authority("this.is.my.new.authority.example.com"))
        }

        grpc_pass unix:/$TEST_NGINX_HTML_DIR/nginx.sock;
    }

--- request
GET /t
--- response_body
:authority: this.is.my.new.authority.example.com

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: when "Host" is set, overriding gRPC :authority pseudo-header does not have effect because :authority is no longer sent
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock http2;
        server_name   example.com;

        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo ':authority: $http_host';
        }
    }
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local grpc = require("resty.kong.grpc")

            assert(grpc.set_authority("this.is.my.new.authority.example.com"))
        }

        grpc_set_header Host "this.is.overriding.authority.example.com";
        grpc_pass unix:/$TEST_NGINX_HTML_DIR/nginx.sock;
    }

--- request
GET /t
--- response_body
:authority: this.is.overriding.authority.example.com

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: calling grpc.set_authority multiple times overrides previously set value
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock http2;
        server_name   example.com;

        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo ':authority: $http_host';
        }
    }
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local grpc = require("resty.kong.grpc")

            assert(grpc.set_authority("this.is.my.new.authority.example.com"))
            assert(grpc.set_authority("foo.this.is.my.new.authority.example.com"))
        }

        grpc_pass unix:/$TEST_NGINX_HTML_DIR/nginx.sock;
    }

--- request
GET /t
--- response_body
:authority: foo.this.is.my.new.authority.example.com

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: grpc.set_authority rejects invalid argument
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock http2;
        server_name   example.com;

        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo ':authority: $http_host';
        }
    }
--- config
    server_tokens off;

    location /t {
        access_by_lua_block {
            local grpc = require("resty.kong.grpc")

            ngx.say(pcall(grpc.set_authority, nil))
            ngx.say(pcall(grpc.set_authority, ""))
            ngx.say(pcall(grpc.set_authority, 123))
        }

        grpc_pass unix:/$TEST_NGINX_HTML_DIR/nginx.sock;
    }

--- request
GET /t
--- response_body
falseincorrect argument, expects a string, got nil
falseincorrect argument, the value can not be empty string
falseincorrect argument, expects a string, got number

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]
