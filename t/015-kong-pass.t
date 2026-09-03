# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

repeat_each(2);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

our $HttpConfig = <<'_EOC_';
    upstream test_upstream {
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;

        # Stock nginx keys the upstream keepalive cache by address only, so a
        # pooled HTTP/2 connection can go to an HTTP/1.1 request once both
        # versions share one location. These tests cover dispatch, not pooling,
        # so give every request its own connection. "keepalive_requests 1"
        # does that on every nginx: 1.29.7 and later drop the connection after
        # one request, and earlier versions cache nothing to begin with.
        keepalive_requests 1;
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        http2 on;
        server_tokens off;

        location / {
            default_type 'text/plain';
            more_clear_headers Date;
            echo "protocol: $server_protocol";
        }

        location /body {
            default_type 'text/plain';
            more_clear_headers Date;
            content_by_lua_block {
                ngx.req.read_body()

                local body = ngx.req.get_body_data()

                if not body then
                    local file = ngx.req.get_body_file()
                    local f = assert(io.open(file, "rb"))
                    body = f:read("*a")
                    f:close()
                end

                ngx.say("protocol: ", ngx.var.server_protocol)
                ngx.say("body: ", body)
            }
        }
    }
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: without version=, the upstream uses the configured proxy_http_version
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme 'http';
        set $upstream_uri    '/t';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri;
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- no_error_log
[error]
[crit]



=== TEST 2: an empty version= keeps the configured proxy_http_version
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- no_error_log
[error]
[crit]



=== TEST 3: version=2 proxies over HTTP/2, overriding proxy_http_version
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '2';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request
GET /t
--- response_body
protocol: HTTP/2.0
--- no_error_log
[error]
[crit]
--- skip_nginx
3: < 1.29.4



=== TEST 4: the version is evaluated per request
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme 'http';
        set $upstream_uri    '/t';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$arg_version;
    }
--- request eval
["GET /t?version=2", "GET /t?version=", "GET /t?version=2"]
--- response_body eval
["protocol: HTTP/2.0\n", "protocol: HTTP/1.1\n", "protocol: HTTP/2.0\n"]
--- no_error_log
[error]
[crit]
--- skip_nginx
3: < 1.29.4



=== TEST 5: a grpc scheme still selects grpc_pass, whatever the version says
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'grpc';
        set $upstream_uri     '/t';
        set $upstream_version '';

        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request
GET /t
--- response_body
protocol: HTTP/2.0
--- no_error_log
[error]
[crit]



=== TEST 6: an unsupported version warns and falls back to proxy_http_version
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '3';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- error_log
kong_pass ignores unsupported version "3"
--- no_error_log
[error]
[crit]



=== TEST 7: version=1.1 names the default and does not warn
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '1.1';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- no_error_log
[error]
[crit]
kong_pass ignores unsupported version



=== TEST 8: the path argument is required
--- config
    location /t {
        set $upstream_scheme 'http';

        kong_pass $upstream_scheme test_upstream;
    }
--- must_die
--- error_log
"kong_pass" directive requires a $variable, a host and a path



=== TEST 9: the selector must be a variable
--- config
    location /t {
        kong_pass http test_upstream /t;
    }
--- must_die
--- error_log
"kong_pass" directive first argument must be a $variable



=== TEST 10: version= must be a variable
--- config
    location /t {
        set $upstream_scheme 'http';
        set $upstream_uri    '/t';

        kong_pass $upstream_scheme test_upstream $upstream_uri version=2;
    }
--- must_die
--- error_log
"version=" must be a $variable



=== TEST 11: version= must not be repeated
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '';

        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version version=$upstream_version;
    }
--- must_die
--- error_log
duplicate "version=" parameter



=== TEST 12: an unknown parameter is rejected
--- config
    location /t {
        set $upstream_scheme 'http';
        set $upstream_uri    '/t';

        kong_pass $upstream_scheme test_upstream $upstream_uri alpn=h2;
    }
--- must_die
--- error_log
invalid parameter "alpn=h2"



=== TEST 13: mixed version=2 and version=1.1 requests with bodies on the same location do not affect each other
--- http_config eval: $::HttpConfig
--- config
    client_body_buffer_size 1;

    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/body';
        set $upstream_version $arg_version;

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;
    }
--- request eval
[
    "POST /t?version=2\nfirst-v2-body",
    "POST /t?version=\nsecond-v1-body",
    "POST /t?version=2\nthird-v2-body",
    "POST /t?version=\nfourth-v1-body",
]
--- response_body eval
[
    "protocol: HTTP/2.0\nbody: first-v2-body\n",
    "protocol: HTTP/1.1\nbody: second-v1-body\n",
    "protocol: HTTP/2.0\nbody: third-v2-body\n",
    "protocol: HTTP/1.1\nbody: fourth-v1-body\n",
]
--- no_error_log
[error]
[crit]
--- skip_nginx
3: < 1.29.4



=== TEST 14: kong_pass inherits into a limit_except block that does not repeat it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version $arg_version;

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;

        # "limit_except GET" runs every non-GET request, POST included, against
        # a separate location config that nginx creates for it. Nothing here
        # repeats kong_pass, so the mediator's selector, version and captured
        # handlers must come from the merge, not from this block's own (empty)
        # config.
        limit_except GET {
            allow all;
        }
    }
--- request eval
["POST /t?version=2", "POST /t?version="]
--- response_body eval
["protocol: HTTP/2.0\n", "protocol: HTTP/1.1\n"]
--- no_error_log
[error]
[crit]
--- skip_nginx
3: < 1.29.4



=== TEST 15: kong_pass inherits into an "if" block that does not repeat it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version $arg_version;

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream $upstream_uri version=$upstream_version;

        # A true "if" condition swaps to a separate location config for the
        # rest of the request, same as limit_except above, but nginx already
        # latches the content handler before that swap; only this module's
        # own per-request state (read through the swapped config) needs the
        # merge to have filled it in.
        if ($request_method = 'POST') {
        }
    }
--- request eval
["GET /t?version=2", "POST /t?version=2", "POST /t?version="]
--- response_body eval
["protocol: HTTP/2.0\n", "protocol: HTTP/2.0\n", "protocol: HTTP/1.1\n"]
--- no_error_log
[error]
[crit]
--- skip_nginx
3: < 1.29.4
