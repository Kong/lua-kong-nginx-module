# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);
use File::Temp qw(tempdir);

repeat_each(2);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

# What this build can do with kong_pass does not follow from the nginx version
# alone: the directive is only compiled when ngx_http_proxy_module and
# ngx_http_grpc_module are, and selecting HTTP/2 for a request additionally
# needs nginx 1.29.4 or later. The module reports both at configuration time, so ask it once with "nginx -t"
# instead of guessing, and let the tests that cannot hold on this build skip.
#
# Only these two answers make a test skip. Anything else, a probe that could
# not run included, counts as fully supported, so that a broken probe leaves
# the tests failing loudly rather than passing silently.
sub probe_build {
    my $nginx = $ENV{TEST_NGINX_BINARY} || 'nginx';
    my $dir = tempdir(CLEANUP => 1);

    mkdir "$dir/logs";

    my $conf = "$dir/nginx.conf";

    open my $fh, '>', $conf or return (0, 0);

    print $fh <<'_EOC_';
error_log stderr warn;

events {
    worker_connections 64;
}

http {
    access_log off;

    server {
        listen 127.0.0.1:65535;

        location / {
            set $probe_version '';
            kong_pass $probe_version probe.test / version=$probe_version;
        }
    }
}
_EOC_

    close $fh;

    my $out = `$nginx -t -p $dir -c $conf 2>&1`;

    return (1, 1) if $out =~ /unknown directive "kong_pass"/;
    return (0, 1) if $out =~ /"version=" has no effect/;

    return (0, 0);
}

our ($NoKongPass, $NoUpstreamHttp2) = probe_build();

# every block here configures kong_pass, so there is nothing left to run
plan(skip_all => "this nginx has no kong_pass directive") if $NoKongPass;

plan('no_plan');

if ($NoUpstreamHttp2) {
    diag("skipping the version=2 tests: this nginx cannot proxy to an "
         . "upstream server over HTTP/2");
}

our $HttpConfig = <<'_EOC_';
    upstream test_upstream {
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;

        # These tests cover dispatch, not pooling, so give every request its
        # own connection. "keepalive_requests 1" does that on every nginx:
        # 1.29.7 and later drop the connection after one request, and earlier
        # versions cache nothing to begin with.
        keepalive_requests 1;
    }

    # nginx counts requests per connection, so anything past the first one
    # arrived on a connection that was pooled and reused.
    map $connection_requests $connection_reuse {
        1       new;
        default reused;
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

        location /reuse {
            default_type 'text/plain';
            more_clear_headers Date;
            echo "protocol: $server_protocol, connection: $connection_reuse";
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

# Kong's way of pooling upstream connections across both protocols. nginx 1.29.7
# and later cache idle upstream connections for every upstream block, even one
# with no "keepalive" directive, and that cache sits in front of
# balancer_by_lua and takes each connection before the Lua pool can. Its
# entries only match on peer address and u->conf, while the Lua pool only
# matches on the pool name and the peer address, so the name has to carry the
# scheme and the HTTP version. "keepalive 0" switches the nginx cache off and
# leaves the Lua pool as the only one. nginx before 1.29.7 rejects
# "keepalive 0", hence a config of its own for the one test that uses it.
our $PooledHttpConfig = $HttpConfig . <<'_EOC_';
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    upstream test_pooled_upstream {
        server 0.0.0.1;

        keepalive 0;
        balancer_keepalive 60;

        balancer_by_lua_block {
            local balancer = require "ngx.balancer"

            local scheme = ngx.var.arg_scheme or ""
            local version = ""

            if scheme == "http" or scheme == "https" then
                version = ngx.var.arg_version == "2" and "2" or "1.1"
            end

            local pool = scheme .. "|" .. version
            local sock = "unix:$TEST_NGINX_HTML_DIR/nginx.sock"

            assert(balancer.set_current_peer(sock, nil, pool))
            assert(balancer.enable_keepalive(60, 100))
        }
    }
_EOC_

# For the test of nginx's own default keepalive cache, see there.
our $DefaultCacheHttpConfig = $HttpConfig . <<'_EOC_';
    upstream test_default_cache_upstream {
        # No "keepalive" directive: nginx 1.29.7 and later still cache idle
        # connections here, and only hand one to a request whose u->conf is
        # the one it was created through. version=2 requests run on the
        # location's HTTP/2 shadow of the proxy config, so the two versions
        # have different u->conf and never get each other's connections.
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;
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
--- skip_eval
3: $::NoUpstreamHttp2



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
--- skip_eval
3: $::NoUpstreamHttp2



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



=== TEST 13: a literal path must start with a slash
--- config
    location /t {
        set $upstream_scheme 'http';

        kong_pass $upstream_scheme test_upstream t;
    }
--- must_die
--- error_log
path argument must start with "/", be empty, or be a $variable



=== TEST 14: a literal path that looks like a port is rejected
--- config
    location /t {
        set $upstream_scheme 'http';

        kong_pass $upstream_scheme test_upstream :8080;
    }
--- must_die
--- error_log
path argument must start with "/", be empty, or be a $variable



=== TEST 15: mixed version=2 and version=1.1 requests with bodies on the same location do not affect each other
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
--- skip_eval
3: $::NoUpstreamHttp2



=== TEST 16: kong_pass covers the location's limit_except block
--- http_config eval: $::HttpConfig
--- config
    location /t {
        proxy_http_version 1.1;

        # The selector and the version come from $arg_ variables rather than
        # from "set", because no "set" can reach the requests below: "set" is
        # not allowed inside "limit_except", and ngx_http_rewrite_module does
        # not inherit the enclosing location's codes into that child config
        # either, so a "set" written here would never run for them.
        kong_pass $arg_scheme test_upstream /t version=$arg_version;

        # "limit_except GET" runs every non-GET request, POST included, against
        # a separate location config that nginx creates for it. kong_pass
        # cannot be written in here, so the mediator's selector, version and
        # captured handlers must come from the merge, not from this block's
        # own (empty) config.
        limit_except GET {
            allow all;
        }
    }
--- request eval
["POST /t?scheme=http&version=2", "POST /t?scheme=http&version="]
--- response_body eval
["protocol: HTTP/2.0\n", "protocol: HTTP/1.1\n"]
--- no_error_log
[error]
[crit]
--- skip_eval
3: $::NoUpstreamHttp2



=== TEST 17: kong_pass covers the location's "if" block
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
--- skip_eval
3: $::NoUpstreamHttp2



=== TEST 18: dispatch stays per request over reused upstream connections
--- http_config eval: $::PooledHttpConfig
--- config
    location /reuse {
        proxy_http_version 1.1;
        kong_pass $arg_scheme test_pooled_upstream /reuse version=$arg_version;
    }
--- request eval
[
    "GET /reuse?scheme=http&version=2",
    "GET /reuse?scheme=http&version=",
    "GET /reuse?scheme=grpc",
    "GET /reuse?scheme=http&version=2",
    "GET /reuse?scheme=http&version=",
    "GET /reuse?scheme=grpc",
]
--- response_body_like eval
[
    qr/^protocol: HTTP\/2\.0, connection: (?:new|reused)$/,
    qr/^protocol: HTTP\/1\.1, connection: (?:new|reused)$/,
    qr/^protocol: HTTP\/2\.0, connection: (?:new|reused)$/,
    qr/^protocol: HTTP\/2\.0, connection: reused$/,
    qr/^protocol: HTTP\/1\.1, connection: reused$/,
    qr/^protocol: HTTP\/2\.0, connection: reused$/,
]
--- no_error_log
[error]
[crit]
--- skip_eval
3: $::NoUpstreamHttp2
--- skip_nginx
3: < 1.29.7



=== TEST 19: an empty path leaves the client's URI to the upstream
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme 'http';

        proxy_http_version 1.1;
        kong_pass $upstream_scheme test_upstream '';
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- no_error_log
[error]
[crit]



=== TEST 20: the selector must be a single variable
--- config
    location /t {
        set $a 'ht';
        set $b 'tp';

        kong_pass $a$b test_upstream /t;
    }
--- must_die
--- error_log
unknown "a$b" variable



=== TEST 21: version= must be a single variable
--- config
    location /t {
        set $upstream_scheme 'http';
        set $a '1';
        set $b '.1';

        kong_pass $upstream_scheme test_upstream /t version=$a$b;
    }
--- must_die
--- error_log
unknown "a$b" variable



=== TEST 22: a scheme that only starts with grpc goes to proxy_pass
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme 'grpcfoo';

        kong_pass $upstream_scheme test_upstream /t;
    }
--- request
GET /t
--- error_code: 500
--- error_log
invalid URL prefix in "grpcfoo://test_upstream/t"



=== TEST 23: a ${name} selector and version are accepted
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $upstream_scheme  'http';
        set $upstream_uri     '/t';
        set $upstream_version '';

        proxy_http_version 1.1;
        kong_pass ${upstream_scheme} test_upstream ${upstream_uri} version=${upstream_version};
    }
--- request
GET /t
--- response_body
protocol: HTTP/1.1
--- no_error_log
[error]
[crit]



=== TEST 24: an unterminated ${name is not a variable
--- config
    location /t {
        set $upstream_scheme 'http';

        kong_pass ${upstream_scheme test_upstream /t;
    }
--- must_die
--- error_log
"kong_pass" directive first argument must be a $variable



=== TEST 25: a location that already proxies names the directive that clashes
--- config
    location /t {
        set $upstream_scheme 'http';

        proxy_pass http://test_upstream;
        kong_pass $upstream_scheme test_upstream /t;
    }
--- must_die
--- error_log
"kong_pass" cannot use "proxy_pass": is duplicate



=== TEST 26: nginx's default keepalive cache keeps HTTP/1.1 and HTTP/2 connections apart
--- http_config eval: $::DefaultCacheHttpConfig
--- config
    location /reuse {
        proxy_http_version 1.1;

        # a connection of the wrong protocol would stall the request, so make
        # that fail fast instead of on the client's timeout
        proxy_read_timeout 2s;

        kong_pass $arg_scheme test_default_cache_upstream /reuse version=$arg_version;
    }
--- request eval
[
    "GET /reuse?scheme=http&version=2",
    "GET /reuse?scheme=http&version=",
    "GET /reuse?scheme=http&version=2",
    "GET /reuse?scheme=http&version=",
]
--- response_body_like eval
[
    qr/^protocol: HTTP\/2\.0, connection: (?:new|reused)$/,
    qr/^protocol: HTTP\/1\.1, connection: (?:new|reused)$/,
    qr/^protocol: HTTP\/2\.0, connection: reused$/,
    qr/^protocol: HTTP\/1\.1, connection: reused$/,
]
--- no_error_log
[error]
[crit]
--- skip_eval
3: $::NoUpstreamHttp2
--- skip_nginx
3: < 1.29.7



=== TEST 27: version=2 in an "if" block runs on that block's own configs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        proxy_http_version 1.1;
        kong_pass $arg_scheme test_upstream /t version=$arg_version;

        # The HTTP/2 shadow is built per location config. If the "if" block
        # reused its parent's, a version=2 request would lose this header.
        if ($arg_tag) {
            add_header X-If-Block $arg_tag;
        }
    }
--- request eval
[
    "GET /t?scheme=http&version=2&tag=v2",
    "GET /t?scheme=http&version=&tag=v1",
]
--- response_headers eval
[
    "X-If-Block: v2",
    "X-If-Block: v1",
]
--- response_body eval
["protocol: HTTP/2.0\n", "protocol: HTTP/1.1\n"]
--- no_error_log
[error]
[crit]
--- skip_eval
3: $::NoUpstreamHttp2



=== TEST 28: kong_pass is not allowed inside an "if" block
--- config
    location /t {
        if ($arg_scheme) {
            kong_pass $arg_scheme test_upstream /t;
        }
    }
--- must_die
--- error_log
"kong_pass" directive is not allowed here



=== TEST 29: kong_pass is not allowed inside a limit_except block
--- config
    location /t {
        limit_except GET {
            kong_pass $arg_scheme test_upstream /t;
        }
    }
--- must_die
--- error_log
"kong_pass" directive is not allowed here
