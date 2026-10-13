# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

repeat_each(2);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

# A variable nginx did not mark non-cacheable keeps the value it cached the
# first time it was read. Reading through the index caches, unlike an
# unindexed read, so rewriting a request header has to drop what the
# variables fed by that header cached. Every block below reads such a
# variable, rewrites its header, and reads it again.
our $Patched = <<'_EOC_';
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    lua_kong_load_var_index $http_foo;
    lua_kong_load_var_index $cookie_a;
    lua_kong_load_var_index default;

    init_by_lua_block {
        require("resty.kong.var").patch_metatable()
    }
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: clearing a header is seen by a later read
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            ngx.say("before: ", tostring(ngx.var.http_foo))
            ngx.req.clear_header("Foo")
            ngx.say("after: ", tostring(ngx.var.http_foo))
        }
    }
--- request
GET /t
--- more_headers
Foo: present
--- response_body
before: present
after: nil
--- no_error_log
[error]
[crit]



=== TEST 2: setting a header is seen by a later read
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            ngx.say("before: ", tostring(ngx.var.http_foo))
            ngx.req.set_header("Foo", "rewritten")
            ngx.say("after: ", tostring(ngx.var.http_foo))
        }
    }
--- request
GET /t
--- more_headers
Foo: present
--- response_body
before: present
after: rewritten
--- no_error_log
[error]
[crit]



=== TEST 3: the variable stays indexed after its header is rewritten
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            local kvar = require "resty.kong.var"

            ngx.req.set_header("Foo", "rewritten")
            ngx.req.clear_header("Foo")

            -- get() errors unless the name is still indexed, so this asserts
            -- that neither rewrite dropped the index for the whole worker
            ngx.say("indexed: ", tostring(kvar.get("http_foo")))
        }
    }
--- request
GET /t
--- more_headers
Foo: present
--- response_body
indexed: nil
--- no_error_log
[error]
[crit]



=== TEST 4: Content-Type feeds a variable of its own
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            ngx.say("before: ", tostring(ngx.var.content_type))
            ngx.req.set_header("Content-Type", "text/plain")
            ngx.say("after: ", tostring(ngx.var.content_type))
        }
    }
--- request
GET /t
--- more_headers
Content-Type: application/json
--- response_body
before: application/json
after: text/plain
--- no_error_log
[error]
[crit]



=== TEST 5: one Cookie header feeds every $cookie_ variable
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            ngx.say("before: ", tostring(ngx.var.cookie_a))
            ngx.req.set_header("Cookie", "a=second")
            ngx.say("after: ", tostring(ngx.var.cookie_a))
        }
    }
--- request
GET /t
--- more_headers
Cookie: a=first
--- response_body
before: first
after: second
--- no_error_log
[error]
[crit]



=== TEST 6: set_uri_args needs no invalidation, $args is not cacheable
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            ngx.say("before: ", tostring(ngx.var.args))
            ngx.req.set_uri_args("b=2")
            ngx.say("after: ", tostring(ngx.var.args))
        }
    }
--- request
GET /t?a=1
--- response_body
before: a=1
after: b=2
--- no_error_log
[error]
[crit]



=== TEST 7: $uri is indexed by default, and is re-read after a rewrite
--- http_config eval: $::Patched
--- config
    location /t {
        content_by_lua_block {
            local kvar = require "resty.kong.var"

            -- get() errors unless the name is indexed
            ngx.say("indexed: ", kvar.get("uri"))

            ngx.req.set_uri("/rewritten")
            ngx.say("after: ", ngx.var.uri)
        }
    }
--- request
GET /t
--- response_body
indexed: /t
after: /rewritten
--- no_error_log
[error]
[crit]



=== TEST 8: an absent upstream TLS protocol is not remembered for the request
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index default;

    server {
        listen unix:$TEST_NGINX_HTML_DIR/upstream.sock ssl;
        server_name upstream.example.com;
        ssl_certificate ../../cert/upstream.crt;
        ssl_certificate_key ../../cert/upstream.key;
        ssl_session_cache off;
        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }
    }

--- config
    location /t {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/upstream.sock;
        proxy_ssl_server_name on;
        proxy_ssl_name upstream.example.com;
        proxy_ssl_session_reuse off;
        proxy_ssl_protocols TLSv1.2;

        # asked before there is an upstream connection to ask, which nginx
        # would otherwise remember as "no value" for the whole request
        access_by_lua_block {
            ngx.log(ngx.WARN, "early=",
                    tostring(ngx.var.kong_upstream_ssl_protocol))
        }

        header_filter_by_lua_block {
            ngx.header["X-Upstream-Ssl"] = ngx.var.kong_upstream_ssl_protocol
        }
    }
--- request
GET /t
--- response_headers
X-Upstream-Ssl: TLSv1.2
--- error_log
early=nil
--- no_error_log
[error]
[crit]
