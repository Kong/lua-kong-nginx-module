# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

plan tests => repeat_each() * (blocks() * 5) + 2;

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_NXSOCK} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: lua_kong_load_var_index directive works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $realip_remote_addr;

--- config
    set $variable_1 'value1';

    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.variable_1)
        }
    }

--- request
GET /t
--- response_body_like
value1

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: load_indexes API works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    # this is not required for variable defined by set
    # but set explictly in tests
    lua_kong_load_var_index $variable_2;

    init_by_lua_block {
        local var = require "resty.kong.var"
        _G.t = var.load_indexes()
    }
--- config
    set $variable_2 'value2';

    location /t {
        content_by_lua_block {
            ngx.say(t.variable_2)
        }
    }

--- request
GET /t
--- response_body_like
\d+

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3: patch metatable works for get
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    # this is not required, but set explictly in tests
    lua_kong_load_var_index $variable_3;

    init_by_lua_block {
        local var = require "resty.kong.var"
        -- break original function
        local breakit = function() error("broken") end
        local mt1 = getmetatable(ngx.var)
        mt1.__index = breakit
        mt1.__newindex = breakit

        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    set $variable_3 'value3';

    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.variable_3)
        }
    }

--- request
GET /t
--- response_body_like
value3

--- error_code: 200
--- error_log
get variable value 'value3' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: patch metatable works for set
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    # this is not required, but set explictly in tests
    lua_kong_load_var_index $variable_4;

    init_by_lua_block {
        local var = require "resty.kong.var"
        -- break original function
        local breakit = function() error("broken") end
        local mt1 = getmetatable(ngx.var)
        mt1.__index = breakit
        mt1.__newindex = breakit

        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    set $variable_4 'value4';

    location /t {
        content_by_lua_block {
            ngx.var.variable_4 = "value4_2"
            ngx.say(ngx.var.variable_4)
        }
    }

--- request
GET /t
--- response_body_like
value4_2

--- error_code: 200
--- error_log
get variable value 'value4_2' by index
--- no_error_log
[error]
[crit]
[alert]



=== TEST 5: a write reaches the storage the variable reads ($args in r->args)
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $args;

    init_by_lua_block {
        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    location /t {
        content_by_lua_block {
            -- $args reads r->args, so a write has to land there, not in the
            -- indexed cache slot
            ngx.var.args = "a=1"
            ngx.say("var: ", tostring(ngx.var.args))
            ngx.say("req: ", tostring(ngx.req.get_uri_args().a))

            -- a write that went to the cache alone used to answer here
            ngx.req.set_uri_args("b=2")
            ngx.say("after: ", tostring(ngx.var.args))
        }
    }

--- request
GET /t
--- response_body
var: a=1
req: 1
after: b=2

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: a header rewrite is visible to the variables fed by it
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $http_authorization;
    lua_kong_load_var_index $http_host;
    lua_kong_load_var_index $cookie_session;
    lua_kong_load_var_index $content_type;

    init_by_lua_block {
        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    location /t {
        content_by_lua_block {
            -- reading first is what used to leave the value in the index cache
            ngx.say("auth: ", tostring(ngx.var.http_authorization))
            ngx.req.set_header("Authorization", "foo")
            ngx.say("auth: ", tostring(ngx.var.http_authorization))
            ngx.req.clear_header("Authorization")
            ngx.say("auth: ", tostring(ngx.var.http_authorization))

            -- one Cookie header feeds every $cookie_ variable
            ngx.req.set_header("Cookie", "session=one")
            ngx.say("cookie: ", tostring(ngx.var.cookie_session))
            ngx.req.set_header("Cookie", "session=two")
            ngx.say("cookie: ", tostring(ngx.var.cookie_session))

            -- a variable of its own, named after the header it reads
            ngx.req.set_header("Content-Type", "text/plain")
            ngx.say("ct: ", tostring(ngx.var.content_type))
            ngx.req.set_header("Content-Type", "application/json")
            ngx.say("ct: ", tostring(ngx.var.content_type))

            -- nginx has a named variable for some headers as well, with no
            -- prefix to tell it apart from the rest by flags alone
            ngx.req.set_header("Host", "one.example")
            ngx.say("host: ", tostring(ngx.var.http_host))
            ngx.req.set_header("Host", "two.example")
            ngx.say("host: ", tostring(ngx.var.http_host))
        }
    }

--- request
GET /t
--- response_body
auth: nil
auth: foo
auth: nil
cookie: one
cookie: two
ct: text/plain
ct: application/json
host: one.example
host: two.example

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 7: the arguments and $limit_rate are re-read too
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $args;
    lua_kong_load_var_index $arg_foo;
    lua_kong_load_var_index $limit_rate;

    init_by_lua_block {
        local var = require "resty.kong.var"
        var.patch_metatable()
    }

--- config
    location /t {
        content_by_lua_block {
            -- reading $arg_foo first is what used to leave the value in the
            -- index cache
            ngx.say("arg: ", tostring(ngx.var.arg_foo))
            ngx.req.set_uri_args("foo=two")
            ngx.say("arg: ", tostring(ngx.var.arg_foo))
            ngx.say("args: ", tostring(ngx.var.args))

            -- $limit_rate keeps its value in r->limit_rate: the write has to
            -- reach it, and the read has to see it
            ngx.say("rate: ", tostring(ngx.var.limit_rate))
            ngx.var.limit_rate = 1024
            ngx.say("rate: ", tostring(ngx.var.limit_rate))
        }
    }

--- request
GET /t?foo=one
--- response_body
arg: one
arg: two
args: foo=two
rate: 0
rate: 1024

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 8: a variable that changes while the request is served is re-read
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index $upstream_status;

    init_by_lua_block {
        local var = require "resty.kong.var"
        var.patch_metatable()
    }

    server {
        listen unix:$TEST_NGINX_NXSOCK/upstream.sock;

        location / {
            content_by_lua_block {
                ngx.say("upstream ok")
            }
        }
    }
--- config
    location = /t {
        access_by_lua_block {
            -- the upstream has not answered yet: this read used to be the value
            -- every later read of the request answered with
            ngx.log(ngx.WARN, "upstream_status before: ", tostring(ngx.var.upstream_status))
        }

        log_by_lua_block {
            ngx.log(ngx.WARN, "upstream_status after: ", tostring(ngx.var.upstream_status))
        }

        proxy_pass http://unix:/$TEST_NGINX_NXSOCK/upstream.sock;
    }
--- request
GET /t
--- error_code: 200
--- error_log eval
qr/upstream_status after: 200/
--- no_error_log
[error]
[crit]
[alert]
