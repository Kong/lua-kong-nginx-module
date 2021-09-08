# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

plan tests => repeat_each() * (blocks() * 5);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: lua_kong_load_var_index directive works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    lua_kong_load_var_index "realip_remote_addr";

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
    lua_kong_load_var_index "variable_2";

--- config
    set $variable_2 'value2';

    location /t {
        content_by_lua_block {
            local var = require "resty.kong.var"
            local t = var.load_indexes()
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
    lua_kong_load_var_index "variable_3";

--- config
    set $variable_3 'value3';

    location /t {
        content_by_lua_block {
            ngx.say(ngx.var.variable_3)

            -- break original function
            local breakit = function() error("broken") end
            local mt1 = getmetatable(ngx.var)
            mt1.__index = breakit
            mt1.__newindex = breakit

            local pok, perr = pcall(function() return ngx.var.variable_3 end)
            ngx.say(perr)

            local var = require "resty.kong.var"
            var.patch_metatable()
            ngx.say(ngx.var.variable_3)
        }
    }

--- request
GET /t
--- response_body_like
value3
.+broken
value3

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]

=== TEST 4: patch metatable works for set
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
    # this is not required, but set explictly in tests
    lua_kong_load_var_index "variable_4";

--- config
    set $variable_4 'value4';

    location /t {
        content_by_lua_block {
            ngx.var.variable_4 = "value4_1"
            ngx.say(ngx.var.variable_4)

            -- break original function
            local breakit = function() error("broken") end
            local mt1 = getmetatable(ngx.var)
            mt1.__index = breakit
            mt1.__newindex = breakit

            local pok, perr = pcall(function() return ngx.var.variable_4 end)
            ngx.say(perr)

            local var = require "resty.kong.var"
            var.patch_metatable()
            ngx.var.variable_4 = "value4_2"
            ngx.say(ngx.var.variable_4)
        }
    }

--- request
GET /t
--- response_body_like
value4_1
.+broken
value4_2

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]
