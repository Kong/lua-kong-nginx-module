# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

plan tests => repeat_each() * (blocks() * 5);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();
#no_diff();

our $HttpConfig = qq{
    #lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;t/?.lua;;";
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;t/?.lua;lib/?.lua;;";

    init_by_lua_block {
        _G.test_var = require "var"
    }
};

run_tests();

__DATA__

=== TEST 1: can return valid index for known variable
--- http_config eval: $::HttpConfig
--- config
    set $variable_1 '';

    location /t {
        content_by_lua_block {
            ngx.say(test_var.load_index("variable_1"))
            ngx.say(test_var.load_index("http_host"))
        }
    }

--- request
GET /t
--- response_body_like
\d+
\d+

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]

=== TEST 2: can use index to get variable
--- http_config eval: $::HttpConfig
--- config
    set $variable_2 'value2';

    location /t {
        content_by_lua_block {
            test_var.load_index("variable_2")

            ngx.say(ngx.var_indexed.variable_2)
            ngx.say(ngx.var_indexed.variable_2)
        }
    }

--- request
GET /t
--- response_body_like
value2
value2

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]

=== TEST 3: can use index to set variable
--- http_config eval: $::HttpConfig
--- config
    set $variable_3 'value3';

    location /t {
        content_by_lua_block {
            test_var.load_index("variable_3")

            ngx.var_indexed.variable_3 = "value3_set"
            ngx.say(ngx.var_indexed.variable_3)
        }
    }

--- request
GET /t
--- response_body_like
value3_set

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]

=== TEST 4: can use index to set variable and read by ngx.var
--- http_config eval: $::HttpConfig
--- config
    set $variable_4 'value4';

    location /t {
        content_by_lua_block {
            test_var.load_index("variable_4")

            ngx.var_indexed.variable_4 = "value4_set"
            ngx.say(ngx.var.variable_4)
        }
    }

--- request
GET /t
--- response_body_like
value4_set

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]

=== TEST 5: can use ngx.var to set variable and read by index
--- http_config eval: $::HttpConfig
--- config
    set $variable_5 'value5';

    location /t {
        content_by_lua_block {
            test_var.load_index("variable_5")

            ngx.var.variable_5 = "value5_set"
            ngx.say(ngx.var_indexed.variable_5)
        }
    }

--- request
GET /t
--- response_body_like
value5_set

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]


