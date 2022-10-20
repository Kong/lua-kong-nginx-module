# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity: directive works well
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- stream_server_config
    lua_kong_set_static_tag "it works";
    content_by_lua_block {
        local tag = require "resty.kong.tag"
        ngx.say(tag.get())
    }
--- response_body
it works
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: default tag is nil
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
--- stream_server_config
    content_by_lua_block {
        local tag = require "resty.kong.tag"
        ngx.say("value:", tag.get())
    }
--- response_body
value:nil
--- no_error_log
[error]
[crit]
[alert]



