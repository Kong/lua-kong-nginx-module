# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: upstream TLS proxying works
--- stream_server_config
    proxy_pass mockbin.com:443;
    proxy_ssl on;
--- stream_request
GET /
--- stream_response_like: ^{"message":"no Route matched with those values"}$
--- no_error_log
[error]



=== TEST 2: upstream plaintext proxying works
--- stream_server_config
    proxy_pass mockbin.com:80;
    proxy_ssl off;
--- stream_request
GET /
--- stream_response_like: ^{"message":"no Route matched with those values"}$
--- no_error_log
[error]



=== TEST 3: upstream TLS proxying inhibit works
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

--- stream_server_config
    proxy_pass mockbin.com:443;
    proxy_ssl on;

    preread_by_lua_block {
        local tls = require("resty.kong.tls")

        assert(tls.disable_proxy_ssl())
    }
--- stream_request
GET /
--- stream_response_like: ^.+400 The plain HTTP request was sent to HTTPS port.+$
--- no_error_log
[error]
