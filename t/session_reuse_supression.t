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

=== TEST 1: session ticket based reuse works
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate_by_lua_block {
            print("ssl session id: ", require("resty.kong.tls").get_session_id())
        }
        ssl_certificate ../../cert/example.com.crt;
        ssl_certificate_key ../../cert/example.com.key;

        server_tokens off;
        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            return 200 'it works!';
        }
    }
--- config
    server_tokens off;

    location /t {
        proxy_ssl_trusted_certificate ../../cert/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- request
GET /t
--- response_body chop
it works!

--- error_log
[lua] ssl_certificate_by_lua:1: ssl cert by lua is running!

--- no_error_log
[error]
[alert]
