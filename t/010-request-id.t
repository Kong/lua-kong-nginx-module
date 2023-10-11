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

=== TEST 1: $kong_request_id works
--- config
    location /t {
        content_by_lua_block {
            local rid = ngx.var.kong_request_id
            assert(ngx.re.match(rid, "[0-9a-f]{32}"))
            ngx.say("ok")
        }
    }

--- request
GET /t
--- response_body_like
ok

--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]


