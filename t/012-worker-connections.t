# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 - 1);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

no_long_string();

run_tests();

__DATA__

=== TEST 1: $worker_connections_total is a positive integer
--- config
    location /t {
        content_by_lua_block {
            local total = ngx.var.kong_worker_connections_total
            assert(total ~= nil, "worker_connections_total is nil")
            local n = tonumber(total)
            assert(n ~= nil and n > 0,
                   "worker_connections_total is not a positive integer: " .. tostring(total))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_code: 200
--- no_error_log
[error]


=== TEST 2: $worker_connections_free is a non-negative integer
--- config
    location /t {
        content_by_lua_block {
            local free = ngx.var.kong_worker_connections_free
            assert(free ~= nil, "worker_connections_free is nil")
            local n = tonumber(free)
            assert(n ~= nil and n >= 0,
                   "worker_connections_free is not a non-negative integer: " .. tostring(free))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_code: 200
--- no_error_log
[error]


=== TEST 3: $worker_connections_free is less than or equal to $worker_connections_total
--- config
    location /t {
        content_by_lua_block {
            local total = tonumber(ngx.var.kong_worker_connections_total)
            local free  = tonumber(ngx.var.kong_worker_connections_free)
            assert(free <= total,
                   "free(" .. free .. ") > total(" .. total .. ")")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_code: 200
--- no_error_log
[error]


=== TEST 4: $worker_connections_free is re-evaluated on each access (no_cacheable)
--- config
    location /t {
        content_by_lua_block {
            -- Read free count before opening an extra connection.
            local free_before = tonumber(ngx.var.kong_worker_connections_free)
            assert(free_before ~= nil, "free_before is nil")

            -- Open a cosocket to consume one connection slot in this worker.
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
            assert(ok, "connect failed: " .. tostring(err))

            -- Read again: must re-invoke the getter (no_cacheable), so the
            -- value reflects the newly consumed slot.
            local free_during = tonumber(ngx.var.kong_worker_connections_free)
            assert(free_during ~= nil, "free_during is nil")
            assert(free_during < free_before,
                   "expected free to decrease after connect, got before="
                   .. free_before .. " during=" .. free_during)

            sock:close()

            -- After closing, free count must recover.
            local free_after = tonumber(ngx.var.kong_worker_connections_free)
            assert(free_after ~= nil, "free_after is nil")
            assert(free_after > free_during,
                   "expected free to increase after close, got during="
                   .. free_during .. " after=" .. free_after)

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_code: 200
