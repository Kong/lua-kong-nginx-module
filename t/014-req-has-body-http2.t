# vim:set ft= ts=4 sw=4 et:

# HTTP/2 coverage using Test::Nginx's "--- http2" (curl --http2-prior-knowledge).
# A body that turns out to be zero length is not a body; a DATA payload
# without Content-Length still is.  "--- more_headers" with an empty
# "Content-Length:" suppresses the header curl would otherwise add.
# nginx >= 1.25.1 (the "http2" directive).

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4) - 4;

no_long_string();

our $HttpConfig = <<'_EOC_';
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
_EOC_

our $Config = <<'_EOC_';
    # has_body() is three-valued: true / false / nil + "pending".
    # nil is not printable, so handlers render it as "pending".

    # gate ngx.req.socket() on has_body(): it raises
    # "http v2 not supported yet" on HTTP/2 (wrong "true" => 500 + [error])
    location = /gate {
        content_by_lua_block {
            local request = require("resty.kong.request")

            local has = request.has_body()
            if has then
                ngx.req.socket()
            end

            ngx.say("ok ", has == nil and "pending" or tostring(has))
        }
    }

    # the body reading path: report the answer and what actually arrived
    location = /read {
        content_by_lua_block {
            local request = require("resty.kong.request")

            ngx.req.read_body()
            local has = request.has_body()
            ngx.say(has == nil and "pending" or tostring(has), ":",
                    ngx.req.get_body_data() or "")
        }
    }

    # no read_body() call at all
    location = /noread {
        content_by_lua_block {
            local request = require("resty.kong.request")
            local has = request.has_body()
            ngx.say(has == nil and "pending" or tostring(has))
        }
    }

    # around read_body(): pending until the ending DATA frame is parsed
    # pins the contract: has_body() reports the client-sent body, not one
    # set from Lua with ngx.req.set_body_data()
    location = /rewrite {
        content_by_lua_block {
            local request = require("resty.kong.request")

            ngx.req.read_body()
            local has = request.has_body()
            ngx.say(has == nil and "pending" or tostring(has))

            ngx.req.set_body_data(ngx.var.arg_set == "add" and "hello" or "")
            has = request.has_body()
            ngx.say(has == nil and "pending" or tostring(has))
        }
    }

    location = /pending {
        content_by_lua_block {
            local request = require("resty.kong.request")

            local function fmt(has)
                return has == nil and "pending" or tostring(has)
            end

            local before_read = request.has_body()
            ngx.req.read_body()
            local after_read = request.has_body()

            ngx.say(fmt(before_read), ":", fmt(after_read), ":",
                    ngx.req.get_body_data() or "")
        }
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->http_config) {
        $block->set_value("http_config", $::HttpConfig);
    }

    if (!defined $block->config) {
        $block->set_value("config", $::Config);
    }
});

run_tests();

__DATA__

=== TEST 1: POST with no content-length and no body, body read
--- http2
--- request
POST /read
--- response_body
false:
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 2: POST with a body and no content-length, body read
--- http2
--- more_headers
Content-Length:
--- request
POST /read
invali
--- response_body eval
"true:invali\n\n"
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 3: POST with a body and no content-length, body not read
# HEADERS carries no END_STREAM and the handler runs inline, before curl's
# DATA frame is parsed, so preread is still empty and the honest pre-read
# answer is pending.
--- http2
--- more_headers
Content-Length:
--- request
POST /noread
invali
--- response_body
pending
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 4: GET, no body at all
--- http2
--- request
GET /noread
--- response_body
false
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 5: POST with no content-length and no body, body not read
# curl ends the request on HEADERS, so the answer is false at once
--- http2
--- request
POST /noread
--- response_body
false
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 6: POST with no content-type, no content-length and no body
--- http2
--- request
POST /gate
--- response_body
ok false
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 7: PATCH with no content-length and no body
--- http2
--- request
PATCH /gate
--- response_body
ok false
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 8: PUT with no content-length and no body
--- http2
--- request
PUT /gate
--- response_body
ok false
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 9: POST with a body and content-length, body read
--- http2
--- request
POST /read
invali
--- response_body
true:invali
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 10: pending stream ends with an empty DATA frame
# -T/dev/null: curl uploads an unknown length -- HEADERS without
# END_STREAM, then an empty DATA with it.  Pending, then false.
--- http2
--- curl_options: -T/dev/null
--- more_headers
Content-Type:
Content-Length:
--- request
POST /pending
--- response_body
pending:false:
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 11: empty --data-binary ends a pending stream
# -d@/dev/null: same wire shape as -T/dev/null.  Pending, then false.
--- http2
--- curl_options: -d@/dev/null
--- more_headers
Content-Type:
Content-Length:
--- request
POST /pending
--- response_body
pending:false:
--- error_code: 200
--- no_error_log
[error]
http v2 not supported yet



=== TEST 12: set_body_data() does not hide the body the client sent
# 5 bytes received: true after read_body(), still true after the rewrite
# (rb->received beats content_length_n)
--- http2
--- more_headers
Content-Length:
--- request
POST /rewrite?set=clear
hello
--- response_body
true
true
--- error_code: 200
--- no_error_log
[error]



=== TEST 13: set_body_data() does not fabricate a body
# no client body (in_closed): false after read_body(), still false after
# the rewrite (in_closed beats content_length_n)
--- http2
--- more_headers
Content-Length:
--- request
POST /rewrite?set=add
--- response_body
false
false
--- error_code: 200
--- no_error_log
[error]
