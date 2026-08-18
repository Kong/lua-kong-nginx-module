# vim:set ft= ts=4 sw=4 et:

# HTTP/2 coverage using Test::Nginx's "--- http2" (curl --http2-prior-knowledge).
# A body that turns out to be zero length is not a body; a DATA payload
# without Content-Length still is.  "--- more_headers" with an empty
# "Content-Length:" suppresses the header curl would otherwise add.
# nginx >= 1.25.1 (the "http2" directive).

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

no_long_string();

our $HttpConfig = <<'_EOC_';
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";
_EOC_

our $Config = <<'_EOC_';
    # had_body() is three-valued: true / false / nil + "pending".
    # nil is not printable, so handlers render it as "pending".

    # gate ngx.req.socket() on had_body(): it raises
    # "http v2 not supported yet" on HTTP/2 (wrong "true" => 500 + [error])
    location = /gate {
        content_by_lua_block {
            local request = require("resty.kong.request")

            local had = request.had_body()
            if had then
                ngx.req.socket()
            end

            ngx.say("ok ", had == nil and "pending" or tostring(had))
        }
    }

    # the body reading path: report the answer and what actually arrived
    location = /read {
        content_by_lua_block {
            local request = require("resty.kong.request")

            ngx.req.read_body()
            local had = request.had_body()
            ngx.say(had == nil and "pending" or tostring(had), ":",
                    ngx.req.get_body_data() or "")
        }
    }

    # no read_body() call at all
    location = /noread {
        content_by_lua_block {
            local request = require("resty.kong.request")
            local had = request.had_body()
            ngx.say(had == nil and "pending" or tostring(had))
        }
    }

    # Observe the request before and after nginx parses the frame that ends
    # an empty stream.  Before read_body() the DATA frame has not been
    # parsed, so the honest answer is pending; after read_body() the
    # received-bytes count proves there was no body.
    location = /pending {
        content_by_lua_block {
            local request = require("resty.kong.request")

            local function fmt(had)
                return had == nil and "pending" or tostring(had)
            end

            local before_read = request.had_body()
            ngx.req.read_body()
            local after_read = request.had_body()

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
# curl ends the request on the HEADERS frame (no DATA frame at all), so
# had_body() is false; the pre-parse "DATA still allowed" window of the
# hand-rolled variant is not reachable through curl.
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
# /dev/null is a non-regular file, so curl starts an upload without a known
# length. It sends HEADERS without END_STREAM, followed by a zero-length DATA
# frame with END_STREAM. nginx runs the content phase between those frames.
# Test::Nginx passes curl_options as one argv item. The full curl form is
# "--upload-file /dev/null", so this test uses its compact -T/dev/null form.
# Pending before read_body() (the empty DATA frame is not parsed yet),
# false after it (the received-bytes count proves zero).
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
# Test::Nginx cannot pass the two argv items in "--data-binary ''". For an
# empty payload, the compact -d@/dev/null form has the same wire behavior.
# curl sends HEADERS without END_STREAM, then an empty DATA with END_STREAM.
# Pending before read_body(), false after it.
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

