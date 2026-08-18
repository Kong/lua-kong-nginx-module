/**
 * Copyright 2019-2025 Kong Inc.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "ngx_http_lua_kong_common.h"


/*
 * Tells whether the client sent a request body, without relying on the
 * Content-Length header being present.  A zero length body (e.g. an HTTP/2
 * zero length DATA frame with END_STREAM) is *not* a body.
 *
 * Returns 1 when a body is proven, 0 when no body is proven, -1 (pending)
 * when neither can be proven yet: chunked framing is declared but no body
 * byte has been accounted.  Pending resolves once the body has been read
 * to its end (rb->rest == 0 and rb->last_saved, the fields nginx itself
 * uses for "read complete"): the final content_length_n then proves the
 * answer -- the HTTP/1.x chunked filter accumulates the parsed chunk sizes
 * into it, and an empty body leaves it at zero.
 *
 * Order: rb->received > 0 (exact counter, maintained by h2 only) /
 * h2 preread buffer non-empty / client done sending with zero bytes
 * (h2: stream->in_closed) / body read to its end: the final
 * content_length_n decides / content_length_n > 0 declared is proof of a
 * body / chunked is pending.  HTTP/3 is rejected by the Lua wrapper.
 */
ngx_int_t
ngx_http_lua_kong_req_has_body(ngx_http_request_t *r)
{
    ngx_http_request_body_t  *rb;

    /* only the main request owns the client body */
    r = r->main;

    rb = r->request_body;

    if (rb != NULL && rb->received > 0) {
        return 1;
    }

#if (NGX_HTTP_V2)
    if (rb == NULL
        && r->stream != NULL
        && r->stream->preread != NULL
        && r->stream->preread->last > r->stream->preread->pos)
    {
        return 1;
    }

    if (r->stream != NULL && r->stream->in_closed) {
        return 0;
    }
#endif

    if (rb != NULL && rb->rest == 0 && rb->last_saved) {
        /* the body has been read to its end: the final
         * content_length_n settles the answer */
        return r->headers_in.content_length_n > 0 ? 1 : 0;
    }

    if (r->headers_in.content_length_n > 0) {
        return 1;
    }

    if (r->headers_in.chunked) {
        return -1;   /* body framing declared, payload unknown yet */
    }

    return 0;
}


int
ngx_http_lua_kong_ffi_req_has_body(ngx_http_request_t *r)
{
    return ngx_http_lua_kong_req_has_body(r);
}
