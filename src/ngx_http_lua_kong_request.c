/**
 * Copyright 2019-2022 Kong Inc.

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


/* name should be lowercased and preprocessed for both search functions */

/* by hash */
static ngx_str_t*
ngx_http_lua_kong_search_known_header(ngx_http_request_t *r, ngx_str_t name)
{
    ngx_uint_t                   hash;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_header_t           *hh;
    ngx_table_elt_t             *header_found;

    /* Calculate a hash of lowercased header name */
    hash = ngx_hash_key(name.data, name.len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, hash, name.data, name.len);

    /* The header is unknown or is not hashed yet. */
    if (hh == NULL) {
        return NULL;
    }

    /* The header is hashed but not cached yet for some reason. */
    if (hh->offset == 0) {
        return NULL;
    }

    /* The header value was already cached in some field of the r->headers_in
        struct (hh->offset tells in which one). */
    header_found = *(ngx_table_elt_t **)((char *) &r->headers_in + hh->offset);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "found %V by hash, value is %V", &name, &header_found->value);

    return &header_found->value;
}


/* linear search */
static ngx_str_t*
ngx_http_lua_kong_search_unknown_header(ngx_http_request_t *r,
    ngx_str_t name, size_t search_limit)
{
    size_t               i, n;
    u_char               ch;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;

    part = &r->headers_in.headers.part;
    header = part->elts;

    /* not limit if search_limit == 0 */
    for (i = 0; search_limit == 0 || i < search_limit; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (name.len != header[i].key.len) {
            continue;
        }

        for (n = 0; n < name.len; n++) {
            ch = header[i].lowcase_key[n];
            if (ch == '_') {
                ch = '-';
            }

            if (name.data[n] != ch) {
                break;
            }
        }

        if (n == name.len) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "found %V by linear search, value is %V",
                    &name, &header[i].value);

            return &header[i].value;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "not found %V by linear search", &name);

    return NULL;
}


static ngx_str_t
ngx_http_lua_kong_header_preprocess(ngx_http_request_t *r, ngx_str_t name)
{
    ngx_str_t   value;
    size_t      i;
    u_char      ch;

    value.data = ngx_palloc(r->pool, name.len);
    value.len = name.len;

    for (i = 0; i < name.len; ++i) {
        ch = ngx_tolower(name.data[i]);

        if (ch == '_') {
            ch = '-';
        }

        value.data[i] = ch;
    }

    return value;
}


/* search request header named "name" and within search_limit */
ngx_str_t *
ngx_http_lua_kong_ffi_request_get_header(ngx_http_request_t *r,
    ngx_str_t name, size_t search_limit)
{
    ngx_str_t    processed_name;
    ngx_str_t   *value;

    processed_name = ngx_http_lua_kong_header_preprocess(r, name);

    value = ngx_http_lua_kong_search_known_header(r, processed_name);

    if (value != NULL) {
        return value;
    }

    return ngx_http_lua_kong_search_unknown_header(r,
                processed_name, search_limit);
}
