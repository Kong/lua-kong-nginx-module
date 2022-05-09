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


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* name should be lowercased and preprocessed for both search functions */

/* by hash */
static ngx_str_t *
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

    return &header_found->value;
}


/* linear search */
static ngx_str_t *
ngx_http_lua_kong_search_unknown_header(ngx_http_request_t *r,
    ngx_str_t name, size_t search_limit)
{
    size_t               i;
    size_t               n;
    u_char               ch;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;

    part = &(r->headers_in.headers.part);
    header = part->elts;

    /* not limited when search_limit == 0 */
    for (i = 0u; search_limit == 0u || i < search_limit; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0u;
        }

        if (header[i].hash == 0u) {
            continue;
        }

        for (n = 0u; n < name.len && (ch = header[i].lowcase_key[n]); n++) {
            if (ch == '-') {
                ch = '_';
            }

            if (name.data[n] != ch) {
                break;
            }
        }

        if (n == name.len && n == header[i].key.len) {
            return &header[i].value;
        }
    }

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

    for (i = 0u; i < name.len; ++i) {
        ch = ngx_tolower(name.data[i]);

        if (ch == '-') {
            ch = '_';
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
    ngx_log_t   *log;

    processed_name = ngx_http_lua_kong_header_preprocess(r, name);

    log = r->connection->log;

    value = ngx_http_lua_kong_search_known_header(r, processed_name);

    if (value == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "%V not found from hashed headers", name);

        value = ngx_http_lua_kong_search_unknown_header(r,
                    processed_name, search_limit);
    }

    if (value == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "%V not found from all", name);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
            "%V:%V",name, *value);
    }

    return value;
}
