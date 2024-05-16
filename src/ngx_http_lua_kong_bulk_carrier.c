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

#define HTTP_HEADER_HASH_FUNC (ngx_hash_key_lc)


static ngx_str_t request_headers[] = {
    ngx_string("user_agent"),
    ngx_string("host"),
    ngx_null_string
};


static ngx_str_t response_headers[] = {
    ngx_string("upgrade"),
    ngx_string("connection"),
    ngx_string("content_type"),
    ngx_string("content_length"),
    ngx_string("ratelimit_limit"),
    ngx_string("ratelimit_remaining"),
    ngx_string("ratelimit_reset"),
    ngx_string("retry_after"),
    ngx_string("x_ratelimit_limit_second"),
    ngx_string("x_ratelimit_limit_minute"),
    ngx_string("x_ratelimit_limit_hour"),
    ngx_string("x_ratelimit_limit_day"),
    ngx_string("x_ratelimit_limit_month"),
    ngx_string("x_ratelimit_limit_year"),
    ngx_string("x_ratelimit_remaining_second"),
    ngx_string("x_ratelimit_remaining_minute"),
    ngx_string("x_ratelimit_remaining_hour"),
    ngx_string("x_ratelimit_remaining_day"),
    ngx_string("x_ratelimit_remaining_month"),
    ngx_string("x_ratelimit_remaining_year"),
    ngx_null_string
};

static ngx_hash_t request_headers_hash;
static ngx_hash_t response_headers_hash;
static ngx_hash_init_t request_headers_hash_init;
static ngx_hash_init_t response_headers_hash_init;

static ngx_hash_keys_arrays_t response_header_keys;


int64_t
ngx_http_lua_ffi_header_bulk_carrier_init()
{
    response_headers_hash_init.hash = &response_headers_hash;
    response_headers_hash_init.key = HTTP_HEADER_HASH_FUNC;
    response_headers_hash_init.max_size = 128;
    response_headers_hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    response_headers_hash_init.name = "lua_kong_response_headers_hash";
    response_headers_hash_init.pool = ngx_cycle->pool;
    response_headers_hash_init.temp_pool = NULL;

    response_header_keys.pool = ngx_cycle->pool;
    response_header_keys.temp_pool = NULL;

    if (ngx_hash_keys_array_init(&response_header_keys, NGX_HASH_SMALL) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "failed to allocate memory for response headers hash keys");
        return NGX_ERROR;
    }

    for (ngx_uint_t i = 0; response_headers[i].len; i++) {
        // skip i == 0, as it represents the the key is not found
        if (ngx_hash_add_key(&response_header_keys, &response_headers[i], i + 1, NGX_HASH_READONLY_KEY) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "failed to add response header key to hash keys array");
            return NGX_ERROR;
        }
    }

    if (ngx_hash_init(&response_headers_hash_init, response_header_keys.keys.elts, response_header_keys.keys.nelts) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "failed to initialize response headers hash");
        return NGX_ERROR;
    }

    return NGX_OK;
}


int64_t
ngx_http_lua_kong_ffi_get_response_headers(ngx_http_request_t *r,
    int32_t* value_offsets,
    uint8_t* buf,
    uint32_t buf_len)
{
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *header = part->elts;
    ngx_str_t *hdr_key, *hdr_val;
    ngx_uint_t i, hash_key, val;
    uint32_t buf_offset = 0;

    // init value_offsets to -1
    for (i = 0; i < sizeof(response_headers) / sizeof(ngx_str_t) - 1; i++) {
        value_offsets[i] = -1;
    }

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        hdr_key = &header[i].key;
        hdr_val = &header[i].value;

        hash_key = HTTP_HEADER_HASH_FUNC(hdr_key->data, hdr_key->len);
        if (!(val = ngx_hash_find(&response_headers_hash, hash_key, hdr_key->data, hdr_key->len))) {
            continue;
        }

        if (buf_offset + hdr_val->len > buf_len) {
            // buffer too small
            return NGX_AGAIN;
        }

        ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
        value_offsets[val - 1] = buf_offset;
        buf_offset += hdr_val->len;
    }

    return NGX_OK;
}
