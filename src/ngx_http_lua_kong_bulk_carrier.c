/**
 * Copyright 2019-2022 Kong Inc.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "eAS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "ngx_http_lua_kong_common.h"

#define HTTP_HEADER_HASH_FUNC (ngx_hash_key)

typedef struct bulk_carrier_s {
    ngx_pool_t *mem_pool;
    ngx_pool_t *mem_temp_pool;  // DO NOT USE IT
                                // AFTER FINALIZATION OF HEADER REGISTRATION
    ngx_hash_t  request_headers;
    ngx_hash_t  response_headers;
    ngx_hash_keys_arrays_t request_headers_keys;
    ngx_hash_keys_arrays_t response_headers_keys;
    ngx_uint_t request_headers_count;
    ngx_uint_t response_headers_count;
    uint32_t   *request_header_fetch_info;
    uint32_t   *response_header_fetch_info;
} bulk_carrier_t;

bulk_carrier_t *
ngx_http_lua_kong_ffi_bulk_carrier_new()
{
    bulk_carrier_t *bc = ngx_calloc(sizeof(bulk_carrier_t), ngx_cycle->log);
    if (bc == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t allocation failed");
        return NULL;
    }

    bc->mem_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    if (bc->mem_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t mem_pool allocation failed");
        return NULL;
    }

    bc->mem_temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    if (bc->mem_temp_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t mem_temp_pool allocation failed");
        return NULL;
    }

    bc->request_headers_keys.pool = bc->mem_pool;
    bc->response_headers_keys.pool = bc->mem_pool;
    bc->request_headers_keys.temp_pool = bc->mem_temp_pool;
    bc->response_headers_keys.temp_pool = bc->mem_temp_pool;

    if (ngx_hash_keys_array_init(&bc->request_headers_keys, NGX_HASH_LARGE) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t request_headers_keys init failed");
        return NULL;
    }

    if (ngx_hash_keys_array_init(&bc->response_headers_keys, NGX_HASH_LARGE) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t response_headers_keys init failed");
        return NULL;
    }

    return bc;
}


void
ngx_http_lua_kong_ffi_bulk_carrier_free(bulk_carrier_t *bc)
{
    ngx_destroy_pool(bc->mem_pool);

    if (bc->mem_temp_pool != NULL) {
        ngx_destroy_pool(bc->mem_temp_pool);
    }

    ngx_free(bc);
}


uint32_t
ngx_http_lua_kong_ffi_bulk_carrier_register_header(
    bulk_carrier_t *bc,
    const unsigned char *header_name,
    uint32_t header_name_len,
    int32_t is_request_header)
{
    unsigned char c;
    uint32_t index;
    ngx_str_t key;
    ngx_hash_keys_arrays_t *keys_array;

    // crash early for invalid arguments
    ngx_http_lua_kong_assert(bc != NULL);
    ngx_http_lua_kong_assert(header_name != NULL);
    ngx_http_lua_kong_assert(header_name_len > 0);

    key.data = ngx_pcalloc(bc->mem_pool, header_name_len);
    if (key.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t header_name allocation failed");
        return 0;
    }

    key.len = header_name_len;
    ngx_memcpy(key.data, header_name, header_name_len);

    keys_array = is_request_header ? (&bc->request_headers_keys) : (&bc->response_headers_keys);
    index = keys_array->keys.nelts + 1;

    if (index >= UINT32_MAX) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t header_name count overflow");
        return 0;
    }

    if (ngx_hash_add_key(keys_array, &key, (void*)index, NGX_HASH_READONLY_KEY) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t header_name add failed");
        return 0;
    }

    return index;
}


int32_t
ngx_http_lua_kong_ffi_bulk_carrier_finalize_registration(
    bulk_carrier_t *bc)
{
    ngx_hash_init_t hash_init;

    // crash early for invalid arguments
    ngx_http_lua_kong_assert(bc != NULL);

    bc->request_headers_count = bc->request_headers_keys.keys.nelts;
    bc->response_headers_count = bc->response_headers_keys.keys.nelts;

    bc->request_header_fetch_info = ngx_pcalloc(bc->mem_pool, (bc->request_headers_count * 2 + 1) * sizeof(uint32_t));
    if (bc->request_header_fetch_info == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t request_header_fetch_info allocation failed");
        return NGX_ERROR;
    }

    bc->response_header_fetch_info = ngx_pcalloc(bc->mem_pool, (bc->response_headers_count * 2 + 1) * sizeof(uint32_t));
    if (bc->response_header_fetch_info == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t response_header_fetch_info allocation failed");
        return NGX_ERROR;
    }

    hash_init.name = "lua_kong_analytics_req_hdr_bulk_hash"; // TODO: use a better name
    hash_init.pool = bc->mem_pool;
    hash_init.temp_pool = bc->mem_temp_pool;
    hash_init.key = HTTP_HEADER_HASH_FUNC;
    hash_init.bucket_size = ngx_align(128, ngx_cacheline_size);

    hash_init.hash = &bc->request_headers;
    hash_init.max_size = 64; // TODO: use a better size

    if (ngx_hash_init(&hash_init, bc->request_headers_keys.keys.elts, bc->request_headers_keys.keys.nelts) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t request_headers hash init failed");
        return NGX_ERROR;
    }

    hash_init.name = "lua_kong_analytics_resp_hdr_bulk_hash"; // TODO: use a better name
    hash_init.hash = &bc->response_headers;
    hash_init.max_size = 64; // TODO: use a better size

    if (ngx_hash_init(&hash_init, bc->response_headers_keys.keys.elts, bc->response_headers_keys.keys.nelts) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bulk_carrier_t response_headers hash init failed");
        return NGX_ERROR;
    }

    ngx_destroy_pool(bc->mem_temp_pool);
    bc->mem_temp_pool = NULL;

    return NGX_OK;
}


int32_t
ngx_http_lua_kong_ffi_bulk_carrier_fetch(ngx_http_request_t *r,
    bulk_carrier_t *bc,
    unsigned char *buf,
    uint32_t buf_len,
    uint32_t **request_header_fetch_info,
    uint32_t **response_header_fetch_info)
{
    ngx_hash_t *request_headers = &bc->request_headers;
    ngx_hash_t *response_headers = &bc->response_headers;
    ngx_uint_t request_headers_count = bc->request_headers_count;
    ngx_uint_t response_headers_count = bc->response_headers_count;
    uint32_t *request_header_info = bc->request_header_fetch_info;
    uint32_t *response_header_info = bc->response_header_fetch_info;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_str_t *hdr_key, *hdr_val;
    ngx_uint_t i, hash_key;
    uint32_t buf_offset = 0, req_hdrs_info_off = 0, resp_hdrs_info_off = 0, hash_val;
    size_t hdr_key_lowercase_buf_len = 128;
    u_char* hdr_key_lowercase_buf = ngx_pcalloc(r->pool, hdr_key_lowercase_buf_len);

    part = &r->headers_in.headers.part;
    header = part->elts;

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

        if (hdr_key->len > hdr_key_lowercase_buf_len) {
            hdr_key_lowercase_buf_len = hdr_key->len * 1.2;
            hdr_key_lowercase_buf = ngx_pcalloc(r->pool, hdr_key_lowercase_buf_len);
            if (hdr_key_lowercase_buf == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for header key lowercase buffer");
                return NGX_ERROR;
            }
        }

        ngx_strlow(hdr_key_lowercase_buf, hdr_key->data, hdr_key->len);

        hash_key = HTTP_HEADER_HASH_FUNC(hdr_key_lowercase_buf, hdr_key->len);

        if (!(hash_val = ngx_hash_find(request_headers, hash_key, hdr_key_lowercase_buf, hdr_key->len))) {
            continue;
        }

        if (buf_offset + hdr_val->len >= buf_len) {
            // buffer too small
            return NGX_AGAIN;
        }

        request_header_info[req_hdrs_info_off++] = hash_val;
        request_header_info[req_hdrs_info_off++] = hdr_val->len;
        ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
        buf_offset += hdr_val->len;

        if (req_hdrs_info_off / 2 == request_headers_count) {
            // all request headers fetched
            break;
        }
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

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

        if (hdr_key->len > hdr_key_lowercase_buf_len) {
            hdr_key_lowercase_buf_len = hdr_key->len * 1.2;
            hdr_key_lowercase_buf = ngx_pcalloc(r->pool, hdr_key_lowercase_buf_len);
            if (hdr_key_lowercase_buf == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for header key lowercase buffer");
                return NGX_ERROR;
            }
        }

        ngx_strlow(hdr_key_lowercase_buf, hdr_key->data, hdr_key->len);

        hash_key = HTTP_HEADER_HASH_FUNC(hdr_key_lowercase_buf, hdr_key->len);

        if (!(hash_val = ngx_hash_find(response_headers, hash_key, hdr_key_lowercase_buf, hdr_key->len))) {
            continue;
        }

        if (buf_offset + hdr_val->len >= buf_len) {
            // buffer too small
            return NGX_AGAIN;
        }

        response_header_info[resp_hdrs_info_off++] = hash_val;
        response_header_info[resp_hdrs_info_off++] = hdr_val->len;
        ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
        buf_offset += hdr_val->len;

        if (resp_hdrs_info_off / 2 == response_headers_count) {
            // all response headers fetched
            break;
        }
    }

    request_header_info[req_hdrs_info_off] = 0;
    response_header_info[resp_hdrs_info_off] = 0;

    *request_header_fetch_info = request_header_info;
    *response_header_fetch_info = response_header_info;

    return NGX_OK;
}
