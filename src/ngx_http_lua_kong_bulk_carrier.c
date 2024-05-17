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

#define HTTP_HEADER_HASH_FUNC (ngx_hash_key_lc)
#define REQ_HDRS (sizeof(request_headers) / sizeof(ngx_str_t) - 1)
#define RESP_HDRS (sizeof(response_headers) / sizeof(ngx_str_t) - 1)
#define VALUE_OFFSETS ((REQ_HDRS + RESP_HDRS) * 2)


static ngx_str_t request_headers[] = {
    ngx_string("user-agent"),
    ngx_string("host"),
    ngx_null_string
};


static ngx_str_t response_headers[] = {
    ngx_string("upgrade"),
    ngx_string("connection"),
    ngx_string("content-type"),
    ngx_string("content-length"),
    ngx_string("ratelimit-limit"),
    ngx_string("ratelimit-remaining"),
    ngx_string("ratelimit-reset"),
    ngx_string("retry-after"),
    ngx_string("x-ratelimit-limit-second"),
    ngx_string("x-ratelimit-limit-minute"),
    ngx_string("x-ratelimit-limit-hour"),
    ngx_string("x-ratelimit-limit-day"),
    ngx_string("x-ratelimit-limit-month"),
    ngx_string("x-ratelimit-limit-year"),
    ngx_string("x-ratelimit-remaining-second"),
    ngx_string("x-ratelimit-remaining-minute"),
    ngx_string("x-ratelimit-remaining-hour"),
    ngx_string("x-ratelimit-remaining-day"),
    ngx_string("x-ratelimit-remaining-month"),
    ngx_string("x-ratelimit-remaining-year"),
    ngx_null_string
};

char *
ngx_http_lua_kong_bulk_carrier(ngx_conf_t *cf,
    ngx_command_t *cmd,
    void *conf)
{
    ngx_http_lua_kong_main_conf_t *lkmcf = (ngx_http_lua_kong_main_conf_t *)conf;
    ngx_hash_init_t hash_init;
    ngx_hash_keys_arrays_t req_hdr_keys, resp_hdr_keys, var_keys;

    req_hdr_keys.pool = cf->pool;
    req_hdr_keys.temp_pool = cf->temp_pool;

    resp_hdr_keys.pool = cf->pool;
    resp_hdr_keys.temp_pool = cf->temp_pool;

    var_keys.pool = cf->pool;
    var_keys.temp_pool = cf->temp_pool;

    if (ngx_hash_keys_array_init(&req_hdr_keys, NGX_HASH_SMALL) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to allocate memory for analytics req hdr bulk hash keys");
        return NGX_CONF_ERROR;
    }

    if (ngx_hash_keys_array_init(&resp_hdr_keys, NGX_HASH_SMALL) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to allocate memory for analytics resp hdr bulk hash keys");
        return NGX_CONF_ERROR;
    }

    // if (ngx_hash_keys_array_init(&var_keys, NGX_HASH_SMALL) != NGX_OK) {
    //     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to allocate memory for analytics var bulk hash keys");
    //     return NGX_CONF_ERROR;
    // }

    for (ngx_uint_t i = 0; request_headers[i].len; i++) {
        // skip i == 0, as it represents the the key is not found
        if (ngx_hash_add_key(&req_hdr_keys, &request_headers[i], i + 1, NGX_HASH_READONLY_KEY) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to add analytics req hdr bulk key to hash keys array");
            return NGX_CONF_ERROR;
        }
    }

    for (ngx_uint_t i = 0; response_headers[i].len; i++) {
        // skip i == 0, as it represents the the key is not found
        if (ngx_hash_add_key(&resp_hdr_keys, &response_headers[i], i + 1, NGX_HASH_READONLY_KEY) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to add analytics resp hdr bulk key to hash keys array");
            return NGX_CONF_ERROR;
        }
    }

    hash_init.hash = &lkmcf->analytics_req_hdr_bulk;
    hash_init.key = HTTP_HEADER_HASH_FUNC;
    hash_init.max_size = 128;
    hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash_init.name = "lua_kong_analytics_req_hdr_bulk_hash";
    hash_init.pool = cf->pool;
    hash_init.temp_pool = cf->temp_pool;

    if (ngx_hash_init(&hash_init, req_hdr_keys.keys.elts, req_hdr_keys.keys.nelts) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to initialize analytics req hdr bulk hash");
        return NGX_CONF_ERROR;
    }

    hash_init.hash = &lkmcf->analytics_resp_hdr_bulk;
    hash_init.key = HTTP_HEADER_HASH_FUNC;
    hash_init.max_size = 128;
    hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash_init.name = "lua_kong_analytics_resp_hdr_bulk_hash";
    hash_init.pool = cf->pool;
    hash_init.temp_pool = cf->temp_pool;

    if (ngx_hash_init(&hash_init, resp_hdr_keys.keys.elts, resp_hdr_keys.keys.nelts) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to initialize analytics resp hdr bulk hash");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

void
ngx_http_lua_kong_ffi_get_req_bulk_name(uint32_t index,
    uint8_t** buf,
    uint32_t* len)
{
    if (index >= REQ_HDRS) {
        *len = 0;
        return;
    }

    *buf = request_headers[index].data;
    *len = request_headers[index].len;
}

void
ngx_http_lua_kong_ffi_get_resp_bulk_name(uint32_t index,
    uint8_t** buf,
    uint32_t* len)
{
    if (index >= RESP_HDRS) {
        *len = 0;
        return;
    }

    *buf = response_headers[index].data;
    *len = response_headers[index].len;
}

uint32_t
ngx_http_lua_kong_ffi_get_value_offset_length()
{
    return VALUE_OFFSETS;
}


int64_t
ngx_http_lua_kong_ffi_fetch_analytics_bulk(ngx_http_request_t *r,
    int32_t* value_offsets,
    uint8_t* buf,
    uint32_t buf_len,
    uint32_t* req_hdrs,
    uint32_t* resp_hdrs)
{
    ngx_http_lua_kong_main_conf_t *lkmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_kong_module);
    ngx_hash_t *req_hdr_bulk = &lkmcf->analytics_req_hdr_bulk;
    ngx_hash_t *resp_hdr_bulk = &lkmcf->analytics_resp_hdr_bulk;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_str_t *hdr_key, *hdr_val;
    ngx_uint_t i, hash_key, hash_val;
    uint32_t buf_offset = 0;
    ngx_str_t req_hdr_user_agent = ngx_string("user-agent");
    ngx_str_t req_hdr_host = ngx_string("host");
    ngx_str_t resp_hdr_content_type = ngx_string("content-type");
    ngx_str_t resp_hdr_content_length = ngx_string("content-length");

    for (i = 0; i < VALUE_OFFSETS; i++) {
        value_offsets[i] = -1;
    }

    *req_hdrs = 0;
    *resp_hdrs = 0;

    hash_key = HTTP_HEADER_HASH_FUNC(req_hdr_user_agent.data, req_hdr_user_agent.len);
    if ((hash_val = ngx_hash_find(req_hdr_bulk, hash_key, req_hdr_user_agent.data, req_hdr_user_agent.len))) {
        hdr_val = &r->headers_in.user_agent->value;

        if (hdr_val->len != 0) {
            if (buf_offset + hdr_val->len >= buf_len) {
                // buffer too small
                return NGX_AGAIN;
            }

            ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
            value_offsets[hash_val - 1] = hdr_val->len;
            value_offsets[hash_val] = buf_offset;
            buf_offset += hdr_val->len;

            *req_hdrs++;
        }

    }

    hash_key = HTTP_HEADER_HASH_FUNC(req_hdr_host.data, req_hdr_host.len);
    if ((hash_val = ngx_hash_find(req_hdr_bulk, hash_key, req_hdr_host.data, req_hdr_host.len))) {
        hdr_val = &r->headers_in.host->value;

        if (hdr_val->len != 0) {
            if (buf_offset + hdr_val->len >= buf_len) {
                // buffer too small
                return NGX_AGAIN;
            }

            ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
            value_offsets[hash_val - 1] = hdr_val->len;
            value_offsets[hash_val] = buf_offset;
            buf_offset += hdr_val->len;

            *req_hdrs++;
        }
    }

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

        hash_key = HTTP_HEADER_HASH_FUNC(hdr_key->data, hdr_key->len);
        if (!(hash_val = ngx_hash_find(req_hdr_bulk, hash_key, hdr_key->data, hdr_key->len))) {
            continue;
        }

        if (buf_offset + hdr_val->len >= buf_len) {
            // buffer too small
            return NGX_AGAIN;
        }

        ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
        value_offsets[hash_val - 1] = hdr_val->len;
        value_offsets[hash_val] = buf_offset;
        *req_hdrs++;
    }

    hash_key = HTTP_HEADER_HASH_FUNC(resp_hdr_content_type.data, resp_hdr_content_type.len);
    if ((hash_val = ngx_hash_find(resp_hdr_bulk, hash_key, resp_hdr_content_type.data, resp_hdr_content_type.len))) {
        hdr_val = &r->headers_out.content_type;

        if (hdr_val->len != 0) {
            if (buf_offset + hdr_val->len >= buf_len) {
                // buffer too small
                return NGX_AGAIN;
            }

            ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
            value_offsets[hash_val - 1] = hdr_val->len;
            value_offsets[hash_val] = buf_offset;
            buf_offset += hdr_val->len;
            *resp_hdrs++;
        }
    }

    hash_key = HTTP_HEADER_HASH_FUNC(resp_hdr_content_length.data, resp_hdr_content_length.len);
    if ((hash_val = ngx_hash_find(resp_hdr_bulk, hash_key, resp_hdr_content_length.data, resp_hdr_content_length.len))) {
        hdr_val = &r->headers_out.content_length;

        if (hdr_val->len != 0) {
            if (buf_offset + hdr_val->len >= buf_len) {
                // buffer too small
                return NGX_AGAIN;
            }

            ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
            value_offsets[hash_val - 1] = hdr_val->len;
            value_offsets[hash_val] = buf_offset;
            buf_offset += hdr_val->len;
            *resp_hdrs++;
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

        hash_key = HTTP_HEADER_HASH_FUNC(hdr_key->data, hdr_key->len);
        if (!(hash_val = ngx_hash_find(resp_hdr_bulk, hash_key, hdr_key->data, hdr_key->len))) {
            continue;
        }

        if (buf_offset + hdr_val->len >= buf_len) {
            // buffer too small
            return NGX_AGAIN;
        }

        ngx_memcpy(buf + buf_offset, hdr_val->data, hdr_val->len);
        value_offsets[hash_val - 1] = hdr_val->len;
        value_offsets[hash_val] = buf_offset;
        buf_offset += hdr_val->len;
        *resp_hdrs++;
    }

    return NGX_OK;
}
