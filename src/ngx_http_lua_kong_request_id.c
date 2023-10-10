/**
 * Copyright 2019-2023 Kong Inc.

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


#define KONG_REQUEST_ID_MAX_LEN     32
#define KONG_REQUEST_ID_FORMAT      "%08x%08x%08x%08x"


#if 0
static void
ngx_http_lua_kong_hex_string(uint32_t x, char *s)
{
    static const char digits[513] =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    int i = 3;
    while (i >= 0) {
        int pos = (x & 0xFF) * 2;
        char ch = digits[pos];
        s[i * 2] = ch;

        ch = digits[pos + 1];
        s[i * 2 + 1] = ch;

        x >>= 8;
        i -= 1;
    }
}
#endif


static ngx_int_t
ngx_http_lua_kong_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

    id = ngx_pnalloc(r->pool, KONG_REQUEST_ID_MAX_LEN);
    if (id == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = KONG_REQUEST_ID_MAX_LEN;
    v->data = id;

    ngx_sprintf(id, KONG_REQUEST_ID_FORMAT,
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

    return NGX_OK;
}


static ngx_http_variable_t  ngx_http_lua_kong_variables[] = {

    { ngx_string("kong_request_id"), NULL,
      ngx_http_lua_kong_variable_request_id,
      0, 0, 0 },

      ngx_http_null_variable
};


ngx_int_t
ngx_http_lua_kong_add_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *cv, *v;

    for (cv = ngx_http_lua_kong_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


