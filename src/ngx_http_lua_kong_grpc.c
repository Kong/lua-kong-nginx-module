/**
 * Copyright 2019-2020 Kong Inc.

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


int
ngx_http_lua_kong_ffi_set_grpc_authority(ngx_http_request_t *r,
    const char *buf, size_t buf_len)
{
    u_char                      *host;
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    host = ngx_palloc(r->pool, buf_len);
    if (host == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(host, buf, buf_len);

    ctx->grpc_authority.data = host;
    ctx->grpc_authority.len = buf_len;

    return NGX_OK;
}


