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


#ifndef _NGX_HTTP_LUA_KONG_SSL_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_SSL_H_INCLUDED_


#include "ngx_http_lua_kong_common.h"


ngx_int_t
ngx_http_lua_kong_ssl_init(ngx_conf_t *cf);

void
ngx_http_lua_kong_cleanup_cert_and_key(ngx_http_lua_kong_ctx_t *ctx);

void
ngx_http_lua_kong_cleanup_trusted_store(ngx_http_lua_kong_ctx_t *ctx);


#endif /* _NGX_HTTP_LUA_KONG_SSL_H_INCLUDED_ */
