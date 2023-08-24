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


#ifndef _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ssl/ngx_lua_kong_ssl.h"

typedef struct {
    ngx_lua_kong_ssl_ctx_t   ssl_ctx;
    ngx_str_t                grpc_authority;
} ngx_http_lua_kong_ctx_t;


typedef struct {
    ngx_str_t                  tag;
    ngx_http_complex_value_t  *error_log_append;
} ngx_http_lua_kong_loc_conf_t;


#ifdef NGX_LUA_USE_ASSERT
#include <assert.h>
#   define ngx_http_lua_kong_assert(a)  assert(a)
#else
#   define ngx_http_lua_kong_assert(a)
#endif

extern ngx_module_t ngx_http_lua_kong_module;

ngx_http_lua_kong_ctx_t *ngx_http_lua_kong_get_module_ctx(
    ngx_http_request_t *r);

#endif /* _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_ */
