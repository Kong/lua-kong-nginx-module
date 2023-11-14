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


typedef struct {
    STACK_OF(X509)     *upstream_client_certificate_chain;
    EVP_PKEY           *upstream_client_private_key;
    X509_STORE         *upstream_trusted_store;
    ngx_uint_t          upstream_ssl_verify_depth;
    ngx_str_t           grpc_authority;
    unsigned            upstream_ssl_verify:1;
    unsigned            upstream_ssl_verify_set:1;
    unsigned            upstream_ssl_verify_depth_set:1;
    ngx_http_log_handler_pt  orig_log_handler;
} ngx_http_lua_kong_ctx_t;


typedef struct {
    ngx_int_t                request_id_var_index;
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

char *ngx_http_lua_kong_error_log_init(
    ngx_conf_t *cf);

ngx_int_t
ngx_http_lua_kong_add_vars(ngx_conf_t *cf);

#endif /* _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_ */
