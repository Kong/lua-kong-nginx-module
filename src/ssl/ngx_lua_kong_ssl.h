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

#ifndef _NGX_LUA_KONG_SSL_H_INCLUDED_
#define _NGX_LUA_KONG_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    STACK_OF(X509)     *upstream_client_certificate_chain;
    EVP_PKEY           *upstream_client_private_key;
    X509_STORE         *upstream_trusted_store;
    ngx_uint_t          upstream_ssl_verify_depth;
    unsigned            upstream_ssl_verify:1;
    unsigned            upstream_ssl_verify_set:1;
    unsigned            upstream_ssl_verify_depth_set:1;
} ngx_lua_kong_ssl_ctx_t;

ngx_int_t ngx_lua_kong_ssl_init(ngx_conf_t *cf);
const char *ngx_lua_kong_ssl_disable_session_reuse(ngx_connection_t *c);
int ngx_lua_kong_ssl_get_full_client_certificate_chain(ngx_connection_t *c,
    char *buf, size_t *buf_len);

void ngx_lua_kong_ssl_set_upstream_ssl(ngx_lua_kong_ssl_ctx_t *ctx, ngx_connection_t *c);
void ngx_lua_kong_ssl_cleanup(ngx_lua_kong_ssl_ctx_t *ctx);
int ngx_lua_kong_ssl_set_upstream_client_cert_and_key(ngx_lua_kong_ssl_ctx_t *ctx,
    void *_chain, void *_key);
int ngx_lua_kong_ssl_set_upstream_ssl_trusted_store(ngx_lua_kong_ssl_ctx_t *ctx,
    void *_store);
int ngx_lua_kong_ssl_set_upstream_ssl_verify(ngx_lua_kong_ssl_ctx_t *ctx,
    int verify);
int ngx_lua_kong_ssl_set_upstream_ssl_verify_depth(ngx_lua_kong_ssl_ctx_t *ctx,
    int depth);
ngx_flag_t ngx_lua_kong_ssl_get_upstream_ssl_verify(ngx_lua_kong_ssl_ctx_t *ctx,
    ngx_flag_t proxy_ssl_verify);

#endif /* _NGX_LUA_KONG_SSL_H_INCLUDED_ */
