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
#include "ngx_http_lua_socket_tcp.h"

/*
 * disables session reuse for the current TLS connection, must be called
 * in ssl_certby_lua* phase
 */

const char *
ngx_http_lua_kong_ffi_disable_session_reuse(ngx_http_request_t *r)
{
#if (NGX_SSL)
    return ngx_lua_kong_ssl_disable_session_reuse(r->connection);
#else
    return "TLS support is not enabled in Nginx build";
#endif
}


int
ngx_http_lua_kong_ffi_get_full_client_certificate_chain(ngx_http_request_t *r,
    char *buf, size_t *buf_len)
{
#if (NGX_SSL)
    return ngx_lua_kong_ssl_get_full_client_certificate_chain(r->connection, buf, buf_len);
#else
    return NGX_ABORT;
#endif
}


int
ngx_http_lua_kong_ffi_get_socket_ssl(ngx_http_lua_socket_tcp_upstream_t *u, void **ssl_conn)
{
#if (NGX_SSL)
    ngx_connection_t    *uc = u->peer.connection;

    if (ssl_conn == NULL) {
        return NGX_ABORT;
    }

    if (uc && (uc->ssl) && (uc->ssl->connection)) {
        *ssl_conn = uc->ssl->connection;
        return NGX_OK;
    }

    return NGX_ERROR;

#else
    return NGX_ABORT;
#endif
}


int
ngx_http_lua_kong_ffi_get_request_ssl(ngx_http_request_t *r, void **ssl_conn)
{
#if (NGX_SSL)
    if (ssl_conn == NULL) {
        return NGX_ABORT;
    }

    ngx_connection_t *c = r->connection;

    if (c && (c->ssl) && (c->ssl->connection)) {
        *ssl_conn = c->ssl->connection;
        return NGX_OK;
    }

    return NGX_ERROR;

#else
    return NGX_ABORT;
#endif
}


#if (NGX_HTTP_SSL)

/*
 * called by ngx_http_upstream_ssl_init_connection right after
 * ngx_ssl_create_connection to override any parameters in the
 * ngx_ssl_conn_t before handshake occurs
 *
 * c->ssl is guaranteed to be present and valid
 */

void
ngx_http_lua_kong_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_kong_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "skip overriding upstream SSL configuration, "
                       "module ctx not set");
        return;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl(&ctx->ssl_ctx, c);
}


int
ngx_http_lua_kong_ffi_set_upstream_client_cert_and_key(ngx_http_request_t *r,
    void *_chain, void *_key)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_client_cert_and_key(&ctx->ssl_ctx, _chain, _key);
}


int
ngx_http_lua_kong_ffi_set_upstream_ssl_trusted_store(ngx_http_request_t *r,
    void *_store)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_trusted_store(&ctx->ssl_ctx,_store);
}


int
ngx_http_lua_kong_ffi_set_upstream_ssl_verify(ngx_http_request_t *r,
    int verify)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_verify(&ctx->ssl_ctx, verify);
}


int
ngx_http_lua_kong_ffi_set_upstream_ssl_verify_depth(ngx_http_request_t *r,
    int depth)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_verify_depth(&ctx->ssl_ctx, depth);
}


ngx_flag_t
ngx_http_lua_kong_get_upstream_ssl_verify(ngx_http_request_t *r,
    ngx_flag_t proxy_ssl_verify)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_kong_module);

    if (ctx == NULL) {
        return proxy_ssl_verify;
    }

    return ngx_lua_kong_ssl_get_upstream_ssl_verify(&ctx->ssl_ctx, proxy_ssl_verify);
}

int
ngx_http_lua_kong_ffi_set_upstream_ssl_sans_dnsnames(ngx_http_request_t *r,
    const char *input, size_t input_len)
{
    u_char                      *sans_data;
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    sans_data = ngx_palloc(r->pool, input_len);
    if (sans_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sans_data, input, input_len);

    ctx->ssl_ctx.upstream_ssl_sans_dnsnames.data = sans_data;
    ctx->ssl_ctx.upstream_ssl_sans_dnsnames.len = input_len;

    return NGX_OK;
}


ngx_str_t *
ngx_http_lua_kong_ssl_get_upstream_ssl_sans_dnsnames(ngx_http_request_t *r)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->ssl_ctx.upstream_ssl_sans_dnsnames.len == 0) {
        return NULL;
    }

    return &ctx->ssl_ctx.upstream_ssl_sans_dnsnames;
}

int
ngx_http_lua_kong_ffi_set_upstream_ssl_sans_uris(ngx_http_request_t *r,
    const char *input, size_t input_len)
{
    u_char                      *sans_data;
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    sans_data = ngx_palloc(r->pool, input_len);
    if (sans_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sans_data, input, input_len);

    ctx->ssl_ctx.upstream_ssl_sans_uris.data = sans_data;
    ctx->ssl_ctx.upstream_ssl_sans_uris.len = input_len;

    return NGX_OK;
}


ngx_str_t *
ngx_http_lua_kong_ssl_get_upstream_ssl_sans_uris(ngx_http_request_t *r)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->ssl_ctx.upstream_ssl_sans_uris.len == 0) {
        return NULL;
    }

    return &ctx->ssl_ctx.upstream_ssl_sans_uris;
}

#endif
