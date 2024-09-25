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
#include "ngx_http_lua_ssl.h"

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

ngx_flag_t
ngx_lua_kong_ssl_enable_http2_alpn(ngx_ssl_connection_t *ssl,
    ngx_flag_t enable_http2)
{
    ngx_http_lua_ssl_ctx_t *cctx;

    cctx = ngx_http_lua_ssl_get_ctx(ssl->connection);
    if (cctx->disable_http2_alpn) {
        return 0;
    }

    return enable_http2;
}

int
ngx_http_lua_ffi_ssl_disable_http2_alpn(ngx_http_request_t *r, char **err)
{
    ngx_ssl_conn_t    *ssl_conn;
    ngx_http_lua_ssl_ctx_t *cctx;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    cctx = ngx_http_lua_ssl_get_ctx(ssl_conn);
    if (cctx == NULL) {
        *err = "bad lua context";
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "lua ssl disable http2");
    cctx->disable_http2_alpn = 1;

    return NGX_OK;
}

#endif


