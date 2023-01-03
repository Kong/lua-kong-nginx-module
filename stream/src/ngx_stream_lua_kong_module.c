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


#include "ngx_stream_lua_kong_module.h"


static void* ngx_stream_lua_kong_create_srv_conf(ngx_conf_t* cf);
static ngx_int_t ngx_stream_lua_kong_init(ngx_conf_t *cf);

static ngx_stream_module_t ngx_stream_lua_kong_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_lua_kong_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_lua_kong_create_srv_conf,   /* create server configuration */
    NULL                                   /* merge server configuration */
};


static ngx_command_t ngx_stream_lua_kong_commands[] = {

    { ngx_string("lua_kong_set_static_tag"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_kong_srv_conf_t, tag),
      NULL },

    ngx_null_command
};


ngx_module_t ngx_stream_lua_kong_module = {
    NGX_MODULE_V1,
    &ngx_stream_lua_kong_module_ctx,   /* module context */
    ngx_stream_lua_kong_commands,      /* module directives */
    NGX_STREAM_MODULE,                 /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_lua_kong_init(ngx_conf_t *cf)
{
    return ngx_lua_kong_ssl_init(cf);
}



static void
ngx_stream_lua_kong_cleanup(void *data)
{
    ngx_stream_lua_kong_ctx_t     *ctx = data;

    ngx_lua_kong_ssl_cleanup(&ctx->ssl_ctx);
}


ngx_stream_lua_kong_ctx_t *
ngx_stream_lua_kong_get_module_ctx(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_ctx_t       *ctx;
    ngx_pool_cleanup_t              *cln;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_kong_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_stream_lua_kong_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        cln->data = ctx;
        cln->handler = ngx_stream_lua_kong_cleanup;

        ngx_stream_lua_set_ctx(r, ctx, ngx_stream_lua_kong_module);
    }

    return ctx;
}

static void *
ngx_stream_lua_kong_create_srv_conf(ngx_conf_t* cf)
{
    ngx_stream_lua_kong_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_lua_kong_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


ngx_str_t *
ngx_stream_lua_kong_ffi_get_static_tag(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_srv_conf_t *scf;

    scf = ngx_stream_get_module_srv_conf(
            r->session, ngx_stream_lua_kong_module);

    return &scf->tag;
}


int
ngx_stream_lua_kong_ffi_get_full_client_certificate_chain(ngx_stream_lua_request_t *r,
    char *buf, size_t *buf_len)
{
#if (NGX_SSL)
    return ngx_lua_kong_ssl_get_full_client_certificate_chain(r->connection, buf, buf_len);
#else
    return NGX_ABORT;
#endif
}


/*
 * disables session reuse for the current TLS connection, must be called
 * in ssl_certby_lua* phase
 */

const char *
ngx_stream_lua_kong_ffi_disable_session_reuse(ngx_stream_lua_request_t *r)
{
#if (NGX_SSL)
    return ngx_lua_kong_ssl_disable_session_reuse(r->connection);
#else
    return "TLS support is not enabled in Nginx build"
#endif
}


#if (NGX_STREAM_SSL)

int
ngx_stream_lua_kong_ffi_set_upstream_ssl_verify(ngx_stream_lua_request_t *r,
    int verify)
{
    ngx_stream_lua_kong_ctx_t    *ctx;

    ctx = ngx_stream_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_verify(&ctx->ssl_ctx, verify);
}


int
ngx_stream_lua_kong_ffi_set_upstream_ssl_verify_depth(ngx_stream_lua_request_t *r,
    int depth)
{
    ngx_stream_lua_kong_ctx_t   *ctx;

    ctx = ngx_stream_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_verify_depth(&ctx->ssl_ctx, depth);
}


int
ngx_stream_lua_kong_ffi_proxy_ssl_disable(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_ctx_t       *ctx;

    ctx = ngx_stream_lua_kong_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->proxy_ssl_disable = 1;

    return NGX_OK;
}


ngx_uint_t
ngx_stream_lua_kong_get_proxy_ssl_disable(ngx_stream_session_t *s)
{
    ngx_stream_lua_kong_ctx_t       *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);

    return ctx == NULL ? 0 : ctx->proxy_ssl_disable;
}


/*
 * called by ngx_stream_upstream_ssl_init_connection right after
 * ngx_ssl_create_connection to override any parameters in the
 * ngx_ssl_conn_t before handshake occurs
 *
 * c->ssl is guaranteed to be present and valid
 */

void
ngx_stream_lua_kong_set_upstream_ssl(ngx_stream_session_t *s, ngx_connection_t *c)
{
    ngx_stream_lua_kong_ctx_t     *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "skip overriding upstream SSL configuration, "
                       "module ctx not set");
        return;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl(&ctx->ssl_ctx, c);
}


int
ngx_stream_lua_kong_ffi_set_upstream_client_cert_and_key(ngx_stream_lua_request_t *r,
    void *_chain, void *_key)
{
    ngx_stream_lua_kong_ctx_t   *ctx;

    ctx = ngx_stream_lua_kong_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_client_cert_and_key(&ctx->ssl_ctx, _chain, _key);
}


int
ngx_stream_lua_kong_ffi_set_upstream_ssl_trusted_store(ngx_stream_lua_request_t *r,
    void *_store)
{
    X509_STORE                  *store = _store;
    ngx_stream_lua_kong_ctx_t   *ctx;

    if (store == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_stream_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_set_upstream_ssl_trusted_store(&ctx->ssl_ctx,_store);
}


ngx_flag_t
ngx_stream_lua_kong_get_upstream_ssl_verify(ngx_stream_session_t *s,
    ngx_flag_t proxy_ssl_verify)
{
    ngx_stream_lua_kong_ctx_t   *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);
    if (ctx == NULL) {
        return proxy_ssl_verify;
    }

    return ngx_lua_kong_ssl_get_upstream_ssl_verify(&ctx->ssl_ctx, proxy_ssl_verify);
}
#endif


// macOS with M1 fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205

int
ngx_stream_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s)
{
    return ngx_stream_lua_ffi_shdict_get(s->zone, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->user_flags, s->get_stale,
        s->is_stale, s->errmsg);
}


int
ngx_stream_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s)
{
    return ngx_stream_lua_ffi_shdict_store(s->zone, s->op, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->exptime, s->user_flags, s->errmsg,
        s->forcible);
}


int
ngx_stream_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s)
{
    return ngx_stream_lua_ffi_shdict_incr(s->zone, s->key, s->key_len, s->num_value,
        s->errmsg, s->has_init, s->init, s->init_ttl, s->forcible);
}

// macOS with M1 fixes end
