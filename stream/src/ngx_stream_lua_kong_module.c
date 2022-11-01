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


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_lua_api.h>
#include "ngx_stream_lua_kong_module.h"


static void* ngx_stream_lua_kong_create_srv_conf(ngx_conf_t* cf);
static void ngx_stream_lua_kong_cleanup_cert_and_key(ngx_stream_lua_kong_ctx_t *ctx);
static void ngx_stream_lua_kong_cleanup_trusted_store(ngx_stream_lua_kong_ctx_t *ctx);
static int ngx_stream_lua_kong_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess);
static ngx_int_t ngx_stream_lua_kong_init(ngx_conf_t *cf);

#if (NGX_SSL)
static int ngx_stream_lua_kong_verify_callback(int ok, X509_STORE_CTX *x509_store);
#endif

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


#if (NGX_SSL)
static int ngx_stream_lua_kong_ssl_old_sess_new_cb_index       = -1;
static int ngx_stream_lua_kong_ssl_no_session_cache_flag_index = -1;
#endif

ngx_int_t
ngx_stream_lua_kong_ssl_init(ngx_conf_t *cf)
{
#if (NGX_SSL)
    if (ngx_stream_lua_kong_ssl_old_sess_new_cb_index == -1) {
        ngx_stream_lua_kong_ssl_old_sess_new_cb_index =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_stream_lua_kong_ssl_old_sess_new_cb_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0,
                          "kong: SSL_CTX_get_ex_new_index() for "
                          "ssl ctx failed");
            return NGX_ERROR;
        }
    }

    if (ngx_stream_lua_kong_ssl_no_session_cache_flag_index == -1) {
        ngx_stream_lua_kong_ssl_no_session_cache_flag_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_stream_lua_kong_ssl_no_session_cache_flag_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0,
                          "kong: SSL_get_ex_new_index() for ssl failed");
            return NGX_ERROR;
        }
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_lua_kong_init(ngx_conf_t *cf)
{
    return ngx_stream_lua_kong_ssl_init(cf);
}



static void
ngx_stream_lua_kong_cleanup(void *data)
{
    ngx_stream_lua_kong_ctx_t     *ctx = data;

    ngx_stream_lua_kong_cleanup_cert_and_key(ctx);

    ngx_stream_lua_kong_cleanup_trusted_store(ctx);
}


ngx_stream_lua_kong_ctx_t *
ngx_stream_lua_kong_get_module_ctx(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_ctx_t     *ctx;
    ngx_pool_cleanup_t          *cln;

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
    ngx_connection_t    *c = r->connection;
    ngx_ssl_conn_t      *sc;
    STACK_OF(X509)      *chain;
    X509                *cert;
    int                  i, n;
    size_t               len;
    BIO                 *bio;
    int                  ret;

    if (c->ssl == NULL) {
        return NGX_ABORT;
    }

    sc = c->ssl->connection;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        /* client did not present a certificate or server did not request it */
        return NGX_DECLINED;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");

        X509_free(cert);
        ret = NGX_ERROR;
        goto done;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");

        X509_free(cert);
        ret = NGX_ERROR;
        goto done;
    }

    X509_free(cert);

    chain = SSL_get_peer_cert_chain(sc);
    if (chain == NULL) {
        ret = NGX_DECLINED;
        goto done;
    }

    n = sk_X509_num(chain);
    for (i = 0; i < n; i++) {
        cert = sk_X509_value(chain, i);

        if (PEM_write_bio_X509(bio, cert) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "PEM_write_bio_X509() failed");

            ret = NGX_ERROR;
            goto done;
        }
    }

    len = BIO_pending(bio);
    if (len > *buf_len) {
        *buf_len = len;

        ret = NGX_AGAIN;
        goto done;
    }

    BIO_read(bio, buf, len);
    *buf_len = len;

    ret = NGX_OK;

done:

    BIO_free(bio);

    return ret;

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
#if (NGX_STREAM_SSL)
    ngx_uint_t           flag;
    ngx_connection_t    *c = r->connection;
    ngx_ssl_conn_t      *sc;
    SSL_CTX             *ctx;

    if (c->ssl == NULL) {
        return "server does not have TLS enabled";
    }

    sc = c->ssl->connection;

    /* the following disables session ticket for the current connection */
    SSL_set_options(sc, SSL_OP_NO_TICKET);

    /* the following disables session cache for the current connection
     * note that we are using the pointer storage to store a flag value to
     * avoid having to do memory allocations. since the pointer is never
     * dereferenced this is completely safe to do */
    flag = 1;

    if (SSL_set_ex_data(sc,
                        ngx_stream_lua_kong_ssl_no_session_cache_flag_index,
                        (void *) flag) == 0)
    {
        return "unable to disable session cache for current connection";
    }

    ctx = c->ssl->session_ctx;

    /* hook session_new_cb if not already done so */
    if (SSL_CTX_sess_get_new_cb(ctx) !=
        ngx_stream_lua_kong_new_session)
    {
        /* save old callback */
        if (SSL_CTX_set_ex_data(ctx,
                                ngx_stream_lua_kong_ssl_old_sess_new_cb_index,
                                SSL_CTX_sess_get_new_cb(ctx)) == 0)
        {
            return "unable to install new session hook";
        }

        /* install hook */
        SSL_CTX_sess_set_new_cb(ctx, ngx_stream_lua_kong_new_session);
    }

    return NULL;

#else
    return "TLS support is not enabled in Nginx build"
#endif
}


/*
 * request downstream to present a client certificate during TLS handshake,
 * but does not validate it
 *
 * this is roughly equivalent to setting ssl_verify_client to optional_no_ca
 *
 * on success, NULL is returned, otherwise a static string indicating the
 * failure reason is returned
 */

const char *
ngx_stream_lua_kong_ffi_request_client_certificate(ngx_stream_lua_request_t *r)
{
#if (NGX_SSL)
    ngx_connection_t    *c = r->connection;
    ngx_ssl_conn_t      *sc;

    if (c->ssl == NULL) {
        return "server does not have TLS enabled";
    }

    sc = c->ssl->connection;

    SSL_set_verify(sc, SSL_VERIFY_PEER, ngx_stream_lua_kong_verify_callback);

    return NULL;

#else
    return "TLS support is not enabled in Nginx build"
#endif
}


int
ngx_stream_lua_kong_ffi_set_upstream_ssl_verify(ngx_stream_lua_request_t *r,
    int verify)
{
    ngx_stream_lua_kong_ctx_t    *ctx;

    ctx = ngx_stream_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->upstream_ssl_verify_set = 1;
    ctx->upstream_ssl_verify = verify;

    return NGX_OK;
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

    ctx->upstream_ssl_verify_depth_set = 1;
    ctx->upstream_ssl_verify_depth = depth;

    return NGX_OK;
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


#if (NGX_STREAM_SSL)


static int
ngx_stream_lua_kong_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    ngx_uint_t      flag;

    flag = (ngx_uint_t) SSL_get_ex_data(ssl_conn,
                            ngx_stream_lua_kong_ssl_no_session_cache_flag_index);

    if (flag) {
        return 0;
    }

    return ((int (*)(SSL *ssl, SSL_SESSION *sess))
               SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn),
                   ngx_stream_lua_kong_ssl_old_sess_new_cb_index))(ssl_conn,
                                                                 sess);
}


static int
ngx_stream_lua_kong_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
    /* similar to ngx_ssl_verify_callback, always allow handshake
     * to conclude before deciding the validity of client certificate */
    return 1;
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
    ngx_ssl_conn_t              *sc = c->ssl->connection;
    ngx_stream_lua_kong_ctx_t     *ctx;
    STACK_OF(X509)              *chain;
    EVP_PKEY                    *pkey;
    X509                        *x509;
    X509_STORE                  *store;
#ifdef OPENSSL_IS_BORINGSSL
    size_t                       i;
#else
    int                          i;
#endif

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "skip overriding upstream SSL configuration, "
                       "module ctx not set");
        return;
    }

    if (ctx->upstream_client_certificate_chain != NULL) {     
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "overriding upstream SSL client cert and key");

        chain = ctx->upstream_client_certificate_chain;
        pkey = ctx->upstream_client_private_key;

        if (sk_X509_num(chain) < 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "invalid client certificate chain provided while "
                          "handshaking with upstream");
            goto failed;
        }

        x509 = sk_X509_value(chain, 0);
        if (x509 == NULL) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "sk_X509_value() failed");
            goto failed;
        }

        if (SSL_use_certificate(sc, x509) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "SSL_use_certificate() failed");
            goto failed;
        }

        /* read rest of the chain */

        for (i = 1; i < sk_X509_num(chain); i++) {
            x509 = sk_X509_value(chain, i);
            if (x509 == NULL) {
                ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                              "sk_X509_value() failed");
                goto failed;
            }

            if (SSL_add1_chain_cert(sc, x509) == 0) {
                ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                              "SSL_add1_chain_cert() failed");
                goto failed;
            }
        }

        if (SSL_use_PrivateKey(sc, pkey) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "SSL_use_PrivateKey() failed");
            goto failed;
        }
    }

    if (ctx->upstream_trusted_store != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "overriding upstream SSL trusted store");
        store = ctx->upstream_trusted_store;

        if (SSL_set1_verify_cert_store(sc, store) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "SSL_set1_verify_cert_store() failed");
            goto failed;
        }
    }

    if (ctx->upstream_ssl_verify_depth_set) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "overriding upstream SSL verify depth");
        SSL_set_verify_depth(sc, ctx->upstream_ssl_verify_depth);
    }


    return;

failed:

    ERR_clear_error();
}


static X509 *
ngx_stream_lua_kong_x509_copy(X509 *in)
{
    return X509_up_ref(in) == 0 ? NULL : in;
}


void
ngx_stream_lua_kong_cleanup_cert_and_key(ngx_stream_lua_kong_ctx_t *ctx)
{
    if (ctx->upstream_client_certificate_chain != NULL) {
        sk_X509_pop_free(ctx->upstream_client_certificate_chain, X509_free);
        EVP_PKEY_free(ctx->upstream_client_private_key);
    }
}


void
ngx_stream_lua_kong_cleanup_trusted_store(ngx_stream_lua_kong_ctx_t *ctx)
{
    if (ctx->upstream_trusted_store != NULL) {
        X509_STORE_free(ctx->upstream_trusted_store);
    }
}



int
ngx_stream_lua_kong_ffi_set_upstream_client_cert_and_key(ngx_stream_lua_request_t *r,
    void *_chain, void *_key)
{
    STACK_OF(X509)              *chain = _chain;
    EVP_PKEY                    *key = _key;
    STACK_OF(X509)              *new_chain;
    ngx_stream_lua_kong_ctx_t   *ctx;
    if (chain == NULL || key == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_stream_lua_kong_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;

    } else if (ctx->upstream_client_certificate_chain != NULL) {
        ngx_stream_lua_kong_cleanup_cert_and_key(ctx);

        ctx->upstream_client_certificate_chain = NULL;
        ctx->upstream_client_private_key = NULL;
    }

    if (EVP_PKEY_up_ref(key) == 0) {
        goto failed;
    }

    new_chain = sk_X509_deep_copy(chain, ngx_stream_lua_kong_x509_copy,
                                  X509_free);
    if (new_chain == NULL) {
        EVP_PKEY_free(key);
        goto failed;
    }

    ctx->upstream_client_certificate_chain = new_chain;
    ctx->upstream_client_private_key = key;

    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;
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

    } else if (ctx->upstream_trusted_store != NULL) {
        ngx_stream_lua_kong_cleanup_trusted_store(ctx);

        ctx->upstream_trusted_store = NULL;
    }

    if (X509_STORE_up_ref(store) == 0) {
        goto failed;
    }

    ctx->upstream_trusted_store = store;

    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;
}


ngx_flag_t
ngx_stream_lua_kong_get_upstream_ssl_verify(ngx_stream_session_t *s,
    ngx_flag_t proxy_ssl_verify)
{
    ngx_stream_lua_kong_ctx_t   *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);

    /*
     * if upstream_ssl_verify is not set,
     * use the default Nginx proxy_ssl_verify value
     */
    if (ctx == NULL || !ctx->upstream_ssl_verify_set) {
        return proxy_ssl_verify;
    }

    return ctx->upstream_ssl_verify;
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