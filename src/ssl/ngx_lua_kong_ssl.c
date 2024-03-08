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


#include "ngx_lua_kong_ssl.h"

#if (NGX_SSL)
static int ngx_lua_kong_ssl_old_sess_new_cb_index       = -1;
static int ngx_lua_kong_ssl_no_session_cache_flag_index = -1;
#endif

ngx_int_t
ngx_lua_kong_ssl_init(ngx_conf_t *cf)
{
#if (NGX_SSL)
    if (ngx_lua_kong_ssl_old_sess_new_cb_index == -1) {
        ngx_lua_kong_ssl_old_sess_new_cb_index =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_lua_kong_ssl_old_sess_new_cb_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0,
                          "kong: SSL_CTX_get_ex_new_index() for "
                          "ssl ctx failed");
            return NGX_ERROR;
        }
    }

    if (ngx_lua_kong_ssl_no_session_cache_flag_index == -1) {
        ngx_lua_kong_ssl_no_session_cache_flag_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_lua_kong_ssl_no_session_cache_flag_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0,
                          "kong: SSL_get_ex_new_index() for ssl failed");
            return NGX_ERROR;
        }
    }
#endif

    return NGX_OK;
}


#if (NGX_SSL)


static int
ngx_lua_kong_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    ngx_uint_t      flag;

    flag = (ngx_uint_t) SSL_get_ex_data(ssl_conn,
                            ngx_lua_kong_ssl_no_session_cache_flag_index);

    if (flag) {
        return 0;
    }

    return ((int (*)(SSL *ssl, SSL_SESSION *sess))
               SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn),
                   ngx_lua_kong_ssl_old_sess_new_cb_index))(ssl_conn,
                                                                 sess);
}


const char *
ngx_lua_kong_ssl_disable_session_reuse(ngx_connection_t *c)
{
    ngx_uint_t           flag;
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
                        ngx_lua_kong_ssl_no_session_cache_flag_index,
                        (void *) flag) == 0)
    {
        return "unable to disable session cache for current connection";
    }

    ctx = c->ssl->session_ctx;

    /* hook session_new_cb if not already done so */
    if (SSL_CTX_sess_get_new_cb(ctx) !=
        ngx_lua_kong_ssl_new_session)
    {
        /* save old callback */
        if (SSL_CTX_set_ex_data(ctx,
                                ngx_lua_kong_ssl_old_sess_new_cb_index,
                                SSL_CTX_sess_get_new_cb(ctx)) == 0)
        {
            return "unable to install new session hook";
        }

        /* install hook */
        SSL_CTX_sess_set_new_cb(ctx, ngx_lua_kong_ssl_new_session);
    }

    return NULL;
}


int
ngx_lua_kong_ssl_get_full_client_certificate_chain(ngx_connection_t *c,
    char *buf, size_t *buf_len)
{
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
}


void
ngx_lua_kong_ssl_set_upstream_ssl(ngx_lua_kong_ssl_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_ssl_conn_t              *sc = c->ssl->connection;
    STACK_OF(X509)              *chain;
    EVP_PKEY                    *pkey;
    X509                        *x509;
    X509_STORE                  *store;
#ifdef OPENSSL_IS_BORINGSSL
    size_t                       i;
#else
    int                          i;
#endif


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
ngx_lua_kong_ssl_x509_copy(const X509 *in)
{
    return X509_up_ref(in) == 0 ? NULL : in;
}


void
ngx_lua_kong_ssl_cleanup_cert_and_key(ngx_lua_kong_ssl_ctx_t *ctx)
{
    if (ctx->upstream_client_certificate_chain != NULL) {
        sk_X509_pop_free(ctx->upstream_client_certificate_chain, X509_free);
        EVP_PKEY_free(ctx->upstream_client_private_key);
    }
}


void
ngx_lua_kong_ssl_cleanup_trusted_store(ngx_lua_kong_ssl_ctx_t *ctx)
{
    if (ctx->upstream_trusted_store != NULL) {
        X509_STORE_free(ctx->upstream_trusted_store);
    }
}


void
ngx_lua_kong_ssl_cleanup(ngx_lua_kong_ssl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ngx_lua_kong_ssl_cleanup_cert_and_key(ctx);

    ngx_lua_kong_ssl_cleanup_trusted_store(ctx);
}


int
ngx_lua_kong_ssl_set_upstream_client_cert_and_key(ngx_lua_kong_ssl_ctx_t *ctx,
    void *_chain, void *_key)
{
    STACK_OF(X509)              *chain = _chain;
    EVP_PKEY                    *key = _key;
    STACK_OF(X509)              *new_chain;

    if (chain == NULL || key == NULL) {
        return NGX_ERROR;
    }

    if (ctx == NULL) {
        return NGX_ERROR;

    } else if (ctx->upstream_client_certificate_chain != NULL) {
        ngx_lua_kong_ssl_cleanup_cert_and_key(ctx);

        ctx->upstream_client_certificate_chain = NULL;
        ctx->upstream_client_private_key = NULL;
    }

    if (EVP_PKEY_up_ref(key) == 0) {
        goto failed;
    }

    new_chain = sk_X509_deep_copy(chain, ngx_lua_kong_ssl_x509_copy,
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
ngx_lua_kong_ssl_set_upstream_ssl_trusted_store(ngx_lua_kong_ssl_ctx_t *ctx,
    void *_store)
{
    X509_STORE                  *store = _store;

    if (store == NULL) {
        return NGX_ERROR;
    }

    if (ctx->upstream_trusted_store != NULL) {
        ngx_lua_kong_ssl_cleanup_trusted_store(ctx);

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


int
ngx_lua_kong_ssl_set_upstream_ssl_verify(ngx_lua_kong_ssl_ctx_t *ctx,
    int verify)
{
    ctx->upstream_ssl_verify_set = 1;
    ctx->upstream_ssl_verify = verify;

    return NGX_OK;
}


int
ngx_lua_kong_ssl_set_upstream_ssl_verify_depth(ngx_lua_kong_ssl_ctx_t *ctx,
    int depth)
{
    ctx->upstream_ssl_verify_depth_set = 1;
    ctx->upstream_ssl_verify_depth = depth;

    return NGX_OK;
}


ngx_flag_t
ngx_lua_kong_ssl_get_upstream_ssl_verify(ngx_lua_kong_ssl_ctx_t *ctx,
    ngx_flag_t proxy_ssl_verify)
{
    /*
     * if upstream_ssl_verify is not set,
     * use the default Nginx proxy_ssl_verify value
     */
    if (!ctx->upstream_ssl_verify_set) {
        return proxy_ssl_verify;
    }

    return ctx->upstream_ssl_verify;
}
#endif