/**
 * Copyright 2019-2021 Kong Inc.

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


#if 1

#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_contentby.h"

enum {
    SOCKET_OP_CONNECT,
    SOCKET_OP_READ,
    SOCKET_OP_WRITE,
    SOCKET_OP_RESUME_CONN,
};

void ngx_http_lua_coctx_cleanup(void *data);
void ngx_http_lua_socket_tcp_handler(ngx_event_t *ev);
void ngx_http_lua_socket_handle_conn_success(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u);
int ngx_http_lua_socket_conn_error_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);
void ngx_http_lua_socket_handle_conn_error(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, ngx_uint_t ft_type);

#endif

#if (NGX_HTTP_SSL)

static void ngx_http_lua_tls_handshake_handler(ngx_connection_t *c);
static int ngx_http_lua_tls_handshake_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);

static const char *
ngx_http_lua_socket_tcp_check_busy(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, unsigned int ops)
{
    if (ops & SOCKET_OP_CONNECT && u->conn_waiting) {
        return "socket busy connecting";
    }

    if (ops & SOCKET_OP_READ && u->read_waiting) {
        return "socket busy reading";
    }

    if (ops & SOCKET_OP_WRITE
        && (u->write_waiting
            || (u->raw_downstream
                && (r->connection->buffered & NGX_HTTP_LOWLEVEL_BUFFERED))))
    {
        return "socket busy writing";
    }

    return NULL;
}


int
ngx_http_lua_ffi_socket_tcp_tlshandshake(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, ngx_ssl_session_t *sess,
    int enable_session_reuse, ngx_str_t *server_name, int verify,
    int ocsp_status_req, STACK_OF(X509) *chain, EVP_PKEY *pkey,
    const char **errmsg)
{
    ngx_int_t                rc, i;
    ngx_connection_t        *c;
    ngx_http_lua_ctx_t      *ctx;
    ngx_http_lua_co_ctx_t   *coctx;
    const char              *busy_rc;
    ngx_ssl_conn_t          *ssl_conn;
    X509                    *x509;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua tcp socket tls handshake");

    if (u == NULL
        || u->peer.connection == NULL
        || u->read_closed
        || u->write_closed)
    {
        *errmsg = "closed";
        return NGX_ERROR;
    }

    if (u->request != r) {
        *errmsg = "bad request";
        return NGX_ERROR;
    }

    busy_rc = ngx_http_lua_socket_tcp_check_busy(r, u, SOCKET_OP_CONNECT
                                                 | SOCKET_OP_READ
                                                 | SOCKET_OP_WRITE);
    if (busy_rc != NULL) {
        *errmsg = busy_rc;
        return NGX_ERROR;
    }

    if (u->raw_downstream || u->body_downstream) {
        *errmsg = "not supported for downstream sockets";
        return NGX_ERROR;
    }

    c = u->peer.connection;

    u->ssl_session_reuse = 1;

    if (c->ssl && c->ssl->handshaked) {
        if (sess != NULL) {
            return NGX_DONE;
        }

        u->ssl_session_reuse = enable_session_reuse;

        (void) ngx_http_lua_tls_handshake_retval_handler(r, u, NULL);

        return NGX_OK;
    }

    if (ngx_ssl_create_connection(u->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        *errmsg = "failed to create ssl connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    coctx = ctx->cur_co_ctx;

    c->sendfile = 0;

    if (sess != NULL) {
        if (ngx_ssl_set_session(c, sess) != NGX_OK) {
            *errmsg = "tls set session failed";
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "lua tls set session: %p", sess);

    } else {
        u->ssl_session_reuse = enable_session_reuse;
    }

    if (chain != NULL) {
        ngx_http_lua_assert(pkey != NULL); /* ensured by resty.core */

        if (sk_X509_num(chain) < 1) {
            ERR_clear_error();
            *errmsg = "invalid client certificate chain";
            return NGX_ERROR;
        }

        x509 = sk_X509_value(chain, 0);
        if (x509 == NULL) {
            ERR_clear_error();
            *errmsg = "tls fetch client certificate from chain failed";
            return NGX_ERROR;
        }

        if (SSL_use_certificate(ssl_conn, x509) == 0) {
            ERR_clear_error();
            *errmsg = "tls set client certificate failed";
            return NGX_ERROR;
        }

        /* read rest of the chain */

        for (i = 1; i < sk_X509_num(chain); i++) {
            x509 = sk_X509_value(chain, i);
            if (x509 == NULL) {
                ERR_clear_error();
                *errmsg = "tls fetch client intermediate certificate from "
                          "chain failed";
                return NGX_ERROR;
            }

            if (SSL_add1_chain_cert(ssl_conn, x509) == 0) {
                ERR_clear_error();
                *errmsg = "tls set client intermediate certificate failed";
                return NGX_ERROR;
            }
        }

        if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
            ERR_clear_error();
            *errmsg = "tls set client private key failed";
            return NGX_ERROR;
        }
    }

    if (server_name != NULL && server_name->data != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua tls server name: \"%V\"", server_name);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (SSL_set_tlsext_host_name(c->ssl->connection,
                                     (char *) server_name->data)
            == 0)
        {
            *errmsg = "SSL_set_tlsext_host_name failed";
            return NGX_ERROR;
        }

#else
        *errmsg = "no TLS extension support";
        return NGX_ERROR;
#endif
    }

    u->ssl_verify = verify;

    if (ocsp_status_req) {
#ifdef NGX_HTTP_LUA_USE_OCSP
        SSL_set_tlsext_status_type(c->ssl->connection,
                                   TLSEXT_STATUSTYPE_ocsp);

#else
        *errmsg = "no OCSP support";
        return NGX_ERROR;
#endif
    }

    if (server_name->len == 0) {
        u->ssl_name.len = 0;

    } else {
        if (u->ssl_name.data) {
            /* buffer already allocated */

            if (u->ssl_name.len >= server_name->len) {
                /* reuse it */
                ngx_memcpy(u->ssl_name.data, server_name->data,
                           server_name->len);
                u->ssl_name.len = server_name->len;

            } else {
                ngx_free(u->ssl_name.data);
                goto new_ssl_name;
            }

        } else {

new_ssl_name:

            u->ssl_name.data = ngx_alloc(server_name->len, ngx_cycle->log);
            if (u->ssl_name.data == NULL) {
                u->ssl_name.len = 0;
                *errmsg = "no memory";
                return NGX_ERROR;
            }

            ngx_memcpy(u->ssl_name.data, server_name->data, server_name->len);
            u->ssl_name.len = server_name->len;
        }
    }

    u->write_co_ctx = coctx;

#if 0
#ifdef NGX_HTTP_LUA_USE_OCSP
    SSL_set_tlsext_status_type(c->ssl->connection, TLSEXT_STATUSTYPE_ocsp);
#endif
#endif

    rc = ngx_ssl_handshake(c);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_ssl_handshake returned: %d", rc);

    if (rc == NGX_AGAIN) {
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_add_timer(c->read, u->connect_timeout);

        u->conn_waiting = 1;
        u->write_prepare_retvals = ngx_http_lua_tls_handshake_retval_handler;

        ngx_http_lua_cleanup_pending_operation(coctx);
        coctx->cleanup = ngx_http_lua_coctx_cleanup;
        coctx->data = u;

        c->ssl->handler = ngx_http_lua_tls_handshake_handler;

        if (ctx->entered_content_phase) {
            r->write_event_handler = ngx_http_lua_content_wev_handler;

        } else {
            r->write_event_handler = ngx_http_core_run_phases;
        }

        return NGX_AGAIN;
    }

    ngx_http_lua_tls_handshake_handler(c);

    if (rc == NGX_ERROR) {
        *errmsg = u->error_ret;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_lua_tls_handshake_handler(ngx_connection_t *c)
{
    int                          waiting;
    ngx_int_t                    rc;
    ngx_connection_t            *dc;  /* downstream connection */
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_loc_conf_t     *llcf;

    ngx_http_lua_socket_tcp_upstream_t  *u;

    u = c->data;
    r = u->request;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    c->write->handler = ngx_http_lua_socket_tcp_handler;
    c->read->handler = ngx_http_lua_socket_tcp_handler;

    waiting = u->conn_waiting;

    dc = r->connection;

    if (c->read->timedout) {
        u->error_ret = "timeout";
        goto failed;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->ssl->handshaked) {
        if (u->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                u->error_ret = X509_verify_cert_error_string(rc);
                u->openssl_error_code_ret = rc;

                llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
                if (llcf->log_socket_errors) {
                    ngx_log_error(NGX_LOG_ERR, dc->log, 0, "lua tls "
                                  "certificate verify error: (%d: %s)",
                                  rc, u->error_ret);
                }

                goto failed;
            }

#if (nginx_version >= 1007000)

            if (u->ssl_name.len
                && ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK)
            {
                u->error_ret = "certificate host mismatch";

                llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
                if (llcf->log_socket_errors) {
                    ngx_log_error(NGX_LOG_ERR, dc->log, 0, "lua tls "
                                  "certificate does not match host \"%V\"",
                                  &u->ssl_name);
                }

                goto failed;
            }

#endif
        }

        if (waiting) {
            ngx_http_lua_socket_handle_conn_success(r, u);

        } else {
            (void) ngx_http_lua_tls_handshake_retval_handler(r, u, NULL);
        }

        if (waiting) {
            ngx_http_run_posted_requests(dc);
        }

        return;
    }

    u->error_ret = "handshake failed";

failed:

    if (waiting) {
        u->write_prepare_retvals =
            ngx_http_lua_socket_conn_error_retval_handler;
        ngx_http_lua_socket_handle_conn_error(r, u, NGX_HTTP_LUA_SOCKET_FT_SSL);
        ngx_http_run_posted_requests(dc);

    } else {
        u->ft_type |= NGX_HTTP_LUA_SOCKET_FT_SSL;

        (void) ngx_http_lua_socket_conn_error_retval_handler(r, u, NULL);
    }
}


int
ngx_http_lua_ffi_socket_tcp_get_tlshandshake_result(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, ngx_ssl_session_t **sess,
    const char **errmsg, int *openssl_error_code)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua cosocket get TLS handshake result for upstream: %p", u);

    if (u->error_ret != NULL) {
        *errmsg = u->error_ret;
        *openssl_error_code = u->openssl_error_code_ret;

        return NGX_ERROR;
    }

    *sess = u->ssl_session_ret;

    return NGX_OK;
}


static int
ngx_http_lua_tls_handshake_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    ngx_connection_t            *c;
    ngx_ssl_session_t           *ssl_session;

    if (!u->ssl_session_reuse) {
        return 0;
    }

    c = u->peer.connection;

    ssl_session = ngx_ssl_get_session(c);
    if (ssl_session == NULL) {
        u->ssl_session_ret = NULL;

    } else {
        u->ssl_session_ret = ssl_session;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "lua tls save session: %p", ssl_session);
    }

    return 0;
}


void
ngx_http_lua_ffi_tls_free_session(ngx_ssl_session_t *sess)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua tls free session: %p", sess);

    ngx_ssl_free_session(sess);
}


#endif  /* NGX_HTTP_SSL */
