/**
 * Copyright 2019-2025 Kong Inc.

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


#define NGX_HTTP_LUA_KONG_RANDOM_COUNT         4
#define NGX_HTTP_LUA_KONG_UINT32_HEX_LEN       sizeof(uint32_t) * 2


static ngx_int_t
ngx_http_lua_kong_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char     *id;
    uint32_t    i, rnd;

    id = ngx_pnalloc(r->pool,
                     NGX_HTTP_LUA_KONG_RANDOM_COUNT *
                     NGX_HTTP_LUA_KONG_UINT32_HEX_LEN);
    if (id == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = NGX_HTTP_LUA_KONG_RANDOM_COUNT *
             NGX_HTTP_LUA_KONG_UINT32_HEX_LEN;
    v->data = id;

    for (i = 0; i < NGX_HTTP_LUA_KONG_RANDOM_COUNT; i++) {
        rnd = (uint32_t) ngx_random();
        id = ngx_hex_dump(id, (u_char *) &rnd, sizeof(uint32_t));
    }

    return NGX_OK;
}


#if (NGX_SSL)
static ngx_int_t
ngx_http_lua_kong_get_ssl_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    size_t   len;
    BIO     *bio;
    X509    *cert;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
        goto failed;
    }

    len = BIO_pending(bio);
    s->len = len;

    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, len);

    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;

failed:
    BIO_free(bio);
    X509_free(cert);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_lua_kong_get_upstream_raw_certificate(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t  s;

    ngx_connection_t *uc;
    ngx_http_upstream_t *u;
    ngx_peer_connection_t *peer;

    u = r->upstream;
    if (u == NULL) {
        goto not_found;
    }

    peer = &(u->peer);
    if (peer == NULL) {
        goto not_found;
    }

    uc = peer->connection;
    if (uc == NULL) {
        goto not_found;
    }

    if (uc->ssl) {
        if (ngx_http_lua_kong_get_ssl_raw_certificate(uc, r->pool, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_kong_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) SSL_get_version(c->ssl->connection);
    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_kong_get_upstream_tls_protocol(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    size_t     len;
    ngx_str_t  s;

    ngx_connection_t *uc;
    ngx_http_upstream_t *u;
    ngx_peer_connection_t *peer;

    u = r->upstream;
    if (u == NULL) {
        goto not_found;
    }

    peer = &(u->peer);
    if (peer == NULL) {
        goto not_found;
    }

    uc = peer->connection;
    if (uc == NULL) {
        goto not_found;
    }

    if (uc->ssl) {
        (void) ngx_http_lua_kong_ssl_get_protocol(uc, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return NGX_OK;
    }

not_found:

    v->not_found = 1;

    return NGX_OK;
}
#endif /* NGX_SSL */


static ngx_int_t
ngx_http_lua_kong_variable_worker_pid(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    p = ngx_sprintf(p, "%P", ngx_pid);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "kong var worker_pid: %P", ngx_pid);

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_kong_variable_worker_connections_total(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    p = ngx_sprintf(p, "%ui", ngx_cycle->connection_n);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "kong var worker_connections_total: %ui",
                  ngx_cycle->connection_n);

    return NGX_OK;
}


/*
 * ngx_http_lua_kong_count_worker_connections
 *
 * Iterates this worker's connection pool and counts per-type connections.
 *
 * After ngx_get_connection() every slot is zeroed (ngx_memzero), so field
 * states are reliable:
 *
 *   fd <= 0                              → free slot (fd == -1 after
 *                                          ngx_close_connection) or stdin
 *                                          placeholder (fd == 0); skip both.
 *
 *   fd > 0, listening != NULL,
 *   listening->connection == &c[i]  → listening socket's own slot.
 *                                     ngx_event_process_init does:
 *                                       c = ngx_get_connection(ls[i].fd)
 *                                       ls[i].connection = c   ← back-ptr
 *                                     So this pointer comparison is the
 *                                     idiomatic check (used by ngx_debug_conn).
 *
 *   fd > 0, listening != NULL,
 *   listening->connection != &c[i]  → accepted HTTP/stream client connection
 *                                     (comparable to ngx_stat_active but
 *                                      scoped to this worker only;
 *                                      ngx_stat_active is a shared-memory
 *                                      atomic summed across ALL workers)
 *
 *   fd > 0, listening == NULL       → outbound upstream connection
 *                                     (proxy, keepalive pool, channel IPC, …)
 *
 * This distinction explains why (connection_n - free_connection_n) can
 * greatly exceed ngx_stat_active: Kong's upstream keepalive pool keeps
 * hundreds of upstream slots allocated even when very few client requests
 * are in flight.
 */
static void
ngx_http_lua_kong_count_worker_connections(ngx_uint_t *out_client,
    ngx_uint_t *out_upstream, ngx_uint_t *out_listening)
{
    ngx_uint_t        i;
    ngx_connection_t *c;

    *out_client    = 0;
    *out_upstream  = 0;
    *out_listening = 0;

    c = ngx_cycle->connections;

    for (i = 0; i < ngx_cycle->connection_n; i++) {

        if (c[i].fd <= 0) {
            continue;  /* free slot (fd == -1) or stdin placeholder (fd == 0) */
        }

        if (c[i].listening == NULL) {
            /* outbound: upstream proxy / keepalive pool / channel IPC */
            (*out_upstream)++;
            continue;
        }

        if (c[i].listening->connection == &c[i]) {
            /*
             * This connection slot IS the listening socket itself.
             * ngx_event_process_init sets ls[i].connection = c after
             * ngx_get_connection(ls[i].fd), so this pointer comparison
             * is the idiomatic way to detect it (used by ngx_debug_conn).
             */
            (*out_listening)++;
            continue;
        }

        /* accepted client connection */
        (*out_client)++;
    }
}


static ngx_int_t
ngx_http_lua_kong_variable_worker_connections_active(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    ngx_uint_t   client, upstream, listening;

    ngx_http_lua_kong_count_worker_connections(&client, &upstream, &listening);

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    p = ngx_sprintf(p, "%ui", client);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "kong var worker_connections_active: client=%ui"
                  " upstream=%ui listening=%ui free=%ui",
                  client, upstream, listening,
                  ngx_cycle->free_connection_n);

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_kong_variable_worker_connections_free(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    p = ngx_sprintf(p, "%ui", ngx_cycle->free_connection_n);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "kong var worker_connections_free: %ui",
                  ngx_cycle->free_connection_n);

    return NGX_OK;
}


static ngx_http_variable_t  ngx_http_lua_kong_variables[] = {

    { ngx_string("kong_request_id"), NULL,
      ngx_http_lua_kong_variable_request_id,
      0, 0, 0 },

    { ngx_string("worker_pid"), NULL,
      ngx_http_lua_kong_variable_worker_pid,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("worker_connections_total"), NULL,
      ngx_http_lua_kong_variable_worker_connections_total,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("worker_connections_active"), NULL,
      ngx_http_lua_kong_variable_worker_connections_active,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("worker_connections_free"), NULL,
      ngx_http_lua_kong_variable_worker_connections_free,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
#if (NGX_SSL)
    { ngx_string("kong_upstream_ssl_server_raw_cert"), NULL,
      ngx_http_lua_kong_get_upstream_raw_certificate,
      0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("kong_upstream_ssl_protocol"), NULL,
      ngx_http_lua_kong_get_upstream_tls_protocol,
      0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
#endif
      ngx_http_null_variable
};


ngx_int_t
ngx_http_lua_kong_add_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *cv, *v;

    for (cv = ngx_http_lua_kong_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}
