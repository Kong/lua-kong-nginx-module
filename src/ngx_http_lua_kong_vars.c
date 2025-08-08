/**
 * Copyright 2019-2023 Kong Inc.

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
        return NGX_ABORT;
    }

    peer = &(u->peer);
    if (peer == NULL) {
        return NGX_ABORT;
    }

    uc = peer->connection;
    if (uc == NULL) {
        return NGX_ABORT;
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
        return NGX_ABORT;
    }

    peer = &(u->peer);
    if (peer == NULL) {
        return NGX_ABORT;
    }

    uc = peer->connection;
    if (uc == NULL) {
        return NGX_ABORT;
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

    v->not_found = 1;

    return NGX_OK;
}


static ngx_http_variable_t  ngx_http_lua_kong_variables[] = {

    { ngx_string("kong_request_id"), NULL,
      ngx_http_lua_kong_variable_request_id,
      0, 0, 0 },
    { ngx_string("upstream_ssl_server_raw_cert"), NULL,
      ngx_http_lua_kong_get_upstream_raw_certificate,
      0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("upstream_ssl_protocol"), NULL,
      ngx_http_lua_kong_get_upstream_tls_protocol,
      0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
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
