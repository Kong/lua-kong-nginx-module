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


typedef struct {
    ngx_str_t   name;
    ngx_uint_t  index;
} var_elt_t;


ngx_http_complex_value_t *
ngx_http_lua_kong_get_error_log_append(ngx_http_request_t *r)
{
    ngx_http_lua_kong_loc_conf_t *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);
    return lcf->error_log_append;
}


static u_char *
ngx_http_lua_kong_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    ngx_http_upstream_t       *u;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        len -= p - buf;
        buf = p;
    }

    /* [START] custom error_log handler [START] */
    ngx_http_complex_value_t *cpx_ela;
    ngx_str_t                 ela;

    cpx_ela = ngx_http_lua_kong_get_error_log_append(r);

    if (cpx_ela != NULL && cpx_ela != NGX_CONF_UNSET_PTR
        && ngx_http_complex_value(r, cpx_ela, &ela) == NGX_OK
        && ela.len > 0) {

       p = ngx_snprintf(buf, len, ", %s", ela.data);
       len -= p - buf;
       buf = p;

    }

    /* [END] custom error_log handler [END] */

    return buf;
}


static ngx_int_t
set_error_log_handler(ngx_http_request_t *r)
{
    r->log_handler = ngx_http_lua_kong_log_error_handler;
    return NGX_OK;
}


char *
ngx_http_lua_kong_configure_error_log(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);

    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    *h = set_error_log_handler;

    return NGX_CONF_OK;
}


