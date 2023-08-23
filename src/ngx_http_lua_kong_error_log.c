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


static ngx_array_t *error_log_append_var_indexes;

typedef struct {
    ngx_str_t   name;
    ngx_uint_t  index;
} var_elt_t;


static u_char *
ngx_http_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
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


    // loop through error_log_append_var_indexes and append
    // each variable and their values to the error log
    var_elt_t *elts  = error_log_append_var_indexes->elts;
    ngx_uint_t nelts = error_log_append_var_indexes->nelts;
    for (int i = 0; i < nelts; i++) {
        var_elt_t                 *v     = &elts[i];
        ngx_uint_t                 index = v->index;
        ngx_http_variable_value_t *value =
                ngx_http_get_indexed_variable(r, index);

        if (value == NULL || value->not_found || !value->valid) {
            continue;
        }

        u_char *name = v->name.data;
        p = ngx_snprintf(buf, len, ", %s: \"%v\"", name, value);

        len -= p - buf;
        buf = p;
    }

    return buf;
}


static ngx_int_t
set_error_log_handler(ngx_http_request_t *r)
{
    r->log_handler = ngx_http_log_error_handler;
    return NGX_OK;
}


char *
ngx_http_lua_kong_configure_error_log(ngx_conf_t *cf)
{
    if (error_log_append_var_indexes == NULL || error_log_append_var_indexes->nelts == 0) {
        return NGX_CONF_OK;
    }

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = set_error_log_handler;

    return NGX_OK;
}


char *
ngx_http_lua_kong_error_log_append_vars(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    error_log_append_var_indexes = ngx_array_create(cf->pool, 4, sizeof(var_elt_t));
    if (error_log_append_var_indexes == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_t *values = cf->args->elts;
    ngx_uint_t num_elts = cf->args->nelts - 1;

    // values passed to the directive start at values[1]
    for (int i = 1; i <= num_elts; i++) {
        ngx_str_t name = values[i];
        ngx_int_t index = ngx_http_get_variable_index(cf, &name);

        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        var_elt_t *v = ngx_array_push(error_log_append_var_indexes);
        v->name = name;
        v->index = index;
    }

    return NGX_CONF_OK;
}
