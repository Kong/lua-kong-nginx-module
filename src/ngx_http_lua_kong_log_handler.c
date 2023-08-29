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


static u_char *
ngx_http_lua_kong_log_handler(ngx_http_request_t *r, u_char *buf, size_t len)
{
    u_char                       *p;
    ngx_http_lua_kong_loc_conf_t *lcf;
    ngx_http_complex_value_t     *log_append;
    ngx_str_t                     log_append_str;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);
    log_append = lcf->error_log_append;

    if (log_append == NULL || log_append == NGX_CONF_UNSET_PTR) {
        return buf;
    }

    if (ngx_http_complex_value(r, log_append, &log_append_str) != NGX_OK) {
        return buf;
    }

    if (log_append_str.len) {
       buf = ngx_snprintf(buf, len, ", %V", &log_append_str);
    }

    return buf;
}


static u_char *
ngx_http_lua_kong_combined_log_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    u_char                      *p;
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx != NULL) {
        p = ctx->orig_log_handler(r, sr, buf, len);
        len -= p - buf;
        buf = p;

        buf = ngx_http_lua_kong_log_handler(r, buf, len);
    }

    return buf;
}


static ngx_int_t
replace_log_handler(ngx_http_request_t *r)
{
    ngx_http_lua_kong_ctx_t     *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->orig_log_handler = r->log_handler;
    r->log_handler = ngx_http_lua_kong_combined_log_handler;

    return NGX_DECLINED;
}


char *
ngx_http_lua_kong_set_post_read_handler(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }
    *h = replace_log_handler;

    return NGX_CONF_OK;
}


