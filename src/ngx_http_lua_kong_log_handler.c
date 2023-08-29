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
ngx_http_lua_kong_error_log_handler(ngx_http_request_t *r, u_char *buf, size_t len)
{
    u_char                       *p;
    ngx_uint_t                    req_id_var_index;
    ngx_http_variable_value_t    *value;
    ngx_http_lua_kong_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);
    req_id_var_index = lcf->req_id_var_index;
    if (req_id_var_index == NGX_CONF_UNSET) {
        return buf;
    }

    value = ngx_http_get_indexed_variable(r, req_id_var_index);
    if (value == NULL) {
        return buf;
    }

    buf = ngx_snprintf(buf, len, ", kong_request_id: %v", value);
    return buf;
}


static u_char *
ngx_http_lua_kong_combined_error_log_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    u_char                       *p;
    ngx_http_lua_kong_ctx_t      *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx != NULL) {
        p = ctx->orig_log_handler(r, sr, buf, len);
        len -= p - buf;
        buf = p;

        buf = ngx_http_lua_kong_error_log_handler(r, buf, len);
    }

    return buf;
}


static ngx_int_t
ngx_http_lua_kong_replace_error_log_handler(ngx_http_request_t *r)
{
    ngx_http_lua_kong_ctx_t      *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->orig_log_handler = r->log_handler;
    r->log_handler = ngx_http_lua_kong_combined_error_log_handler;

    return NGX_DECLINED;
}


char *
ngx_http_lua_kong_set_post_read_handler(ngx_conf_t *cf)
{
    ngx_http_handler_pt          *h;
    ngx_http_core_main_conf_t    *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }
    *h = ngx_http_lua_kong_replace_error_log_handler;

    return NGX_CONF_OK;
}


char *
ngx_http_lua_kong_error_log_request_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                         *p;
    ngx_str_t                    *value;
    ngx_uint_t                   *index;

    value = cf->args->elts;
    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    value[1].len--;
    value[1].data++;

    p = conf;
    index = (ngx_uint_t *) (p + cmd->offset);
    *index = ngx_http_get_variable_index(cf, &value[1]);
    if (*index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


