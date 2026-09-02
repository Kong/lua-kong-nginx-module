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


#include "ngx_http_lua_kong_directive.h"
#include <ngx_http_proxy_module.h>


extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_grpc_module;


static ngx_int_t ngx_http_lua_kong_pass_handler(ngx_http_request_t *r);


static char *
ngx_http_lua_kong_pass_invoke(ngx_conf_t *cf, ngx_module_t *module,
    const char *cmd_name, size_t cmd_name_len, ngx_str_t *url,
    ngx_http_handler_pt *captured)
{
    ngx_command_t              *cmd;
    void                       *conf;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_array_t                 args;
    ngx_array_t                *saved_args;
    ngx_str_t                   items[2];
    char                       *rv;

    for (cmd = module->commands; cmd->name.len; cmd++) {
        if (cmd->name.len == cmd_name_len
            && ngx_strncmp(cmd->name.data, cmd_name, cmd_name_len) == 0)
        {
            goto found;
        }
    }

    return "internal error: pass slot not found";

found:

    items[0] = cmd->name;
    items[1] = *url;

    ngx_memzero(&args, sizeof(args));
    args.elts = items;
    args.nelts = 2;
    args.size = sizeof(ngx_str_t);
    args.nalloc = 2;
    args.pool = cf->pool;

    saved_args = cf->args;
    cf->args = &args;

    conf = ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module->ctx_index];

    rv = cmd->set(cf, cmd, conf);

    cf->args = saved_args;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    *captured = clcf->handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_lua_kong_pass_version(ngx_conf_t *cf,
    ngx_http_lua_kong_loc_conf_t *klcf, ngx_str_t *value)
{
    ngx_http_compile_complex_value_t  ccv;

    if (klcf->pass_version != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"version=\" parameter");
        return NGX_CONF_ERROR;
    }

    if (value->len < 2 || value->data[0] != (u_char) '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"version=\" must be a $variable");
        return NGX_CONF_ERROR;
    }

#if !(NGX_HTTP_V2)

    /*
     * the value is still compiled, so that one configuration works on both
     * builds, but nothing can act on it here
     */

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"version=\" has no effect, because nginx is built "
                       "without the ngx_http_v2_module");

#endif

    klcf->pass_version = ngx_palloc(cf->pool,
                                    sizeof(ngx_http_complex_value_t));
    if (klcf->pass_version == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = klcf->pass_version;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_lua_kong_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lua_kong_loc_conf_t      *klcf = conf;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_str_t                         *value, *selector, *host, *path, arg;
    ngx_str_t                          proxy_url, grpc_url;
    ngx_uint_t                         i;
    u_char                            *p;
    ngx_http_compile_complex_value_t   ccv;
    char                              *rv;

    if (klcf->pass_selector != NULL) {
        return "is duplicate";
    }

    if (cf->args->nelts < 4) {
        return "requires a $variable, a host and a path";
    }

    value = cf->args->elts;
    selector = &value[1];
    host = &value[2];
    path = &value[3];

    if (selector->len < 2 || selector->data[0] != (u_char) '$') {
        return "first argument must be a $variable";
    }

    if (host->len == 0) {
        return "host argument must not be empty";
    }

    for (i = 4; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "version=", 8) == 0) {
            arg.len = value[i].len - 8;
            arg.data = value[i].data + 8;

            rv = ngx_http_lua_kong_pass_version(cf, klcf, &arg);
            if (rv != NGX_CONF_OK) {
                return rv;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    klcf->pass_selector = ngx_palloc(cf->pool,
                                     sizeof(ngx_http_complex_value_t));
    if (klcf->pass_selector == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = selector;
    ccv.complex_value = klcf->pass_selector;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * grpc URL: "<selector>://<host>" (path always dropped, since gRPC carries
     * the method in the :path pseudo-header and ngx_parse_url does not accept
     * a URI part for grpc_pass)
     */

    grpc_url.len = selector->len + sizeof("://") - 1 + host->len;
    grpc_url.data = ngx_pnalloc(cf->pool, grpc_url.len);
    if (grpc_url.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = grpc_url.data;
    p = ngx_cpymem(p, selector->data, selector->len);
    p = ngx_cpymem(p, "://", sizeof("://") - 1);
    p = ngx_cpymem(p, host->data, host->len);

    /* proxy URL: same as grpc, with the path appended */

    if (path->len == 0) {
        proxy_url = grpc_url;

    } else {
        proxy_url.len = grpc_url.len + path->len;
        proxy_url.data = ngx_pnalloc(cf->pool, proxy_url.len);
        if (proxy_url.data == NULL) {
            return NGX_CONF_ERROR;
        }

        p = proxy_url.data;
        p = ngx_cpymem(p, grpc_url.data, grpc_url.len);
        p = ngx_cpymem(p, path->data, path->len);
    }

    rv = ngx_http_lua_kong_pass_invoke(cf, &ngx_http_proxy_module,
                                       "proxy_pass", sizeof("proxy_pass") - 1,
                                       &proxy_url, &klcf->proxy_handler);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    rv = ngx_http_lua_kong_pass_invoke(cf, &ngx_http_grpc_module,
                                       "grpc_pass", sizeof("grpc_pass") - 1,
                                       &grpc_url, &klcf->grpc_handler);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_lua_kong_pass_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_lua_kong_pass_handler(ngx_http_request_t *r)
{
    ngx_http_lua_kong_loc_conf_t   *klcf;
    ngx_str_t                       sel, ver;

    klcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);

    if (klcf == NULL
        || klcf->pass_selector == NULL
        || klcf->proxy_handler == NULL
        || klcf->grpc_handler == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, klcf->pass_selector, &sel) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* gRPC always speaks HTTP/2, so the version selector does not apply */

    if (sel.len >= 4 && ngx_strncasecmp(sel.data, (u_char *) "grpc", 4) == 0) {
        return klcf->grpc_handler(r);
    }

    if (klcf->pass_version == NULL) {
        return klcf->proxy_handler(r);
    }

    if (ngx_http_complex_value(r, klcf->pass_version, &ver) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ver.len == 0) {
        return klcf->proxy_handler(r);
    }

#if (NGX_HTTP_V2)

    if (ver.len == 1 && ver.data[0] == (u_char) '2') {
        return ngx_http_proxy_v2_handler(r);
    }

#endif

    /*
     * "1.1" is accepted so that the caller can name the default explicitly.
     * Only "2" changes the handler; kong_pass cannot influence the HTTP/1.x
     * minor version, which ngx_http_proxy_create_request takes from the
     * proxy_http_version directive. Warn about everything else, so that a
     * value we cannot honour does not look like it was applied.
     */

    if (ver.len != 3 || ngx_strncmp(ver.data, "1.1", 3) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "kong_pass ignores unsupported version \"%V\", "
                      "falling back to the proxy_http_version directive",
                      &ver);
    }

    return klcf->proxy_handler(r);
}
