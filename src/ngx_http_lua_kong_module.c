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


#include "ngx_http_lua_kong_directive.h"


static ngx_int_t ngx_http_lua_kong_init(ngx_conf_t *cf);
static ngx_http_lua_kong_ctx_t *ngx_http_lua_kong_get_module_ctx(
    ngx_http_request_t *r);


static ngx_http_module_t ngx_http_lua_kong_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_lua_kong_init,                  /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};

static ngx_command_t ngx_http_lua_kong_commands[] = {

    { ngx_string("lua_kong_load_var_index"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_lua_kong_load_var_index,
      0,
      0,
      NULL },

    ngx_null_command
};


ngx_module_t ngx_http_lua_kong_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_kong_module_ctx,     /* module context */
    ngx_http_lua_kong_commands,        /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_lua_kong_init(ngx_conf_t *cf)
{
    return ngx_http_lua_kong_ssl_init(cf);
}

