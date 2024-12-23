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


#include "ngx_http_lua_kong_directive.h"
#include "ngx_http_upstream.h"

static ngx_int_t ngx_http_lua_kong_init(ngx_conf_t *cf);
static void* ngx_http_lua_kong_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_lua_kong_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_http_module_t ngx_http_lua_kong_module_ctx = {
    ngx_http_lua_kong_add_vars,              /* preconfiguration */
    ngx_http_lua_kong_init,                  /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_lua_kong_create_loc_conf,       /* create location configuration */
    ngx_http_lua_kong_merge_loc_conf         /* merge location configuration */
};


static ngx_command_t ngx_http_lua_kong_commands[] = {

    { ngx_string("lua_kong_load_var_index"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_lua_kong_load_var_index,
      0,
      0,
      NULL },

    { ngx_string("lua_kong_set_static_tag"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lua_kong_loc_conf_t, tag),
      NULL },

    { ngx_string("lua_kong_error_log_request_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_lua_kong_error_log_request_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lua_kong_loc_conf_t, request_id_var_index),
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
    if (ngx_http_lua_kong_error_log_init(cf) != NGX_CONF_OK) {
        return NGX_ERROR;
    }

    return ngx_lua_kong_ssl_init(cf);
}


static void
ngx_http_lua_kong_cleanup(void *data)
{
    ngx_http_lua_kong_ctx_t     *ctx = data;

    ngx_lua_kong_ssl_cleanup(&ctx->ssl_ctx);
}


ngx_http_lua_kong_ctx_t *
ngx_http_lua_kong_get_module_ctx(ngx_http_request_t *r)
{
    ngx_http_lua_kong_ctx_t     *ctx;
    ngx_pool_cleanup_t          *cln;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_kong_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lua_kong_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        cln->data = ctx;
        cln->handler = ngx_http_lua_kong_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_lua_kong_module);
    }

    return ctx;
}


static void *
ngx_http_lua_kong_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_lua_kong_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_kong_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->request_id_var_index = NGX_CONF_UNSET;

    return conf;
}


static char*
ngx_http_lua_kong_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_lua_kong_loc_conf_t *prev = parent;
    ngx_http_lua_kong_loc_conf_t *conf = child;

    /* conf->tag is NGX_HTTP_LOC_CONF only */
    ngx_conf_merge_value(conf->request_id_var_index, prev->request_id_var_index, NGX_CONF_UNSET);

    return NGX_CONF_OK;
}

const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_error = NGX_HTTP_UPSTREAM_FT_ERROR;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_timeout = NGX_HTTP_UPSTREAM_FT_TIMEOUT;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_invalid_header = NGX_HTTP_UPSTREAM_FT_INVALID_HEADER;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_500 = NGX_HTTP_UPSTREAM_FT_HTTP_500;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_502 = NGX_HTTP_UPSTREAM_FT_HTTP_502;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_503 = NGX_HTTP_UPSTREAM_FT_HTTP_503;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_504 = NGX_HTTP_UPSTREAM_FT_HTTP_504;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_403 = NGX_HTTP_UPSTREAM_FT_HTTP_403;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_404 = NGX_HTTP_UPSTREAM_FT_HTTP_404;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_http_429 = NGX_HTTP_UPSTREAM_FT_HTTP_429;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_off = NGX_HTTP_UPSTREAM_FT_OFF;
const ngx_uint_t ngx_http_lua_kong_next_upstream_mask_non_idempotent = NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;

ngx_flag_t
ngx_http_lua_kong_get_next_upstream_mask(ngx_http_request_t *r,
    ngx_flag_t upstream_next)
{
    ngx_http_lua_kong_ctx_t      *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return upstream_next;
    }

    if(ctx->next_upstream != 0) {
        return ctx->next_upstream;
    }
    return upstream_next;
}

int
ngx_http_lua_ffi_set_next_upstream(ngx_http_request_t *r, ngx_uint_t next_upstream, char **err)
{
    ngx_http_lua_kong_ctx_t      *ctx;

    ctx = ngx_http_lua_kong_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->next_upstream = next_upstream;
    return NGX_OK;
}