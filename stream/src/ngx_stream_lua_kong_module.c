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


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_lua_api.h>
#include <ngx_stream_lua_socket_tcp.h>
#include "ngx_stream_lua_kong_module.h"


static void* ngx_stream_lua_kong_create_srv_conf(ngx_conf_t* cf);


static ngx_stream_module_t ngx_stream_lua_kong_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_lua_kong_create_srv_conf,   /* create server configuration */
    NULL                                   /* merge server configuration */
};


static ngx_command_t ngx_stream_lua_kong_commands[] = {

    { ngx_string("lua_kong_set_static_tag"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_kong_srv_conf_t, tag),
      NULL },

    ngx_null_command
};


ngx_module_t ngx_stream_lua_kong_module = {
    NGX_MODULE_V1,
    &ngx_stream_lua_kong_module_ctx,   /* module context */
    ngx_stream_lua_kong_commands,      /* module directives */
    NGX_STREAM_MODULE,                 /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_stream_lua_kong_create_srv_conf(ngx_conf_t* cf)
{
    ngx_stream_lua_kong_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_lua_kong_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


ngx_str_t *
ngx_stream_lua_kong_ffi_get_static_tag(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_srv_conf_t *scf;

    scf = ngx_stream_get_module_srv_conf(
            r->session, ngx_stream_lua_kong_module);

    return &scf->tag;
}


#if (NGX_STREAM_SSL)


int
ngx_stream_lua_kong_ffi_proxy_ssl_disable(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_kong_ctx_t       *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_kong_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_stream_lua_kong_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_lua_set_ctx(r, ctx, ngx_stream_lua_kong_module);
    }

    ctx->proxy_ssl_disable = 1;

    return NGX_OK;
}


ngx_uint_t
ngx_stream_lua_kong_get_proxy_ssl_disable(ngx_stream_session_t *s)
{
    ngx_stream_lua_kong_ctx_t       *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_kong_module);

    return ctx == NULL ? 0 : ctx->proxy_ssl_disable;
}


// macOS with M1 fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205

int
ngx_stream_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s)
{
    return ngx_stream_lua_ffi_shdict_get(s->zone, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->user_flags, s->get_stale,
        s->is_stale, s->errmsg);
}


int
ngx_stream_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s)
{
    return ngx_stream_lua_ffi_shdict_store(s->zone, s->op, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->exptime, s->user_flags, s->errmsg,
        s->forcible);
}


int
ngx_stream_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s)
{
    return ngx_stream_lua_ffi_shdict_incr(s->zone, s->key, s->key_len, s->num_value,
        s->errmsg, s->has_init, s->init, s->init_ttl, s->forcible);
}

// macOS with M1 fixes end


#endif
