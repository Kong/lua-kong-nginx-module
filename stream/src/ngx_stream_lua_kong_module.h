#ifndef _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_lua_api.h>
#include "../../src/ssl/ngx_lua_kong_ssl.h"

typedef struct {
    ngx_lua_kong_ssl_ctx_t   ssl_ctx;
    ngx_flag_t               proxy_ssl_disable; /* unsigned proxy_ssl_disable:1; */
} ngx_stream_lua_kong_ctx_t;


typedef struct {
    ngx_str_t               tag;
} ngx_stream_lua_kong_srv_conf_t;


#if (NGX_STREAM_SSL)

ngx_flag_t
ngx_stream_lua_kong_get_proxy_ssl_disable(ngx_stream_session_t *s);

void
ngx_stream_lua_kong_set_upstream_ssl(ngx_stream_session_t *s,
    ngx_connection_t *c);

ngx_flag_t
ngx_stream_lua_kong_get_upstream_ssl_verify(ngx_stream_session_t *s,
    ngx_flag_t proxy_ssl_verify);

ngx_str_t *
ngx_stream_lua_kong_get_upstream_ssl_sans_dnsnames(ngx_stream_session_t *s);

ngx_str_t *
ngx_stream_lua_kong_get_upstream_ssl_sans_uris(ngx_stream_session_t *s);

#endif

#endif /* _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_ */
