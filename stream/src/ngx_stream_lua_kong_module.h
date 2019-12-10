#ifndef _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_uint_t              proxy_ssl_disable; /* unsigned proxy_ssl_disable:1; */
} ngx_stream_lua_kong_ctx_t;


#if (NGX_STREAM_SSL)

ngx_uint_t
ngx_stream_lua_kong_get_proxy_ssl_disable(ngx_stream_session_t *s);

#endif

#endif /* _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_ */
