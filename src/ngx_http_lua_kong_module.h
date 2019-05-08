#ifndef _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_


#if (NGX_SSL)
typedef struct {
    ngx_uint_t      session_flags; /* unsigned ssl_session_flags:2 */
} ngx_http_lua_kong_ssl_ctx_t;


#define NGX_HTTP_LUA_KONG_SSL_NO_SESSION_CACHE      0x00000001
#define NGX_HTTP_LUA_KONG_SSL_NO_SESSION_TICKET     0x00000002


ngx_uint_t ngx_http_lua_kong_ssl_get_session_flags(ngx_ssl_conn_t *sc);
#endif


#endif /* _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_ */
