#ifndef _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#ifdef NGX_LUA_USE_ASSERT
#include <assert.h>
#   define ngx_http_lua_kong_assert(a)  assert(a)
#else
#   define ngx_http_lua_kong_assert(a)
#endif


#endif /* _NGX_HTTP_LUA_KONG_COMMON_H_INCLUDED_ */
