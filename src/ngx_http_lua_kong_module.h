#ifndef _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    STACK_OF(X509)      *upstream_client_certificate_chain;
    EVP_PKEY            *upstream_client_private_key;
} ngx_http_lua_kong_ctx_t;


void ngx_http_lua_kong_set_upstream_ssl(ngx_http_request_t *r,
    ngx_connection_t *c);


#endif /* _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_ */
