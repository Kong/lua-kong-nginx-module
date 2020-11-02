#ifndef _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    STACK_OF(X509)      *upstream_client_certificate_chain;
    EVP_PKEY            *upstream_client_private_key;
    X509_STORE          *upstream_trusted_store;
    ngx_uint_t          upstream_ssl_verify_depth;
    ngx_str_t           grpc_authority;
    unsigned            upstream_ssl_verify:1;
    unsigned            upstream_ssl_verify_set:1;
    unsigned            upstream_ssl_verify_depth_set:1;
} ngx_http_lua_kong_ctx_t;


void ngx_http_lua_kong_set_upstream_ssl(ngx_http_request_t *r,
    ngx_connection_t *c);
void ngx_http_lua_kong_set_grpc_authority(ngx_http_request_t *r,
    ngx_str_t *host);

ngx_flag_t
ngx_http_lua_kong_get_upstream_ssl_verify(ngx_http_request_t *r,
    ngx_flag_t proxy_ssl_verify);


#endif /* _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_ */
