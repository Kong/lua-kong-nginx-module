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

char *
ngx_http_lua_kong_load_var_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


void ngx_http_lua_kong_set_upstream_ssl(ngx_http_request_t *r,
    ngx_connection_t *c);
void ngx_http_lua_kong_set_grpc_authority(ngx_http_request_t *r,
    ngx_str_t *host);

ngx_flag_t
ngx_http_lua_kong_get_upstream_ssl_verify(ngx_http_request_t *r,
    ngx_flag_t proxy_ssl_verify);


// macOS with M1 fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205

int ngx_http_lua_ffi_shdict_get(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, int *value_type, unsigned char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **errmsg);

typedef struct {
    ngx_shm_zone_t *zone;
    const unsigned char *key;
    size_t key_len;
    int *value_type;
    unsigned char **str_value_buf;
    size_t *str_value_len;
    double *num_value;
    int *user_flags;
    int get_stale;
    int *is_stale;
    char **errmsg;
} ngx_shdict_get_t;

int ngx_http_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s);


int ngx_http_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op,
    const unsigned char *key, size_t key_len, int value_type,
    const unsigned char *str_value_buf, size_t str_value_len,
    double num_value, long exptime, int user_flags, char **errmsg,
    int *forcible);

typedef struct {
    ngx_shm_zone_t *zone;
    int op;
    const unsigned char *key;
    size_t key_len;
    int value_type;
    const unsigned char *str_value_buf;
    size_t str_value_len;
    double num_value;
    long exptime;
    int user_flags;
    char **errmsg;
    int *forcible;
} ngx_shdict_store_t;

int ngx_http_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s);


int ngx_http_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, double *num_value, char **errmsg, int has_init,
    double init, long init_ttl, int *forcible);

typedef struct {
    ngx_shm_zone_t *zone;
    const unsigned char *key;
    size_t key_len;
    double *num_value;
    char **errmsg;
    int has_init;
    double init;
    long init_ttl;
    int *forcible;
} ngx_shdict_incr_t;

int ngx_http_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s);


int ngx_http_lua_ffi_set_resp_header(ngx_http_request_t *r,
    const char *key_data, size_t key_len, int is_nil,
    const char *sval, size_t sval_len, void *mvals,
    size_t mvals_len, int override, char **errmsg);

typedef struct {
    ngx_http_request_t *r;
    const char *key_data;
    size_t key_len;
    int is_nil;
    const char *sval;
    size_t sval_len;
    void *mvals;
    size_t mvals_len;
    int override;
    char **errmsg;
} ngx_set_resp_header_t;

int ngx_http_lua_ffi_set_resp_header_m1(ngx_set_resp_header_t *s);

// macOS with M1 fixes end


#endif /* _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_ */
