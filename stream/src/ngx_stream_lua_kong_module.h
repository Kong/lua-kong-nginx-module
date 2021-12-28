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


// macOS with M1 fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205

int ngx_stream_lua_ffi_shdict_get(ngx_shm_zone_t *zone, const unsigned char *key,
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

int ngx_stream_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s);


int ngx_stream_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op,
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

int ngx_stream_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s);


int ngx_stream_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, const unsigned char *key,
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

int ngx_stream_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s);

// macOS with M1 fixes end


#endif

#endif /* _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_ */
