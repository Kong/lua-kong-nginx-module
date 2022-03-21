#ifndef _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_stream_lua_common.h>


typedef struct {
    ngx_uint_t              proxy_ssl_disable; /* unsigned proxy_ssl_disable:1; */
} ngx_stream_lua_kong_ctx_t;


#if (NGX_STREAM_SSL)

ngx_uint_t
ngx_stream_lua_kong_get_proxy_ssl_disable(ngx_stream_session_t *s);

#endif


/* macOS with Apple Silicon fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205 */


typedef struct {
    ngx_shm_zone_t      *zone;
    const unsigned char *key;
    size_t               key_len;
    int                 *value_type;
    unsigned char      **str_value_buf;
    size_t              *str_value_len;
    double              *num_value;
    int                 *user_flags;
    int                  get_stale;
    int                 *is_stale;
    char               **errmsg;
} ngx_stream_lua_kong_shdict_get_t;

typedef struct {
    ngx_shm_zone_t      *zone;
    int                  op;
    const unsigned char *key;
    size_t               key_len;
    int                  value_type;
    const unsigned char *str_value_buf;
    size_t               str_value_len;
    double               num_value;
    long                 exptime;
    int                  user_flags;
    char               **errmsg;
    int                 *forcible;
} ngx_stream_lua_kong_shdict_store_t;

typedef struct {
    ngx_shm_zone_t      *zone;
    const unsigned char *key;
    size_t               key_len;
    double              *num_value;
    char               **errmsg;
    int                  has_init;
    double               init;
    long                 init_ttl;
    int                 *forcible;
} ngx_stream_lua_kong_shdict_incr_t;

int ngx_stream_lua_ffi_shdict_get(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, int *value_type, unsigned char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **errmsg);

int ngx_stream_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op,
    const unsigned char *key, size_t key_len, int value_type,
    const unsigned char *str_value_buf, size_t str_value_len,
    double num_value, long exptime, int user_flags, char **errmsg,
    int *forcible);

int ngx_stream_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, double *num_value, char **errmsg, int has_init,
    double init, long init_ttl, int *forcible);


/* macOS with Apple Silicon fixes end */


#endif /* _NGX_STREAM_LUA_KONG_MODULE_H_INCLUDED_ */
