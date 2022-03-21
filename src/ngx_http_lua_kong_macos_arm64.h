/**
 * Copyright 2019-2022 Kong Inc.

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


#ifndef _NGX_HTTP_LUA_KONG_MACOS_ARM64_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_MACOS_ARM64_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* macOS with Apple Silicon fixes, see: https://github.com/LuaJIT/LuaJIT/issues/205 */


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
} ngx_http_lua_kong_shdict_get_t;


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
} ngx_http_lua_kong_shdict_store_t;


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
} ngx_http_lua_kong_shdict_incr_t;


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
} ngx_http_lua_kong_set_resp_header_t;


/* copied from ngx_http_lua_shdict.c */


int ngx_http_lua_ffi_shdict_get(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, int *value_type, unsigned char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **errmsg);

int ngx_http_lua_ffi_shdict_store(ngx_shm_zone_t *zone, int op,
    const unsigned char *key, size_t key_len, int value_type,
    const unsigned char *str_value_buf, size_t str_value_len,
    double num_value, long exptime, int user_flags, char **errmsg,
    int *forcible);

int ngx_http_lua_ffi_shdict_incr(ngx_shm_zone_t *zone, const unsigned char *key,
    size_t key_len, double *num_value, char **errmsg, int has_init,
    double init, long init_ttl, int *forcible);


/* copied from ngx_http_lua_headers.c */


int ngx_http_lua_ffi_set_resp_header(ngx_http_request_t *r,
    const char *key_data, size_t key_len, int is_nil,
    const char *sval, size_t sval_len, void *mvals,
    size_t mvals_len, int override, char **errmsg);


#endif /* _NGX_HTTP_LUA_KONG_MACOS_ARM64_H_INCLUDED_ */
