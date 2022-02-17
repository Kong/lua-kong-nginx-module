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


#include "ngx_http_lua_kong_common.h"


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

int
ngx_http_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s)
{
    return ngx_http_lua_ffi_shdict_get(s->zone, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->user_flags, s->get_stale,
        s->is_stale, s->errmsg);
}


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

int
ngx_http_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s)
{
    return ngx_http_lua_ffi_shdict_store(s->zone, s->op, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->exptime, s->user_flags, s->errmsg,
        s->forcible);
}


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

int
ngx_http_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s)
{
    return ngx_http_lua_ffi_shdict_incr(s->zone, s->key, s->key_len, s->num_value,
        s->errmsg, s->has_init, s->init, s->init_ttl, s->forcible);
}


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

int
ngx_http_lua_ffi_set_resp_header_m1(ngx_set_resp_header_t *s)
{
    return ngx_http_lua_ffi_set_resp_header(s->r, s->key_data, s->key_len, s->is_nil,
        s->sval, s->sval_len, s->mvals, s->mvals_len, s->override, s->errmsg);
}


// macOS with M1 fixes end
