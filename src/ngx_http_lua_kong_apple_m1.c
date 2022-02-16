/**
 * Copyright 2019-2020 Kong Inc.

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

int
ngx_http_lua_ffi_shdict_get_m1(ngx_shdict_get_t *s)
{
    return ngx_http_lua_ffi_shdict_get(s->zone, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->user_flags, s->get_stale,
        s->is_stale, s->errmsg);
}


int
ngx_http_lua_ffi_shdict_store_m1(ngx_shdict_store_t *s)
{
    return ngx_http_lua_ffi_shdict_store(s->zone, s->op, s->key, s->key_len, s->value_type,
        s->str_value_buf, s->str_value_len, s->num_value, s->exptime, s->user_flags, s->errmsg,
        s->forcible);
}


int
ngx_http_lua_ffi_shdict_incr_m1(ngx_shdict_incr_t *s)
{
    return ngx_http_lua_ffi_shdict_incr(s->zone, s->key, s->key_len, s->num_value,
        s->errmsg, s->has_init, s->init, s->init_ttl, s->forcible);
}


int
ngx_http_lua_ffi_set_resp_header_m1(ngx_set_resp_header_t *s)
{
    return ngx_http_lua_ffi_set_resp_header(s->r, s->key_data, s->key_len, s->is_nil,
        s->sval, s->sval_len, s->mvals, s->mvals_len, s->override, s->errmsg);
}

// macOS with M1 fixes end
