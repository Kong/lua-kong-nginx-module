/**
 * Copyright 2019-2023 Kong Inc.

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


#define KONG_REQUEST_ID_MAX_LEN     32
#define KONG_REQUEST_ID_FORMAT      "%08x%08x%08x%08x"


static ngx_int_t
ngx_http_lua_kong_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_http_variable_t  ngx_http_lua_kong_variables[] = {

    { ngx_string("kong_request_id"), NULL,
      ngx_http_lua_kong_variable_request_id,
      0, 0, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_lua_kong_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

    id = ngx_pnalloc(r->pool, KONG_REQUEST_ID_MAX_LEN);
    if (id == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = KONG_REQUEST_ID_MAX_LEN;
    v->data = id;

    ngx_sprintf(id, KONG_REQUEST_ID_FORMAT,
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

    return NGX_OK;
}


ngx_int_t
ngx_http_lua_kong_add_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *cv, *v;

    for (cv = ngx_http_lua_kong_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


