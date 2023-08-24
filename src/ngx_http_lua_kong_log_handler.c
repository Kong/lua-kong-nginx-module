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


void
ngx_http_lua_kong_error_handler(ngx_http_request_t *r, u_char **buf, size_t *len)
{
    u_char                       *p;
    ngx_http_lua_kong_loc_conf_t *lcf;
    ngx_http_complex_value_t     *cpx_ela;
    ngx_str_t                     ela;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);
    cpx_ela = lcf->error_log_append;

    if (cpx_ela != NULL && cpx_ela != NGX_CONF_UNSET_PTR
        && ngx_http_complex_value(r, cpx_ela, &ela) == NGX_OK
        && ela.len > 0) {

       p = ngx_snprintf(*buf, len, ", %v", &ela);
       len -= p - *buf;
       *buf = p;

    }
}


