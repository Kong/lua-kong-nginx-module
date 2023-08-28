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
    ngx_http_complex_value_t     *log_append;
    ngx_str_t                     log_append_str;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);
    log_append = lcf->error_log_append;

    if (log_append == NULL || log_append == NGX_CONF_UNSET_PTR) {
        return;
    }

    if (ngx_http_complex_value(r, log_append, &log_append_str) != NGX_OK) {
        return;
    }

    if (log_append_str.len) {

       p = ngx_snprintf(*buf, len, ", %V", &log_append_str);
       len -= p - *buf;
       *buf = p;

    }
}


