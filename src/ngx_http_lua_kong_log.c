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


int
ngx_http_lua_kong_ffi_set_log_level(ngx_http_request_t *r, int level)
{
    ngx_log_t                   *log;
    ngx_listening_t             *ls;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_uint_t                   i;

    if (r == NULL) {
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    clcf->error_log->log_level = (ngx_uint_t) level;

    if (ngx_cycle == NULL) {
        return NGX_ERROR;
    }

    if (r->connection && r->connection->log) {
        log = r->connection->log;
    }

    ngx_cycle->log->log_level = (ngx_uint_t) level;

    /* current request */
    log->log_level = (ngx_uint_t) level;

    /* for each listening socket (new requests) */
    ls = ngx_cycle->listening.elts;
    for (i = 0; i < ngx_cycle->listening.nelts; i++) {
        ls[i].log.log_level = (ngx_uint_t) level;
        ls[i].logp->log_level = (ngx_uint_t) level;
    }

    return NGX_OK;
}
