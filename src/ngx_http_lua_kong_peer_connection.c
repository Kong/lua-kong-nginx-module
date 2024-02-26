/**
 * Copyright 2019-2024 Kong Inc.

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
ngx_http_lua_kong_ffi_get_last_peer_connection_cached(ngx_http_request_t *r, 
    char **err)
{
    if (r->upstream == NULL) {
        *err = "no upstream found";
        return NGX_ERROR;
    }

    return r->upstream->peer.cached;
}
