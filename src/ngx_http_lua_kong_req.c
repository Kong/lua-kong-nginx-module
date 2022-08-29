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
ngx_http_lua_kong_ffi_req_is_https(ngx_http_request_t *r)
{
    return r->connection->ssl != NULL;
}


int
ngx_http_lua_kong_ffi_req_has_args(ngx_http_request_t *r)
{
    return r->args.len != 0;
}


ngx_str_t *
ngx_http_lua_kong_ffi_req_get_args(ngx_http_request_t *r)
{
    return &r->args;
}


ngx_str_t *
ngx_http_lua_kong_ffi_req_get_request_uri(ngx_http_request_t *r)
{
    return &r->unparsed_uri;
}


