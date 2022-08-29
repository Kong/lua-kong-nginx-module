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
#if (NGX_HTTP_SSL)
    return r->connection->ssl != NULL;
#else
    return 0;
#endif
}


int
ngx_http_lua_kong_ffi_req_get_scheme(ngx_http_request_t *r)
{
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        return 1;
    }
#endif
    return 0;
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

int
ngx_http_lua_kong_ffi_req_get_server_port(ngx_http_request_t *r)
{
    if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_inet_get_port(r->connection->local_sockaddr);
}



