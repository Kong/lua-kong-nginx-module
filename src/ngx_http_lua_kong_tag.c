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


ngx_str_t *
ngx_http_lua_kong_ffi_get_static_tag(ngx_http_request_t *r)
{
    ngx_http_lua_kong_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_kong_module);

    return &lcf->tag;
}


