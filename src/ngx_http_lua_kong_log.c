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

#if (NGX_WIN32)
/*
** The dynamic log level feature is only supported on UNIX like system,
** because we only call the function
** void ngx_http_lua_kong_log_set_ready_for_dynamic_log_level();
** in ngx_worker_process_cycle in the file src/os/unix/ngx_process_cycle.c.
**
** Excluding the technical view,
** the Kong Gateway does not supoort the Windows OS.
** 
*/
#error "The dynamic log level feature is only supported on UNIX like system"
#endif

/* -- Global variables for the dynamic log level feature ------------------- */

/* the dynamic log level */
static ngx_uint_t g_dynamic_log_level = NGX_CONF_UNSET_UINT;

/* after this time, the dynamic log level will restore to original value */
static time_t     g_dynamic_log_level_timeout_at; 

/* ------------------------------------------------------------------------- */

int
ngx_http_lua_kong_ffi_set_dynamic_log_level(int log_level, int timeout)
{
    if (timeout == 0) {
        /*
        ** if the timeout is 0,
        ** we will disable the dynamic log level,
        ** that is, the log_level will be restored to the default setting from log_level in kong.conf.
        ** and ignore the first parameter.
        */
        g_dynamic_log_level = NGX_CONF_UNSET_UINT;
        return NGX_OK;
    }

    /*
    ** if the log level is invalid,
    ** we will not change the current log level,
    ** and return an error.
    */
    if (log_level > NGX_LOG_DEBUG || log_level < NGX_LOG_STDERR) {
        return NGX_ERROR;
    }

    g_dynamic_log_level = log_level;
    g_dynamic_log_level_timeout_at = (time_t)ngx_time() + (time_t)timeout;

    return NGX_OK;
}

ngx_uint_t
ngx_http_lua_kong_get_dynamic_log_level(ngx_uint_t current_log_level)
{
    if (g_dynamic_log_level == NGX_CONF_UNSET_UINT) {
        return current_log_level;
    }

    if (g_dynamic_log_level_timeout_at < ngx_time()) {
        g_dynamic_log_level = NGX_CONF_UNSET_UINT;
        return current_log_level;
    }

    return g_dynamic_log_level;
}

int
ngx_http_lua_kong_ffi_get_dynamic_log_level(int current_log_level)
{
    return ngx_http_lua_kong_get_dynamic_log_level(current_log_level);
}
