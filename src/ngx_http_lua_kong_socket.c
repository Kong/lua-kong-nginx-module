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

static void
ngx_http_lua_kong_socket_close_listening(ngx_listening_t *ls)
{
    ngx_connection_t  *c = ls->connection;

    /* copied from ngx_close_listening_sockets */

    if (c) {
        if (c->read->active) {
            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {

                /*
                 * it seems that Linux-2.6.x OpenVZ sends events
                 * for closed shared listening sockets unless
                 * the events was explicitly deleted
                 */

                ngx_del_event(c->read, NGX_READ_EVENT, 0);

            } else {
                ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            }
        }

    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "close listening %V #%d ", &ls->addr_text, ls->fd);
}

void
ngx_http_lua_kong_ffi_socket_close_unix_listening(ngx_str_t *sock_name)
{
#if (NGX_HAVE_UNIX_DOMAIN)

    ngx_uint_t           i;
    ngx_listening_t     *ls;

    /* copied from ngx_close_listening_sockets */

    ls = ngx_cycle->listening.elts;
    for (i = 0; i < ngx_cycle->listening.nelts; i++) {

#if (NGX_HAVE_REUSEPORT)
        if (ls[i].fd == (ngx_socket_t) -1) {
            continue;
        }
#endif

        if (ls[i].sockaddr->sa_family != AF_UNIX) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "try to close listening %V #%d", &ls[i].addr_text, ls[i].fd);

        if (ngx_strncmp(ls[i].addr_text.data + sizeof("unix:") - 1,
                         sock_name->data, sock_name->len) == 0) {
            ngx_http_lua_kong_socket_close_listening(&ls[i]);
            break;
        }
    }

#endif
}

