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

static ngx_listening_t*
ngx_http_lua_kong_find_listening_socket(in_port_t port)
{
    ngx_uint_t           i;
    ngx_listening_t     *ls;
    struct sockaddr     *sa;

    ls = ngx_cycle->listening.elts;
    for (i = 0; i < ngx_cycle->listening.nelts; i++) {
        sa = ls[i].sockaddr;
        if (ngx_inet_get_port(sa) == port) {
            return &ls[i];
        }
    }

    return NULL;
}

int
ngx_http_lua_kong_close_listening_socket(ngx_listening_t *ls)
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

        ngx_free_connection(c);

        c->fd = (ngx_socket_t) -1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "close listening %V #%d ", &ls->addr_text, ls->fd);

    if (ngx_close_socket(ls->fd) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                ngx_close_socket_n " %V failed", &ls->addr_text);
    }

    ls->fd = (ngx_socket_t) -1;

    ls->connection = NULL;

    return NGX_OK;
}

int
ngx_http_lua_kong_ffi_close_listening_socket(unsigned short port)
{
    ngx_listening_t   *ls;

    ls = ngx_http_lua_kong_find_listening_socket(port);
    if (ls == NULL) {
        return NGX_ERROR;
    }

    return ngx_http_lua_kong_close_listening_socket(ls);
}
