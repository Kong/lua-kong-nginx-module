Name
====
lua-kong-nginx-module - Nginx C module that exposes a Lua API to dynamically control Nginx


Table of Contents
=================

* [Name](#name)
* [Description](#description)
* [Install](#install)
* [Directives](#directives)
    * [lua\_kong\_load\_var\_index](#lua_kong_load_var_index)
    * [lua\_kong\_set\_static\_tag](#lua_kong_set_static_tag)
    * [lua\_kong\_error\_log\_request\_id](#lua_kong_error_log_request_id)
* [Variables](#variables)
    * [$kong\_request\_id](#kong_request_id)
    * [$kong\_upstream\_ssl\_server\_raw\_cert](#kong_upstream_ssl_server_raw_cert)
    * [$kong\_upstream\_ssl\_protocol](#kong_upstream_ssl_protocol)
* [Methods](#methods)
    * [resty.kong.tls.disable\_session\_reuse](#restykongtlsdisable_session_reuse)
    * [resty.kong.tls.get\_full\_client\_certificate\_chain](#restykongtlsget_full_client_certificate_chain)
    * [resty.kong.tls.set\_upstream\_cert\_and\_key](#restykongtlsset_upstream_cert_and_key)
    * [resty.kong.tls.set\_upstream\_ssl\_sans\_dnsnames](#restykongtlsset_upstream_ssl_sans_dnsnames)
    * [resty.kong.tls.set\_upstream\_ssl\_sans\_uris](#restykongtlsset_upstream_ssl_sans_uris)
    * [resty.kong.tls.set\_upstream\_ssl\_trusted\_store](#restykongtlsset_upstream_ssl_trusted_store)
    * [resty.kong.tls.set\_upstream\_ssl\_verify](#restykongtlsset_upstream_ssl_verify)
    * [resty.kong.tls.set\_upstream\_ssl\_verify\_depth](#restykongtlsset_upstream_ssl_verify_depth)
    * [resty.kong.tls.get\_ssl\_pointer](#restykongtlsget_ssl_pointer)
    * [resty.kong.tls.get\_request\_ssl\_pointer](#restykongtlsget_request_ssl_pointer)
    * [resty.kong.grpc.set\_authority](#restykonggrpcset_authority)
    * [resty.kong.tls.disable\_proxy\_ssl](#restykongtlsdisable_proxy_ssl)
    * [resty.kong.var.patch\_metatable](#restykongvarpatch_metatable)
    * [resty.kong.tag.get](#restykongtagget)
    * [resty.kong.log.set\_log\_level](#restykonglogset_log_level)
    * [resty.kong.log.get\_log\_level](#restykonglogget_log_level)
    * [resty.kong.upstream.set\_next\_upstream](#restykongupstreamset_next_upstream)
* [License](#license)

Description
===========
Kong often needs to be able to change Nginx behavior at runtime. Traditionally this
has been done using various core patches. This module attempts to unify those approaches
and ensure the least amount of modifications made directly to Nginx to support future
maintainability.

Patches from [openresty-patches](https://github.com/Kong/kong-build-tools/tree/master/openresty-patches/patches)
are **required** for this module to compile successfully.
You may use the [openresty-build-tools](https://github.com/Kong/kong-build-tools/tree/master/openresty-build-tools)
script to automatically build an OpenResty binary with required patches as well as this module
included.

Install
=======
This module can be installed just like any ordinary Nginx C module, using the
`--add-module` configuration option:

```shell
./configure --prefix=/usr/local/kong-nginx \
            --add-module=/path/to/lua-kong-nginx-module \
            ...

```

Directives
=======

lua\_kong\_load\_var\_index
-------------------------------------------
**syntax:** *lua_kong_load_var_index $variable | default;*

**context:** *http*

Ensure *variable* is indexed. Note that variables defined by `set` directive
are always indexed by default and does not need to be defined here again.

Common variables defined by other modules that are already indexed:

- `$proxy_host`
- `$proxy_internal_body_length`
- `$proxy_internal_chunked`
- `$remote_addr`
- `$remote_user`
- `$request`
- `$http_referer`
- `$http_user_agent`
- `$host`

Specially, use `lua_kong_load_var_index default` to
index *commonly used variables* as follows:

- `$args`
- `$is_args`
- `$bytes_sent`
- `$content_type`
- `$http_authorization`
- `$http_connection`
- `$http_host`
- `$http_kong_debug`
- `$http_proxy`
- `$http_proxy_connection`
- `$http_te`
- `$http_upgrade`
- `$http_via`
- `$http_x_forwarded_for`
- `$http_x_forwarded_host`
- `$http_x_forwarded_path`
- `$http_x_forwarded_port`
- `$http_x_forwarded_prefix`
- `$http_x_forwarded_proto`
- `$http_x_kong_request_debug`
- `$http_x_kong_request_debug_token`
- `$http_x_kong_request_debug_log`
- `$https`
- `$http2`
- `$realip_remote_addr`
- `$realip_remote_port`
- `$remote_port`
- `$request_length`
- `$request_method`
- `$request_uri`
- `$scheme`
- `$server_addr`
- `$server_port`
- `$ssl_cipher`
- `$ssl_client_raw_cert`
- `$ssl_client_verify`
- `$ssl_protocol`
- `$ssl_server_name`
- `$upstream_http_connection`
- `$upstream_http_trailer`
- `$upstream_http_upgrade`
- `$upstream_status`
- `$upstream_start_timestamp_us`
- `$upstream_connect_timestamp_us`
- `$upstream_request_timestamp_us`
- `$upstream_header_timestamp_us`
- `$upstream_response_timestamp_us`
- `$kong_request_id`

See [resty.kong.var.patch\_metatable](#restykongvarpatch_metatable) on how to enable
indexed variable access.

[Back to TOC](#table-of-contents)

lua\_kong\_set\_static\_tag
-------------------------------------------
**syntax:** *lua_kong_set_static_tag value;*

**context:** *location(http subsystem)* *server(stream subsystem)*

Add a static tag string for Nginx's `location`(http subsystem) or `server`(stream subsystem) block,
which can be accessed in Lua land by [`resty.kong.tag.get`](#restykongtagget).

Notice: the value of tag is bound with the `location`(http subsystem) or `server`(stream subsystem) block
where it is defined.
So if you defined multi tags in different `location`(http subsystem) or `server`(stream subsystem) block,
you will always get the value where your Lua code runs in but not others.

[Back to TOC](#table-of-contents)

lua\_kong\_error\_log\_request\_id
-------------------------------------------
**syntax:** *lua_kong_error_log_request_id $variable;*

**context:** *http* *server* *location*

Append a Request ID to the standard error log format, load the ID value from `$variable`. `$variable` must be previously defined.

For example, with this configuration:
```
lua_kong_error_log_request_id $request_id;
```
An error log line may look similar to the following:
```
2023/09/06 11:33:36 [error] 94085#0: *6 [lua] content_by_lua(nginx.conf:27):7: hello world, client: 127.0.0.1, server: , request: "GET /foo HTTP/1.1", host: "localhost:8080", request_id: "cd7706e903db672ac5fac333bc8db5ed"
```

[Back to TOC](#table-of-contents)

Variables
=========

$kong\_request\_id
------------------
Unique request identifier generated from 16 pseudo-random bytes, in hexadecimal.
This variable is indexed.

[Back to TOC](#table-of-contents)

$kong\_upstream\_ssl\_server\_raw\_cert
----------------------------------------------------

Returns the upstream server certificate in the PEM format for an established SSL connection.

[Back to TOC](#table-of-contents)

$kong\_upstream\_ssl\_protocol
----------------------------------------------------

Returns the protocol of an established SSL connection for an upstream
HTTP request.


[Back to TOC](#table-of-contents)

Methods
=======

resty.kong.tls.disable\_session\_reuse
--------------------------------------
**syntax:** *succ, err = resty.kong.tls.disable\_session\_reuse()*

**context:** *ssl_certificate_by_lua&#42;*

**subsystems:** *http* *stream*

Prevents the TLS session for the current connection from being reused by
disabling session ticket and session ID for the current TLS connection.

This function returns `true` when the call is successful. Otherwise it returns
`nil` and a string describing the error.

[Back to TOC](#table-of-contents)

resty.kong.tls.get\_full\_client\_certificate\_chain
----------------------------------------------------
**syntax:** *pem_chain, err = resty.kong.tls.get\_full\_client\_certificate\_chain()*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, content_by_lua&#42;, log_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Returns the PEM encoded downstream client certificate chain with the client certificate
at the top and intermediate certificates (if any) at the bottom.

If client did not present any certificate or if session was reused, then this
function will return `nil`.

This is functionally similar to
[$ssl\_client\_raw\_cert](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_raw_cert)
provided by [ngx\_http\_ssl\_module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html),
with the notable exception that this function also returns any certificate chain
client sent during handshake.

If the TLS session was reused, (signaled by
[$ssl\_session\_reused](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_session_reused) returns "r"),
then no client certificate information will be available as a full handshake never occurred.
In this case caller should use
[$ssl\_session\_id](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_session_id) to
associate this session with one of the previous handshakes to identify the connecting
client.

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_cert\_and\_key
--------------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_cert\_and\_key(chain, key)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Overrides and enables sending client certificate while connecting to the
upstream in the current request.

`chain` is the client certificate and intermediate chain (if any) returned by
functions such as [ngx.ssl.parse\_pem\_cert](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#parse_pem_cert).

`key` is the private key corresponding to the client certificate returned by
functions such as [ngx.ssl.parse\_pem\_priv\_key](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#parse_pem_priv_key).

On success, this function returns `true` and future handshakes with upstream servers
will always use the provided client certificate. Otherwise `nil` and a string describing the error
will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_ssl\_sans\_dnsnames
-----------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_ssl\_sans\_dnsnames(entries)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Set additional SANs entries for name validation of upstream ssl certificate,
where `entries` is an array of DNS-names.

On success, this function returns `true`. Otherwise `nil` and a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_ssl\_sans\_uris
-----------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_ssl\_sans\_uris(entries)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Set additional SANs entries for name validation of upstream ssl certificate,
where `entries` is an array of URIs.

On success, this function returns `true`. Otherwise `nil` and a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_ssl\_trusted\_store
-------------------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_ssl\_trusted\_store(store)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Set upstream ssl verification trusted store of current request. Global setting set by
`proxy_ssl_trusted_certificate` will be overwritten for the current request.

`store` is a table object that can be created by
[resty.openssl.x509.store.new](https://github.com/fffonion/lua-resty-openssl#storenew).

On success, this function returns `true` and future handshakes with upstream servers
will be verified with given store. Otherwise `nil` and a string describing the
error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

Example:
```lua
local x509 = require("resty.openssl.x509")
local crt, err = x509.new([[-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----]])
if err then
    ngx.log(ngx.ERR, "failed to parse cert: ", err)
    ngx.exit(500)
end
local store = require("resty.openssl.x509.store")
local st, err = store.new()
if err then
    ngx.log(ngx.ERR, "failed to create store: ", err)
    ngx.exit(500)
end
local ok, err = st:add(crt)
if err then
    ngx.log(ngx.ERR, "failed to add cert to store: ", err)
    ngx.exit(500)
end
-- st:add can be called multiple times, also accept a crl
-- st:add(another_crt)
-- st:add(crl)
-- OR
-- st:use_default() to load default CA bundle
local tls = require("resty.kong.tls")
local ok, err = tls.set_upstream_ssl_trusted_store(st.ctx)
if err then
    ngx.log(ngx.ERR, "failed to set upstream trusted store: ", err)
    ngx.exit(500)
end
local ok, err = tls.set_upstream_ssl_verify(true)
if err then
    ngx.log(ngx.ERR, "failed to set upstream ssl verify: ", err)
    ngx.exit(500)
end
```

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_ssl\_verify
-----------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_ssl\_verify(verify)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Set upstream ssl verification enablement of current request to the given boolean
argument `verify`. Global setting set by `proxy_ssl_verify` will be overwritten.

On success, this function returns `true`. Otherwise `nil` and a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)

resty.kong.tls.set\_upstream\_ssl\_verify\_depth
------------------------------------------------
**syntax:** *ok, err = resty.kong.tls.set\_upstream\_ssl\_verify\_depth(depth)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Set upstream ssl verification depth of current request to the given non-negative integer
argument `depth`. Global setting set by `proxy_ssl_verify_depth` will be overwritten.

On success, this function returns `true`. Otherwise `nil` and a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)

resty.kong.tls.get\_ssl\_pointer
----------------------------------------------------
**syntax:** *ssl_ptr, err = resty.kong.tls.get\_ssl\_pointer(sock)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, content_by_lua&#42;, log_by_lua&#42;*, *preread_by_lua&#42;*

**subsystems:** *http* *stream*

Retrieves the OpenSSL `SSL*` object for the current tcpsock `sock`.

On success, this function returns the pointer of type `SSL`. Otherwise `nil` and a string
describing the error will be returned.

[Back to TOC](#table-of-contents)

resty.kong.tls.get\_request\_ssl\_pointer
----------------------------------------------------
**syntax:** *ssl_ptr, err = resty.kong.get\_request\_ssl\_pointer()*

**context:** *client_hello_by_lua&#42;, *ssl_certificate_by_lua&#42;, *rewrite_by_lua&#42;, access_by_lua&#42;, content_by_lua&#42;, log_by_lua&#42;*

**subsystems:** *http*

Retrieves the OpenSSL `SSL*` object for the current HTTP request.

On success, this function returns the pointer of type `SSL`. Otherwise `nil` and a string
describing the error will be returned.

[Back to TOC](#table-of-contents)

resty.kong.grpc.set\_authority
------------------------------
**syntax:** *ok, err = resty.kong.grpc.set_authority(new_authority)*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*

**subsystems:** *http*

Overrides the `:authority` pseudo header sent to gRPC upstream by
[ngx\_http\_grpc\_module](https://nginx.org/en/docs/http/ngx_http_grpc_module.html).

This function is a capability not possible in Nginx through means of config
directive alone. Reason being Nginx auto-generates the `:authority` pseudo header
without giving us a way to override it at config time. Closest being
`grpc_set_header Host "foo.example.com"`, but this will cause the gRPC
module to use the `Host` header and not generate the `:authority` pseudo header,
causing problems for certain gRPC server.

When called, this function accepts a new value to override the `:authority`
pseudo header that will be generated by the ngx\_http\_grpc\_module for the
current request.

The `new_authority` parameter **can not** be an empty string.

On success, this function returns `true`. Otherwise `nil` and a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

If called in the `balancer_by_lua` context, the request needs to be recreated
(see [balancer.recreate](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/balancer.md#recreate_request).

[Back to TOC](#table-of-contents)

resty.kong.tls.disable\_proxy\_ssl
----------------------------------
**syntax:** *ok, err = resty.kong.tls.disable_proxy_ssl()*

**context:** *preread_by_lua&#42;, balancer_by_lua&#42;*

**subsystems:** *stream*

Disables the TLS handshake to upstream for [ngx\_stream\_proxy\_module](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html).
Effectively this overrides [proxy\_ssl](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl) directive to `off` setting
for the current stream session.

This function has no side effects if the `proxy_ssl off;` setting has already
been specified inside `nginx.conf` or if this function has been previously
called from the current session.

[Back to TOC](#table-of-contents)

resty.kong.var.patch\_metatable
----------------------------------
**syntax:** *resty.kong.var.patch_metatable()*

**context:** *init_by_lua*

**subsystems:** *http*

Indexed variable access is a faster way of accessing Nginx variables for OpenResty.
This method patches the metatable of `ngx.var` to enable index access to variables
that supports it. It should be called once in the `init` phase which will be effective for
all subsequent `ngx.var` uses.

For variables that does not have indexed access, the slower hash based lookup will
be used instead (this is the OpenResty default behavior).

To ensure a variable can be accessed using index, you can use the [lua_kong_load_var_index](#lua_kong_load_var_index)
directive.

[Back to TOC](#table-of-contents)

resty.kong.tag.get
----------------------------------
**syntax:** *resty.kong.tag.get()*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, content_by_lua&#42;, log_by_lua&#42;, header_filter_by_lua&#42;, body_filter_by_lua&#42;*

**subsystems:** *http* *stream*

Return the tag value which is set by [`lua_kong_set_static_tag`](#lua_kong_set_static_tag) directive.

If there is no tag in `location`(http subsystems) or `server`(stream subsystems) block,
it will return `nil`.

[Back to TOC](#table-of-contents)

resty.kong.log.set\_log\_level
----------------------------------
**syntax:** *resty.kong.log.set_log_level(level, timeout)*

**context:** *any*

**subsystems:** *http*

Dynamically configures the [level](http://nginx.org/en/docs/ngx_core_module.html#error_log)
with a timeout for the current worker, and **must** be one
of the [Nginx log level constants](https://github.com/openresty/lua-nginx-module#nginx-log-level-constants).

The `timeout` specifies a number of seconds after which the log level will be
reset to the previous value. If `timeout` is `0`, the log level will be reset to the
default `log_level` setting from Nginx configuration immediately.

If this method is called again before the timeout, the log level and timeout will be overwritten.

If we don’t pass timeout to set_log_level(), it will raise a Lua error.

[Back to TOC](#table-of-contents)

resty.kong.log.get\_log\_level
----------------------------------
**syntax:** *current_level, timeout, original_level = resty.kong.log.get_log_level()*

**context:** *any*

**subsystems:** *http*

Returns the current dynamic log level, remaining timeout (in seconds),
and the original log level.

If the dynamic log level is not set or not active,
the `timeout` will be `0`.

Please see [Nginx log level constants](https://github.com/openresty/lua-nginx-module#nginx-log-level-constants)
for the possible value of `level`.

[Back to TOC](#table-of-contents)

resty.kong.upstream.set\_next\_upstream
----------------------------------
**syntax:** *res = resty.kong.upstream.set_next_upstream("http_404")*

**context:** *rewrite_by_lua&#42;, access_by_lua&#42;, balancer_by_lua&#42;*


**subsystems:** *http*

Set upstream next enablement of current request to the given string of table
argument . Global setting set by [`proxy_next_upstream`](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream) will be overwritten.

The `set_next_upstream` function supports variable length of arguments, and each argument must be one of the following strings (also defined in [`proxy_next_upstream`](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream)):
- `error`
- `timeout`
- `invalid_header`
- `http_500`
- `http_502`
- `http_503`
- `http_504`
- `http_403`
- `http_404`
- `http_429`
- `non_idempotent`
- `off`

On success, this function returns `nil`. Otherwise throw a string
describing the error will be returned.

This function can be called multiple times in the same request. Later calls override
previous ones.

[Back to TOC](#table-of-contents)


License
=======

```
Copyright 2020-2023 Kong Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

[Back to TOC](#table-of-contents)
