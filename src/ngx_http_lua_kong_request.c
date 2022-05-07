#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* name should be lowercased and preprocessed for both search functions */

/* by hash */
static ngx_str_t *search_known_header(ngx_http_request_t *r, ngx_str_t name)
{
    /* Calculate a hash of lowercased header name */
    ngx_uint_t hash = 0;
    for (size_t i = 0; i < name.len; i++) {
        hash = ngx_hash(hash, name.data[i]);
    }

    ngx_http_core_main_conf_t *cmcf =
        ngx_http_get_module_main_conf(r, ngx_http_core_module);
    ngx_http_header_t *hh =
        ngx_hash_find(&cmcf->headers_in_hash, hash, name.data, name.len);

    /* There header is unknown or is not hashed yet. */
    if (hh == NULL) {
        return NULL;
    }

    /* There header is hashed but not cached yet for some reason. */
    if (hh->offset == 0) {
        return NULL;
    }

    /* The header value was already cached in some field of the r->headers_in
        struct (hh->offset tells in which one). */
    return &((*(ngx_table_elt_t **)
        ((char *) &r->headers_in + hh->offset))->value);
}

/* linear search */
static ngx_str_t *search_unknown_header(
    ngx_http_request_t *r, ngx_str_t name, size_t search_limit)
{
    ngx_list_part_t *part = &(r->headers_in.headers.part);
    ngx_table_elt_t *header = part->elts;

    /* not limit when search_limit == 0 */
    for (size_t i = 0u; search_limit == 0 || i < search_limit; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        size_t n;
        for (n = 0u; n < name.len && n < header[i].key.len; n++) {
            u_char ch = tolower(header[i].key.data[n]);

            if (ch == '-') {
                ch = '_';
            }

            if (name.data[n] != ch) {
                break;
            }
        }

        if (n == name.len && n == header[i].key.len) {
            return &header[i].value;
        }
    }

    return NULL;
}

static ngx_str_t header_preprocess(
    ngx_http_request_t *r, ngx_str_t name)
{
    ngx_str_t ret;
    ret.data = ngx_palloc(r->pool, name.len);
    ret.len = name.len;

    for (size_t n = 0u; n < name.len; ++n) {
        u_char ch = ngx_tolower(name.data[n]);
        if (ch == '-') {
            ch = '_';
        }
        ret.data[n] = ch;
    }

    return ret;
}

/* search request header named "name" and within search_limit */
ngx_str_t * ngx_http_lua_kong_request_get_header(
        ngx_http_request_t *r, ngx_str_t name, size_t search_limit)
{
    ngx_str_t processed_name = header_preprocess(r, name);
    ngx_str_t * ret = search_known_header(r, processed_name);
    if (ret == NULL) {
        ret = search_unknown_header(r, processed_name, search_limit);
    }
    return ret;
}
