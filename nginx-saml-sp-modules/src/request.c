#include <string.h>
#include "request.h"

ngx_int_t openiam_get_method(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    if (r->main->method_name.data) {
        v->len = r->main->method_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->main->method_name.data;

    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

ngx_int_t openiam_get_url(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    char *scheme = NULL;
    char *hostname = NULL;
    char *url = NULL;
    u_char *last = NULL;
    int len = 0;
    openiam_get_scheme(r, v);
    if (v == NULL || v->not_found) {
        return NGX_OK;
    }
    len = v->len + 3;
    scheme = (char *) ngx_calloc(len, r->connection->log);
    last = ngx_copy(scheme, v->data, v->len);
    last = ngx_copy(last, "://", 3);

    openiam_get_hostname(r,v);
    if (v == NULL || v->not_found) {
        return NGX_OK;
    }
    len += v->len;
    hostname = (char *) ngx_calloc(len, r->connection->log);
    last = ngx_copy(hostname, scheme, strlen(scheme));
    last = ngx_copy(last, (const char *)v->data, v->len);

    openiam_get_uri(r, v);
    if (v == NULL || v->not_found) {
        return NGX_OK;
    }
    v->len = v->len + len;
    url = ngx_pnalloc(r->pool, v->len+1);
    last = ngx_copy(url, hostname, len);
    last = ngx_copy(last, v->data, v->len-len);
    *last = '\0';
    v->data = (u_char*)url;
    ngx_free(scheme);
    ngx_free(hostname);
    return NGX_OK;
}

ngx_int_t openiam_get_protocol(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    if (r->main->http_protocol.data) {
        v->len = r->main->http_protocol.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->main->http_protocol.data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}

ngx_int_t openiam_get_content_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    if (r->headers_out.content_encoding) {
        v->len = r->headers_out.content_encoding->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_encoding->value.data;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}

ngx_int_t openiam_get_content_length(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    u_char  *p;

    if (r->headers_in.content_length) {
        v->len = r->headers_in.content_length->value.len;
        v->data = r->headers_in.content_length->value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->reading_body) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else if (r->headers_in.content_length_n >= 0) {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%O", r->headers_in.content_length_n) - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}

ngx_int_t openiam_get_content_type(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.content_type));
}

ngx_int_t openiam_get_context_path(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_str_t                  path;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->root_lengths == NULL) {
        v->len = clcf->root.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = clcf->root.data;

    } else {
        if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                                clcf->root_values->elts)
            == NULL)
        {
            return NGX_ERROR;
        }

        if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        v->len = path.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = path.data;
    }

    return NGX_OK;
}

ngx_int_t openiam_get_server_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_str_t  s;
    u_char     addr[NGX_SOCKADDR_STRLEN];

    s.len = NGX_SOCKADDR_STRLEN;
    s.data = addr;

    if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    s.data = ngx_pnalloc(r->pool, s.len);
    if (s.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s.data, addr, s.len);

    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s.data;

    return NGX_OK;
}

ngx_int_t openiam_get_server_name(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    v->len = cscf->server_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cscf->server_name.data;

    return NGX_OK;
}

ngx_int_t openiam_get_server_port(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(r->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}

ngx_int_t openiam_get_remote_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return NGX_OK;
}

ngx_int_t openiam_get_remote_port(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(r->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}

ngx_int_t openiam_get_issecure(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("1") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "1";

        return NGX_OK;
    }

#endif
    v->len = sizeof("0") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "0";
    return NGX_OK;
}

ngx_int_t openiam_get_scheme(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("https") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "https";

        return NGX_OK;
    }

#endif

    v->len = sizeof("http") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "http";

    return NGX_OK;
}

ngx_int_t openiam_get_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_variable(r, v, offsetof(ngx_http_request_t, unparsed_uri));
}

ngx_int_t openiam_get_hostname(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.host));
}

ngx_int_t openiam_get_unparsed_cookies(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    size_t             len;
    u_char            *p, *end;
    u_char             sep = ';';
    ngx_uint_t         i, n;
    ngx_array_t       *a;
    ngx_table_elt_t  **h;
    uintptr_t          data = offsetof(ngx_http_request_t, headers_in.cookies);
    
    a = (ngx_array_t *) ((char *) r + data);

    n = a->nelts;
    h = a->elts;

    len = 0;

    for (i = 0; i < n; i++) {

        if (h[i]->hash == 0) {
            continue;
        }

        len += h[i]->value.len + 2;
    }

    if (len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (n == 1) {
        v->len = (*h)->value.len;
        v->data = (*h)->value.data;

        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (i = 0; /* void */ ; i++) {

        if (h[i]->hash == 0) {
            continue;
        }

        p = ngx_copy(p, h[i]->value.data, h[i]->value.len);

        if (p == end) {
            break;
        }

        *p++ = sep; *p++ = ' ';
    }

    return NGX_OK;
}

ngx_int_t openiam_get_accept_language(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
#if (NGX_HTTP_HEADERS) 
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.accept_language));
#else
    v->not_found = 1;
    return NGX_OK;
#endif
}
ngx_int_t openiam_get_connection(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    size_t   len;
    char    *p;

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        len = sizeof("upgrade") - 1;
        p = "upgrade";

    } else if (r->keepalive) {
        len = sizeof("keep-alive") - 1;
        p = "keep-alive";

    } else {
        len = sizeof("close") - 1;
        p = "close";
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) p;

    return NGX_OK;
}
ngx_int_t openiam_get_accept(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
#if (NGX_HTTP_HEADERS) 
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.accept));
#else
    v->not_found = 1;
    return NGX_OK;
#endif
}
// ngx_int_t get_host(ngx_http_request_t *r, ngx_http_variable_value_t *v)
// {

// }
ngx_int_t openiam_get_accept_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
#if (NGX_HTTP_GZIP)
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.accept_encoding));
#else
    v->not_found = 1;
    return NGX_OK;
#endif
}
ngx_int_t openiam_get_user_agent(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_headers(r, v, offsetof(ngx_http_request_t, headers_in.user_agent));
}

ngx_int_t openiam_get_extension(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_variable(r, v, offsetof(ngx_http_request_t, exten));
}

ngx_int_t openiam_get_args(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    return openiam_get_variable(r, v, offsetof(ngx_http_request_t, args));
}

ngx_array_t *openiam_get_locales(ngx_http_request_t *r)
{
#if (NGX_HTTP_HEADERS) 
    u_char            *start, *pos, *end;
    ngx_array_t       *langs_array;
    ngx_str_t         *lang;
    
    langs_array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
    
    if(langs_array == NULL)
    {
        return NULL;
    }
    if ( NULL != r->headers_in.accept_language ) {
        start = r->headers_in.accept_language->value.data;
        end = start + r->headers_in.accept_language->value.len;
        while (start < end) {
            while (start < end && *start == ' ') {start++; }
            pos = start;
            while (pos < end && *pos != ',' && *pos != ';') { pos++; }    

            lang = ngx_array_push(langs_array);
            lang->len = (ngx_uint_t)(pos - start);
            lang->data = ngx_palloc(r->pool, lang->len+1);
            ngx_memcpy(lang->data, start, lang->len);
            lang->data[lang->len] = '\0';
            // We discard the quality value
            if (*pos == ';') {
                while (pos < end && *pos != ',') {pos++; }
            }
            if (*pos == ',') {
                pos++;
            }
          
            start = pos;
        }
    }     
    return langs_array; 
#endif
  return NULL; 
}

ngx_int_t openiam_get_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_table_elt_t  *h;
    h = *(ngx_table_elt_t **) ((char *) r + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

ngx_int_t openiam_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}

char* toStringSafety(ngx_pool_t *pool, ngx_http_variable_value_t *v) 
{
    if (v == NULL || v->not_found) {
        return "";
    }
    char *dst = ngx_pnalloc(pool, v->len + 1);
    strncpy(dst, (const char *) (v->data), v->len);
    dst[v->len] = '\0';
    return dst;
}