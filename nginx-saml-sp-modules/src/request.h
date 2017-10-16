#include <ngx_http.h>

ngx_int_t 	 openiam_get_method(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_url(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_protocol(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_content_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_content_length(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_content_type(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_context_path(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_server_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_server_name(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_server_port(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_remote_addr(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_remote_port(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_issecure(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_scheme(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_hostname(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_accept_language(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_connection(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_accept(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_accept_encoding(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_user_agent(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t    openiam_get_unparsed_cookies(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_extension(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t 	 openiam_get_args(ngx_http_request_t *r, ngx_http_variable_value_t *v);
ngx_int_t	 openiam_get_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t 	 openiam_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_array_t *openiam_get_locales(ngx_http_request_t *r);
char 		*toStringSafety(ngx_pool_t *pool, ngx_http_variable_value_t *v);

