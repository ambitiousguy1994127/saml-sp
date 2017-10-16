#include <ngx_http.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>


#define GZIP_ENCODING                       16
// #define windowBits                          -15

#define SAMLRESPONSE_NOT_VALID              0
#define SAMLRESPONSE_VALID                  1

char 				*openiam_create_saml_request(ngx_http_request_t *r, ngx_pool_t *pool, void *module_conf);
char 				*openiam_create_raw_saml_request(ngx_http_request_t *r, ngx_pool_t *pool, void *module_conf);
char 				*openiam_escape_str(ngx_pool_t *p, const char *src);
int 				 openiam_unescape_str(const char *s, char *dec);
ngx_int_t 			 openiam_get_saml_requester(ngx_http_request_t *r, ngx_str_t *saml_requester);
ngx_int_t 			 openiam_verify_saml_response(ngx_http_request_t *r, void *module_conf, char *encoded_xmlstring);
ngx_int_t 			 openiam_validate_saml_response(ngx_http_request_t *r, xmlSecKeysMngrPtr mngr, const char *xml_content, void *module_conf);
xmlSecKeysMngrPtr 	 openiam_load_trusted_certs(ngx_http_request_t *r, ngx_array_t *cert_files);