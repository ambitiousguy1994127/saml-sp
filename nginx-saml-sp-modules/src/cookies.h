#include <ngx_core.h>

#ifndef ENCRYPT_COOKIE
	#define ENCRYPT_COOKIE
#endif 

/* Session Data Structure */
typedef struct 
{
    ngx_str_t expiration_time;        /* Expires Time */
    ngx_str_t saml_requester;         /* Saml Requester */     
}saml_sp_auth_rec;

int 	openiam_check_auth_cookie(void *r, void *module_conf);
int 	openiam_get_session_auth(void *r, saml_sp_auth_rec *sp);
int 	openiam_get_cookie(void *r, ngx_str_t *name, ngx_str_t *value);
int 	openiam_set_cookie(void *r, char *name, char *value);
int 	openiam_set_session_auth(void *r, void *module_conf, saml_sp_auth_rec *sp);
char   *myltoa(long value, char* result, int base);
long 	myatol(char *str);