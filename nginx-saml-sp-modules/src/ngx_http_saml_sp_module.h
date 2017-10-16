#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

/* Constants */
#define COOKIE_EXPIRED                      0
#define COOKIE_NOT_FOUND                    1
#define COOKIE_VALID                        2

#define COOKIE_DEF_TIME                     30

#define Enabled                             1
#define Disabled                            0

#define AUTH_NEED                           1
#define AUTH_NONEED                         0

#define AUTH_COOKIE_EXPIRATION_TIME         "OPENIAM_EXPIRATION_TIME"
#define AUTH_COOKIE_SAML_REQUEST            "OPENIAM_SAML_REQUESTER"


/* Module Configurations */
typedef struct {
    ngx_flag_t    sso_enable;         /* This enables SSO */
    ngx_flag_t    signature_enable;   /* This indicate Signature Present */
    ngx_uint_t    expiration_time;    /* The cookie expires within this time.  */
    ngx_flag_t    additional_header;  /* This indicates wheter header should be set */
    ngx_str_t     sp_name;            /* The service provider's name */
    ngx_str_t     sp_issuer;          /* The service provider's name */
    ngx_str_t     idp_logout_uri;     /* The Idp  Logout uri */
    ngx_str_t     idp_login_uri;      /* The Idp  Login uri */
    ngx_str_t     sp_logout_uri;      /* The SP's Logout uri */
    ngx_str_t     sp_login_uri;       /* The SP's Login uri */
    ngx_array_t  *cert_files;         /* Self-signed certifcate of IdP */
    ngx_array_t  *prefix_uri_set;     /* Some special uri don't need authentication */
}saml_sp_config_rec;

