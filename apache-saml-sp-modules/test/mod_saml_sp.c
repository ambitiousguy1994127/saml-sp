#include "httpd.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"

#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_base64.h"
#include "apr_random.h"

#include <time.h>
#include "mod_session.h"

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
 
#include <zlib.h>

/* Constants */
#define COOKIE_EXPIRED                      0
#define COOKIE_NOT_FOUND                    1
#define COOKIE_VALID                        2

#define COOKIE_DEF_TIME                     30

#define Enabled                             1
#define Disabled                            0

#define SAMLRESPONSE_NOT_VALID              0
#define SAMLRESPONSE_VALID                  1

#define AUTH_NEED                           1
#define AUTH_NONEED                         0

#define AUTH_COOKIE_EXPIRATION_TIME         "expires_time"
#define AUTH_COOKIE_SAML_REQUEST            "saml_requester"

#define RANDOM_STRING_LENGTH                20
#define SAMLREQUEST_ID_PREFIX               "_"

#define GZIP_ENCODING                       16
#define windowBits                          -15

/* Session Data Structure */
typedef struct 
{
  const char *expiration_time;            /* Expires Time */
}saml_sp_auth_rec;

/* Module Configurations */
typedef struct {
  int                 sso_enable;         /* This enables SSO */
  int                 signature_enable;   /* This indicate Signature Present */
  int                 expiration_time;    /* The cookie expires within this time.  */
  int                 additional_header;  /* This indicates wheter header should be set */
  const char          *sp_name;           /* The service provider's name */
  const char          *sp_issuer;         /* The service provider's name */
  const char          *idp_logout_uri;    /* The Idp  Logout uri */
  const char          *idp_login_uri;     /* The Idp  Login uri */
  const char          *sp_logout_uri;     /* The SP's Logout uri */
  const char          *sp_login_uri;      /* The SP's Login uri */
  apr_array_header_t  *cert_files;        /* Self-signed certifcate of IdP */
  apr_array_header_t  *prefix_uri_set;    /* Some special uri don't need authentication */
}saml_sp_config_rec;

static char *openiam_escape_str(apr_pool_t *p, const char *src);

static apr_status_t (*ap_session_load_fn) (request_rec *r, session_rec ** z)
                                                                     = NULL;
static apr_status_t (*ap_session_get_fn)(request_rec *r, session_rec * z,
                                const char *key, const char **value) = NULL;
static apr_status_t (*ap_session_set_fn)(request_rec *r, session_rec *z,
                                const char *key, const char *value)  = NULL;
static const char* openiam_set_sso_enable(cmd_parms *cmd, void *config, 
                                const char *arg);
static const char* openiam_set_signature_enable(cmd_parms *cmd, void *config, 
                                const char *arg);
static const char* openiam_set_cookie_expiration_time(cmd_parms * cmd, 
                                void *config, const char *expiration_time);
static const char* openiam_set_additional_header(cmd_parms *cmd, void *config, 
                                const char *arg);
static const char* openiam_set_sp_name(cmd_parms *cmd, 
                                void *config, const char *sp_name);
static const char* openiam_set_sp_issuer(cmd_parms *cmd, 
                                void *config, const char *sp_issuer);
static const char* openiam_set_idp_logout_uri(cmd_parms *cmd, 
                                void *config, const char *idp_logout_uri);
static const char* openiam_set_idp_login_uri(cmd_parms *cmd, 
                                void *config, const char *idp_login_uri);
static const char* openiam_set_sp_logout_uri(cmd_parms *cmd, 
                                void *config, const char *sp_logout_uri);
static const char* openiam_set_sp_login_uri(cmd_parms *cmd, 
                                void *config, const char *sp_login_uri);
static const char* openiam_set_cert_file(cmd_parms *cmd, 
                                void *config, const char *cert_file);
static const char* openiam_set_prefix_uri(cmd_parms *cmd, 
                                void *config, const char *prefix_uri);
static void* openiam_create_saml_sp_dir_config(apr_pool_t *p, char *d);

static int openiam_check_auth_cookie(request_rec *r);

static apr_status_t openiam_get_session_auth(request_rec *r, 
                                saml_sp_auth_rec *sp);
static apr_status_t openiam_set_session_auth(request_rec *r, 
                                saml_sp_auth_rec *sp);
static apr_status_t openiam_get_saml_requester(request_rec *r, 
                                const char **saml_requester);
static apr_status_t openiam_set_saml_requester(request_rec *r, 
                                const char *saml_requester);
static apr_status_t openiam_check_request(request_rec *r);

#ifdef ADD_X509_TO_SAMLREQUEST
static int opeiniam_sign_file();
#endif 

static char* openiam_create_saml_request(request_rec *r);

static int openiam_verify_saml_response(request_rec *r,
                                const char *encoded_xmlstring);
static xmlNodePtr findNodeByName(xmlNodePtr rootnode,
                                const xmlChar *nodename);
static xmlSecKeysMngrPtr openiam_load_trusted_certs(request_rec *r,
                                              apr_array_header_t *cert_files);
static int openiam_validate_saml_response(request_rec *r, 
                                xmlSecKeysMngrPtr mngr, const char *xml_file);
static int openiam_saml_sp_initialize_module(apr_pool_t *pconf, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s);
static apr_status_t openiam_lib_terminate(void *data);

static void register_hooks(apr_pool_t *pool);

static const command_rec saml_sp_cmds[] = {
  AP_INIT_TAKE1("OPENIAM_SSOEnable", openiam_set_sso_enable, NULL, 
          ACCESS_CONF, "Enable or Disable this module."),

  AP_INIT_TAKE1("OPENIAM_SignatureEnable", openiam_set_signature_enable, NULL, 
          ACCESS_CONF, "Indicate whether signature is included in SAMLResponse."),

  AP_INIT_TAKE1("OPENIAM_ExpirationTime", openiam_set_cookie_expiration_time,
          NULL, ACCESS_CONF, "Auth Cookie expires in this period."),

  AP_INIT_TAKE1("OPENIAM_AddtionalHeader", openiam_set_additional_header, 
          NULL, ACCESS_CONF, "Set additional request header if it is enabled."),

  AP_INIT_TAKE1("OPENIAM_SP_Name", openiam_set_sp_name, NULL,
          ACCESS_CONF, "Specify the name of service provider."),

  AP_INIT_TAKE1("OPENIAM_SP_Issuer", openiam_set_sp_issuer, NULL,
          ACCESS_CONF, "Specify unique identifier of Idp."),

  AP_INIT_TAKE1("OPENIAM_IDP_LogoutURI", openiam_set_idp_logout_uri, NULL,
          ACCESS_CONF, "Specify the log out uri of the Identity Provider."),

  AP_INIT_TAKE1("OPENIAM_IDP_LoginURI", openiam_set_idp_login_uri, NULL,
          ACCESS_CONF, "Specify the log in uri of the Identity Provider."),

  AP_INIT_TAKE1("OPENIAM_SP_LogoutURI", openiam_set_sp_logout_uri, NULL,
          ACCESS_CONF, "Specify the log out uri of the Service Provider."),

  AP_INIT_TAKE1("OPENIAM_SP_LoginURI", openiam_set_sp_login_uri, NULL,
          ACCESS_CONF, "Specify the log in uri of the Service Provider."),
  
  AP_INIT_ITERATE("OPENIAM_Cert_File", openiam_set_cert_file, NULL,
          ACCESS_CONF, "Certificate file of Identity Provider."),

  AP_INIT_ITERATE("OPENIAM_PrefixURI", openiam_set_prefix_uri, NULL,
          ACCESS_CONF, "Specify uris that don't need authentication."),

  {NULL}
};


module AP_MODULE_DECLARE_DATA saml_sp_module = 
{
  STANDARD20_MODULE_STUFF, 
  openiam_create_saml_sp_dir_config, 
  NULL, 
  NULL, 
  NULL, 
  saml_sp_cmds, 
  register_hooks
};


/* escape functions is from mod_rewrite.c */

static const char c2x_table[] = "0123456789ABCDEF";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
  what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
  *where++ = prefix;
  *where++ = c2x_table[what >> 4];
  *where++ = c2x_table[what & 0xf];
  return where;
}

static char *openiam_escape_str(apr_pool_t *p, const char *src)
{
  char *copy = apr_palloc(p, 3 * strlen(src) + 3);
  const unsigned char *s = (const unsigned char *)src;
  unsigned char *d = (unsigned char *)copy;
  unsigned c;
  while ( (c = *s) )
  {
    if ( apr_isalnum(c) || c == '_'  || c == '-' || c == '.' || c == '~' )
      *d++ = c;
    else if ( c == ' ' )
      *d++ = '+';
    else
      d = c2x(c, '%', d);
    ++s;
  }

  *d = '\0';
  return copy;
}

static const char *openiam_set_sso_enable(cmd_parms *cmd, 
                                void *config, const char *arg)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  if (!strcasecmp(arg, "on"))
    conf->sso_enable = Enabled;
  return NULL;
}

static const char *openiam_set_signature_enable(cmd_parms *cmd, 
                                void *config, const char *arg)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  if (!strcasecmp(arg, "on"))
    conf->signature_enable = Enabled;
  return NULL;
}

static const char *openiam_set_cookie_expiration_time(cmd_parms *cmd, 
                                void *config, const char *expiration_time)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->expiration_time = atol(expiration_time);
  return NULL;
}

static const char* openiam_set_additional_header(cmd_parms *cmd, void *config, 
                                const char *arg)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  if (!strcasecmp(arg, "on"))
    conf->additional_header = Enabled;
  return NULL; 
}

static const char *openiam_set_sp_name(cmd_parms *cmd, 
                                void *config, const char *sp_name)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->sp_name = sp_name;
  return NULL;
}

static const char *openiam_set_sp_issuer(cmd_parms *cmd, 
                                void *config, const char *sp_issuer)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->sp_issuer = sp_issuer;
  return NULL;
}

static const char *openiam_set_idp_logout_uri(cmd_parms *cmd, 
                                void *config, const char *idp_logout_uri)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->idp_logout_uri = idp_logout_uri;
  return NULL;
}

static const char *openiam_set_idp_login_uri(cmd_parms *cmd, 
                                void *config, const char *idp_login_uri)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->idp_login_uri = idp_login_uri;
  return NULL;
}

static const char *openiam_set_sp_logout_uri(cmd_parms *cmd, 
                                void *config, const char *sp_logout_uri)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->sp_logout_uri = sp_logout_uri;
  return NULL;
}

static const char *openiam_set_sp_login_uri(cmd_parms *cmd, 
                                void *config, const char *sp_login_uri)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  conf->sp_login_uri = sp_login_uri;
  return NULL;
}

static const char* openiam_set_cert_file(cmd_parms *cmd, 
                                void *config, const char *cert_file)
{
 saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  *(const char**)apr_array_push(conf->cert_files) = cert_file;
  return NULL;
}

static const char *openiam_set_prefix_uri(cmd_parms *cmd, 
                                void *config, const char *prefix_uri)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) config;
  char *prefix = apr_pstrdup(cmd->pool, prefix_uri);
  int prefix_len = strlen(prefix_uri);
  if ((prefix[0] == '/') &&
    (prefix[prefix_len - 1] == '*' || prefix[prefix_len - 1] == '/'))
  {
      if (prefix[prefix_len - 2] == '/')
          prefix[prefix_len - 1] = 0;
      *(const char**)apr_array_push(conf->prefix_uri_set) = prefix;
  }
  return NULL;
}

static void *openiam_create_saml_sp_dir_config(apr_pool_t *p, char *d)
{
  saml_sp_config_rec *conf = apr_pcalloc(p, sizeof(*conf));
  conf->sso_enable        = Disabled;
  conf->signature_enable  = Disabled;
  conf->expiration_time   = COOKIE_DEF_TIME;
  conf->additional_header = Disabled;
  conf->sp_name           = NULL;
  conf->sp_issuer         = NULL;
  conf->idp_logout_uri    = NULL;
  conf->idp_login_uri     = NULL;
  conf->sp_logout_uri     = NULL;
  conf->sp_login_uri      = NULL;
  conf->cert_files        = apr_array_make(p, 1, sizeof(const char*));
  conf->prefix_uri_set    = apr_array_make(p, 1, sizeof(const char*));

  return (void *)conf;
}

/**
 * openiam_check_auth_cookie:
 * @r: The current request pointer.
 *
 * Check the auth cookie from the browser.
 * Auth cookie consists of expiration time and rich user information
 * Compare this expiration time with server time.
 *
 * Return values:
 * COOKIE_VALID:      if the cookie is valid
 * COOKIE_EXPIRED:    if the cookie expires
 * COOKIE_NOT_FOUND:  if not cookie is found
 */
static int openiam_check_auth_cookie(request_rec *r)
{
  int rv = COOKIE_NOT_FOUND;
  long expires = 0; 
  long now = apr_time_now();
  saml_sp_auth_rec *sp = apr_pcalloc(r->pool, sizeof(saml_sp_auth_rec));
  openiam_get_session_auth(r, sp);

  if (sp->expiration_time)
  {
    expires = apr_atoi64(sp->expiration_time);
    if (expires && expires > now) {
      openiam_set_session_auth(r, sp);
      rv = COOKIE_VALID;
    } else {
      openiam_set_session_auth(r, NULL);
      openiam_set_saml_requester(r, NULL);
      rv = COOKIE_EXPIRED;
    }
  } else {
    rv = COOKIE_NOT_FOUND;
  }
  return rv;
}

/**
 * openiam_get_session_auth:
 * @r:  The current request pointer
 * @sp: The pointer of the session data structure into which user data is stored
 *
 * Get the user information from session
 *
 * Return Values:
 * APR_SUCCESS:  in any cases
 */
static apr_status_t openiam_get_session_auth(request_rec *r, 
                                saml_sp_auth_rec *sp)
{
  session_rec *z = NULL;

  ap_session_load_fn(r, &z);

  ap_session_get_fn(r, z, AUTH_COOKIE_EXPIRATION_TIME, &sp->expiration_time);
  
  return APR_SUCCESS;
}

/**
 * openiam_set_session_auth:
 * @r:  The current request pointer
 * @sp: The pointer of the session data
 *
 * Set the user information into session
 *
 * Return Values:
 * APR_SUCCESS: in any cases
 */
static apr_status_t openiam_set_session_auth(request_rec *r, 
                                saml_sp_auth_rec *sp)
{
  session_rec *z = NULL;
  saml_sp_config_rec *conf = (saml_sp_config_rec *)
                  ap_get_module_config(r->per_dir_config, &saml_sp_module);
  
  ap_session_load_fn(r, &z);

  if (!sp)
  {
    ap_session_set_fn(r, z, AUTH_COOKIE_EXPIRATION_TIME, NULL);
  } else {
    long now = apr_time_now();
    now += 60 * APR_USEC_PER_SEC * conf->expiration_time;
    sp->expiration_time = apr_ltoa(r->pool, now);

    ap_session_set_fn(r, z, AUTH_COOKIE_EXPIRATION_TIME, 
                                            sp->expiration_time);
  }
  return APR_SUCCESS;
}

/**
 * openiam_set_saml_requester:
 * @r:              The current request pointer
 * @saml_requester: The pointer of the string that indicates saml requester
 *
 * Set the samlRequester id in session
 * This function is called after samlrequest is made.
 *
 * Return Values:
 * APR_SUCCESS: in any cases
 */
static apr_status_t openiam_set_saml_requester(request_rec *r, 
                                const char *saml_requester)
{
  session_rec *z = NULL;
  
  ap_session_load_fn(r, &z);

  if (!saml_requester)
  {
    ap_session_set_fn(r, z, AUTH_COOKIE_SAML_REQUEST, NULL);
  } else {
    ap_session_set_fn(r, z, AUTH_COOKIE_SAML_REQUEST, 
                                            saml_requester);
  }
  return APR_SUCCESS;
}

/**
 * openiam_get_saml_requester:
 * @r:              The current request pointer
 * @saml_requester: The pointer of the string that indicates saml requester
 *
 * Get the samlRequester id from session
 * SamlRequest id should be used in validating saml response
 *
 * Return Values:
 * APR_SUCCESS: in any cases
 */
static apr_status_t openiam_get_saml_requester(request_rec *r, 
                                const char **saml_requester)
{
  session_rec *z = NULL;

  ap_session_load_fn(r, &z);

  ap_session_get_fn(r, z, AUTH_COOKIE_SAML_REQUEST, saml_requester);
  
  return APR_SUCCESS;
}

/**
 * openiam_check_request:
 * @r: The current request pointer
 *
 * This is registered as call back function of 
 * ap_hook_check_access hook
 *
 * Senario 1
 *   When the user hit logout uri,
 *    - clear the cookie and then redirect the user to idp logout page
 * Senario 2
 *   When the user make request to non-protected uri
 *    - The request is permitted wheter the user has valid auth cookie or not
 * Senario 3
 *   When the user make request to protected uri service provider, 
 *   it validate authCookie from the browser
 *    - If the user has valid authenticated cookie, the request is permitted.
 *    - If not, it redirect user to idp to let them issue SAMLResponse and validate it.
 *      If the samlResponse is valid, the original request is permitted.
 */
static apr_status_t openiam_check_request(request_rec *r)
{
  int auth_need = AUTH_NONEED;
  saml_sp_config_rec *conf = (saml_sp_config_rec *) 
                  ap_get_module_config(r->per_dir_config, &saml_sp_module);  
  char *full_url = ap_construct_url(r->pool, r->uri, r);
  if (conf->sso_enable) {
    if (!strcasecmp(full_url, conf->sp_logout_uri)) {
      /* 
       * Check the request uri whether it matches with logout uri
       * If the requested uri matches with the logout uri in service provider
       * redirect the user to idp logout uri noted in configuration
       * and remove authentication cookie at that time
       */
      int status = openiam_check_auth_cookie(r);
      if (status == COOKIE_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10000)
            "Warning: Unauthenticated user hit the logout uri.");
      } else if(status == COOKIE_EXPIRED) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10000)
            "Warning: User with expired cookie hit the logout uri.");
      }
      openiam_set_session_auth(r, NULL);
      openiam_set_saml_requester(r, NULL);
      apr_table_set(r->headers_out, "Location", conf->idp_logout_uri);
      return HTTP_MOVED_PERMANENTLY;  
    } if(!strcasecmp(full_url, conf->sp_login_uri)) {
      int status = openiam_check_auth_cookie(r);
      if (status != COOKIE_VALID) {
        if (!strcasecmp(r->method, "POST")) {
          /* Ignore other request with no SAMLResponse and RelayState */
          
          apr_array_header_t  *pairs        = NULL;    
          const char          *relaystate   = NULL;
          char                *buffer       = NULL;
          apr_off_t           len           = 0;
          apr_size_t          size          = 0;
          int                 xml_valid     = SAMLRESPONSE_NOT_VALID;
          int                 response_set  = Disabled;
          int                 res           = 0;
          
          res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
          if (res != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      APLOGNO(10002) "Error: Error occured while parsing POST data");
            return res;
          }
                
          while (pairs && !apr_is_empty_array(pairs)) {
            ap_form_pair_t *pair = (ap_form_pair_t *) 
                                        apr_array_pop(pairs);
            if (!strcasecmp(pair->name, "RelayState")) {
              apr_brigade_length(pair->value, 1, &len);
              size = (apr_size_t) len;
              buffer = apr_palloc(r->pool, size + 1);
              apr_brigade_flatten(pair->value, buffer, &size);
              buffer[len] = 0;
              if(len != 0)
                relaystate = buffer;
              else
                relaystate = conf->sp_login_uri;
            } else if (!strcasecmp(pair->name, "SAMLResponse") && 
                    conf->signature_enable == Enabled) {
              /* 
               * Get saml response from SAMLResponse
               * parse it using apr xml parser function
               */
              response_set = Enabled;
              apr_brigade_length(pair->value, 1, &len);
              size = (apr_size_t) len;
              buffer = apr_palloc(r->pool, size + 1);
              apr_brigade_flatten(pair->value, buffer, &size);
              buffer[len] = 0;
              xml_valid = openiam_verify_saml_response(r, buffer);
            }
          }
          if(response_set == Disabled && conf->signature_enable == Enabled){
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, 
                      APLOGNO(10023) "Error: No SAMLResponse from IdP");
            return HTTP_BAD_REQUEST;
          }
          if ((xml_valid == SAMLRESPONSE_VALID && 
                                        conf->signature_enable == Enabled) || 
              (xml_valid == SAMLRESPONSE_NOT_VALID && 
                                        conf->signature_enable == Disabled))
          {
            saml_sp_auth_rec *sp = apr_pcalloc(r->pool, 
                                          sizeof(saml_sp_auth_rec));
            openiam_set_session_auth(r, sp);
            ap_log_rerror(APLOG_MARK, LOG_NOTICE, 0, r, 
                    APLOGNO(10027) "Notice: Set Auth Cookie successfully");
            apr_table_set(r->headers_out, "Location", relaystate);
            return HTTP_MOVED_PERMANENTLY;
            
          } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      APLOGNO(10004) "Error: SAMLResponse is not valid");
            return HTTP_BAD_REQUEST;
          }
        } else {
          auth_need = AUTH_NEED;
        }
      } else {
        auth_need = AUTH_NONEED;
      }
    } else {
      int status, i;
      /* 
       * Check the request uri whether it matches with prefix uri in conf
       * If the requested uri matches with one of prefix uris in conf
       * no need to check authenticate cookie
       */
      for (i = 0; i < conf->prefix_uri_set->nelts; i++) {
        const char *s = ((const char**)conf->prefix_uri_set->elts)[i];
        if (strstr(full_url, s))
            return OK;
      }
      status = openiam_check_auth_cookie(r);
      if (status == COOKIE_VALID) {
        /* 
         * This uri is accessible b/c current user has valid cookie
         * - renew auth cookie.
         * - set additional headers and/or cookies from http session if exists
         * - proceed to this uri
         */
        auth_need = AUTH_NONEED;
      } else {
        /* 
         * No Auth Cookie 
         * Generate Saml Request and redirect user to Idp
         * SamlRequest should be Base64Encoded
         * and it should be put on argument named SAMLRequest on request url 
         */
        auth_need = AUTH_NEED;
      }
    }

    if (auth_need == AUTH_NEED) {
      const char *request_url       = NULL;
      const char *relaystate        = NULL;
      char       *raw_xmlstring     = NULL;
      apr_size_t raw_xmlstring_len  = 0;
      char       *deflate_xmlstring = NULL;
      apr_size_t deflate_size       = 0;
      char       *encoded_xmlstring = NULL;
      apr_size_t size               = 0;
      z_stream   *defstream         = NULL;
      int        zRC                = 0; 
      
      raw_xmlstring = openiam_create_saml_request(r);

      /* Deflate xmlstring first */
      defstream = apr_palloc(r->pool, sizeof(z_stream));

      raw_xmlstring_len     = strlen(raw_xmlstring);
      deflate_size          = raw_xmlstring_len + 10; /* gzip header is 10 bytes */
      deflate_xmlstring     = apr_palloc(r->pool, deflate_size);
      defstream->zalloc     = Z_NULL;
      defstream->zfree      = Z_NULL;
      defstream->opaque     = Z_NULL;

      defstream->avail_in   = (uInt)raw_xmlstring_len; /* compress only chars, no need to compress zero at the end of string */
      defstream->next_in    = (Bytef *)raw_xmlstring;
      defstream->avail_out  = (uInt)deflate_size;
      defstream->next_out   = (Bytef *)deflate_xmlstring;

      zRC = deflateInit2(defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                                  windowBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY);
      if (zRC != Z_OK) {
        deflateEnd(defstream);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      APLOGNO(10028) "Unable to init ZLib");
        return !OK;
      }
      deflate(defstream, Z_FINISH);
      deflateEnd(defstream);

      /* Base64 Encode */
      size = (apr_size_t) defstream->total_out;
      encoded_xmlstring = apr_palloc(r->pool,
                        apr_base64_encode_len(size));
      apr_base64_encode(encoded_xmlstring, deflate_xmlstring, size);

      if (!strcmp(r->method, "POST")) {
        relaystate = apr_table_get(r->headers_in, "Referer");
        if(!relaystate)
          relaystate = full_url;
      } else {
        relaystate = full_url;
      }
      request_url = apr_psprintf(r->pool, 
                              "%s?SAMLRequest=%s&RelayState=%s",
                              conf->idp_login_uri,
                              openiam_escape_str(r->pool, encoded_xmlstring),
                              relaystate);
      apr_table_set(r->headers_out, "Location", request_url);
      return HTTP_MOVED_TEMPORARILY;
    }
  }
  return OK;
}

#ifdef ADD_X509_TO_SAMLREQUEST
static int opeiniam_sign_file()
{
  return 0;
}
#endif

/**
 * openiam_create_saml_request:
 * @r: The current request pointer
 *
 * Create the SAML Reqeuest as XML format first and convert it into string
 *
 * Return Values
 * raw_xmlstring: String of generated SAML Request
 */
static char* openiam_create_saml_request(request_rec *r)
{
  char            *raw_xmlstring  = NULL;
  xmlChar         *s              = NULL;
  const char      *m_instanttime  = NULL;
  unsigned char   *m_randomvalue  = NULL;
  char            *m_randomstring = NULL;
  char            *m_mixedstring  = NULL;
  apr_random_t    *prng           = NULL;

  xmlDocPtr       doc             = NULL;
  xmlNodePtr      root            = NULL;
  xmlNodePtr      node_issuer     = NULL;
  xmlNodePtr      node_namepolicy = NULL;
  xmlNsPtr        ns_saml2p       = NULL;
  xmlNsPtr        ns_saml2        = NULL;
  apr_time_exp_t  tm;

  int             length          = 0;
  int             i;

  saml_sp_config_rec *conf = (saml_sp_config_rec *) 
                  ap_get_module_config(r->per_dir_config, &saml_sp_module);
  /* First create the AuthnRequest */
  doc = xmlNewDoc((const xmlChar*)("1.0"));
  if (doc == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    APLOGNO(10029) "Error occured while creating xml doc");
    return NULL;
  }

  apr_pool_cleanup_register(r->pool, doc, (void *) xmlFreeDoc, apr_pool_cleanup_null);

  /* Compose AuthnRequest as Root */
  root = xmlNewNode(NULL, (const xmlChar*)("AuthnRequest"));
  if (root == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    APLOGNO(10030) "Error occured while AuthnRequest node");
    return NULL; 
  }

  xmlDocSetRootElement(doc, root);

  /* Set Namespaces as attributes */
  ns_saml2p   = xmlNewNs (root, 
                          (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:protocol"),
                          (const xmlChar*)("saml2p"));
  if (ns_saml2p == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    APLOGNO(10031) "Error occured while saml2p Namespaces");
    return NULL;  
  }
  xmlSetNs(root,ns_saml2p);
  
  /* Set AuthnReqest Attributes */
  xmlNewProp(root, (const xmlChar*)("AssertionConsumerServiceURL"), 
                                (const xmlChar*)(conf->sp_login_uri));

  /* Generate the time string */
  apr_time_exp_gmt(&tm, apr_time_now());
  m_instanttime = apr_psprintf(r->pool,
              "%02d%02d-%02d-%02dT%02d:%02d:%02dZ", (tm.tm_year / 100) + 19,
              (tm.tm_year % 100), tm.tm_mon+1, tm.tm_mday,
              tm.tm_hour, tm.tm_min, tm.tm_sec);
  
  /* Generate the secure random bytes string */
  prng = apr_random_standard_new(r->pool);
  while (apr_random_secure_ready(prng) == APR_ENOTENOUGHENTROPY) {
    unsigned char randbuf[256];
    apr_generate_random_bytes(randbuf, 256);
    apr_random_add_entropy(prng, randbuf, 256);
  }
  m_randomvalue = apr_palloc(r->pool, RANDOM_STRING_LENGTH);
  apr_random_secure_bytes(prng, m_randomvalue, RANDOM_STRING_LENGTH);
  
  /* Convert bytes to string */
  m_randomstring = apr_palloc(r->pool,
                RANDOM_STRING_LENGTH * 2 + 1);
  for(i = 0; i < RANDOM_STRING_LENGTH; i++)
  {
    sprintf(m_randomstring+(i*2), "%02x", m_randomvalue[i]);
  }
  m_randomstring[RANDOM_STRING_LENGTH * 2] = '\0';
  

  /* Set Secure Time value to IssueInstant attribute */  
  xmlNewProp(root, (const xmlChar*)("IssueInstant"), (const xmlChar*)(m_instanttime));

  /* Set Secure Random value to ID attribute */  
  m_mixedstring = apr_pstrcat(r->pool, 
                                SAMLREQUEST_ID_PREFIX, m_randomstring, NULL);
  xmlNewProp(root, (const xmlChar*)("ID"), (const xmlChar*)m_mixedstring);
  
  /* Add SAMLRequest ID in session */
  openiam_set_saml_requester(r, m_mixedstring);

  /* Set Provider Name which configurable in conf file */  
  xmlNewProp(root, (const xmlChar*)("ProviderName"), (const xmlChar*)(conf->sp_name));

  /* Set Other Attributes */  
  xmlNewProp(root,  (const xmlChar*)("ProtocolBinding"), 
                    (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
  xmlNewProp(root, (const xmlChar*)("Version"), (const xmlChar*)("2.0"));


  /* Add Issuer Node into root */
  node_issuer = xmlNewChild(root, NULL, (const xmlChar*)("Issuer"), 
                                        (const xmlChar*)(conf->sp_issuer));

  /* Set Namespaces as attributes */
  ns_saml2    = xmlNewNs (node_issuer, 
                          (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:assertion"),
                          (const xmlChar*)("saml2"));

  if (ns_saml2 == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    APLOGNO(10032) "Error occured while saml2 Namespaces");
    return NULL;  
  }

  xmlSetNs(node_issuer,ns_saml2);

  /* Add Name Policy Node into root */
  node_namepolicy = xmlNewChild(root, NULL, (const xmlChar*)("NameIDPolicy"), NULL);
  xmlNewProp(node_namepolicy, (const xmlChar*)("AllowCreate"), (const xmlChar*)("true"));
  xmlNewProp(node_namepolicy, 
            (const xmlChar*)("Format"), 
            (const xmlChar*)("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"));

  #ifdef ADD_X509_TO_SAMLREQUEST
    /* 
     * Theoritically the xmlrequest should be signed with X.509
     * For now we adopted that send Certificate via X509Certificate node
     * Following functions perform this functionality
     */
      opeiniam_sign_file();
  #endif  /* ADD_X509_TO_SAMLREQUEST */

  xmlDocDumpFormatMemoryEnc(doc, &s, &length, "UTF-8", 0);
  raw_xmlstring = (char *)s;
  if ( raw_xmlstring == NULL || length == 0 ) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    APLOGNO(10033) "Error occured while encoding UTC-8");
    return NULL;
  } else {
    apr_pool_cleanup_register(r->pool, s, (void *) xmlFree, apr_pool_cleanup_null);
  }
  
  return raw_xmlstring;
}


/**
 * findNodeByName: 
 * @rootnode: The node pointer of which the search is applied
 * @nodename: The node name
 * 
 * Find sub-node by name. This is recursive function.
 *
 * Return Values:
 * node:    the pointer of the node with such name
 * NULL:    if no node with such name
 */
static xmlNodePtr findNodeByName(xmlNodePtr rootnode, const xmlChar *nodename)
{
    xmlNodePtr node = rootnode;
    if(node == NULL){
        return NULL;
    }

    while(node != NULL){

        if(!xmlStrcmp(node->name, nodename)){
            return node; 
        }
        else if (node->children != NULL) {
            xmlNodePtr intNode =  findNodeByName(node->children, nodename);
            if(intNode != NULL) {
                return intNode;
            }
        }
        node = node->next;
    }
    return NULL;
}

/**
 * openiam_verify_saml_response:
 * @r:                  The Current Request Pointer
 * @encoded_xmlstring:  Base64EncodedSamlResponseXML from IDP as string
 *
 * Verify the SAMLResponse from the IdP
 * Initialize the XML Security Library and load certificate files
 * to verify the samlresponse
 *
 * Return Values
 * SAMLRESPONSE_VALID:      if the SAMLResponse is valid
 * SAMLRESPONSE_NOT_VALID:  if the SAMLResponse is not valid
 */
static int openiam_verify_saml_response(request_rec *r, 
                                        const char *encoded_xmlstring)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *) 
                  ap_get_module_config(r->per_dir_config, &saml_sp_module);

  xmlSecKeysMngrPtr mngr;
  int res = SAMLRESPONSE_NOT_VALID;
  char *xml_content;
  size_t decoded_len;  
  /* Decode Base64 first */

  decoded_len = apr_base64_decode_len(encoded_xmlstring);
  if(!decoded_len)
    return SAMLRESPONSE_NOT_VALID;
  xml_content = apr_palloc(r->pool, decoded_len);
  decoded_len = apr_base64_decode(xml_content, encoded_xmlstring);
  /* create keys manager and load trusted certificates */
  mngr = openiam_load_trusted_certs(r, conf->cert_files);
  if(mngr == NULL) {
      return SAMLRESPONSE_NOT_VALID;
  }

  /* verify saml */
  res = openiam_validate_saml_response(r, mngr, xml_content);

  if(res != SAMLRESPONSE_VALID) {
      return SAMLRESPONSE_NOT_VALID;
  }    

  return SAMLRESPONSE_VALID;
}

/**
 * openiam_load_trusted_certs:
 * @cert_files:         the list of certificate filenames.
 *
 * Creates simple keys manager and load trusted certificates from PEM #files.
 * The caller is responsible for destroing returned keys manager using
 * @xmlSecKeysMngrDestroy.
 *
 * Return Values
 * NULL:  if an error occurs
 * mngr:  The pointer to newly created keys manager
 */
static 
xmlSecKeysMngrPtr openiam_load_trusted_certs(request_rec *r, 
                                            apr_array_header_t *cert_files)
{
  xmlSecKeysMngrPtr mngr;
  int i;
      
  /* create and initialize keys manager, we use a simple list based
   * keys manager, implement your own xmlSecKeysStore klass if you need
   * something more sophisticated 
   */
  mngr = xmlSecKeysMngrCreate();
  if(mngr == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10024)
          "Error: failed to create keys manager");
    return(NULL);
  }
  if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10025)
          "Error: failed to initialize keys manager");
    xmlSecKeysMngrDestroy(mngr);
    return(NULL);
  }
  for(i = 0; i < cert_files->nelts; ++i) {
    /* load trusted cert */
    const char *file = ((const char**)cert_files->elts)[i];
    if(xmlSecCryptoAppKeysMngrCertLoad(mngr, file, xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10026)
            "Error: failed to load pem certificate from %s", file);  
      xmlSecKeysMngrDestroy(mngr);
      return(NULL);
    }
  }

  return(mngr);
}

/** 
 * openiam_verify_saml_response:
 * @mngr:               the pointer to keys manager.
 * @xml_file:           the signed XML file name.
 *
 * Validate the SAMLResponse
 * 1. Validate the Signature by its certificate file in cofiguration file
 * 2. Validate the Timestamp
 *
 * Return Values
 * SAMLRESPONSE_VALID:      if the SAMLResponse is valid
 * SAMLRESPONSE_NOT_VALID:  if the SAMLResponse is not valid
 */
static int openiam_validate_saml_response(request_rec *r, 
                            xmlSecKeysMngrPtr mngr, const char *xml_content)
{
  xmlDocPtr           doc               = NULL;
  xmlNodePtr          root              = NULL;
  xmlNodePtr          node              = NULL;
  xmlNodePtr          conditions        = NULL;
  xmlNodePtr          NameID            = NULL;
  xmlSecDSigCtxPtr    dsigCtx           = NULL;
  xmlAttrPtr          attr              = NULL;
  xmlAttrPtr          id_attr           = NULL;
  xmlChar             *id               = NULL;
  int                 res               = SAMLRESPONSE_NOT_VALID;
  const char          *notBefore        = NULL;
  const char          *notOnOrAfter     = NULL;
  const char          *m_InResponseTo   = NULL;
  const char          *m_samlRequester  = NULL;
  struct tm           tm_notBefore, tm_notOnOrAfter;
  time_t              t_notBefore, t_notOnOrAfter;
  apr_time_t          now, apr_t_notBefore, apr_t_notOnOrAfter;
  
  saml_sp_config_rec *conf = (saml_sp_config_rec *) 
                  ap_get_module_config(r->per_dir_config, &saml_sp_module);
  /* load file */
  doc = xmlReadMemory(xml_content, strlen(xml_content), "noname.xml", NULL, 0);
  if (doc == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10011)
            "Error: Failed to parse document");
    goto done;
  }

  apr_pool_cleanup_register(r->pool, doc, (void *) xmlFreeDoc, apr_pool_cleanup_null);
  
  root = xmlDocGetRootElement(doc);
  /* Validate InResponseTo */
  m_InResponseTo = (const char*)xmlGetProp(root, 
                                          (const xmlChar*)("InResponseTo"));
  openiam_get_saml_requester(r, &m_samlRequester);
  if(m_InResponseTo == NULL || m_samlRequester == NULL)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10017)
              "Error: No matching with InResponseTo");
    goto done;
  } else {
    if(apr_strnatcmp(m_InResponseTo, m_samlRequester))
    {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10017)
              "Error: No matching with InResponseTo");
      goto done;
    }
  }
  /* Validate date */
  conditions = findNodeByName(root, (const xmlChar*)("Conditions"));
  if(conditions == NULL )
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10017)
            "Error: No Condtion Node in SAMLResponse");
    goto done;
  }
  notBefore = (const char*)xmlGetProp(conditions, 
                                          (const xmlChar*)("NotBefore"));
  if(notBefore == NULL)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10018)
            "Error: No notBefore Attribute in SAMLResponse");
    goto done;
  }
  notOnOrAfter = (const char*)xmlGetProp(conditions, 
                                          (const xmlChar*)("NotOnOrAfter"));
  if(notOnOrAfter == NULL)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10019)
            "Error: No notOnOrAfter Attribute in SAMLResponse");
    goto done;
  }

  strptime(notBefore, "%Y-%m-%dT%H:%M:%S", &tm_notBefore);
  strptime(notOnOrAfter, "%Y-%m-%dT%H:%M:%S", &tm_notOnOrAfter);
  t_notBefore = timegm(&tm_notBefore);
  t_notOnOrAfter = timegm(&tm_notOnOrAfter);

  apr_time_ansi_put(&apr_t_notBefore, t_notBefore);
  apr_time_ansi_put(&apr_t_notOnOrAfter, t_notOnOrAfter);
  

  /* Compare the date */
  now = apr_time_now();
  if(apr_t_notBefore > now)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10020)
            "Error: Timestamp error. notBefore Timestamp is not valid");
    goto done;
  }

  if(apr_t_notOnOrAfter < now)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10021)
            "Error: Timestamp error. notOnOrAfter Timestamp is not valid");
    goto done;
  } 

/* Add ID Attribute --id-attr */
  id =  xmlGetProp(root, (const xmlChar *)("ID"));
  if(!id) { 
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10012)
          "Error: ID Attribute not found in the response");
    goto done;
  }
  id_attr = xmlHasProp(root, (const xmlChar *)("ID"));
  xmlAddID(NULL, doc, (xmlChar *)id, id_attr);

  /* find start node */
  node = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10012)
            "Error: start node not found in the response");
    goto done;      
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if(dsigCtx == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10013)
            "Error: failed to create signature context");
    goto done;
  }

  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10014)
            "Error: signature verify");
    goto done;
  }
      
  /* print verification result to stdout */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(10015)
            "Notice: Signature is OK");
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(10016)
            "Error: Signature is INVALID");
    goto done;
  }    

  /* Set Additional header if it enables */
  if(conf->additional_header == Enabled)
  {
    NameID = findNodeByName(root, (const xmlChar*)("NameID"));
    if(NameID)
    {
      apr_table_set(r->headers_out, "NameID", 
                              (const char*)xmlNodeGetContent(NameID));
      for(attr = NameID->properties; NULL != attr; attr = attr->next)
      {
        const char *attr_content = (const char*)xmlGetProp(NameID, attr->name);
        apr_table_set(r->headers_out, (const char*)attr->name, 
                                      (const char*)attr_content);
      }
    }
  }

  /* success */
  res = SAMLRESPONSE_VALID;

done:    
  /* cleanup */
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  
  return(res);
}

static int openiam_saml_sp_initialize_module(apr_pool_t *p,
                          apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  /* openiam_saml_sp_initialize_module() will be called twice, and if it's a DSO
   * then all static data from the first call will be lost. Only
   * set up our static data on the second call. */
  if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    return OK;

  /* Init third-party library libxml2 */
  xmlInitParser();
  LIBXML_TEST_VERSION;
  
  xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
  xmlSubstituteEntitiesDefault(1);

  /* Init xmlsec library */
  if(xmlSecInit() < 0) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10006)
                "Error: xmlsec initialization failed.");
    return !OK;
  }

  /* Check loaded library version */
  if(xmlSecCheckVersion() != 1) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10007)
                "Error: loaded xmlsec library version is not compatible.");
    return !OK;
  }

  /* Init crypto library */
  if(xmlSecCryptoAppInit(NULL) < 0) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10009)
                "Error: crypto initialization failed.");
    return !OK;
  }

  /* Init xmlsec-crypto library */
  if(xmlSecCryptoInit() < 0) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10010)
                "Error: xmlsec-crypto initialization failed.");
    return !OK;
  }

  apr_pool_cleanup_register(p, NULL, openiam_lib_terminate, apr_pool_cleanup_null);

  if (!ap_session_load_fn || !ap_session_get_fn || !ap_session_set_fn) {
    ap_session_load_fn  = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
    ap_session_get_fn   = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
    ap_session_set_fn   = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
    if (!ap_session_load_fn || !ap_session_get_fn || !ap_session_set_fn) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10022)
              "You must load mod_session to let this module work well");
      return !OK;
    }
  }
  return OK;
}

static apr_status_t openiam_lib_terminate(void *data)
{
  /* Shutdown xmlsec-crypto library */
  xmlSecCryptoShutdown();
  
  /* Shutdown crypto library */
  xmlSecCryptoAppShutdown();
  
  /* Shutdown xmlsec library */
  xmlSecShutdown();
  return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *pool) 
{
  /* 
   * This hook is executed after configuration has been parsed, 
   * but before the server has forked.
   *
   */
  ap_hook_post_config(openiam_saml_sp_initialize_module, NULL, NULL, 
                      APR_HOOK_MIDDLE);

  /*
   * This hook is used to apply additional access control to current request
   */
  ap_hook_check_access(openiam_check_request, NULL, NULL, APR_HOOK_MIDDLE,
                      AP_AUTH_INTERNAL_PER_URI);
}
