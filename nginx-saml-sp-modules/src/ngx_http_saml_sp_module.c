/**
 * @file   ngx_http_saml_sp_module.c
 * @author Alexander Lesin <alexander.lesin@openiam.com>
 * @date   Mon Jun 12 12:06:52 2011
 *
 * @workflow 
 *
 */

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include "cookies.h"
#include "request.h"
#include "saml.h"
#include "crypto.h"
#include "logging.h"
#include "ngx_http_saml_sp_module.h"

static ngx_int_t openiam_saml_sp_initialize_module(ngx_conf_t *cf);
static ngx_int_t openiam_check_request(ngx_http_request_t *r);

static void *openiam_saml_sp_create_conf(ngx_conf_t *cf);
static char *openiam_saml_sp_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *openiam_setCertificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *openiam_setIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Define Module Directives */
static ngx_command_t ngx_http_saml_sp_commands[] = {
    { 
        ngx_string("OPENIAM_SSOEnable"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, sso_enable),
        NULL
    },
    {
        ngx_string("OPENIAM_SignatureEnable"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, signature_enable),
        NULL
    },
    {
        ngx_string("OPENIAM_ExpirationTime"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, expiration_time),
        NULL
    },
    {
        ngx_string("OPENIAM_AddtionalHeader"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, additional_header),
        NULL
    },
    {
        ngx_string("OPENIAM_SP_Name"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, sp_name),
        NULL
    },
    {
        ngx_string("OPENIAM_SP_Issuer"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, sp_issuer),
        NULL
    },
    {
        ngx_string("OPENIAM_SP_LogoutURI"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, sp_logout_uri),
        NULL
    },
    {
        ngx_string("OPENIAM_SP_LoginURI"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, sp_login_uri),
        NULL
    },
    {
        ngx_string("OPENIAM_IDP_LogoutURI"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, idp_logout_uri),
        NULL
    },
    {
        ngx_string("OPENIAM_IDP_LoginURI"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, idp_login_uri),
        NULL
    },
    {
        ngx_string("OPENIAM_PrefixURI"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
        openiam_setIgnoreUrl,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, prefix_uri_set),
        NULL
    },
    {
        ngx_string("OPENIAM_Cert_FILE"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
        openiam_setCertificate,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(saml_sp_config_rec, cert_files),
        NULL
    },
    
    ngx_null_command
};

/* Define Module Context */
static ngx_http_module_t ngx_http_saml_sp_module_ctx = 
{
    /* preconfiguration */
    NULL,                 

    /* postconfiguration */
    openiam_saml_sp_initialize_module,      

    /* create main configuration */
    NULL,                          

    /* init main configuration */
    NULL,                                   

    /* create server configuration */
    NULL,            

    /* merge server configuration */
    NULL,                                   

    /* create location configuration */
    openiam_saml_sp_create_conf,       

    /* merge location configuration */                            
    openiam_saml_sp_merge_conf
};

/* Module definition. */
ngx_module_t ngx_http_saml_sp_module = {
    NGX_MODULE_V1,
    &ngx_http_saml_sp_module_ctx,           /* module context */
    ngx_http_saml_sp_commands,              /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t openiam_saml_sp_initialize_module(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = openiam_check_request;

#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs(); 
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs); 
#endif /* XMLSEC_NO_XSLT */
                
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        logError(cf->pool->log, 0, "Error: xmlsec initialization failed.");
        return NGX_ERROR;
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        logError(cf->pool->log, 0, "Error: loaded xmlsec library version is not compatible.");
        return NGX_ERROR;
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        logError(cf->pool->log, 0, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) envornment variables.\n");
        return NGX_ERROR;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        logError(cf->pool->log, 0, "Error: crypto initialization failed.");
        return NGX_ERROR;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        logError(cf->pool->log, 0, "Error: xmlsec-crypto initialization failed.");
        return NGX_ERROR;
    }

    return NGX_OK;    
}

void openiam_read_post_data(ngx_http_request_t *r)
{
    ngx_chain_t *chain_link     = NULL;
    char        *msg_pos        = NULL;
    char        *query          = NULL;
    u_char      *param_name     = NULL;
    u_char      *param_value    = NULL;
    u_char      *relaystate     = NULL;
    u_char      *xml_content    = NULL;
    char        *in_buffer      = NULL;
    int          len            = 0;
    int          buffers        = 0;   
    ngx_int_t   rv              = NGX_DECLINED;
    ngx_int_t   xml_valid       = SAMLRESPONSE_NOT_VALID;
    saml_sp_config_rec *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_saml_sp_module);

    for(chain_link = r->request_body->bufs; chain_link != NULL; 
        chain_link = chain_link->next) {
        len += chain_link->buf->last - chain_link->buf->pos;
        buffers++;
        if(chain_link->buf->in_file) {
            logError(r->connection->log, 0, "Invalid Post Data from IDP");
            rv = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }
    /* allocate memory for the buffer of the body */
    in_buffer = (char *)ngx_palloc(r->pool, (len + 1)*sizeof(char));
    if(in_buffer == NULL) {
        logError(r->connection->log, 0, "Error occured while allocating memory in post data context");
        rv = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* collect body into one buffer */
    msg_pos = in_buffer;
    for(chain_link = r->request_body->bufs; chain_link != NULL; chain_link = chain_link->next) {
        ngx_buf_t *buf = chain_link->buf;
        msg_pos = (char *)ngx_copy(msg_pos, (char *)buf->pos, buf->last - buf->pos);
    }
    in_buffer[len] = '\0';

    query = strtok(in_buffer, "&");
    while (query != NULL)
    {
        param_name = ngx_alloc(20, r->connection->log);
        param_value = ngx_alloc(strlen(query), r->connection->log);
        sscanf(query, "%[^=]=%s", (char *) param_name, (char *) param_value);
        
        if(!ngx_strcasecmp((u_char *) param_name, (u_char *) "RelayState"))
        {
            int len = strlen((char *) param_value);
            relaystate = ngx_pnalloc(r->pool, len + 1);
            openiam_unescape_str((char *) param_value, (char *) relaystate);
        } 
        else if(!ngx_strcasecmp((u_char *) param_name, (u_char *) "SAMLResponse"))
        {
            int len = strlen((char *) param_value);
            xml_content = ngx_pnalloc(r->pool, len + 1);
            openiam_unescape_str((char *) param_value, (char *) xml_content);

            xml_valid = openiam_verify_saml_response(r, conf, (char *) xml_content);
        }
        ngx_free(param_name);
        ngx_free(param_value);
        query = strtok(NULL, "&");
    }
    if ((xml_valid == SAMLRESPONSE_VALID && conf->signature_enable == Enabled) || 
        (xml_valid == SAMLRESPONSE_NOT_VALID && conf->signature_enable == Disabled))
    {
        saml_sp_auth_rec *sp = ngx_pnalloc(r->pool, sizeof(saml_sp_auth_rec));
        openiam_set_session_auth(r, conf, sp);
        logError(r->connection->log, 0, "Notice: Set Auth Cookie successfully");

        ngx_http_clear_location(r);
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            rv = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = strlen((char *) relaystate);
        r->headers_out.location->value.data = relaystate;
        rv = NGX_HTTP_MOVED_PERMANENTLY;


    } else {
        logError(r->connection->log, 0, "Error: SAMLResponse is not valid");
        rv = NGX_HTTP_BAD_REQUEST;
    }
done:
    ngx_http_finalize_request(r, rv);
    return;
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
static ngx_int_t openiam_check_request(ngx_http_request_t *r)
{
    saml_sp_config_rec *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_saml_sp_module);
    
    /* Check if the module is enalbed */
    if(conf->sso_enable == 0 || conf->sso_enable == NGX_CONF_UNSET)
        return NGX_DECLINED;

    // Module is enabled
    int                         status      = COOKIE_VALID;
    int                         auth_need   = AUTH_NONEED;
    char                        *full_url   = "";
    ngx_pool_t                  *pool       = r->pool;
    ngx_http_variable_value_t   *v;
    
    logError(r->connection->log, 0, "Processing New Request");

    v = ngx_pnalloc(r->pool, sizeof(ngx_http_variable_value_t));
    if(!v)
    {
        logError(r->connection->log, 0, "Could not allocate memory.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    openiam_get_url(r, v);
    full_url = toStringSafety(r->pool, v);

    // Get Auth Cookie Status
    status = openiam_check_auth_cookie(r, conf);

    logError(r->connection->log, 0, "Cookie Status:%d", status);
    if (!ngx_strncmp(full_url, conf->sp_logout_uri.data, conf->sp_logout_uri.len)) {
        /* 
        * Check the request uri whether it matches with logout uri
        * If the requested uri matches with the logout uri in service provider
        * redirect the user to idp logout uri noted in configuration
        * and remove authentication cookie at that time
        */
        // Free 
        ngx_pfree(r->pool, full_url);

        if (status == COOKIE_NOT_FOUND) {
            logError(r->connection->log, 0, "Warning: Unauthenticated user hit the logout uri.");
        } else if(status == COOKIE_EXPIRED) {
            logError(r->connection->log, 0, "Warning: User with expired cookie hit the logout uri.");
        }

        // Remove Auth Cookie
        openiam_set_session_auth(r, conf, NULL);
 
        // Redirect to OpenIAM IDP Logout Page
        ngx_http_clear_location(r);
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = strlen((char *) conf->idp_logout_uri.data);
        r->headers_out.location->value.data = conf->idp_logout_uri.data;
        return NGX_HTTP_MOVED_PERMANENTLY;

    } else if(!ngx_strncmp(full_url, conf->sp_login_uri.data, conf->sp_login_uri.len)) {
        // Free 
        ngx_pfree(r->pool, full_url);

        if(status != COOKIE_VALID)
        {
            openiam_get_method(r, v);
            char *value = toStringSafety(r->pool, v);

            if (!ngx_strcasecmp((u_char *) value, (u_char *) "POST")) {
                ngx_int_t rc;

                // Free
                ngx_pfree(r->pool, value);
                rc = ngx_http_read_client_request_body(r, openiam_read_post_data);

                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    logError(r->connection->log, 0, "Error occured while reading post data");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                auth_need = AUTH_NEED;
            }
        } else {
            auth_need = AUTH_NONEED;
        }
    } else {

        ngx_uint_t i;
        ngx_str_t *ignore_uri;
        ignore_uri = conf->prefix_uri_set->elts;
        for (i = 0; i < conf->prefix_uri_set->nelts; i++) {
            if(ngx_strstr(full_url, ignore_uri[i].data))
            {
                // Free 
                ngx_pfree(r->pool, full_url);
                return NGX_DECLINED;
            }
        }
        
        // Free 
        ngx_pfree(r->pool, full_url);

        if (status == COOKIE_VALID) {
            auth_need = AUTH_NONEED;
            logError(r->connection->log, 0, "no need to redirect to idp");
        } else {
            auth_need = AUTH_NEED;
        }
    }
    if(auth_need == AUTH_NEED)
    {
        char *location = openiam_create_saml_request(r, pool, conf);
        ngx_http_clear_location(r);
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = strlen(location);
        r->headers_out.location->value.data = (u_char *) location;
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    // Free
    ngx_pfree(r->pool, v);
    return NGX_DECLINED;
}

static void *openiam_saml_sp_create_conf(ngx_conf_t *cf)
{
    saml_sp_config_rec  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(saml_sp_config_rec));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * conf->sp_name            = { 0, NULL };
     * conf->sp_issuer          = { 0, NULL };
     * conf->idp_logout_uri     = { 0, NULL };
     * conf->idp_login_uri      = { 0, NULL };
     * conf->sp_logout_uri      = { 0, NULL };
     * conf->sp_login_uri       = { 0, NULL };
     * 
     */

    conf->sso_enable            = NGX_CONF_UNSET;
    conf->signature_enable      = NGX_CONF_UNSET;
    conf->additional_header     = NGX_CONF_UNSET;
    conf->expiration_time       = NGX_CONF_UNSET_UINT;
    conf->cert_files            = NULL;
    conf->prefix_uri_set        = NULL;

    return conf;
}

static char *openiam_saml_sp_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    saml_sp_config_rec *prev = parent;
    saml_sp_config_rec *conf = child;

    ngx_conf_merge_value(conf->sso_enable, prev->sso_enable, 0);
    ngx_conf_merge_value(conf->signature_enable, prev->signature_enable, 0);
    ngx_conf_merge_value(conf->additional_header, prev->additional_header, 0);
    
    ngx_conf_merge_uint_value(conf->expiration_time, prev->expiration_time, COOKIE_DEF_TIME);

    ngx_conf_merge_str_value(conf->sp_name, prev->sp_name, "");
    ngx_conf_merge_str_value(conf->sp_issuer, prev->sp_issuer, "");
    ngx_conf_merge_str_value(conf->idp_logout_uri, prev->idp_logout_uri, "");
    ngx_conf_merge_str_value(conf->idp_login_uri, prev->idp_login_uri, "");
    ngx_conf_merge_str_value(conf->sp_logout_uri, prev->sp_logout_uri, "");
    ngx_conf_merge_str_value(conf->sp_login_uri, prev->sp_login_uri, "");

    if (conf->cert_files == NULL)
    {
        /* Merge if the parent 'cert_files' is set */
        if (prev->cert_files != NULL)
        {
            ngx_str_t  *prev_val;
            ngx_str_t  *cur_val;
            ngx_uint_t  i;
            ngx_uint_t  size;
            u_char     *last;
            
            size        = prev->cert_files->nelts;
            prev_val    = prev->cert_files->elts;

            /* Create array for storing cert_files from the parent */
            conf->cert_files = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->cert_files == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < size; i++) {
                cur_val     = ngx_array_push(conf->cert_files);
                if (cur_val == NULL) {
                    if(!conf->cert_files)
                        ngx_array_destroy(conf->cert_files);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(!conf->cert_files)
                        ngx_array_destroy(conf->cert_files);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }   
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }
        }
    }

    if (conf->prefix_uri_set == NULL)
    {
        /* Merge if the parent 'prefix_uri_set' is set */
        if (prev->prefix_uri_set != NULL)
        {
            ngx_str_t  *prev_val;
            ngx_str_t  *cur_val;
            ngx_uint_t  i;
            ngx_uint_t  size;
            u_char     *last;
            
            size        = prev->prefix_uri_set->nelts;
            prev_val    = prev->prefix_uri_set->elts;

            /* Create array for storing prefix_uri_set from the parent */
            conf->prefix_uri_set = ngx_array_create(cf->pool, size, sizeof(ngx_str_t));
            if (conf->prefix_uri_set == NULL) {
                logError(cf->log, 0, "Cannot Allocate Array Pool");
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < size; i++) {
                cur_val     = ngx_array_push(conf->prefix_uri_set);
                if (cur_val == NULL) {
                    if(!conf->prefix_uri_set)
                        ngx_array_destroy(conf->prefix_uri_set);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }
                /* Copy one by one */
                cur_val->len    = prev_val[i].len;
                cur_val->data   = ngx_pcalloc(cf->pool, prev_val[i].len + 1);
                if(cur_val->data == NULL)
                {
                    if(!conf->prefix_uri_set)
                        ngx_array_destroy(conf->prefix_uri_set);
                    logError(cf->log, 0, "Cannot Allocate Array Item");
                    return NGX_CONF_ERROR;
                }   
                last = ngx_copy(cur_val->data, prev_val[i].data, prev_val[i].len);
                *last = '\0';
            }
        }
    }

    return NGX_CONF_OK;
}

static char *openiam_setCertificate(ngx_conf_t *cf, ngx_command_t *cmd, void *saml_sp_conf)
{
    ngx_str_t             *value;
    ngx_str_t             *cert_files;
    ngx_uint_t             i;
    saml_sp_config_rec    *conf = (saml_sp_config_rec *) saml_sp_conf;

    if (conf->cert_files == NULL) {
        conf->cert_files = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (conf->cert_files == NULL) {
            logError(cf->log, 0, "Could not allocate array.");
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        cert_files = ngx_array_push(conf->cert_files);
        if(cert_files == NULL){
            if(!conf->cert_files)
                ngx_array_destroy(conf->cert_files);
            logError(cf->log, 0, "Could not allocate array item.");
            return NGX_CONF_ERROR;
        }
        u_char *last;
        cert_files->len  = value[i].len;
        cert_files->data = ngx_pcalloc(cf->pool, cert_files->len + 1);
        last             = ngx_copy(cert_files->data, value[i].data, cert_files->len);
        *last            = '\0';
    }
    return NGX_CONF_OK;
}

static char *openiam_setIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *saml_sp_conf)
{
    saml_sp_config_rec    *conf = saml_sp_conf;
    ngx_str_t                       *value;
    ngx_str_t                       *prefix_uri_set;
    ngx_uint_t                       i;

    if (conf->prefix_uri_set == NULL) {
        conf->prefix_uri_set = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (conf->prefix_uri_set == NULL) {
            logError(cf->log, 0, "Could not allocate array.");
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if(value[i].data[0] != '/')
        {
            return "should be start with '/'";
        }
        prefix_uri_set = ngx_array_push(conf->prefix_uri_set);
        if(prefix_uri_set == NULL)
        {
            if(!conf->prefix_uri_set)
                ngx_array_destroy(conf->prefix_uri_set);
            logError(cf->log, 0, "Could not allocate array item.");
            return NGX_CONF_ERROR;
        }

        u_char *last;
        prefix_uri_set->len  = value[i].len;
        prefix_uri_set->data = ngx_pcalloc(cf->pool, prefix_uri_set->len + 1);
        last                 = ngx_copy(prefix_uri_set->data, value[i].data, prefix_uri_set->len);
        *last                = '\0';
    }
    return NGX_CONF_OK;
}

