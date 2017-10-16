#include "ngx_http_saml_sp_module.h"
#include "cookies.h"
#include "logging.h"
#include "crypto.h"

/**
 * openiam_check_auth_cookie:
 * @r:           Pointer to current request
 * @module_conf: Pointer to module conf
 *
 * Check the auth cookie from the browser.
 * That auth cookie contains expiration time
 * Compare this expiration time with server time.
 *
 * Return values:
 * COOKIE_VALID:      if the cookie is valid
 * COOKIE_EXPIRED:    if the cookie expires
 * COOKIE_NOT_FOUND:  if not cookie is found
 */
int openiam_check_auth_cookie(void *request, void *module_conf)
{
    ngx_int_t           rv;
    long                expires; 
    time_t              now;
    saml_sp_auth_rec   *sp;
    ngx_http_request_t *r;

    r       = (ngx_http_request_t *) request;
    rv      = COOKIE_NOT_FOUND;
    expires = 0; 
    now     = ngx_time();
    sp      = ngx_pnalloc(r->pool, sizeof(saml_sp_auth_rec));

    if(!sp)
    {
        logError(r->connection->log, 0, "Could not allocate memory.");
        return rv;
    }

    logError(r->connection->log, 0, "Start Reading Cookie from browser...");

    openiam_get_session_auth(r, sp);

    logError(r->connection->log, 0, "Finish Reading Cookie from browser...");

    if (sp->expiration_time.data)
    {
        expires = myatol((char *) sp->expiration_time.data);
        
        if (expires && expires > now) {
            // Renew Auth Cookie
            openiam_set_session_auth(r, module_conf, sp);
            logError(r->connection->log, 0, "Renew Auth Cookie");
            rv = COOKIE_VALID;
        } else {
            // Remove Auth Cookie
            logError(r->connection->log, 0, "Removing Auth Cookie...");
            openiam_set_session_auth(r, module_conf, NULL);
            logError(r->connection->log, 0, "Removed Auth Cookie");
            rv = COOKIE_EXPIRED;
        }
    } else {
        rv = COOKIE_NOT_FOUND;
    }
    return rv;
}

/**
 * openiam_get_session_auth:
 * @r:  Pointer to current request
 * @sp: Pointer to Session Data
 *
 * Get the user information from session
 *
 * Return Values:
 * NGX_OK:      In Any Cases
 */
int openiam_get_session_auth(void *request, saml_sp_auth_rec *sp)
{
    ngx_str_t cookie_name;
    ngx_http_request_t *r = (ngx_http_request_t *) request;
    
    // Expiration Time
    ngx_str_set(&cookie_name, AUTH_COOKIE_EXPIRATION_TIME);
    openiam_get_cookie(r, &cookie_name, &sp->expiration_time);

    // Saml Requester
    // ngx_str_set(&cookie_name, AUTH_COOKIE_SAML_REQUEST);
    // openiam_get_cookie(r, &cookie_name, &sp->saml_requester);
            
   return NGX_OK;
}

/**
 * openiam_set_session_auth:
 * @r:            Pointer to current request
 * @module_conf:  Pointer to module conf
 * @sp:           Pointer to Session Data
 *
 * Set the user information into session
 *
 * Return Values:
 * NGX_OK:      if succeed
 * NGX_ERROR:   if fails
 */
int openiam_set_session_auth(void *request, void *module_conf, saml_sp_auth_rec *sp)
{
    saml_sp_config_rec *conf = (saml_sp_config_rec *)module_conf;
    ngx_http_request_t *r = (ngx_http_request_t *) request;
    if (!sp)
    {
        // Remove Auth Cookie
        openiam_set_cookie(r, AUTH_COOKIE_EXPIRATION_TIME, NULL);
        openiam_set_cookie(r, AUTH_COOKIE_SAML_REQUEST, NULL);
    } else {
        // Set Auth Cookie expiration time.
        time_t now = ngx_time();
        now += (60 * conf->expiration_time);
        sp->expiration_time.len = 32;
        sp->expiration_time.data = ngx_pnalloc(r->pool, sp->expiration_time.len);
        if(!sp->expiration_time.data)
        {
            logError(r->connection->log, 0, "Could not allocate memory.");
            return NGX_ERROR;
        }
        myltoa(now, (char *) sp->expiration_time.data, 10);
        openiam_set_cookie(r, AUTH_COOKIE_EXPIRATION_TIME, (char *) sp->expiration_time.data);
        // if(sp->saml_requester.len && sp->saml_requester.data)
        // {
        //     openiam_set_cookie(r, AUTH_COOKIE_SAML_REQUEST, (char *) sp->saml_requester.data);
        // }
    }
    return NGX_OK;
}

/**
 * openiam_get_cookie:
 * @r:     Pointer to current request
 * @name:  Pointer to Cookie Name
 * @value: Pointer to Cookie Value
 *
 * Get Cookie from the request.
 *
 * Return Values:
 * NGX_OK:    if succeeded
 * NGX_ERROR: if failed
 */
int openiam_get_cookie(void *request, ngx_str_t *name, ngx_str_t *value)
{
    ngx_str_t cookie;
    ngx_http_request_t *r = (ngx_http_request_t *) request;

    logError(r->connection->log, 0, "Getting %s Cookie...", name->data);

    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, name, &cookie)
        == NGX_DECLINED)
    {
        logError(r->connection->log, 0, "[%s Cookie] Not Found", name->data);
        value->len     = 0;
        value->data    = NULL;
        return NGX_ERROR;
    }

    logError(r->connection->log, 0, "Original Cookie Value:%s", cookie.data);

#ifdef ENCRYPT_COOKIE
    // Base64 Decode First
    u_char *base64_ciphertext;
    u_char *decrypted_cookie;
    ngx_int_t decrypted_len;
    size_t base64_ciphertext_len;
    decrypted_cookie = ngx_pnalloc(r->pool, 256);
    if(!decrypted_cookie)
    {
        logError(r->connection->log, 0, "Could not allocate memory.");
        return NGX_ERROR;
    }
    base64_ciphertext = ngx_pnalloc(r->pool, 256);
    if(!base64_ciphertext)
    {
        logError(r->connection->log, 0, "Could not allocate memory.");
        return NGX_ERROR;
    }

    base64_ciphertext_len = base64_decode_ext(cookie.data, base64_ciphertext, cookie.len);
    logError(r->connection->log, 0, "Base64 Decoded Cookie: ");

    // ignore last zero byte
    if(base64_ciphertext[base64_ciphertext_len - 1] == 0)
        base64_ciphertext_len--;
    print_binary(r, base64_ciphertext, base64_ciphertext_len);


    // AES CBC Decode
    decrypted_len = openiam_aes_cbc_decrypt(r, base64_ciphertext, base64_ciphertext_len, decrypted_cookie);
    decrypted_cookie[decrypted_len] = '\0';
    
    logError(r->connection->log, 0, "AES Decrypted Cookie: ");
    print_binary(r, decrypted_cookie, decrypted_len);

    value->len = decrypted_len;
    value->data = decrypted_cookie;

    // Free
    ngx_pfree(r->pool, base64_ciphertext);
#else
    value->len = cookie.len;
    value->data = cookie.data;
#endif
    logError(r->connection->log, 0, "Got Cookie [Name]: %s, [Value]: %s,", name->data, value->data);
    return NGX_OK;
}

/**
 * openiam_set_cookie:
 * @r:     Pointer to current request
 * @name:  Pointer to Cookie Name
 * @value: Pointer to Cookie Value
 *
 * Set Cookie into the request.
 * If value is set to null, cookie will be removed.
 *
 * Return Values:
 * NGX_OK:    if succeeded
 * NGX_ERROR: if failed
 */
int openiam_set_cookie(void *request, char *name, char *value)
{
    ngx_table_elt_t  *set_cookie;
    u_char           *cookie, *p;
    char             *cookie_value;
    size_t            cookie_len = 0;
    ngx_http_request_t *r = (ngx_http_request_t *) request;

    if(name == NULL)
    {
        logError(r->connection->log, 0, "Cookie name is null");
        return NGX_ERROR;
    }

    if(value)
        logError(r->connection->log, 0, "Setting %s Cookie... [Value]:%s", name, value);

#ifdef ENCRYPT_COOKIE
    if(value != NULL)
    {
        u_char *ciphertext;
        u_char *base64_ciphertext;
        size_t base64_ciphertext_len;
        ngx_int_t ciphertext_len;

        // Encrypt AES CBC
        ciphertext = ngx_pnalloc(r->pool, 256);
        if(!ciphertext)
        {
            logError(r->connection->log, 0, "Could not allocate memory.");
            return NGX_ERROR;
        }
        ciphertext_len = openiam_aes_cbc_encrypt (r, (u_char *) value, strlen ((char *)value), ciphertext);
        logError(r->connection->log, 0, "AES Encrypted Cookie:");
        print_binary(r, ciphertext, ciphertext_len);

        // Base64 Encode
        base64_ciphertext = ngx_pnalloc(r->pool, 256);
        if(!base64_ciphertext)
        {
            logError(r->connection->log, 0, "Could not allocate memory.");
            return NGX_ERROR;
        }
        base64_ciphertext_len = base64_encode_ext(ciphertext, base64_ciphertext, ciphertext_len);
        logError(r->connection->log, 0, "Base64 Encoded Cookie:");
        print_binary(r, base64_ciphertext, base64_ciphertext_len);

        // Free 
        ngx_pfree(r->pool, ciphertext);
        
        cookie_value = (char *)base64_ciphertext;
        if(cookie_value)
            cookie_len = base64_ciphertext_len;
    } else {
        cookie_value = value;    
    }
#else
    cookie_value = value;
    if(cookie_value)
        cookie_len = strlen(cookie_value);
#endif
    if(cookie_value)
        logError(r->connection->log, 0, "Cookie Value: %s", cookie_value);

    cookie_len += (strlen(name) + 2);
    
    if(cookie_value == NULL)
    {
        cookie_len += strlen("deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }

    cookie = ngx_pnalloc(r->pool, cookie_len);
    if (cookie == NULL) {
        logError(r->connection->log, 0, "Could not allocate memory.");
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, name, strlen(name));
    *p++ = '=';
    
    if(cookie_value == NULL)
    {
        p = ngx_copy(p, "deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", strlen("deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    } else {
        p = ngx_copy(p, cookie_value, strlen(cookie_value));
    }
    *p = '\0';

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        if(cookie)
            ngx_pfree(r->pool, cookie);
        logError(r->connection->log, 0, "Could not allocate memory.");
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len  = p - cookie;
    set_cookie->value.data = cookie;

    logError(r->connection->log, 0, "Set Cookie [Name]: %s, [Value]: %s,", name, cookie);
    return NGX_OK;
}

char* myltoa(long value, char* result, int base) 
{
    // check that the base if valid
    if (base < 2 || base > 36) { 
        *result = '\0'; 
        return result; 
    }

    char* ptr = result, *ptr1 = result, tmp_char;
    long tmp_value;

    do {
        tmp_value   = value;
        value      /= base;
        *ptr++      = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
    } while ( value );

    // Apply negative sign
    if (tmp_value < 0) 
        *ptr++ = '-';
    *ptr-- = '\0';
    
    while(ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr--= *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}

long myatol(char *str)
{
    long res = 0; // Initialize result
  
    int i;
    for (i = 0; str[i] != '\0'; ++i)
        res = res*10 + str[i] - '0';
    return res;
}