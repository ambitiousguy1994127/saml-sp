#include "ngx_http_saml_sp_module.h"
#include "crypto.h"
#include "saml.h"
#include "logging.h"
#include "request.h"
#include "cookies.h"
#include <zlib.h>

xmlNodePtr findNodeByName(xmlNodePtr rootnode, const xmlChar *nodename);

char* openiam_create_saml_request(ngx_http_request_t *r, ngx_pool_t *pool, void *module_conf)
{
  char       *raw_xmlstring     = NULL;  
  char       *deflate_xmlstring = NULL;
  char       *encoded_xmlstring = NULL;
  char       *escaped_xmlstring = NULL;
  char       *request_url       = NULL;
  z_stream   *defstream         = NULL;
  int         zRC                = 0; 
  size_t      deflate_size       = 0;
  size_t      raw_xmlstring_len  = 0;
  size_t      size               = 0;
  size_t      length             = 0;
  u_char     *last;
  saml_sp_config_rec *conf = (saml_sp_config_rec *)module_conf;
  raw_xmlstring = openiam_create_raw_saml_request(r, pool, module_conf);

  /* Deflate xmlstring first */
  defstream = ngx_pcalloc(pool, sizeof(z_stream));

  raw_xmlstring_len     = strlen(raw_xmlstring);
  deflate_size          = raw_xmlstring_len + 10; /* gzip header is 10 bytes */
  deflate_xmlstring     = ngx_palloc(pool, deflate_size);
  defstream->zalloc     = Z_NULL;
  defstream->zfree      = Z_NULL;
  defstream->opaque     = Z_NULL;

  defstream->avail_in   = (uInt)raw_xmlstring_len; /* compress only chars, no need to compress zero at the end of string */
  defstream->next_in    = (Bytef *)raw_xmlstring;
  defstream->avail_out  = (uInt)deflate_size;
  defstream->next_out   = (Bytef *)deflate_xmlstring;

  zRC = deflateInit2(defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                              (-15) | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY);
  if (zRC != Z_OK) {
    deflateEnd(defstream);
    logError(r->connection->log, 0, "Unable to init ZLib");
    return NULL;
  }
  deflate(defstream, Z_FINISH);
  deflateEnd(defstream);

  /* Base64 Encode */
  size = (size_t) defstream->total_out;
  encoded_xmlstring = base64_encode(pool, deflate_xmlstring, size);
  
  // Url Encode
  escaped_xmlstring = openiam_escape_str(pool, encoded_xmlstring);

  // Get RelayState (Current request url)
  ngx_http_variable_value_t   *v;
  char                        *value = "";
  v = ngx_pnalloc(pool, sizeof(ngx_http_variable_value_t));

  // RelayState
  openiam_get_url(r, v);
  value = toStringSafety(pool, v);

  length = strlen((char *)conf->idp_login_uri.data);
  length += strlen("?SAMLRequest=");
  length += strlen(escaped_xmlstring);
  length += strlen("&RelayState=");
  length += strlen(value);
  length ++;

  request_url = ngx_pcalloc(pool, length);
  last = ngx_copy(request_url, conf->idp_login_uri.data, strlen((char *)conf->idp_login_uri.data));
  last = ngx_copy(last, "?SAMLRequest=", strlen("?SAMLRequest="));
  last = ngx_copy(last, escaped_xmlstring, strlen(escaped_xmlstring));
  last = ngx_copy(last, "&RelayState=", strlen("&RelayState="));
  last = ngx_copy(last, value, strlen(value));
  *last = '\0';

  // request_url = apr_psprintf(r->pool, 
  //                             "%s?SAMLRequest=%s&RelayState=%s",
  //                             conf->idp_login_uri,
  //                             openiam_escape_str(r->pool, encoded_xmlstring),
  //                             relaystate);
  //     apr_table_set(r->headers_out, "Location", request_url);
  return request_url;
}

/**
 * openiam_create_raw_saml_request:
 * @r:            The current request pointer
 * @pool:         The memory pool pointer
 * @module_conf:  The module configuration pointer
 *
 * Create the SAML Reqeuest as XML format first and convert it into string
 *
 * Return Values
 * raw_xmlstring: String of generated SAML Request
 */
char* openiam_create_raw_saml_request(ngx_http_request_t *r, ngx_pool_t *pool, void *module_conf)
{
  char          *raw_xmlstring  = NULL;
  xmlChar         *s              = NULL;
  char            *m_randomstring = NULL;
  // apr_random_t    *prng           = NULL;

  xmlDocPtr       doc             = NULL;
  xmlNodePtr      root            = NULL;
  xmlNodePtr      node_issuer     = NULL;
  xmlNodePtr      node_namepolicy = NULL;
  xmlNsPtr        ns_saml2p       = NULL;
  xmlNsPtr        ns_saml2        = NULL;
  // apr_time_exp_t  tm;

  int             length          = 0;
  // int             i;
  saml_sp_config_rec *conf = (saml_sp_config_rec *)module_conf;
  
  /* First create the AuthnRequest */
  doc = xmlNewDoc((const xmlChar*)("1.0"));
  if (doc == NULL) {
    logError(r->connection->log, 0, "Error occured while creating xml doc");
    return NULL;
  }

  /* Compose AuthnRequest as Root */
  root = xmlNewNode(NULL, (const xmlChar*)("AuthnRequest"));
  if (root == NULL) {
    logError(r->connection->log, 0, "Error occured while AuthnRequest node");
    return NULL; 
  }
  xmlDocSetRootElement(doc, root);

  /* Set Namespaces as attributes */
  ns_saml2p   = xmlNewNs (root, 
                          (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:protocol"),
                          (const xmlChar*)("saml2p"));
  if (ns_saml2p == NULL) {
    logError(r->connection->log, 0, "Error occured while saml2p Namespaces");
    return NULL;  
  }
  xmlSetNs(root,ns_saml2p);
  
  /* Set AuthnReqest Attributes */
  xmlNewProp(root, (const xmlChar*)("AssertionConsumerServiceURL"), 
                                (const xmlChar*)(conf->sp_login_uri.data));

  /* Generate the time string */
  u_char    m_instanttime[sizeof("2010-11-19T20:56:31Z") - 1];
  ngx_tm_t  tm;
  ngx_gmtime(ngx_time(), &tm);
  ngx_sprintf(m_instanttime, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.ngx_tm_year,
          tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min,
          tm.ngx_tm_sec);
  xmlNewProp(root, (const xmlChar*)("IssueInstant"), (const xmlChar*)(m_instanttime));

  /* Generate the secure random bytes string */
  m_randomstring = generateSecureRandomBytes(pool, RANDOM_STRING_LENGTH, PREFIX_ENABLE);
  xmlNewProp(root, (const xmlChar*)("ID"), (const xmlChar*)m_randomstring);
  
  /* Add SAMLRequest ID in session */
  openiam_set_cookie(r, AUTH_COOKIE_SAML_REQUEST, m_randomstring);

  /* Set Provider Name which configurable in conf file */  
  xmlNewProp(root, (const xmlChar*)("ProviderName"), (const xmlChar*)(conf->sp_name.data));

  /* Set Other Attributes */  
  xmlNewProp(root,  (const xmlChar*)("ProtocolBinding"), 
                    (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
  xmlNewProp(root, (const xmlChar*)("Version"), (const xmlChar*)("2.0"));


  /* Add Issuer Node into root */
  node_issuer = xmlNewChild(root, NULL, (const xmlChar*)("Issuer"), 
                                        (const xmlChar*)(conf->sp_issuer.data));

  /* Set Namespaces as attributes */
  ns_saml2    = xmlNewNs (node_issuer, 
                          (const xmlChar*)("urn:oasis:names:tc:SAML:2.0:assertion"),
                          (const xmlChar*)("saml2"));

  if (ns_saml2 == NULL) {
    logError(r->connection->log, 0, "Error occured while saml2 Namespaces");
    return NULL;  
  }

  xmlSetNs(node_issuer,ns_saml2);

  /* Add Name Policy Node into root */
  node_namepolicy = xmlNewChild(root, NULL, (const xmlChar*)("NameIDPolicy"), NULL);
  xmlNewProp(node_namepolicy, (const xmlChar*)("AllowCreate"), (const xmlChar*)("true"));
  xmlNewProp(node_namepolicy, 
            (const xmlChar*)("Format"), 
            (const xmlChar*)("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"));


  xmlDocDumpFormatMemoryEnc(doc, &s, &length, "UTF-8", 0);
  raw_xmlstring = (char *)s;
  if ( raw_xmlstring == NULL || length == 0 ) {
      logError(r->connection->log, 0, "Error occured while encoding UTC-8");
    return NULL;
  }

  return raw_xmlstring;
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
ngx_int_t openiam_verify_saml_response(ngx_http_request_t *r, void *module_conf, char *encoded_xmlstring)
{
  saml_sp_config_rec *conf = (saml_sp_config_rec *)module_conf;

  xmlSecKeysMngrPtr mngr;
  int res = SAMLRESPONSE_NOT_VALID;
  char *xml_content;
  /* Decode Base64 first */

  xml_content = base64_decode(r->pool, encoded_xmlstring, strlen(encoded_xmlstring));

  /* create keys manager and load trusted certificates */
  mngr = openiam_load_trusted_certs(r, conf->cert_files);
  if(mngr == NULL) {
    return SAMLRESPONSE_NOT_VALID;
  }

  logError(r->connection->log, 0, "SAMLResponse from IDP: %s", xml_content);
  /* verify saml */
  res = openiam_validate_saml_response(r, mngr, xml_content, conf);

  if(res != SAMLRESPONSE_VALID) {
    return SAMLRESPONSE_NOT_VALID;
  }    

  return SAMLRESPONSE_VALID;
}

/** 
 * openiam_validate_saml_response:
 * @r:                  the pointer to current request
 * @mngr:               the pointer to keys manager.
 * @xml_content:        the Xml Content.
 *
 * Validate the SAMLResponse
 * 1. Validate the Signature by its certificate file in cofiguration file
 * 2. Validate the Timestamp
 *
 * Return Values
 * SAMLRESPONSE_VALID:      if the SAMLResponse is valid
 * SAMLRESPONSE_NOT_VALID:  if the SAMLResponse is not valid
 */
ngx_int_t openiam_validate_saml_response(ngx_http_request_t *r, 
                            xmlSecKeysMngrPtr mngr, const char *xml_content, void *module_conf)
{
  xmlDocPtr           doc               = NULL;
  xmlNodePtr          root              = NULL;
  xmlNodePtr          node              = NULL;
  xmlNodePtr          conditions        = NULL;
  // xmlNodePtr          NameID            = NULL;
  xmlSecDSigCtxPtr    dsigCtx           = NULL;
  // xmlAttrPtr          attr              = NULL;
  xmlAttrPtr          id_attr           = NULL;
  xmlChar             *id               = NULL;
  int                 res               = SAMLRESPONSE_NOT_VALID;
  const char          *notBefore        = NULL;
  const char          *notOnOrAfter     = NULL;
  const char          *m_InResponseTo   = NULL;
  ngx_str_t           m_samlRequester;
  struct tm           tm_notBefore, tm_notOnOrAfter;
  time_t              now, t_notBefore, t_notOnOrAfter;
  
  // saml_sp_config_rec *conf = (saml_sp_config_rec *) module_conf; 

  /* load file */
  doc = xmlReadMemory(xml_content, strlen(xml_content), "noname.xml", NULL, 0);
  if (doc == NULL) {
    logError(r->connection->log, 0, "Error: Failed to parse documen");
    goto done;
  }

  // apr_pool_cleanup_register(r->pool, doc, (void *) xmlFreeDoc, apr_pool_cleanup_null);
  
  root = xmlDocGetRootElement(doc);
  /* Validate InResponseTo */
  m_InResponseTo = (const char*)xmlGetProp(root, 
                                          (const xmlChar*)("InResponseTo"));
  openiam_get_saml_requester(r, &m_samlRequester);
  if(m_InResponseTo == NULL || m_samlRequester.data == NULL)
  {
    logError(r->connection->log, 0, "Error: No matching with InResponseTo");
    goto done;
  } else {
    if(ngx_strcmp(m_InResponseTo, m_samlRequester.data))
    {
      logError(r->connection->log, 0, "Error: No matching with InResponseTo");
      goto done;
    }
  }
  /* Validate date */
  conditions = findNodeByName(root, (const xmlChar*)("Conditions"));
  if(conditions == NULL )
  {
    logError(r->connection->log, 0, "Error: No Condtion Node in SAMLResponse");
    goto done;
  }
  notBefore = (const char*)xmlGetProp(conditions, 
                                          (const xmlChar*)("NotBefore"));
  if(notBefore == NULL)
  {
    logError(r->connection->log, 0, "Error: No notBefore Attribute in SAMLResponse");
    goto done;
  }
  notOnOrAfter = (const char*)xmlGetProp(conditions, 
                                          (const xmlChar*)("NotOnOrAfter"));
  if(notOnOrAfter == NULL)
  {
    logError(r->connection->log, 0, "Error: No notOnOrAfter Attribute in SAMLResponse");
    goto done;
  }

  strptime(notBefore, "%Y-%m-%dT%H:%M:%S", &tm_notBefore);
  strptime(notOnOrAfter, "%Y-%m-%dT%H:%M:%S", &tm_notOnOrAfter);
  t_notBefore = timegm(&tm_notBefore);
  t_notOnOrAfter = timegm(&tm_notOnOrAfter);


  /* Compare the date */
  now = ngx_time();
  if(t_notBefore > now)
  {
    logError(r->connection->log, 0, "Error: Timestamp error. notBefore Timestamp is not valid");
    goto done;
  }

  if(t_notOnOrAfter < now)
  {
    logError(r->connection->log, 0, "Error: Timestamp error. notOnOrAfter Timestamp is not valid");
    goto done;
  } 

/* Add ID Attribute --id-attr */
  id =  xmlGetProp(root, (const xmlChar *)("ID"));
  if(!id) { 
    logError(r->connection->log, 0, "Error: ID Attribute not found in the response");
    goto done;
  }
  id_attr = xmlHasProp(root, (const xmlChar *)("ID"));
  xmlAddID(NULL, doc, (xmlChar *)id, id_attr);

  /* find start node */
  node = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    logError(r->connection->log, 0, "Error: start node not found in the response");
    goto done;      
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if(dsigCtx == NULL) {
    logError(r->connection->log, 0, "Error: failed to create signature context");
    goto done;
  }

  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    logError(r->connection->log, 0, "Error: signature verify");
    goto done;
  }
      
  /* print verification result to stdout */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    logError(r->connection->log, 0, "Notice: Signature is OK");
  } else {
    logError(r->connection->log, 0, "Error: Signature is INVALID");
    goto done;
  }    

  /* Set Additional header if it enables */
  // if(conf->additional_header == Enabled)
  // {
  //   NameID = findNodeByName(root, (const xmlChar*)("NameID"));
  //   if(NameID)
  //   {
  //     apr_table_set(r->headers_out, "NameID", 
  //                             (const char*)xmlNodeGetContent(NameID));
  //     for(attr = NameID->properties; NULL != attr; attr = attr->next)
  //     {
  //       const char *attr_content = (const char*)xmlGetProp(NameID, attr->name);
  //       apr_table_set(r->headers_out, (const char*)attr->name, 
  //                                     (const char*)attr_content);
  //     }
  //   }
  // }

  /* success */
  res = SAMLRESPONSE_VALID;

done:    
  /* cleanup */
  xmlFreeDoc(doc);
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  
  return(res);
}

char *openiam_escape_str(ngx_pool_t *p, const char *src)
{
    char *h = "0123456789abcdef";
    char *copy = ngx_palloc(p, 3 * strlen((char*) src) + 3);
    const u_char *s = (const u_char*) src;
    u_char *d = (u_char *) copy;
    unsigned c;
    while ((c = *s))
    {
        if (('a' <= c && c <= 'z')
                || ('A' <= c && c <= 'Z')
                || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.')
            *d++ = c;
        else if (c == ' ')
            *d++ = '+';
        else {
            *d++ = '%';
            *d++ = h[c >> 4];
            *d++ = h[c & 0x0f];
        }
        ++s;
    }

    *d = '\0';
    return copy;
}

inline int ishex(int x)
{
  return  (x >= '0' && x <= '9')  ||
    (x >= 'a' && x <= 'f')  ||
    (x >= 'A' && x <= 'F');
}

int openiam_unescape_str(const char *s, char *dec)
{
    char *o;
  const char *end = s + strlen(s);
  int c;
 
  for (o = dec; s <= end; o++) {
    c = *s++;
    if (c == '+') c = ' ';
    else if (c == '%' && (  !ishex(*s++)  ||
          !ishex(*s++)  ||
          !sscanf(s - 2, "%2x", &c)))
      return -1;
 
    if (dec) *o = c;
  }
 
  return o - dec;
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
xmlNodePtr findNodeByName(xmlNodePtr rootnode, const xmlChar *nodename)
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
ngx_int_t openiam_get_saml_requester(ngx_http_request_t *r, 
                                ngx_str_t *saml_requester)
{
    ngx_str_t cookie_name;

    ngx_str_set(&cookie_name, AUTH_COOKIE_SAML_REQUEST);
    openiam_get_cookie(r, &cookie_name, saml_requester);
    return NGX_OK;
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
xmlSecKeysMngrPtr openiam_load_trusted_certs(ngx_http_request_t *r, 
                                            ngx_array_t *cert_files)
{
  xmlSecKeysMngrPtr mngr;
  ngx_uint_t i;
  ngx_str_t *cert_file;
      
  /* create and initialize keys manager, we use a simple list based
   * keys manager, implement your own xmlSecKeysStore klass if you need
   * something more sophisticated 
   */
  mngr = xmlSecKeysMngrCreate();
  if(mngr == NULL) {
    logError(r->connection->log, 0, "Error: failed to create keys manager");
    return(NULL);
  }
  if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    logError(r->connection->log, 0, "Error: failed to initialize keys manager");
    xmlSecKeysMngrDestroy(mngr);
    return(NULL);
  }

  cert_file = cert_files->elts;
  for(i = 0; i < cert_files->nelts; ++i) {
    /* load trusted cert */
    if(xmlSecCryptoAppKeysMngrCertLoad(mngr, (char *) cert_file[i].data, xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
      logError(r->connection->log, 0, "Error: failed to load pem certificate from %s", cert_file[i].data);
      xmlSecKeysMngrDestroy(mngr);
      return(NULL);
    }
  }

  return(mngr);
}