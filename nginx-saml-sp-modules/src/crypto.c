#include <ngx_core.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "crypto.h"
#include "logging.h"
#include <ngx_http.h>
  
/* A 256 bit key */
unsigned char *aes_key = (unsigned char *)"01234567890123456789012345678901";
/* A 128 bit IV */
unsigned char *aes_iv = (unsigned char *)"0123456789012345";

char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void generateSecureRandomString(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    int i;
    for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = '\0';
}

char *generateSecureRandomBytes(void *poo, const int len, const int flag) 
{
	u_char	   *randomValue;
	char       *randomString;
	ngx_int_t   ii;
	size_t      size;
  ngx_pool_t *pool = (ngx_pool_t *) poo;
	
  /* Generate the secure random bytes string */
	randomValue = ngx_calloc(len, pool->log);
	if (!RAND_bytes(randomValue, len))
		return NULL;

	/* Convert bytes to string */
	size = len * 2 + 1;
	if(flag == PREFIX_ENABLE)
		size++;
	randomString = ngx_pcalloc(pool, size);

	if(flag == PREFIX_ENABLE)
	{
		*randomString = '_';
		randomString++;
	}
  	
	for(ii = 0; ii < len; ii++)
	{
		sprintf(randomString+(ii*2), "%02x", randomValue[ii]);
	 }
	randomString[size-1] = '\0';
  	
	// Free
  ngx_free(randomValue);
	if(flag == PREFIX_ENABLE)
		randomString--;
  return randomString;
}

char *base64_encode(void *poo, char *source, size_t len)
{
  ngx_pool_t *pool = (ngx_pool_t *) poo;
  ngx_str_t dst;
  ngx_str_t src;
  src.len = len;
  src.data = (u_char*)source;
  dst.len = ngx_base64_encoded_length(len);
  dst.data = ngx_pnalloc(pool, dst.len + 1);
  if(dst.data == NULL)
    return NULL;
  ngx_encode_base64(&dst, &src); 
  dst.data[dst.len] = '\0';
  return (char*)dst.data;
}

char *base64_decode(void *poo, char *source, size_t len)
{
  ngx_pool_t *pool = (ngx_pool_t *) poo;
  ngx_str_t dst;
  ngx_str_t src;
    
  src.len     = len;
  src.data    = (u_char *) source;
  dst.len     = ngx_base64_decoded_length(len);
  dst.data    = ngx_pnalloc(pool, dst.len + 1);
  if (dst.data == NULL)
  {
    return NULL;
  }
  if (ngx_decode_base64(&dst, &src) != NGX_OK)
  {
    return NULL;
  }
  dst.data[dst.len] = '\0';
  return (char*) dst.data;
}

void decodeblock(u_char *in, char *clrstr) {
  u_char out[4];
  out[0] = in[0] << 2 | in[1] >> 4;
  out[1] = in[1] << 4 | in[2] >> 2;
  out[2] = in[2] << 6 | in[3] >> 0;
  out[3] = '\0';
  strncat(clrstr, (char *) out, sizeof(out));
}

void encodeblock(u_char *in, char *b64str, int len ) {
    u_char out[5];
    out[0] = b64[ in[0] >> 2 ];
    out[1] = b64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? b64[ ((in[1] & 0x0f) << 2) |
             ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? b64[ in[2] & 0x3f ] : '=');
    out[4] = '\0';
    strncat(b64str, (char *)out, sizeof(out));
}

/**
 * openiam_aes_cbc_encrypt:
 * @pool: The pointer to current pool
 * @src:  String pointer to be encrypted
 *
 * Encrypt AES(Advanced Encryption Standard) string.
 *
 * Return Values:
 * Encrypted String
 */
int openiam_aes_cbc_encrypt(void *request, u_char *plaintext, int plaintext_len, u_char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int             len;
  int             ciphertext_len;
  ngx_http_request_t *r = (ngx_http_request_t *)request;
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
  {
    logError(r->connection->log, 0, "Error occurred while intializing the encrypt context");
  } 

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv))
  {
    logError(r->connection->log, 0, "Error occurred while intializing the encrypt operation");
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
   logError(r->connection->log, 0, "Error occurred while updating encrypt operation");
  }
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
  {
    logError(r->connection->log, 0, "Error occurred while finalizing encrypt operation");
  }
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/**
 * openiam_aes_cbc_decrypt:
 * @pool: The pointer to current pool
 * @src:  String pointer to be decrypted
 *
 * Decrypt AES(Advanced Encryption Standard) encrypted string.
 *
 * Return Values:
 * Decrypted String
 */
int openiam_aes_cbc_decrypt(void *request, u_char *ciphertext, int ciphertext_len, u_char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int             len;
  int             plaintext_len;
  ngx_http_request_t *r = (ngx_http_request_t *)request;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
  {
    logError(r->connection->log, 0, "Error occurred while intializing the decrypt context");
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv))
  {
    logError(r->connection->log, 0, "Error occurred while intializing the decrypt operation");
  }


  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
   logError(r->connection->log, 0, "Error occurred while updating decrypt operation");
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  {
   logError(r->connection->log, 0, "Error occurred while finalizing decrypt operation");
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


unsigned char revchar(char ch)
{
   if (ch >= 'A' && ch <= 'Z')
      ch -= 'A';
   else if (ch >= 'a' && ch <='z')
      ch = ch - 'a' + 26;
   else if (ch >= '0' && ch <='9')
      ch = ch - '0' + 52;
   else if (ch == '+')
      ch = 62;
   else if (ch == '/')
      ch = 63;
   return(ch);
}

int base64_encode_ext(unsigned char in[], unsigned char out[], int len)
{
   int idx,idx2,blks,left_over;
   // Since 3 input bytes = 4 output bytes, figure out how many even sets of 3 input bytes
   // there are and process those. Multiplying by the equivilent of 3/3 (int arithmetic)
   // will reduce a number to the lowest multiple of 3.
   blks = (len / 3) * 3;
   for (idx=0,idx2=0; idx < blks; idx += 3,idx2 += 4) {
      out[idx2] = b64[in[idx] >> 2];
      out[idx2+1] = b64[((in[idx] & 0x03) << 4) + (in[idx+1] >> 4)];
      out[idx2+2] = b64[((in[idx+1] & 0x0f) << 2) + (in[idx+2] >> 6)];
      out[idx2+3] = b64[in[idx+2] & 0x3F];
   }
   left_over = len % 3;
   if (left_over == 1) {
      out[idx2] = b64[in[idx] >> 2];
      out[idx2+1] = b64[(in[idx] & 0x03) << 4];
      out[idx2+2] = '=';
      out[idx2+3] = '=';
      idx2 += 4;
   }
   else if (left_over == 2) {
      out[idx2] = b64[in[idx] >> 2];
      out[idx2+1] = b64[((in[idx] & 0x03) << 4) + (in[idx+1] >> 4)];
      out[idx2+2] = b64[(in[idx+1] & 0x0F) << 2];
      out[idx2+3] = '=';
      idx2 += 4;
   }
   out[idx2] = '\0';
   return(idx2);
}

/*
ADD: Option to strip out newlines
*/
int base64_decode_ext(unsigned char in[], unsigned char out[], int len)
{
   int idx,idx2,blks,left_over;

   if (in[len-1] == '=')
      len--;
   if (in[len-1] == '=')
      len--;

   blks = (len / 4) * 4;
   for (idx=0,idx2=0; idx2 < blks; idx += 3,idx2 += 4) {
      out[idx] = (revchar(in[idx2]) << 2) + ((revchar(in[idx2+1]) & 0x30) >> 4);
      out[idx+1] = (revchar(in[idx2+1]) << 4) + (revchar(in[idx2+2]) >> 2);
      out[idx+2] = (revchar(in[idx2+2]) << 6) + revchar(in[idx2+3]);
   }
   left_over = len % 4;
   if (left_over == 2) {
      out[idx] = (revchar(in[idx2]) << 2) + ((revchar(in[idx2+1]) & 0x30) >> 4);
      out[idx+1] = (revchar(in[idx2+1]) << 4);
      idx += 2;
   }
   else if (left_over == 3) {
      out[idx] = (revchar(in[idx2]) << 2) + ((revchar(in[idx2+1]) & 0x30) >> 4);
      out[idx+1] = (revchar(in[idx2+1]) << 4) + (revchar(in[idx2+2]) >> 2);
      out[idx+2] = revchar(in[idx2+2]) << 6;
      idx += 3;
   }
   out[idx] = '\0';
   return(idx);
}

void print_binary(void *request, const void* data, int len)
{
  ngx_http_request_t *r = (ngx_http_request_t *) request;
  size_t  size  = len * 3 + 1;
  char   *value = ngx_pcalloc(r->pool, size);
  int     ii;
  u_char *p = (u_char *)data;
  for(ii = 0; ii < len; ii++)
  {
    sprintf(value+(ii*3), "%02x ", p[ii]);
   }
  value[size-1] = '\0';
  
  logError(r->connection->log, 0, "Binary Data: %s", value);
  // Free
  ngx_pfree(r->pool, value);
}