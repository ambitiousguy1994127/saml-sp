#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define RANDOM_STRING_LENGTH                20
#define PREFIX_ENABLE						1
#define PREFIX_DISABLE						0

void  	generateSecureRandomString(char *s, const int len);
char   *generateSecureRandomBytes(void *pool, const int len, const int flag);
char   *base64_encode(void *pool, char *source, size_t len);
char   *base64_decode(void *pool, char *source, size_t len);
int   	openiam_aes_cbc_encrypt(void *r, u_char *plaintext, int plaintext_len, u_char *ciphertext);
int   	openiam_aes_cbc_decrypt(void *r, u_char *ciphertext, int ciphertext_len, u_char *plaintext);
void  	decodeblock(u_char *in, char *clrstr);
void  	encodeblock(u_char *in, char *b64str, int len );
int   	base64_encode_ext(unsigned char in[], unsigned char out[], int len);
int   	base64_decode_ext(unsigned char in[], unsigned char out[], int len);
u_char 	revchar(char ch);
void  	print_binary(void *request, const void* data, int len);