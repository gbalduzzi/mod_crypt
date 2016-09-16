#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "mod_proxy.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "util_script.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

/* Declare some global variables */
bool debug = FALSE;
const char *rootPath;
const char *aclFilePath;
const char *keysFilePath;

/* Function for base64 encoding using Openssl */
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}


/**
  Function to encrypt ifp
  *r : Apache request object used to output encrypted file to the user
  **pub_key : First elements is public RSA key used to encrypt generated AES key
  *ifp : File object that must be encrypted and sent to user
  **key : At position 0 will be stored encrypted AES key
  *ekl : At position 0 will be stored key[0] length
  *ivec: In this string will be stored the random generated ivec (not encrypted) -> nonce in CTR
 */
void rsa_encrypt(request_rec *r,EVP_PKEY **pub_key, FILE *ifp, unsigned char **key, int *ekl, unsigned char *ivec) {
    //Initialize variables
    const unsigned BUFSIZE=4096;
    unsigned char *read_buf = malloc(BUFSIZE);
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    EVP_CIPHER_CTX ctx;

    //Initialize ctx to perform AES ctr 256 bit, generating random key and ivec
    EVP_SealInit(&ctx, EVP_aes_256_ctr(), key,ekl, ivec, pub_key,1);

    //Alloc memory for cipher_buf buffer
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = malloc(BUFSIZE + blocksize);

    while (1) {
        // Read in data in blocks until EOF
        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_SealUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
        ap_rprintf(r,"%s", cipher_buf);
        if (numRead < BUFSIZE) { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out, closing encryption process
    EVP_SealFinal(&ctx, cipher_buf, &out_len);
    ap_rprintf(r,"%s", cipher_buf);

    // Free memory
    free(cipher_buf);
    free(read_buf);

}


static int crypt_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "crypt-handler")) return (DECLINED);

    /* Check if the file requested is present on the disk
     * Otherwise decline the request and let other modules handle it
     */
     int rc, exists;
     apr_finfo_t finfo;
     apr_file_t *file;
     char *filename;
     filename = apr_pstrdup(r->pool, r->filename);

     /* Try to load the file: return 404 if not possible */
     rc = apr_stat(&finfo, filename, APR_FINFO_MIN, r->pool);
     if (rc == APR_SUCCESS) {
        exists =
        (
            (finfo.filetype != APR_NOFILE)
        &&  !(finfo.filetype & APR_DIR)
        );
        if (!exists) return HTTP_NOT_FOUND; /* Return a 404 if not found. */
     }
     else return HTTP_NOT_FOUND;

     /* get data for user from GET param and set -1 if not provided */
     apr_table_t*GET;
     ap_args_to_table(r, &GET);
     const char *user_id = apr_table_get(GET, "user");
     if (!user_id) user_id = "-1";

    ap_set_content_type(r, "application/octet-stream");

    /* Open ACL file */
    FILE* aclStream = fopen(aclFilePath, "r");
    char lineAcl[4096];
    int count = 0;
    bool auth = false;
    while (fgets(lineAcl, 4096, aclStream))
    {
        if (count++ == 0) {
            /* First row is csv header */
            continue;
        }

       const char* tmp = strtok(lineAcl,";");
       char *completePath = strcat(apr_pstrdup(r->pool, rootPath),tmp);
       if (strcmp(completePath, r->filename) == 0) {
           tmp = strtok(NULL, ";");
           const char* user = strtok(strdup(tmp),",");

           /* If no user is provided, all users are accepted */
           if (user != NULL && strcmp(user,"all") == 0) {
               auth = true;
               break;
           }

           while (user != NULL) {
               if (strcmp(user,user_id) == 0) {
                   auth = true;
                   break;
               }

               user = strtok(NULL,",");
           }
       }
       count++;
    }

    /* Send 403 if not authorised */
    if (!auth) {
        return HTTP_FORBIDDEN;
    }

    /* Initialize encryption */
    unsigned char **key = (unsigned char **)malloc(sizeof(unsigned char *) * 1);
    unsigned char nonce[16];
    FILE *fin = fopen(r->filename, "rb");
    int *ekl = (int *)malloc(sizeof(int));

    //Get public file
    char PublicKeyFile[1024];
    strncpy(PublicKeyFile,keysFilePath,sizeof(PublicKeyFile));
    strcat(PublicKeyFile,user_id);
    strcat(PublicKeyFile,".pem");

    //Get rsa public key of user
    FILE *rsaPublic = fopen(PublicKeyFile,"rb");
    if (rsaPublic == NULL) {
        return HTTP_FORBIDDEN;
    }
    RSA* pubkey = RSA_new();
    pubkey = PEM_read_RSA_PUBKEY(rsaPublic,&pubkey,NULL,NULL);
    EVP_PKEY **pubk = (EVP_PKEY **)malloc(sizeof(EVP_PKEY *) * 1);
    pubk[0] = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pubk[0], pubkey);
    key[0] = (unsigned char *)malloc(EVP_PKEY_size(pubk[0]));

    //Encrypt file
    rsa_encrypt(r, pubk, fin, key,ekl, nonce);

    //Base64 Encode Key and nonce
    char *b64Key = base64encode(key[0], ekl[0]);
    char *b64Nonce = base64encode(nonce, 16);

    // Send Key and nonceas responde headers
    apr_table_set(r->headers_out,"Aes-Key",b64Key);
    apr_table_set(r->headers_out,"Nonce",b64Nonce);

    /* Lastly, we must tell the server that we took care of this request and everything went fine.
     * We do so by simply returning the value OK to the server.
     */
    return OK;
}

static void register_hooks(apr_pool_t *pool)
{
    rootPath = "/";
    aclFilePath = "acl.csv";
    keysFilePath = "keys";
    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(crypt_handler, NULL, NULL, APR_HOOK_LAST);
}

/* Handler for the "rootPath" directive */
const char *set_request_root(cmd_parms *cmd, void *cfg, const char *arg)
{
    rootPath = arg;
    return NULL;
}

/* Handler for the "aclFIle" directive */
const char *set_acl_file_path(cmd_parms *cmd, void *cfg, const char *arg)
{
    aclFilePath = arg;
    return NULL;
}

/* Handler for the "keysFIle" directive */
const char *set_keys_file_path(cmd_parms *cmd, void *cfg, const char *arg)
{
    keysFilePath = arg;
    return NULL;
}

static const command_rec  crypt_directives[] =
{
    AP_INIT_TAKE1("CryptRootPath", set_request_root, NULL, RSRC_CONF, "Set the root of our crypted folder"),
    AP_INIT_TAKE1("CryptAclFile", set_acl_file_path, NULL, RSRC_CONF, "Set the location of ACL csv file"),
    AP_INIT_TAKE1("CryptKeysRoot", set_keys_file_path, NULL, RSRC_CONF, "Set the directory location of Public keys"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA   crypt_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    crypt_directives,
    register_hooks   /* Our hook registering function */
};
