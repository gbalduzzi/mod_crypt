#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include <unistd.h>
#include <stdlib.h>


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
     /* If apr_stat failed, we're probably not allowed to check this file. */
     else return HTTP_NOT_FOUND;

     /* get data for user from GET param and set 0 if not provided */
     apr_table_t*GET;
     ap_args_to_table(r, &GET);
     const char *user_id = apr_table_get(GET, "user");
     if (!user_id) user_id = "0";

    /*
     * now let's handle the request
    */
    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "Hello World!<br>");
    ap_rprintf(r, "Your user was: %s", user_id);

    /* Build the command to AES crypt the requested file */
    ap_rprintf(r, "<br>Your filename request was: %s", r->filename);
    ap_rprintf(r, "<br>Your crypted file is: %s.crypt", r->filename);

    char *command;
    size_t sz;
    sz = snprintf(NULL, 0, "openssl aes-256-cbc -a -salt -in %s -out %s -pass pass:0123456789", r->filename, r->filename);
    command = (char *)malloc(sz++); /* make sure you check for != NULL in real code */
    snprintf(command, sz, "openssl aes-256-cbc -a -salt -in %s -out %s.crypt -pass pass:0123456789", r->filename, r->filename);

    ap_rprintf(r, "<br>Command is: %s", command);
    system(command);

    /* Lastly, we must tell the server that we took care of this request and everything went fine.
     * We do so by simply returning the value OK to the server.
     */
    return OK;
}

static void register_hooks(apr_pool_t *pool)
{
    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(crypt_handler, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA   crypt_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks   /* Our hook registering function */
};
