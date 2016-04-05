#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "util_script.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool debug = true;

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

    /* Build the command to AES crypt the requested file */
    char *command;
    size_t sz;
    sz = snprintf(NULL, 0, "openssl aes-256-cbc -a -salt -in %s -pass pass:0123456789", r->filename);
    command = (char *)malloc(sz++); /* make sure you check for != NULL in real code */
    snprintf(command, sz, "openssl aes-256-cbc -a -salt -in %s -pass pass:0123456789", r->filename);

    if (debug) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "Your user was: %s\n", user_id);
        ap_rprintf(r, "Requested file:%s\n", r->filename);
    } else {
        ap_set_content_type(r, "application/octet-stream");
    }

    /* Open ACL file */

    FILE* stream = fopen("/srv/http/cryptoApache/acl.csv", "r");
    char line[1024];
    int count = 0;
    bool auth = false;
    while (fgets(line, 1024, stream))
    {
        if (count++ == 0) {
            /* First row is csv header */
            continue;
        }

       const char* tmp = strtok(line,";");

       if (strcmp(tmp, r->filename) == 0) {
           tmp = strtok(NULL, ";");
           const char* user = strtok(strdup(tmp),",");
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

    /* Otherwise send crypted data */

    FILE *fp;
    char path[1035];

    /* Open the command for reading. */
    fp = popen(command, "r");
    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        ap_rprintf(r, "%s", path);
    }

    /* close */
    pclose(fp);

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
