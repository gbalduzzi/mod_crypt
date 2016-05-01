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

/* Declare some global variables */
bool debug = true;
const char *rootPath;
const char *aclFilePath;
const char *keysFilePath;

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

    if (debug) {
        ap_set_content_type(r, "text/plain");
    } else {
        ap_set_content_type(r, "application/octet-stream");
    }

    /* Open ACL file */
    FILE* aclStream = fopen(aclFilePath, "r");
    char lineAcl[1024];
    int count = 0;
    bool auth = false;
    while (fgets(lineAcl, 1024, aclStream))
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

    /* Otherwise send crypted data */

    /* Get user personal key from keys.csv */
    FILE* streamKeys = fopen(keysFilePath, "r");
    char lineKeys[1024];
    char *userKey = "";
    count = 0;
    while (fgets(lineKeys, 1024, streamKeys))
    {
        if (count++ == 0) {
            /* First row is csv header */
            continue;
        }

       const char* field = strtok(lineKeys,";");
       if (strcmp(field, user_id) == 0) {
           /* I found the correct key for my user */
            field = strtok(NULL, ";");
            userKey = strdup(field);
       }
    }

    if (strcmp("",userKey) == 0) {
        /* User not in the list */
        return HTTP_FORBIDDEN;
    }

    /* Build the command to AES crypt the requested file */
    char *command;
    size_t sz;
    sz = snprintf(NULL, 0, "openssl aes-256-cbc -a -salt -in %s -pass pass:%s", r->filename, userKey);
    command = (char *)malloc(sz++); /* make sure you check for != NULL in real code */
    snprintf(command, sz, "openssl aes-256-cbc -a -salt -in %s -pass pass:%s", r->filename, userKey);
    ap_rprintf(r, "Command: %s \n", command);

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
    rootPath = "/";
    aclFilePath = "acl.csv";
    keysFilePath = "keys.csv";
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
    AP_INIT_TAKE1("CryptKeysFile", set_keys_file_path, NULL, RSRC_CONF, "Set the location of Keys csv file"),
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
