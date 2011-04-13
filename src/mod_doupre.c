#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"

#define MAX_SIZE 1024*1024*10

static int get_data_from_POST(request_rec *r, char **buffer, apr_size_t *bsize)
{
        int bytes = 0;
        int eos = 0;
        apr_size_t count;
        apr_status_t rv;
        apr_bucket_brigade *bb;
        apr_bucket_brigade *bbin;
        char *buf;

        const char *clen = apr_table_get(r->headers_in, "Content-Length");
        if (clen != NULL) {
                bytes = strtol(clen, NULL, 0);
                if (bytes >= MAX_SIZE) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Request too big (%d bytes; limit %d)", bytes, MAX_SIZE);
                        return HTTP_REQUEST_ENTITY_TOO_LARGE;
                }
        }
        else {
                bytes = MAX_SIZE;
        }

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        count = 0;

        do {
                rv = ap_get_brigade(r->input_filters, bbin, AP_MODE_READBYTES, APR_BLOCK_READ, bytes);
                if (rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to read input");
                        return HTTP_INTERNAL_SERVER_ERROR;
                }

                apr_bucket *b = APR_BRIGADE_FIRST(bbin);
                apr_bucket *nextb;

                while (b != APR_BRIGADE_SENTINEL(bbin)) {
                        nextb = APR_BUCKET_NEXT(b);

                        if (APR_BUCKET_IS_EOS(b)) {
                                eos = 1;
                        }

                        if (!APR_BUCKET_IS_METADATA(b)) {
                                if (b->length != -1) {
                                        count += b->length;
                                }
                        }

                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(bb,b);
                        b = nextb;
                }
        }
        while (!eos);

        /* OK, done with the data. Kill the request if we got too much data. */
        if (count > MAX_SIZE) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Request too big (%d bytes; limit %d)", bytes, MAX_SIZE);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        /* We've got all the data. Now put it in a buffer and parse it. */
        buf = apr_palloc(r->pool, count+1);
        rv = apr_brigade_flatten(bb, buf, &count);
        if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Error (flatten) reading form data");
                return HTTP_INTERNAL_SERVER_ERROR;
        }
        buf[count] = '\0';

        *bsize = count;
        *buffer = buf;

        return OK;
}

static apr_table_t *parse_args(apr_pool_t *pool, const char *args)
{
        apr_table_t *rarray = NULL;
        char *tok, *val;
        char *targs;

        rarray = apr_table_make(pool, 10);
        targs = apr_pstrdup(pool, args);

        while (targs && *targs) {
                if ((val = ap_strchr(targs, '='))) {
                        *val++ = '\0';
                        if ((tok = ap_strchr(val, '&')))
                                *tok++ = '\0';
                        ap_unescape_url(val);
                        apr_table_setn(rarray, targs, val);
                        targs = tok;
                } else {
                        return rarray;
                }
        }

        return rarray;
}

static int get_method(request_rec *r, apr_table_t *args)
{
        const char *amethod = NULL;

        amethod = apr_table_get(args, "_method");
        if (amethod) {
                if (!apr_strnatcasecmp(amethod, "post")) {
                        return M_POST;
                } else if (!apr_strnatcasecmp(amethod, "delete")) {
                        return M_DELETE;
                } else if (!apr_strnatcasecmp(amethod, "get")) {
                        return M_GET;
                }
        }

        return r->method_number;
}

static char *get_key(request_rec *r)
{
        char *slash = NULL;

        slash = rindex(r->parsed_uri.path, '/');
        if (!slash) {
                return NULL;
        }

        slash++;

        if (*slash == '\0')     {
                return NULL;
        }

        return slash;
}

static int doupre_handler(request_rec *r)
{
    int my_method;
    apr_table_t *my_args = NULL;
    apr_size_t bsize = 0;
    char *bdata = NULL;
    int rv;
    char *my_key = NULL;

    if (strcmp(r->handler, "doupre")) {
        return DECLINED;
    }

    r->content_type = "text/html";      

    my_args = parse_args(r->pool, r->args);
    my_method = get_method(r, my_args);
    my_key = get_key(r);

    if (!my_key) {
            ap_rprintf(r, "No key selected.\n");
            return HTTP_OK;
    }

    if (my_method == M_POST) {

            rv = get_data_from_POST(r, &bdata, &bsize);
            if (rv != OK) {
                    return rv;
            }

            ap_rprintf(r, "Method POST.\n", my_key);
            ap_rprintf(r, "Key '%s'\n", my_key);
            ap_rprintf(r, "Size of POST data %"APR_SIZE_T_FMT" bytes.\n", bsize);

            return OK;

    } else if (my_method == M_DELETE) {
            ap_rprintf(r, "Method DELETE.\n", my_key);
            ap_rprintf(r, "Key '%s'\n", my_key);
            return OK;
    } else if (my_method == M_GET) {
            ap_rprintf(r, "Method GET.\n", my_key);
            ap_rprintf(r, "Key '%s'\n", my_key);
            return OK;
    } else {
            return HTTP_METHOD_NOT_ALLOWED;
    }

    return OK;
}

static void doupre_register_hooks(apr_pool_t *p)
{
        ap_hook_handler(doupre_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA doupre_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    doupre_register_hooks  /* register hooks                      */
};

