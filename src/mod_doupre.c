#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include "apr.h"
#include "apr_strings.h"

#include "mod_micex_passport.h"

#include "../hiredis/hiredis.h"

#define MAX_SIZE 1024*1024*10

module AP_MODULE_DECLARE_DATA doupre_module;

typedef struct {
        const char *redis_server;
        int redis_port;
} doupre_server_cfg_t;

static int get_data_from_POST(request_rec * r, char **buffer, apr_size_t * bsize)
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
        } else {
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
                        APR_BRIGADE_INSERT_TAIL(bb, b);
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
        buf = apr_palloc(r->pool, count + 1);
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

static apr_table_t *parse_args(apr_pool_t * pool, const char *args)
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

static int get_method(request_rec * r, apr_table_t * args)
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

static char *get_key(request_rec * r)
{
        char *slash = NULL;

        slash = rindex(r->parsed_uri.path, '/');
        if (!slash) {
                return NULL;
        }

        slash++;

        if (*slash == '\0') {
                return NULL;
        }

        return slash;
}

static int doupre_handler(request_rec * r)
{
        doupre_server_cfg_t *sconf = ap_get_module_config(r->server->module_config, &doupre_module);
        int my_method;
        apr_table_t *my_args = NULL;
        apr_size_t bsize = 0;
        char *bdata = NULL;
        int rv;
        char *my_key = NULL;
        bool debug = false;

        if (strcmp(r->handler, "doupre")) {
                return DECLINED;
        }

        r->content_type = "text/html";

        my_args = parse_args(r->pool, r->args);
        my_method = get_method(r, my_args);
        my_key = get_key(r);

        if (apr_table_get(my_args, "debug")) {
                debug = true;
        }

        if (!my_key) {
                ap_rprintf(r, "No key selected.\n");
                return HTTP_OK;
        }

        char *(*my_mp_get_cert) (request_rec *);
        mp_cert_t *(*my_mp_cert_load) (request_rec *, char *);

        my_mp_get_cert = APR_RETRIEVE_OPTIONAL_FN(mp_get_cert);
        if (!my_mp_get_cert) {
                if (debug) {
                        ap_rprintf(r, "Can't acquire certificate acquiring function.");
                        r->status = HTTP_INTERNAL_SERVER_ERROR;
                        return OK;
                } else {
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        my_mp_cert_load = APR_RETRIEVE_OPTIONAL_FN(mp_cert_load);
        if (!my_mp_cert_load) {
                if (debug) {
                        ap_rprintf(r, "Can't acquire certificate parsing function.");
                        r->status = HTTP_INTERNAL_SERVER_ERROR;
                        return OK;
                } else {
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        char *cert = NULL;
        cert = my_mp_get_cert(r);
        if (!cert) {
                if (debug) {
                        ap_rprintf(r, "User not authenticated.");
                        r->status = HTTP_UNAUTHORIZED;
                        return OK;
                } else {
                        return HTTP_UNAUTHORIZED;
                }
        }

        mp_cert_t *ocert = NULL;
        ocert = my_mp_cert_load(r, cert);
        if (!ocert) {
                if (debug) {
                        ap_rprintf(r, "Can't parse certificate");
                        r->status = HTTP_UNAUTHORIZED;
                        return OK;
                } else {
                        return HTTP_UNAUTHORIZED;
                }
        }

        char *my_full_key = NULL;
        my_full_key = apr_psprintf(r->pool, "%s:%s", ocert->uid, my_key);

        struct timeval timeout = { 1, 500000 }; // 1.5 seconds
        redisContext *c = NULL;
        c = redisConnectWithTimeout(sconf->redis_server, sconf->redis_port, timeout);
        if (c->err) {
                if (debug) {
                        ap_rprintf(r, "Error: %s\n", c->errstr);
                        r->status = HTTP_INTERNAL_SERVER_ERROR;
                        return OK;
                } else {
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        redisReply *reply = NULL;

        if (my_method == M_POST) {

                rv = get_data_from_POST(r, &bdata, &bsize);
                if (rv != OK) {
                        if (debug) {
                                ap_rputs("Error while reading POST.\n", r);
                                r->status = rv;
                                return OK;
                        } else {
                                return rv;
                        }
                }

                reply = redisCommand(c, "SET %s %b", my_full_key, bdata, bsize);
                if (!reply) {
                        redisFree(c);
                        if (debug) {
                                ap_rprintf(r, "Error: %s\n", c->errstr);
                                r->status = HTTP_INTERNAL_SERVER_ERROR;
                                return OK;
                        } else {
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
                }

        } else if (my_method == M_DELETE) {

                reply = redisCommand(c, "DEL %s", my_full_key);
                if (!reply) {
                        redisFree(c);
                        if (debug) {
                                ap_rprintf(r, "Error: %s\n", c->errstr);
                                r->status = HTTP_INTERNAL_SERVER_ERROR;
                                return OK;
                        } else {
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
                }

        } else if (my_method == M_GET) {

                reply = redisCommand(c, "GET %s", my_full_key);
                if (!reply) {
                        redisFree(c);
                        if (debug) {
                                ap_rprintf(r, "Error: %s\n", c->errstr);
                                r->status = HTTP_INTERNAL_SERVER_ERROR;
                                return OK;
                        } else {
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
                }

                if (reply->type == REDIS_REPLY_STRING) {
                        ap_rputs(reply->str, r);
                }

        } else {
                redisFree(c);
                return HTTP_METHOD_NOT_ALLOWED;
        }

        if (reply->type == REDIS_REPLY_STATUS) {
                if (debug) {
                        ap_rputs(reply->str, r);
                }
        }

        if (reply->type == REDIS_REPLY_NIL) {
                redisFree(c);
                return HTTP_NOT_FOUND;
        }

        if (reply->type == REDIS_REPLY_ERROR) {
                redisFree(c);
                if (debug) {
                        ap_rputs(reply->str, r);
                        r->status = HTTP_INTERNAL_SERVER_ERROR;
                        return OK;
                } else {
                        return HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        redisFree(c);

        return OK;
}

typedef enum {
        cmd_redis_server,
        cmd_redis_port
} cmd_parts;

static const char *doupre_cmd_args(cmd_parms * cmd, void *dconf, const char *val)
{
        doupre_server_cfg_t *sconf = ap_get_module_config(cmd->server->module_config, &doupre_module);

        switch ((long)cmd->info) {
        case cmd_redis_server:
                sconf->redis_server = val;
                break;
        case cmd_redis_port:
                sconf->redis_port = atoi(val);
                break;
        }

        return NULL;
}

static void *doupre_server_config_create(apr_pool_t * p, server_rec * s)
{
        doupre_server_cfg_t *sconf = apr_pcalloc(p, sizeof(*sconf));
        sconf->redis_server = "localhost";
        sconf->redis_port = 6379;
        return sconf;
}

static void *doupre_server_config_merge(apr_pool_t * p, void *basev, void *overridesv)
{
        doupre_server_cfg_t *ps = apr_pcalloc(p, sizeof(*ps));
        doupre_server_cfg_t *base = basev;
        doupre_server_cfg_t *overrides = overridesv;

        ps->redis_server = !apr_strnatcmp(base->redis_server, overrides->redis_server) ? base->redis_server : overrides->redis_server;
        ps->redis_port = base->redis_port == overrides->redis_port ? base->redis_port : overrides->redis_port;

        return ps;
}

static void doupre_register_hooks(apr_pool_t * p)
{
        ap_hook_handler(doupre_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec doupre_cmds[] = {
        AP_INIT_TAKE1("DoupreRedisServer", doupre_cmd_args, (void *)cmd_redis_server, RSRC_CONF, "Redis server hostname or ip"),
        AP_INIT_TAKE1("DoupreRedisPort", doupre_cmd_args, (void *)cmd_redis_port, RSRC_CONF, "Redis port"),
        {NULL}
};

module AP_MODULE_DECLARE_DATA doupre_module = {
        STANDARD20_MODULE_STUFF,
        NULL,                   /* create per-dir    config structures */
        NULL,                   /* merge  per-dir    config structures */
        doupre_server_config_create,    /* create per-server config structures */
        doupre_server_config_merge,     /* merge  per-server config structures */
        doupre_cmds,            /* table of config file commands       */
        doupre_register_hooks   /* register hooks                      */
};
