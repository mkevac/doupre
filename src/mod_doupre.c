#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include "apr.h"
#include "apr_strings.h"

#include "mod_micex_passport.h"

#include <netdb.h>

#define MAX_SIZE 1024*1024*10

module AP_MODULE_DECLARE_DATA doupre_module;

#define DOUPREDEBUG "doupredebug"

typedef struct {
        const char *hs_host;
        int hs_read_port;
        int hs_write_port;
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

static int hs_connect(const char *host, int port, char **error)
{
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int rc;
        int cfd;

        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        char *port_str = NULL;
        asprintf(&port_str, "%d", port);
        rc = getaddrinfo(host, port_str, &hints, &result);
        if (rc != 0) {
            asprintf(error, "getaddrinfo(): %s", gai_strerror(rc));
            return -1;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            cfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (cfd == -1) {
                continue;
            }

            if (connect(cfd, rp->ai_addr, rp->ai_addrlen) != -1) {
                break;
            }

            close(cfd);
        }

        if (rp == NULL) {
            asprintf(error, "Could not connect socket to any address");
            return -1;
        }

        return cfd;
}

static int hs_connect_read(request_rec *r, char **error)
{
        doupre_server_cfg_t *sconf = ap_get_module_config(r->server->module_config, &doupre_module);
        return hs_connect(sconf->hs_host, sconf->hs_read_port, error);
}

static int hs_connect_write(request_rec *r, char **error)
{
        doupre_server_cfg_t *sconf = ap_get_module_config(r->server->module_config, &doupre_module);
        return hs_connect(sconf->hs_host, sconf->hs_write_port, error);
}

static void hs_disconnect(int sock)
{
        close(sock);
}

typedef struct {
        int count;
        char **cols;
} hs_data_t;

static int hs_cmd_int(int sock, const char *cmd, char **error, hs_data_t **data)
{
        int len;
        int cmd_len = strlen(cmd);
        char *buff;
        int count = 0;
        int i;

        buff = alloca(1024);

        len = write(sock, cmd, cmd_len);
        if (len != cmd_len) {
                asprintf(error, "write() error");
                return -1;
        }

        len = read(sock, buff, 1024);
        if (len < 1) {
                asprintf(error, "read error");
                return -1;
        }

        if (len > 1024) {
                asprintf(error, "len error");
                return -1;
        }

        if (strncmp(buff, "0\t", 2)) {
                asprintf(error, "int error: %s", buff);
                return -1;
        }

        buff++;
        buff++;
        count = atoi(buff);

        buff = index(buff, '\t');
        if (!buff) {
                *data = NULL;
                return count;
        }

        buff++;

        char *token = NULL;

        *data = calloc(1, sizeof(hs_data_t));
        (*data)->cols = calloc(count, sizeof(char *));
        (*data)->count = count;

        for (i = 0, token = strsep(&buff, "\t"); token; token = strsep(&buff, "\t"), i++) {
                ((*data)->cols)[i] = strdup(token);
        }

        return count;
}

static void hs_data_free(hs_data_t **data)
{
        int i;

        for (i = 0; i < (*data)->count; i++) {
                free(((*data)->cols)[i]);
        }
        free((*data)->cols);
        free(*data);
}

static int hs_cmd(int sock, char **error, hs_data_t **data, const char *format, ...)
{
        char cmd[1025];
        va_list ap;

        memset(cmd, '\0', 1025);

        va_start(ap, format);
        vsnprintf(cmd, 1024, format, ap);
        va_end(ap);

        return hs_cmd_int(sock, cmd, error, data);
}

static void debug(request_rec *r, const char *format, ...)
{
        va_list ap;

        if (!apr_table_get(r->notes, DOUPREDEBUG)) {
                return;
        }

        va_start(ap, format);
        ap_vrprintf(r, format, ap);
        va_end(ap);
}

static int returnmsg(request_rec *r, int status, const char *format, ...)
{
        va_list ap;

        if (!apr_table_get(r->notes, DOUPREDEBUG)) {
                if (status == HTTP_OK) {
                        va_start(ap, format);
                        ap_vrprintf(r, format, ap);
                        va_end(ap);
                        return OK;
                }
                return status;
        }

        va_start(ap, format);
        ap_vrprintf(r, format, ap);
        va_end(ap);

        r->status = status;
        return OK;
}

static char *encode_string(apr_pool_t *p, const char *buf)
{
        size_t buf_len = strlen(buf);
        char *res = apr_pcalloc(p, buf_len * 2);
        int i, j;

        for (i = 0, j = 0; i < buf_len; i++) {
                if (buf[i] < 0x0f) {
                        res[j++] = 0x01;
                        res[j++] = buf[i] + 0x40;
                } else {
                        res[j++] = buf[i];
                }
        }
        return res;
}

static char *decode_string(apr_pool_t *p, const char *buf)
{
        size_t buf_len = strlen(buf);
        char *res = apr_pcalloc(p, buf_len);
        int i, j;

        for (i = 0, j = 0; i < buf_len; i++) {
                if (buf[i] == 0x01) {
                        res[j++] = buf[++i] - 0x40;
                } else {
                        res[j++] = buf[i];
                }
        }
        res[j] = '\0';

        return res;
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
        hs_data_t *data;
        int reply = 0;
        char *cmd;
        char *error = NULL;
        int hs_sock = -1;

        if (strcmp(r->handler, "doupre")) {
                return DECLINED;
        }

        r->content_type = "text/html";

        my_args = parse_args(r->pool, r->args);
        my_method = get_method(r, my_args);
        my_key = get_key(r);

        if (apr_table_get(my_args, "debug")) {
                apr_table_set(r->notes, DOUPREDEBUG, "1");
        }

        if (!my_key) {
                ap_rprintf(r, "No key selected.\n");
                return HTTP_OK;
        }

        char *(*my_mp_get_cert) (request_rec *);
        mp_cert_t *(*my_mp_cert_load) (request_rec *, char *);

        my_mp_get_cert = APR_RETRIEVE_OPTIONAL_FN(mp_get_cert);
        if (!my_mp_get_cert) {
                return returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Can't acquire certificate acquiring function\n");
        }

        my_mp_cert_load = APR_RETRIEVE_OPTIONAL_FN(mp_cert_load);
        if (!my_mp_cert_load) {
                return returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Can't acquire certificate parsing function\n");
        }

        char *cert = NULL;
        cert = my_mp_get_cert(r);
        if (!cert) {
                return returnmsg(r, HTTP_UNAUTHORIZED, "User not authenticated\n");
        }

        mp_cert_t *ocert = NULL;
        ocert = my_mp_cert_load(r, cert);
        if (!ocert) {
                return returnmsg(r, HTTP_UNAUTHORIZED, "Can't parse certificate\n");
        }

        char *my_full_key = NULL;
        my_full_key = apr_psprintf(r->pool, "%s:%s", ocert->uid, my_key);

        if (my_method == M_POST || my_method == M_DELETE) {
                hs_sock = hs_connect_write(r, &error);
        } else {
                hs_sock = hs_connect_read(r, &error);
        }

        if (hs_sock < 0) {
                rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error while connecting go hs: %s\n", error);
                goto exit;
        }

        cmd = "P\t0\tmarko\thsdb\tPRIMARY\tkey,data\n";

        debug(r, "exec: %s\n", cmd);

        reply = hs_cmd(hs_sock, &error, &data, cmd);
        if (reply < 0) {
                rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error opening index: %s\n", error);
                goto exit;
        }

        if (my_method == M_POST) {

                rv = get_data_from_POST(r, &bdata, &bsize);
                if (rv != OK) {
                        rv = returnmsg(r, rv, "Error while reading POST\n");
                }
                else {
                        bdata = encode_string(r->pool, bdata);

                        // Try update
                        cmd = apr_psprintf(r->pool, "0\t=\t1\t%s\t1\t0\tU\t%s\t%s\n", my_full_key, my_full_key, bdata);

                        debug(r, "exec: %s\n", cmd);

                        reply = hs_cmd(hs_sock, &error, &data, cmd);
                        if (reply < 0) {
                                rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error: %s\n", error);
                        } else if (reply == 1) {

                                int count = atoi(data->cols[0]);
                                if (count == 0) {

                                        // Try insert
                                        cmd = apr_psprintf(r->pool, "0\t+\t2\t%s\t%s\n", my_full_key, bdata);

                                        debug(r, "exec: %s\n", cmd);

                                        reply = hs_cmd(hs_sock, &error, &data, cmd);
                                        if (reply < 0) {
                                                rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error: %s\n", error);
                                        }
                                        else {
                                                rv = returnmsg(r, HTTP_OK, "Inserted\n");
                                        }
                                }
                                else {
                                        rv = returnmsg(r, HTTP_OK, "Updated\n");
                                }
                        }
                }

        } else if (my_method == M_DELETE) {

                cmd = apr_psprintf(r->pool, "0\t=\t1\t%s\t1\t0\tD\n", my_full_key);

                debug(r, "exec: %s\n", cmd);

                reply = hs_cmd(hs_sock, &error, &data, cmd);

                if (reply < 0) {
                        rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error: %s\n", error);
                } else if (reply == 0) {
                        rv = returnmsg(r, HTTP_NOT_FOUND, "Nothing to delete\n");
                }
                else {
                        if (atoi((data->cols)[0]) > 0) {
                                rv = returnmsg(r, HTTP_OK, "Deleted\n");
                        } else {
                                rv = returnmsg(r, HTTP_NOT_FOUND, "Nothing to delete\n");
                        }
                }

        } else if (my_method == M_GET) {

                cmd = apr_psprintf(r->pool, "0\t=\t1\t%s\t1\t0\n", my_full_key);

                debug(r, "exec: %s\n", cmd);

                reply = hs_cmd(hs_sock, &error, &data, cmd);
                if (reply < 0) {
                        rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR, "Error: %s\n", error);
                }
                if (reply == 0 || (reply > 0 && !data)) {
                        rv =  returnmsg(r, HTTP_NOT_FOUND, "Data not found\n");
                }
                else {
                        ap_rprintf(r, "%s", decode_string(r->pool, (data->cols)[1]));
                        rv = OK;
                }

        } else {
                rv = returnmsg(r, HTTP_METHOD_NOT_ALLOWED, "Unknown HTTP method\n");
        }

exit:

        if (error) {
                free(error);
        }
        if (hs_sock != -1) {
                hs_disconnect(hs_sock);
        }

        return rv;
}

typedef enum {
        cmd_hs_host,
        cmd_hs_read_port,
        cmd_hs_write_port
} cmd_parts;

static const char *doupre_cmd_args(cmd_parms * cmd, void *dconf, const char *val)
{
        doupre_server_cfg_t *sconf = ap_get_module_config(cmd->server->module_config, &doupre_module);

        switch ((long)cmd->info) {
        case cmd_hs_host:
                sconf->hs_host = val;
                break;
        case cmd_hs_read_port:
                sconf->hs_read_port = atoi(val);
        case cmd_hs_write_port:
                sconf->hs_write_port = atoi(val);
        }

        return NULL;
}

static void *doupre_server_config_create(apr_pool_t * p, server_rec * s)
{
        doupre_server_cfg_t *sconf = apr_pcalloc(p, sizeof(*sconf));
        sconf->hs_host = "localhost";
        sconf->hs_read_port = 9998;
        sconf->hs_write_port = 9999;
        return sconf;
}

static void *doupre_server_config_merge(apr_pool_t * p, void *basev, void *overridesv)
{
        doupre_server_cfg_t *ps = apr_pcalloc(p, sizeof(*ps));
        doupre_server_cfg_t *base = basev;
        doupre_server_cfg_t *overrides = overridesv;

        ps->hs_host = !apr_strnatcmp(base->hs_host, overrides->hs_host) ? base->hs_host : overrides->hs_host;
        ps->hs_read_port = base->hs_read_port == overrides->hs_read_port ? base->hs_read_port : overrides->hs_read_port;
        ps->hs_write_port = base->hs_write_port == overrides->hs_write_port ? base->hs_write_port : overrides->hs_write_port;

        return ps;
}

static void doupre_register_hooks(apr_pool_t * p)
{
        ap_hook_handler(doupre_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec doupre_cmds[] = {
        AP_INIT_TAKE1("DoupreHSHost", doupre_cmd_args, (void *)cmd_hs_host, RSRC_CONF, ""),
        AP_INIT_TAKE1("DoupreHSReadPort", doupre_cmd_args, (void *)cmd_hs_read_port, RSRC_CONF, ""),
        AP_INIT_TAKE1("DoupreHSWritePort", doupre_cmd_args, (void *)cmd_hs_write_port, RSRC_CONF, ""),
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
