#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_reslist.h"

#include "mod_micex_passport.h"

#include <stdbool.h>

#include <netdb.h>

#define MAX_SIZE 1024*1024*10

module AP_MODULE_DECLARE_DATA doupre_module;

#define DOUPREDEBUG "doupredebug"

typedef struct {
	bool enabled;
	const char *hs_host;
	int hs_read_port;
	int hs_write_port;
	int reslist_min;
	int reslist_smax;
	int reslist_hmax;
	int reslist_ttl;

	apr_reslist_t *reslist_read;
	apr_reslist_t *reslist_write;
} doupre_server_cfg_t;

static int get_data_from_POST(request_rec * r, char **buffer,
			      apr_size_t * bsize)
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
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "Request too big (%d bytes; limit %d)",
				      bytes, MAX_SIZE);
			return HTTP_REQUEST_ENTITY_TOO_LARGE;
		}
	} else {
		bytes = MAX_SIZE;
	}

	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	count = 0;

	do {
		rv = ap_get_brigade(r->input_filters, bbin, AP_MODE_READBYTES,
				    APR_BLOCK_READ, bytes);
		if (rv != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
				      "failed to read input");
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
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
			      "Request too big (%d bytes; limit %d)", bytes,
			      MAX_SIZE);
		return HTTP_REQUEST_ENTITY_TOO_LARGE;
	}

	/* We've got all the data. Now put it in a buffer and parse it. */
	buf = apr_palloc(r->pool, count + 1);
	rv = apr_brigade_flatten(bb, buf, &count);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
			      "Error (flatten) reading form data");
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

	memset(&hints, 0, sizeof(hints));

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

		int optval = 1;
		if (setsockopt
		    (cfd, SOL_SOCKET, SO_REUSEADDR, &optval,
		     sizeof(optval)) == -1) {
			close(cfd);
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

static int hs_connect_read(request_rec * r, char **error)
{
	doupre_server_cfg_t *sconf =
	    ap_get_module_config(r->server->module_config, &doupre_module);
	return hs_connect(sconf->hs_host, sconf->hs_read_port, error);
}

static int hs_connect_write(request_rec * r, char **error)
{
	doupre_server_cfg_t *sconf =
	    ap_get_module_config(r->server->module_config, &doupre_module);
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

static int hs_cmd_int(int sock, const char *cmd, char **error,
		      hs_data_t ** data)
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

	for (i = 0, token = strsep(&buff, "\t"); token;
	     token = strsep(&buff, "\t"), i++) {
		((*data)->cols)[i] = strdup(token);
	}

	return count;
}

static void hs_data_free(hs_data_t ** data)
{
	int i;

	for (i = 0; i < (*data)->count; i++) {
		free(((*data)->cols)[i]);
	}
	free((*data)->cols);
	free(*data);
}

static int hs_cmd(int sock, char **error, hs_data_t ** data, const char *format,
		  ...)
{
	char cmd[1025];
	va_list ap;

	memset(cmd, '\0', 1025);

	va_start(ap, format);
	vsnprintf(cmd, 1024, format, ap);
	va_end(ap);

	return hs_cmd_int(sock, cmd, error, data);
}

static void debug(request_rec * r, const char *format, ...)
{
	va_list ap;

	if (!apr_table_get(r->notes, DOUPREDEBUG)) {
		return;
	}

	va_start(ap, format);
	ap_vrprintf(r, format, ap);
	va_end(ap);
}

static int returnmsg(request_rec * r, int status, const char *format, ...)
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

static char *encode_string(apr_pool_t * p, const char *buf)
{
	size_t buf_len = strlen(buf);
	char *res = apr_pcalloc(p, buf_len * 2);
	int i, j;

	for (i = 0, j = 0; i < buf_len; i++) {
		uint8_t b = buf[i];
		if (b < 0x0f) {
			res[j++] = 0x01;
			res[j++] = b + 0x40;
		} else {
			res[j++] = b;
		}
	}
	return res;
}

static char *decode_string(apr_pool_t * p, const char *buf)
{
	size_t buf_len = strlen(buf);
	char *res = apr_pcalloc(p, buf_len);
	int i, j;

	for (i = 0, j = 0; i < buf_len; i++) {
		uint8_t b = buf[i];
		if (b == 0x01) {
			res[j++] = b - 0x40;
		} else {
			res[j++] = b;
		}
	}
	res[j] = '\0';

	return res;
}

typedef struct {
	int sock;
} doupre_hs_res_t;

long timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
	long msec;
	msec = (finishtime->tv_sec - starttime->tv_sec) * 1000;
	msec += (finishtime->tv_usec - starttime->tv_usec) / 1000;
	return msec;
}

static int doupre_handler(request_rec * r)
{
	doupre_server_cfg_t *sconf =
	    ap_get_module_config(r->server->module_config, &doupre_module);
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
	bool hs_sock_read = true;

	long diff1 = -1;
	long diff2 = -1;
	bool diff2_started;
	struct timeval start;
	struct timeval end;

	if (strcmp(r->handler, "doupre") || !sconf->enabled) {
		return DECLINED;
	}

	if (!sconf->reslist_read || !sconf->reslist_write) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "Resource lists are NULL. Check error_log.");
		return HTTP_INTERNAL_SERVER_ERROR;
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
		return returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
				 "Can't acquire certificate acquiring function\n");
	}

	my_mp_cert_load = APR_RETRIEVE_OPTIONAL_FN(mp_cert_load);
	if (!my_mp_cert_load) {
		return returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
				 "Can't acquire certificate parsing function\n");
	}

	char *cert = NULL;
	cert = my_mp_get_cert(r);
	if (!cert) {
		return returnmsg(r, HTTP_UNAUTHORIZED,
				 "User not authenticated\n");
	}

	mp_cert_t *ocert = NULL;
	ocert = my_mp_cert_load(r, cert);
	if (!ocert) {
		return returnmsg(r, HTTP_UNAUTHORIZED,
				 "Can't parse certificate\n");
	}

	char *my_full_key = NULL;
	my_full_key = apr_psprintf(r->pool, "%s:%s", ocert->uid, my_key);

	doupre_hs_res_t *hs_res;
	gettimeofday(&start, NULL);
	if (my_method == M_POST || my_method == M_DELETE) {
		hs_sock_read = false;
		rv = apr_reslist_acquire(sconf->reslist_write,
					 (void **)&hs_res);
	} else {
		hs_sock_read = true;
		rv = apr_reslist_acquire(sconf->reslist_read, (void **)&hs_res);
	}
	gettimeofday(&end, NULL);
	diff1 = timevaldiff(&start, &end);

	if (rv != APR_SUCCESS) {
		rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
			       "Error while connecting to hs: %s\n", error);
		goto exit;
	} else {
		hs_sock = hs_res->sock;
	}

	cmd = "P\t0\tmarko\thsdb\tPRIMARY\tkey,data\n";

	debug(r, "exec: %s\n", cmd);

	diff2_started = true;
	gettimeofday(&start, NULL);

	reply = hs_cmd(hs_sock, &error, &data, cmd);
	if (reply < 0) {
		rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
			       "Error opening index: %s\n", error);
		goto exit;
	}

	if (my_method == M_POST) {

		rv = get_data_from_POST(r, &bdata, &bsize);
		if (rv != OK) {
			rv = returnmsg(r, rv, "Error while reading POST\n");
		} else {
			bdata = encode_string(r->pool, bdata);

			// Try update
			cmd =
			    apr_psprintf(r->pool,
					 "0\t=\t1\t%s\t1\t0\tU\t%s\t%s\n",
					 my_full_key, my_full_key, bdata);

			debug(r, "exec: %s\n", cmd);

			reply = hs_cmd(hs_sock, &error, &data, cmd);
			if (reply < 0) {
				rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
					       "Error: %s\n", error);
			} else if (reply == 1) {

				int count = atoi(data->cols[0]);
				if (count == 0) {

					// Try insert
					cmd =
					    apr_psprintf(r->pool,
							 "0\t+\t2\t%s\t%s\n",
							 my_full_key, bdata);

					debug(r, "exec: %s\n", cmd);

					reply =
					    hs_cmd(hs_sock, &error, &data, cmd);
					if (reply < 0) {
						rv = returnmsg(r,
							       HTTP_INTERNAL_SERVER_ERROR,
							       "Error: %s\n",
							       error);
					} else {
						rv = returnmsg(r, HTTP_OK,
							       "Inserted\n");
					}
				} else {
					rv = returnmsg(r, HTTP_OK, "Updated\n");
				}
			}
		}

	} else if (my_method == M_DELETE) {

		cmd =
		    apr_psprintf(r->pool, "0\t=\t1\t%s\t1\t0\tD\n",
				 my_full_key);

		debug(r, "exec: %s\n", cmd);

		reply = hs_cmd(hs_sock, &error, &data, cmd);

		if (reply < 0) {
			rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
				       "Error: %s\n", error);
		} else if (reply == 0) {
			rv = returnmsg(r, HTTP_NOT_FOUND,
				       "Nothing to delete\n");
		} else {
			if (atoi((data->cols)[0]) > 0) {
				rv = returnmsg(r, HTTP_OK, "Deleted\n");
			} else {
				rv = returnmsg(r, HTTP_NOT_FOUND,
					       "Nothing to delete\n");
			}
		}

	} else if (my_method == M_GET) {

		cmd = apr_psprintf(r->pool, "0\t=\t1\t%s\t1\t0\n", my_full_key);

		debug(r, "exec: %s\n", cmd);

		reply = hs_cmd(hs_sock, &error, &data, cmd);
		if (reply < 0) {
			rv = returnmsg(r, HTTP_INTERNAL_SERVER_ERROR,
				       "Error: %s\n", error);
		}
		if (reply == 0 || (reply > 0 && !data)) {
			rv = returnmsg(r, HTTP_NOT_FOUND, "Data not found\n");
		} else {
			ap_rprintf(r, "%s",
				   decode_string(r->pool, (data->cols)[1]));
			rv = OK;
		}

	} else {
		rv = returnmsg(r, HTTP_METHOD_NOT_ALLOWED,
			       "Unknown HTTP method\n");
	}

 exit:

	if (diff2_started) {
		gettimeofday(&end, NULL);
		diff2 = timevaldiff(&start, &end);
	}
	//ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "acquiring conn %ld, acquiring data %ld", diff1, diff2);

	if (error) {
		free(error);
	}
	if (hs_sock != -1) {
		if (hs_sock_read) {
			apr_reslist_release(sconf->reslist_read, hs_res);
		} else {
			apr_reslist_release(sconf->reslist_write, hs_res);
		}
	}

	return rv;
}

typedef struct {
	doupre_server_cfg_t *cfg;
	server_rec *s;
	bool read;
} doupre_c_d_params_t;

apr_status_t doupre_hs_constructor(void **resource, void *params,
				   apr_pool_t * pool)
{
	doupre_c_d_params_t *pms = params;
	char *error;

	int port;
	const char *host;
	server_rec *s;

	host = pms->cfg->hs_host;
	port = pms->read ? pms->cfg->hs_read_port : pms->cfg->hs_write_port;
	s = pms->s;

	int sock;
	sock = hs_connect(host, port, &error);
	if (sock < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			     "error while connecting to hs (%s:%d): %s", host,
			     port, error);
		free(error);
		return APR_EGENERAL;
	}

	doupre_hs_res_t *res = calloc(1, sizeof(*res));
	res->sock = sock;

	*resource = res;

	return APR_SUCCESS;
}

apr_status_t doupre_hs_destructor(void *resource, void *params,
				  apr_pool_t * pool)
{
	doupre_hs_res_t *res = resource;
	hs_disconnect(res->sock);
	free(res);
	return APR_SUCCESS;
}

static int doupre_post_config(apr_pool_t * pconf, apr_pool_t * plog,
			      apr_pool_t * ptemp, server_rec * s)
{
	server_rec *sp;
	apr_status_t rv;

	for (sp = s; sp; sp = sp->next) {
		doupre_server_cfg_t *sconf =
		    ap_get_module_config(sp->module_config, &doupre_module);

		if (!sconf->enabled) {
			continue;
		}

		doupre_c_d_params_t *params_read =
		    apr_pcalloc(pconf, sizeof(*params_read));
		doupre_c_d_params_t *params_write =
		    apr_pcalloc(pconf, sizeof(*params_write));

		params_read->cfg = sconf;
		params_write->cfg = sconf;
		params_read->s = sp;
		params_write->s = sp;

		params_read->read = true;
		rv = apr_reslist_create(&sconf->reslist_read,
					sconf->reslist_min, sconf->reslist_smax,
					sconf->reslist_hmax, sconf->reslist_ttl,
					doupre_hs_constructor,
					doupre_hs_destructor, params_read,
					pconf);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, sp,
				     "Error while creating reslist for HandlerSocket read port");
			return DECLINED;
		}

		params_write->read = false;
		rv = apr_reslist_create(&sconf->reslist_write,
					sconf->reslist_min, sconf->reslist_smax,
					sconf->reslist_hmax, sconf->reslist_ttl,
					doupre_hs_constructor,
					doupre_hs_destructor, params_write,
					pconf);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, sp,
				     "Error while creating reslist for HandlerSocket write port");
			return DECLINED;
		}

	}

	return OK;
}

typedef enum {
	cmd_enabled,
	cmd_hs_host,
	cmd_hs_read_port,
	cmd_hs_write_port,
	cmd_reslist_min,
	cmd_reslist_smax,
	cmd_reslist_hmax,
	cmd_reslist_ttl
} cmd_parts;

static const char *doupre_cmd_args(cmd_parms * cmd, void *dconf,
				   const char *val)
{
	doupre_server_cfg_t *sconf =
	    ap_get_module_config(cmd->server->module_config, &doupre_module);

	switch ((long)cmd->info) {
	case cmd_hs_host:
		sconf->hs_host = val;
		break;
	case cmd_hs_read_port:
		sconf->hs_read_port = atoi(val);
		break;
	case cmd_hs_write_port:
		sconf->hs_write_port = atoi(val);
		break;
	case cmd_reslist_min:
		sconf->reslist_min = atoi(val);
		break;
	case cmd_reslist_smax:
		sconf->reslist_smax = atoi(val);
		break;
	case cmd_reslist_hmax:
		sconf->reslist_hmax = atoi(val);
		break;
	case cmd_reslist_ttl:
		sconf->reslist_ttl = atoi(val);
		break;
	}

	return NULL;
}

static const char *doupre_cmd_flag(cmd_parms * cmd, void *dconf, int flag)
{
	doupre_server_cfg_t *sconf =
	    ap_get_module_config(cmd->server->module_config, &doupre_module);

	switch ((long)cmd->info) {
	case cmd_enabled:
		sconf->enabled = flag;
		break;
	}

	return NULL;
}

static void *doupre_server_config_create(apr_pool_t * p, server_rec * s)
{
	doupre_server_cfg_t *sconf = apr_pcalloc(p, sizeof(*sconf));

	sconf->enabled = false;

	sconf->hs_host = "localhost";
	sconf->hs_read_port = 9998;
	sconf->hs_write_port = 9999;

	sconf->reslist_min = 1;
	sconf->reslist_smax = 5;
	sconf->reslist_hmax = 10;
	sconf->reslist_ttl = 0;

	return sconf;
}

static void *doupre_server_config_merge(apr_pool_t * p, void *basev,
					void *overridesv)
{
	doupre_server_cfg_t *ps = apr_pcalloc(p, sizeof(*ps));
	doupre_server_cfg_t *base = basev;
	doupre_server_cfg_t *overrides = overridesv;

	ps->enabled =
	    base->enabled ==
	    overrides->enabled ? base->enabled : overrides->enabled;

	ps->hs_host =
	    !apr_strnatcmp(base->hs_host,
			   overrides->hs_host) ? base->hs_host : overrides->
	    hs_host;
	ps->hs_read_port =
	    base->hs_read_port ==
	    overrides->hs_read_port ? base->hs_read_port : overrides->
	    hs_read_port;
	ps->hs_write_port =
	    base->hs_write_port ==
	    overrides->hs_write_port ? base->hs_write_port : overrides->
	    hs_write_port;

	ps->reslist_min =
	    base->reslist_min ==
	    overrides->reslist_min ? base->reslist_min : overrides->reslist_min;
	ps->reslist_smax =
	    base->reslist_smax ==
	    overrides->reslist_smax ? base->reslist_smax : overrides->
	    reslist_smax;
	ps->reslist_hmax =
	    base->reslist_hmax ==
	    overrides->reslist_hmax ? base->reslist_hmax : overrides->
	    reslist_hmax;
	ps->reslist_ttl =
	    base->reslist_ttl ==
	    overrides->reslist_ttl ? base->reslist_ttl : overrides->reslist_ttl;

	return ps;
}

static void doupre_register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(doupre_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(doupre_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec doupre_cmds[] = {
	AP_INIT_FLAG("DoupreEnabled", doupre_cmd_flag, (void *)cmd_enabled,
		     RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreHSHost", doupre_cmd_args, (void *)cmd_hs_host,
		      RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreHSReadPort", doupre_cmd_args,
		      (void *)cmd_hs_read_port, RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreHSWritePort", doupre_cmd_args,
		      (void *)cmd_hs_write_port, RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreReslistMin", doupre_cmd_args,
		      (void *)cmd_reslist_min, RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreReslistSMax", doupre_cmd_args,
		      (void *)cmd_reslist_smax, RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreReslistHMax", doupre_cmd_args,
		      (void *)cmd_reslist_hmax, RSRC_CONF, ""),
	AP_INIT_TAKE1("DoupreReslistTtl", doupre_cmd_args,
		      (void *)cmd_reslist_ttl, RSRC_CONF, ""),
	{NULL}
};

module AP_MODULE_DECLARE_DATA doupre_module = {
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir    config structures */
	NULL,			/* merge  per-dir    config structures */
	doupre_server_config_create,	/* create per-server config structures */
	doupre_server_config_merge,	/* merge  per-server config structures */
	doupre_cmds,		/* table of config file commands       */
	doupre_register_hooks	/* register hooks                      */
};
