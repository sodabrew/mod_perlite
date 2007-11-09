
#include "mod_perlite.h"

// BEGIN perl -MExtUtils::Embed -e xsinit -- -o -

EXTERN_C void xs_init (pTHX);

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

EXTERN_C void
xs_init(pTHX)
{
	char *file = __FILE__;
	dXSUB_SYS;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}
// END  perl -MExtUtils::Embed -e xsinit -- -o -

// Redirect STDOUT to Apache

__thread request_rec *thread_r;

#define crazyhv(h, key, val) \
	hv_store(h, key, sizeof(key)-1, newSVpv(val, 0), 0);

XS(XS_Perlite_get_env);
XS(XS_Perlite_get_env)
{
    dXSARGS;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, thread_r, "Getting \%ENV");
    if (items != 0)
	Perl_croak(aTHX_ "Usage: Perlite::perlite_get_env()");
    {
	dXSTARG;
        HV *RETVAL = newHV();

	crazyhv(RETVAL, "DOCUMENT_ROOT"         , ap_document_root(thread_r)       );
	crazyhv(RETVAL, "REMOTE_ADDR"           , thread_r->connection->remote_ip  );
	crazyhv(RETVAL, "GATEWAY_INTERFACE"     , "CGI/1.1"                        );
	crazyhv(RETVAL, "HTTP_ACCEPT"           , "FIXME"                          );
	crazyhv(RETVAL, "HTTP_ACCEPT_ENCODING"  , "FIXME"                          );
	crazyhv(RETVAL, "HTTP_ACCEPT_LANGUAGE"  , "FIXME"                          );
	crazyhv(RETVAL, "HTTP_CACHE_CONTROL"    , "FIXME"                          );
	crazyhv(RETVAL, "HTTP_CONNECTION"       , "FIXME"                          );

///struct request_rec {
///    /** The pool associated with the request */
///    apr_pool_t *pool;
///    /** The connection to the client */
///    conn_rec *connection;
///    /** The virtual host for this request */
///    server_rec *server;
///
///    /** Pointer to the redirected request if this is an external redirect */
///    request_rec *next;
///    /** Pointer to the previous request if this is an internal redirect */
///    request_rec *prev;
///
///    /** Pointer to the main request if this is a sub-request
///     * (see http_request.h) */
///    request_rec *main;
///
///    /* Info about the request itself... we begin with stuff that only
///     * protocol.c should ever touch...
///     */
///    /** First line of request */
///    char *the_request;
///    /** HTTP/0.9, "simple" request (e.g. GET /foo\n w/no headers) */
///    int assbackwards;
///    /** A proxy request (calculated during post_read_request/translate_name)
///     *  possible values PROXYREQ_NONE, PROXYREQ_PROXY, PROXYREQ_REVERSE,
///     *                  PROXYREQ_RESPONSE
///     */
///    int proxyreq;
///    /** HEAD request, as opposed to GET */
///    int header_only;
///    /** Protocol string, as given to us, or HTTP/0.9 */
///    char *protocol;
///    /** Protocol version number of protocol; 1.1 = 1001 */
///    int proto_num;
///    /** Host, as set by full URI or Host: */
///    const char *hostname;
///
///    /** Time when the request started */
///    apr_time_t request_time;
///
///    /** Status line, if set by script */
///    const char *status_line;
///    /** Status line */
///    int status;
///
///    /* Request method, two ways; also, protocol, etc..  Outside of protocol.c,
///     * look, but don't touch.
///     */
///
///    /** Request method (eg. GET, HEAD, POST, etc.) */
///    const char *method;
///    /** M_GET, M_POST, etc. */
///    int method_number;
///
///    /**
///     *  'allowed' is a bitvector of the allowed methods.
///     *
///     *  A handler must ensure that the request method is one that
///     *  it is capable of handling.  Generally modules should DECLINE
///     *  any request methods they do not handle.  Prior to aborting the
///     *  handler like this the handler should set r->allowed to the list
///     *  of methods that it is willing to handle.  This bitvector is used
///     *  to construct the "Allow:" header required for OPTIONS requests,
///     *  and HTTP_METHOD_NOT_ALLOWED and HTTP_NOT_IMPLEMENTED status codes.
///     *
///     *  Since the default_handler deals with OPTIONS, all modules can
///     *  usually decline to deal with OPTIONS.  TRACE is always allowed,
///     *  modules don't need to set it explicitly.
///     *
///     *  Since the default_handler will always handle a GET, a
///     *  module which does *not* implement GET should probably return
///     *  HTTP_METHOD_NOT_ALLOWED.  Unfortunately this means that a Script GET
///     *  handler can't be installed by mod_actions.
///     */
///    apr_int64_t allowed;
///    /** Array of extension methods */
///    apr_array_header_t *allowed_xmethods; 
///    /** List of allowed methods */
///    ap_method_list_t *allowed_methods; 
///
///    /** byte count in stream is for body */
///    apr_off_t sent_bodyct;
///    /** body byte count, for easy access */
///    apr_off_t bytes_sent;
///    /** Last modified time of the requested resource */
///    apr_time_t mtime;
///
///    /* HTTP/1.1 connection-level features */
///
///    /** sending chunked transfer-coding */
///    int chunked;
///    /** The Range: header */
///    const char *range;
///    /** The "real" content length */
///    apr_off_t clength;
///
///    /** Remaining bytes left to read from the request body */
///    apr_off_t remaining;
///    /** Number of bytes that have been read  from the request body */
///    apr_off_t read_length;
///    /** Method for reading the request body
///     * (eg. REQUEST_CHUNKED_ERROR, REQUEST_NO_BODY,
///     *  REQUEST_CHUNKED_DECHUNK, etc...) */
///    int read_body;
///    /** reading chunked transfer-coding */
///    int read_chunked;
///    /** is client waiting for a 100 response? */
///    unsigned expecting_100;
///
///    /* MIME header environments, in and out.  Also, an array containing
///     * environment variables to be passed to subprocesses, so people can
///     * write modules to add to that environment.
///     *
///     * The difference between headers_out and err_headers_out is that the
///     * latter are printed even on error, and persist across internal redirects
///     * (so the headers printed for ErrorDocument handlers will have them).
///     *
///     * The 'notes' apr_table_t is for notes from one module to another, with no
///     * other set purpose in mind...
///     */
///
///    /** MIME header environment from the request */
///    apr_table_t *headers_in;
///    /** MIME header environment for the response */
///    apr_table_t *headers_out;
///    /** MIME header environment for the response, printed even on errors and
///     * persist across internal redirects */
///    apr_table_t *err_headers_out;
///    /** Array of environment variables to be used for sub processes */
///    apr_table_t *subprocess_env;
///    /** Notes from one module to another */
///    apr_table_t *notes;
///
///    /* content_type, handler, content_encoding, and all content_languages 
///     * MUST be lowercased strings.  They may be pointers to static strings;
///     * they should not be modified in place.
///     */
///    /** The content-type for the current request */
///    const char *content_type;	/* Break these out --- we dispatch on 'em */
///    /** The handler string that we use to call a handler function */
///    const char *handler;	/* What we *really* dispatch on */
///
///    /** How to encode the data */
///    const char *content_encoding;
///    /** Array of strings representing the content languages */
///    apr_array_header_t *content_languages;
///
///    /** variant list validator (if negotiated) */
///    char *vlist_validator;
///    
///    /** If an authentication check was made, this gets set to the user name. */
///    char *user;	
///    /** If an authentication check was made, this gets set to the auth type. */
///    char *ap_auth_type;
///
///    /** This response can not be cached */
///    int no_cache;
///    /** There is no local copy of this response */
///    int no_local_copy;
///
///    /* What object is being requested (either directly, or via include
///     * or content-negotiation mapping).
///     */
///
///    /** The URI without any parsing performed */
///    char *unparsed_uri;	
///    /** The path portion of the URI */
///    char *uri;
///    /** The filename on disk corresponding to this response */
///    char *filename;
///    /* XXX: What does this mean? Please define "canonicalize" -aaron */
///    /** The true filename, we canonicalize r->filename if these don't match */
///    char *canonical_filename;
///    /** The PATH_INFO extracted from this request */
///    char *path_info;
///    /** The QUERY_ARGS extracted from this request */
///    char *args;	
///    /**  finfo.protection (st_mode) set to zero if no such file */
///    apr_finfo_t finfo;
///    /** A struct containing the components of URI */
///    apr_uri_t parsed_uri;
///
///    /**
///     * Flag for the handler to accept or reject path_info on 
///     * the current request.  All modules should respect the
///     * AP_REQ_ACCEPT_PATH_INFO and AP_REQ_REJECT_PATH_INFO 
///     * values, while AP_REQ_DEFAULT_PATH_INFO indicates they
///     * may follow existing conventions.  This is set to the
///     * user's preference upon HOOK_VERY_FIRST of the fixups.
///     */
///    int used_path_info;
///
///    /* Various other config info which may change with .htaccess files
///     * These are config vectors, with one void* pointer for each module
///     * (the thing pointed to being the module's business).
///     */
///
///    /** Options set in config files, etc. */
///    struct ap_conf_vector_t *per_dir_config;
///    /** Notes on *this* request */
///    struct ap_conf_vector_t *request_config;
///
///    /**
///     * A linked list of the .htaccess configuration directives
///     * accessed by this request.
///     * N.B. always add to the head of the list, _never_ to the end.
///     * that way, a sub request's list can (temporarily) point to a parent's list
///     */
///    const struct htaccess_result *htaccess;
///
///    /** A list of output filters to be used for this request */
///    struct ap_filter_t *output_filters;
///    /** A list of input filters to be used for this request */
///    struct ap_filter_t *input_filters;
///
///    /** A list of protocol level output filters to be used for this
///     *  request */
///    struct ap_filter_t *proto_output_filters;
///    /** A list of protocol level input filters to be used for this
///     *  request */
///    struct ap_filter_t *proto_input_filters;
///
///    /** A flag to determine if the eos bucket has been sent yet */
///    int eos_sent;
///
////* Things placed at the end of the record to avoid breaking binary
/// * compatibility.  It would be nice to remember to reorder the entire
/// * record to improve 64bit alignment the next time we need to break
/// * binary compatibility for some other reason.
/// */
///};

        ST(0) = newRV((SV*)RETVAL);
        sv_2mortal(ST(0));
    }
    XSRETURN(1);
}

XS(XS_PerliteIO_perlite_io_write);
XS(XS_PerliteIO_perlite_io_write)
{
    dXSARGS;
//    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, thread_r, "In %s: %d", __func__, __LINE__);
    if (items != 1)
	Perl_croak(aTHX_ "Usage: PerliteIO::perlite_io_write(buf)");
    {
        STRLEN        len;
	int	      RETVAL;
	char        * buf = (char *)SvPV(ST(0), len);
//	IV            riv = ST(1);
//	request_rec * r   = INT2PTR(request_rec *, riv);
	dXSTARG;
        RETVAL = ap_rwrite(buf, len, thread_r);
	XSprePUSH; PUSHi((IV)RETVAL);
    }
    XSRETURN(1);
}

// Meat of the module

static int perlite_handler(request_rec *r)
{
    PerlInterpreter *my_perl;

    int argc = 0;
    char *argv[] = { "", NULL };
    char **env = NULL;

    // Make the request available as a thread-local global.
    thread_r = r;

    // Only handle our own files
    if (strcmp(r->handler, PERLITE_MAGIC_TYPE)) {
        return DECLINED;
    }

    // FIXME: find this header from the script.
    r->content_type = "text/html";      

    if (r->header_only) {
        // We have no further headers to add at this time.
        return OK;
    }

    PERL_SYS_INIT3(&argc,&argv,&env);
    my_perl = perl_alloc();
    PL_perl_destruct_level = 1;
    perl_construct(my_perl);

    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    perl_parse(my_perl, xs_init, argc, argv, env);
    perl_run(my_perl);

    newXSproto("Perlite::IO::perlite_io_write", XS_PerliteIO_perlite_io_write, __FILE__, "$");
    newXSproto("Perlite::perlite_get_env", XS_Perlite_get_env, __FILE__, "");
//    newXSproto("Perlite::perlite_warn", XS_Perlite_warn, __FILE__, "$");
//    newXSproto("Perlite::perlite_die", XS_Perlite_die, __FILE__, "$");

    // FIXME: how to get errors from here?
    eval_pv("use lib '/home/aaron/codingprojects/mod_perlite';", TRUE);
    eval_pv("use Perlite;", TRUE);

    char *call_args[] = { r->filename, NULL };
    int res = call_argv("Perlite::run_file", TRUE, call_args);

    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();
    
    return OK;
}

static void perlite_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(perlite_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static apr_status_t destroy_perlite_config(void *data)
{
    return APR_SUCCESS;
}

void *create_perlite_config(apr_pool_t *p, char *dummy)
{
    return NULL;
}

void *merge_perlite_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    return NULL;
}

module AP_MODULE_DECLARE_DATA perlite_module = {
    STANDARD20_MODULE_STUFF, 
    create_perlite_config,      /* create per-dir    config structures */
    merge_perlite_config,       /* merge  per-dir    config structures */
    NULL,                       /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    NULL,                       /* table of config file commands       */
    perlite_register_hooks      /* register hooks                      */
};
