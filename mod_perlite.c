
#include "mod_perlite.h"

#define LOG(level, foo...) ap_log_rerror(APLOG_MARK, APLOG_ ## level, 0, thread_r, foo);

int perlite_argc = 0;
char *perlite_argv[] = { "", NULL };
char **perlite_env = NULL;

// DynaLoader from perl -MExtUtils::Embed -e xsinit -- -o -

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

// XS functions to expose some basic Apache hooks

__thread int suppress_output;
__thread request_rec *thread_r;

static int perlite_copy_env(void *hv, const char *key, const char *val)
{
    LOG(DEBUG, "Setting $ENV{%s} = %s", key, val);
    hv_store((HV *)hv, key, strlen(key), newSVpv(val, 0), 0);
    return TRUE;
}

XS(XS_Perlite__env);
XS(XS_Perlite__env)
{
    dXSARGS;
    LOG(DEBUG, "Preparing %%ENV");
    {
        dXSTARG;
        HV *RETVAL, *hv = newHV();

        // TODO: Accept an HV ref argument and replace its elements with those below.

        ap_add_common_vars(thread_r);
        ap_add_cgi_vars(thread_r);

        apr_table_do(perlite_copy_env, hv, thread_r->subprocess_env, NULL);

        hv_store(hv, "MOD_PERLITE", sizeof("MOD_PERLITE")-1, newSVpv(VERSION, 0), 0);

        RETVAL = hv;
        ST(0) = newRV((SV*)RETVAL);
        sv_2mortal(ST(0));
    }
    LOG(DEBUG, "Returning %%ENV");
    XSRETURN(1);
}

XS(XS_Perlite__log);
XS(XS_Perlite__log)
{
    dXSARGS;
    if (items != 2)
        Perl_croak(aTHX_ "Usage: Perlite::_log(level, message)");
    {
        int         level = (   int)SvIV(ST(0));
        char        * msg = (char *)SvPV_nolen(ST(1));
        dXSTARG;

        // I'm not going to bother exporting these constants.
        // I suggest that authors use Sys::Syslog's LOG_foolevel.
        switch (level) {
            case APLOG_EMERG:
            case APLOG_ALERT:
            case APLOG_CRIT:
            case APLOG_ERR:
            case APLOG_WARNING:
            case APLOG_NOTICE:
            case APLOG_INFO:
            case APLOG_DEBUG:
                // We know these.
                break;
            default:
                // Default to ERR.
                level = APLOG_ERR;
        }

        // Can't use the LOG macro due to constant stringification of level.
        ap_log_rerror(APLOG_MARK, level, 0, thread_r, "%s", msg);

    }
    XSRETURN(0);
}

XS(XS_PerliteIO__header);
XS(XS_PerliteIO__header)
{
    dXSARGS;
    LOG(DEBUG, "In %s: %d", __func__, __LINE__);
    if (items != 2)
        Perl_croak(aTHX_ "Usage: PerliteIO::_header(key, value)");
    {
        char        * key = (char *)SvPV_nolen(ST(0));
        char        * val = (char *)SvPV_nolen(ST(1));
        dXSTARG;

        apr_table_add(thread_r->headers_out, key, val);

        if (strcasecmp(key, "Content-Type") == 0) {
            LOG(INFO, "Setting Content-Type: %s", val);
            ap_set_content_type(thread_r, apr_pstrdup(thread_r->pool, val));
        } else if (strcasecmp(key, "Location") == 0) {
            // TODO: set location (r, val);
        } else if (strcasecmp(key, "Status") == 0) {
            // TODO: set status (r, val);
        }

        XSprePUSH; PUSHi((IV)1);
    }
    XSRETURN(1);
}

XS(XS_PerliteIO__write);
XS(XS_PerliteIO__write)
{
    dXSARGS;
    LOG(DEBUG, "In %s: %d", __func__, __LINE__);
    if (items != 1)
        Perl_croak(aTHX_ "Usage: PerliteIO::_write(buf)");
    {
        STRLEN        len;
        int           RETVAL;
        char        * buf = (char *)SvPV(ST(0), len);
        dXSTARG;
        if (!suppress_output) {
            RETVAL = ap_rwrite(buf, len, thread_r);
        } else {
            RETVAL = len;
        }
        XSprePUSH; PUSHi((IV)RETVAL);
    }
    XSRETURN(1);
}

/* Each call should return one Apache bucket to Perl, and undef when we're done. */
XS(XS_PerliteIO__read);
XS(XS_PerliteIO__read)
{
    dXSARGS;
    LOG(DEBUG, "In %s: %d", __func__, __LINE__);
    if (items != 0)
        Perl_croak(aTHX_ "Usage: PerliteIO::_read()");
    {
        SV           * RETVAL = &PL_sv_undef;
        apr_status_t rv;
        dXSTARG;

        RETVAL = newSV(0);

        rv = ap_setup_client_block(thread_r, REQUEST_CHUNKED_DECHUNK);
        if (rv != OK) goto _write_end;
        if (!ap_should_client_block(thread_r)) goto _write_end;
        while (1) {
            char buf[HUGE_STRING_LEN];
            apr_size_t len = ap_get_client_block(thread_r, buf, sizeof(buf)-1);
            if (len == 0) {
                break; /* end of session */
            } else if (len < 0) {
                break; /* error */
            } else {
                sv_catpvn(RETVAL, buf, len);
            }
        }

    _write_end:

        LOG(ERR, "Pushing [%s] back out", SvPV_nolen(RETVAL));

        // FIXME: Is it safe to call sv_2mortal on PL_sv_undef?
        XSprePUSH; PUSHs(sv_2mortal(RETVAL));
    }
    XSRETURN(1);
}

XS(XS_Perlite__exit);
XS(XS_Perlite__exit)
{
    dXSARGS;
    {
        dXSTARG;
        LOG(DEBUG, "Exiting");
        Perl_croak(aTHX_ "Exiting");
        // suppress_output = 1; wtf
    }
    XSRETURN(0);
}


// Meat of the module

static int perlite_handler(request_rec *r)
{
    PerlInterpreter *my_perl;

    int res = 0, retval = OK;
    apr_status_t rv;
    char *run_file[] = { "", NULL };
    char path_before[HUGE_STRING_LEN], path_after[HUGE_STRING_LEN];
    const char *location;

    // Only handle our own files
    if (strcmp(r->handler, PERLITE_MAGIC_TYPE)) {
        return DECLINED;
    }

    // Make the request available as a thread-local global.
    thread_r = r;
    suppress_output = 0;

    if (r->header_only) {
        // TODO: suppress body output?
        LOG(ERR, "Only asked for headers, how rude!");
    }

    getcwd(path_before, HUGE_STRING_LEN -1);

    my_perl = perl_alloc();
    PL_perl_destruct_level = 1;
    perl_construct(my_perl);

    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    perl_parse(my_perl, xs_init, perlite_argc, perlite_argv, perlite_env);
    perl_run(my_perl);

    newXSproto("Perlite::IO::_read", XS_PerliteIO__read, __FILE__, "");
    newXSproto("Perlite::IO::_write", XS_PerliteIO__write, __FILE__, "$");
    newXSproto("Perlite::IO::_header", XS_PerliteIO__header, __FILE__, "$$");
    newXSproto("Perlite::_env", XS_Perlite__env, __FILE__, "");
    newXSproto("Perlite::_log", XS_Perlite__log, __FILE__, "$$");
    newXSproto("Perlite::_exit", XS_Perlite__exit, __FILE__, "");

    require_pv("Perlite.pm");
    if (SvTRUE(ERRSV)) {
        LOG(ERR, "Please make sure that you have Perlite.pm installed in one of the INC locations that follow:"
                 " %s\n", SvPV_nolen(ERRSV));
        retval = HTTP_INTERNAL_SERVER_ERROR;
        goto handler_done;
    }

//    require_pv("Sys/Protect.pm");
//    if (SvTRUE(ERRSV)) {
//        LOG(ERR, "Please make sure that you have Sys/Protect.pm installed in one of the INC locations that follow:"
//                 " %s\n", SvPV_nolen(ERRSV));
//        retval = HTTP_INTERNAL_SERVER_ERROR;
//        goto handler_done;
//    }

    run_file[0] = r->filename;
    res = call_argv("Perlite::run_file", G_EVAL|G_SCALAR|G_KEEPERR, run_file);
    if (SvTRUE(ERRSV)) {
        ap_rprintf(thread_r, "Error: %s\n", SvPV_nolen(ERRSV));
    }

handler_done:

    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);

    getcwd(path_after, HUGE_STRING_LEN -1);
    LOG(DEBUG, "Before running Perl, pwd is [%s]. After running Perl, pwd is [%s]", path_before, path_after);
#ifdef _WIN32
    /* don't use chdir() to back to original directory cause by crash */
    SetCurrentDirectory(path_before);
#else
    chdir(path_before);
#endif

    location = apr_table_get(r->headers_out, "Location");
 
    if (location && location[0] == '/' && r->status == 200) {
        /* This redirect needs to be a GET no matter what the original
         * method was.
         */
        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;
 
        /* We already read the message body (if any), so don't allow
         * the redirected request to think it has one.  We can ignore
         * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
         */
        apr_table_unset(r->headers_in, "Content-Length");
 
        ap_internal_redirect_handler(location, r);
        return OK;
    }
    else if (location && r->status == 200) {
        /* XX Note that if a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */
        return HTTP_MOVED_TEMPORARILY;
    }

    return retval;
}

// Setup functions

static apr_pool_t *server_pool = NULL;

static apr_status_t perlite_hook_term(void *data)
{
    PERL_SYS_TERM();
}

static int perlite_hook_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    PERL_SYS_INIT3(&perlite_argc, &perlite_argv, &perlite_env);
    apr_pool_create(&server_pool, pconf);
    apr_pool_cleanup_register(server_pool, NULL, perlite_hook_term, apr_pool_cleanup_null);
    return OK;
}

static void perlite_register_hooks(apr_pool_t *p)
{
    ap_hook_open_logs(perlite_hook_init, NULL, NULL, APR_HOOK_REALLY_FIRST);
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
