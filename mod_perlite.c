
#include "mod_perlite.h"

#define LOG(level, foo...) ap_log_rerror(APLOG_MARK, APLOG_ ## level, 0, thread_r, foo);

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
    if (items != 0)
        Perl_croak(aTHX_ "Usage: Perlite::_env()");
    {
        dXSTARG;
        HV *RETVAL, *hv = newHV();

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

        switch (level) {
            case APLOG_DEBUG:
	        // No problem
	        break;
	    default:
	        // Error if we don't know the right level
	        level = APLOG_ERR;
	}

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
        RETVAL = ap_rwrite(buf, len, thread_r);
        XSprePUSH; PUSHi((IV)RETVAL);
    }
    XSRETURN(1);
}

// Meat of the module

static int perlite_handler(request_rec *r)
{
    PerlInterpreter *my_perl;

    int argc = 0, res = 0;
    char *argv[] = { "", NULL };
    char *run_file[] = { "", NULL };
    char **env = NULL;

    // Only handle our own files
    if (strcmp(r->handler, PERLITE_MAGIC_TYPE)) {
        return DECLINED;
    }

    // Make the request available as a thread-local global.
    thread_r = r;

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

    newXSproto("Perlite::IO::_write", XS_PerliteIO__write, __FILE__, "$");
    newXSproto("Perlite::IO::_header", XS_PerliteIO__header, __FILE__, "$$");
    newXSproto("Perlite::_env", XS_Perlite__env, __FILE__, "");
    newXSproto("Perlite::_log", XS_Perlite__log, __FILE__, "$$");

    eval_pv("use Perlite;", G_EVAL|G_SCALAR|G_KEEPERR);
    if (SvTRUE(ERRSV)) {
        ap_rprintf(thread_r, "Died: %s\n", SvPV_nolen(ERRSV));
        goto handler_done;
    }

    run_file[0] = r->filename;
    res = call_argv("Perlite::run_file", G_EVAL|G_SCALAR|G_KEEPERR, run_file);
    if (SvTRUE(ERRSV)) {
        ap_rprintf(thread_r, "Died: %s\n", SvPV_nolen(ERRSV));
    }

handler_done:

    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();
    
    return OK;
}

// Setup functions

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
