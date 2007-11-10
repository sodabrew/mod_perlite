
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

static int perlite_copy_env(void *hv, const char *key, const char *val)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, thread_r, "Setting $ENV{%s} = %s", key, val);
    hv_store((HV *)hv, key, strlen(key), newSVpv(val, 0), 0);
    return TRUE;
}

XS(XS_Perlite_get_env);
XS(XS_Perlite_get_env)
{
    dXSARGS;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, thread_r, "Preparing %%ENV");
    if (items != 0)
        Perl_croak(aTHX_ "Usage: Perlite::perlite_get_env()");
    {
        dXSTARG;
        HV *RETVAL, *hv = newHV();

        ap_add_common_vars(thread_r);
        ap_add_cgi_vars(thread_r);

        apr_table_do(perlite_copy_env, hv, thread_r->subprocess_env, NULL);

        hv_store(hv, "MOD_PERLITE", sizeof("MOD_PERLITE")-1, newSVpv("Hello World", 0), 0);

        RETVAL = hv;
        ST(0) = newRV((SV*)RETVAL);
        sv_2mortal(ST(0));
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, thread_r, "Returning %%ENV");
    XSRETURN(1);
}

XS(XS_PerliteIO_perlite_io_write);
XS(XS_PerliteIO_perlite_io_write)
{
    dXSARGS;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, thread_r, "In %s: %d", __func__, __LINE__);
    if (items != 1)
        Perl_croak(aTHX_ "Usage: PerliteIO::perlite_io_write(buf)");
    {
        STRLEN        len;
        int              RETVAL;
        char        * buf = (char *)SvPV(ST(0), len);
//        IV            riv = ST(1);
//        request_rec * r   = INT2PTR(request_rec *, riv);
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
//    eval_pv("use lib '/home/aaron/codingprojects/mod_perlite';", TRUE);
    eval_pv("use Perlite;", TRUE);

    run_file[0] = r->filename;
    res = call_argv("Perlite::run_file", TRUE, run_file);

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
