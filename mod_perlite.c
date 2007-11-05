
#include "includes.h"

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

static void perlite_stdout(request_rec *r, PerlInterpreter *my_perl)
{
    STRLEN n_a;
    SV *val;
    val = eval_pv("reverse 'rekcaH lreP rehtonA tsuJ'", TRUE);
    ap_rputs(SvPV(val,n_a), r);
}

static int perlite_handler(request_rec *r)
{
    PerlInterpreter *my_perl;

    int argc = 0;
    char *argv[] = { "", NULL };
    char **env = NULL;

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

    modperl_io_apache_init(aTHX);

    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    perl_parse(my_perl, xs_init, argc, argv, env);
    perl_run(my_perl);

    perlite_stdout(r, my_perl);

    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();
    
    return OK;
}

static void perlite_register_hooks(apr_pool_t *p)
{
//      ap_hook_pre_config(php_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
//      ap_hook_post_config(php_apache_server_startup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(perlite_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static apr_status_t destroy_perlite_config(void *data)
{
//        php_conf_rec *d = data;
//
//        phpapdebug((stderr, "Destroying config %p\n", data));
//        zend_hash_destroy(&d->config);

        return APR_SUCCESS;
}

void *create_perlite_config(apr_pool_t *p, char *dummy)
{
//        php_conf_rec *newx = (php_conf_rec *) apr_pcalloc(p, sizeof(*newx));
//
//        phpapdebug((stderr, "Creating new config (%p) for %s\n", newx, dummy));
//        zend_hash_init(&newx->config, 0, NULL, NULL, 1);
//        apr_pool_cleanup_register(p, newx, destroy_php_config, apr_pool_cleanup_null);
        return NULL;
}

void *merge_perlite_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    return NULL;
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA perlite_module = {
    STANDARD20_MODULE_STUFF, 
    create_perlite_config, /* create per-dir    config structures */
    merge_perlite_config,  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL, // perlite_dir_cmds,      /* table of config file commands       */
    perlite_register_hooks  /* register hooks                      */
};

