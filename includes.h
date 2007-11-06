
#ifndef INCLUDES_H
#define INCLUDES_H

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_protocol.h"

#include "ap_config.h"

#include "apr_portable.h"
#include "apr_file_io.h"
#include "apr_errno.h"
#include "apr_lib.h"

/* needed starting from 5.8.2 to access the PERL_HASH_INTERNAL macro
 * in hv.h. we use it in modperl_util.c */
#define PERL_HASH_INTERNAL_ACCESS

#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"

#define PERLITE_MAGIC_TYPE "application/x-httpd-perlite"
#define PERLITE_SCRIPT "perlite-script"

#define MP_INLINE
#define MP_FUNC NULL
#define MP_TRACE_r(...)
#define MP_TRACE_o(...)
#define MP_TRACE_g(...)
#define MP_TRACE_f(...)

#define MP_dINTERP_SELECT(r, c, s) dNOOP

#define MP_INTERP_PUTBACK(interp) NOOP

#define MODPERL_FILTER_ERROR   APR_OS_START_USERERR + 1

#define MP_aTHX 0

#define MP_IO_TIE_PERLIO 1

#define modperl_threaded_mpm(foo) 0

extern module AP_MODULE_DECLARE_DATA perlite_module;

// begin modperl_config.h

#define MP_dRCFG \
    modperl_config_req_t *rcfg = modperl_config_req_get(r)

#if defined(MP_IN_XS) && defined(WIN32)
#   define modperl_get_module_config(v)         \
    modperl_get_perl_module_config(v)

#   define modperl_set_module_config(v, c)      \
    modperl_set_perl_module_config(v, c)
#else
#   define modperl_get_module_config(v)         \
    ap_get_module_config(v, &perlite_module)

#   define modperl_set_module_config(v, c)      \
    ap_set_module_config(v, &perlite_module, c)
#endif

#define modperl_config_req_get(r)                               \
    (r ? (modperl_config_req_t *)                               \
     modperl_get_module_config(r->request_config) : NULL)

// end modperl_config.h

// begin modperl_perl_global.h

#define MP_dDCFG \
    modperl_config_dir_t *dcfg = modperl_config_dir_get(r)

typedef struct {
    const char *name;
    const char *val;
    I32 len;
    U32 hash;
} modperl_modglobal_key_t;

typedef enum {
    MP_MODGLOBAL_END
} modperl_modglobal_key_e;

typedef struct {
    AV **av;
    modperl_modglobal_key_e key;
} modperl_perl_global_avcv_t;

typedef struct {
    GV *gv;
    AV *tmpav;
    AV *origav;
} modperl_perl_global_gvav_t;

typedef struct {
    GV *gv;
    HV *tmphv;
    HV *orighv;
} modperl_perl_global_gvhv_t;

typedef struct {
    GV *gv;
    char flags;
} modperl_perl_global_gvio_t;

typedef struct {
    SV **sv;
    char pv[256]; /* XXX: only need enough for $/ at the moment */
    I32 cur;
} modperl_perl_global_svpv_t;

typedef struct {
    modperl_perl_global_avcv_t end;
    modperl_perl_global_gvhv_t env;
    modperl_perl_global_gvav_t inc;
    modperl_perl_global_gvio_t defout;
    modperl_perl_global_svpv_t rs;
} modperl_perl_globals_t;

// end modperl_perl_global.h

// begin modperl_types.h

typedef apr_array_header_t MpAV;
typedef apr_table_t        MpHV;

#define MP_HANDLER_NUM_PER_DIR 10
#define MP_HANDLER_NUM_PER_SRV 10

typedef U32 modperl_opts_t;

typedef struct {
    modperl_opts_t opts;
    modperl_opts_t opts_add;
    modperl_opts_t opts_remove;
    modperl_opts_t opts_override;
    modperl_opts_t opts_seen;
    int unset;
} modperl_options_t;

typedef struct {
    char *location;
    char *PerlDispatchHandler;
    MpAV *handlers_per_dir[MP_HANDLER_NUM_PER_DIR];
    MpHV *SetEnv;
    MpHV *setvars;
    MpHV *configvars;
    modperl_options_t *flags;
#ifdef USE_ITHREADS
    modperl_interp_scope_e interp_scope;
#endif
} modperl_config_dir_t;

#ifndef MP_IOBUFSIZE
#   ifdef AP_IOBUFSIZE
#      define MP_IOBUFSIZE AP_IOBUFSIZE
#   else
#      define MP_IOBUFSIZE 8192
#   endif
#endif

typedef struct {
    int outcnt;
    char outbuf[MP_IOBUFSIZE];
    apr_pool_t *pool;
    ap_filter_t **filters;
    int header_parse;
    request_rec *r;
} modperl_wbucket_t;

typedef struct {
    HV *pnotes;
    SV *global_request_obj;
    U8 flags;
    int status;
    modperl_wbucket_t *wbucket;
    MpAV *handlers_per_dir[MP_HANDLER_NUM_PER_DIR];
    MpAV *handlers_per_srv[MP_HANDLER_NUM_PER_SRV];
    modperl_perl_globals_t perl_globals;
#ifdef USE_ITHREADS
    modperl_interp_t *interp;
#endif
} modperl_config_req_t;

typedef struct {
    apr_pool_t *pool;
    void *data;
} modperl_cleanup_data_t;

typedef struct modperl_handler_t modperl_handler_t;

typedef struct modperl_mgv_t modperl_mgv_t;

struct modperl_mgv_t {
    char *name;
    int len;
    UV hash;
    modperl_mgv_t *next;
};

struct modperl_handler_t {
    /* could be:
     * - the lightweight gv for named subs
     * - the lookup data in $PL_modperl{ANONSUB}
     */
    modperl_mgv_t *mgv_obj;
    modperl_mgv_t *mgv_cv;
    /* could be:
     * - a subroutine name for named subs
     * - NULL for anon subs
     */
    const char *name; 
    CV *cv;
    U8 flags;
    U32 attrs;
    modperl_handler_t *next;
};

#define MP_HANDLER_TYPE_CHAR 1
#define MP_HANDLER_TYPE_SV   2

typedef enum {
    MP_INPUT_FILTER_MODE,
    MP_OUTPUT_FILTER_MODE
} modperl_filter_mode_e;

typedef struct {
    int seen_eos;
    int eos;
    int flush;
    ap_filter_t *f;
    char *leftover;
    apr_ssize_t remaining;
    modperl_wbucket_t *wbucket;
    apr_bucket *bucket;
    apr_bucket_brigade *bb_in;
    apr_bucket_brigade *bb_out;
    ap_input_mode_t input_mode;
    apr_read_type_e block;
    apr_off_t readbytes;
    apr_status_t rc;
    modperl_filter_mode_e mode;
    apr_pool_t *pool;
    apr_pool_t *temp_pool;
} modperl_filter_t;

typedef struct {
    int sent_eos;
    SV *data;
    modperl_handler_t *handler;
    PerlInterpreter *perl;
} modperl_filter_ctx_t;

// end modperl_types.h

// begin modperl_common_util.h

#ifdef WIN32
#   define MP_FUNC_T(name)          (_stdcall *name)
#   define MP_FUNC_NONSTD_T(name)   (*name)
/* XXX: not all functions get inlined
 * so its unclear what to and not to include in the .def files
 */
#   undef MP_INLINE
#   define MP_INLINE
#else
#   define MP_FUNC_T(name)          (*name)
#   define MP_FUNC_NONSTD_T(name)   (*name)
#endif

// end modperl_common_util.h

#include "modperl_util.h"
#include "modperl_io.h"
#include "modperl_io_apache.h"
#include "modperl_filter.h"
#include "modperl_handler.h"
#include "modperl_global.h"
#include "modperl_debug.h"
#include "modperl_error.h"

#endif
