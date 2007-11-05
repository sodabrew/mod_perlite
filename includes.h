
#ifndef INCLUDES_H
#define INCLUDES_H

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "ap_config.h"

#include "apr_portable.h"
#include "apr_file_io.h"
#include "apr_errno.h"

#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"

#define PERLITE_MAGIC_TYPE "application/x-httpd-perlite"
#define PERLITE_SCRIPT "perlite-script"

#define MP_INLINE
#define MP_FUNC NULL
#define MP_TRACE_r(...)

#define MP_IO_TIE_PERLIO 1

// begin modperl_perl_global.h

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

#ifndef MP_IOBUFSIZE
#   ifdef AP_IOBUFSIZE
#      define MP_IOBUFSIZE AP_IOBUFSIZE
#   else
#      define MP_IOBUFSIZE 8192
#   endif
#endif

typedef apr_array_header_t MpAV;

typedef struct {
    int outcnt;
    char outbuf[MP_IOBUFSIZE];
    apr_pool_t *pool;
    ap_filter_t **filters;
    int header_parse;
    request_rec *r;
} modperl_wbucket_t;

#define MP_HANDLER_NUM_PER_DIR 10
#define MP_HANDLER_NUM_PER_SRV 10

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

// end modperl_types.h

#include "modperl_util.h"
#include "modperl_io.h"
#include "modperl_io_apache.h"

#endif
