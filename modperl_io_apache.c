/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes.h"

#ifdef MP_IO_TIE_PERLIO

/***************************
 * The PerlIO Apache layer *
 ***************************/

/* PerlIO ":Apache2" layer is used to use the Apache callbacks to read
 * from STDIN and write to STDOUT. The PerlIO API is documented in
 * perliol.pod */

typedef struct {
    struct _PerlIO base;
    request_rec *r;
} PerlIOApache;

/* _open just allocates the layer, _pushed does the real job of
 * filling the data in */
static PerlIO *
PerlIOApache_open(pTHX_ PerlIO_funcs *self, PerlIO_list_t *layers, IV n,
                  const char *mode, int fd, int imode, int perm,
                  PerlIO *f, int narg, SV **args)
{
    if (!f) {
        f = PerlIO_allocate(aTHX);
    }
    if ( (f = PerlIO_push(aTHX_ f, self, mode, args[0])) ) {
        PerlIOBase(f)->flags |= PERLIO_F_OPEN;
    }

    MP_TRACE_o(MP_FUNC, "mode %s", mode);

    return f;
}

/* this callback is used by pushed() and binmode() to add the layer */
static IV
PerlIOApache_pushed(pTHX_ PerlIO *f, const char *mode, SV *arg,
                    PerlIO_funcs *tab)
{
    IV code;
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);

    if (arg) {
        st->r = modperl_sv2request_rec(aTHX_ arg);
        MP_TRACE_o(MP_FUNC, "stored request_rec obj: 0x%lx", st->r);
    }
    else {
        Perl_croak(aTHX_"failed to insert the :Apache2 layer. "
                   "Apache2::RequestRec object argument is required");
        /* XXX: try to get Apache2->request? */
    }

    /* this method also sets the right flags according to the
     * 'mode' */
    code = PerlIOBase_pushed(aTHX_ f, mode, Nullsv, tab);

    return code;
}

static SV *
PerlIOApache_getarg(pTHX_ PerlIO *f, CLONE_PARAMS *param, int flags)
{
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);
    SV *sv;

    if (!st->r) {
        Perl_croak(aTHX_ "an attempt to getarg from a stale io handle");
    }

    sv = newSV(0);
    sv_setref_pv(sv, "Apache2::RequestRec", (void*)(st->r));

    MP_TRACE_o(MP_FUNC, "retrieved request_rec obj: 0x%lx", st->r);

    return sv;
}

static IV
PerlIOApache_fileno(pTHX_ PerlIO *f)
{
    /* XXX: we could return STDIN => 0, STDOUT => 1, but that wouldn't
     * be correct, as the IO goes through the socket, may be we should
     * return the filedescriptor of the socket? 
     *
     * -1 in this case indicates that the layer cannot provide fileno
     */
    MP_TRACE_o(MP_FUNC, "did nothing");
    return -1;
}

static SSize_t
PerlIOApache_read(pTHX_ PerlIO *f, void *vbuf, Size_t count)
{
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);
    request_rec *r = st->r;

    if (!(PerlIOBase(f)->flags & PERLIO_F_CANREAD) ||
        PerlIOBase(f)->flags & (PERLIO_F_EOF|PERLIO_F_ERROR)) {
        return 0;
    }

    return modperl_request_read(aTHX_ r, (char*)vbuf, count);
}

static SSize_t
PerlIOApache_write(pTHX_ PerlIO *f, const void *vbuf, Size_t count)
{
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);
    modperl_config_req_t *rcfg = modperl_config_req_get(st->r);
    apr_size_t bytes = 0;
    apr_status_t rv;

    if (!(PerlIOBase(f)->flags & PERLIO_F_CANWRITE)) {
        return 0;
    }

    MP_CHECK_WBUCKET_INIT("print");

    MP_TRACE_o(MP_FUNC, "%4db [%s]", count,
               MP_TRACE_STR_TRUNC(rcfg->wbucket->pool, vbuf, count));

    rv = modperl_wbucket_write(aTHX_ rcfg->wbucket, vbuf, &count);
    if (rv != APR_SUCCESS) {
        Perl_croak(aTHX_ modperl_error_strerror(aTHX_ rv)); 
    }
    bytes += count;

    return (SSize_t) bytes;
}

static IV
PerlIOApache_flush(pTHX_ PerlIO *f)
{
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);
    modperl_config_req_t *rcfg;

    if (!st->r) {
        Perl_warn(aTHX_ "an attempt to flush a stale IO handle");
        return -1;
    }

    /* no flush on readonly io handle */
    if (! (PerlIOBase(f)->flags & PERLIO_F_CANWRITE) ) {
        return -1;
    }

    rcfg = modperl_config_req_get(st->r);

    MP_CHECK_WBUCKET_INIT("flush");

    MP_TRACE_o(MP_FUNC, "%4db [%s]", rcfg->wbucket->outcnt,
               MP_TRACE_STR_TRUNC(rcfg->wbucket->pool,
                                  rcfg->wbucket->outbuf,
                                  rcfg->wbucket->outcnt));

    MP_RUN_CROAK(modperl_wbucket_flush(rcfg->wbucket, FALSE),
                 ":Apache2 IO flush");

    return 0;
}

/* 5.8.0 doesn't export PerlIOBase_noop_fail, so we duplicate it here */
static IV PerlIOApache_noop_fail(pTHX_ PerlIO *f)
{
    return -1;
}

static IV
PerlIOApache_close(pTHX_ PerlIO *f)
{
    IV code = PerlIOBase_close(aTHX_ f);
    PerlIOApache *st = PerlIOSelf(f, PerlIOApache);

    MP_TRACE_o(MP_FUNC, "done with request_rec obj: 0x%lx", st->r);
    /* prevent possible bugs where a stale r will be attempted to be
     * reused (e.g. dupped filehandle) */
    st->r = NULL;

    return code;
}

static IV
PerlIOApache_popped(pTHX_ PerlIO *f)
{
    /* XXX: just temp for tracing */
    MP_TRACE_o(MP_FUNC, "done");
    return PerlIOBase_popped(aTHX_ f);
}


static PerlIO_funcs PerlIO_Apache = {
    sizeof(PerlIO_funcs),
    "Apache2",
    sizeof(PerlIOApache),
    PERLIO_K_MULTIARG | PERLIO_K_RAW,
    PerlIOApache_pushed,
    PerlIOApache_popped,
    PerlIOApache_open,
    PerlIOBase_binmode,
    PerlIOApache_getarg,
    PerlIOApache_fileno,
    PerlIOBase_dup,
    PerlIOApache_read,
    PerlIOBase_unread,
    PerlIOApache_write,
    NULL,                       /* can't seek on STD{IN|OUT}, fail on call*/
    NULL,                       /* can't tell on STD{IN|OUT}, fail on call*/
    PerlIOApache_close,
    PerlIOApache_flush,        
    PerlIOApache_noop_fail,     /* fill */
    PerlIOBase_eof,
    PerlIOBase_error,
    PerlIOBase_clearerr,
    PerlIOBase_setlinebuf,
    NULL,                       /* get_base */
    NULL,                       /* get_bufsiz */
    NULL,                       /* get_ptr */
    NULL,                       /* get_cnt */
    NULL,                       /* set_ptrcnt */
};

/* ***** End of PerlIOApache tab ***** */

MP_INLINE void modperl_io_apache_init(pTHX)
{
    PerlIO_define_layer(aTHX_ &PerlIO_Apache);
}

#endif /* defined MP_IO_TIE_PERLIO */

/******  Other request IO functions  *******/


MP_INLINE SSize_t modperl_request_read(pTHX_ request_rec *r,
                                       char *buffer, Size_t len)
{
    SSize_t total = 0;
    Size_t wanted = len;
    int seen_eos = 0;
    char *tmp = buffer;
    apr_bucket_brigade *bb;

    if (len <= 0) {
        return 0;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb == NULL) {
        r->connection->keepalive = AP_CONN_CLOSE;
        Perl_croak(aTHX_ "failed to create bucket brigade");
    }

    do {
        apr_size_t read;
        apr_status_t rc;

        rc = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, len);
        if (rc != APR_SUCCESS) { 
            /* if we fail here, we want to stop trying to read data
             * from the client.
             */
            r->connection->keepalive = AP_CONN_CLOSE;
            apr_brigade_destroy(bb);
            modperl_croak(aTHX_ rc, "Apache2::RequestIO::read");
        }

        /* If this fails, it means that a filter is written
         * incorrectly and that it needs to learn how to properly
         * handle APR_BLOCK_READ requests by returning data when
         * requested.
         */
        if (APR_BRIGADE_EMPTY(bb)) {
            apr_brigade_destroy(bb);
            /* we can't tell which filter is broken, since others may
             * just pass data through */
            Perl_croak(aTHX_ "Apache2::RequestIO::read: "
                       "Aborting read from client. "
                       "One of the input filters is broken. "
                       "It returned an empty bucket brigade for "
                       "the APR_BLOCK_READ mode request");
        }

        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
            seen_eos = 1;
        }

        read = len;
        rc = apr_brigade_flatten(bb, tmp, &read);
        if (rc != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            modperl_croak(aTHX_ rc, "Apache2::RequestIO::read");
        }

        total += read;
        tmp   += read;
        len   -= read;

        /* XXX: what happens if the downstream filter returns more
         * data than the caller has asked for? We can't return more
         * data than requested, so it needs to be stored somewhere and
         * dealt with on the subsequent calls to this function. or may
         * be we should just assert, blaming a bad filter. at the
         * moment I couldn't find a spec telling whether it's wrong
         * for the filter to return more data than it was asked for in
         * the AP_MODE_READBYTES mode.
         */

        apr_brigade_cleanup(bb);

    } while (len > 0 && !seen_eos);

    apr_brigade_destroy(bb);

    MP_TRACE_o(MP_FUNC, "wanted %db, read %db [%s]", wanted, total,
               MP_TRACE_STR_TRUNC(r->pool, buffer, total));

    return total;
}




