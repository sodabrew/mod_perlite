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

/* helper funcs */

#define MP_FILTER_NAME_FORMAT "   %s\n\n\t"

#define MP_FILTER_NAME(f)                                   \
    (is_modperl_filter(f)                                   \
         ? modperl_handler_name(                            \
             ((modperl_filter_ctx_t *)(f)->ctx)->handler)   \
         : (f)->frec->name)

#define MP_FILTER_TYPE(filter)                                         \
    (is_modperl_filter(filter->f)                                      \
        ? ((modperl_filter_ctx_t *)(filter)->f->ctx)->handler->attrs & \
            MP_FILTER_CONNECTION_HANDLER  ? "connection" : "request"   \
        : "unknown")

#define MP_FILTER_MODE(filter)                                  \
    (filter->mode == MP_INPUT_FILTER_MODE ? "input" : "output")

#define MP_FILTER_POOL(f) f->r ? f->r->pool : f->c->pool

/* allocate wbucket memory using a sub-pool and not a ap_filter_t
 * pool, since we may need many of these if the filter is invoked
 * multiple times */
#define WBUCKET_INIT(filter)                                     \
    if (!filter->wbucket) {                                      \
        modperl_wbucket_t *wb =                                  \
            (modperl_wbucket_t *)apr_pcalloc(filter->temp_pool,  \
                                             sizeof(*wb));       \
        wb->pool         = filter->pool;                         \
        wb->filters      = &(filter->f->next);                   \
        wb->outcnt       = 0;                                    \
        wb->r            = NULL;                                 \
        wb->header_parse = 0;                                    \
        filter->wbucket  = wb;                                   \
    }

#define FILTER_FREE(filter)                     \
    apr_pool_destroy(filter->temp_pool);

/* Save the value of $@ if it was set */
#define MP_FILTER_SAVE_ERRSV(tmpsv)                 \
    if (SvTRUE(ERRSV)) {                            \
        tmpsv = newSVsv(ERRSV);                     \
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT   \
                  "Saving $@='%s'",                 \
                   MP_FILTER_NAME(filter->f),       \
                   SvPVX(tmpsv)                     \
                   );                               \
    }

/* Restore previously saved value of $@. if there was a filter error
 * it'd have been logged by modperl_errsv call following
 * modperl_callback */
#define MP_FILTER_RESTORE_ERRSV(tmpsv)                  \
    if (tmpsv) {                                        \
        sv_setsv(ERRSV, tmpsv);                         \
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT       \
                   "Restoring $@='%s'",                 \
                   MP_FILTER_NAME(filter->f),           \
                   SvPVX(tmpsv)                         \
                   );                                   \
    }

/* this function is for tracing only, it's not optimized for performance */
static int is_modperl_filter(ap_filter_t *f)
{
    const char *name = f->frec->name;

    /* frec->name is always lowercased */ 
    if (!strcasecmp(name, MP_FILTER_CONNECTION_INPUT_NAME)  ||
        !strcasecmp(name, MP_FILTER_CONNECTION_OUTPUT_NAME) ||
        !strcasecmp(name, MP_FILTER_REQUEST_INPUT_NAME)     ||
        !strcasecmp(name, MP_FILTER_REQUEST_OUTPUT_NAME) ) {
        return 1;
    }
    else {
        return 0;
    }
}


MP_INLINE static apr_status_t send_input_eos(modperl_filter_t *filter)
{
    apr_bucket_alloc_t *ba = filter->f->c->bucket_alloc;
    apr_bucket *b = apr_bucket_eos_create(ba);
    APR_BRIGADE_INSERT_TAIL(filter->bb_out, b);
    ((modperl_filter_ctx_t *)filter->f->ctx)->sent_eos = 1;
    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "write out: EOS bucket\n", MP_FILTER_NAME(filter->f));
    return APR_SUCCESS;
}

MP_INLINE static apr_status_t send_input_flush(modperl_filter_t *filter)
{
    apr_bucket_alloc_t *ba = filter->f->c->bucket_alloc;
    apr_bucket *b = apr_bucket_flush_create(ba);
    APR_BRIGADE_INSERT_TAIL(filter->bb_out, b);
    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "write out: FLUSH bucket\n", MP_FILTER_NAME(filter->f));
    return APR_SUCCESS;
}

MP_INLINE static apr_status_t send_output_eos(ap_filter_t *f)
{
    apr_bucket_alloc_t *ba = f->c->bucket_alloc;
    apr_bucket_brigade *bb = apr_brigade_create(MP_FILTER_POOL(f),
                                                ba);
    apr_bucket *b = apr_bucket_eos_create(ba);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ((modperl_filter_ctx_t *)f->ctx)->sent_eos = 1;
    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "write out: EOS bucket in separate bb\n", MP_FILTER_NAME(f));
    return ap_pass_brigade(f->next, bb);
}

MP_INLINE static apr_status_t send_output_flush(ap_filter_t *f)
{
    apr_bucket_alloc_t *ba = f->c->bucket_alloc;
    apr_bucket_brigade *bb = apr_brigade_create(MP_FILTER_POOL(f),
                                                ba);
    apr_bucket *b = apr_bucket_flush_create(ba);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "write out: FLUSH bucket in separate bb\n", MP_FILTER_NAME(f));
    return ap_pass_brigade(f, bb);
}

/* simple buffer api */

MP_INLINE apr_status_t modperl_wbucket_pass(modperl_wbucket_t *wb,
                                            const char *buf, apr_size_t len,
                                            int add_flush_bucket)
{
    apr_bucket_alloc_t *ba = (*wb->filters)->c->bucket_alloc;
    apr_bucket_brigade *bb;
    apr_bucket *bucket;

    /* reset the counter to 0 as early as possible and in one place,
     * since this function will always either pass the data out (and
     * it has 'len' already) or return an error.
     */
    wb->outcnt = 0;

    if (wb->header_parse) {
        request_rec *r = wb->r;
        const char *body;
        int status;

        MP_TRACE_f(MP_FUNC, "\n\n\tparsing headers: %db [%s]\n", len,
                   MP_TRACE_STR_TRUNC(wb->pool, buf, len));

        status = modperl_cgi_header_parse(r, (char *)buf, &len, &body);

        wb->header_parse = 0; /* only once per-request */

        if (status == HTTP_MOVED_TEMPORARILY) {
            return APR_SUCCESS; /* XXX: HTTP_MOVED_TEMPORARILY ? */
        }
        else if (status != OK) {
            ap_log_error(APLOG_MARK, APLOG_WARNING,
                         0, r->server, "%s did not send an HTTP header",
                         r->uri);
            r->status = status;
            /* XXX: body == NULL here */
            return APR_SUCCESS;
        }
        else if (!len) {
            return APR_SUCCESS;
        }

        buf = body;
    }

    /* this is a note for filter writers who may decide that there is
     * a bug in mod_perl. We send a transient bucket. That means that
     * this bucket can't be stored inside a filter without copying the
     * data in it. This is done automatically by apr_bucket_setaside,
     * which is written exactly for the purpose to make setaside
     * operation transparent to the kind of bucket.
     */
    bucket = apr_bucket_transient_create(buf, len, ba);
    bb = apr_brigade_create(wb->pool, ba);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    if (add_flush_bucket) {
        /* append the flush bucket rather then calling ap_rflush, to
         * prevent a creation of yet another bb, which will cause an
         * extra call for each filter in the chain */
        apr_bucket *bucket = apr_bucket_flush_create(ba);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    MP_TRACE_f(MP_FUNC, "\n\n\twrite out: %db [%s]\n"
               "\t\tfrom %s\n\t\tto %s filter handler\n",
               len, 
               MP_TRACE_STR_TRUNC(wb->pool, buf, len),
               ((wb->r && wb->filters == &wb->r->output_filters)
                   ? "response handler" : "current filter handler"),
               MP_FILTER_NAME(*(wb->filters)));

    return ap_pass_brigade(*(wb->filters), bb);
}

/* flush data if any,
 * if add_flush_bucket is TRUE
 *     if there is data to flush
 *         a flush bucket is added to the tail of bb with data
 *     else
 *         a flush bucket is sent in its own bb
 * else
 *     nothing is sent
 */
MP_INLINE apr_status_t modperl_wbucket_flush(modperl_wbucket_t *wb,
                                             int add_flush_bucket)
{
    apr_status_t rv = APR_SUCCESS;

    if (wb->outcnt) {
        rv = modperl_wbucket_pass(wb, wb->outbuf, wb->outcnt,
                                  add_flush_bucket);
    }
    else if (add_flush_bucket) {
        rv = send_output_flush(*(wb->filters));
    }

    return rv;
}

MP_INLINE apr_status_t modperl_wbucket_write(pTHX_ modperl_wbucket_t *wb,
                                             const char *buf,
                                             apr_size_t *wlen)
{
    apr_size_t len = *wlen;
    *wlen = 0;

    if ((len + wb->outcnt) > sizeof(wb->outbuf)) {
        apr_status_t rv;
        if ((rv = modperl_wbucket_flush(wb, FALSE)) != APR_SUCCESS) {
            return rv;
        }
    }

    if (len >= sizeof(wb->outbuf)) {
        *wlen = len;
        return modperl_wbucket_pass(wb, buf, len, FALSE);
    }
    else {
        memcpy(&wb->outbuf[wb->outcnt], buf, len);
        wb->outcnt += len;
        *wlen = len;
        return APR_SUCCESS;
    }
}

/* generic filter routines */

/* all ap_filter_t filter cleanups should go here */
static apr_status_t modperl_filter_f_cleanup(void *data)
{
    ap_filter_t *f            = (ap_filter_t *)data;
    modperl_filter_ctx_t *ctx = (modperl_filter_ctx_t *)(f->ctx);

    /* mod_perl filter ctx cleanup */
    if (ctx->data){
#ifdef USE_ITHREADS
        dTHXa(ctx->perl);
#endif
        if (SvOK(ctx->data) && SvREFCNT(ctx->data)) {
            SvREFCNT_dec(ctx->data);
            ctx->data = NULL;
        }
        ctx->perl = NULL;
    }

    return APR_SUCCESS;
}

modperl_filter_t *modperl_filter_new(ap_filter_t *f,
                                     apr_bucket_brigade *bb,
                                     modperl_filter_mode_e mode,
                                     ap_input_mode_t input_mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    apr_pool_t *p = MP_FILTER_POOL(f);
    apr_pool_t *temp_pool;
    modperl_filter_t *filter;

    /* we can't allocate memory from the pool here, since potentially
     * a filter can be called hundreds of times during the same
     * request/connection resulting in enormous memory demands
     * (sizeof(*filter)*number of invocations). so we use a sub-pool
     * which will get destroyed at the end of each modperl_filter
     * invocation.
     */
    apr_status_t rv = apr_pool_create(&temp_pool, p);
    if (rv != APR_SUCCESS) {
        /* XXX: how do we handle the error? assert? */
        return NULL;
    }
    filter = (modperl_filter_t *)apr_pcalloc(temp_pool, sizeof(*filter));

#ifdef MP_DEBUG
    apr_pool_tag(temp_pool, "mod_perl temp filter");
#endif

    filter->temp_pool = temp_pool;
    filter->mode      = mode;
    filter->f         = f;
    filter->pool      = p;
    filter->wbucket   = NULL;

    if (mode == MP_INPUT_FILTER_MODE) {
        filter->bb_in      = NULL;
        filter->bb_out     = bb;
        filter->input_mode = input_mode;
        filter->block      = block;
        filter->readbytes  = readbytes;
    }
    else {
        filter->bb_in  = bb;
        filter->bb_out = NULL;
    }

    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "new: %s %s filter (modperl_filter_t *0x%lx), "
               "f (ap_filter_t *0x%lx)\n",
               MP_FILTER_NAME(f),
               MP_FILTER_TYPE(filter),
               MP_FILTER_MODE(filter),
               (unsigned long)filter,
               (unsigned long)filter->f);

    return filter;
}

static void modperl_filter_mg_set(pTHX_ SV *obj, modperl_filter_t *filter)
{
    sv_magic(SvRV(obj), Nullsv, PERL_MAGIC_ext, NULL, -1);
    SvMAGIC(SvRV(obj))->mg_ptr = (char *)filter;
}

modperl_filter_t *modperl_filter_mg_get(pTHX_ SV *obj)
{
    MAGIC *mg = mg_find(SvRV(obj), PERL_MAGIC_ext);
    return mg ? (modperl_filter_t *)mg->mg_ptr : NULL;
}

/* eval "package Foo; \&init_handler" */
///int modperl_filter_resolve_init_handler(pTHX_ modperl_handler_t *handler,
///                                        apr_pool_t *p)
///{
///    char *init_handler_pv_code = NULL;
///
///    if (handler->mgv_cv) {
///        GV *gv = modperl_mgv_lookup(aTHX_ handler->mgv_cv);
///        if (gv) {
///            CV *cv = modperl_mgv_cv(gv);
///            if (cv && SvMAGICAL(cv)) {
///                MAGIC *mg = mg_find((SV*)(cv), PERL_MAGIC_ext);
///                init_handler_pv_code = mg ? mg->mg_ptr : NULL;
///            }
///            else {
///                /* XXX: should we complain in such a case? */
///                return 0;
///            }
///        }
///    }
///
///    if (init_handler_pv_code) {
///        char *package_name =
///            modperl_mgv_as_string(aTHX_ handler->mgv_cv, p, 1);
///        /* fprintf(stderr, "PACKAGE: %s\n", package_name ); */
///
///        /* eval the code in the parent handler's package's context */
///        char *code = apr_pstrcat(p, "package ", package_name, ";",
///                                 init_handler_pv_code, NULL);
///        SV *sv;
///        modperl_handler_t *init_handler;
///
///        ENTER;SAVETMPS;
///        sv = eval_pv(code, TRUE);
///        /* fprintf(stderr, "code: %s\n", code); */
///        init_handler = modperl_handler_new_from_sv(aTHX_ p, sv);
///        FREETMPS;LEAVE;
///
///        if (init_handler) {
///            MP_TRACE_h(MP_FUNC, "found init handler %s\n",
///                       modperl_handler_name(init_handler));
///
///            if (!init_handler->attrs & MP_FILTER_INIT_HANDLER) {
///                Perl_croak(aTHX_ "handler %s doesn't have "
///                           "the FilterInitHandler attribute set",
///                           modperl_handler_name(init_handler));
///            }
///
///            handler->next = init_handler;
///            return 1;
///        }
///        else {
///            Perl_croak(aTHX_ "failed to eval code: %s", code);
///
///        }
///    }
///
///    return 1;
///}
///
///static int modperl_run_filter_init(ap_filter_t *f,
///                                   modperl_filter_mode_e mode,
///                                   modperl_handler_t *handler) 
///{
///    AV *args = Nullav;
///    int status;
///
///    request_rec *r = f->r;
///    conn_rec    *c = f->c;
///    server_rec  *s = r ? r->server : c->base_server;
///    apr_pool_t  *p = r ? r->pool : c->pool;
///    modperl_filter_t *filter = modperl_filter_new(f, NULL, mode, 0, 0, 0);
///
///    MP_dINTERP_SELECT(r, c, s);    
///
///    MP_TRACE_h(MP_FUNC, "running filter init handler %s\n",
///               modperl_handler_name(handler));
///
///    modperl_handler_make_args(aTHX_ &args,
///                              "Apache2::Filter", f,
///                              NULL);
///
///    modperl_filter_mg_set(aTHX_ AvARRAY(args)[0], filter);
///
///    /* XXX filter_init return status is propagated back to Apache over
///     * in C land, making it possible to use filter_init to return, say,
///     * BAD_REQUEST.  this implementation, however, ignores the return status
///     * even though we're trapping it here - modperl_filter_add_request sees
///     * the error and propagates it, but modperl_output_filter_add_request
///     * is void so the error is lost  */
///    if ((status = modperl_callback(aTHX_ handler, p, r, s, args)) != OK) {
///        status = modperl_errsv(aTHX_ status, r, s);
///    }
///
///    FILTER_FREE(filter);
///    SvREFCNT_dec((SV*)args);
///
///    MP_INTERP_PUTBACK(interp);
///
///    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
///               "return: %d\n", modperl_handler_name(handler), status);
///
///    return status;  
///}
///

#define MP_RUN_CROAK_RESET_OK(func)                                     \
    {                                                                   \
        apr_status_t rc = func(filter);                                 \
        if (rc != APR_SUCCESS) {                                        \
            if (APR_STATUS_IS_ECONNRESET(rc) ||                         \
                APR_STATUS_IS_ECONNABORTED(rc)) {                       \
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,              \
                             "Apache2::Filter internal flush got: %s",  \
                             modperl_error_strerror(aTHX_ rc));         \
            }                                                           \
            else {                                                      \
                modperl_croak(aTHX_ rc,                                 \
                              "Apache2::Filter internal flush");        \
            }                                                           \
        }                                                               \
    }

///int modperl_run_filter(modperl_filter_t *filter)
///{
///    AV *args = Nullav;
///    SV *errsv = Nullsv;
///    int status;
///    modperl_handler_t *handler =
///        ((modperl_filter_ctx_t *)filter->f->ctx)->handler;
///
///    request_rec *r = filter->f->r;
///    conn_rec    *c = filter->f->c;
///    server_rec  *s = r ? r->server : c->base_server;
///    apr_pool_t  *p = r ? r->pool : c->pool;
///
///    MP_dINTERP_SELECT(r, c, s);
///
///    MP_FILTER_SAVE_ERRSV(errsv);
///
///    modperl_handler_make_args(aTHX_ &args,
///                              "Apache2::Filter", filter->f,
///                              "APR::Brigade",
///                              (filter->mode == MP_INPUT_FILTER_MODE
///                               ? filter->bb_out
///                               : filter->bb_in),
///                              NULL);
///
///    modperl_filter_mg_set(aTHX_ AvARRAY(args)[0], filter);
///
///    if (filter->mode == MP_INPUT_FILTER_MODE) {
///        av_push(args, newSViv(filter->input_mode));
///        av_push(args, newSViv(filter->block));
///        av_push(args, newSViv(filter->readbytes));
///    }
///
///    /* while filters are VOID handlers, we need to log any errors,
///     * because most perl coders will forget to check the return errors
///     * from read() and print() calls. and if the caller is not a perl
///     * program they won't make any sense of ERRSV or $!
///     */
///    if ((status = modperl_callback(aTHX_ handler, p, r, s, args)) != OK) {
///        status = modperl_errsv(aTHX_ status, r, s);
///    }
///
///    SvREFCNT_dec((SV*)args);
///
///    /* when the streaming filter is invoked it should be able to send
///     * extra data, after the read in a while() loop is finished.
///     * Therefore we need to postpone propogating the EOS bucket, up
///     * until the filter handler is returned and only then send the EOS
///     * bucket if the stream had one.
///     */
///    if (filter->seen_eos) {
///        filter->eos = 1;
///        filter->seen_eos = 0;
///    }
///
///    if (filter->mode == MP_INPUT_FILTER_MODE) {
///        if (filter->bb_in) {
///            if (status == DECLINED) {
///                /* make sure the filter doesn't try to make mod_perl
///                 * pass the bucket brigade through after it called
///                 * $f->read(), since it causes a pre-fetch of the
///                 * bb */
///                modperl_croak(aTHX_ MODPERL_FILTER_ERROR,
///                              "a filter calling $f->read "
///                              "must return OK and not DECLINED");
///            }
///            /* in the streaming mode filter->bb_in is populated on the
///             * first modperl_input_filter_read, so it must be
///             * destroyed at the end of the filter invocation
///             */
///            apr_brigade_destroy(filter->bb_in);
///            filter->bb_in = NULL;
///        }
///        MP_RUN_CROAK_RESET_OK(modperl_input_filter_flush);
///    }
///    else {
///        MP_RUN_CROAK_RESET_OK(modperl_output_filter_flush);
///    }
///
///    MP_FILTER_RESTORE_ERRSV(errsv);
///
///    MP_INTERP_PUTBACK(interp);
///
///    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
///               "return: %d\n", modperl_handler_name(handler), status);
///
///    return status;
///}
///
/* unrolled APR_BRIGADE_FOREACH loop */

#define MP_FILTER_EMPTY(filter)                 \
    APR_BRIGADE_EMPTY(filter->bb_in)

#define MP_FILTER_SENTINEL(filter)              \
    APR_BRIGADE_SENTINEL(filter->bb_in)

#define MP_FILTER_FIRST(filter)                 \
    APR_BRIGADE_FIRST(filter->bb_in)

#define MP_FILTER_NEXT(filter)                  \
    APR_BUCKET_NEXT(filter->bucket)

#define MP_FILTER_IS_EOS(filter)                \
    APR_BUCKET_IS_EOS(filter->bucket)

#define MP_FILTER_IS_FLUSH(filter)              \
    APR_BUCKET_IS_FLUSH(filter->bucket)

MP_INLINE static int get_bucket(modperl_filter_t *filter)
{
    if (!filter->bb_in || MP_FILTER_EMPTY(filter)) {
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                   "read in: bucket brigade is empty\n",
                   MP_FILTER_NAME(filter->f));
        return 0;
    }

    if (!filter->bucket) {
        filter->bucket = MP_FILTER_FIRST(filter);
    }
    else if (filter->bucket != MP_FILTER_SENTINEL(filter)) {
        filter->bucket = MP_FILTER_NEXT(filter);
    }

    if (filter->bucket == MP_FILTER_SENTINEL(filter)) {
        filter->bucket = NULL;
        /* can't destroy bb_in since the next read will need a brigade
         * to try to read from */
        apr_brigade_cleanup(filter->bb_in);
        return 0;
    }

    if (MP_FILTER_IS_EOS(filter)) {
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                   "read in: EOS bucket\n",
                   MP_FILTER_NAME(filter->f));

        filter->seen_eos = 1;
        /* there should be only one EOS sent, modperl_filter_read will
         * not come here, since filter->seen_eos is set
         */
        return 0;
    }
    else if (MP_FILTER_IS_FLUSH(filter)) {
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                   "read in: FLUSH bucket\n",
                   MP_FILTER_NAME(filter->f));
        filter->flush = 1;
        return 0;
    }
    else {
        return 1;
    }
}


MP_INLINE static apr_size_t modperl_filter_read(pTHX_
                                                modperl_filter_t *filter,
                                                SV *buffer,
                                                apr_size_t wanted)
{
    int num_buckets = 0;
    apr_size_t len = 0;

    (void)SvUPGRADE(buffer, SVt_PV);
    SvPOK_only(buffer);
    SvCUR(buffer) = 0;

    /* sometimes the EOS bucket arrives in the same brigade with other
     * buckets, so that particular read() will not return 0 and will
     * be called again if called in the while ($filter->read(...))
     * loop. In that case we return 0.
     */
    if (filter->seen_eos) {
        return 0;
    }

    /* modperl_brigade_dump(filter->bb_in, NULL); */

    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "wanted: %db\n",
               MP_FILTER_NAME(filter->f),
               wanted);

    if (filter->remaining) {
        if (filter->remaining >= wanted) {
            MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                       "eating and returning %d [%s]\n\tof "
                       "remaining %db\n",
                       MP_FILTER_NAME(filter->f),
                       wanted,
                       MP_TRACE_STR_TRUNC(filter->pool, filter->leftover, wanted),
                       filter->remaining);
            sv_catpvn(buffer, filter->leftover, wanted);
            filter->leftover += wanted;
            filter->remaining -= wanted;
            return wanted;
        }
        else {
            MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                       "eating remaining %db\n",
                       MP_FILTER_NAME(filter->f),
                       filter->remaining);
            sv_catpvn(buffer, filter->leftover, filter->remaining);
            len = filter->remaining;
            filter->remaining = 0;
            filter->leftover = NULL;
        }
    }

    while (1) {
        const char *buf;
        apr_size_t buf_len;

        if (!get_bucket(filter)) {
            break;
        }

        num_buckets++;

        filter->rc = apr_bucket_read(filter->bucket, &buf, &buf_len, 0);

        if (filter->rc == APR_SUCCESS) {
            MP_TRACE_f(MP_FUNC,
                       MP_FILTER_NAME_FORMAT
                       "read in: %s bucket with %db (0x%lx)\n",
                       MP_FILTER_NAME(filter->f),
                       filter->bucket->type->name,
                       buf_len,
                       (unsigned long)filter->bucket);
        }
        else {
            SvREFCNT_dec(buffer);
            modperl_croak(aTHX_ filter->rc, "Apache2::Filter::read");
        }

        if (buf_len) {
            if ((SvCUR(buffer) + buf_len) >= wanted) {
                int nibble = wanted - SvCUR(buffer);
                sv_catpvn(buffer, buf, nibble);
                filter->leftover = (char *)buf+nibble;
                filter->remaining = buf_len - nibble;
                len += nibble;
                break;
            }
            else {
                len += buf_len;
                sv_catpvn(buffer, buf, buf_len);
            }
        }
    }

    MP_TRACE_f(MP_FUNC,
               MP_FILTER_NAME_FORMAT
               "return: %db from %d bucket%s [%s]\n\t(%db leftover)\n",
               MP_FILTER_NAME(filter->f),
               len, num_buckets, ((num_buckets == 1) ? "" : "s"),
               MP_TRACE_STR_TRUNC(filter->pool, SvPVX(buffer), len),
               filter->remaining);

    return len;
}

MP_INLINE apr_size_t modperl_input_filter_read(pTHX_
                                               modperl_filter_t *filter,
                                               SV *buffer,
                                               apr_size_t wanted)
{
    apr_size_t len = 0;

    if (!filter->bb_in) {
        /* This should be read only once per handler invocation! */
        filter->bb_in = apr_brigade_create(filter->pool,
                                           filter->f->c->bucket_alloc);
        MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
                   "retrieving bb: 0x%lx\n",
                   MP_FILTER_NAME(filter->f),
                   (unsigned long)(filter->bb_in));
        MP_RUN_CROAK(ap_get_brigade(filter->f->next, filter->bb_in,
                                    filter->input_mode, filter->block,
                                    filter->readbytes),
                     "Apache2::Filter::read");
    }

    len = modperl_filter_read(aTHX_ filter, buffer, wanted);

    if (filter->flush && len == 0) {
        /* if len > 0 then $filter->write will flush */
        apr_status_t rc = modperl_input_filter_flush(filter);
        if (rc != APR_SUCCESS) {
            SvREFCNT_dec(buffer);
            modperl_croak(aTHX_ rc, "Apache2::Filter::read");
        }
    }

    return len;
}


MP_INLINE apr_size_t modperl_output_filter_read(pTHX_
                                                modperl_filter_t *filter,
                                                SV *buffer,
                                                apr_size_t wanted)
{
    apr_size_t len = 0;
    len = modperl_filter_read(aTHX_ filter, buffer, wanted);

    if (filter->flush && len == 0) {
        /* if len > 0 then $filter->write will flush */
        apr_status_t rc = modperl_output_filter_flush(filter);
        if (rc != APR_SUCCESS) {
            SvREFCNT_dec(buffer);
            modperl_croak(aTHX_ rc, "Apache2::Filter::read");
        }
    }

    return len;
}


MP_INLINE apr_status_t modperl_input_filter_flush(modperl_filter_t *filter)
{
    if (((modperl_filter_ctx_t *)filter->f->ctx)->sent_eos) {
        /* no data should be sent after EOS has been sent */
        return filter->rc;
    }

    if (filter->flush) {
        filter->rc = send_input_flush(filter);
        filter->flush = 0;
    }

    if (filter->eos) {
        filter->rc = send_input_eos(filter);
        filter->eos = 0;
    }

    return filter->rc;
}

MP_INLINE apr_status_t modperl_output_filter_flush(modperl_filter_t *filter)
{
    int add_flush_bucket = FALSE;

    if (((modperl_filter_ctx_t *)filter->f->ctx)->sent_eos) {
        /* no data should be sent after EOS has been sent */
        return filter->rc;
    }

    if (filter->flush) {
        add_flush_bucket = TRUE;
        filter->flush = 0;
    }

    WBUCKET_INIT(filter);
    filter->rc = modperl_wbucket_flush(filter->wbucket, add_flush_bucket);
    if (filter->rc != APR_SUCCESS) {
        return filter->rc;
    }

    if (filter->eos) {
        filter->rc = send_output_eos(filter->f);
        if (filter->bb_in) {
            apr_brigade_destroy(filter->bb_in);
            filter->bb_in = NULL;
        }
        filter->eos = 0;
    }

    return filter->rc;
}

MP_INLINE apr_status_t modperl_input_filter_write(pTHX_
                                                  modperl_filter_t *filter,
                                                  const char *buf,
                                                  apr_size_t *len)
{
    apr_bucket_alloc_t *ba = filter->f->c->bucket_alloc;
    char *copy = apr_pmemdup(filter->pool, buf, *len);
    apr_bucket *bucket = apr_bucket_transient_create(copy, *len, ba);
    MP_TRACE_f(MP_FUNC, MP_FILTER_NAME_FORMAT
               "write out: %db [%s]:\n",
               MP_FILTER_NAME(filter->f), *len,
               MP_TRACE_STR_TRUNC(filter->pool, copy, *len));
    APR_BRIGADE_INSERT_TAIL(filter->bb_out, bucket);
    /* modperl_brigade_dump(filter->bb_out, NULL); */
    return APR_SUCCESS;
}

MP_INLINE apr_status_t modperl_output_filter_write(pTHX_
                                                   modperl_filter_t *filter,
                                                   const char *buf,
                                                   apr_size_t *len)
{
    WBUCKET_INIT(filter);

    return modperl_wbucket_write(aTHX_ filter->wbucket, buf, len);
}

///apr_status_t modperl_output_filter_handler(ap_filter_t *f,
///                                           apr_bucket_brigade *bb)
///{
///    modperl_filter_t *filter;
///    int status;
///
///    if (((modperl_filter_ctx_t *)f->ctx)->sent_eos) {
///        MP_TRACE_f(MP_FUNC,
///                   MP_FILTER_NAME_FORMAT
///                   "write_out: EOS was already sent, "
///                   "passing through the brigade\n",
///                   MP_FILTER_NAME(f));
///        return ap_pass_brigade(f->next, bb);
///    }
///    else {
///        filter = modperl_filter_new(f, bb, MP_OUTPUT_FILTER_MODE,
///                                    0, 0, 0);
///        status = modperl_run_filter(filter);
///        FILTER_FREE(filter);
///    }
///
///    switch (status) {
///      case OK:
///        return APR_SUCCESS;
///      case DECLINED:
///        return ap_pass_brigade(f->next, bb);
///      default:
///        return status; /*XXX*/
///    }
///}
///
///apr_status_t modperl_input_filter_handler(ap_filter_t *f,
///                                          apr_bucket_brigade *bb,
///                                          ap_input_mode_t input_mode,
///                                          apr_read_type_e block,
///                                          apr_off_t readbytes)
///{
///    modperl_filter_t *filter;
///    int status;
///
///    if (((modperl_filter_ctx_t *)f->ctx)->sent_eos) {
///        MP_TRACE_f(MP_FUNC,
///                   MP_FILTER_NAME_FORMAT
///                   "write out: EOS was already sent, "
///                   "passing through the brigade\n",
///                   MP_FILTER_NAME(f));
///        return ap_get_brigade(f->next, bb, input_mode, block, readbytes);
///    }
///    else {
///        filter = modperl_filter_new(f, bb, MP_INPUT_FILTER_MODE,
///                                    input_mode, block, readbytes);
///        status = modperl_run_filter(filter);
///        FILTER_FREE(filter);
///    }
///
///    switch (status) {
///      case OK:
///        return APR_SUCCESS;
///      case DECLINED:
///        return ap_get_brigade(f->next, bb, input_mode, block, readbytes);
///      case HTTP_INTERNAL_SERVER_ERROR:
///          /* XXX: later may introduce separate error codes for
///           * modperl_run_filter and modperl_run_filter_init */
///        return MODPERL_FILTER_ERROR;
///      default:
///        return status; /*XXX*/
///    }
///}
///
///static int modperl_filter_add_connection(conn_rec *c,
///                                         int idx,
///                                         const char *name,
///                                         modperl_filter_add_t addfunc,
///                                         const char *type)
///{
///    modperl_config_dir_t *dcfg =
///        modperl_config_dir_get_defaults(c->base_server);
///    MpAV *av;
///
///    if ((av = dcfg->handlers_per_dir[idx])) {
///        modperl_handler_t **handlers = (modperl_handler_t **)av->elts;
///        int i;
///
///        for (i=0; i<av->nelts; i++) {
///            modperl_filter_ctx_t *ctx;
///            ap_filter_t *f;
///
///            /* process non-mod_perl filter handlers */
///            if ((handlers[i]->attrs & MP_FILTER_HTTPD_HANDLER)) {
///
///                /* non-mp2 filters below PROTOCOL level can't be added
///                 * at the connection level, so we need to go through
///                 * the pain of figuring out the type of the filter */
///                ap_filter_rec_t *frec;
///                char *normalized_name = apr_pstrdup(c->pool,
///                                                    handlers[i]->name);
///                ap_str_tolower(normalized_name);
///                frec = idx == MP_INPUT_FILTER_HANDLER
///                    ? ap_get_input_filter_handle(normalized_name)
///                    : ap_get_output_filter_handle(normalized_name);
///                if (frec && frec->ftype < AP_FTYPE_PROTOCOL) {
///                    MP_TRACE_f(MP_FUNC, "a non-mod_perl %s handler %s "
///                               "skipped (not a connection filter)",
///                               type, handlers[i]->name);
///                    continue;
///                }
///
///                addfunc(handlers[i]->name, NULL, NULL, c);
///                MP_TRACE_f(MP_FUNC,
///                           "a non-mod_perl %s handler %s configured "
///                           "(connection)\n", type, handlers[i]->name);
///                continue;
///            }
///
///            /* skip non-connection level filters, e.g. request filters
///             * configured outside the resource container */
///            if (!(handlers[i]->attrs & MP_FILTER_CONNECTION_HANDLER)) {
///                MP_TRACE_f(MP_FUNC,
///                           "%s is not a FilterConnection handler, skipping\n",
///                           handlers[i]->name);
///                continue;
///            }
///
///            ctx = (modperl_filter_ctx_t *)apr_pcalloc(c->pool, sizeof(*ctx));
///            ctx->handler = handlers[i];
///
///            f = addfunc(name, (void*)ctx, NULL, c);
///
///            /* ap_filter_t filter cleanup */
///            apr_pool_cleanup_register(c->pool, (void *)f,
///                                      modperl_filter_f_cleanup,
///                                      apr_pool_cleanup_null);
///
///            if (handlers[i]->attrs & MP_FILTER_HAS_INIT_HANDLER &&
///                handlers[i]->next) {
///                int status = modperl_run_filter_init(
///                    f,
///                    (idx == MP_INPUT_FILTER_HANDLER
///                     ? MP_INPUT_FILTER_MODE : MP_OUTPUT_FILTER_MODE),
///                    handlers[i]->next);
///                if (status != OK) {
///                    return status;
///                }
///            }
///
///            MP_TRACE_h(MP_FUNC, "%s handler %s configured (connection)\n",
///                       type, handlers[i]->name);
///        }
///
///        return OK;
///    }
///
///    MP_TRACE_h(MP_FUNC, "no %s handlers configured (connection)\n", type);
///
///    return DECLINED;
///}
///
///static int modperl_filter_add_request(request_rec *r,
///                                      int idx,
///                                      const char *name,
///                                      modperl_filter_add_t addfunc,
///                                      const char *type,
///                                      ap_filter_t *filters)
///{
///    MP_dDCFG;
///    MpAV *av;
///
///    if ((av = dcfg->handlers_per_dir[idx])) {
///        modperl_handler_t **handlers = (modperl_handler_t **)av->elts;
///        int i;
///
///        for (i=0; i<av->nelts; i++) {
///            modperl_filter_ctx_t *ctx;
///            int registered = 0;
///            ap_filter_t *f;
///
///            /* process non-mod_perl filter handlers */
///            if ((handlers[i]->attrs & MP_FILTER_HTTPD_HANDLER)) {
///                addfunc(handlers[i]->name, NULL, r, r->connection);
///                MP_TRACE_f(MP_FUNC,
///                           "a non-mod_perl %s handler %s configured (%s)\n",
///                           type, handlers[i]->name, r->uri);
///                continue;
///            }
///
///            /* skip non-request level filters, e.g. connection filters
///             * configured outside the resource container, merged into
///             * resource's dcfg->handlers_per_dir[] entry.
///             */
///            if ((handlers[i]->attrs & MP_FILTER_CONNECTION_HANDLER)) {
///                MP_TRACE_f(MP_FUNC,
///                           "%s is not a FilterRequest handler, skipping\n",
///                           handlers[i]->name);
///                continue;
///            }
///
///            /* XXX: I fail to see where this feature is used, since
///             * modperl_filter_add_connection doesn't register request
///             * filters. may be it'll be still useful when the same
///             * filter handler is configured to run more than once?
///             * e.g. snooping filter [stas] */
///            f = filters;
///            while (f) {
///                const char *fname = f->frec->name;
///
///                /* XXX: I think this won't work as f->frec->name gets
///                 * lowercased when added to the chain */
///                if (*fname == 'M' && strEQ(fname, name)) {
///                    modperl_handler_t *ctx_handler = 
///                        ((modperl_filter_ctx_t *)f->ctx)->handler;
///
///                    if (modperl_handler_equal(ctx_handler, handlers[i])) {
///                        /* skip if modperl_filter_add_connection
///                         * already registered this handler
///                         * XXX: set a flag in the modperl_handler_t instead
///                         */
///                        registered = 1;
///                        break;
///                    }
///                }
///
///                f = f->next;
///            }
///
///            if (registered) {
///                MP_TRACE_f(MP_FUNC,
///                        "%s %s already registered\n",
///                        handlers[i]->name, type);
///                continue;
///            }
///
///            ctx = (modperl_filter_ctx_t *)apr_pcalloc(r->pool, sizeof(*ctx));
///            ctx->handler = handlers[i];
///
///            f = addfunc(name, (void*)ctx, r, r->connection);
///
///            /* ap_filter_t filter cleanup */
///            apr_pool_cleanup_register(r->pool, (void *)f,
///                                      modperl_filter_f_cleanup,
///                                      apr_pool_cleanup_null);
///
///            if (handlers[i]->attrs & MP_FILTER_HAS_INIT_HANDLER &&
///                handlers[i]->next) {
///                int status = modperl_run_filter_init(
///                    f,
///                    (idx == MP_INPUT_FILTER_HANDLER
///                     ? MP_INPUT_FILTER_MODE : MP_OUTPUT_FILTER_MODE),
///                    handlers[i]->next);
///                if (status != OK) {
///                    return status;
///                }
///            }
///
///            MP_TRACE_h(MP_FUNC, "%s handler %s configured (%s)\n",
///                       type, handlers[i]->name, r->uri);
///        }
///
///        return OK;
///    }
///
///    MP_TRACE_h(MP_FUNC, "no %s handlers configured (%s)\n",
///               type, r->uri);
///
///    return DECLINED;
///}
///
///void modperl_output_filter_add_connection(conn_rec *c)
///{
///    modperl_filter_add_connection(c,
///                                  MP_OUTPUT_FILTER_HANDLER,
///                                  MP_FILTER_CONNECTION_OUTPUT_NAME,
///                                  ap_add_output_filter,
///                                  "OutputFilter");
///}
///
///void modperl_output_filter_add_request(request_rec *r)
///{
///    modperl_filter_add_request(r,
///                               MP_OUTPUT_FILTER_HANDLER,
///                               MP_FILTER_REQUEST_OUTPUT_NAME,
///                               ap_add_output_filter,
///                               "OutputFilter",
///                               r->connection->output_filters);
///}
///
///void modperl_input_filter_add_connection(conn_rec *c)
///{
///    modperl_filter_add_connection(c,
///                                  MP_INPUT_FILTER_HANDLER,
///                                  MP_FILTER_CONNECTION_INPUT_NAME,
///                                  ap_add_input_filter,
///                                  "InputFilter");
///}
///
///void modperl_input_filter_add_request(request_rec *r)
///{
///    modperl_filter_add_request(r,
///                               MP_INPUT_FILTER_HANDLER,
///                               MP_FILTER_REQUEST_INPUT_NAME,
///                               ap_add_input_filter,
///                               "InputFilter",
///                               r->connection->input_filters);
///}
///
///void modperl_filter_runtime_add(pTHX_ request_rec *r, conn_rec *c,
///                                const char *name,
///                                modperl_filter_mode_e mode,
///                                modperl_filter_add_t addfunc,
///                                SV *callback, const char *type)
///{
///    apr_pool_t *pool = r ? r->pool : c->pool;
///    modperl_handler_t *handler =
///        modperl_handler_new_from_sv(aTHX_ pool, callback);
///
///    if (handler) {
///        ap_filter_t *f;
///        modperl_filter_ctx_t *ctx =
///            (modperl_filter_ctx_t *)apr_pcalloc(pool, sizeof(*ctx));
///
///        ctx->handler = handler;
///        f = addfunc(name, (void*)ctx, r, c);
///
///        /* ap_filter_t filter cleanup */
///        apr_pool_cleanup_register(pool, (void *)f,
///                                  modperl_filter_f_cleanup,
///                                  apr_pool_cleanup_null);
///
///        /* has to resolve early so we can check for init functions */ 
///        if (!modperl_mgv_resolve(aTHX_ handler, pool, handler->name, TRUE)) {
///            Perl_croak(aTHX_ "unable to resolve handler %s\n",
///                       modperl_handler_name(handler));
///        }
///
///        /* verify that the filter handler is of the right kind */
///        if (r == NULL) {
///            /* needs to have the FilterConnectionHandler attribute */
///            if (!(handler->attrs & MP_FILTER_CONNECTION_HANDLER)) {
///                Perl_croak(aTHX_ "Can't add connection filter handler '%s' "
///                           "since it doesn't have the "
///                           "FilterConnectionHandler attribute set",
///                           modperl_handler_name(handler));
///            }
///        }
///        else {
///            /* needs to have the FilterRequestHandler attribute, but
///             * since by default request filters are not required to
///             * have the FilterRequestHandler attribute, croak only if
///             * some other attribute is set, but not
///             * FilterRequestHandler */
///            if (handler->attrs &&
///                !(handler->attrs & MP_FILTER_REQUEST_HANDLER)) {
///                Perl_croak(aTHX_ "Can't add request filter handler '%s' "
///                           "since it doesn't have the "
///                           "FilterRequestHandler attribute set",
///                           modperl_handler_name(handler));
///            }
///        }
///
///        if (handler->attrs & MP_FILTER_HAS_INIT_HANDLER && handler->next) {
///            int status = modperl_run_filter_init(f, mode, handler->next);
///            if (status != OK) {
///                modperl_croak(aTHX_ status, strEQ("InputFilter", type)
///                              ? "Apache2::Filter::add_input_filter"
///                              : "Apache2::Filter::add_output_filter");
///            }
///        }
///
///        MP_TRACE_h(MP_FUNC, "%s handler %s configured (connection)\n",
///                   type, name);
///
///        return;
///    }
///
///    Perl_croak(aTHX_ "unable to resolve handler 0x%lx\n",
///               (unsigned long)callback);
///}
///
///void modperl_brigade_dump(apr_bucket_brigade *bb, apr_file_t *file)
///{
///    apr_bucket *bucket;
///    int i = 0;
///#ifndef WIN32
///    if (file == NULL) {
///        file = modperl_global_get_server_rec()->error_log;
///    }
///
///    apr_file_printf(file, "dump of brigade 0x%lx\n", (unsigned long)bb);
///
///    for (bucket = APR_BRIGADE_FIRST(bb);
///         bucket != APR_BRIGADE_SENTINEL(bb);
///         bucket = APR_BUCKET_NEXT(bucket))
///    {
///        apr_file_printf(file,
///                        "   %d: bucket=%s(0x%lx), length=%ld, data=0x%lx\n",
///                        i, bucket->type->name,
///                        (unsigned long)bucket,
///                        (long)bucket->length,
///                        (unsigned long)bucket->data);
///        /* apr_file_printf(file, "       : %s\n", (char *)bucket->data); */
///
///        i++;
///    }
///#endif
///}
