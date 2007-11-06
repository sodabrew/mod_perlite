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

///modperl_handler_t *modperl_handler_new(apr_pool_t *p, const char *name)
///{
///    modperl_handler_t *handler = 
///        (modperl_handler_t *)apr_pcalloc(p, sizeof(*handler));
///
///    switch (*name) {
///      case '+':
///        ++name;
///        MpHandlerAUTOLOAD_On(handler);
///        break;
///      case '-':
///        ++name;
///        /* XXX: currently a noop; should disable autoload of given handler
///         * if PerlOptions +AutoLoad is configured
///         * see: modperl_hash_handlers in modperl_mgv.c
///         */
///        MpHandlerAUTOLOAD_Off(handler);
///        break;
///    }
///
///    handler->cv = NULL;
///    handler->name = name;
///    MP_TRACE_h(MP_FUNC, "[%s] new handler %s\n",
///               modperl_pid_tid(p), handler->name);
///
///    return handler;
///}
///
/* How anon-subs are handled:
 * We have two ways anon-subs can be registered
 * A) at startup from httpd.conf:
 *    PerlTransHandler 'sub { ... }'
 * B) run-time perl code
 *    $r->push_handlers(PerlTransHandler => sub { .... });
 *    $s->push_handlers(PerlTransHandler => sub { .... });
 *
 * In the case of non-threaded perl, we just compile A or grab B and
 * store it in the mod_perl struct and call it when it's used. No
 * problems here
 *
 * In the case of threads, things get more complicated. we no longer
 * can store the CV value of the compiled anon-sub, since when
 * perl_clone is called each interpreter will have a different CV
 * value. since we need to be able to have 1 entry for each anon-sub
 * across all interpreters a different solution is needed. to remind
 * in the case of named subs, we just store the name of the sub and
 * look its corresponding CV when we need it.
 *
 * The used solution: each process has a global counter, which always
 * grows. Every time a new anon-sub is encountered, a new ID is
 * allocated from that process-global counter and that ID is stored in
 * the mod_perl struct. The compiled CV is stored as
 *     $PL_modglobal{ANONSUB}{$id} = CV;
 * when perl_clone is called, each clone will clone that CV value, but
 * we will still be able to find it, since we stored it in the
 * hash. so we retrieve the CV value, whatever it is and we run it.
 * 
 * that explanation can be written and run in perl:
 *
 * use threads;
 * our %h;
 * $h{x} = eval 'sub { print qq[this is sub @_\n] }';
 * $h{x}->("main");
 * threads->new(sub { $h{x}->(threads->self->tid)});
 *
 * XXX: more nuances will follow
 */

///void modperl_handler_anon_init(pTHX_ apr_pool_t *p)
///{
///    modperl_modglobal_key_t *gkey =
///        modperl_modglobal_lookup(aTHX_ "ANONSUB");
///    MP_TRACE_h(MP_FUNC, "init $PL_modglobal{ANONSUB} = []");
///    (void)MP_MODGLOBAL_STORE_HV(gkey);
///}
///
/* allocate and populate the anon handler sub-struct */
///MP_INLINE modperl_mgv_t *modperl_handler_anon_next(pTHX_ apr_pool_t *p)
///{
///    /* re-use modperl_mgv_t entry which is otherwise is not used
///     * by anon handlers */
///    modperl_mgv_t *anon = 
///        (modperl_mgv_t *)apr_pcalloc(p, sizeof(*anon));
///
///    anon->name = apr_psprintf(p, "anon%d", modperl_global_anon_cnt_next());
///    anon->len  = strlen(anon->name);
///    PERL_HASH(anon->hash, anon->name, anon->len);
///
///    MP_TRACE_h(MP_FUNC, "[%s] new anon handler: '%s'",
///               modperl_pid_tid(p), anon->name);
///    return anon;
///}
///
///MP_INLINE void modperl_handler_anon_add(pTHX_ modperl_mgv_t *anon, CV *cv)
///{
///    modperl_modglobal_key_t *gkey =
///        modperl_modglobal_lookup(aTHX_ "ANONSUB");
///    HE *he = MP_MODGLOBAL_FETCH(gkey);
///    HV *hv;
///
///    if (!(he && (hv = (HV*)HeVAL(he)))) {
///        Perl_croak(aTHX_ "modperl_handler_anon_add: "
///                   "can't find ANONSUB top entry (get)");
///    }
///
///    SvREFCNT_inc(cv);
///    if (!(*hv_store(hv, anon->name, anon->len, (SV*)cv, anon->hash))) {
///        SvREFCNT_dec(cv);
///        Perl_croak(aTHX_ "hv_store of anonsub '%s' has failed!", anon->name);
///    }
///
///    MP_TRACE_h(MP_FUNC, "anonsub '%s' added", anon->name);
///}
///
///MP_INLINE CV *modperl_handler_anon_get(pTHX_ modperl_mgv_t *anon)
///{
///    modperl_modglobal_key_t *gkey =
///        modperl_modglobal_lookup(aTHX_ "ANONSUB");
///    HE *he = MP_MODGLOBAL_FETCH(gkey);
///    HV *hv;
///    SV *sv;
///
///    if (!(he && (hv = (HV*)HeVAL(he)))) {
///        Perl_croak(aTHX_ "modperl_handler_anon_get: "
///                   "can't find ANONSUB top entry (get)");
///    }
///
///    if ((he = hv_fetch_he(hv, anon->name, anon->len, anon->hash))) {
///        sv = HeVAL(he);
///        MP_TRACE_h(MP_FUNC, "anonsub gets name '%s'", anon->name);
///    }
///    else {
///        Perl_croak(aTHX_ "can't find ANONSUB's '%s' entry", anon->name);
///    }
///
///    return (CV*)sv;
///}
///
///static
///modperl_handler_t *modperl_handler_new_anon(pTHX_ apr_pool_t *p, CV *cv)
///{
///    modperl_handler_t *handler = 
///        (modperl_handler_t *)apr_pcalloc(p, sizeof(*handler));
///    MpHandlerPARSED_On(handler);
///    MpHandlerANON_On(handler);
///
///#ifdef USE_ITHREADS
///    handler->cv      = NULL;
///    handler->name    = NULL;
///    handler->mgv_obj = modperl_handler_anon_next(aTHX_ p);
///    modperl_handler_anon_add(aTHX_ handler->mgv_obj, cv);
///#else
///    /* it's safe to cache and later use the cv, since the same perl
///     * interpeter is always used */
///    SvREFCNT_inc((SV*)cv);
///    handler->cv   = cv;
///    handler->name = NULL;
///
///    MP_TRACE_h(MP_FUNC, "[%s] new cached cv anon handler\n",
///               modperl_pid_tid(p));
///#endif
///
///    return handler;
///}
///
MP_INLINE
const char *modperl_handler_name(modperl_handler_t *handler)
{
    /* a handler containing an anonymous sub doesn't have a normal sub
     * name */
    if (handler->name) {
        return handler->name;
    }
    else {
        /* anon sub stores the internal modperl name in mgv_obj */
        return handler->mgv_obj ? handler->mgv_obj->name : "anonsub";
    }
}


///int modperl_handler_resolve(pTHX_ modperl_handler_t **handp,
///                            apr_pool_t *p, server_rec *s)
///{
///    int duped=0;
///    modperl_handler_t *handler = *handp;
///
///#ifdef USE_ITHREADS
///    if (modperl_threaded_mpm() && p &&
///        !MpHandlerPARSED(handler) && !MpHandlerDYNAMIC(handler)) {
///        /*
///         * under threaded mpm we cannot update the handler structure
///         * at request time without locking, so just copy it
///         */
///        handler = *handp = modperl_handler_dup(p, handler);
///        duped = 1;
///    }
///#endif
///
///    MP_TRACE_h_do(MpHandler_dump_flags(handler,
///                                       modperl_handler_name(handler)));
///
///    if (!MpHandlerPARSED(handler)) {
///        apr_pool_t *rp = duped ? p : s->process->pconf;
///        MpHandlerAUTOLOAD_On(handler);
///
///        MP_TRACE_h(MP_FUNC,
///                   "[%s %s] handler %s hasn't yet been resolved, "
///                   "attempting to resolve using %s pool 0x%lx\n",
///                   modperl_pid_tid(p),
///                   modperl_server_desc(s, p),
///                   modperl_handler_name(handler),
///                   duped ? "current" : "server conf",
///                   (unsigned long)rp);
///
///        if (!modperl_mgv_resolve(aTHX_ handler, rp, handler->name, FALSE)) {
///            modperl_errsv_prepend(aTHX_
///                                  "failed to resolve handler `%s': ",
///                                  handler->name);
///            return HTTP_INTERNAL_SERVER_ERROR;
///        }
///    }
///
///    return OK;
///}
///
///modperl_handler_t *modperl_handler_dup(apr_pool_t *p,
///                                       modperl_handler_t *h)
///{
///    MP_TRACE_h(MP_FUNC, "dup handler %s\n", modperl_handler_name(h));
///    return modperl_handler_new(p, h->name);
///}
///
///int modperl_handler_equal(modperl_handler_t *h1, modperl_handler_t *h2)
///{
///    if (h1->mgv_cv && h2->mgv_cv) {
///        return modperl_mgv_equal(h1->mgv_cv, h2->mgv_cv);
///    }
///    return strEQ(h1->name, h2->name);
///}
///
///MpAV *modperl_handler_array_merge(apr_pool_t *p, MpAV *base_a, MpAV *add_a)
///{
///    int i, j;
///    modperl_handler_t **base_h, **add_h, **mrg_h;
///    MpAV *mrg_a;
///
///    if (!add_a) {
///        return base_a;
///    }
///
///    if (!base_a) {
///        return add_a;
///    }
///
///    mrg_a = apr_array_copy(p, base_a);
///
///    mrg_h  = (modperl_handler_t **)mrg_a->elts;
///    base_h = (modperl_handler_t **)base_a->elts;
///    add_h  = (modperl_handler_t **)add_a->elts;
///
///    for (i=0; i<base_a->nelts; i++) {
///        for (j=0; j<add_a->nelts; j++) {
///            if (modperl_handler_equal(base_h[i], add_h[j])) {
///                MP_TRACE_d(MP_FUNC, "both base and new config contain %s\n",
///                           add_h[j]->name);
///            }
///            else {
///                modperl_handler_array_push(mrg_a, add_h[j]);
///                MP_TRACE_d(MP_FUNC, "base does not contain %s\n",
///                           add_h[j]->name);
///            }
///        }
///    }
///
///    return mrg_a;
///}
///
///void modperl_handler_make_args(pTHX_ AV **avp, ...)
///{
///    va_list args;
///
///    if (!*avp) {
///        *avp = newAV(); /* XXX: cache an intialized AV* per-request */
///    }
///
///    va_start(args, avp);
///
///    for (;;) {
///        char *classname = va_arg(args, char *);
///        void *ptr;
///        SV *sv;
///
///        if (classname == NULL) {
///            break;
///        }
///
///        ptr = va_arg(args, void *);
///
///        switch (*classname) {
///          case 'A':
///            if (strEQ(classname, "APR::Table")) {
///                sv = modperl_hash_tie(aTHX_ classname, Nullsv, ptr);
///                break;
///            }
///          case 'I':
///            if (strEQ(classname, "IV")) {
///                sv = ptr ? newSViv(PTR2IV(ptr)) : &PL_sv_undef;
///                break;
///            }
///          case 'P':
///            if (strEQ(classname, "PV")) {
///                sv = ptr ? newSVpv((char *)ptr, 0) : &PL_sv_undef;
///                break;
///            }
///          case 'H':
///            if (strEQ(classname, "HV")) {
///                sv = newRV_noinc((SV*)ptr);
///                break;
///            }
///          default:
///            sv = modperl_ptr2obj(aTHX_ classname, ptr);
///            break;
///        }
///
///        av_push(*avp, sv);
///    }
///
///    va_end(args);
///}
///
#define set_desc(dtype)                                 \
    if (desc) *desc = modperl_handler_desc_##dtype(idx)

#define check_modify(dtype)                                     \
    if ((action > MP_HANDLER_ACTION_GET) && rcfg) {             \
        MP_dSCFG_dTHX;                                          \
        Perl_croak(aTHX_ "too late to modify %s handlers",      \
                   modperl_handler_desc_##dtype(idx));          \
    }

/*
 * generic function to lookup handlers for use in modperl_callback(),
 * $r->{push,set,get}_handlers, $s->{push,set,get}_handlers
 * $s->push/set at startup time are the same as configuring Perl*Handlers
 * $r->push/set at request time will create entries in r->request_config
 * push will first merge with configured handlers, unless an entry
 * in r->request_config already exists.  in this case, push or set has
 * already been called for the given handler, 
 * r->request_config entries then override those in r->per_dir_config
 */

///MpAV **modperl_handler_lookup_handlers(modperl_config_dir_t *dcfg,
///                                       modperl_config_srv_t *scfg,
///                                       modperl_config_req_t *rcfg,
///                                       apr_pool_t *p,
///                                       int type, int idx,
///                                       modperl_handler_action_e action,
///                                       const char **desc)
///{
///    MpAV **avp = NULL, **ravp = NULL;
///
///    switch (type) {
///      case MP_HANDLER_TYPE_PER_DIR:
///        avp = &dcfg->handlers_per_dir[idx];
///        if (rcfg) {
///            ravp = &rcfg->handlers_per_dir[idx];
///        }
///        set_desc(per_dir);
///        break;
///      case MP_HANDLER_TYPE_PER_SRV:
///        avp = &scfg->handlers_per_srv[idx];
///        if (rcfg) {
///            ravp = &rcfg->handlers_per_srv[idx];
///        }
///        set_desc(per_srv);
///        break;
///      case MP_HANDLER_TYPE_PRE_CONNECTION:
///        avp = &scfg->handlers_pre_connection[idx];
///        check_modify(pre_connection);
///        set_desc(pre_connection);
///        break;
///      case MP_HANDLER_TYPE_CONNECTION:
///        avp = &scfg->handlers_connection[idx];
///        check_modify(connection);
///        set_desc(connection);
///        break;
///      case MP_HANDLER_TYPE_FILES:
///        avp = &scfg->handlers_files[idx];
///        check_modify(files);
///        set_desc(files);
///        break;
///      case MP_HANDLER_TYPE_PROCESS:
///        avp = &scfg->handlers_process[idx];
///        check_modify(files);
///        set_desc(process);
///        break;
///    };
///
///    if (!avp) {
///        /* should never happen */
///#if 0
///        fprintf(stderr, "PANIC: no such handler type: %d\n", type);
///#endif
///        return NULL;
///    }
///
///    switch (action) {
///      case MP_HANDLER_ACTION_GET:
///        /* just a lookup */
///        break;
///      case MP_HANDLER_ACTION_PUSH:
///        if (ravp && !*ravp) {
///            if (*avp) {
///                /* merge with existing configured handlers */
///                *ravp = apr_array_copy(p, *avp);
///            }
///            else {
///                /* no request handlers have been previously pushed or set */
///                *ravp = modperl_handler_array_new(p);
///            }
///        }
///        else if (!*avp) {
///            /* directly modify the configuration at startup time */
///            *avp = modperl_handler_array_new(p);
///        }
///        break;
///      case MP_HANDLER_ACTION_SET:
///        if (ravp) {
///            if (*ravp) {
///                /* wipe out existing pushed/set request handlers */
///                (*ravp)->nelts = 0;
///            }
///            else {
///                /* no request handlers have been previously pushed or set */
///                *ravp = modperl_handler_array_new(p);
///            }
///        }
///        else if (*avp) {
///            /* wipe out existing configuration, only at startup time */
///            (*avp)->nelts = 0;
///        }
///        else {
///            /* no configured handlers for this phase */
///            *avp = modperl_handler_array_new(p);
///        }
///        break;
///    }
///
///    return (ravp && *ravp) ? ravp : avp;
///}
///
///MpAV **modperl_handler_get_handlers(request_rec *r, conn_rec *c, server_rec *s,
///                                    apr_pool_t *p, const char *name,
///                                    modperl_handler_action_e action)
///{
///    MP_dSCFG(s);
///    MP_dDCFG;
///    MP_dRCFG;
///
///    int idx, type;
///
///    if (!r) {
///        /* so $s->{push,set}_handlers can configured request-time handlers */
///        dcfg = modperl_config_dir_get_defaults(s);
///    }
///
///    if ((idx = modperl_handler_lookup(name, &type)) == DECLINED) {
///        return FALSE;
///    }
///
///    return modperl_handler_lookup_handlers(dcfg, scfg, rcfg, p,
///                                           type, idx,
///                                           action, NULL);
///}
///
///modperl_handler_t *modperl_handler_new_from_sv(pTHX_ apr_pool_t *p, SV *sv)
///{
///    char *name = NULL;
///    GV *gv;
///
///    if (SvROK(sv)) {
///        sv = SvRV(sv);
///    }
///
///    switch (SvTYPE(sv)) {
///      case SVt_PV:
///        name = SvPVX(sv);
///        return modperl_handler_new(p, apr_pstrdup(p, name));
///        break;
///      case SVt_PVCV:
///        if (CvANON((CV*)sv)) {
///            return modperl_handler_new_anon(aTHX_ p, (CV*)sv);
///        }
///        if (!(gv = CvGV((CV*)sv))) {
///            Perl_croak(aTHX_ "can't resolve the code reference");
///        }
///        name = apr_pstrcat(p, HvNAME(GvSTASH(gv)), "::", GvNAME(gv), NULL);
///        return modperl_handler_new(p, apr_pstrdup(p, name));
///        break;
///    };
///
///    return NULL;
///}
///
///int modperl_handler_push_handlers(pTHX_ apr_pool_t *p,
///                                  MpAV *handlers, SV *sv)
///{
///    modperl_handler_t *handler = modperl_handler_new_from_sv(aTHX_ p, sv);
///
///    if (handler) {
///        modperl_handler_array_push(handlers, handler);
///        return TRUE;
///    }
///
///    MP_TRACE_h(MP_FUNC, "unable to push_handler 0x%lx\n",
///               (unsigned long)sv);
///
///    return FALSE;
///}
///
/* convert array header of modperl_handlers_t's to AV ref of CV refs */
///SV *modperl_handler_perl_get_handlers(pTHX_ MpAV **handp, apr_pool_t *p)
///{
///    AV *av = newAV();
///    int i;
///    modperl_handler_t **handlers;
///
///    if (!(handp && *handp)) {
///        return &PL_sv_undef;
///    }
///
///    av_extend(av, (*handp)->nelts - 1);
///
///    handlers = (modperl_handler_t **)(*handp)->elts;
///
///    for (i=0; i<(*handp)->nelts; i++) {
///        modperl_handler_t *handler = NULL;
///        GV *gv;
///
///        if (MpHandlerPARSED(handlers[i])) {
///            handler = handlers[i];
///        }
///        else {
///#ifdef USE_ITHREADS
///            if (!MpHandlerDYNAMIC(handlers[i])) {
///                handler = modperl_handler_dup(p, handlers[i]);
///            }
///#endif
///            if (!handler) {
///                handler = handlers[i];
///            }
///
///            if (!modperl_mgv_resolve(aTHX_ handler, p, handler->name, TRUE)) {
///                MP_TRACE_h(MP_FUNC, "failed to resolve handler %s\n",
///                           handler->name);
///            }
///
///        }
///
///        if (handler->mgv_cv) {
///            if ((gv = modperl_mgv_lookup(aTHX_ handler->mgv_cv))) {
///                CV *cv = modperl_mgv_cv(gv);
///                av_push(av, newRV_inc((SV*)cv));
///            }
///        }
///        else {
///            av_push(av, newSVpv(handler->name, 0));
///        }
///    }
///
///    return newRV_noinc((SV*)av);
///}
///
#define push_sv_handler \
    if ((modperl_handler_push_handlers(aTHX_ p, *handlers, sv))) { \
        MpHandlerDYNAMIC_On(modperl_handler_array_last(*handlers)); \
    }

/* allow push/set of single cv ref or array ref of cv refs */
///int modperl_handler_perl_add_handlers(pTHX_
///                                      request_rec *r,
///                                      conn_rec *c,
///                                      server_rec *s,
///                                      apr_pool_t *p,
///                                      const char *name,
///                                      SV *sv,
///                                      modperl_handler_action_e action)
///{
///    I32 i;
///    AV *av = Nullav;
///    MpAV **handlers =
///        modperl_handler_get_handlers(r, c, s,
///                                     p, name, action);
///
///    if (!(handlers && *handlers)) {
///        return FALSE;
///    }
///
///    if (SvROK(sv) && (SvTYPE(SvRV(sv)) == SVt_PVAV)) {
///        av = (AV*)SvRV(sv);
///
///        for (i=0; i <= AvFILL(av); i++) {
///            sv = *av_fetch(av, i, FALSE);
///            push_sv_handler;
///        }
///    }
///    else {
///        push_sv_handler;
///    }
///
///    return TRUE;
///}
