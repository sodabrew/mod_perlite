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

#define TIEHANDLE(handle,r) \
modperl_io_handle_tie(aTHX_ handle, "Apache2::RequestRec", (void *)r)

#define TIED(handle) \
modperl_io_handle_tied(aTHX_ handle, "Apache2::RequestRec")

MP_INLINE void modperl_io_handle_tie(pTHX_ GV *handle,
                                     char *classname, void *ptr)
{
    SV *obj = modperl_ptr2obj(aTHX_ classname, ptr);

    modperl_io_handle_untie(aTHX_ handle);

    sv_magic(TIEHANDLE_SV(handle), obj, PERL_MAGIC_tiedscalar, Nullch, 0);

    SvREFCNT_dec(obj); /* since sv_magic did SvREFCNT_inc */

    MP_TRACE_r(MP_FUNC, "tie *%s(0x%lx) => %s, REFCNT=%d\n",
               GvNAME(handle), (unsigned long)handle, classname,
               SvREFCNT(TIEHANDLE_SV(handle)));
}

MP_INLINE GV *modperl_io_tie_stdin(pTHX_ request_rec *r)
{
#if defined(MP_IO_TIE_SFIO)
    /* XXX */
#else
    dHANDLE("STDIN");

    if (TIED(handle)) {
        return handle;
    }

    TIEHANDLE(handle, r);

    return handle;
#endif
}

MP_INLINE GV *modperl_io_tie_stdout(pTHX_ request_rec *r)
{
#if defined(MP_IO_TIE_SFIO)
    /* XXX */
#else
    dHANDLE("STDOUT");

    if (TIED(handle)) {
        return handle;
    }

    IoFLUSH_off(PL_defoutgv); /* $|=0 */

    TIEHANDLE(handle, r);

    return handle;
#endif
}

MP_INLINE int modperl_io_handle_tied(pTHX_ GV *handle, char *classname)
{
    MAGIC *mg;
    SV *sv = TIEHANDLE_SV(handle);

    if (SvMAGICAL(sv) && (mg = mg_find(sv, PERL_MAGIC_tiedscalar))) {
	char *package = HvNAME(SvSTASH((SV*)SvRV(mg->mg_obj)));

	if (!strEQ(package, classname)) {
	    MP_TRACE_r(MP_FUNC, "%s tied to %s\n", GvNAME(handle), package);
	    return TRUE;
	}
    }

    return FALSE;
}

MP_INLINE void modperl_io_handle_untie(pTHX_ GV *handle)
{
#ifdef MP_TRACE
    if (mg_find(TIEHANDLE_SV(handle), PERL_MAGIC_tiedscalar)) {
        MP_TRACE_r(MP_FUNC, "untie *%s(0x%lx), REFCNT=%d\n",
                   GvNAME(handle), (unsigned long)handle,
                   SvREFCNT(TIEHANDLE_SV(handle)));
    }
#endif

    sv_unmagic(TIEHANDLE_SV(handle), PERL_MAGIC_tiedscalar);
}

MP_INLINE GV *modperl_io_perlio_override_stdin(pTHX_ request_rec *r)
{
    dHANDLE("STDIN");
    int status;
    GV *handle_save = (GV*)Nullsv;
    SV *sv = sv_newmortal();

    MP_TRACE_o(MP_FUNC, "start");

    /* if STDIN is open, dup it, to be restored at the end of response */
    if (handle && SvTYPE(handle) == SVt_PVGV &&
        IoTYPE(GvIO(handle)) != IoTYPE_CLOSED) {
        handle_save = gv_fetchpv(Perl_form(aTHX_
                                           "Apache2::RequestIO::_GEN_%ld",
                                           (long)PL_gensym++),
                                 TRUE, SVt_PVIO);

        /* open my $oldout, "<&STDIN" or die "Can't dup STDIN: $!"; */
        status = do_open(handle_save, "<&STDIN", 7, FALSE,
                         O_RDONLY, 0, Nullfp);
        if (status == 0) {
            Perl_croak(aTHX_ "Failed to dup STDIN: %" SVf, get_sv("!", TRUE));
        }

        /* similar to PerlIO::scalar, the PerlIO::Apache layer doesn't
         * have file descriptors, so STDIN must be closed before it can
         * be reopened */
        do_close(handle, TRUE);
    }

    sv_setref_pv(sv, "Apache2::RequestRec", (void*)r);
    status = do_open9(handle, "<:Apache2", 9, FALSE, O_RDONLY,
                      0, Nullfp, sv, 1);
    if (status == 0) {
        Perl_croak(aTHX_ "Failed to open STDIN: %" SVf, get_sv("!", TRUE));
    }

    MP_TRACE_o(MP_FUNC, "end\n");

    return handle_save;
}

/* XXX: refactor to merge with the previous function */
MP_INLINE GV *modperl_io_perlio_override_stdout(pTHX_ request_rec *r)
{
    dHANDLE("STDOUT");
    int status;
    GV *handle_save = (GV*)Nullsv;
    SV *sv = sv_newmortal();

    MP_TRACE_o(MP_FUNC, "start");

    /* if STDOUT is open, dup it, to be restored at the end of response */
    if (handle && SvTYPE(handle) == SVt_PVGV &&
        IoTYPE(GvIO(handle)) != IoTYPE_CLOSED) {
        handle_save = gv_fetchpv(Perl_form(aTHX_
                                           "Apache2::RequestIO::_GEN_%ld",
                                           (long)PL_gensym++),
                                 TRUE, SVt_PVIO);

        /* open my $oldout, ">&STDOUT" or die "Can't dup STDOUT: $!"; */
        status = do_open(handle_save, ">&STDOUT", 8, FALSE,
                         O_WRONLY, 0, Nullfp);
        if (status == 0) {
            Perl_croak(aTHX_ "Failed to dup STDOUT: %" SVf, get_sv("!", TRUE));
        }

        /* similar to PerlIO::scalar, the PerlIO::Apache layer doesn't
         * have file descriptors, so STDOUT must be closed before it can
         * be reopened */
        do_close(handle, TRUE);
    }

    sv_setref_pv(sv, "Apache2::RequestRec", (void*)r);
    status = do_open9(handle, ">:Apache2", 9, FALSE, O_WRONLY,
                      0, Nullfp, sv, 1);
    if (status == 0) {
        Perl_croak(aTHX_ "Failed to open STDOUT: %" SVf, get_sv("!", TRUE));
    }

    MP_TRACE_o(MP_FUNC, "end\n");

    /* XXX: shouldn't we preserve the value STDOUT had before it was
     * overridden? */
    IoFLUSH_off(handle); /* STDOUT's $|=0 */

    return handle_save;

}

MP_INLINE void modperl_io_perlio_restore_stdin(pTHX_ GV *handle)
{
    GV *handle_orig = gv_fetchpv("STDIN", FALSE, SVt_PVIO);

    MP_TRACE_o(MP_FUNC, "start");

    /* close the overriding filehandle */
    do_close(handle_orig, FALSE);

    /*
     * open STDIN, "<&STDIN_SAVED" or die "Can't dup STDIN_SAVED: $!";
     * close STDIN_SAVED;
     */
    if (handle != (GV*)Nullsv) {
        SV *err = Nullsv;

        MP_TRACE_o(MP_FUNC, "restoring STDIN");

        if (do_open9(handle_orig, "<&", 2, FALSE,
                     O_RDONLY, 0, Nullfp, (SV*)handle, 1) == 0) {
            err = get_sv("!", TRUE);
        }

        do_close(handle, FALSE);
        (void)hv_delete(gv_stashpv("Apache2::RequestIO", TRUE), 
                        GvNAME(handle), GvNAMELEN(handle), G_DISCARD);

        if (err != Nullsv) {
            Perl_croak(aTHX_ "Failed to restore STDIN: %" SVf, err);
        }
    }

    MP_TRACE_o(MP_FUNC, "end\n");
}

MP_INLINE void modperl_io_perlio_restore_stdout(pTHX_ GV *handle)
{ 
    GV *handle_orig = gv_fetchpv("STDOUT", FALSE, SVt_PVIO);

    MP_TRACE_o(MP_FUNC, "start");

    /* since closing unflushed STDOUT may trigger a subrequest
     * (e.g. via mod_include), resulting in potential another response
     * handler call, which may try to close STDOUT too. We will
     * segfault, if that subrequest doesn't return before the the top
     * level STDOUT is attempted to be closed. To prevent this
     * situation always explicitly flush STDOUT, before reopening it.
     */
    if (GvIOn(handle_orig) && IoOFP(GvIOn(handle_orig)) &&
        (PerlIO_flush(IoOFP(GvIOn(handle_orig))) == -1)) {
        Perl_croak(aTHX_ "Failed to flush STDOUT: %" SVf, get_sv("!", TRUE));
    }

    /* close the overriding filehandle */
    do_close(handle_orig, FALSE);

    /*
     * open STDOUT, ">&STDOUT_SAVED" or die "Can't dup STDOUT_SAVED: $!";
     * close STDOUT_SAVED;
     */
    if (handle != (GV*)Nullsv) {
        SV *err = Nullsv;

        MP_TRACE_o(MP_FUNC, "restoring STDOUT");

        if (do_open9(handle_orig, ">&", 2, FALSE,
                     O_WRONLY, 0, Nullfp, (SV*)handle, 1) == 0) {
            err = get_sv("!", TRUE);
        }

        do_close(handle, FALSE);
        (void)hv_delete(gv_stashpv("Apache2::RequestIO", TRUE), 
                        GvNAME(handle), GvNAMELEN(handle), G_DISCARD);

        if (err != Nullsv) {
            Perl_croak(aTHX_ "Failed to restore STDOUT: %" SVf, err);
        }
    }

    MP_TRACE_o(MP_FUNC, "end\n");
}
