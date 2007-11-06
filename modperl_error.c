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

static const char *MP_error_strings[] = {
    "exit was called",           /* MODPERL_RC_EXIT */
    "filter handler has failed", /* MODPERL_FILTER_ERROR */
};

#define MP_error_strings_size \
    sizeof(MP_error_strings) / sizeof(MP_error_strings[0])

char *modperl_error_strerror(pTHX_ apr_status_t rc)
{
    char *ptr;
    char buf[256];

    if (rc >= APR_OS_START_USERERR &&
        rc < APR_OS_START_USERERR + MP_error_strings_size) {
        /* custom mod_perl errors */
        ptr = (char*)MP_error_strings[(int)(rc - APR_OS_START_USERERR)];
    }
    else {
        /* apache apr errors */
        ptr = apr_strerror(rc, buf, sizeof(buf));
    }

    /* must copy the string and not return a pointer to the local
     * address. Using a single (per interpreter) static buffer.
     */
    return Perl_form(aTHX_ "%s", ptr ? ptr : "unknown error");
}


/* modperl_croak notes: under -T we can't really do anything when die
 * was called in the stacked eval_sv (which is the case when a
 * response handler calls a filter handler and that filter calls die
 * ""). for example trying to require a file in modperl_croak(), will
 * cause 'panic: POPSTACK' and the process will exit. Dave fixed that
 * in perl Change 23209 by davem@davem-percy on 2004/08/09 19:48:57,
 * which will hopefully appear in perl 5.8.6. for now workaround this
 * perl bug by setting the taint mode off for the APR/Error loading.
 */

/* croak with $@ as a APR::Error object
 *   rc   - set to apr_status_t value
 *   file - set to the callers filename
 *   line - set to the callers line number
 *   func - set to the function name
 */
void modperl_croak(pTHX_ apr_status_t rc, const char* func) 
{
    HV *stash;
    HV *data;
    int is_tainted = PL_tainted;

    /* see the explanation above */
    if (is_tainted) {
        TAINT_NOT;
    }
    Perl_require_pv(aTHX_ "APR/Error.pm");
    if (is_tainted) {
        TAINT;
    }

    if (SvTRUE(ERRSV)) {
        Perl_croak(aTHX_ "%s", SvPV_nolen(ERRSV));   
    }

    stash = gv_stashpvn("APR::Error", 10, FALSE);
    data = newHV();
    /* $@ = bless {}, "APR::Error"; */
    sv_setsv(ERRSV, sv_bless(newRV_noinc((SV*)data), stash));

    sv_setiv(*hv_fetch(data, "rc",   2, 1), rc);
    sv_setpv(*hv_fetch(data, "file", 4, 1), CopFILE(PL_curcop));
    sv_setiv(*hv_fetch(data, "line", 4, 1), CopLINE(PL_curcop));
    sv_setpv(*hv_fetch(data, "func", 4, 1), func);

    Perl_croak(aTHX_ Nullch);   
}
