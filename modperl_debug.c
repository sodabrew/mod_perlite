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

char *modperl_server_desc(server_rec *s, apr_pool_t *p)
{
    return apr_psprintf(p, "%s:%u", s->server_hostname, s->port);
}

/* used in debug traces */
MP_INLINE char *modperl_pid_tid(apr_pool_t *p)
{
    if (modperl_threaded_mpm()) {
        return apr_psprintf(p, "%lu"
#if APR_HAS_THREADS
                            "/%lu"
#endif /* APR_HAS_THREADS */
                            , (unsigned long)getpid()
#if APR_HAS_THREADS
                            , modperl_threads_started()
                            ? (unsigned long)apr_os_thread_current()
                            : 0
#endif /* APR_HAS_THREADS */
            );
    }
    else {
        return apr_psprintf(p, "%lu", (unsigned long)getpid());
    }
}

    
#ifdef MP_TRACE
void modperl_apr_table_dump(pTHX_ apr_table_t *table, char *name)
{
    int i, tmp_len, len = 0;
    char *fmt;
    const apr_array_header_t *array = apr_table_elts(table);
    apr_table_entry_t *elts  = (apr_table_entry_t *)array->elts;

    modperl_trace(MP_FUNC, "*** Contents of table '%s' ***", name);
    for (i = 0; i < array->nelts; i++) {
        if (elts[i].key && elts[i].val) {
            tmp_len = strlen(elts[i].key);
            if (tmp_len > len) {
                len = tmp_len;
            }
        }
    }    
    /* dump the table with keys aligned */
    fmt = Perl_form(aTHX_ "%%-%ds => %%s", len);

    for (i = 0; i < array->nelts; i++) {
        if (!elts[i].key || !elts[i].val) {
            continue;
        }
        modperl_trace(MP_FUNC, fmt, elts[i].key, elts[i].val);
    }    
    modperl_trace(MP_FUNC, "");
}
#endif

#ifdef MP_TRACE
void modperl_perl_modglobal_dump(pTHX)
{
    HV *hv = PL_modglobal;
    AV *val;
    char *key;
    I32 klen;
    hv_iterinit(hv);

    MP_TRACE_g(MP_FUNC, "|-------- PL_modglobal --------");
#ifdef USE_ITHREADS
    MP_TRACE_g(MP_FUNC, "| perl 0x%lx", (unsigned long)aTHX);
#endif
    MP_TRACE_g(MP_FUNC, "| PL_modglobal 0x%lx",
               (unsigned long)PL_modglobal);

    while ((val = (AV*)hv_iternextsv(hv, &key, &klen))) {
        MP_TRACE_g(MP_FUNC, "| %s => 0x%lx", key, val);
    }

    MP_TRACE_g(MP_FUNC, "|-------- PL_modglobal --------\n");

}
#endif

