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

/*
 * Stat_t needs flags in modperl_largefiles.h
 */
int modperl_sys_is_dir(pTHX_ SV *sv)
{
    Stat_t statbuf;
    STRLEN n_a;
    char *name = SvPV(sv, n_a);

    if (PerlLIO_stat(name, &statbuf) < 0) {
        return 0;
    }

    return S_ISDIR(statbuf.st_mode);
}

/*
 * Perl does not provide this abstraction.
 * APR does, but requires a pool.  efforts to expose this area of apr
 * failed.  so we roll our own.  *sigh*
 */
int modperl_sys_dlclose(void *handle)
{
#if defined(MP_SYS_DL_DLOPEN)
#ifdef I_DLFCN
#include <dlfcn.h>
#else
#include <nlist.h>
#include <link.h>
#endif
    return dlclose(handle) == 0;
#elif defined(MP_SYS_DL_DYLD)
    return NSUnLinkModule(handle, FALSE);
#elif defined(MP_SYS_DL_HPUX)
#include <dl.h>
    shl_unload((shl_t)handle);
    return 1;
#elif defined(MP_SYS_DL_WIN32)
    return FreeLibrary(handle);
#elif defined(MP_SYS_DL_BEOS)
    return unload_add_on(handle) < B_NO_ERROR;
#elif defined(MP_SYS_DL_DLLLOAD)
    return dllfree(handle) == 0;
#elif defined(MP_SYS_DL_AIX)
    return dlclose(handle) == 0;
#else
#error "modperl_sys_dlclose not defined on this platform"
    return 0;
#endif
}
