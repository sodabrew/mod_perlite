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

MP_INLINE int modperl_cgi_header_parse(request_rec *r, char *buffer,
                                       apr_size_t *len, const char **body)
{
    int status;
    int termarg;
    const char *location;
    const char *tmp;
    apr_size_t tlen, newln;

    if (!buffer) {
        return DECLINED;
    }

    /* ap_scan_script_header_err_strs won't handle correctly binary
     * data following the headers, e.g. when the terminating /\n\r?\n/
     * is followed by \0\0 which is a part of the response
     * body. Therefore we need to separate the headers from the body
     * and not rely on ap_scan_script_header_err_strs to do that for
     * us.
     */
    tmp = buffer;
    newln = 0;
    tlen = *len;
    while (tlen--) {
        /* that strange mix of CR and \n (and not LF) copied from
         * util_script.c:ap_scan_script_header_err_core
         */
        if (*tmp != CR && *tmp != '\n') {
            newln = 0;
        }
        if (*tmp == '\n') {
            newln++;
        }
        tmp++;
        if (newln == 2) {
            break;
        }
    }

    if (tmp - buffer >= *len) {
        *body = NULL; /* no body along with headers */
        *len = 0;
    }
    else {
        *body = tmp;
        *len = *len - (tmp - buffer);
    }

    status = ap_scan_script_header_err_strs(r, NULL, NULL,
                                            &termarg, buffer, NULL);

    /* code below from mod_cgi.c */
    location = apr_table_get(r->headers_out, "Location");

    if (location && (location[0] == '/') && (r->status == 200)) {
        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /* We already read the message body (if any), so don't allow
         * the redirected request to think it has one.  We can ignore 
         * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
         */
        apr_table_unset(r->headers_in, "Content-Length");

        ap_internal_redirect_handler(location, r);

        return OK;
    }
    else if (location && (r->status == 200)) {
        MP_dRCFG;

        /* Note that if a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */

        /* XXX: this is a hack.
         * filter return value doesn't seem to impact anything.
         */
        rcfg->status = HTTP_MOVED_TEMPORARILY;

        return HTTP_MOVED_TEMPORARILY;
    }

    return status;
}
