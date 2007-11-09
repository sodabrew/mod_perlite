
#ifndef INCLUDES_H
#define INCLUDES_H

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"

#include "ap_config.h"

#include "apr_portable.h"
#include "apr_file_io.h"
#include "apr_errno.h"
#include "apr_lib.h"

#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"

#define PERLITE_MAGIC_TYPE "application/x-httpd-perlite"
#define PERLITE_SCRIPT "perlite-script"

#endif
