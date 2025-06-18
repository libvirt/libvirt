/*
 * libvirt_nss_log: Logging for Name Service Switch plugin
 *
 * Copyright (C) 2025 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#undef _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "libvirt_nss_log.h"
#include "libvirt_nss.h"

#define NULLSTR(s) ((s) ? (s) : "<null>")

static const char *  __attribute__((returns_nonnull))
nssLogPriorityToString(nssLogPriority prio)
{
    switch (prio) {
    case NSS_DEBUG:
        return "DEBUG";
    case NSS_ERROR:
        return "ERROR";
    }

    return "";
}

void
nssLog(nssLogPriority prio,
       const char *func,
       int linenr,
       const char *fmt, ...)
{
    int saved_errno = errno;
    const size_t ebuf_size = 512;
    g_autofree char *ebuf = NULL;
    va_list ap;

    if (!getenv(NSS_LOG_ENV_VAR))
        return;

    fprintf(stderr, "%s %s:%d : ", nssLogPriorityToString(prio), func, linenr);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    switch (prio) {
    case NSS_DEBUG:
        break;

    case NSS_ERROR:
        ebuf = calloc(ebuf_size, sizeof(*ebuf));
        if (ebuf)
            strerror_r(saved_errno, ebuf, ebuf_size);
        fprintf(stderr, " : %s", NULLSTR(ebuf));
        break;
    }

    fprintf(stderr, "\n");
}
