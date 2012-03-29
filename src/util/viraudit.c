/*
 * viraudit.c: auditing support
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#ifdef HAVE_AUDIT
# include <libaudit.h>
#endif
#include <stdio.h>
#include <unistd.h>

#include "virterror_internal.h"
#include "logging.h"
#include "viraudit.h"
#include "util.h"
#include "virfile.h"
#include "memory.h"

/* Provide the macros in case the header file is old.
   FIXME: should be removed. */
#ifndef AUDIT_VIRT_CONTROL
# define AUDIT_VIRT_CONTROL              2500 /* Start, Pause, Stop VM */
#endif
#ifndef AUDIT_VIRT_RESOURCE
# define AUDIT_VIRT_RESOURCE             2501 /* Resource assignment */
#endif
#ifndef AUDIT_VIRT_MACHINE_ID
# define AUDIT_VIRT_MACHINE_ID           2502 /* Binding of label to VM */
#endif

#define VIR_FROM_THIS VIR_FROM_AUDIT

#if HAVE_AUDIT
static int auditfd = -1;
#endif
static int auditlog = 0;

int virAuditOpen(void)
{
#if HAVE_AUDIT
    if ((auditfd = audit_open()) < 0) {
        virReportSystemError(errno, "%s", _("Unable to initialize audit layer"));
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}


void virAuditLog(int logging)
{
    auditlog = logging;
}


void virAuditSend(const char *file ATTRIBUTE_UNUSED, const char *func,
                  size_t linenr,
                  const char *clienttty ATTRIBUTE_UNUSED,
                  const char *clientaddr ATTRIBUTE_UNUSED,
                  enum virAuditRecordType type ATTRIBUTE_UNUSED, bool success,
                  const char *fmt, ...)
{
    char *str = NULL;
    va_list args;

    /* Duplicate later checks, to short circuit & avoid printf overhead
     * when nothing is enabled */
#if HAVE_AUDIT
    if (!auditlog && auditfd < 0)
        return;
#else
    if (!auditlog)
        return;
#endif

    va_start(args, fmt);
    if (virVasprintf(&str, fmt, args) < 0) {
        VIR_WARN("Out of memory while formatting audit message");
        str = NULL;
    }
    va_end(args);

    if (auditlog && str) {
        if (success)
            virLogMessage("audit", VIR_LOG_INFO, func, linenr, 0,
                          "success=yes %s", str);
        else
            virLogMessage("audit", VIR_LOG_WARN, func, linenr, 0,
                          "success=no %s", str);
    }

#if HAVE_AUDIT
    if (auditfd < 0) {
        VIR_FREE(str);
        return;
    }

    if (str) {
        static const int record_types[] = {
            [VIR_AUDIT_RECORD_MACHINE_CONTROL] = AUDIT_VIRT_CONTROL,
            [VIR_AUDIT_RECORD_MACHINE_ID] = AUDIT_VIRT_MACHINE_ID,
            [VIR_AUDIT_RECORD_RESOURCE] = AUDIT_VIRT_RESOURCE,
        };

        if (type >= ARRAY_CARDINALITY(record_types) || record_types[type] == 0)
            VIR_WARN("Unknown audit record type %d", type);
        else if (audit_log_user_message(auditfd, record_types[type], str, NULL,
                                        clientaddr, clienttty, success) < 0) {
            char ebuf[1024];
            VIR_WARN("Failed to send audit message %s: %s",
                     NULLSTR(str), virStrerror(errno, ebuf, sizeof(ebuf)));
        }
        VIR_FREE(str);
    }
#endif
}

void virAuditClose(void)
{
#if HAVE_AUDIT
    VIR_FORCE_CLOSE(auditfd);
#endif
}

char *virAuditEncode(const char *key, const char *value)
{
#if HAVE_AUDIT
    return audit_encode_nv_string(key, value, 0);
#else
    char *str;
    if (virAsprintf(&str, "%s=%s", key, value) < 0)
        return NULL;
    return str;
#endif
}
