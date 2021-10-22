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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#ifdef WITH_AUDIT
# include <libaudit.h>
#endif

#include "virerror.h"
#include "virlog.h"
#include "viraudit.h"
#include "virfile.h"

VIR_LOG_INIT("util.audit");

#define VIR_FROM_THIS VIR_FROM_AUDIT

#if WITH_AUDIT
static int auditfd = -1;
#endif
static bool auditlog;

int virAuditOpen(unsigned int audit_level G_GNUC_UNUSED)
{
#if WITH_AUDIT
    if ((auditfd = audit_open()) < 0) {
        /* You get these error codes only when the kernel does not
         * have audit compiled in or it's disabled (e.g. by the kernel
         * cmdline) */
        if (errno == EINVAL || errno == EPROTONOSUPPORT ||
            errno == EAFNOSUPPORT) {
            if (audit_level < 2)
                VIR_INFO("Audit is not supported by the kernel");
            else
                virReportError(VIR_FROM_THIS, "%s", _("Audit is not supported by the kernel"));
        } else {
            virReportSystemError(errno, "%s", _("Unable to initialize audit layer"));
        }

        return -1;
    }

    return 0;
#else
    return -1;
#endif
}


void virAuditLog(bool logging)
{
    auditlog = logging;
}


void virAuditSend(virLogSource *source,
                  const char *filename,
                  size_t linenr,
                  const char *funcname,
                  const char *clienttty G_GNUC_UNUSED,
                  const char *clientaddr G_GNUC_UNUSED,
                  virAuditRecordType type G_GNUC_UNUSED, bool success,
                  const char *fmt, ...)
{
    g_autofree char *str = NULL;
    va_list args;

    /* Duplicate later checks, to short circuit & avoid printf overhead
     * when nothing is enabled */
#if WITH_AUDIT
    if (!auditlog && auditfd < 0)
        return;
#else
    if (!auditlog)
        return;
#endif

    va_start(args, fmt);
    str = g_strdup_vprintf(fmt, args);
    va_end(args);

    if (auditlog && str) {
        if (success)
            virLogMessage(source, VIR_LOG_INFO,
                          filename, linenr, funcname,
                          NULL, "success=yes %s", str);
        else
            virLogMessage(source, VIR_LOG_WARN,
                          filename, linenr, funcname,
                          NULL, "success=no %s", str);
    }

#if WITH_AUDIT
    if (str && auditfd >= 0) {
        static const int record_types[] = {
            [VIR_AUDIT_RECORD_MACHINE_CONTROL] = AUDIT_VIRT_CONTROL,
            [VIR_AUDIT_RECORD_MACHINE_ID] = AUDIT_VIRT_MACHINE_ID,
            [VIR_AUDIT_RECORD_RESOURCE] = AUDIT_VIRT_RESOURCE,
        };

        if (type >= G_N_ELEMENTS(record_types) || record_types[type] == 0)
            VIR_WARN("Unknown audit record type %d", type);
        else if (audit_log_user_message(auditfd, record_types[type], str, NULL,
                                        clientaddr, clienttty, success) < 0) {
            VIR_WARN("Failed to send audit message %s: %s",
                     NULLSTR(str), g_strerror(errno));
        }
    }
#endif
}

void virAuditClose(void)
{
#if WITH_AUDIT
    VIR_FORCE_CLOSE(auditfd);
#endif
}

char *virAuditEncode(const char *key, const char *value)
{
#if WITH_AUDIT
    return audit_encode_nv_string(key, value, 0);
#else
    return g_strdup_printf("%s=%s", key, value);
#endif
}
