/*
 * viraudit.h: auditing support
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


#ifndef __LIBVIRT_AUDIT_H__
# define __LIBVIRT_AUDIT_H__

# include "internal.h"
# include "virlog.h"

enum virAuditRecordType {
    VIR_AUDIT_RECORD_MACHINE_CONTROL,
    VIR_AUDIT_RECORD_MACHINE_ID,
    VIR_AUDIT_RECORD_RESOURCE,
};

int virAuditOpen(void);

void virAuditLog(int enabled);

void virAuditSend(virLogSourcePtr source,
                  const char *filename, size_t linenr, const char *funcname,
                  const char *clienttty, const char *clientaddr,
                  enum virAuditRecordType type, bool success,
                  const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(9, 10);

char *virAuditEncode(const char *key, const char *value);

void virAuditClose(void);

# define VIR_AUDIT(type, success, ...)				\
    virAuditSend(&virLogSelf, __FILE__, __LINE__, __func__,     \
                 NULL, NULL, type, success, __VA_ARGS__);

# define VIR_AUDIT_USER(type, success, clienttty, clientaddr, ...)	\
    virAuditSend(&virLogSelf, __FILE__, __LINE__, __func__,             \
                 clienttty, clientaddr, type, success, __VA_ARGS__);

# define VIR_AUDIT_STR(str) \
    ((str) ? (str) : "?")

#endif /* __LIBVIRT_AUDIT_H__ */
