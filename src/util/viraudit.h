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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */


#ifndef __LIBVIRT_AUDIT_H__
# define __LIBVIRT_AUDIT_H__

# include "internal.h"

enum virAuditRecordType {
    VIR_AUDIT_RECORD_MACHINE_CONTROL,
    VIR_AUDIT_RECORD_MACHINE_ID,
    VIR_AUDIT_RECORD_RESOURCE,
};

int virAuditOpen(void);

void virAuditLog(int enabled);

void virAuditSend(const char *file, const char *func, size_t linenr,
                  const char *clienttty, const char *clientaddr,
                  enum virAuditRecordType type, bool success,
                  const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(8, 9);

char *virAuditEncode(const char *key, const char *value);

void virAuditClose(void);

# define VIR_AUDIT(type, success, ...)				\
    virAuditSend(__FILE__, __func__, __LINE__,			\
                 NULL, NULL, type, success, __VA_ARGS__);

# define VIR_AUDIT_USER(type, success, clienttty, clientaddr, ...)	\
    virAuditSend(__FILE__, __func__, __LINE__,				\
                 clienttty, clientaddr, type, success, __VA_ARGS__);

# define VIR_AUDIT_STR(str) \
    ((str) ? (str) : "?")

#endif /* __LIBVIRT_AUDIT_H__ */
