/*
 * qemu_audit.h: QEMU audit management
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_AUDIT_H__
# define __QEMU_AUDIT_H__

# include "domain_conf.h"

void qemuDomainStartAudit(virDomainObjPtr vm, const char *reason, bool success);
void qemuDomainStopAudit(virDomainObjPtr vm, const char *reason);
void qemuDomainDiskAudit(virDomainObjPtr vm,
                         virDomainDiskDefPtr oldDef,
                         virDomainDiskDefPtr newDef,
                         const char *reason,
                         bool success);
void qemuDomainNetAudit(virDomainObjPtr vm,
                        virDomainNetDefPtr oldDef,
                        virDomainNetDefPtr newDef,
                        const char *reason,
                        bool success);
void qemuDomainSecurityLabelAudit(virDomainObjPtr vm, bool success);

#endif /* __QEMU_AUDIT_H__ */
