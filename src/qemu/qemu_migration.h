/*
 * qemu_migration.h: QEMU migration handling
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#ifndef __QEMU_MIGRATION_H__
# define __QEMU_MIGRATION_H__

# include "qemu_conf.h"


bool qemuMigrationIsAllowed(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);
int qemuMigrationSetOffline(struct qemud_driver *driver,
                            virDomainObjPtr vm);

int qemuMigrationWaitForCompletion(struct qemud_driver *driver, virDomainObjPtr vm);

int qemuMigrationPrepareTunnel(struct qemud_driver *driver,
                               virConnectPtr dconn,
                               virStreamPtr st,
                               const char *dname,
                               const char *dom_xml);

int qemuMigrationPrepareDirect(struct qemud_driver *driver,
                               virConnectPtr dconn,
                               const char *uri_in,
                               char **uri_out,
                               const char *dname,
                               const char *dom_xml);

int qemuMigrationPerform(struct qemud_driver *driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *uri,
                         unsigned long flags,
                         const char *dname,
                         unsigned long resource);

virDomainPtr qemuMigrationFinish(struct qemud_driver *driver,
                                 virConnectPtr dconn,
                                 virDomainObjPtr vm,
                                 unsigned long flags,
                                 int retcode);


#endif /* __QEMU_MIGRATION_H__ */
