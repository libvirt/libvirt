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
# include "qemu_domain.h"

/* All supported qemu migration flags.  */
# define QEMU_MIGRATION_FLAGS                   \
    (VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_PEER2PEER |                    \
     VIR_MIGRATE_TUNNELLED |                    \
     VIR_MIGRATE_PERSIST_DEST |                 \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_PAUSED |                       \
     VIR_MIGRATE_NON_SHARED_DISK |              \
     VIR_MIGRATE_NON_SHARED_INC |               \
     VIR_MIGRATE_CHANGE_PROTECTION |            \
     VIR_MIGRATE_UNSAFE)

enum qemuMigrationJobPhase {
    QEMU_MIGRATION_PHASE_NONE = 0,
    QEMU_MIGRATION_PHASE_PERFORM2,
    QEMU_MIGRATION_PHASE_BEGIN3,
    QEMU_MIGRATION_PHASE_PERFORM3,
    QEMU_MIGRATION_PHASE_PERFORM3_DONE,
    QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED,
    QEMU_MIGRATION_PHASE_CONFIRM3,
    QEMU_MIGRATION_PHASE_PREPARE,
    QEMU_MIGRATION_PHASE_FINISH2,
    QEMU_MIGRATION_PHASE_FINISH3,

    QEMU_MIGRATION_PHASE_LAST
};
VIR_ENUM_DECL(qemuMigrationJobPhase)

int qemuMigrationJobStart(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          enum qemuDomainAsyncJob job)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
void qemuMigrationJobSetPhase(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              enum qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuMigrationJobStartPhase(struct qemud_driver *driver,
                                virDomainObjPtr vm,
                                enum qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuMigrationJobContinue(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
bool qemuMigrationJobIsActive(virDomainObjPtr vm,
                              enum qemuDomainAsyncJob job)
    ATTRIBUTE_NONNULL(1);
int qemuMigrationJobFinish(struct qemud_driver *driver, virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int qemuMigrationSetOffline(struct qemud_driver *driver,
                            virDomainObjPtr vm);

virDomainObjPtr qemuMigrationCleanup(struct qemud_driver *driver,
                                     virDomainObjPtr vm,
                                     virConnectPtr conn);

char *qemuMigrationBegin(struct qemud_driver *driver,
                         virDomainObjPtr vm,
                         const char *xmlin,
                         const char *dname,
                         char **cookieout,
                         int *cookieoutlen,
                         unsigned long flags);

int qemuMigrationPrepareTunnel(struct qemud_driver *driver,
                               virConnectPtr dconn,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               virStreamPtr st,
                               const char *dname,
                               const char *dom_xml);

int qemuMigrationPrepareDirect(struct qemud_driver *driver,
                               virConnectPtr dconn,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               const char *uri_in,
                               char **uri_out,
                               const char *dname,
                               const char *dom_xml);

int qemuMigrationPerform(struct qemud_driver *driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *xmlin,
                         const char *dconnuri,
                         const char *uri,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         unsigned long flags,
                         const char *dname,
                         unsigned long resource,
                         bool v3proto);

virDomainPtr qemuMigrationFinish(struct qemud_driver *driver,
                                 virConnectPtr dconn,
                                 virDomainObjPtr vm,
                                 const char *cookiein,
                                 int cookieinlen,
                                 char **cookieout,
                                 int *cookieoutlen,
                                 unsigned long flags,
                                 int retcode,
                                 bool v3proto);

int qemuMigrationConfirm(struct qemud_driver *driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned int flags,
                         int retcode);


int qemuMigrationToFile(struct qemud_driver *driver, virDomainObjPtr vm,
                        int fd, off_t offset, const char *path,
                        const char *compressor,
                        bool bypassSecurityDriver,
                        enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_RETURN_CHECK;

#endif /* __QEMU_MIGRATION_H__ */
