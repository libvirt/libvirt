/*
 * qemu_migration.h: QEMU migration handling
 *
 * Copyright (C) 2006-2011, 2014 Red Hat, Inc.
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

#pragma once

#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_migration_params.h"
#include "virenum.h"

/*
 * General function naming conventions:
 *
 *  - qemuMigrationSrcXXX - only runs on source host
 *  - qemuMigrationDstXXX - only runs on dest host
 *  - qemuMigrationAnyXXX - runs on source or dest host
 *
 * Exceptions:
 *
 *  - qemuMigrationOptionXXX - runs on source or dest host
 *  - qemuMigrationJobXXX - runs on source or dest host
 */

/* All supported qemu migration flags.  */
#define QEMU_MIGRATION_FLAGS \
    (VIR_MIGRATE_LIVE | \
     VIR_MIGRATE_PEER2PEER | \
     VIR_MIGRATE_TUNNELLED | \
     VIR_MIGRATE_PERSIST_DEST | \
     VIR_MIGRATE_UNDEFINE_SOURCE | \
     VIR_MIGRATE_PAUSED | \
     VIR_MIGRATE_NON_SHARED_DISK | \
     VIR_MIGRATE_NON_SHARED_INC | \
     VIR_MIGRATE_CHANGE_PROTECTION | \
     VIR_MIGRATE_UNSAFE | \
     VIR_MIGRATE_OFFLINE | \
     VIR_MIGRATE_COMPRESSED | \
     VIR_MIGRATE_ABORT_ON_ERROR | \
     VIR_MIGRATE_AUTO_CONVERGE | \
     VIR_MIGRATE_RDMA_PIN_ALL | \
     VIR_MIGRATE_POSTCOPY | \
     VIR_MIGRATE_TLS | \
     VIR_MIGRATE_PARALLEL | \
     VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES | \
     VIR_MIGRATE_POSTCOPY_RESUME | \
     VIR_MIGRATE_ZEROCOPY | \
     0)

/* All supported migration parameters and their types. */
#define QEMU_MIGRATION_PARAMETERS \
    VIR_MIGRATE_PARAM_URI,              VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_NAME,        VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_XML,         VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_BANDWIDTH,        VIR_TYPED_PARAM_ULLONG, \
    VIR_MIGRATE_PARAM_GRAPHICS_URI,     VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_LISTEN_ADDRESS,   VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_MIGRATE_DISKS,    VIR_TYPED_PARAM_STRING | \
                                        VIR_TYPED_PARAM_MULTIPLE, \
    VIR_MIGRATE_PARAM_DISKS_PORT,       VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION,      VIR_TYPED_PARAM_STRING | \
                                        VIR_TYPED_PARAM_MULTIPLE, \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL,         VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS,       VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS,      VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE,     VIR_TYPED_PARAM_ULLONG, \
    VIR_MIGRATE_PARAM_PERSIST_XML,      VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL,        VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT,      VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY, VIR_TYPED_PARAM_ULLONG, \
    VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS, VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION_ZLIB_LEVEL, VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_COMPRESSION_ZSTD_LEVEL, VIR_TYPED_PARAM_INT, \
    VIR_MIGRATE_PARAM_TLS_DESTINATION, VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DISKS_URI,     VIR_TYPED_PARAM_STRING, \
    NULL


typedef enum {
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
    QEMU_MIGRATION_PHASE_POSTCOPY_FAILED, /* marker for resume phases */
    QEMU_MIGRATION_PHASE_BEGIN_RESUME,
    QEMU_MIGRATION_PHASE_PERFORM_RESUME,
    QEMU_MIGRATION_PHASE_CONFIRM_RESUME,
    QEMU_MIGRATION_PHASE_PREPARE_RESUME,
    QEMU_MIGRATION_PHASE_FINISH_RESUME,

    QEMU_MIGRATION_PHASE_LAST
} qemuMigrationJobPhase;
VIR_ENUM_DECL(qemuMigrationJobPhase);

char *
qemuMigrationSrcBegin(virConnectPtr conn,
                      virDomainObj *vm,
                      const char *xmlin,
                      const char *dname,
                      char **cookieout,
                      int *cookieoutlen,
                      size_t nmigrate_disks,
                      const char **migrate_disks,
                      unsigned int flags);

virDomainDef *
qemuMigrationAnyPrepareDef(virQEMUDriver *driver,
                           virQEMUCaps *qemuCaps,
                           const char *dom_xml,
                           const char *dname,
                           char **origname);

int
qemuMigrationDstPrepareTunnel(virQEMUDriver *driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              virStreamPtr st,
                              virDomainDef **def,
                              const char *origname,
                              qemuMigrationParams *migParams,
                              unsigned int flags);

int
qemuMigrationDstPrepareDirect(virQEMUDriver *driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              const char *uri_in,
                              char **uri_out,
                              virDomainDef **def,
                              const char *origname,
                              const char *listenAddress,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              int nbdPort,
                              const char *nbdURI,
                              qemuMigrationParams *migParams,
                              unsigned int flags);

int
qemuMigrationSrcPerform(virQEMUDriver *driver,
                        virConnectPtr conn,
                        virDomainObj *vm,
                        const char *xmlin,
                        const char *persist_xml,
                        const char *dconnuri,
                        const char *uri,
                        const char *graphicsuri,
                        const char *listenAddress,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        int nbdPort,
                        const char *nbdURI,
                        qemuMigrationParams *migParams,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned int flags,
                        const char *dname,
                        unsigned long resource,
                        bool v3proto);

virDomainPtr
qemuMigrationDstFinish(virQEMUDriver *driver,
                       virConnectPtr dconn,
                       virDomainObj *vm,
                       const char *cookiein,
                       int cookieinlen,
                       char **cookieout,
                       int *cookieoutlen,
                       unsigned int flags,
                       int retcode,
                       bool v3proto);

void
qemuMigrationDstComplete(virQEMUDriver *driver,
                         virDomainObj *vm,
                         bool inPostCopy,
                         virDomainAsyncJob asyncJob,
                         virDomainJobObj *job);

int
qemuMigrationSrcConfirm(virQEMUDriver *driver,
                        virDomainObj *vm,
                        const char *cookiein,
                        int cookieinlen,
                        unsigned int flags,
                        int cancelled);

void
qemuMigrationSrcComplete(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainAsyncJob asyncJob);

void
qemuMigrationProcessUnattended(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainAsyncJob job,
                               qemuMonitorMigrationStatus status);

bool
qemuMigrationSrcIsAllowed(virDomainObj *vm,
                          bool remote,
                          int asyncJob,
                          unsigned int flags);

int
qemuMigrationSrcToFile(virQEMUDriver *driver,
                       virDomainObj *vm,
                       int fd,
                       virCommand *compressor,
                       virDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int
qemuMigrationSrcCancelUnattended(virDomainObj *vm,
                                 virDomainJobObj *oldJob);

int
qemuMigrationSrcCancel(virDomainObj *vm,
                       virDomainAsyncJob asyncJob,
                       bool wait);

int
qemuMigrationAnyFetchStats(virDomainObj *vm,
                           virDomainAsyncJob asyncJob,
                           virDomainJobData *jobData,
                           char **error);

int
qemuMigrationDstErrorInit(virQEMUDriver *driver);

void
qemuMigrationDstErrorSave(virQEMUDriver *driver,
                          const char *name,
                          virErrorPtr err);

void
qemuMigrationDstErrorReport(virQEMUDriver *driver,
                            const char *name);

int
qemuMigrationDstCheckProtocol(virQEMUCaps *qemuCaps,
                              const char *migrateFrom);

char *
qemuMigrationDstGetURI(const char *migrateFrom,
                       int migrateFd);

int
qemuMigrationDstRun(virDomainObj *vm,
                    const char *uri,
                    virDomainAsyncJob asyncJob);

void
qemuMigrationSrcPostcopyFailed(virDomainObj *vm);

void
qemuMigrationDstPostcopyFailed(virDomainObj *vm);

int
qemuMigrationSrcFetchMirrorStats(virDomainObj *vm,
                                 virDomainAsyncJob asyncJob,
                                 virDomainJobData *jobData);

int
qemuMigrationAnyRefreshStatus(virDomainObj *vm,
                              virDomainAsyncJob asyncJob,
                              virDomainJobStatus *status);
