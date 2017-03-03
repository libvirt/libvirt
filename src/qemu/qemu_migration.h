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

#ifndef __QEMU_MIGRATION_H__
# define __QEMU_MIGRATION_H__

# include "qemu_conf.h"
# include "qemu_domain.h"

typedef struct _qemuMigrationCompression qemuMigrationCompression;
typedef qemuMigrationCompression *qemuMigrationCompressionPtr;

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
     VIR_MIGRATE_UNSAFE |                       \
     VIR_MIGRATE_OFFLINE |                      \
     VIR_MIGRATE_COMPRESSED |                   \
     VIR_MIGRATE_ABORT_ON_ERROR |               \
     VIR_MIGRATE_AUTO_CONVERGE |                \
     VIR_MIGRATE_RDMA_PIN_ALL |                 \
     VIR_MIGRATE_POSTCOPY |                     \
     VIR_MIGRATE_TLS)

/* All supported migration parameters and their types. */
# define QEMU_MIGRATION_PARAMETERS                                \
    VIR_MIGRATE_PARAM_URI,              VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_DEST_NAME,        VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_DEST_XML,         VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_BANDWIDTH,        VIR_TYPED_PARAM_ULLONG,   \
    VIR_MIGRATE_PARAM_GRAPHICS_URI,     VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_LISTEN_ADDRESS,   VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_MIGRATE_DISKS,    VIR_TYPED_PARAM_STRING |  \
                                        VIR_TYPED_PARAM_MULTIPLE, \
    VIR_MIGRATE_PARAM_DISKS_PORT,       VIR_TYPED_PARAM_INT,      \
    VIR_MIGRATE_PARAM_COMPRESSION,      VIR_TYPED_PARAM_STRING |  \
                                        VIR_TYPED_PARAM_MULTIPLE, \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL,         VIR_TYPED_PARAM_INT,    \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS,       VIR_TYPED_PARAM_INT,    \
    VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS,      VIR_TYPED_PARAM_INT,    \
    VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE,     VIR_TYPED_PARAM_ULLONG, \
    VIR_MIGRATE_PARAM_PERSIST_XML,      VIR_TYPED_PARAM_STRING,   \
    VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL,        VIR_TYPED_PARAM_INT,    \
    VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT,      VIR_TYPED_PARAM_INT,    \
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

    QEMU_MIGRATION_PHASE_LAST
} qemuMigrationJobPhase;
VIR_ENUM_DECL(qemuMigrationJobPhase)

typedef enum {
    QEMU_MIGRATION_COMPRESS_XBZRLE = 0,
    QEMU_MIGRATION_COMPRESS_MT,

    QEMU_MIGRATION_COMPRESS_LAST
} qemuMigrationCompressMethod;
VIR_ENUM_DECL(qemuMigrationCompressMethod)

struct _qemuMigrationCompression {
    unsigned long long methods;

    bool level_set;
    int level;

    bool threads_set;
    int threads;

    bool dthreads_set;
    int dthreads;

    bool xbzrle_cache_set;
    unsigned long long xbzrle_cache;
};

qemuMigrationCompressionPtr
qemuMigrationCompressionParse(virTypedParameterPtr params,
                              int nparams,
                              unsigned long flags);
int qemuMigrationCompressionDump(qemuMigrationCompressionPtr compression,
                                 virTypedParameterPtr *params,
                                 int *nparams,
                                 int *maxparams,
                                 unsigned long *flags);

void
qemuMigrationParamsClear(qemuMonitorMigrationParamsPtr migParams);

void
qemuMigrationParamsFree(qemuMonitorMigrationParamsPtr *migParams);

qemuMonitorMigrationParamsPtr
qemuMigrationParams(virTypedParameterPtr params,
                    int nparams,
                    unsigned long flags);

int qemuMigrationJobStart(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          qemuDomainAsyncJob job)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
void qemuMigrationJobSetPhase(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuMigrationJobStartPhase(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuMigrationJobContinue(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
bool qemuMigrationJobIsActive(virDomainObjPtr vm,
                              qemuDomainAsyncJob job)
    ATTRIBUTE_NONNULL(1);
void qemuMigrationJobFinish(virQEMUDriverPtr driver, virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMigrationSetOffline(virQEMUDriverPtr driver,
                            virDomainObjPtr vm);

char *qemuMigrationBegin(virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *xmlin,
                         const char *dname,
                         char **cookieout,
                         int *cookieoutlen,
                         size_t nmigrate_disks,
                         const char **migrate_disks,
                         unsigned long flags);

virDomainDefPtr qemuMigrationPrepareDef(virQEMUDriverPtr driver,
                                        const char *dom_xml,
                                        const char *dname,
                                        char **origname);

int qemuMigrationPrepareTunnel(virQEMUDriverPtr driver,
                               virConnectPtr dconn,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               virStreamPtr st,
                               virDomainDefPtr *def,
                               const char *origname,
                               unsigned long flags);

int qemuMigrationPrepareDirect(virQEMUDriverPtr driver,
                               virConnectPtr dconn,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               const char *uri_in,
                               char **uri_out,
                               virDomainDefPtr *def,
                               const char *origname,
                               const char *listenAddress,
                               size_t nmigrate_disks,
                               const char **migrate_disks,
                               int nbdPort,
                               qemuMigrationCompressionPtr compression,
                               unsigned long flags);

int qemuMigrationPerform(virQEMUDriverPtr driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *xmlin,
                         const char *persist_xml,
                         const char *dconnuri,
                         const char *uri,
                         const char *graphicsuri,
                         const char *listenAddress,
                         size_t nmigrate_disks,
                         const char **migrate_disks,
                         int nbdPort,
                         qemuMigrationCompressionPtr compression,
                         qemuMonitorMigrationParamsPtr migParams,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         unsigned long flags,
                         const char *dname,
                         unsigned long resource,
                         bool v3proto);

virDomainPtr qemuMigrationFinish(virQEMUDriverPtr driver,
                                 virConnectPtr dconn,
                                 virDomainObjPtr vm,
                                 const char *cookiein,
                                 int cookieinlen,
                                 char **cookieout,
                                 int *cookieoutlen,
                                 unsigned long flags,
                                 int retcode,
                                 bool v3proto);

int qemuMigrationConfirm(virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned int flags,
                         int cancelled);

bool qemuMigrationIsAllowed(virQEMUDriverPtr driver, virDomainObjPtr vm,
                            bool remote, unsigned int flags);

int qemuMigrationToFile(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        int fd,
                        const char *compressor,
                        qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int qemuMigrationCancel(virQEMUDriverPtr driver,
                        virDomainObjPtr vm);

int qemuMigrationFetchJobStatus(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                qemuDomainAsyncJob asyncJob,
                                qemuDomainJobInfoPtr jobInfo);

int qemuMigrationErrorInit(virQEMUDriverPtr driver);
void qemuMigrationErrorSave(virQEMUDriverPtr driver,
                            const char *name,
                            virErrorPtr err);
void qemuMigrationErrorReport(virQEMUDriverPtr driver,
                              const char *name);

int qemuMigrationCheckIncoming(virQEMUCapsPtr qemuCaps,
                               const char *migrateFrom);

char *qemuMigrationIncomingURI(const char *migrateFrom,
                               int migrateFd);

int qemuMigrationRunIncoming(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             const char *uri,
                             qemuDomainAsyncJob asyncJob);

void qemuMigrationPostcopyFailed(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm);

int
qemuMigrationResetTLS(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      qemuDomainAsyncJob asyncJob,
                      char *in_tlsAlias,
                      char *in_secAlias);

#endif /* __QEMU_MIGRATION_H__ */
