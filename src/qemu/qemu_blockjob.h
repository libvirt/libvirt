/*
 * qemu_blockjob.h: helper functions for QEMU block jobs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "internal.h"
#include "qemu_conf.h"

/**
 * This enum has to map all known block job states from enum virDomainBlockJobType
 * to the same values. All internal blockjobs can be mapped after and don't
 * need to have stable values.
 */
typedef enum {
    /* Mapped to public enum */
    QEMU_BLOCKJOB_STATE_COMPLETED = VIR_DOMAIN_BLOCK_JOB_COMPLETED,
    QEMU_BLOCKJOB_STATE_FAILED = VIR_DOMAIN_BLOCK_JOB_FAILED,
    QEMU_BLOCKJOB_STATE_CANCELLED = VIR_DOMAIN_BLOCK_JOB_CANCELED,
    QEMU_BLOCKJOB_STATE_READY = VIR_DOMAIN_BLOCK_JOB_READY,
    /* Additional enum values local to qemu */
    QEMU_BLOCKJOB_STATE_NEW,
    QEMU_BLOCKJOB_STATE_RUNNING,
    QEMU_BLOCKJOB_STATE_CONCLUDED, /* job has finished, but it's unknown
                                      whether it has failed or not */
    QEMU_BLOCKJOB_STATE_ABORTING,
    QEMU_BLOCKJOB_STATE_PENDING,
    QEMU_BLOCKJOB_STATE_PIVOTING,
    QEMU_BLOCKJOB_STATE_LAST
} qemuBlockjobState;
G_STATIC_ASSERT((int)QEMU_BLOCKJOB_STATE_NEW == VIR_DOMAIN_BLOCK_JOB_LAST);

VIR_ENUM_DECL(qemuBlockjobState);

/**
 * This enum has to map all known block job types from enum virDomainBlockJobType
 * to the same values. All internal blockjobs can be mapped after and don't
 * need to have stable values.
 */
typedef enum {
    /* Mapped to public enum */
    QEMU_BLOCKJOB_TYPE_NONE = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN,
    QEMU_BLOCKJOB_TYPE_PULL = VIR_DOMAIN_BLOCK_JOB_TYPE_PULL,
    QEMU_BLOCKJOB_TYPE_COPY = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY,
    QEMU_BLOCKJOB_TYPE_COMMIT = VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT,
    QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT = VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT,
    QEMU_BLOCKJOB_TYPE_BACKUP = VIR_DOMAIN_BLOCK_JOB_TYPE_BACKUP,
    /* Additional enum values local to qemu */
    QEMU_BLOCKJOB_TYPE_INTERNAL,
    QEMU_BLOCKJOB_TYPE_CREATE,
    QEMU_BLOCKJOB_TYPE_BROKEN,
    QEMU_BLOCKJOB_TYPE_LAST
} qemuBlockJobType;
G_STATIC_ASSERT((int)QEMU_BLOCKJOB_TYPE_INTERNAL == VIR_DOMAIN_BLOCK_JOB_TYPE_LAST);

VIR_ENUM_DECL(qemuBlockjob);


typedef struct _qemuBlockJobPullData qemuBlockJobPullData;
struct _qemuBlockJobPullData {
    virStorageSource *base;
};


typedef struct _qemuBlockJobCommitData qemuBlockJobCommitData;
struct _qemuBlockJobCommitData {
    virStorageSource *topparent;
    virStorageSource *top;
    virStorageSource *base;
    bool deleteCommittedImages;
};


typedef struct _qemuBlockJobCreateData qemuBlockJobCreateData;
struct _qemuBlockJobCreateData {
    bool storage;
    virStorageSource *src;
};


typedef struct _qemuBlockJobCopyData qemuBlockJobCopyData;
struct _qemuBlockJobCopyData {
    bool shallownew;
};


typedef struct _qemuBlockJobBackupData qemuBlockJobBackupData;
struct _qemuBlockJobBackupData {
    virStorageSource *store;
    char *bitmap;
};


typedef struct _qemuBlockJobData qemuBlockJobData;
struct _qemuBlockJobData {
    virObject parent;

    char *name;

    virDomainDiskDef *disk; /* may be NULL, if blockjob does not correspond to any disk */
    virStorageSource *chain; /* Reference to the chain the job operates on. */
    virStorageSource *mirrorChain; /* reference to 'mirror' part of the job */

    unsigned int jobflags; /* per job flags */
    bool jobflagsmissing; /* job flags were not stored */

    union {
        qemuBlockJobPullData pull;
        qemuBlockJobCommitData commit;
        qemuBlockJobCreateData create;
        qemuBlockJobCopyData copy;
        qemuBlockJobBackupData backup;
    } data;

    int type; /* qemuBlockJobType */
    int state; /* qemuBlockjobState */
    char *errmsg;
    bool synchronous; /* API call is waiting for this job */

    int newstate; /* qemuBlockjobState, subset of events emitted by qemu */

    int brokentype; /* the previous type of a broken blockjob qemuBlockJobType */

    bool processPending; /* process the 'pending' state of the job, if the job
                            should not be auto-finalized */

    bool invalidData; /* the job data (except name) is not valid */
    bool reconnected; /* internal field for tracking whether job is live after reconnect to qemu */
};
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockJobData, virObjectUnref);

int
qemuBlockJobRegister(qemuBlockJobData *job,
                     virDomainObj *vm,
                     virDomainDiskDef *disk,
                     bool savestatus)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

qemuBlockJobData *
qemuBlockJobDataNew(qemuBlockJobType type,
                    const char *name)
    ATTRIBUTE_NONNULL(2);

qemuBlockJobData *
qemuBlockJobDiskNew(virDomainObj *vm,
                    virDomainDiskDef *disk,
                    qemuBlockJobType type,
                    const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

qemuBlockJobData *
qemuBlockJobDiskNewPull(virDomainObj *vm,
                        virDomainDiskDef *disk,
                        virStorageSource *base,
                        unsigned int jobflags);

qemuBlockJobData *
qemuBlockJobDiskNewCommit(virDomainObj *vm,
                          virDomainDiskDef *disk,
                          virStorageSource *topparent,
                          virStorageSource *top,
                          virStorageSource *base,
                          bool delete_imgs,
                          virTristateBool autofinalize,
                          unsigned int jobflags);

qemuBlockJobData *
qemuBlockJobNewCreate(virDomainObj *vm,
                      virStorageSource *src,
                      virStorageSource *chain,
                      bool storage);

qemuBlockJobData *
qemuBlockJobDiskNewCopy(virDomainObj *vm,
                        virDomainDiskDef *disk,
                        virStorageSource *mirror,
                        bool shallow,
                        bool reuse,
                        unsigned int jobflags);

qemuBlockJobData *
qemuBlockJobDiskNewBackup(virDomainObj *vm,
                          virDomainDiskDef *disk,
                          virStorageSource *store,
                          const char *bitmap);

qemuBlockJobData *
qemuBlockJobDiskGetJob(virDomainDiskDef *disk)
    ATTRIBUTE_NONNULL(1);

void
qemuBlockJobStarted(qemuBlockJobData *job,
                    virDomainObj *vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool
qemuBlockJobIsRunning(qemuBlockJobData *job)
    ATTRIBUTE_NONNULL(1);

void
qemuBlockJobStartupFinalize(virDomainObj *vm,
                            qemuBlockJobData *job);

int
qemuBlockJobRefreshJobs(virDomainObj *vm);

void
qemuBlockJobUpdate(virDomainObj *vm,
                   qemuBlockJobData *job,
                   int asyncJob);

void qemuBlockJobSyncBegin(qemuBlockJobData *job);
void qemuBlockJobSyncEnd(virDomainObj *vm,
                         qemuBlockJobData *job,
                         int asyncJob);

qemuBlockJobData *
qemuBlockJobGetByDisk(virDomainDiskDef *disk)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

qemuBlockjobState
qemuBlockjobConvertMonitorStatus(int monitorstatus);
