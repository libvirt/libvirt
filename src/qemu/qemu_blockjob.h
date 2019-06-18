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
    QEMU_BLOCKJOB_STATE_LAST
} qemuBlockjobState;
verify((int)QEMU_BLOCKJOB_STATE_NEW == VIR_DOMAIN_BLOCK_JOB_LAST);

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
    /* Additional enum values local to qemu */
    QEMU_BLOCKJOB_TYPE_INTERNAL,
    QEMU_BLOCKJOB_TYPE_LAST
} qemuBlockJobType;
verify((int)QEMU_BLOCKJOB_TYPE_INTERNAL == VIR_DOMAIN_BLOCK_JOB_TYPE_LAST);

typedef struct _qemuBlockJobData qemuBlockJobData;
typedef qemuBlockJobData *qemuBlockJobDataPtr;

struct _qemuBlockJobData {
    virObject parent;

    char *name;

    virDomainDiskDefPtr disk; /* may be NULL, if blockjob does not correspond to any disk */

    int type; /* qemuBlockJobType */
    int state; /* qemuBlockjobState */
    char *errmsg;
    bool synchronous; /* API call is waiting for this job */

    int newstate; /* qemuBlockjobState, subset of events emitted by qemu */
};


qemuBlockJobDataPtr
qemuBlockJobDiskNew(virDomainDiskDefPtr disk,
                    qemuBlockJobType type,
                    const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

qemuBlockJobDataPtr
qemuBlockJobDiskGetJob(virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1);

void
qemuBlockJobStarted(qemuBlockJobDataPtr job)
    ATTRIBUTE_NONNULL(1);

bool
qemuBlockJobIsRunning(qemuBlockJobDataPtr job)
    ATTRIBUTE_NONNULL(1);

void
qemuBlockJobStartupFinalize(qemuBlockJobDataPtr job);

int qemuBlockJobUpdate(virDomainObjPtr vm,
                       qemuBlockJobDataPtr job,
                       int asyncJob);

void qemuBlockJobSyncBegin(qemuBlockJobDataPtr job);
void qemuBlockJobSyncEnd(virDomainObjPtr vm,
                         qemuBlockJobDataPtr job,
                         int asyncJob);

qemuBlockJobDataPtr
qemuBlockJobGetByDisk(virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
