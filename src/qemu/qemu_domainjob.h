/*
 * qemu_domainjob.h: helper functions for QEMU domain jobs
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

#include <glib-object.h>
#include "qemu_monitor.h"
#include "virdomainjob.h"


typedef enum {
    QEMU_DOMAIN_JOB_STATS_TYPE_NONE = 0,
    QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION,
    QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP,
} qemuDomainJobStatsType;


typedef struct _qemuDomainMirrorStats qemuDomainMirrorStats;
struct _qemuDomainMirrorStats {
    unsigned long long transferred;
    unsigned long long total;
};

typedef struct _qemuDomainBackupStats qemuDomainBackupStats;
struct _qemuDomainBackupStats {
    unsigned long long transferred;
    unsigned long long total;
    unsigned long long tmp_used;
    unsigned long long tmp_total;
};

typedef struct _qemuDomainJobDataPrivate qemuDomainJobDataPrivate;
struct _qemuDomainJobDataPrivate {
    /* Raw values from QEMU */
    qemuDomainJobStatsType statsType;
    union {
        qemuMonitorMigrationStats mig;
        qemuMonitorDumpStats dump;
        qemuDomainBackupStats backup;
    } stats;
    qemuDomainMirrorStats mirrorStats;
};

void qemuDomainJobSetStatsType(virDomainJobData *jobData,
                               qemuDomainJobStatsType type);

const char *qemuDomainAsyncJobPhaseToString(virDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(virDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventEmitJobCompleted(virQEMUDriver *driver,
                                     virDomainObj *vm);

void qemuDomainObjAbortAsyncJob(virDomainObj *obj);
void qemuDomainObjSetJobPhase(virDomainObj *obj,
                              int phase);
void
qemuDomainObjStartJobPhase(virDomainObj *obj,
                           int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObj *obj,
                                  unsigned long long allowedJobs);
void
qemuDomainObjRestoreAsyncJob(virDomainObj *vm,
                             virDomainAsyncJob asyncJob,
                             int phase,
                             unsigned long long started,
                             virDomainJobOperation operation,
                             qemuDomainJobStatsType statsType,
                             virDomainJobStatus status,
                             unsigned long long allowedJobs);
void qemuDomainObjDiscardAsyncJob(virDomainObj *obj);
void qemuDomainObjReleaseAsyncJob(virDomainObj *obj);

int qemuDomainJobDataUpdateTime(virDomainJobData *jobData)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobDataUpdateDowntime(virDomainJobData *jobData)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobDataToInfo(virDomainJobData *jobData,
                            virDomainJobInfoPtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainJobDataToParams(virDomainJobData *jobData,
                              int *type,
                              virTypedParameterPtr *params,
                              int *nparams)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
qemuDomainObjPrivateXMLFormatJob(virBuffer *buf,
                                 virDomainObj *vm);

int
qemuDomainObjPrivateXMLParseJob(virDomainObj *vm,
                                xmlXPathContextPtr ctxt);
