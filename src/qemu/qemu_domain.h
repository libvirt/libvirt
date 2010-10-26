/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#ifndef __QEMU_DOMAIN_H__
# define __QEMU_DOMAIN_H__

# include "threads.h"
# include "domain_conf.h"
# include "qemu_monitor.h"
# include "qemu_conf.h"
# include "bitmap.h"

/* Only 1 job is allowed at any time
 * A job includes *all* monitor commands, even those just querying
 * information, not merely actions */
enum qemuDomainJob {
    QEMU_JOB_NONE = 0,  /* Always set to 0 for easy if (jobActive) conditions */
    QEMU_JOB_UNSPECIFIED,
    QEMU_JOB_MIGRATION_OUT,
    QEMU_JOB_MIGRATION_IN,
    QEMU_JOB_SAVE,
    QEMU_JOB_DUMP,
};

enum qemuDomainJobSignals {
    QEMU_JOB_SIGNAL_CANCEL  = 1 << 0, /* Request job cancellation */
    QEMU_JOB_SIGNAL_SUSPEND = 1 << 1, /* Request VM suspend to finish live migration offline */
    QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME = 1 << 2, /* Request migration downtime change */
    QEMU_JOB_SIGNAL_MIGRATE_SPEED = 1 << 3, /* Request migration speed change */
    QEMU_JOB_SIGNAL_BLKSTAT = 1 << 4, /* Request blkstat during migration */
    QEMU_JOB_SIGNAL_BLKINFO = 1 << 5, /* Request blkinfo during migration */
};

struct qemuDomainJobSignalsData {
    unsigned long long migrateDowntime; /* Data for QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME */
    unsigned long migrateBandwidth; /* Data for QEMU_JOB_SIGNAL_MIGRATE_SPEED */
    char *statDevName; /* Device name used by blkstat calls */
    virDomainBlockStatsPtr blockStat; /* Block statistics for QEMU_JOB_SIGNAL_BLKSTAT */
    int *statRetCode; /* Return code for the blkstat calls */
    char *infoDevName; /* Device name used by blkinfo calls */
    virDomainBlockInfoPtr blockInfo; /* Block information for QEMU_JOB_SIGNAL_BLKINFO */
    int *infoRetCode; /* Return code for the blkinfo calls */
};

typedef struct _qemuDomainPCIAddressSet qemuDomainPCIAddressSet;
typedef qemuDomainPCIAddressSet *qemuDomainPCIAddressSetPtr;

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    virCond jobCond; /* Use in conjunction with main virDomainObjPtr lock */
    virCond signalCond; /* Use to coordinate the safe queries during migration */
    enum qemuDomainJob jobActive;   /* Currently running job */
    unsigned int jobSignals;        /* Signals for running job */
    struct qemuDomainJobSignalsData jobSignalsData; /* Signal specific data */
    virDomainJobInfo jobInfo;
    unsigned long long jobStart;

    qemuMonitorPtr mon;
    virDomainChrSourceDefPtr monConfig;
    int monJSON;
    bool gotShutdown;

    int nvcpupids;
    int *vcpupids;

    qemuDomainPCIAddressSetPtr pciaddrs;
    int persistentAddrs;

    virBitmapPtr qemuCaps;
    char *lockState;
};

struct qemuDomainWatchdogEvent
{
    virDomainObjPtr vm;
    int action;
};

void qemuDomainEventFlush(int timer ATTRIBUTE_UNUSED, void *opaque);

/* driver must be locked before calling */
void qemuDomainEventQueue(struct qemud_driver *driver,
                          virDomainEventPtr event);

void qemuDomainSetPrivateDataHooks(virCapsPtr caps);
void qemuDomainSetNamespaceHooks(virCapsPtr caps);

int qemuDomainObjBeginJob(virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                    virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjEndJob(virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;
void qemuDomainObjEnterMonitor(virDomainObjPtr obj);
void qemuDomainObjExitMonitor(virDomainObjPtr obj);
void qemuDomainObjEnterMonitorWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj);
void qemuDomainObjExitMonitorWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj);
void qemuDomainObjEnterRemoteWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj);
void qemuDomainObjExitRemoteWithDriver(struct qemud_driver *driver,
                                       virDomainObjPtr obj);

char *qemuDomainDefFormatXML(struct qemud_driver *driver,
                             virDomainDefPtr vm,
                             int flags);

char *qemuDomainFormatXML(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          int flags);

void qemuDomainObjTaint(struct qemud_driver *driver,
                        virDomainObjPtr obj,
                        enum virDomainTaintFlags taint,
                        int logFD);

void qemuDomainObjCheckTaint(struct qemud_driver *driver,
                             virDomainObjPtr obj,
                             int logFD);
void qemuDomainObjCheckDiskTaint(struct qemud_driver *driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 int logFD);
void qemuDomainObjCheckNetTaint(struct qemud_driver *driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                int logFD);


int qemuDomainCreateLog(struct qemud_driver *driver, virDomainObjPtr vm, bool append);
int qemuDomainOpenLog(struct qemud_driver *driver, virDomainObjPtr vm, off_t pos);
int qemuDomainAppendLog(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        int logFD,
                        const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(4, 5);

#endif /* __QEMU_DOMAIN_H__ */
