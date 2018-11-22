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

#ifndef LIBVIRT_QEMU_BLOCKJOB_H
# define LIBVIRT_QEMU_BLOCKJOB_H

# include "internal.h"
# include "qemu_conf.h"


typedef struct _qemuBlockJobData qemuBlockJobData;
typedef qemuBlockJobData *qemuBlockJobDataPtr;

struct _qemuBlockJobData {
    virObject parent;

    bool started;
    int type;
    char *errmsg;
    bool synchronous; /* API call is waiting for this job */

    int newstate; /* virConnectDomainEventBlockJobStatus - new state to be processed */
};

qemuBlockJobDataPtr qemuBlockJobDataNew(void);

int qemuBlockJobUpdateDisk(virDomainObjPtr vm,
                           int asyncJob,
                           virDomainDiskDefPtr disk,
                           char **error);

void qemuBlockJobSyncBeginDisk(virDomainDiskDefPtr disk);
void qemuBlockJobSyncEndDisk(virDomainObjPtr vm,
                             int asyncJob,
                             virDomainDiskDefPtr disk);

#endif /* LIBVIRT_QEMU_BLOCKJOB_H */
