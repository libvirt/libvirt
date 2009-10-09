/*
 * qemu_monitor.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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


#ifndef QEMU_MONITOR_H
#define QEMU_MONITOR_H

#include "internal.h"

#include "domain_conf.h"

typedef struct _qemuMonitor qemuMonitor;
typedef qemuMonitor *qemuMonitorPtr;

typedef void (*qemuMonitorEOFNotify)(qemuMonitorPtr mon,
                                     virDomainObjPtr vm,
                                     int withError);

/* XXX we'd really like to avoid virCOnnectPtr here
 * It is required so the callback can find the active
 * secret driver. Need to change this to work like the
 * security drivers do, to avoid this
 */
typedef int (*qemuMonitorDiskSecretLookup)(qemuMonitorPtr mon,
                                           virConnectPtr conn,
                                           virDomainObjPtr vm,
                                           const char *path,
                                           char **secret,
                                           size_t *secretLen);

qemuMonitorPtr qemuMonitorOpen(virDomainObjPtr vm,
                               int reconnect,
                               qemuMonitorEOFNotify eofCB);

void qemuMonitorClose(qemuMonitorPtr mon);

void qemuMonitorRegisterDiskSecretLookup(qemuMonitorPtr mon,
                                         qemuMonitorDiskSecretLookup secretCB);

int qemuMonitorWrite(qemuMonitorPtr mon,
                     const char *data,
                     size_t len);

int qemuMonitorWriteWithFD(qemuMonitorPtr mon,
                           const char *data,
                           size_t len,
                           int fd);

int qemuMonitorRead(qemuMonitorPtr mon,
                    char *data,
                    size_t len);

int qemuMonitorWaitForInput(qemuMonitorPtr mon);

int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                             virConnectPtr conn,
                             const char *path,
                             char **secret,
                             size_t *secretLen);

#endif /* QEMU_MONITOR_H */
