/*
 * qemu_agent.h: interaction with QEMU guest agent
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
#include "domain_conf.h"

typedef struct _qemuAgent qemuAgent;

typedef struct _qemuAgentCallbacks qemuAgentCallbacks;
struct _qemuAgentCallbacks {
    void (*eofNotify)(qemuAgent *mon,
                      virDomainObj *vm);
    void (*errorNotify)(qemuAgent *mon,
                        virDomainObj *vm);
};


qemuAgent *qemuAgentOpen(virDomainObj *vm,
                           const virDomainChrSourceDef *config,
                           GMainContext *context,
                           qemuAgentCallbacks *cb);

void qemuAgentClose(qemuAgent *mon);

void qemuAgentNotifyClose(qemuAgent *mon);

typedef enum {
    QEMU_AGENT_EVENT_NONE = 0,
    QEMU_AGENT_EVENT_SHUTDOWN,
    QEMU_AGENT_EVENT_SUSPEND,
    QEMU_AGENT_EVENT_RESET,
} qemuAgentEvent;

void qemuAgentNotifyEvent(qemuAgent *mon,
                          qemuAgentEvent event);

typedef enum {
    QEMU_AGENT_SHUTDOWN_POWERDOWN,
    QEMU_AGENT_SHUTDOWN_REBOOT,
    QEMU_AGENT_SHUTDOWN_HALT,

    QEMU_AGENT_SHUTDOWN_LAST,
} qemuAgentShutdownMode;

typedef struct _qemuAgentDiskAddress qemuAgentDiskAddress;
struct _qemuAgentDiskAddress {
    char *serial;
    virPCIDeviceAddress pci_controller;
    char *bus_type;
    unsigned int bus;
    unsigned int target;
    unsigned int unit;
    char *devnode;
    virCCWDeviceAddress *ccw_addr;
};
void qemuAgentDiskAddressFree(qemuAgentDiskAddress *addr);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuAgentDiskAddress, qemuAgentDiskAddressFree);

typedef struct _qemuAgentDiskInfo qemuAgentDiskInfo;
struct _qemuAgentDiskInfo {
    char *name;
    bool partition;
    char **dependencies;
    qemuAgentDiskAddress *address;
    char *alias;
};
void qemuAgentDiskInfoFree(qemuAgentDiskInfo *info);

typedef struct _qemuAgentFSInfo qemuAgentFSInfo;
struct _qemuAgentFSInfo {
    char *mountpoint; /* path to mount point */
    char *name;       /* device name in the guest (e.g. "sda1") */
    char *fstype;     /* filesystem type */
    long long total_bytes;
    long long used_bytes;
    size_t ndisks;
    qemuAgentDiskAddress **disks;
};
void qemuAgentFSInfoFree(qemuAgentFSInfo *info);

int qemuAgentShutdown(qemuAgent *mon,
                      qemuAgentShutdownMode mode);

int qemuAgentFSFreeze(qemuAgent *mon,
                      const char **mountpoints, unsigned int nmountpoints);
int qemuAgentFSThaw(qemuAgent *mon);
int qemuAgentGetFSInfo(qemuAgent *mon,
                       qemuAgentFSInfo ***info,
                       bool report_unsupported);

int qemuAgentSuspend(qemuAgent *mon,
                     unsigned int target);

int qemuAgentArbitraryCommand(qemuAgent *mon,
                              const char *cmd,
                              char **result,
                              int timeout);
int qemuAgentFSTrim(qemuAgent *mon,
                    unsigned long long minimum);


typedef struct _qemuAgentCPUInfo qemuAgentCPUInfo;
struct _qemuAgentCPUInfo {
    unsigned int id;    /* logical cpu ID */
    bool online;        /* true if the CPU is activated */
    bool offlinable;    /* true if the CPU can be offlined */

    bool modified; /* set to true if the vcpu state needs to be changed */
};

int qemuAgentGetVCPUs(qemuAgent *mon, qemuAgentCPUInfo **info);
int qemuAgentSetVCPUs(qemuAgent *mon, qemuAgentCPUInfo *cpus, size_t ncpus);
int qemuAgentUpdateCPUInfo(unsigned int nvcpus,
                           qemuAgentCPUInfo *cpuinfo,
                           int ncpuinfo);

int
qemuAgentGetHostname(qemuAgent *mon,
                     char **hostname,
                     bool report_unsupported);

int qemuAgentGetTime(qemuAgent *mon,
                     long long *seconds,
                     unsigned int *nseconds);
int qemuAgentSetTime(qemuAgent *mon,
                     long long seconds,
                     unsigned int nseconds,
                     bool sync);

int qemuAgentGetInterfaces(qemuAgent *mon,
                           virDomainInterfacePtr **ifaces,
                           bool report_unsupported);

int qemuAgentSetUserPassword(qemuAgent *mon,
                             const char *user,
                             const char *password,
                             bool crypted);

int qemuAgentGetUsers(qemuAgent *mon,
                      virTypedParameterPtr *params,
                      int *nparams,
                      int *maxparams,
                      bool report_unsupported);

int qemuAgentGetOSInfo(qemuAgent *mon,
                       virTypedParameterPtr *params,
                       int *nparams,
                       int *maxparams,
                       bool report_unsupported);

int qemuAgentGetTimezone(qemuAgent *mon,
                         virTypedParameterPtr *params,
                         int *nparams,
                         int *maxparams,
                         bool report_unsupported);

void qemuAgentSetResponseTimeout(qemuAgent *mon,
                                 int timeout);

int qemuAgentSSHGetAuthorizedKeys(qemuAgent *agent,
                                  const char *user,
                                  char ***keys);

int qemuAgentSSHAddAuthorizedKeys(qemuAgent *agent,
                                  const char *user,
                                  const char **keys,
                                  size_t nkeys,
                                  bool reset);

int qemuAgentSSHRemoveAuthorizedKeys(qemuAgent *agent,
                                     const char *user,
                                     const char **keys,
                                     size_t nkeys);

int qemuAgentGetDisks(qemuAgent *mon,
                      qemuAgentDiskInfo ***disks,
                      bool report_unsupported);
