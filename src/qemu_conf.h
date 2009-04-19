/*
 * config.h: VM configuration management
 *
 * Copyright (C) 2006, 2007, 2009 Red Hat, Inc.
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

#ifndef __QEMUD_CONF_H
#define __QEMUD_CONF_H

#include <config.h>

#include "internal.h"
#include "bridge.h"
#include "capabilities.h"
#include "network_conf.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "threads.h"
#include "security.h"

#define qemudDebug(fmt, ...) do {} while(0)

#define QEMUD_CPUMASK_LEN CPU_SETSIZE

/* Internal flags to keep track of qemu command line capabilities */
enum qemud_cmd_flags {
    QEMUD_CMD_FLAG_KQEMU          = (1 << 0), /* Whether KQEMU is compiled in */
    QEMUD_CMD_FLAG_VNC_COLON      = (1 << 1), /* Does the VNC take just port, or address + display */
    QEMUD_CMD_FLAG_NO_REBOOT      = (1 << 2), /* Is the -no-reboot flag available */
    QEMUD_CMD_FLAG_DRIVE          = (1 << 3), /* Is the new -drive arg available */
    QEMUD_CMD_FLAG_DRIVE_BOOT     = (1 << 4), /* Does -drive support boot=on */
    QEMUD_CMD_FLAG_NAME           = (1 << 5), /* Is the -name flag available */
    QEMUD_CMD_FLAG_UUID           = (1 << 6), /* Is the -uuid flag available */
    QEMUD_CMD_FLAG_DOMID          = (1 << 7), /* Xenner only, special -domid flag available */
    QEMUD_CMD_FLAG_VNET_HDR        = (1 << 8),
    QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO = (1 << 9),  /* Original migration code from KVM. Also had tcp, but we can't use that
                                                   * since it had a design bug blocking the entire monitor console */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP  = (1 << 10), /* New migration syntax after merge to QEMU with TCP transport */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC = (1 << 11), /* New migration syntax after merge to QEMU with EXEC transport */
    QEMUD_CMD_FLAG_DRIVE_CACHE_V2    = (1 << 12), /* Is the cache= flag wanting new v2 values */
    QEMUD_CMD_FLAG_KVM               = (1 << 13), /* Whether KVM is compiled in */
};

/* Main driver state */
struct qemud_driver {
    virMutex lock;

    unsigned int qemuVersion;
    int nextvmid;

    virDomainObjList domains;

    brControl *brctl;
    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    unsigned int vncTLS : 1;
    unsigned int vncTLSx509verify : 1;
    unsigned int vncSASL : 1;
    char *vncTLSx509certdir;
    char *vncListen;
    char *vncPassword;
    char *vncSASLdir;

    virCapsPtr caps;

    /* An array of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;
    virDomainEventQueuePtr domainEventQueue;
    int domainEventTimer;
    int domainEventDispatching;

    char *securityDriverName;
    virSecurityDriverPtr securityDriver;
};

/* Status needed to reconenct to running VMs */
typedef struct _qemudDomainStatus qemudDomainStatus;
typedef qemudDomainStatus *qemudDomainStatusPtr;
struct _qemudDomainStatus {
    char *monitorpath;
    pid_t pid;
    int state;
    virDomainDefPtr def;
};

/* Port numbers used for KVM migration. */
#define QEMUD_MIGRATION_FIRST_PORT 49152
#define QEMUD_MIGRATION_NUM_PORTS 64

#define qemudReportError(conn, dom, net, code, fmt...)                       \
        virReportErrorHelper(conn, VIR_FROM_QEMU, code, __FILE__,          \
                               __FUNCTION__, __LINE__, fmt)


int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename);

virCapsPtr  qemudCapsInit               (void);

int         qemudExtractVersion         (virConnectPtr conn,
                                         struct qemud_driver *driver);
int         qemudExtractVersionInfo     (const char *qemu,
                                         unsigned int *version,
                                         unsigned int *flags);

int         qemudBuildCommandLine       (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         virDomainDefPtr def,
                                         unsigned int qemuCmdFlags,
                                         const char ***retargv,
                                         const char ***retenv,
                                         int **tapfds,
                                         int *ntapfds,
                                         const char *migrateFrom);

const char *qemudVirtTypeToString       (int type);
qemudDomainStatusPtr qemudDomainStatusParseFile(virConnectPtr conn,
                                                virCapsPtr caps,
                                                const char *filename,
                                                int flags);
int qemudSaveDomainStatus(virConnectPtr conn,
                          struct qemud_driver *driver,
                          virDomainObjPtr vm);

#endif /* __QEMUD_CONF_H */
