/*
 * config.h: VM configuration management
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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
#include "iptables.h"
#include "bridge.h"
#include "capabilities.h"
#include "network_conf.h"
#include "domain_conf.h"

#define qemudDebug(fmt, ...) do {} while(0)

#define QEMUD_CPUMASK_LEN CPU_SETSIZE

/* Internal flags to keep track of qemu command line capabilities */
enum qemud_cmd_flags {
    QEMUD_CMD_FLAG_KQEMU          = (1 << 0),
    QEMUD_CMD_FLAG_VNC_COLON      = (1 << 1),
    QEMUD_CMD_FLAG_NO_REBOOT      = (1 << 2),
    QEMUD_CMD_FLAG_DRIVE          = (1 << 3),
    QEMUD_CMD_FLAG_DRIVE_BOOT     = (1 << 4),
    QEMUD_CMD_FLAG_NAME           = (1 << 5),
};

/* Main driver state */
struct qemud_driver {
    unsigned int qemuVersion;
    int nextvmid;

    virDomainObjPtr domains;
    virNetworkObjPtr networks;

    brControl *brctl;
    iptablesContext *iptables;
    char *configDir;
    char *autostartDir;
    char *networkConfigDir;
    char *networkAutostartDir;
    char *logDir;
    unsigned int vncTLS : 1;
    unsigned int vncTLSx509verify : 1;
    char *vncTLSx509certdir;
    char *vncListen;

    virCapsPtr caps;
};


void qemudReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,5,6);


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
                                         virDomainObjPtr dom,
                                         unsigned int qemuCmdFlags,
                                         const char ***argv,
                                         int **tapfds,
                                         int *ntapfds,
                                         const char *migrateFrom);

const char *qemudVirtTypeToString       (int type);

#endif /* __QEMUD_CONF_H */
