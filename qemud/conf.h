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

#include "internal.h"

int         qemudExtractVersion         (struct qemud_server *server);
int         qemudBuildCommandLine       (struct qemud_server *server,
                                         struct qemud_vm *vm,
                                         char ***argv);

int         qemudScanConfigs            (struct qemud_server *server);
int         qemudDeleteConfig           (struct qemud_server *server,
                                         const char *configFile,
                                         const char *name);
int         qemudEnsureDir              (const char *path);

void        qemudFreeVMDef              (struct qemud_vm_def *vm);
void        qemudFreeVM                 (struct qemud_vm *vm);

struct qemud_vm *
            qemudAssignVMDef            (struct qemud_server *server,
                                         struct qemud_vm_def *def);
void        qemudRemoveInactiveVM       (struct qemud_server *server,
                                         struct qemud_vm *vm);

struct qemud_vm_def *
            qemudParseVMDef             (struct qemud_server *server,
                                         const char *xmlStr,
                                         const char *displayName);
int         qemudSaveVMDef              (struct qemud_server *server,
                                         struct qemud_vm *vm,
                                         struct qemud_vm_def *def);
char *      qemudGenerateXML            (struct qemud_server *server,
                                         struct qemud_vm *vm,
                                         struct qemud_vm_def *def,
                                         int live);

void        qemudFreeNetworkDef         (struct qemud_network_def *def);
void        qemudFreeNetwork            (struct qemud_network *network);

struct qemud_network *
            qemudAssignNetworkDef       (struct qemud_server *server,
                                         struct qemud_network_def *def);
void        qemudRemoveInactiveNetwork  (struct qemud_server *server,
                                         struct qemud_network *network);

struct qemud_network_def *
            qemudParseNetworkDef        (struct qemud_server *server,
                                         const char *xmlStr,
                                         const char *displayName);
int         qemudSaveNetworkDef         (struct qemud_server *server,
                                         struct qemud_network *network,
                                         struct qemud_network_def *def);
char *      qemudGenerateNetworkXML     (struct qemud_server *server,
                                         struct qemud_network *network,
                                         struct qemud_network_def *def);

struct qemu_arch_info {
    const char *arch;
    int wordsize;
    const char **machines;
    const char *binary;
};
extern struct qemu_arch_info qemudArchs[];

#endif

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
