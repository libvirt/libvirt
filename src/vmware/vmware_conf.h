/*---------------------------------------------------------------------------*/
/*
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright 2010, diateam (www.diateam.net)
 * Copyright (c) 2013, Doug Goldstein (cardoe@cardoe.com)
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
/*---------------------------------------------------------------------------*/

#ifndef VMWARE_CONF_H
# define VMWARE_CONF_H

# define NOGUI "nogui"

# include "internal.h"
# include "domain_conf.h"
# include "virthread.h"

# define VIR_FROM_THIS VIR_FROM_VMWARE
# define PROGRAM_SENTINEL ((char *)0x1)

enum vmwareDriverType {
    VMWARE_DRIVER_PLAYER      = 0, /* VMware Player */
    VMWARE_DRIVER_WORKSTATION = 1, /* VMware Workstation */
    VMWARE_DRIVER_FUSION      = 2, /* VMware Fusion */

    VMWARE_DRIVER_LAST,            /* required last item */
};

VIR_ENUM_DECL(vmwareDriver)

struct vmware_driver {
    virMutex lock;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;

    virDomainObjListPtr domains;
    int version;
    int type;
    char *vmrun;
};

typedef struct _vmwareDomain {
    char *vmxPath;
    bool gui;

} vmwareDomain, *vmwareDomainPtr;

void vmwareFreeDriver(struct vmware_driver *driver);

virCapsPtr vmwareCapsInit(void);

int vmwareLoadDomains(struct vmware_driver *driver);

void vmwareSetSentinal(const char **prog, const char *key);

int vmwareExtractVersion(struct vmware_driver *driver);

int vmwareParseVersionStr(int type, const char *buf, unsigned long *version);

int vmwareDomainConfigDisplay(vmwareDomainPtr domain, virDomainDefPtr vmdef);

int vmwareConstructVmxPath(char *directoryName, char *name,
                           char **vmxPath);

int vmwareVmxPath(virDomainDefPtr vmdef, char **vmxPath);

int vmwareMoveFile(char *srcFile, char *dstFile);

int vmwareMakePath(char *srcDir, char *srcName, char *srcExt,
                   char **outpath);

int vmwareExtractPid(const char * vmxPath);

char *vmwareCopyVMXFileName(const char *datastorePath, void *opaque);

#endif
