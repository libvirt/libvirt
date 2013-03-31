/*---------------------------------------------------------------------------*/
/* Copyright 2010, diateam (www.diateam.net)
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

# define VMRUN "vmrun"
# define NOGUI "nogui"

# include "internal.h"
# include "domain_conf.h"
# include "virthread.h"

# define VIR_FROM_THIS VIR_FROM_VMWARE
# define PROGRAM_SENTINAL ((char *)0x1)

# define TYPE_PLAYER        0
# define TYPE_WORKSTATION   1

struct vmware_driver {
    virMutex lock;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;

    virDomainObjListPtr domains;
    int version;
    int type;
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

int vmwareDomainConfigDisplay(vmwareDomainPtr domain, virDomainDefPtr vmdef);

int vmwareParsePath(char *path, char **directory, char **filename);

int vmwareConstructVmxPath(char *directoryName, char *name,
                           char **vmxPath);

int vmwareVmxPath(virDomainDefPtr vmdef, char **vmxPath);

int vmwareMoveFile(char *srcFile, char *dstFile);

int vmwareMakePath(char *srcDir, char *srcName, char *srcExt,
                   char **outpath);

int vmwareExtractPid(const char * vmxPath);

char *vmwareCopyVMXFileName(const char *datastorePath, void *opaque);

#endif
