/*
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.h: header file for linux container config functions
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef LXC_CONF_H
#define LXC_CONF_H

#include <config.h>

#ifdef WITH_LXC

#include "internal.h"

/* Defines */
#define LXC_MAX_TTY_NAME 32
#define LXC_MAX_XML_LENGTH 16384
#define LXC_MAX_ERROR_LEN 1024
#define LXC_DOMAIN_TYPE "lxc"

typedef struct __lxc_mount lxc_mount_t;
struct __lxc_mount {
    char source[PATH_MAX]; /* user's directory */
    char target[PATH_MAX];

    lxc_mount_t *next;
};

typedef struct __lxc_vm_def lxc_vm_def_t;
struct __lxc_vm_def {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char* name;
    int id;

    /* init command string */
    char *init;

    int maxMemory;

    /* mounts - list of mount structs */
    int nmounts;
    lxc_mount_t *mounts;

    /* tty device */
    char *tty;
};

typedef struct __lxc_vm lxc_vm_t;
struct __lxc_vm {
    int pid;
    int state;

    char configFile[PATH_MAX];
    char configFileBase[PATH_MAX];

    int parentTty;

    lxc_vm_def_t *def;

    lxc_vm_t *next;
};

typedef struct __lxc_driver lxc_driver_t;
struct __lxc_driver {
    lxc_vm_t *vms;
    int nactivevms;
    int ninactivevms;
    char* configDir;
};

/* Types and structs */

/* Inline Functions */
static inline int lxcIsActiveVM(lxc_vm_t *vm)
{
    return vm->def->id != -1;
}

/* Function declarations */
lxc_vm_def_t * lxcParseVMDef(virConnectPtr conn,
                             const char* xmlString,
                             const char* fileName);
int lxcSaveVMDef(virConnectPtr conn,
                 lxc_driver_t *driver,
                 lxc_vm_t *vm,
                 lxc_vm_def_t *def);
int lxcLoadDriverConfig(lxc_driver_t *driver);
int lxcSaveConfig(virConnectPtr conn,
                  lxc_driver_t *driver,
                  lxc_vm_t *vm,
                  lxc_vm_def_t *def);
int lxcLoadContainerInfo(lxc_driver_t *driver);
int lxcLoadContainerConfigFile(lxc_driver_t *driver,
                               const char *file);
lxc_vm_t * lxcAssignVMDef(virConnectPtr conn,
                          lxc_driver_t *driver,
                          lxc_vm_def_t *def);
char *lxcGenerateXML(virConnectPtr conn,
                     lxc_driver_t *driver,
                     lxc_vm_t *vm,
                     lxc_vm_def_t *def);
lxc_vm_t *lxcFindVMByID(const lxc_driver_t *driver, int id);
lxc_vm_t *lxcFindVMByUUID(const lxc_driver_t *driver,
                          const unsigned char *uuid);
lxc_vm_t *lxcFindVMByName(const lxc_driver_t *driver,
                          const char *name);
void lxcRemoveInactiveVM(lxc_driver_t *driver,
                         lxc_vm_t *vm);
void lxcFreeVMs(lxc_vm_t *vms);
void lxcFreeVM(lxc_vm_t *vm);
void lxcFreeVMDef(lxc_vm_def_t *vmdef);
int lxcDeleteConfig(virConnectPtr conn,
                    lxc_driver_t *driver,
                    const char *configFile,
                    const char *name);

void lxcError(virConnectPtr conn,
              virDomainPtr dom,
              int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,4,5);

#endif /* WITH_LXC */
#endif /* LXC_CONF_H */

