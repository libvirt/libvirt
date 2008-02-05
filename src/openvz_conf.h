/*
 * openvz_config.h: config information for OpenVZ VPSs
 *
 * Copyright (C) 2006, 2007 Binary Karma.
 * Copyright (C) 2006 Shuveb Hussain
 * Copyright (C) 2007 Anoop Joe Cyriac
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
 * Authors:
 * Shuveb Hussain <shuveb@binarykarma.com>
 * Anoop Joe Cyriac <anoop@binarykarma.com>
 *
 */

#ifndef OPENVZ_CONF_H
#define OPENVZ_CONF_H

#include "openvz_driver.h"

enum { OPENVZ_WARN, OPENVZ_ERR };

#define OPENVZ_NAME_MAX 8
#define OPENVZ_TMPL_MAX 256
#define OPENVZ_UNAME_MAX    32
#define OPENVZ_IP_MAX   16
#define OPENVZ_HOSTNAME_MAX 256
#define OPENVZ_PROFILE_MAX  256
#define OPENVZ_MAX_ERROR_LEN	 1024
#define OPENVZ_MAX_XML_LEN	 4096
#define OPENVZ_MAX_QUOTA	 8
#define OPENVZ_MAX_XPathEval_LEN 256
#define OPENVZ_RSRV_VM_LIMIT 100

enum openvz_quota{
    VM_LEVEL = 0,
    USER_LEVEL = 1,
};

/* TODO Add more properties here */
struct vps_props {
   int kmemsize;    /* currently held */
   int kmemsize_m;  /* max held */
   int kmemsize_b;  /* barrier */
   int kmemsize_l;  /* limit */
   int kmemsize_f;  /* fail count */

};

struct openvz_fs_def {
    char tmpl[OPENVZ_TMPL_MAX];
    struct ovz_quota *quota;
};

struct ovz_ip {
    char ip[OPENVZ_IP_MAX];
    char netmask[OPENVZ_IP_MAX];
    struct ovz_ip *next;
};

struct ovz_ns {
    char ip[OPENVZ_IP_MAX];
    struct ovz_ns *next;
};

struct openvz_net_def {
    char hostname[OPENVZ_HOSTNAME_MAX];
    char def_gw[OPENVZ_IP_MAX];
    struct ovz_ip *ips;
    struct ovz_ns *ns;
};

struct openvz_vm_def {
    char name[OPENVZ_NAME_MAX];
    unsigned char uuid[VIR_UUID_BUFLEN];
    char profile[OPENVZ_PROFILE_MAX];
    struct openvz_fs_def fs;
    struct openvz_net_def net;
};

struct ovz_quota {
    enum openvz_quota type;
    unsigned int size;
    char uname[OPENVZ_UNAME_MAX];
    struct ovz_quota *next;
};

struct openvz_vm {
    int vpsid;
    int status;
    struct openvz_vm_def *vmdef;
    struct openvz_vm *next;
};

static inline int
openvzIsActiveVM(struct openvz_vm *vm)
{
    return vm->vpsid != -1;
}

int openvz_readline(int fd, char *ptr, int maxlen);
struct openvz_vm *openvzFindVMByID(const struct openvz_driver *driver, int id);
struct openvz_vm *openvzFindVMByUUID(const struct openvz_driver *driver,
                                            const unsigned char *uuid);

struct openvz_vm *openvzFindVMByName(const struct openvz_driver *driver, const char *name);
struct openvz_vm_def *openvzParseVMDef(virConnectPtr conn, const char *xmlStr,
                                            const char *displayName);

struct openvz_vm *openvzAssignVMDef(virConnectPtr conn, struct openvz_driver *driver,
                                    struct openvz_vm_def *def);

struct openvz_vm *openvzGetVPSInfo(virConnectPtr conn);
void openvzGenerateUUID(unsigned char *uuid);
int openvzAssignUUIDs(void);
void openvzRemoveInactiveVM(struct openvz_driver *driver, struct openvz_vm *vm);
void openvzFreeDriver(struct openvz_driver *driver);
void openvzFreeVM(struct openvz_driver *driver, struct openvz_vm *vm, int checkCallee);
void openvzFreeVMDef(struct openvz_vm_def *def);
int strtoI(const char *str);
#endif /* OPENVZ_CONF_H */
