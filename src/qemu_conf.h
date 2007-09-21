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
#include "bridge.h"
#include "iptables.h"
#include <netinet/in.h>

#define qemudDebug(fmt, ...) do {} while(0)

/* Different types of QEMU acceleration possible */
enum qemud_vm_virt_type {
    QEMUD_VIRT_QEMU,
    QEMUD_VIRT_KQEMU,
    QEMUD_VIRT_KVM,
};

/* Two types of disk backends */
enum qemud_vm_disk_type {
    QEMUD_DISK_BLOCK,
    QEMUD_DISK_FILE
};

/* Three types of disk frontend */
enum qemud_vm_disk_device {
    QEMUD_DISK_DISK,
    QEMUD_DISK_CDROM,
    QEMUD_DISK_FLOPPY,
};

/* Stores the virtual disk configuration */
struct qemud_vm_disk_def {
    int type;
    int device;
    char src[PATH_MAX];
    char dst[NAME_MAX];
    int readonly;

    struct qemud_vm_disk_def *next;
};

#define QEMUD_MAC_ADDRESS_LEN 6
#define QEMUD_OS_TYPE_MAX_LEN 10
#define QEMUD_OS_ARCH_MAX_LEN 10
#define QEMUD_OS_MACHINE_MAX_LEN 10

/* 5 different types of networking config */
enum qemud_vm_net_type {
    QEMUD_NET_USER,
    QEMUD_NET_ETHERNET,
    QEMUD_NET_SERVER,
    QEMUD_NET_CLIENT,
    QEMUD_NET_MCAST,
    QEMUD_NET_NETWORK,
    QEMUD_NET_BRIDGE,
};

#define QEMUD_MAX_NAME_LEN 50
#define QEMUD_MAX_XML_LEN 4096
#define QEMUD_MAX_ERROR_LEN 1024

/* Stores the virtual network interface configuration */
struct qemud_vm_net_def {
    int type;
    unsigned char mac[QEMUD_MAC_ADDRESS_LEN];
    union {
        struct {
            char ifname[BR_IFNAME_MAXLEN];
            char script[PATH_MAX];
        } ethernet;
        struct {
            char address[BR_INET_ADDR_MAXLEN];
            int port;
        } socket; /* any of NET_CLIENT or NET_SERVER or NET_MCAST */
        struct {
            char name[QEMUD_MAX_NAME_LEN];
            char ifname[BR_IFNAME_MAXLEN];
        } network;
        struct {
            char brname[BR_IFNAME_MAXLEN];
            char ifname[BR_IFNAME_MAXLEN];
        } bridge;
    } dst;

    struct qemud_vm_net_def *next;
};


enum qemu_vm_input_type {
    QEMU_INPUT_TYPE_MOUSE,
    QEMU_INPUT_TYPE_TABLET,
};

enum qemu_vm_input_bus {
    QEMU_INPUT_BUS_PS2,
    QEMU_INPUT_BUS_USB,
};

struct qemud_vm_input_def {
    int type;
    int bus;
    struct qemud_vm_input_def *next;
};

#define QEMUD_MAX_BOOT_DEVS 4

/* 3 possible boot devices */
enum qemud_vm_boot_order {
    QEMUD_BOOT_FLOPPY,
    QEMUD_BOOT_CDROM,
    QEMUD_BOOT_DISK,
    QEMUD_BOOT_NET,
};
/* 3 possible graphics console modes */
enum qemud_vm_graphics_type {
    QEMUD_GRAPHICS_NONE,
    QEMUD_GRAPHICS_SDL,
    QEMUD_GRAPHICS_VNC,
};

/* Internal flags to keep track of qemu command line capabilities */
enum qemud_cmd_flags {
    QEMUD_CMD_FLAG_KQEMU = 1,
    QEMUD_CMD_FLAG_VNC_COLON = 2,
    QEMUD_CMD_FLAG_NO_REBOOT = 4,
};


enum qemud_vm_features {
    QEMUD_FEATURE_ACPI = 1,
};

/* Operating system configuration data & machine / arch */
struct qemud_vm_os_def {
    char type[QEMUD_OS_TYPE_MAX_LEN];
    char arch[QEMUD_OS_ARCH_MAX_LEN];
    char machine[QEMUD_OS_MACHINE_MAX_LEN];
    int nBootDevs;
    int bootDevs[QEMUD_MAX_BOOT_DEVS];
    char kernel[PATH_MAX];
    char initrd[PATH_MAX];
    char cmdline[PATH_MAX];
    char binary[PATH_MAX];
};

/* Guest VM main configuration */
struct qemud_vm_def {
    int virtType;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char name[QEMUD_MAX_NAME_LEN];

    int memory;
    int maxmem;
    int vcpus;

    int noReboot;

    struct qemud_vm_os_def os;

    int localtime;
    int features;
    int graphicsType;
    int vncPort;
    int vncActivePort;
    char vncListen[BR_INET_ADDR_MAXLEN];

    int ndisks;
    struct qemud_vm_disk_def *disks;

    int nnets;
    struct qemud_vm_net_def *nets;

    int ninputs;
    struct qemud_vm_input_def *inputs;
};

/* Guest VM runtime state */
struct qemud_vm {
    int stdin;
    int stdout;
    int stderr;
    int monitor;
    int logfile;
    int pid;
    int id;
    int state;

    int *tapfds;
    int ntapfds;

    int qemuVersion;
    int qemuCmdFlags; /* values from enum qemud_cmd_flags */

    char configFile[PATH_MAX];
    char autostartLink[PATH_MAX];
    char migrateFrom[PATH_MAX];

    struct qemud_vm_def *def; /* The current definition */
    struct qemud_vm_def *newDef; /* New definition to activate at shutdown */

    unsigned int autostart : 1;

    struct qemud_vm *next;
};

/* Store start and end addresses of a dhcp range */
struct qemud_dhcp_range_def {
    char start[BR_INET_ADDR_MAXLEN];
    char end[BR_INET_ADDR_MAXLEN];

    struct qemud_dhcp_range_def *next;
};

/* Virtual Network main configuration */
struct qemud_network_def {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char name[QEMUD_MAX_NAME_LEN];

    char bridge[BR_IFNAME_MAXLEN];
    int disableSTP;
    int forwardDelay;

    int forward;
    char forwardDev[BR_IFNAME_MAXLEN];

    char ipAddress[BR_INET_ADDR_MAXLEN];
    char netmask[BR_INET_ADDR_MAXLEN];
    char network[BR_INET_ADDR_MAXLEN+BR_INET_ADDR_MAXLEN+1];

    int nranges;
    struct qemud_dhcp_range_def *ranges;
};

/* Virtual Network runtime state */
struct qemud_network {
    char configFile[PATH_MAX];
    char autostartLink[PATH_MAX];

    struct qemud_network_def *def; /* The current definition */
    struct qemud_network_def *newDef; /* New definition to activate at shutdown */

    char bridge[BR_IFNAME_MAXLEN];
    int dnsmasqPid;

    unsigned int active : 1;
    unsigned int autostart : 1;

    struct qemud_network *next;
};


/* Main driver state */
struct qemud_driver {
    int qemuVersion;
    int nactivevms;
    int ninactivevms;
    struct qemud_vm *vms;
    int nextvmid;
    int nactivenetworks;
    int ninactivenetworks;
    struct qemud_network *networks;
    brControl *brctl;
    iptablesContext *iptables;
    char *configDir;
    char *autostartDir;
    char *networkConfigDir;
    char *networkAutostartDir;
    char logDir[PATH_MAX];
};


static inline int
qemudIsActiveVM(struct qemud_vm *vm)
{
    return vm->id != -1;
}

static inline int
qemudIsActiveNetwork(struct qemud_network *network)
{
    return network->active;
}

void qemudReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,5,6);



struct qemud_vm *qemudFindVMByID(const struct qemud_driver *driver,
                                 int id);
struct qemud_vm *qemudFindVMByUUID(const struct qemud_driver *driver,
                                   const unsigned char *uuid);
struct qemud_vm *qemudFindVMByName(const struct qemud_driver *driver,
                                   const char *name);

struct qemud_network *qemudFindNetworkByUUID(const struct qemud_driver *driver,
                                             const unsigned char *uuid);
struct qemud_network *qemudFindNetworkByName(const struct qemud_driver *driver,
                                             const char *name);

int         qemudExtractVersion         (virConnectPtr conn,
                                         struct qemud_driver *driver);
int         qemudBuildCommandLine       (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_vm *vm,
                                         char ***argv);

int         qemudScanConfigs            (struct qemud_driver *driver);
int         qemudDeleteConfig           (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         const char *configFile,
                                         const char *name);
int         qemudEnsureDir              (const char *path);

void        qemudFreeVMDef              (struct qemud_vm_def *vm);
void        qemudFreeVM                 (struct qemud_vm *vm);

struct qemud_vm *
            qemudAssignVMDef            (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_vm_def *def);
void        qemudRemoveInactiveVM       (struct qemud_driver *driver,
                                         struct qemud_vm *vm);

struct qemud_vm_def *
            qemudParseVMDef             (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         const char *xmlStr,
                                         const char *displayName);
int         qemudSaveVMDef              (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_vm *vm,
                                         struct qemud_vm_def *def);
char *      qemudGenerateXML            (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_vm *vm,
                                         struct qemud_vm_def *def,
                                         int live);

void        qemudFreeNetworkDef         (struct qemud_network_def *def);
void        qemudFreeNetwork            (struct qemud_network *network);

struct qemud_network *
            qemudAssignNetworkDef       (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_network_def *def);
void        qemudRemoveInactiveNetwork  (struct qemud_driver *driver,
                                         struct qemud_network *network);

struct qemud_network_def *
            qemudParseNetworkDef        (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         const char *xmlStr,
                                         const char *displayName);
int         qemudSaveNetworkDef         (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_network *network,
                                         struct qemud_network_def *def);
char *      qemudGenerateNetworkXML     (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_network *network,
                                         struct qemud_network_def *def);

struct qemu_feature_flags {
    const char *name;
    const int default_on;
    const int toggle;
};

struct qemu_arch_info {
    const char *arch;
    int wordsize;
    const char **machines;
    const char *binary;
    const struct qemu_feature_flags *fflags;
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
