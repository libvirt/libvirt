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

#ifdef WITH_QEMU

#include "internal.h"
#include "bridge.h"
#include "iptables.h"
#include "capabilities.h"
#include <netinet/in.h>
#include <sched.h>

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

enum qemud_vm_disk_bus {
    QEMUD_DISK_BUS_IDE,
    QEMUD_DISK_BUS_FDC,
    QEMUD_DISK_BUS_SCSI,
    QEMUD_DISK_BUS_VIRTIO,
    QEMUD_DISK_BUS_XEN,

    QEMUD_DISK_BUS_LAST
};

/* Stores the virtual disk configuration */
struct qemud_vm_disk_def {
    int type;
    int device;
    int bus;
    char src[PATH_MAX];
    char dst[NAME_MAX];
    int readonly;

    struct qemud_vm_disk_def *next;
};

#define QEMUD_MAC_ADDRESS_LEN 6
#define QEMUD_MODEL_MAX_LEN 10
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

/* 2 possible types of forwarding */
enum qemud_vm_net_forward_type {
    QEMUD_NET_FORWARD_NAT,
    QEMUD_NET_FORWARD_ROUTE,
};

#define QEMUD_MAX_NAME_LEN 50
#define QEMUD_MAX_XML_LEN 4096
#define QEMUD_MAX_ERROR_LEN 1024
#define QEMUD_CPUMASK_LEN CPU_SETSIZE

/* Stores the virtual network interface configuration */
struct qemud_vm_net_def {
    int type;
    unsigned char mac[QEMUD_MAC_ADDRESS_LEN];
    char model[QEMUD_MODEL_MAX_LEN];
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

enum qemu_vm_chr_dst_type {
    QEMUD_CHR_SRC_TYPE_NULL,
    QEMUD_CHR_SRC_TYPE_VC,
    QEMUD_CHR_SRC_TYPE_PTY,
    QEMUD_CHR_SRC_TYPE_DEV,
    QEMUD_CHR_SRC_TYPE_FILE,
    QEMUD_CHR_SRC_TYPE_PIPE,
    QEMUD_CHR_SRC_TYPE_STDIO,
    QEMUD_CHR_SRC_TYPE_UDP,
    QEMUD_CHR_SRC_TYPE_TCP,
    QEMUD_CHR_SRC_TYPE_UNIX,

    QEMUD_CHR_SRC_TYPE_LAST,
};

enum {
    QEMUD_CHR_SRC_TCP_PROTOCOL_RAW,
    QEMUD_CHR_SRC_TCP_PROTOCOL_TELNET,
};

struct qemud_vm_chr_def {
    int dstPort;

    int srcType;
    union {
        struct {
            char path[PATH_MAX];
        } file; /* pty, file, pipe, or device */
        struct {
            char host[BR_INET_ADDR_MAXLEN];
            char service[BR_INET_ADDR_MAXLEN];
            int listen;
            int protocol;
        } tcp;
        struct {
            char bindHost[BR_INET_ADDR_MAXLEN];
            char bindService[BR_INET_ADDR_MAXLEN];
            char connectHost[BR_INET_ADDR_MAXLEN];
            char connectService[BR_INET_ADDR_MAXLEN];
        } udp;
        struct {
            char path[PATH_MAX];
            int listen;
        } nix;
    } srcData;

    struct qemud_vm_chr_def *next;
};

enum qemu_vm_input_type {
    QEMU_INPUT_TYPE_MOUSE,
    QEMU_INPUT_TYPE_TABLET,
};

enum qemu_vm_input_bus {
    QEMU_INPUT_BUS_PS2,
    QEMU_INPUT_BUS_USB,
    QEMU_INPUT_BUS_XEN,
};

struct qemud_vm_input_def {
    int type;
    int bus;
    struct qemud_vm_input_def *next;
};

enum qemu_vm_sound_model {
    QEMU_SOUND_NONE   = 0,
    QEMU_SOUND_SB16,
    QEMU_SOUND_ES1370,
    QEMU_SOUND_PCSPK,
};

struct qemud_vm_sound_def {
    int model;
    struct qemud_vm_sound_def *next;
};

/* Flags for the 'type' field in next struct */
enum qemud_vm_device_type {
    QEMUD_DEVICE_DISK,
    QEMUD_DEVICE_NET,
    QEMUD_DEVICE_INPUT,
    QEMUD_DEVICE_SOUND,
};

struct qemud_vm_device_def {
    int type;
    union {
        struct qemud_vm_disk_def disk;
        struct qemud_vm_net_def net;
        struct qemud_vm_input_def input;
        struct qemud_vm_sound_def sound;
    } data;
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
    QEMUD_CMD_FLAG_KQEMU          = (1 << 0),
    QEMUD_CMD_FLAG_VNC_COLON      = (1 << 1),
    QEMUD_CMD_FLAG_NO_REBOOT      = (1 << 2),
    QEMUD_CMD_FLAG_DRIVE          = (1 << 3),
    QEMUD_CMD_FLAG_DRIVE_BOOT     = (1 << 4),
    QEMUD_CMD_FLAG_NAME           = (1 << 5),
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
    char bootloader[PATH_MAX];
};

/* Guest VM main configuration */
struct qemud_vm_def {
    int virtType;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char name[QEMUD_MAX_NAME_LEN];

    unsigned long memory;
    unsigned long maxmem;
    int vcpus;
    char cpumask[QEMUD_CPUMASK_LEN];

    int noReboot;

    struct qemud_vm_os_def os;

    int localtime;
    int features;
    int graphicsType;
    int vncPort;
    int vncActivePort;
    char vncListen[BR_INET_ADDR_MAXLEN];
    char *keymap;

    unsigned int ndisks;
    struct qemud_vm_disk_def *disks;

    unsigned int nnets;
    struct qemud_vm_net_def *nets;

    unsigned int ninputs;
    struct qemud_vm_input_def *inputs;

    unsigned int nsounds;
    struct qemud_vm_sound_def *sounds;

    unsigned int nserials;
    struct qemud_vm_chr_def *serials;

    unsigned int nparallels;
    struct qemud_vm_chr_def *parallels;
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

    int nvcpupids;
    int *vcpupids;

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
    int forwardMode; /* From qemud_vm_net_forward_type */
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
    unsigned int vncTLS : 1;
    unsigned int vncTLSx509verify : 1;
    char *vncTLSx509certdir;
    char vncListen[BR_INET_ADDR_MAXLEN];

    virCapsPtr caps;
};


static inline int
qemudIsActiveVM(const struct qemud_vm *vm)
{
    return vm->id != -1;
}

static inline int
qemudIsActiveNetwork(const struct qemud_network *network)
{
    return network->active;
}

void qemudReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,5,6);


int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename);

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

virCapsPtr  qemudCapsInit               (void);

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

void        qemudFreeVMDef              (struct qemud_vm_def *vm);
void        qemudFreeVM                 (struct qemud_vm *vm);

struct qemud_vm *
            qemudAssignVMDef            (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         struct qemud_vm_def *def);
void        qemudRemoveInactiveVM       (struct qemud_driver *driver,
                                         struct qemud_vm *vm);

struct qemud_vm_device_def *
            qemudParseVMDeviceDef       (virConnectPtr conn,
                                         const struct qemud_vm_def *def,
                                         const char *xmlStr);

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

const char *qemudVirtTypeToString       (int type);

#endif /* WITH_QEMU */

#endif /* __QEMUD_CONF_H */
