/*
 * internal.h: daemon data structure definitions
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


#ifndef QEMUD_INTERNAL_H__
#define QEMUD_INTERNAL_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

#include "protocol.h"

#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((unused))
#endif
#else
#define ATTRIBUTE_UNUSED
#endif

#ifdef DEBUG
#define QEMUD_DEBUG(args...) fprintf(stderr, args)
#else
#define QEMUD_DEBUG(args...) do {} while(0)
#endif

#define UUID_LEN 16

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
    QEMUD_NET_TAP,
    QEMUD_NET_SERVER,
    QEMUD_NET_CLIENT,
    QEMUD_NET_MCAST,
    /*  QEMUD_NET_VDE*/
};

/* Stores the virtual network interface configuration */
struct qemud_vm_net_def {
    int type;
    int vlan;
    unsigned char mac[QEMUD_MAC_ADDRESS_LEN];
    union {
        struct {
            char ifname[NAME_MAX];
            char script[PATH_MAX];
        } tap;
        struct {
            struct sockaddr_in listen;
            int port;
        } server;
        struct {
            struct sockaddr_in connect;
            int port;
        } client;
        struct {
            struct sockaddr_in group;
            int port;
        } mcast;
        struct {
            char vlan[PATH_MAX];
        } vde;
    } dst;

    struct qemud_vm_net_def *next;
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
enum qemud_vm_grapics_type {
    QEMUD_GRAPHICS_NONE,
    QEMUD_GRAPHICS_SDL,
    QEMUD_GRAPHICS_VNC,
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
    int id;
    int virtType;
    unsigned char uuid[QEMUD_UUID_RAW_LEN];
    char name[QEMUD_MAX_NAME_LEN];

    int memory;
    int maxmem;
    int vcpus;

    struct qemud_vm_os_def os;

    int features;
    int graphicsType;
    int vncPort;
    int vncActivePort;

    int ndisks;
    struct qemud_vm_disk_def *disks;

    int nnets;
    struct qemud_vm_net_def *nets;
};

/* Guest VM runtime state */
struct qemud_vm {
    int stdout;
    int stderr;
    int monitor;
    int pid;

    char configFile[PATH_MAX];

    struct qemud_vm_def def;

    struct qemud_vm *next;
};

/* Virtual Network main configuration */
struct qemud_network_def {
    unsigned char uuid[QEMUD_UUID_RAW_LEN];
    char name[QEMUD_MAX_NAME_LEN];
};

/* Virtual Network runtime state */
struct qemud_network {
    struct qemud_network_def def;
    struct qemud_network *next;
};

/* Stores the per-client connection state */
struct qemud_client {
    int fd;
    int readonly;
    struct qemud_packet incoming;
    unsigned int incomingReceived;
    struct qemud_packet outgoing;
    unsigned int outgoingSent;
    int tx;
    struct qemud_client *next;
};


struct qemud_socket {
    int fd;
    int readonly;
    struct qemud_socket *next;
};

/* Main server state */
struct qemud_server {
    int nsockets;
    struct qemud_socket *sockets;
    int qemuVersion;
    int nclients;
    struct qemud_client *clients;
    int nvmfds;
    int nactivevms;
    struct qemud_vm *activevms;
    int ninactivevms;
    struct qemud_vm *inactivevms;
    int nextvmid;
    char configDir[PATH_MAX];
    char errorMessage[QEMUD_MAX_ERROR_LEN];
    int errorCode;
};

int qemudStartVMDaemon(struct qemud_server *server,
                       struct qemud_vm *vm);

int qemudShutdownVMDaemon(struct qemud_server *server,
                          struct qemud_vm *vm);

#endif

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
