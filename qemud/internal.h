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
#include <gnutls/x509.h>

#include "protocol.h"
#include "remote_protocol.h"
#include "bridge.h"
#include "iptables.h"

#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif
#ifndef ATTRIBUTE_FORMAT
#define ATTRIBUTE_FORMAT(args...) __attribute__((__format__ (args)))
#endif
#else
#define ATTRIBUTE_UNUSED
#define ATTRIBUTE_FORMAT(...)
#endif

#define UUID_LEN 16

typedef enum {
    QEMUD_ERR,
    QEMUD_WARN,
    QEMUD_INFO,
#ifdef ENABLE_DEBUG
    QEMUD_DEBUG
#endif
} qemudLogPriority;

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
    unsigned char uuid[QEMUD_UUID_RAW_LEN];
    char name[QEMUD_MAX_NAME_LEN];

    int memory;
    int maxmem;
    int vcpus;

    int noReboot;

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
    int logfile;
    int pid;
    int id;
    int state;

    int *tapfds;
    int ntapfds;

    char configFile[PATH_MAX];
    char autostartLink[PATH_MAX];

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
    unsigned char uuid[QEMUD_UUID_RAW_LEN];
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


enum qemud_mode {
    QEMUD_MODE_RX_HEADER,
    QEMUD_MODE_RX_PAYLOAD,
    QEMUD_MODE_TX_PACKET,
    QEMUD_MODE_TLS_HANDSHAKE,
};

/* These have to remain compatible with gnutls_record_get_direction. */
enum qemud_tls_direction {
    QEMUD_TLS_DIRECTION_READ = 0,
    QEMUD_TLS_DIRECTION_WRITE = 1,
};

/* Stores the per-client connection state */
struct qemud_client {
    int magic;

    int fd;
    int readonly;
    enum qemud_mode mode;

    struct sockaddr_storage addr;
    socklen_t addrlen;

    /* If set, TLS is required on this socket. */
    int tls;
    gnutls_session_t session;
    enum qemud_tls_direction direction;

    unsigned int incomingSerial;
    unsigned int outgoingSerial;

    char buffer [REMOTE_MESSAGE_MAX];
    unsigned int bufferLength;
    unsigned int bufferOffset;

    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;

    struct qemud_client *next;
};

#define QEMUD_CLIENT_MAGIC 0x7788aaee


struct qemud_socket {
    int fd;
    int readonly;
    /* If set, TLS is required on this socket. */
    int tls;

    struct qemud_socket *next;
};

/* Main server state */
struct qemud_server {
    int nsockets;
    struct qemud_socket *sockets;
    int qemuVersion;
    int qemuCmdFlags; /* values from enum qemud_cmd_flags */
    int nclients;
    struct qemud_client *clients;
    int sigread;
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
    unsigned int shutdown : 1;
};

void qemudLog(int priority, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,2,3);

#ifdef ENABLE_DEBUG
#define qemudDebug(...) qemudLog(QEMUD_DEBUG, __VA_ARGS__)
#else
#define qemudDebug(fmt, ...) do {} while(0)
#endif

void remoteDispatchClientRequest (struct qemud_server *server,
                                  struct qemud_client *client);

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

#endif

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
