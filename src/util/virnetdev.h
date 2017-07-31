/*
 * Copyright (C) 2007-2016 Red Hat, Inc.
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
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_H__
# define __VIR_NETDEV_H__

# include <net/if.h>

# include "virbitmap.h"
# include "virsocketaddr.h"
# include "virmacaddr.h"
# include "virpci.h"
# include "virnetdevvlan.h"

# ifdef HAVE_STRUCT_IFREQ
typedef struct ifreq virIfreq;
# else
typedef void virIfreq;
# endif

/* Used for prefix of ifname of any tap device name generated
 * dynamically by libvirt, cannot be used for a persistent network name.
 */
# define VIR_NET_GENERATED_TAP_PREFIX "vnet"

typedef enum {
   VIR_NETDEV_RX_FILTER_MODE_NONE = 0,
   VIR_NETDEV_RX_FILTER_MODE_NORMAL,
   VIR_NETDEV_RX_FILTER_MODE_ALL,

   VIR_NETDEV_RX_FILTER_MODE_LAST
} virNetDevRxFilterMode;
VIR_ENUM_DECL(virNetDevRxFilterMode)

typedef struct _virNetDevRxFilter virNetDevRxFilter;
typedef virNetDevRxFilter *virNetDevRxFilterPtr;
struct _virNetDevRxFilter {
    char *name; /* the alias used by qemu, *not* name used by guest */
    virMacAddr mac;
    bool promiscuous;
    bool broadcastAllowed;

    struct {
        int mode; /* enum virNetDevRxFilterMode */
        bool overflow;
        virMacAddrPtr table;
        size_t nTable;
    } unicast;
    struct {
        int mode; /* enum virNetDevRxFilterMode */
        bool overflow;
        virMacAddrPtr table;
        size_t nTable;
    } multicast;
    struct {
        int mode; /* enum virNetDevRxFilterMode */
        unsigned int *table;
        size_t nTable;
    } vlan;
};

typedef enum {
    VIR_NETDEV_IF_STATE_UNKNOWN = 1,
    VIR_NETDEV_IF_STATE_NOT_PRESENT,
    VIR_NETDEV_IF_STATE_DOWN,
    VIR_NETDEV_IF_STATE_LOWER_LAYER_DOWN,
    VIR_NETDEV_IF_STATE_TESTING,
    VIR_NETDEV_IF_STATE_DORMANT,
    VIR_NETDEV_IF_STATE_UP,
    VIR_NETDEV_IF_STATE_LAST
} virNetDevIfState;

VIR_ENUM_DECL(virNetDevIfState)

typedef struct _virNetDevIfLink virNetDevIfLink;
typedef virNetDevIfLink *virNetDevIfLinkPtr;
struct _virNetDevIfLink {
    virNetDevIfState state; /* link state */
    unsigned int speed;      /* link speed in Mbits per second */
};

typedef enum {
    VIR_NET_DEV_FEAT_GRXCSUM,
    VIR_NET_DEV_FEAT_GTXCSUM,
    VIR_NET_DEV_FEAT_GSG,
    VIR_NET_DEV_FEAT_GTSO,
    VIR_NET_DEV_FEAT_GGSO,
    VIR_NET_DEV_FEAT_GGRO,
    VIR_NET_DEV_FEAT_LRO,
    VIR_NET_DEV_FEAT_RXVLAN,
    VIR_NET_DEV_FEAT_TXVLAN,
    VIR_NET_DEV_FEAT_NTUPLE,
    VIR_NET_DEV_FEAT_RXHASH,
    VIR_NET_DEV_FEAT_RDMA,
    VIR_NET_DEV_FEAT_TXUDPTNL,
    VIR_NET_DEV_FEAT_LAST
} virNetDevFeature;

VIR_ENUM_DECL(virNetDevFeature)

/* Modeled after struct ethtool_coalesce, see linux/ethtool.h for explanations
 * of particular fields */
typedef struct _virNetDevCoalesce virNetDevCoalesce;
typedef virNetDevCoalesce *virNetDevCoalescePtr;
struct _virNetDevCoalesce {
    uint32_t rx_coalesce_usecs;
    uint32_t rx_max_coalesced_frames;
    uint32_t rx_coalesce_usecs_irq;
    uint32_t rx_max_coalesced_frames_irq;
    uint32_t tx_coalesce_usecs;
    uint32_t tx_max_coalesced_frames;
    uint32_t tx_coalesce_usecs_irq;
    uint32_t tx_max_coalesced_frames_irq;
    uint32_t stats_block_coalesce_usecs;
    uint32_t use_adaptive_rx_coalesce;
    uint32_t use_adaptive_tx_coalesce;
    uint32_t pkt_rate_low;
    uint32_t rx_coalesce_usecs_low;
    uint32_t rx_max_coalesced_frames_low;
    uint32_t tx_coalesce_usecs_low;
    uint32_t tx_max_coalesced_frames_low;
    uint32_t pkt_rate_high;
    uint32_t rx_coalesce_usecs_high;
    uint32_t rx_max_coalesced_frames_high;
    uint32_t tx_coalesce_usecs_high;
    uint32_t tx_max_coalesced_frames_high;
    uint32_t rate_sample_interval;
};


int virNetDevSetupControl(const char *ifname,
                          virIfreq *ifr)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevExists(const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetOnline(const char *ifname,
                       bool online)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NOINLINE;
int virNetDevGetOnline(const char *ifname,
                      bool *online)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;


int virNetDevSetMAC(const char *ifname,
                    const virMacAddr *macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NOINLINE;
int virNetDevGetMAC(const char *ifname,
                    virMacAddrPtr macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevReplaceMacAddress(const char *linkdev,
                               const virMacAddr *macaddress,
                               const char *stateDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevRestoreMacAddress(const char *linkdev,
                               const char *stateDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetCoalesce(const char *ifname,
                         virNetDevCoalescePtr coalesce,
                         bool update)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetMTU(const char *ifname,
                    int mtu)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevSetMTUFromDevice(const char *ifname,
                              const char *otherifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetMTU(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevSetNamespace(const char *ifname, pid_t pidInNs)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevSetName(const char *ifname, const char *newifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

char *virNetDevGetName(int ifindex)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevGetIndex(const char *ifname, int *ifindex)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVLanID(const char *ifname, int *vlanid)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetMaster(const char *ifname, char **master)
   ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevValidateConfig(const char *ifname,
                            const virMacAddr *macaddr, int ifindex)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevIsVirtualFunction(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVirtualFunctionIndex(const char *pfname, const char *vfname,
                                     int *vf_index)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevGetPhysicalFunction(const char *ifname, char **pfname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevPFGetVF(const char *pfname, int vf, char **vfname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetPhysPortID(const char *ifname,
                           char **physPortID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVirtualFunctions(const char *pfname,
                                 char ***vfname,
                                 virPCIDeviceAddressPtr **virt_fns,
                                 size_t *n_vfname,
                                 unsigned int *max_vfs)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_RETURN_CHECK;

int virNetDevSaveNetConfig(const char *linkdev, int vf,
                           const char *stateDir,
                           bool saveVlan)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;

int
virNetDevReadNetConfig(const char *linkdev, int vf,
                       const char *stateDir,
                       virMacAddrPtr *adminMAC,
                       virNetDevVlanPtr *vlan,
                       virMacAddrPtr *MAC)
   ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
   ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6) ATTRIBUTE_RETURN_CHECK;

int
virNetDevSetNetConfig(const char *linkdev, int vf,
                      const virMacAddr *adminMAC,
                      virNetDevVlanPtr vlan,
                      const virMacAddr *MAC,
                      bool setVLan)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVirtualFunctionInfo(const char *vfname, char **pfname,
                                    int *vf)
    ATTRIBUTE_NONNULL(1);

int virNetDevGetFeatures(const char *ifname,
                         virBitmapPtr *out)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetLinkInfo(const char *ifname,
                         virNetDevIfLinkPtr lnk)
    ATTRIBUTE_NONNULL(1);

virNetDevRxFilterPtr virNetDevRxFilterNew(void)
   ATTRIBUTE_RETURN_CHECK;
void virNetDevRxFilterFree(virNetDevRxFilterPtr filter);
int virNetDevGetRxFilter(const char *ifname,
                         virNetDevRxFilterPtr *filter)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevAddMulti(const char *ifname,
                      virMacAddrPtr macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevDelMulti(const char *ifname,
                      virMacAddrPtr macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetPromiscuous(const char *ifname, bool promiscuous)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetPromiscuous(const char *ifname, bool *promiscuous)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetRcvMulti(const char *ifname, bool receive)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetRcvMulti(const char *ifname, bool *receive)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetRcvAllMulti(const char *ifname, bool receive)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetRcvAllMulti(const char *ifname, bool *receive)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

# define SYSFS_NET_DIR "/sys/class/net/"
# define SYSFS_INFINIBAND_DIR "/sys/class/infiniband/"
int virNetDevSysfsFile(char **pf_sysfs_device_link,
                       const char *ifname,
                       const char *file)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NOINLINE;

int virNetDevRunEthernetScript(const char *ifname, const char *script)
    ATTRIBUTE_NOINLINE;
#endif /* __VIR_NETDEV_H__ */
