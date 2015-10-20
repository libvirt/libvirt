/*
 * Copyright (C) 2007-2015 Red Hat, Inc.
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
# include "virnetlink.h"
# include "virmacaddr.h"
# include "virpci.h"
# include "device_conf.h"

# ifdef HAVE_STRUCT_IFREQ
typedef struct ifreq virIfreq;
# else
typedef void virIfreq;
# endif

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

int virNetDevSetupControl(const char *ifname,
                          virIfreq *ifr)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevExists(const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetOnline(const char *ifname,
                       bool online)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetOnline(const char *ifname,
                      bool *online)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevSetIPAddress(const char *ifname,
                          virSocketAddr *addr,
                          unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevAddRoute(const char *ifname,
                      virSocketAddrPtr addr,
                      unsigned int prefix,
                      virSocketAddrPtr gateway,
                      unsigned int metric)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevClearIPAddress(const char *ifname,
                            virSocketAddr *addr,
                            unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevGetIPAddress(const char *ifname, virSocketAddrPtr addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevWaitDadFinish(virSocketAddrPtr *addrs, size_t count)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


int virNetDevSetMAC(const char *ifname,
                    const virMacAddr *macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
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

int virNetDevGetIndex(const char *ifname, int *ifindex)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVLanID(const char *ifname, int *vlanid)
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

int virNetDevGetVirtualFunctions(const char *pfname,
                                 char ***vfname,
                                 virPCIDeviceAddressPtr **virt_fns,
                                 size_t *n_vfname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;

int virNetDevLinkDump(const char *ifname, int ifindex,
                      void **nlData, struct nlattr **tb,
                      uint32_t src_pid, uint32_t dst_pid)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevReplaceNetConfig(const char *linkdev, int vf,
                              const virMacAddr *macaddress, int vlanid,
                              const char *stateDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(5);

int virNetDevRestoreNetConfig(const char *linkdev, int vf, const char *stateDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

int virNetDevGetVirtualFunctionInfo(const char *vfname, char **pfname,
                                    int *vf)
    ATTRIBUTE_NONNULL(1);

int virNetDevGetFeatures(const char *ifname,
                         virBitmapPtr *out)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetLinkInfo(const char *ifname,
                         virInterfaceLinkPtr lnk)
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
    ATTRIBUTE_RETURN_CHECK;
#endif /* __VIR_NETDEV_H__ */
