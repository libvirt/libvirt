/*
 * nwfilter_learnipaddr.c: support for learning IP address used by a VM
 *                         on an interface
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corp.
 * Copyright (C) 2010 Stefan Berger
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
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#ifdef HAVE_LIBPCAP
# include <pcap.h>
#endif

#include <fcntl.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if_arp.h>

#include "internal.h"

#include "intprops.h"
#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "datatypes.h"
#include "virnetdev.h"
#include "virterror_internal.h"
#include "threads.h"
#include "conf/nwfilter_params.h"
#include "conf/domain_conf.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

#define IFINDEX2STR(VARNAME, ifindex) \
    char VARNAME[INT_BUFSIZE_BOUND(ifindex)]; \
    snprintf(VARNAME, sizeof(VARNAME), "%d", ifindex);

#define PKT_TIMEOUT_MS 500 /* ms */

/* structure of an ARP request/reply message */
struct f_arphdr {
    struct arphdr arphdr;
    uint8_t ar_sha[ETH_ALEN];
    uint32_t ar_sip;
    uint8_t ar_tha[ETH_ALEN];
    uint32_t ar_tip;
} ATTRIBUTE_PACKED;


struct dhcp_option {
    uint8_t code;
    uint8_t len;
    uint8_t value[0]; /* length varies */
} ATTRIBUTE_PACKED;


/* structure representing DHCP message */
struct dhcp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t zeroes[192];
    uint32_t magic;
    struct dhcp_option options[0];
} ATTRIBUTE_PACKED;

#define DHCP_MSGT_DHCPOFFER 2
#define DHCP_MSGT_DHCPACK   5


#define DHCP_OPT_BCASTADDRESS 28
#define DHCP_OPT_MESSAGETYPE  53

struct ether_vlan_header
{
    uint8_t dhost[ETH_ALEN];
    uint8_t shost[ETH_ALEN];
    uint16_t vlan_type;
    uint16_t vlan_flags;
    uint16_t ether_type;
} ATTRIBUTE_PACKED;


static virMutex pendingLearnReqLock;
static virHashTablePtr pendingLearnReq;

static virMutex ipAddressMapLock;
static virNWFilterHashTablePtr ipAddressMap;

static virMutex ifaceMapLock;
static virHashTablePtr ifaceLockMap;

typedef struct _virNWFilterIfaceLock virNWFilterIfaceLock;
typedef virNWFilterIfaceLock *virNWFilterIfaceLockPtr;
struct _virNWFilterIfaceLock {
    char ifname[IF_NAMESIZE];
    virMutex lock;
    int refctr;
};


static bool threadsTerminate = false;


int
virNWFilterLockIface(const char *ifname) {
    virNWFilterIfaceLockPtr ifaceLock;

    virMutexLock(&ifaceMapLock);

    ifaceLock = virHashLookup(ifaceLockMap, ifname);
    if (!ifaceLock) {
        if (VIR_ALLOC(ifaceLock) < 0) {
            virReportOOMError();
            goto err_exit;
        }

        if (virMutexInitRecursive(&ifaceLock->lock) < 0) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("mutex initialization failed"));
            VIR_FREE(ifaceLock);
            goto err_exit;
        }

        if (virStrcpyStatic(ifaceLock->ifname, ifname) == NULL) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("interface name %s does not fit into "
                                     "buffer "),
                                   ifaceLock->ifname);
            VIR_FREE(ifaceLock);
            goto err_exit;
        }

        while (virHashAddEntry(ifaceLockMap, ifname, ifaceLock)) {
            VIR_FREE(ifaceLock);
            goto err_exit;
        }

        ifaceLock->refctr = 0;
    }

    ifaceLock->refctr++;

    virMutexUnlock(&ifaceMapLock);

    virMutexLock(&ifaceLock->lock);

    return 0;

 err_exit:
    virMutexUnlock(&ifaceMapLock);

    return -1;
}


static void
freeIfaceLock(void *payload, const void *name ATTRIBUTE_UNUSED) {
    VIR_FREE(payload);
}


void
virNWFilterUnlockIface(const char *ifname) {
    virNWFilterIfaceLockPtr ifaceLock;

    virMutexLock(&ifaceMapLock);

    ifaceLock = virHashLookup(ifaceLockMap, ifname);

    if (ifaceLock) {
        virMutexUnlock(&ifaceLock->lock);

        ifaceLock->refctr--;
        if (ifaceLock->refctr == 0)
            virHashRemoveEntry(ifaceLockMap, ifname);
    }

    virMutexUnlock(&ifaceMapLock);
}


static void
virNWFilterIPAddrLearnReqFree(virNWFilterIPAddrLearnReqPtr req) {
    if (!req)
        return;

    VIR_FREE(req->filtername);
    virNWFilterHashTableFree(req->filterparams);

    VIR_FREE(req);
}


#if HAVE_LIBPCAP

static int
virNWFilterRegisterLearnReq(virNWFilterIPAddrLearnReqPtr req) {
    int res = -1;
    IFINDEX2STR(ifindex_str, req->ifindex);

    virMutexLock(&pendingLearnReqLock);

    if (!virHashLookup(pendingLearnReq, ifindex_str))
        res = virHashAddEntry(pendingLearnReq, ifindex_str, req);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}


#endif

int
virNWFilterTerminateLearnReq(const char *ifname) {
    int rc = -1;
    int ifindex;
    virNWFilterIPAddrLearnReqPtr req;

    if (virNetDevGetIndex(ifname, &ifindex) < 0) {
        virResetLastError();
        return rc;
    }

    IFINDEX2STR(ifindex_str, ifindex);

    virMutexLock(&pendingLearnReqLock);

    req = virHashLookup(pendingLearnReq, ifindex_str);
    if (req) {
        rc = 0;
        req->terminate = true;
    }

    virMutexUnlock(&pendingLearnReqLock);

    return rc;
}


virNWFilterIPAddrLearnReqPtr
virNWFilterLookupLearnReq(int ifindex) {
    void *res;
    IFINDEX2STR(ifindex_str, ifindex);

    virMutexLock(&pendingLearnReqLock);

    res = virHashLookup(pendingLearnReq, ifindex_str);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}


static void
freeLearnReqEntry(void *payload, const void *name ATTRIBUTE_UNUSED) {
    virNWFilterIPAddrLearnReqFree(payload);
}


#ifdef HAVE_LIBPCAP

static virNWFilterIPAddrLearnReqPtr
virNWFilterDeregisterLearnReq(int ifindex) {
    virNWFilterIPAddrLearnReqPtr res;
    IFINDEX2STR(ifindex_str, ifindex);

    virMutexLock(&pendingLearnReqLock);

    res = virHashSteal(pendingLearnReq, ifindex_str);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}

/* Add an IP address to the list of IP addresses an interface is
 * known to use. This function feeds the per-interface cache that
 * is used to instantiate filters with variable '$IP'.
 *
 * @ifname: The name of the (tap) interface
 * @addr: An IPv4 address in dotted decimal format that the (tap)
 *        interface is known to use.
 *
 * This function returns 0 on success, -1 otherwise
 */
static int
virNWFilterAddIpAddrForIfname(const char *ifname, char *addr)
{
    int ret = -1;
    virNWFilterVarValuePtr val;

    virMutexLock(&ipAddressMapLock);

    val = virHashLookup(ipAddressMap->hashTable, ifname);
    if (!val) {
        val = virNWFilterVarValueCreateSimple(addr);
        if (!val) {
            virReportOOMError();
            goto cleanup;
        }
        ret = virNWFilterHashTablePut(ipAddressMap, ifname, val, 1);
        goto cleanup;
    } else {
        if (virNWFilterVarValueAddValue(val, addr) < 0)
            goto cleanup;
    }

    ret = 0;

cleanup:
    virMutexUnlock(&ipAddressMapLock);

    return ret;
}
#endif

/* Delete all or a specific IP address from an interface. After this
 * call either all or the given IP address will not be associated
 * with the interface anymore.
 *
 * @ifname: The name of the (tap) interface
 * @addr: An IPv4 address in dotted decimal format that the (tap)
 *        interface is not using anymore; provide NULL to remove all IP
 *        addresses associated with the given interface
 *
 * This function returns the number of IP addresses that are still
 * known to be associated with this interface, in case of an error
 * -1 is returned. Error conditions are:
 * - IP addresses is not known to be associated with the interface
 */
int
virNWFilterDelIpAddrForIfname(const char *ifname, const char *ipaddr)
{
    int ret = -1;
    virNWFilterVarValuePtr val = NULL;

    virMutexLock(&ipAddressMapLock);

    if (ipaddr != NULL) {
        val = virHashLookup(ipAddressMap->hashTable, ifname);
        if (val) {
            if (virNWFilterVarValueGetCardinality(val) == 1 &&
                STREQ(ipaddr,
                      virNWFilterVarValueGetNthValue(val, 0)))
                goto remove_entry;
            virNWFilterVarValueDelValue(val, ipaddr);
            ret = virNWFilterVarValueGetCardinality(val);
        }
    } else {
remove_entry:
        /* remove whole entry */
        val = virNWFilterHashTableRemoveEntry(ipAddressMap, ifname);
        virNWFilterVarValueFree(val);
        ret = 0;
    }

    virMutexUnlock(&ipAddressMapLock);

    return ret;
}

/* Get the list of IP addresses known to be in use by an interface
 *
 * This function returns NULL in case no IP address is known to be
 * associated with the interface, a virNWFilterVarValuePtr otherwise
 * that then can contain one or multiple entries.
 */
virNWFilterVarValuePtr
virNWFilterGetIpAddrForIfname(const char *ifname)
{
    virNWFilterVarValuePtr res;

    virMutexLock(&ipAddressMapLock);

    res = virHashLookup(ipAddressMap->hashTable, ifname);

    virMutexUnlock(&ipAddressMapLock);

    return res;
}


#ifdef HAVE_LIBPCAP

static void
procDHCPOpts(struct dhcp *dhcp, int dhcp_opts_len,
             uint32_t *vmaddr, uint32_t *bcastaddr,
             enum howDetect *howDetected) {
    struct dhcp_option *dhcpopt = &dhcp->options[0];

    while (dhcp_opts_len >= 2) {

        switch (dhcpopt->code) {

        case DHCP_OPT_BCASTADDRESS: /* Broadcast address */
            if (dhcp_opts_len >= 6) {
                uint32_t *tmp = (uint32_t *)&dhcpopt->value;
                (*bcastaddr) = ntohl(*tmp);
            }
        break;

        case DHCP_OPT_MESSAGETYPE: /* Message type */
            if (dhcp_opts_len >= 3) {
                uint8_t *val = (uint8_t *)&dhcpopt->value;
                switch (*val) {
                case DHCP_MSGT_DHCPACK:
                case DHCP_MSGT_DHCPOFFER:
                    *vmaddr = dhcp->yiaddr;
                    *howDetected = DETECT_DHCP;
                break;
                }
            }
        }
        dhcp_opts_len -= (2 + dhcpopt->len);
        dhcpopt = (struct dhcp_option*)((char *)dhcpopt + 2 + dhcpopt->len);
    }
}


/**
 * learnIPAddressThread
 * arg: pointer to virNWFilterIPAddrLearnReq structure
 *
 * Learn the IP address being used on an interface. Use ARP Request and
 * Reply messages, DHCP offers and the first IP packet being sent from
 * the VM to detect the IP address it is using. Detects only one IP address
 * per interface (IP aliasing not supported). The method on how the
 * IP address is detected can be chosen through flags. DETECT_DHCP will
 * require that the IP address is detected from a DHCP OFFER, DETECT_STATIC
 * will require that the IP address was taken from an ARP packet or an IPv4
 * packet. Both flags can be set at the same time.
 */
static void *
learnIPAddressThread(void *arg)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = NULL;
    struct bpf_program fp;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header *ether_hdr;
    struct ether_vlan_header *vlan_hdr;
    virNWFilterIPAddrLearnReqPtr req = arg;
    uint32_t vmaddr = 0, bcastaddr = 0;
    unsigned int ethHdrSize;
    char *listen_if = (strlen(req->linkdev) != 0) ? req->linkdev
                                                  : req->ifname;
    int dhcp_opts_len;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *filter = NULL;
    uint16_t etherType;
    bool showError = true;
    enum howDetect howDetected = 0;
    virNWFilterTechDriverPtr techdriver = req->techdriver;

    if (virNWFilterLockIface(req->ifname) < 0)
       goto err_no_lock;

    req->status = 0;

    /* anything change to the VM's interface -- check at least once */
    if (virNetDevValidateConfig(req->ifname, NULL, req->ifindex) <= 0) {
        virResetLastError();
        req->status = ENODEV;
        goto done;
    }

    handle = pcap_open_live(listen_if, BUFSIZ, 0, PKT_TIMEOUT_MS, errbuf);

    if (handle == NULL) {
        VIR_DEBUG("Couldn't open device %s: %s\n", listen_if, errbuf);
        req->status = ENODEV;
        goto done;
    }

    virMacAddrFormat(req->macaddr, macaddr);

    switch (req->howDetect) {
    case DETECT_DHCP:
        if (techdriver->applyDHCPOnlyRules(req->ifname,
                                           req->macaddr,
                                           NULL, false) < 0) {
            req->status = EINVAL;
            goto done;
        }
        virBufferAsprintf(&buf, " ether dst %s"
                                " and src port 67 and dst port 68",
                          macaddr);
        break;
    default:
        if (techdriver->applyBasicRules(req->ifname,
                                        req->macaddr) < 0) {
            req->status = EINVAL;
            goto done;
        }
        virBufferAsprintf(&buf, "ether host %s", macaddr);
    }

    if (virBufferError(&buf)) {
        req->status = ENOMEM;
        goto done;
    }

    filter = virBufferContentAndReset(&buf);

    if (pcap_compile(handle, &fp, filter, 1, 0) != 0) {
        VIR_DEBUG("Couldn't compile filter '%s'.\n", filter);
        req->status = EINVAL;
        goto done;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        VIR_DEBUG("Couldn't set filter '%s'.\n", filter);
        req->status = EINVAL;
        pcap_freecode(&fp);
        goto done;
    }

    pcap_freecode(&fp);

    while (req->status == 0 && vmaddr == 0) {
        packet = pcap_next(handle, &header);

        if (!packet) {

            if (threadsTerminate || req->terminate) {
                req->status = ECANCELED;
                showError = false;
                break;
            }

            /* check whether VM's dev is still there */
            if (virNetDevValidateConfig(req->ifname, NULL, req->ifindex) <= 0) {
                virResetLastError();
                req->status = ENODEV;
                showError = false;
                break;
            }
            continue;
        }

        if (header.len >= sizeof(struct ether_header)) {
            ether_hdr = (struct ether_header*)packet;

            switch (ntohs(ether_hdr->ether_type)) {

            case ETHERTYPE_IP:
                ethHdrSize = sizeof(struct ether_header);
                etherType = ntohs(ether_hdr->ether_type);
                break;

            case ETHERTYPE_VLAN:
                ethHdrSize = sizeof(struct ether_vlan_header);
                vlan_hdr = (struct ether_vlan_header *)packet;
                if (ntohs(vlan_hdr->ether_type) != ETHERTYPE_IP ||
                    header.len < ethHdrSize)
                    continue;
                etherType = ntohs(vlan_hdr->ether_type);
                break;

            default:
                continue;
            }

            if (memcmp(ether_hdr->ether_shost,
                       req->macaddr,
                       VIR_MAC_BUFLEN) == 0) {
                /* packets from the VM */

                if (etherType == ETHERTYPE_IP &&
                    (header.len >= ethHdrSize +
                                   sizeof(struct iphdr))) {
                    struct iphdr *iphdr = (struct iphdr*)(packet +
                                                          ethHdrSize);
                    vmaddr = iphdr->saddr;
                    /* skip mcast addresses (224.0.0.0 - 239.255.255.255),
                     * class E (240.0.0.0 - 255.255.255.255, includes eth.
                     * bcast) and zero address in DHCP Requests */
                    if ( (ntohl(vmaddr) & 0xe0000000) == 0xe0000000 ||
                         vmaddr == 0) {
                        vmaddr = 0;
                        continue;
                    }

                    howDetected = DETECT_STATIC;
                } else if (etherType == ETHERTYPE_ARP &&
                           (header.len >= ethHdrSize +
                                          sizeof(struct f_arphdr))) {
                    struct f_arphdr *arphdr = (struct f_arphdr*)(packet +
                                                         ethHdrSize);
                    switch (ntohs(arphdr->arphdr.ar_op)) {
                    case ARPOP_REPLY:
                        vmaddr = arphdr->ar_sip;
                        howDetected = DETECT_STATIC;
                    break;
                    case ARPOP_REQUEST:
                        vmaddr = arphdr->ar_tip;
                        howDetected = DETECT_STATIC;
                    break;
                    }
                }
            } else if (memcmp(ether_hdr->ether_dhost,
                              req->macaddr,
                              VIR_MAC_BUFLEN) == 0) {
                /* packets to the VM */
                if (etherType == ETHERTYPE_IP &&
                    (header.len >= ethHdrSize +
                                   sizeof(struct iphdr))) {
                    struct iphdr *iphdr = (struct iphdr*)(packet +
                                                          ethHdrSize);
                    if ((iphdr->protocol == IPPROTO_UDP) &&
                        (header.len >= ethHdrSize +
                                       iphdr->ihl * 4 +
                                       sizeof(struct udphdr))) {
                        struct udphdr *udphdr= (struct udphdr *)
                                          ((char *)iphdr + iphdr->ihl * 4);
                        if (ntohs(udphdr->source) == 67 &&
                            ntohs(udphdr->dest)   == 68 &&
                            header.len >= ethHdrSize +
                                          iphdr->ihl * 4 +
                                          sizeof(struct udphdr) +
                                          sizeof(struct dhcp)) {
                            struct dhcp *dhcp = (struct dhcp *)
                                        ((char *)udphdr + sizeof(udphdr));
                            if (dhcp->op == 2 /* BOOTREPLY */ &&
                                !memcmp(&dhcp->chaddr[0],
                                        req->macaddr,
                                        6)) {
                                dhcp_opts_len = header.len -
                                    (ethHdrSize + iphdr->ihl * 4 +
                                     sizeof(struct udphdr) +
                                     sizeof(struct dhcp));
                                procDHCPOpts(dhcp, dhcp_opts_len,
                                             &vmaddr,
                                             &bcastaddr,
                                             &howDetected);
                            }
                        }
                    }
                }
            }
        }
        if (vmaddr && (req->howDetect & howDetected) == 0) {
            vmaddr = 0;
            howDetected = 0;
        }
    } /* while */

 done:
    VIR_FREE(filter);

    if (handle)
        pcap_close(handle);

    if (req->status == 0) {
        int ret;
        virSocketAddr sa;
        sa.len = sizeof(sa.data.inet4);
        sa.data.inet4.sin_family = AF_INET;
        sa.data.inet4.sin_addr.s_addr = vmaddr;
        char *inetaddr;

        if ((inetaddr = virSocketAddrFormat(&sa)) != NULL) {
            if (virNWFilterAddIpAddrForIfname(req->ifname, inetaddr) < 0) {
                VIR_ERROR(_("Failed to add IP address %s to IP address "
                          "cache for interface %s"), inetaddr, req->ifname);
            }

            ret = virNWFilterInstantiateFilterLate(NULL,
                                                   req->ifname,
                                                   req->ifindex,
                                                   req->linkdev,
                                                   req->nettype,
                                                   req->macaddr,
                                                   req->filtername,
                                                   req->filterparams,
                                                   req->driver);
            VIR_DEBUG("Result from applying firewall rules on "
                      "%s with IP addr %s : %d\n", req->ifname, inetaddr, ret);
        }
    } else {
        if (showError)
            virReportSystemError(req->status,
                                 _("encountered an error on interface %s "
                                   "index %d"),
                                 req->ifname, req->ifindex);

        techdriver->applyDropAllRules(req->ifname);
    }

    memset(&req->thread, 0x0, sizeof(req->thread));

    VIR_DEBUG("pcap thread terminating for interface %s\n",req->ifname);

    virNWFilterUnlockIface(req->ifname);

 err_no_lock:
    virNWFilterDeregisterLearnReq(req->ifindex);

    virNWFilterIPAddrLearnReqFree(req);

    return 0;
}


/**
 * virNWFilterLearnIPAddress
 * @techdriver : driver to build firewalls
 * @ifname: the name of the interface
 * @ifindex: the index of the interface
 * @linkdev : the name of the link device; currently only used in case of a
 *     macvtap device
 * @nettype : the type of interface
 * @macaddr : the MAC address of the interface
 * @filtername : the name of the top-level filter to apply to the interface
 *               once its IP address has been detected
 * @driver : the network filter driver
 * @howDetect : the method on how the thread is supposed to detect the
 *              IP address; must choose any of the available flags
 *
 * Instruct to learn the IP address being used on a given interface (ifname).
 * Unless there already is a thread attempting to learn the IP address
 * being used on the interface, a thread is started that will listen on
 * the traffic being sent on the interface (or link device) with the
 * MAC address that is provided. Will then launch the application of the
 * firewall rules on the interface.
 */
int
virNWFilterLearnIPAddress(virNWFilterTechDriverPtr techdriver,
                          const char *ifname,
                          int ifindex,
                          const char *linkdev,
                          enum virDomainNetType nettype,
                          const unsigned char *macaddr,
                          const char *filtername,
                          virNWFilterHashTablePtr filterparams,
                          virNWFilterDriverStatePtr driver,
                          enum howDetect howDetect) {
    int rc;
    virNWFilterIPAddrLearnReqPtr req = NULL;
    virNWFilterHashTablePtr ht = NULL;

    if (howDetect == 0)
        return -1;

    if ( !techdriver->canApplyBasicRules()) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("IP parameter must be provided since "
                                 "snooping the IP address does not work "
                                 "possibly due to missing tools"));
        return -1;
    }

    if (VIR_ALLOC(req) < 0) {
        virReportOOMError();
        goto err_no_req;
    }

    ht = virNWFilterHashTableCreate(0);
    if (ht == NULL) {
        virReportOOMError();
        goto err_free_req;
    }

    if (virNWFilterHashTablePutAll(filterparams, ht) < 0)
        goto err_free_ht;

    req->filtername = strdup(filtername);
    if (req->filtername == NULL) {
        virReportOOMError();
        goto err_free_ht;
    }

    if (virStrcpyStatic(req->ifname, ifname) == NULL) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Destination buffer for ifname ('%s') "
                               "not large enough"), ifname);
        goto err_free_ht;
    }

    if (linkdev) {
        if (virStrcpyStatic(req->linkdev, linkdev) == NULL) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Destination buffer for linkdev ('%s') "
                                   "not large enough"), linkdev);
            goto err_free_ht;
        }
    }

    req->ifindex = ifindex;
    req->nettype = nettype;
    memcpy(req->macaddr, macaddr, sizeof(req->macaddr));
    req->driver = driver;
    req->filterparams = ht;
    ht = NULL;
    req->howDetect = howDetect;
    req->techdriver = techdriver;

    rc = virNWFilterRegisterLearnReq(req);

    if (rc < 0)
        goto err_free_req;

    if (pthread_create(&req->thread,
                       NULL,
                       learnIPAddressThread,
                       req) != 0)
        goto err_dereg_req;

    return 0;

err_dereg_req:
    virNWFilterDeregisterLearnReq(ifindex);
err_free_ht:
    virNWFilterHashTableFree(ht);
err_free_req:
    virNWFilterIPAddrLearnReqFree(req);
err_no_req:
    return -1;
}

#else

int
virNWFilterLearnIPAddress(virNWFilterTechDriverPtr techdriver ATTRIBUTE_UNUSED,
                          const char *ifname ATTRIBUTE_UNUSED,
                          int ifindex ATTRIBUTE_UNUSED,
                          const char *linkdev ATTRIBUTE_UNUSED,
                          enum virDomainNetType nettype ATTRIBUTE_UNUSED,
                          const unsigned char *macaddr ATTRIBUTE_UNUSED,
                          const char *filtername ATTRIBUTE_UNUSED,
                          virNWFilterHashTablePtr filterparams ATTRIBUTE_UNUSED,
                          virNWFilterDriverStatePtr driver ATTRIBUTE_UNUSED,
                          enum howDetect howDetect ATTRIBUTE_UNUSED) {
    virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("IP parameter must be given since libvirt "
                             "was not compiled with IP address learning "
                             "support"));
    return -1;
}
#endif /* HAVE_LIBPCAP */


/**
 * virNWFilterLearnInit
 * Initialization of this layer
 */
int
virNWFilterLearnInit(void) {

    if (pendingLearnReq)
        return 0;

    threadsTerminate = false;

    pendingLearnReq = virHashCreate(0, freeLearnReqEntry);
    if (!pendingLearnReq) {
        return -1;
    }

    if (virMutexInit(&pendingLearnReqLock) < 0) {
        virNWFilterLearnShutdown();
        return -1;
    }

    ipAddressMap = virNWFilterHashTableCreate(0);
    if (!ipAddressMap) {
        virReportOOMError();
        virNWFilterLearnShutdown();
        return -1;
    }

    if (virMutexInit(&ipAddressMapLock) < 0) {
        virNWFilterLearnShutdown();
        return -1;
    }

    ifaceLockMap = virHashCreate(0, freeIfaceLock);
    if (!ifaceLockMap) {
        virNWFilterLearnShutdown();
        return -1;
    }

    if (virMutexInit(&ifaceMapLock) < 0) {
        virNWFilterLearnShutdown();
        return -1;
    }

    return 0;
}


void
virNWFilterLearnThreadsTerminate(bool allowNewThreads) {
    threadsTerminate = true;

    while (virHashSize(pendingLearnReq) != 0)
        usleep((PKT_TIMEOUT_MS * 1000) / 3);

    if (allowNewThreads)
        threadsTerminate = false;
}

/**
 * virNWFilterLearnShutdown
 * Shutdown of this layer
 */
void
virNWFilterLearnShutdown(void)
{
    if (!pendingLearnReq)
        return;

    virNWFilterLearnThreadsTerminate(false);

    virHashFree(pendingLearnReq);
    pendingLearnReq = NULL;

    virNWFilterHashTableFree(ipAddressMap);
    ipAddressMap = NULL;

    virHashFree(ifaceLockMap);
    ifaceLockMap = NULL;
}
