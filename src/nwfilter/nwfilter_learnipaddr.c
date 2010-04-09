/*
 * nwfilter_learnipaddr.c: support for learning IP address used by a VM
 *                         on an interface
 *
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

#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "threads.h"
#include "conf/nwfilter_params.h"
#include "conf/domain_conf.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER


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
    virMutexLock(&pendingLearnReqLock);

    if (!virHashLookup(pendingLearnReq, req->ifname))
        res = virHashAddEntry(pendingLearnReq, req->ifname, req);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}

#endif


virNWFilterIPAddrLearnReqPtr
virNWFilterLookupLearnReq(const char *ifname) {
    void *res;

    virMutexLock(&pendingLearnReqLock);

    res = virHashLookup(pendingLearnReq, ifname);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}


static void
freeLearnReqEntry(void *payload, const char *name ATTRIBUTE_UNUSED) {
    virNWFilterIPAddrLearnReqFree(payload);
}


#ifdef HAVE_LIBPCAP

static virNWFilterIPAddrLearnReqPtr
virNWFilterDeregisterLearnReq(const char *ifname) {
    virNWFilterIPAddrLearnReqPtr res;

    virMutexLock(&pendingLearnReqLock);

    res = virHashLookup(pendingLearnReq, ifname);

    if (res)
        virHashRemoveEntry(pendingLearnReq, ifname, NULL);

    virMutexUnlock(&pendingLearnReqLock);

    return res;
}



static int
virNWFilterAddIpAddrForIfname(const char *ifname, char *addr) {
    int ret;

    virMutexLock(&ipAddressMapLock);

    ret = virNWFilterHashTablePut(ipAddressMap, ifname, addr, 1);

    virMutexUnlock(&ipAddressMapLock);

    return ret;
}
#endif


void
virNWFilterDelIpAddrForIfname(const char *ifname) {

    virMutexLock(&ipAddressMapLock);

    if (virHashLookup(ipAddressMap->hashTable, ifname))
        virNWFilterHashTableRemoveEntry(ipAddressMap, ifname);

    virMutexUnlock(&ipAddressMapLock);
}


const char *
virNWFilterGetIpAddrForIfname(const char *ifname) {
    const char *res;

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

        case 28: /* Broadcast address */
            if (dhcp_opts_len >= 6) {
                uint32_t *tmp = (uint32_t *)&dhcpopt->value;
                (*bcastaddr) = ntohl(*tmp);
            }
        break;

        case 53: /* Message type */
            if (dhcp_opts_len >= 3) {
                uint8_t *val = (uint8_t *)&dhcpopt->value;
                switch (*val) {
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
    pcap_t *handle;
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
    int to_ms = (strlen(req->linkdev) != 0) ? 1000
                                            : 0;
    int dhcp_opts_len;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *filter= NULL;
    uint16_t etherType;
    enum howDetect howDetected = 0;

    req->status = 0;

    handle = pcap_open_live(listen_if, BUFSIZ, 0, to_ms, errbuf);

    if (handle == NULL) {
        VIR_DEBUG("Couldn't open device %s: %s\n", listen_if, errbuf);
        req->status = ENODEV;
        goto done;
    }

    virFormatMacAddr(req->macaddr, macaddr);

    switch (req->howDetect) {
    case DETECT_DHCP:
        virBufferVSprintf(&buf, " ether dst %s"
                                " and src port 67 and dst port 68",
                          macaddr);
        break;
    default:
        virBufferVSprintf(&buf, "ether host %s", macaddr);
    }

    if (virBufferError(&buf)) {
        req->status = ENOMEM;
        goto done;
    }

    filter = virBufferContentAndReset(&buf);

    if (pcap_compile(handle, &fp, filter, 1, 0) != 0 ||
        pcap_setfilter(handle, &fp) != 0) {
        VIR_DEBUG("Couldn't compile or set filter '%s'.\n", filter);
        req->status = EINVAL;
        goto done;
    }

    while (req->status == 0 && vmaddr == 0) {
        packet = pcap_next(handle, &header);

        if (!packet) {
            if (to_ms == 0) {
                /* assuming IF disappeared */
                req->status = ENODEV;
                break;
            }
            /* listening on linkdev, check whether VM's dev is still there */
            if (checkIf(req->ifname, req->macaddr)) {
                req->status = ENODEV;
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
                // packets from the VM

                if (etherType == ETHERTYPE_IP &&
                    (header.len >= ethHdrSize +
                                   sizeof(struct iphdr))) {
                    struct iphdr *iphdr = (struct iphdr*)(packet +
                                                          ethHdrSize);
                    vmaddr = iphdr->saddr;
                    // skip eth. bcast and mcast addresses,
                    // and zero address in DHCP Requests
                    if ((ntohl(vmaddr) & 0xc0000000) || vmaddr == 0) {
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
                // packets to the VM
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

    ebtablesRemoveBasicRules(req->ifname);

    if (req->status == 0) {
        int ret;
        char inetaddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &vmaddr, inetaddr, sizeof(inetaddr));

        virNWFilterAddIpAddrForIfname(req->ifname, strdup(inetaddr));

        ret = virNWFilterInstantiateFilterLate(NULL,
                                               req->ifname,
                                               req->linkdev,
                                               req->nettype,
                                               req->macaddr,
                                               req->filtername,
                                               req->filterparams,
                                               req->driver);
        VIR_DEBUG("Result from applying firewall rules on "
                  "%s with IP addr %s : %d\n", req->ifname, inetaddr, ret);
    }

    memset(&req->thread, 0x0, sizeof(req->thread));

    VIR_DEBUG("pcap thread terminating for interface %s\n",req->ifname);

    virNWFilterDeregisterLearnReq(req->ifname);

    virNWFilterIPAddrLearnReqFree(req);

    return 0;
}


/**
 * virNWFilterLearnIPAddress
 * @conn: pointer to virConnect object
 * @ifname: the name of the interface
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
virNWFilterLearnIPAddress(const char *ifname,
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
        return 1;

    if (VIR_ALLOC(req) < 0) {
        virReportOOMError();
        goto err_no_req;
    }

    ht = virNWFilterHashTableCreate(0);
    if (ht == NULL) {
        virReportOOMError();
        goto err_no_ht;
    }

    if (virNWFilterHashTablePutAll(filterparams, ht))
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
    req->nettype = nettype;
    memcpy(req->macaddr, macaddr, sizeof(req->macaddr));
    req->driver = driver;
    req->filterparams = ht;
    ht = NULL;
    req->howDetect = howDetect;

    rc = virNWFilterRegisterLearnReq(req);

    if (rc)
        goto err_free_ht;

    switch (howDetect) {
    case DETECT_DHCP:
        if (ebtablesApplyDHCPOnlyRules(ifname,
                                       macaddr,
                                       NULL))
            goto err_free_ht;
        break;
    default:
        if (ebtablesApplyBasicRules(ifname,
                                    macaddr))
            goto err_free_ht;
    }


    if (pthread_create(&req->thread,
                       NULL,
                       learnIPAddressThread,
                       req) != 0)
        goto err_remove_rules;

    return 0;

err_remove_rules:
    ebtablesRemoveBasicRules(ifname);
err_free_ht:
    virNWFilterHashTableFree(ht);
err_no_ht:
    virNWFilterIPAddrLearnReqFree(req);
err_no_req:
    return 1;
}

#else

int
virNWFilterLearnIPAddress(const char *ifname ATTRIBUTE_UNUSED,
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
    return 1;
}
#endif /* HAVE_LIBPCAP */


/**
 * virNWFilterLearnInit
 * Initialization of this layer
 */
int
virNWFilterLearnInit(void) {
    pendingLearnReq = virHashCreate(0);
    if (!pendingLearnReq) {
        virReportOOMError();
        return 1;
    }

    if (virMutexInit(&pendingLearnReqLock)) {
        virNWFilterLearnShutdown();
        return 1;
    }

    ipAddressMap = virNWFilterHashTableCreate(0);
    if (!ipAddressMap) {
        virReportOOMError();
        virNWFilterLearnShutdown();
        return 1;
    }

    if (virMutexInit(&ipAddressMapLock)) {
        virNWFilterLearnShutdown();
        return 1;
    }

    return 0;
}


/**
 * virNWFilterLearnShutdown
 * Shutdown of this layer
 */
void
virNWFilterLearnShutdown(void) {
    virHashFree(pendingLearnReq, freeLearnReqEntry);
    pendingLearnReq = NULL;

    virNWFilterHashTableFree(ipAddressMap);
    ipAddressMap = NULL;
}
