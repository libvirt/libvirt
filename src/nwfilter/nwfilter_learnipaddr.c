/*
 * nwfilter_learnipaddr.c: support for learning IP address used by a VM
 *                         on an interface
 *
 * Copyright (C) 2011, 2013, 2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef WITH_LIBPCAP
# include <pcap.h>
#endif

#include <fcntl.h>
#include <sys/ioctl.h>
#include <poll.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include "internal.h"

#include "virbuffer.h"
#include "virlog.h"
#include "virnetdev.h"
#include "virerror.h"
#include "virthread.h"
#include "conf/nwfilter_params.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ipaddrmap.h"
#include "nwfilter_learnipaddr.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_learnipaddr");

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


static virMutex pendingLearnReqLock = VIR_MUTEX_INITIALIZER;
static GHashTable *pendingLearnReq;

static virMutex ifaceMapLock = VIR_MUTEX_INITIALIZER;
static GHashTable *ifaceLockMap;

typedef struct _virNWFilterIfaceLock virNWFilterIfaceLock;
struct _virNWFilterIfaceLock {
    char ifname[IF_NAMESIZE];
    virMutex lock;
    int refctr;
};

typedef struct _virNWFilterIPAddrLearnReq virNWFilterIPAddrLearnReq;
struct _virNWFilterIPAddrLearnReq {
    virNWFilterTechDriver *techdriver;
    int ifindex;
    virNWFilterBindingDef *binding;
    virNWFilterDriverState *driver;
    int howDetect; /* bitmask of enum howDetect */

    int status;
    volatile bool terminate;
};


static bool threadsTerminate;


int
virNWFilterLockIface(const char *ifname)
{
    virNWFilterIfaceLock *ifaceLock = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&ifaceMapLock) {
        ifaceLock = virHashLookup(ifaceLockMap, ifname);

        if (!ifaceLock) {
            ifaceLock = g_new0(virNWFilterIfaceLock, 1);

            if (virMutexInitRecursive(&ifaceLock->lock) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("mutex initialization failed"));
                g_free(ifaceLock);
                return -1;
            }

            if (virStrcpyStatic(ifaceLock->ifname, ifname) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("interface name %1$s does not fit into buffer"),
                               ifaceLock->ifname);
                g_free(ifaceLock);
                return -1;
            }

            while (virHashAddEntry(ifaceLockMap, ifname, ifaceLock)) {
                g_free(ifaceLock);
                return -1;
            }

            ifaceLock->refctr = 0;
        }

        ifaceLock->refctr++;
    }

    virMutexLock(&ifaceLock->lock);

    return 0;
}


void
virNWFilterUnlockIface(const char *ifname)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&ifaceMapLock);
    virNWFilterIfaceLock *ifaceLock = virHashLookup(ifaceLockMap, ifname);

    if (ifaceLock) {
        virMutexUnlock(&ifaceLock->lock);

        ifaceLock->refctr--;
        if (ifaceLock->refctr == 0)
            virHashRemoveEntry(ifaceLockMap, ifname);
    }
}


static void
virNWFilterIPAddrLearnReqFree(virNWFilterIPAddrLearnReq *req)
{
    if (!req)
        return;

    virNWFilterBindingDefFree(req->binding);

    g_free(req);
}


#if WITH_LIBPCAP

static int
virNWFilterRegisterLearnReq(virNWFilterIPAddrLearnReq *req)
{
    g_autofree char *ifindex_str = g_strdup_printf("%d", req->ifindex);
    VIR_LOCK_GUARD lock = virLockGuardLock(&pendingLearnReqLock);

    if (virHashLookup(pendingLearnReq, ifindex_str))
        return -1;

    return virHashAddEntry(pendingLearnReq, ifindex_str, req);
}


#endif

int
virNWFilterTerminateLearnReq(const char *ifname)
{
    int ifindex;
    g_autofree char *ifindex_str = NULL;

    /* It's possible that it's already been removed as a result of
     * virNWFilterDeregisterLearnReq during learnIPAddressThread() exit
     */
    if (virNetDevExists(ifname) != 1) {
        virResetLastError();
        return 0;
    }

    if (virNetDevGetIndex(ifname, &ifindex) < 0) {
        virResetLastError();
        return -1;
    }

    ifindex_str = g_strdup_printf("%d", ifindex);

    VIR_WITH_MUTEX_LOCK_GUARD(&pendingLearnReqLock) {
        virNWFilterIPAddrLearnReq *req;
        if ((req = virHashLookup(pendingLearnReq, ifindex_str))) {
            req->terminate = true;
            return 0;
        }
    }

    return -1;
}


bool
virNWFilterHasLearnReq(int ifindex)
{
    g_autofree char *ifindex_str = g_strdup_printf("%d", ifindex);
    VIR_LOCK_GUARD lock = virLockGuardLock(&pendingLearnReqLock);

    return virHashLookup(pendingLearnReq, ifindex_str) != NULL;
}


static void
freeLearnReqEntry(void *payload)
{
    virNWFilterIPAddrLearnReqFree(payload);
}


#ifdef WITH_LIBPCAP

static virNWFilterIPAddrLearnReq *
virNWFilterDeregisterLearnReq(int ifindex)
{
    g_autofree char *ifindex_str = g_strdup_printf("%d", ifindex);
    VIR_LOCK_GUARD lock = virLockGuardLock(&pendingLearnReqLock);

    return virHashSteal(pendingLearnReq, ifindex_str);
}

#endif

#ifdef WITH_LIBPCAP

static void
procDHCPOpts(struct dhcp *dhcp, int dhcp_opts_len,
             uint32_t *vmaddr, uint32_t *bcastaddr,
             enum howDetect *howDetected)
{
    struct dhcp_option *dhcpopt = &dhcp->options[0];

    while (dhcp_opts_len >= 2) {

        switch (dhcpopt->code) {

        case DHCP_OPT_BCASTADDRESS: /* Broadcast address */
            if (dhcp_opts_len >= 6) {
                VIR_WARNINGS_NO_CAST_ALIGN
                uint32_t *tmp = (uint32_t *)&dhcpopt->value;
                VIR_WARNINGS_RESET
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
static void
learnIPAddressThread(void *arg)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = NULL;
    struct bpf_program fp;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header ether_hdr;
    struct ether_vlan_header *vlan_hdr;
    virNWFilterIPAddrLearnReq *req = arg;
    uint32_t vmaddr = 0, bcastaddr = 0;
    unsigned int ethHdrSize;
    char *listen_if = (req->binding->linkdevname ?
                       req->binding->linkdevname :
                       req->binding->portdevname);
    int dhcp_opts_len;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *filter = NULL;
    uint16_t etherType;
    bool showError = true;
    enum howDetect howDetected = 0;
    virNWFilterTechDriver *techdriver = req->techdriver;
    struct pollfd fds[1];

    if (virNWFilterLockIface(req->binding->portdevname) < 0)
       goto err_no_lock;

    req->status = 0;

    /* anything change to the VM's interface -- check at least once */
    if (virNetDevValidateConfig(req->binding->portdevname, NULL, req->ifindex) <= 0) {
        virResetLastError();
        req->status = ENODEV;
        goto cleanup;
    }

    handle = pcap_open_live(listen_if, BUFSIZ, 0, PKT_TIMEOUT_MS, errbuf);

    if (handle == NULL) {
        VIR_DEBUG("Couldn't open device %s: %s", listen_if, errbuf);
        req->status = ENODEV;
        goto cleanup;
    }

    fds[0].fd = pcap_fileno(handle);
    fds[0].events = POLLIN | POLLERR;

    virMacAddrFormat(&req->binding->mac, macaddr);

    if (req->howDetect == DETECT_DHCP) {
        if (techdriver->applyDHCPOnlyRules(req->binding->portdevname,
                                           &req->binding->mac,
                                           NULL, false) < 0) {
            VIR_DEBUG("Unable to apply DHCP only rules");
            req->status = EINVAL;
            goto cleanup;
        }
        virBufferAddLit(&buf, "src port 67 and dst port 68");
    } else {
        if (techdriver->applyBasicRules(req->binding->portdevname,
                                        &req->binding->mac) < 0) {
            VIR_DEBUG("Unable to apply basic rules");
            req->status = EINVAL;
            goto cleanup;
        }
        virBufferAsprintf(&buf, "ether host %s or ether dst ff:ff:ff:ff:ff:ff",
                          macaddr);
    }

    filter = virBufferContentAndReset(&buf);

    if (pcap_compile(handle, &fp, filter, 1, 0) != 0) {
        VIR_DEBUG("Couldn't compile filter '%s'", filter);
        req->status = EINVAL;
        goto cleanup;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        VIR_DEBUG("Couldn't set filter '%s'", filter);
        req->status = EINVAL;
        pcap_freecode(&fp);
        goto cleanup;
    }

    pcap_freecode(&fp);

    while (req->status == 0 && vmaddr == 0) {
        int n = poll(fds, G_N_ELEMENTS(fds), PKT_TIMEOUT_MS);

        if (threadsTerminate || req->terminate) {
            req->status = ECANCELED;
            showError = false;
            break;
        }

        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            req->status = errno;
            showError = true;
            break;
        }

        if (n == 0)
            continue;

        if (fds[0].revents & (POLLHUP | POLLERR)) {
            VIR_DEBUG("Error from FD probably dev deleted");
            req->status = ENODEV;
            showError = false;
            break;
        }

        packet = pcap_next(handle, &header);

        if (!packet) {
            /* Again, already handled above, but lets be sure */
            if (virNetDevValidateConfig(req->binding->portdevname, NULL, req->ifindex) <= 0) {
                virResetLastError();
                req->status = ENODEV;
                showError = false;
                break;
            }
            continue;
        }

        if (header.len >= sizeof(struct ether_header)) {
            /* Avoid alignment issues */
            memcpy(&ether_hdr, packet, sizeof(struct ether_header));

            switch (ntohs(ether_hdr.ether_type)) {

            case ETHERTYPE_IP:
                ethHdrSize = sizeof(struct ether_header);
                etherType = ntohs(ether_hdr.ether_type);
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

            if (virMacAddrCmpRaw(&req->binding->mac, ether_hdr.ether_shost) == 0) {
                /* packets from the VM */

                if (etherType == ETHERTYPE_IP &&
                    (header.len >= ethHdrSize +
                                   sizeof(struct iphdr))) {
                    VIR_WARNINGS_NO_CAST_ALIGN
                    struct iphdr *iphdr = (struct iphdr*)(packet +
                                                          ethHdrSize);
                    VIR_WARNINGS_RESET
                    vmaddr = iphdr->saddr;
                    /* skip mcast addresses (224.0.0.0 - 239.255.255.255),
                     * class E (240.0.0.0 - 255.255.255.255, includes eth.
                     * bcast) and zero address in DHCP Requests */
                    if ((ntohl(vmaddr) & 0xe0000000) == 0xe0000000 ||
                        vmaddr == 0) {
                        vmaddr = 0;
                        continue;
                    }

                    howDetected = DETECT_STATIC;
                } else if (etherType == ETHERTYPE_ARP &&
                           (header.len >= ethHdrSize +
                                          sizeof(struct f_arphdr))) {
                    VIR_WARNINGS_NO_CAST_ALIGN
                    struct f_arphdr *arphdr = (struct f_arphdr*)(packet +
                                                         ethHdrSize);
                    VIR_WARNINGS_RESET
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
            } else if (virMacAddrCmpRaw(&req->binding->mac,
                                        ether_hdr.ether_dhost) == 0 ||
                       /* allow Broadcast replies from DHCP server */
                       virMacAddrIsBroadcastRaw(ether_hdr.ether_dhost)) {
                /* packets to the VM */
                if (etherType == ETHERTYPE_IP &&
                    (header.len >= ethHdrSize +
                                   sizeof(struct iphdr))) {
                    VIR_WARNINGS_NO_CAST_ALIGN
                    struct iphdr *iphdr = (struct iphdr*)(packet +
                                                          ethHdrSize);
                    VIR_WARNINGS_RESET
                    if ((iphdr->protocol == IPPROTO_UDP) &&
                        (header.len >= ethHdrSize +
                                       iphdr->ihl * 4 +
                                       sizeof(struct udphdr))) {
                        VIR_WARNINGS_NO_CAST_ALIGN
                        struct udphdr *udphdr = (struct udphdr *)
                                          ((char *)iphdr + iphdr->ihl * 4);
                        VIR_WARNINGS_RESET
                        if (ntohs(udphdr->source) == 67 &&
                            ntohs(udphdr->dest)   == 68 &&
                            header.len >= ethHdrSize +
                                          iphdr->ihl * 4 +
                                          sizeof(struct udphdr) +
                                          sizeof(struct dhcp)) {
                            struct dhcp *dhcp = (struct dhcp *)
                                        ((char *)udphdr + sizeof(udphdr));
                            if (dhcp->op == 2 /* BOOTREPLY */ &&
                                virMacAddrCmpRaw(
                                        &req->binding->mac,
                                        &dhcp->chaddr[0]) == 0) {
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

 cleanup:
    if (handle)
        pcap_close(handle);

    if (req->status == 0) {
        g_autofree char *inetaddr = NULL;
        int ret;
        virSocketAddr sa;
        sa.len = sizeof(sa.data.inet4);
        sa.data.inet4.sin_family = AF_INET;
        sa.data.inet4.sin_addr.s_addr = vmaddr;

        /* It is necessary to unlock interface here to avoid updateMutex and
         * interface ordering deadlocks. Otherwise we are going to
         * instantiate the filter, which will try to lock updateMutex, and
         * some other thread instantiating a filter in parallel is holding
         * updateMutex and is trying to lock interface, both will deadlock.
         * Also it is safe to unlock interface here because we stopped
         * capturing and applied necessary rules on the interface, while
         * instantiating a new filter doesn't require a locked interface.*/
        virNWFilterUnlockIface(req->binding->portdevname);

        if ((inetaddr = virSocketAddrFormat(&sa)) != NULL) {
            if (virNWFilterIPAddrMapAddIPAddr(req->binding->portdevname, inetaddr) < 0) {
                VIR_ERROR(_("Failed to add IP address %1$s to IP address cache for interface %2$s"),
                          inetaddr, req->binding->portdevname);
            }

            ret = virNWFilterInstantiateFilterLate(req->driver,
                                                   req->binding,
                                                   req->ifindex);
            VIR_DEBUG("Result from applying firewall rules on "
                      "%s with IP addr %s : %d", req->binding->portdevname, inetaddr, ret);
        }
    } else {
        if (showError)
            virReportSystemError(req->status,
                                 _("encountered an error on interface %1$s index %2$d"),
                                 req->binding->portdevname, req->ifindex);

        techdriver->applyDropAllRules(req->binding->portdevname);
        virNWFilterUnlockIface(req->binding->portdevname);
    }

    VIR_DEBUG("pcap thread terminating for interface %s", req->binding->portdevname);


 err_no_lock:
    virNWFilterDeregisterLearnReq(req->ifindex);

    virNWFilterIPAddrLearnReqFree(req);
}


/**
 * virNWFilterLearnIPAddress
 * @techdriver : driver to build firewalls
 * @binding: the network port binding information
 * @ifindex: the index of the interface
 * @driver : the network filter driver
 * @howDetect : the method on how the thread is supposed to detect the
 *              IP address; bitmask of "enum howDetect" flags.
 *
 * Instruct to learn the IP address being used on a given interface (ifname).
 * Unless there already is a thread attempting to learn the IP address
 * being used on the interface, a thread is started that will listen on
 * the traffic being sent on the interface (or link device) with the
 * MAC address that is provided. Will then launch the application of the
 * firewall rules on the interface.
 */
int
virNWFilterLearnIPAddress(virNWFilterTechDriver *techdriver,
                          virNWFilterBindingDef *binding,
                          int ifindex,
                          virNWFilterDriverState *driver,
                          int howDetect)
{
    int rc;
    virThread thread;
    virNWFilterIPAddrLearnReq *req = NULL;

    if (howDetect == 0)
        return -1;

    if (!techdriver->canApplyBasicRules()) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("IP parameter must be provided since snooping the IP address does not work possibly due to missing tools"));
        return -1;
    }

    req = g_new0(virNWFilterIPAddrLearnReq, 1);

    if (!(req->binding = virNWFilterBindingDefCopy(binding)))
        goto err_free_req;

    req->ifindex = ifindex;
    req->driver = driver;
    req->howDetect = howDetect;
    req->techdriver = techdriver;

    rc = virNWFilterRegisterLearnReq(req);

    if (rc < 0)
        goto err_free_req;

    if (virThreadCreateFull(&thread,
                            false,
                            learnIPAddressThread,
                            "ip-learn",
                            false,
                            req) != 0)
        goto err_dereg_req;

    return 0;

 err_dereg_req:
    virNWFilterDeregisterLearnReq(ifindex);
 err_free_req:
    virNWFilterIPAddrLearnReqFree(req);
    return -1;
}

#else

int
virNWFilterLearnIPAddress(virNWFilterTechDriver *techdriver G_GNUC_UNUSED,
                          virNWFilterBindingDef *binding G_GNUC_UNUSED,
                          int ifindex G_GNUC_UNUSED,
                          virNWFilterDriverState *driver G_GNUC_UNUSED,
                          int howDetect G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("IP parameter must be given since libvirt was not compiled with IP address learning support"));
    return -1;
}
#endif /* WITH_LIBPCAP */


/**
 * virNWFilterLearnInit
 * Initialization of this layer
 */
int
virNWFilterLearnInit(void)
{
    if (pendingLearnReq)
        return 0;

    VIR_DEBUG("Initializing IP address learning");
    threadsTerminate = false;
    pendingLearnReq = virHashNew(freeLearnReqEntry);
    ifaceLockMap = virHashNew(g_free);

    return 0;
}


void
virNWFilterLearnThreadsTerminate(bool allowNewThreads)
{
    threadsTerminate = true;

    while (virHashSize(pendingLearnReq) != 0)
        g_usleep((PKT_TIMEOUT_MS * 1000) / 3);

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

    g_clear_pointer(&pendingLearnReq, g_hash_table_unref);
    g_clear_pointer(&ifaceLockMap, g_hash_table_unref);
}
