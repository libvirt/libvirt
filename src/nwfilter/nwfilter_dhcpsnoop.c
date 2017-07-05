/*
 * nwfilter_dhcpsnoop.c: support for DHCP snooping used by a VM
 *                       on an interface
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
 * Copyright (C) 2011,2012 IBM Corp.
 *
 * Authors:
 *    David L Stevens <dlstevens@us.ibm.com>
 *    Stefan Berger <stefanb@linux.vnet.ibm.com>
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
 * Based in part on work by Stefan Berger <stefanb@us.ibm.com>
 */

/*
 * Note about testing:
 *   On the host run in a shell:
 *      while :; do kill -SIGHUP `pidof libvirtd`; echo "HUP $RANDOM"; sleep 20; done
 *
 *   Inside a couple of VMs that for example use the 'clean-traffic' filter:
 *      while :; do kill -SIGTERM `pidof dhclient`; dhclient eth0; ifconfig eth0; done
 *
 *   On the host check the lease file and that it's periodically shortened:
 *      cat /var/run/libvirt/network/nwfilter.leases; date +%s
 *
 *   On the host also check that the ebtables rules 'look' ok:
 *      ebtables -t nat -L
 */
#include <config.h>

#ifdef HAVE_LIBPCAP
# include <pcap.h>
#endif

#include <fcntl.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>

#include "viralloc.h"
#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "conf/domain_conf.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_ipaddrmap.h"
#include "virnetdev.h"
#include "virfile.h"
#include "viratomic.h"
#include "virsocketaddr.h"
#include "virthreadpool.h"
#include "configmake.h"
#include "virtime.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_dhcpsnoop");

#ifdef HAVE_LIBPCAP

# define LEASEFILE_DIR LOCALSTATEDIR "/run/libvirt/network/"
# define LEASEFILE LEASEFILE_DIR "nwfilter.leases"
# define TMPLEASEFILE LEASEFILE_DIR "nwfilter.ltmp"

struct virNWFilterSnoopState {
    /* lease file */
    int                  leaseFD;
    int                  nLeases; /* number of active leases */
    int                  wLeases; /* number of written leases */
    int                  nThreads; /* number of running threads */
    /* thread management */
    virHashTablePtr      snoopReqs;
    virHashTablePtr      ifnameToKey;
    virMutex             snoopLock;  /* protects SnoopReqs and IfNameToKey */
    virHashTablePtr      active;
    virMutex             activeLock; /* protects Active */
};

# define virNWFilterSnoopLock() \
    do { \
        virMutexLock(&virNWFilterSnoopState.snoopLock); \
    } while (0)
# define virNWFilterSnoopUnlock() \
    do { \
        virMutexUnlock(&virNWFilterSnoopState.snoopLock); \
    } while (0)
# define virNWFilterSnoopActiveLock() \
    do { \
        virMutexLock(&virNWFilterSnoopState.activeLock); \
    } while (0)
# define virNWFilterSnoopActiveUnlock() \
    do { \
        virMutexUnlock(&virNWFilterSnoopState.activeLock); \
    } while (0)

# define VIR_IFKEY_LEN   ((VIR_UUID_STRING_BUFLEN) + (VIR_MAC_STRING_BUFLEN))

typedef struct _virNWFilterSnoopReq virNWFilterSnoopReq;
typedef virNWFilterSnoopReq *virNWFilterSnoopReqPtr;

typedef struct _virNWFilterSnoopIPLease virNWFilterSnoopIPLease;
typedef virNWFilterSnoopIPLease *virNWFilterSnoopIPLeasePtr;

typedef enum {
    THREAD_STATUS_NONE,
    THREAD_STATUS_OK,
    THREAD_STATUS_FAIL,
} virNWFilterSnoopThreadStatus;

struct _virNWFilterSnoopReq {
    /*
     * reference counter: while the req is on the
     * publicSnoopReqs hash, the refctr may only
     * be modified with the SnoopLock held
     */
    int                                  refctr;

    virNWFilterTechDriverPtr             techdriver;
    char                                *ifname;
    int                                  ifindex;
    char                                *linkdev;
    char                                 ifkey[VIR_IFKEY_LEN];
    virMacAddr                           macaddr;
    char                                *filtername;
    virNWFilterHashTablePtr              vars;
    virNWFilterDriverStatePtr            driver;
    /* start and end of lease list, ordered by lease time */
    virNWFilterSnoopIPLeasePtr           start;
    virNWFilterSnoopIPLeasePtr           end;
    char                                *threadkey;

    virNWFilterSnoopThreadStatus         threadStatus;
    virCond                              threadStatusCond;

    int                                  jobCompletionStatus;
    /* the number of submitted jobs in the worker's queue */
    /*
     * protect those members that can change while the
     * req is on the public SnoopReq hash and
     * at least one reference is held:
     * - ifname
     * - threadkey
     * - start
     * - end
     * - a lease while it is on the list
     * - threadStatus
     * (for refctr, see above)
     */
    virMutex                             lock;
};

/*
 * Note about lock-order:
 * 1st: virNWFilterSnoopLock()
 * 2nd: virNWFilterSnoopReqLock(req)
 *
 * Rationale: Former protects the SnoopReqs hash, latter its contents
 */

struct _virNWFilterSnoopIPLease {
    virSocketAddr              ipAddress;
    virSocketAddr              ipServer;
    virNWFilterSnoopReqPtr     snoopReq;
    unsigned int               timeout;
    /* timer list */
    virNWFilterSnoopIPLeasePtr prev;
    virNWFilterSnoopIPLeasePtr next;
};

typedef struct _virNWFilterSnoopEthHdr virNWFilterSnoopEthHdr;
typedef virNWFilterSnoopEthHdr *virNWFilterSnoopEthHdrPtr;

struct _virNWFilterSnoopEthHdr {
    virMacAddr eh_dst;
    virMacAddr eh_src;
    uint16_t eh_type;
    uint8_t eh_data[];
} ATTRIBUTE_PACKED;

typedef struct _virNWFilterSnoopDHCPHdr virNWFilterSnoopDHCPHdr;
typedef virNWFilterSnoopDHCPHdr *virNWFilterSnoopDHCPHdrPtr;

struct _virNWFilterSnoopDHCPHdr {
    uint8_t   d_op;
    uint8_t   d_htype;
    uint8_t   d_hlen;
    uint8_t   d_hops;
    uint32_t  d_xid;
    uint16_t  d_secs;
    uint16_t  d_flags;
    uint32_t  d_ciaddr;
    uint32_t  d_yiaddr;
    uint32_t  d_siaddr;
    uint32_t  d_giaddr;
    uint8_t   d_chaddr[16];
    char      d_sname[64];
    char      d_file[128];
    uint8_t   d_opts[];
} ATTRIBUTE_PACKED;

/* DHCP options */

# define DHCPO_PAD         0
# define DHCPO_LEASE      51     /* lease time in secs */
# define DHCPO_MTYPE      53     /* message type */
# define DHCPO_END       255     /* end of options */

/* DHCP message types */
# define DHCPDECLINE     4
# define DHCPACK         5
# define DHCPRELEASE     7

# define MIN_VALID_DHCP_PKT_SIZE \
    (offsetof(virNWFilterSnoopEthHdr, eh_data) + \
     sizeof(struct udphdr) + \
     offsetof(virNWFilterSnoopDHCPHdr, d_opts))

# define PCAP_PBUFSIZE              576 /* >= IP/TCP/DHCP headers */
# define PCAP_READ_MAXERRS          25 /* retries on failing device */
# define PCAP_FLOOD_TIMEOUT_MS      10 /* ms */

typedef struct _virNWFilterDHCPDecodeJob virNWFilterDHCPDecodeJob;
typedef virNWFilterDHCPDecodeJob *virNWFilterDHCPDecodeJobPtr;

struct _virNWFilterDHCPDecodeJob {
    unsigned char packet[PCAP_PBUFSIZE];
    int caplen;
    bool fromVM;
    int *qCtr;
};

# define DHCP_PKT_RATE          10 /* pkts/sec */
# define DHCP_PKT_BURST         50 /* pkts/sec */
# define DHCP_BURST_INTERVAL_S  10 /* sec */

/*
 * libpcap 1.5 requires a 128kb buffer
 * 128 kb is bigger than (DHCP_PKT_BURST * PCAP_PBUFSIZE / 2)
 */
# define PCAP_BUFFERSIZE        (128 * 1024)

# define MAX_QUEUED_JOBS        (DHCP_PKT_BURST + 2 * DHCP_PKT_RATE)

typedef struct _virNWFilterSnoopRateLimitConf virNWFilterSnoopRateLimitConf;
typedef virNWFilterSnoopRateLimitConf *virNWFilterSnoopRateLimitConfPtr;

struct _virNWFilterSnoopRateLimitConf {
    time_t prev;
    unsigned int pkt_ctr;
    time_t burst;
    const unsigned int rate;
    const unsigned int burstRate;
    const unsigned int burstInterval;
};
# define SNOOP_POLL_MAX_TIMEOUT_MS  (10 * 1000) /* milliseconds */

typedef struct _virNWFilterSnoopPcapConf virNWFilterSnoopPcapConf;
typedef virNWFilterSnoopPcapConf *virNWFilterSnoopPcapConfPtr;

struct _virNWFilterSnoopPcapConf {
    pcap_t *handle;
    const pcap_direction_t dir;
    const char *filter;
    virNWFilterSnoopRateLimitConf rateLimit; /* indep. rate limiters */
    int qCtr; /* number of jobs in the worker's queue */
    const unsigned int maxQSize;
    unsigned long long penaltyTimeoutAbs;
};

/* local function prototypes */
static int virNWFilterSnoopReqLeaseDel(virNWFilterSnoopReqPtr req,
                                       virSocketAddrPtr ipaddr,
                                       bool update_leasefile,
                                       bool instantiate);

static void virNWFilterSnoopReqLock(virNWFilterSnoopReqPtr req);
static void virNWFilterSnoopReqUnlock(virNWFilterSnoopReqPtr req);

static void virNWFilterSnoopLeaseFileLoad(void);
static void virNWFilterSnoopLeaseFileSave(virNWFilterSnoopIPLeasePtr ipl);

/* local variables */
static struct virNWFilterSnoopState virNWFilterSnoopState = {
    .leaseFD = -1,
};

static const unsigned char dhcp_magic[4] = { 99, 130, 83, 99 };


static char *
virNWFilterSnoopActivate(virNWFilterSnoopReqPtr req)
{
    char *key;

    if (virAsprintf(&key, "%p-%d", req, req->ifindex) < 0)
        return NULL;

    virNWFilterSnoopActiveLock();

    if (virHashAddEntry(virNWFilterSnoopState.active, key, (void *)0x1) < 0)
        VIR_FREE(key);

    virNWFilterSnoopActiveUnlock();

    return key;
}

static void
virNWFilterSnoopCancel(char **threadKey)
{
    if (*threadKey == NULL)
        return;

    virNWFilterSnoopActiveLock();

    ignore_value(virHashRemoveEntry(virNWFilterSnoopState.active, *threadKey));
    VIR_FREE(*threadKey);

    virNWFilterSnoopActiveUnlock();
}

static bool
virNWFilterSnoopIsActive(char *threadKey)
{
    void *entry;

    if (threadKey == NULL)
        return 0;

    virNWFilterSnoopActiveLock();

    entry = virHashLookup(virNWFilterSnoopState.active, threadKey);

    virNWFilterSnoopActiveUnlock();

    return entry != NULL;
}

/*
 * virNWFilterSnoopListAdd - add an IP lease to a list
 */
static void
virNWFilterSnoopListAdd(virNWFilterSnoopIPLeasePtr plnew,
                        virNWFilterSnoopIPLeasePtr *start,
                        virNWFilterSnoopIPLeasePtr *end)
{
    virNWFilterSnoopIPLeasePtr pl;

    plnew->next = plnew->prev = NULL;

    if (!*start) {
        *start = *end = plnew;
        return;
    }

    for (pl = *end; pl && plnew->timeout < pl->timeout;
         pl = pl->prev)
        ; /* empty */

    if (!pl) {
        plnew->next = *start;
        *start = plnew;
    } else {
        plnew->next = pl->next;
        pl->next = plnew;
    }

    plnew->prev = pl;

    if (plnew->next)
        plnew->next->prev = plnew;
    else
        *end = plnew;
}

/*
 * virNWFilterSnoopListDel - remove an IP lease from a list
 */
static void
virNWFilterSnoopListDel(virNWFilterSnoopIPLeasePtr ipl,
                        virNWFilterSnoopIPLeasePtr *start,
                        virNWFilterSnoopIPLeasePtr *end)
{
    if (ipl->prev)
        ipl->prev->next = ipl->next;
    else
        *start = ipl->next;

    if (ipl->next)
        ipl->next->prev = ipl->prev;
    else
        *end = ipl->prev;

    ipl->next = ipl->prev = NULL;
}

/*
 * virNWFilterSnoopLeaseTimerAdd - add an IP lease to the timer list
 */
static void
virNWFilterSnoopIPLeaseTimerAdd(virNWFilterSnoopIPLeasePtr plnew)
{
    virNWFilterSnoopReqPtr req = plnew->snoopReq;

    /* protect req->start / req->end */
    virNWFilterSnoopReqLock(req);

    virNWFilterSnoopListAdd(plnew, &req->start, &req->end);

    virNWFilterSnoopReqUnlock(req);
}

/*
 * virNWFilterSnoopLeaseTimerDel - remove an IP lease from the timer list
 */
static void
virNWFilterSnoopIPLeaseTimerDel(virNWFilterSnoopIPLeasePtr ipl)
{
    virNWFilterSnoopReqPtr req = ipl->snoopReq;

    /* protect req->start / req->end */
    virNWFilterSnoopReqLock(req);

    virNWFilterSnoopListDel(ipl, &req->start, &req->end);

    virNWFilterSnoopReqUnlock(req);

    ipl->timeout = 0;
}

/*
 * virNWFilterSnoopInstallRule - install rule for a lease
 *
 * @instantiate: when calling this function in a loop, indicate
 *               the last call with 'true' here so that the
 *               rules all get instantiated
 *               Always calling this with 'true' is fine, but less
 *               efficient.
 */
static int
virNWFilterSnoopIPLeaseInstallRule(virNWFilterSnoopIPLeasePtr ipl,
                                   bool instantiate)
{
    char *ipaddr;
    int rc = -1;
    virNWFilterSnoopReqPtr req;

    ipaddr = virSocketAddrFormat(&ipl->ipAddress);
    if (!ipaddr)
        return -1;

    req = ipl->snoopReq;

    /* protect req->ifname */
    virNWFilterSnoopReqLock(req);

    if (virNWFilterIPAddrMapAddIPAddr(req->ifname, ipaddr) < 0)
        goto exit_snooprequnlock;

    /* ipaddr now belongs to the map */
    ipaddr = NULL;

    if (!instantiate) {
        rc = 0;
        goto exit_snooprequnlock;
    }

    /* instantiate the filters */

    if (req->ifname)
        rc = virNWFilterInstantiateFilterLate(req->driver,
                                              NULL,
                                              req->ifname,
                                              req->ifindex,
                                              req->linkdev,
                                              &req->macaddr,
                                              req->filtername,
                                              req->vars);

 exit_snooprequnlock:
    virNWFilterSnoopReqUnlock(req);

    VIR_FREE(ipaddr);

    return rc;
}

/*
 * virNWFilterSnoopIPLeaseUpdate - update the timeout on an IP lease
 */
static void
virNWFilterSnoopIPLeaseUpdate(virNWFilterSnoopIPLeasePtr ipl, time_t timeout)
{
    if (timeout < ipl->timeout)
        return;  /* no take-backs */

    virNWFilterSnoopIPLeaseTimerDel(ipl);
    ipl->timeout = timeout;
    virNWFilterSnoopIPLeaseTimerAdd(ipl);
}

/*
 * virNWFilterSnoopGetByIP - lookup IP lease by IP address
 */
static virNWFilterSnoopIPLeasePtr
virNWFilterSnoopIPLeaseGetByIP(virNWFilterSnoopIPLeasePtr start,
                               virSocketAddrPtr ipaddr)
{
    virNWFilterSnoopIPLeasePtr pl;

    for (pl = start;
         pl && !virSocketAddrEqual(&pl->ipAddress, ipaddr);
         pl = pl->next)
        ; /* empty */
    return pl;
}

/*
 * virNWFilterSnoopReqLeaseTimerRun - run the IP lease timeout list
 */
static unsigned int
virNWFilterSnoopReqLeaseTimerRun(virNWFilterSnoopReqPtr req)
{
    time_t now = time(0);
    bool is_last = false;

    /* protect req->start */
    virNWFilterSnoopReqLock(req);

    while (req->start && req->start->timeout <= now) {
        if (req->start->next == NULL ||
            req->start->next->timeout > now)
            is_last = true;
        virNWFilterSnoopReqLeaseDel(req, &req->start->ipAddress, true,
                                    is_last);
    }

    virNWFilterSnoopReqUnlock(req);

    return 0;
}

/*
 * Get a reference to the given Snoop request
 */
static void
virNWFilterSnoopReqGet(virNWFilterSnoopReqPtr req)
{
    virAtomicIntInc(&req->refctr);
}

/*
 * Create a new Snoop request. Initialize it with the given
 * interface key. The caller must release the request with a call
 * to virNWFilerSnoopReqPut(req).
 */
static virNWFilterSnoopReqPtr
virNWFilterSnoopReqNew(const char *ifkey)
{
    virNWFilterSnoopReqPtr req;

    if (ifkey == NULL || strlen(ifkey) != VIR_IFKEY_LEN - 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterSnoopReqNew called with invalid "
                         "key \"%s\" (%zu)"),
                       ifkey ? ifkey : "",
                       ifkey ? strlen(ifkey) : 0);
        return NULL;
    }

    if (VIR_ALLOC(req) < 0)
        return NULL;

    req->threadStatus = THREAD_STATUS_NONE;

    if (virStrcpyStatic(req->ifkey, ifkey) == NULL ||
        virMutexInitRecursive(&req->lock) < 0)
        goto err_free_req;

    if (virCondInit(&req->threadStatusCond) < 0)
        goto err_destroy_mutex;

    virNWFilterSnoopReqGet(req);

    return req;

 err_destroy_mutex:
    virMutexDestroy(&req->lock);

 err_free_req:
    VIR_FREE(req);

    return NULL;
}

/*
 * Free a snoop request unless it is still referenced.
 * All its associated leases are also freed.
 * The lease file is NOT rewritten.
 */
static void
virNWFilterSnoopReqFree(virNWFilterSnoopReqPtr req)
{
    virNWFilterSnoopIPLeasePtr ipl;

    if (!req)
        return;

    if (virAtomicIntGet(&req->refctr) != 0)
        return;

    /* free all leases */
    for (ipl = req->start; ipl; ipl = req->start)
        virNWFilterSnoopReqLeaseDel(req, &ipl->ipAddress, false, false);

    /* free all req data */
    VIR_FREE(req->ifname);
    VIR_FREE(req->linkdev);
    VIR_FREE(req->filtername);
    virNWFilterHashTableFree(req->vars);

    virMutexDestroy(&req->lock);
    virCondDestroy(&req->threadStatusCond);

    VIR_FREE(req);
}

/*
 * Lock a Snoop request 'req'
 */
static void
virNWFilterSnoopReqLock(virNWFilterSnoopReqPtr req)
{
    virMutexLock(&req->lock);
}

/*
 * Unlock a Snoop request 'req'
 */
static void
virNWFilterSnoopReqUnlock(virNWFilterSnoopReqPtr req)
{
    virMutexUnlock(&req->lock);
}

/*
 * virNWFilterSnoopReqRelease - hash table free function to kill a request
 */
static void
virNWFilterSnoopReqRelease(void *req0, const void *name ATTRIBUTE_UNUSED)
{
    virNWFilterSnoopReqPtr req = req0;

    if (!req)
        return;

    /* protect req->threadkey */
    virNWFilterSnoopReqLock(req);

    if (req->threadkey)
        virNWFilterSnoopCancel(&req->threadkey);

    virNWFilterSnoopReqUnlock(req);

    virNWFilterSnoopReqFree(req);
}

/*
 * virNWFilterSnoopReqGetByIFKey
 *
 * Get a Snoop request given an interface key; caller must release
 * the Snoop request with a call to virNWFilterSnoopReqPut()
 */
static virNWFilterSnoopReqPtr
virNWFilterSnoopReqGetByIFKey(const char *ifkey)
{
    virNWFilterSnoopReqPtr req;

    virNWFilterSnoopLock();

    req = virHashLookup(virNWFilterSnoopState.snoopReqs, ifkey);
    if (req)
        virNWFilterSnoopReqGet(req);

    virNWFilterSnoopUnlock();

    return req;
}

/*
 * Drop the reference to the Snoop request. Don't use the req
 * after this call.
 */
static void
virNWFilterSnoopReqPut(virNWFilterSnoopReqPtr req)
{
    if (!req)
        return;

    virNWFilterSnoopLock();

    if (virAtomicIntDecAndTest(&req->refctr)) {
        /*
         * delete the request:
         * - if we don't find req on the global list anymore
         *   (this happens during SIGHUP)
         * we would keep the request:
         * - if we still have a valid lease, keep the req for restarts
         */
        if (virHashLookup(virNWFilterSnoopState.snoopReqs, req->ifkey) != req) {
            virNWFilterSnoopReqRelease(req, NULL);
        } else if (!req->start || req->start->timeout < time(0)) {
            ignore_value(virHashRemoveEntry(virNWFilterSnoopState.snoopReqs,
                                            req->ifkey));
        }
    }

    virNWFilterSnoopUnlock();
}

/*
 * virNWFilterSnoopReqLeaseAdd - create or update an IP lease
 */
static int
virNWFilterSnoopReqLeaseAdd(virNWFilterSnoopReqPtr req,
                            virNWFilterSnoopIPLeasePtr plnew,
                            bool update_leasefile)
{
    virNWFilterSnoopIPLeasePtr pl;

    plnew->snoopReq = req;

    /* protect req->start and the lease */
    virNWFilterSnoopReqLock(req);

    pl = virNWFilterSnoopIPLeaseGetByIP(req->start, &plnew->ipAddress);

    if (pl) {
        virNWFilterSnoopIPLeaseUpdate(pl, plnew->timeout);

        virNWFilterSnoopReqUnlock(req);

        goto exit;
    }

    virNWFilterSnoopReqUnlock(req);

    if (VIR_ALLOC(pl) < 0)
        return -1;
    *pl = *plnew;

    /* protect req->threadkey */
    virNWFilterSnoopReqLock(req);

    if (req->threadkey && virNWFilterSnoopIPLeaseInstallRule(pl, true) < 0) {
        virNWFilterSnoopReqUnlock(req);
        VIR_FREE(pl);
        return -1;
    }

    virNWFilterSnoopReqUnlock(req);

    /* put the lease on the req's list */
    virNWFilterSnoopIPLeaseTimerAdd(pl);

    virAtomicIntInc(&virNWFilterSnoopState.nLeases);

 exit:
    if (update_leasefile)
        virNWFilterSnoopLeaseFileSave(pl);

    return 0;
}

/*
 * Restore a Snoop request -- walk its list of leases
 * and re-build the filtering rules with them
 */
static int
virNWFilterSnoopReqRestore(virNWFilterSnoopReqPtr req)
{
    int ret = 0;
    virNWFilterSnoopIPLeasePtr ipl;

    /* protect req->start */
    virNWFilterSnoopReqLock(req);

    for (ipl = req->start; ipl; ipl = ipl->next) {
        /* instantiate the rules at the last lease */
        bool is_last = (ipl->next == NULL);
        if (virNWFilterSnoopIPLeaseInstallRule(ipl, is_last) < 0) {
            ret = -1;
            break;
        }
    }

    virNWFilterSnoopReqUnlock(req);

    return ret;
}

/*
 * virNWFilterSnoopReqLeaseDel - delete an IP lease
 *
 * @update_leasefile: set to 'true' if the lease expired or the lease
 *                    was returned to the DHCP server and therefore
 *                    this has to be noted in the lease file.
 *                    set to 'false' for any other reason such as for
 *                    example when calling only to free the lease's
 *                    memory or when calling this function while reading
 *                    leases from the file.
 *
 * @instantiate: when calling this function in a loop, indicate
 *               the last call with 'true' here so that the
 *               rules all get instantiated
 *               Always calling this with 'true' is fine, but less
 *               efficient.
 *
 * Returns 0 on success, -1 if the instantiation of the rules failed
 */
static int
virNWFilterSnoopReqLeaseDel(virNWFilterSnoopReqPtr req,
                            virSocketAddrPtr ipaddr, bool update_leasefile,
                            bool instantiate)
{
    int ret = 0;
    virNWFilterSnoopIPLeasePtr ipl;
    char *ipstr = NULL;
    int ipAddrLeft;

    /* protect req->start, req->ifname and the lease */
    virNWFilterSnoopReqLock(req);

    ipl = virNWFilterSnoopIPLeaseGetByIP(req->start, ipaddr);
    if (ipl == NULL)
        goto lease_not_found;

    ipstr = virSocketAddrFormat(&ipl->ipAddress);
    if (!ipstr) {
        ret = -1;
        goto lease_not_found;
    }

    virNWFilterSnoopIPLeaseTimerDel(ipl);
    /* lease is off the list now */

    if (update_leasefile)
        virNWFilterSnoopLeaseFileSave(ipl);

    ipAddrLeft = virNWFilterIPAddrMapDelIPAddr(req->ifname, ipstr);

    if (!req->threadkey || !instantiate)
        goto skip_instantiate;

    if (ipAddrLeft) {
        ret = virNWFilterInstantiateFilterLate(req->driver,
                                               NULL,
                                               req->ifname,
                                               req->ifindex,
                                               req->linkdev,
                                               &req->macaddr,
                                               req->filtername,
                                               req->vars);
    } else {
        virNWFilterVarValuePtr dhcpsrvrs =
            virHashLookup(req->vars->hashTable, NWFILTER_VARNAME_DHCPSERVER);

        if (req->techdriver &&
            req->techdriver->applyDHCPOnlyRules(req->ifname, &req->macaddr,
                                                dhcpsrvrs, false) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("virNWFilterSnoopListDel failed"));
            ret = -1;
        }

    }

 skip_instantiate:
    VIR_FREE(ipl);

    virAtomicIntDecAndTest(&virNWFilterSnoopState.nLeases);

 lease_not_found:
    VIR_FREE(ipstr);

    virNWFilterSnoopReqUnlock(req);

    return ret;
}

static int
virNWFilterSnoopDHCPGetOpt(virNWFilterSnoopDHCPHdrPtr pd, int len,
                           uint8_t *pmtype, uint32_t *pleasetime)
{
    int oind, olen;
    uint32_t nwint;

    olen = len - sizeof(*pd);
    oind = 0;

    if (olen < 4)               /* bad magic */
        return -1;

    if (memcmp(dhcp_magic, pd->d_opts, sizeof(dhcp_magic)) != 0)
        return -1;              /* bad magic */

    oind += sizeof(dhcp_magic);

    *pmtype = 0;
    *pleasetime = 0;

    while (oind < olen) {
        switch (pd->d_opts[oind]) {
        case DHCPO_LEASE:
            if (olen - oind < 6)
                goto malformed;
            if (*pleasetime)
                return -1;  /* duplicate lease time */
            memcpy(&nwint, (char *)pd->d_opts + oind + 2, sizeof(nwint));
            *pleasetime = ntohl(nwint);
            break;
        case DHCPO_MTYPE:
            if (olen - oind < 3)
                goto malformed;
            if (*pmtype)
                return -1;  /* duplicate message type */
            *pmtype = pd->d_opts[oind + 2];
            break;
        case DHCPO_PAD:
            oind++;
            continue;
        case DHCPO_END:
            return 0;
        default:
            if (olen - oind < 2)
                goto malformed;
        }
        oind += pd->d_opts[oind + 1] + 2;
    }
    return 0;
 malformed:
    VIR_WARN("got lost in the options!");
    return -1;
}

/*
 * Decode the DHCP options
 *
 * Returns 0 in case of full success.
 * Returns -2 in case of some error with the packet.
 * Returns -1 in case of error with the installation of rules
 */
static int
virNWFilterSnoopDHCPDecode(virNWFilterSnoopReqPtr req,
                           virNWFilterSnoopEthHdrPtr pep,
                           int len, bool fromVM)
{
    struct iphdr *pip;
    struct udphdr *pup;
    virNWFilterSnoopDHCPHdrPtr pd;
    virNWFilterSnoopIPLease ipl;
    uint8_t mtype;
    uint32_t leasetime;
    uint32_t nwint;

    /* go through the protocol headers */
    switch (ntohs(pep->eh_type)) {
    case ETHERTYPE_IP:
        VIR_WARNINGS_NO_CAST_ALIGN
        pip = (struct iphdr *) pep->eh_data;
        VIR_WARNINGS_RESET
        len -= offsetof(virNWFilterSnoopEthHdr, eh_data);
        break;
    default:
        return -2;
    }

    if (len < 0)
        return -2;

    VIR_WARNINGS_NO_CAST_ALIGN
    pup = (struct udphdr *) ((char *) pip + (pip->ihl << 2));
    VIR_WARNINGS_RESET
    len -= pip->ihl << 2;
    if (len < 0)
        return -2;

    pd = (virNWFilterSnoopDHCPHdrPtr) ((char *) pup + sizeof(*pup));
    len -= sizeof(*pup);
    if (len < 0)
        return -2;                 /* invalid packet length */

    /*
     * some DHCP servers send their responses as MAC broadcast replies
     * filter messages from the server also by the destination MAC
     * inside the DHCP response
     */
    if (!fromVM) {
        if (virMacAddrCmpRaw(&req->macaddr,
                             (unsigned char *)&pd->d_chaddr) != 0)
            return -2;
    }

    if (virNWFilterSnoopDHCPGetOpt(pd, len, &mtype, &leasetime) < 0)
        return -2;

    memset(&ipl, 0, sizeof(ipl));

    memcpy(&nwint, &pd->d_yiaddr, sizeof(nwint));
    virSocketAddrSetIPv4AddrNetOrder(&ipl.ipAddress, nwint);

    memcpy(&nwint, &pd->d_siaddr, sizeof(nwint));
    virSocketAddrSetIPv4AddrNetOrder(&ipl.ipServer, nwint);

    if (leasetime == ~0)
        ipl.timeout = ~0;
    else
        ipl.timeout = time(0) + leasetime;

    ipl.snoopReq = req;

    /* check that the type of message comes from the right direction */
    switch (mtype) {
    case DHCPACK:
    case DHCPDECLINE:
        if (fromVM)
            return -2;
        break;
    case DHCPRELEASE:
        if (!fromVM)
            return -2;
        break;
    default:
        break;
    }

    switch (mtype) {
    case DHCPACK:
        if (virNWFilterSnoopReqLeaseAdd(req, &ipl, true) < 0)
            return -1;
        break;
    case DHCPDECLINE:
    case DHCPRELEASE:
        if (virNWFilterSnoopReqLeaseDel(req, &ipl.ipAddress, true, true) < 0)
            return -1;
        break;
    default:
        return -2;
    }

    return 0;
}

static pcap_t *
virNWFilterSnoopDHCPOpen(const char *ifname, virMacAddr *mac,
                         const char *filter, pcap_direction_t dir)
{
    pcap_t *handle = NULL;
    struct bpf_program fp;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char *ext_filter = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);

    if (dir == PCAP_D_IN /* from VM */) {
        /*
         * don't want to hear about another VM's DHCP requests
         *
         * extend the filter with the macaddr of the VM; filter the
         * more unlikely parameters first, then go for the MAC
         */
        if (virAsprintf(&ext_filter,
                        "%s and ether src %s", filter, macaddr) < 0)
            return NULL;
    } else {
        /*
         * Some DHCP servers respond via MAC broadcast; we rely on later
         * filtering of responses by comparing the MAC address inside the
         * DHCP response against the one of the VM. Assuming that the
         * bridge learns the VM's MAC address quickly this should not
         * generate much more traffic than if we filtered by VM and
         * braodcast MAC as well
         */
        if (VIR_STRDUP(ext_filter, filter) < 0)
            return NULL;
    }

    handle = pcap_create(ifname, pcap_errbuf);

    if (handle == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("pcap_create failed"));
        goto cleanup_nohandle;
    }

    if (pcap_set_snaplen(handle, PCAP_PBUFSIZE) < 0 ||
        pcap_set_buffer_size(handle, PCAP_BUFFERSIZE) < 0 ||
        pcap_activate(handle) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("setup of pcap handle failed: %s"),
                       pcap_geterr(handle));
        goto cleanup;
    }

    if (pcap_compile(handle, &fp, ext_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_compile: %s"), pcap_geterr(handle));
        goto cleanup;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_setfilter: %s"), pcap_geterr(handle));
        goto cleanup_freecode;
    }

    if (pcap_setdirection(handle, dir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_setdirection: %s"),
                       pcap_geterr(handle));
        goto cleanup_freecode;
    }

    pcap_freecode(&fp);
    VIR_FREE(ext_filter);

    return handle;

 cleanup_freecode:
    pcap_freecode(&fp);
 cleanup:
    pcap_close(handle);
 cleanup_nohandle:
    VIR_FREE(ext_filter);

    return NULL;
}

/*
 * Worker function to decode the DHCP message and with that
 * also do the time-consuming work of instantiating the filters
 */
static void virNWFilterDHCPDecodeWorker(void *jobdata, void *opaque)
{
    virNWFilterSnoopReqPtr req = opaque;
    virNWFilterDHCPDecodeJobPtr job = jobdata;
    virNWFilterSnoopEthHdrPtr packet = (virNWFilterSnoopEthHdrPtr)job->packet;

    if (virNWFilterSnoopDHCPDecode(req, packet,
                                   job->caplen, job->fromVM) == -1) {
        req->jobCompletionStatus = -1;

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Instantiation of rules failed on "
                         "interface '%s'"), req->ifname);
    }
    virAtomicIntDecAndTest(job->qCtr);
    VIR_FREE(job);
}

/*
 * Submit a job to the worker thread doing the time-consuming work...
 */
static int
virNWFilterSnoopDHCPDecodeJobSubmit(virThreadPoolPtr pool,
                                    virNWFilterSnoopEthHdrPtr pep,
                                    int len, pcap_direction_t dir,
                                    int *qCtr)
{
    virNWFilterDHCPDecodeJobPtr job;
    int ret;

    if (len <= MIN_VALID_DHCP_PKT_SIZE || len > sizeof(job->packet))
        return 0;

    if (VIR_ALLOC(job) < 0)
        return -1;

    memcpy(job->packet, pep, len);
    job->caplen = len;
    job->fromVM = (dir == PCAP_D_IN);
    job->qCtr = qCtr;

    ret = virThreadPoolSendJob(pool, 0, job);

    if (ret == 0)
        virAtomicIntInc(qCtr);
    else
        VIR_FREE(job);

    return ret;
}

/*
 * virNWFilterSnoopRateLimit -- limit the rate of jobs submitted to the
 *                              worker thread
 *
 * Help defend the worker thread from being flooded with likely bogus packets
 * sent by the VM.
 *
 * rl: The state of the rate limiter
 *
 * Returns the delta of packets compared to the rate, i.e. if the rate
 * is 4 (pkts/s) and we now have received 5 within a second, it would
 * return 1. If the number of packets is below the rate, it returns 0.
 */
static unsigned int
virNWFilterSnoopRateLimit(virNWFilterSnoopRateLimitConfPtr rl)
{
    time_t now = time(0);
    int diff;
# define IN_BURST(n, b) ((n)-(b) <= 1) /* bursts span 2 discrete seconds */

    if (rl->prev != now && !IN_BURST(now, rl->burst)) {
        rl->prev = now;
        rl->pkt_ctr = 1;
    } else {
        rl->pkt_ctr++;
        if (rl->pkt_ctr >= rl->rate) {
            if (IN_BURST(now, rl->burst)) {
                /* in a burst */
                diff = rl->pkt_ctr - rl->burstRate;
                if (diff > 0)
                    return diff;
                return 0;
            }
            if (rl->prev - rl->burst > rl->burstInterval) {
                /* this second will start a new burst */
                rl->burst = rl->prev;
                return 0;
            }
            /* previous burst is too close */
            return rl->pkt_ctr - rl->rate;
        }
    }

    return 0;
}

/*
 * virNWFilterSnoopRatePenalty
 *
 * @pc: pointer to the virNWFilterSnoopPcapConf
 * @diff: the amount of pkts beyond the rate, i.e., if the rate is 10
 *        and 13 pkts have been received now in one seconds, then
 *        this should be 3.
 *
 * Adjusts the timeout the virNWFilterSnooPcapConf will be penalized for
 * sending too many packets.
 */
static void
virNWFilterSnoopRatePenalty(virNWFilterSnoopPcapConfPtr pc,
                            unsigned int diff, unsigned int limit)
{
    if (diff > limit) {
        unsigned long long now;

        if (virTimeMillisNowRaw(&now) < 0) {
            usleep(PCAP_FLOOD_TIMEOUT_MS); /* 1 ms */
            pc->penaltyTimeoutAbs = 0;
        } else {
            /* don't listen to the fd for 1 ms */
            pc->penaltyTimeoutAbs = now + PCAP_FLOOD_TIMEOUT_MS;
        }
    }
}

static int
virNWFilterSnoopAdjustPoll(virNWFilterSnoopPcapConfPtr pc,
                           size_t nPc, struct pollfd *pfd,
                           int *pollTo)
{
    int ret = 0;
    size_t i;
    int tmp;
    unsigned long long now = 0;

    *pollTo = -1;

    for (i = 0; i < nPc; i++) {
        if (pc[i].penaltyTimeoutAbs != 0) {
            if (now == 0) {
                if (virTimeMillisNow(&now) < 0) {
                    ret = -1;
                    break;
                }
            }

            if (now < pc[i].penaltyTimeoutAbs) {
                /* don't listen to incoming data on the fd for some time */
                pfd[i].events &= ~POLLIN;
                /*
                 * calc the max. time to spend in poll() until adjustments
                 * to the pollfd array are needed again.
                 */
                tmp = pc[i].penaltyTimeoutAbs - now;
                if (*pollTo == -1 || tmp < *pollTo)
                    *pollTo = tmp;
            } else {
                /* listen again to the fd */
                pfd[i].events |= POLLIN;

                pc[i].penaltyTimeoutAbs = 0;
            }
        }
    }

    return ret;
}

/*
 * The DHCP snooping thread. It spends most of its time in the pcap
 * library and if it gets suitable packets, it submits them to the worker
 * thread for processing.
 */
static void
virNWFilterDHCPSnoopThread(void *req0)
{
    virNWFilterSnoopReqPtr req = req0;
    struct pcap_pkthdr *hdr;
    virNWFilterSnoopEthHdrPtr packet;
    int ifindex = 0;
    int errcount = 0;
    int tmp = -1, rv, n, pollTo;
    size_t i;
    char *threadkey = NULL;
    virThreadPoolPtr worker = NULL;
    time_t last_displayed = 0, last_displayed_queue = 0;
    virNWFilterSnoopPcapConf pcapConf[] = {
        {
            .dir = PCAP_D_IN, /* from VM */
            .filter = "dst port 67 and src port 68",
            .rateLimit = {
                .prev = time(0),
                .rate = DHCP_PKT_RATE,
                .burstRate = DHCP_PKT_BURST,
                .burstInterval = DHCP_BURST_INTERVAL_S,
            },
            .maxQSize = MAX_QUEUED_JOBS,
        }, {
            .dir = PCAP_D_OUT, /* to VM */
            .filter = "src port 67 and dst port 68",
            .rateLimit = {
                .prev = time(0),
                .rate = DHCP_PKT_RATE,
                .burstRate = DHCP_PKT_BURST,
                .burstInterval = DHCP_BURST_INTERVAL_S,
            },
            .maxQSize = MAX_QUEUED_JOBS,
        },
    };
    struct pollfd fds[] = {
        {
            /* get a POLLERR if interface goes down or disappears */
            .events = POLLIN | POLLERR,
        }, {
            .events = POLLIN | POLLERR,
        },
    };
    bool error = false;

    /* whoever started us increased the reference counter for the req for us */

    /* protect req->ifname & req->threadkey */
    virNWFilterSnoopReqLock(req);

    if (req->ifname && req->threadkey) {
        for (i = 0; i < ARRAY_CARDINALITY(pcapConf); i++) {
            pcapConf[i].handle =
                virNWFilterSnoopDHCPOpen(req->ifname, &req->macaddr,
                                         pcapConf[i].filter,
                                         pcapConf[i].dir);
            if (!pcapConf[i].handle) {
                error = true;
                break;
            }
            fds[i].fd = pcap_fileno(pcapConf[i].handle);
        }
        tmp = virNetDevGetIndex(req->ifname, &ifindex);
        ignore_value(VIR_STRDUP(threadkey, req->threadkey));
        worker = virThreadPoolNew(1, 1, 0,
                                  virNWFilterDHCPDecodeWorker,
                                  req);
    }

    /* let creator know how well we initialized */
    if (error || !threadkey || tmp < 0 || !worker ||
        ifindex != req->ifindex)
        req->threadStatus = THREAD_STATUS_FAIL;
    else
        req->threadStatus = THREAD_STATUS_OK;

    virCondSignal(&req->threadStatusCond);

    virNWFilterSnoopReqUnlock(req);

    if (req->threadStatus != THREAD_STATUS_OK)
        goto exit;

    while (!error) {
        if (virNWFilterSnoopAdjustPoll(pcapConf,
                                       ARRAY_CARDINALITY(pcapConf),
                                       fds, &pollTo) < 0) {
            break;
        }

        /* cap pollTo so we don't hold up the join for too long */
        if (pollTo < 0 || pollTo > SNOOP_POLL_MAX_TIMEOUT_MS)
            pollTo = SNOOP_POLL_MAX_TIMEOUT_MS;

        n = poll(fds, ARRAY_CARDINALITY(fds), pollTo);

        if (n < 0) {
            if (errno != EAGAIN && errno != EINTR)
                error = true;
        }

        virNWFilterSnoopReqLeaseTimerRun(req);

        /*
         * Check whether we were cancelled or whether
         * a previously submitted job failed.
         */
        if (!virNWFilterSnoopIsActive(threadkey) ||
            req->jobCompletionStatus != 0)
            goto exit;

        for (i = 0; n > 0 && i < ARRAY_CARDINALITY(fds); i++) {
            if (!fds[i].revents)
                continue;

            fds[i].revents = 0;
            n--;

            rv = pcap_next_ex(pcapConf[i].handle, &hdr,
                              (const u_char **)&packet);

            if (rv < 0) {
                /* error reading from socket */
                tmp = -1;

                /* protect req->ifname */
                virNWFilterSnoopReqLock(req);

                if (req->ifname)
                    tmp = virNetDevValidateConfig(req->ifname, NULL, ifindex);

                virNWFilterSnoopReqUnlock(req);

                if (tmp <= 0) {
                    error = true;
                    break;
                }

                if (++errcount > PCAP_READ_MAXERRS) {
                    pcap_close(pcapConf[i].handle);
                    pcapConf[i].handle = NULL;

                    /* protect req->ifname */
                    virNWFilterSnoopReqLock(req);

                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("interface '%s' failing; "
                                     "reopening"),
                                   req->ifname);
                    if (req->ifname)
                        pcapConf[i].handle =
                            virNWFilterSnoopDHCPOpen(req->ifname, &req->macaddr,
                                                     pcapConf[i].filter,
                                                     pcapConf[i].dir);

                    virNWFilterSnoopReqUnlock(req);

                    if (!pcapConf[i].handle) {
                        error = true;
                        break;
                    }
                }
                continue;
            }

            errcount = 0;

            if (rv) {
                unsigned int diff;

                /* submit packet to worker thread */
                if (virAtomicIntGet(&pcapConf[i].qCtr) >
                    pcapConf[i].maxQSize) {
                    if (last_displayed_queue - time(0) > 10) {
                        last_displayed_queue = time(0);
                        VIR_WARN("Worker thread for interface '%s' has a "
                                 "job queue that is too long",
                                 req->ifname);
                    }
                    continue;
                }

                diff = virNWFilterSnoopRateLimit(&pcapConf[i].rateLimit);
                if (diff > 0) {
                    virNWFilterSnoopRatePenalty(&pcapConf[i], diff,
                                                DHCP_PKT_RATE);
                    /* rate-limited warnings */
                    if (time(0) - last_displayed > 10) {
                         last_displayed = time(0);
                         VIR_WARN("Too many DHCP packets on interface '%s'",
                                  req->ifname);
                    }
                    continue;
                }

                if (virNWFilterSnoopDHCPDecodeJobSubmit(worker, packet,
                                                      hdr->caplen,
                                                      pcapConf[i].dir,
                                                      &pcapConf[i].qCtr) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Job submission failed on "
                                     "interface '%s'"), req->ifname);
                    error = true;
                    break;
                }
            }
        } /* for all fds */
    } /* while (!error) */

    /* protect IfNameToKey */
    virNWFilterSnoopLock();

    /* protect req->ifname & req->threadkey */
    virNWFilterSnoopReqLock(req);

    virNWFilterSnoopCancel(&req->threadkey);

    ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                    req->ifname));

    VIR_FREE(req->ifname);

    virNWFilterSnoopReqUnlock(req);
    virNWFilterSnoopUnlock();

 exit:
    virThreadPoolFree(worker);

    virNWFilterSnoopReqPut(req);

    VIR_FREE(threadkey);

    for (i = 0; i < ARRAY_CARDINALITY(pcapConf); i++) {
        if (pcapConf[i].handle)
            pcap_close(pcapConf[i].handle);
    }

    virAtomicIntDecAndTest(&virNWFilterSnoopState.nThreads);

    return;
}

static void
virNWFilterSnoopIFKeyFMT(char *ifkey, const unsigned char *vmuuid,
                         const virMacAddr *macaddr)
{
    virUUIDFormat(vmuuid, ifkey);
    ifkey[VIR_UUID_STRING_BUFLEN - 1] = '-';
    virMacAddrFormat(macaddr, ifkey + VIR_UUID_STRING_BUFLEN);
}

int
virNWFilterDHCPSnoopReq(virNWFilterTechDriverPtr techdriver,
                        const char *ifname,
                        const char *linkdev,
                        const unsigned char *vmuuid,
                        const virMacAddr *macaddr,
                        const char *filtername,
                        virNWFilterHashTablePtr filterparams,
                        virNWFilterDriverStatePtr driver)
{
    virNWFilterSnoopReqPtr req;
    bool isnewreq;
    char ifkey[VIR_IFKEY_LEN];
    int tmp;
    virThread thread;
    virNWFilterVarValuePtr dhcpsrvrs;
    bool threadPuts = false;

    virNWFilterSnoopIFKeyFMT(ifkey, vmuuid, macaddr);

    req = virNWFilterSnoopReqGetByIFKey(ifkey);
    isnewreq = (req == NULL);
    if (!isnewreq) {
        if (req->threadkey) {
            virNWFilterSnoopReqPut(req);
            return 0;
        }
        /* a recycled req may still have filtername and vars */
        VIR_FREE(req->filtername);
        virNWFilterHashTableFree(req->vars);
    } else {
        req = virNWFilterSnoopReqNew(ifkey);
        if (!req)
            return -1;
    }

    req->driver = driver;
    req->techdriver = techdriver;
    tmp = virNetDevGetIndex(ifname, &req->ifindex);
    virMacAddrSet(&req->macaddr, macaddr);
    req->vars = virNWFilterHashTableCreate(0);
    req->linkdev = NULL;

    if (VIR_STRDUP(req->ifname, ifname) < 0 ||
        VIR_STRDUP(req->filtername, filtername) < 0 ||
        VIR_STRDUP(req->linkdev, linkdev) < 0)
        goto exit_snoopreqput;

    if (!req->vars || tmp < 0)
        goto exit_snoopreqput;

    /* check that all tools are available for applying the filters (late) */
    if (!techdriver->canApplyBasicRules()) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IP parameter must be provided since "
                         "snooping the IP address does not work "
                         "possibly due to missing tools"));
        goto exit_snoopreqput;
    }

    dhcpsrvrs = virHashLookup(filterparams->hashTable,
                              NWFILTER_VARNAME_DHCPSERVER);

    if (techdriver->applyDHCPOnlyRules(req->ifname, &req->macaddr,
                                       dhcpsrvrs, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("applyDHCPOnlyRules "
                         "failed - spoofing not protected!"));
        goto exit_snoopreqput;
    }

    if (virNWFilterHashTablePutAll(filterparams, req->vars) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq: can't copy variables"
                         " on if %s"), ifkey);
        goto exit_snoopreqput;
    }

    virNWFilterSnoopLock();

    if (virHashAddEntry(virNWFilterSnoopState.ifnameToKey, ifname,
                        req->ifkey) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq ifname map failed"
                         " on interface \"%s\" key \"%s\""), ifname,
                       ifkey);
        goto exit_snoopunlock;
    }

    if (isnewreq &&
        virHashAddEntry(virNWFilterSnoopState.snoopReqs, ifkey, req) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq req add failed on"
                         " interface \"%s\" ifkey \"%s\""), ifname,
                       ifkey);
        goto exit_rem_ifnametokey;
    }

    /* prevent thread from holding req */
    virNWFilterSnoopReqLock(req);

    if (virThreadCreate(&thread, false, virNWFilterDHCPSnoopThread,
                        req) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq virThreadCreate "
                         "failed on interface '%s'"), ifname);
        goto exit_snoopreq_unlock;
    }

    threadPuts = true;

    virAtomicIntInc(&virNWFilterSnoopState.nThreads);

    req->threadkey = virNWFilterSnoopActivate(req);
    if (!req->threadkey) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Activation of snoop request failed on "
                         "interface '%s'"), req->ifname);
        goto exit_snoopreq_unlock;
    }

    if (virNWFilterSnoopReqRestore(req) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Restoring of leases failed on "
                         "interface '%s'"), req->ifname);
        goto exit_snoop_cancel;
    }

    /* sync with thread */
    if (virCondWait(&req->threadStatusCond, &req->lock) < 0 ||
        req->threadStatus != THREAD_STATUS_OK)
        goto exit_snoop_cancel;

    virNWFilterSnoopReqUnlock(req);

    virNWFilterSnoopUnlock();

    /* do not 'put' the req -- the thread will do this */

    return 0;

 exit_snoop_cancel:
    virNWFilterSnoopCancel(&req->threadkey);
 exit_snoopreq_unlock:
    virNWFilterSnoopReqUnlock(req);
 exit_rem_ifnametokey:
    virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey, ifname);
 exit_snoopunlock:
    virNWFilterSnoopUnlock();
 exit_snoopreqput:
    if (!threadPuts)
        virNWFilterSnoopReqPut(req);

    return -1;
}

static void
virNWFilterSnoopLeaseFileClose(void)
{
    VIR_FORCE_CLOSE(virNWFilterSnoopState.leaseFD);
}

static void
virNWFilterSnoopLeaseFileOpen(void)
{
    virNWFilterSnoopLeaseFileClose();

    virNWFilterSnoopState.leaseFD = open(LEASEFILE, O_CREAT|O_RDWR|O_APPEND,
                                         0644);
}

/*
 * Write a single lease to the given file.
 *
 */
static int
virNWFilterSnoopLeaseFileWrite(int lfd, const char *ifkey,
                               virNWFilterSnoopIPLeasePtr ipl)
{
    char *lbuf = NULL;
    char *ipstr, *dhcpstr;
    int len;
    int ret = 0;

    ipstr = virSocketAddrFormat(&ipl->ipAddress);
    dhcpstr = virSocketAddrFormat(&ipl->ipServer);

    if (!dhcpstr || !ipstr) {
        ret = -1;
        goto cleanup;
    }

    /* time intf ip dhcpserver */
    len = virAsprintf(&lbuf, "%u %s %s %s\n", ipl->timeout,
                      ifkey, ipstr, dhcpstr);

    if (len < 0) {
        ret = -1;
        goto cleanup;
    }

    if (safewrite(lfd, lbuf, len) != len) {
        virReportSystemError(errno, "%s", _("lease file write failed"));
        ret = -1;
        goto cleanup;
    }

    ignore_value(fsync(lfd));

 cleanup:
    VIR_FREE(lbuf);
    VIR_FREE(dhcpstr);
    VIR_FREE(ipstr);

    return ret;
}

/*
 * Append a single lease to the end of the lease file.
 * To keep a limited number of dead leases, re-read the lease
 * file if the threshold of active leases versus written ones
 * exceeds a threshold.
 */
static void
virNWFilterSnoopLeaseFileSave(virNWFilterSnoopIPLeasePtr ipl)
{
    virNWFilterSnoopReqPtr req = ipl->snoopReq;

    virNWFilterSnoopLock();

    if (virNWFilterSnoopState.leaseFD < 0)
        virNWFilterSnoopLeaseFileOpen();
    if (virNWFilterSnoopLeaseFileWrite(virNWFilterSnoopState.leaseFD,
                                       req->ifkey, ipl) < 0)
        goto err_exit;

    /* keep dead leases at < ~95% of file size */
    if (virAtomicIntInc(&virNWFilterSnoopState.wLeases) >=
        virAtomicIntGet(&virNWFilterSnoopState.nLeases) * 20)
        virNWFilterSnoopLeaseFileLoad();   /* load & refresh lease file */

 err_exit:
    virNWFilterSnoopUnlock();
}

/*
 * Have requests removed that have no leases.
 * Remove all expired leases.
 * Call this function with the SnoopLock held.
 */
static int
virNWFilterSnoopPruneIter(const void *payload,
                          const void *name ATTRIBUTE_UNUSED,
                          const void *data ATTRIBUTE_UNUSED)
{
    virNWFilterSnoopReqPtr req = (virNWFilterSnoopReqPtr)payload;
    bool del_req;

    /* clean up orphaned, expired leases */

    /* protect req->threadkey */
    virNWFilterSnoopReqLock(req);

    if (!req->threadkey)
        virNWFilterSnoopReqLeaseTimerRun(req);

    /*
     * have the entry removed if it has no leases and no one holds a ref
     */
    del_req = ((req->start == NULL) && (virAtomicIntGet(&req->refctr) == 0));

    virNWFilterSnoopReqUnlock(req);

    return del_req;
}

/*
 * Iterator to write all leases of a single request to a file.
 * Call this function with the SnoopLock held.
 */
static int
virNWFilterSnoopSaveIter(void *payload,
                         const void *name ATTRIBUTE_UNUSED,
                         void *data)
{
    virNWFilterSnoopReqPtr req = payload;
    int tfd = *(int *)data;
    virNWFilterSnoopIPLeasePtr ipl;

    /* protect req->start */
    virNWFilterSnoopReqLock(req);

    for (ipl = req->start; ipl; ipl = ipl->next)
        ignore_value(virNWFilterSnoopLeaseFileWrite(tfd, req->ifkey, ipl));

    virNWFilterSnoopReqUnlock(req);
    return 0;
}

/*
 * Write all valid leases into a temporary file and then
 * rename the file to the final file.
 * Call this function with the SnoopLock held.
 */
static void
virNWFilterSnoopLeaseFileRefresh(void)
{
    int tfd;

    if (virFileMakePathWithMode(LEASEFILE_DIR, 0700) < 0) {
        virReportError(errno, _("mkdir(\"%s\")"), LEASEFILE_DIR);
        return;
    }

    if (unlink(TMPLEASEFILE) < 0 && errno != ENOENT)
        virReportSystemError(errno, _("unlink(\"%s\")"), TMPLEASEFILE);

    /* lease file loaded, delete old one */
    tfd = open(TMPLEASEFILE, O_CREAT|O_RDWR|O_TRUNC|O_EXCL, 0644);
    if (tfd < 0) {
        virReportSystemError(errno, _("open(\"%s\")"), TMPLEASEFILE);
        return;
    }

    if (virNWFilterSnoopState.snoopReqs) {
        /* clean up the requests */
        virHashRemoveSet(virNWFilterSnoopState.snoopReqs,
                         virNWFilterSnoopPruneIter, NULL);
        /* now save them */
        virHashForEach(virNWFilterSnoopState.snoopReqs,
                       virNWFilterSnoopSaveIter, (void *)&tfd);
    }

    if (VIR_CLOSE(tfd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), TMPLEASEFILE);
        /* assuming the old lease file is still better, skip the renaming */
        goto skip_rename;
    }

    if (rename(TMPLEASEFILE, LEASEFILE) < 0) {
        virReportSystemError(errno, _("rename(\"%s\", \"%s\")"),
                             TMPLEASEFILE, LEASEFILE);
        ignore_value(unlink(TMPLEASEFILE));
    }
    virAtomicIntSet(&virNWFilterSnoopState.wLeases, 0);

 skip_rename:
    virNWFilterSnoopLeaseFileOpen();
}


static void
virNWFilterSnoopLeaseFileLoad(void)
{
    char line[256], ifkey[VIR_IFKEY_LEN];
    char ipstr[INET_ADDRSTRLEN], srvstr[INET_ADDRSTRLEN];
    virNWFilterSnoopIPLease ipl;
    virNWFilterSnoopReqPtr req;
    time_t now;
    FILE *fp;
    int ln = 0, tmp;

    /* protect the lease file */
    virNWFilterSnoopLock();

    fp = fopen(LEASEFILE, "r");
    time(&now);
    while (fp && fgets(line, sizeof(line), fp)) {
        if (line[strlen(line)-1] != '\n') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("virNWFilterSnoopLeaseFileLoad lease file "
                             "line %d corrupt"), ln);
            break;
        }
        ln++;
        /* key len 54 = "VMUUID"+'-'+"MAC" */
        if (sscanf(line, "%u %54s %15s %15s", &ipl.timeout,
                   ifkey, ipstr, srvstr) < 4) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("virNWFilterSnoopLeaseFileLoad lease file "
                             "line %d corrupt"), ln);
            break;
        }
        if (ipl.timeout && ipl.timeout < now)
            continue;
        req = virNWFilterSnoopReqGetByIFKey(ifkey);
        if (!req) {
            req = virNWFilterSnoopReqNew(ifkey);
            if (!req)
               break;

            tmp = virHashAddEntry(virNWFilterSnoopState.snoopReqs, ifkey, req);

            if (tmp < 0) {
                virNWFilterSnoopReqPut(req);
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("virNWFilterSnoopLeaseFileLoad req add"
                                 " failed on interface \"%s\""), ifkey);
                continue;
            }
        }

        if (virSocketAddrParseIPv4(&ipl.ipAddress, ipstr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("line %d corrupt ipaddr \"%s\""),
                           ln, ipstr);
            virNWFilterSnoopReqPut(req);
            continue;
        }
        ignore_value(virSocketAddrParseIPv4(&ipl.ipServer, srvstr));
        ipl.snoopReq = req;

        if (ipl.timeout)
            virNWFilterSnoopReqLeaseAdd(req, &ipl, false);
        else
            virNWFilterSnoopReqLeaseDel(req, &ipl.ipAddress, false, false);

        virNWFilterSnoopReqPut(req);
    }

    VIR_FORCE_FCLOSE(fp);

    virNWFilterSnoopLeaseFileRefresh();

    virNWFilterSnoopUnlock();
}

/*
 * Wait until all threads have ended.
 */
static void
virNWFilterSnoopJoinThreads(void)
{
    while (virAtomicIntGet(&virNWFilterSnoopState.nThreads) != 0) {
        VIR_WARN("Waiting for snooping threads to terminate: %u",
                 virAtomicIntGet(&virNWFilterSnoopState.nThreads));
        usleep(1000 * 1000);
    }
}

/*
 * Iterator to remove a request, repeatedly called on one
 * request after another.
 * The requests' ifname is freed allowing for an association
 * of the Snoop request's leases with the same VM under a
 * different interface name at a later time.
 */
static int
virNWFilterSnoopRemAllReqIter(const void *payload,
                              const void *name ATTRIBUTE_UNUSED,
                              const void *data ATTRIBUTE_UNUSED)
{
    virNWFilterSnoopReqPtr req = (virNWFilterSnoopReqPtr)payload;

    /* protect req->ifname */
    virNWFilterSnoopReqLock(req);

    if (req->ifname) {
        ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                        req->ifname));

        /*
         * Remove all IP addresses known to be associated with this
         * interface so that a new thread will be started on this
         * interface
         */
        virNWFilterIPAddrMapDelIPAddr(req->ifname, NULL);

        VIR_FREE(req->ifname);
    }

    virNWFilterSnoopReqUnlock(req);

    /* removal will call virNWFilterSnoopCancel() */
    return 1;
}


/*
 * Terminate all threads; keep the SnoopReqs hash allocated
 */
static void
virNWFilterSnoopEndThreads(void)
{
    virNWFilterSnoopLock();
    virHashRemoveSet(virNWFilterSnoopState.snoopReqs,
                     virNWFilterSnoopRemAllReqIter,
                     NULL);
    virNWFilterSnoopUnlock();
}

int
virNWFilterDHCPSnoopInit(void)
{
    if (virNWFilterSnoopState.snoopReqs)
        return 0;

    VIR_DEBUG("Initializing DHCP snooping");

    if (virMutexInitRecursive(&virNWFilterSnoopState.snoopLock) < 0 ||
        virMutexInit(&virNWFilterSnoopState.activeLock) < 0)
        return -1;

    virNWFilterSnoopState.ifnameToKey = virHashCreate(0, NULL);
    virNWFilterSnoopState.active = virHashCreate(0, NULL);
    virNWFilterSnoopState.snoopReqs =
        virHashCreate(0, virNWFilterSnoopReqRelease);

    if (!virNWFilterSnoopState.ifnameToKey ||
        !virNWFilterSnoopState.snoopReqs ||
        !virNWFilterSnoopState.active)
        goto err_exit;

    virNWFilterSnoopLeaseFileLoad();
    virNWFilterSnoopLeaseFileOpen();

    return 0;

 err_exit:
    virHashFree(virNWFilterSnoopState.ifnameToKey);
    virNWFilterSnoopState.ifnameToKey = NULL;

    virHashFree(virNWFilterSnoopState.snoopReqs);
    virNWFilterSnoopState.snoopReqs = NULL;

    virHashFree(virNWFilterSnoopState.active);
    virNWFilterSnoopState.active = NULL;

    return -1;
}

/**
 * End a DHCP snoop thread on the given interface or end all
 * DHCP snoop threads.
 *
 * @ifname: Name of an interface or NULL to stop all snoop threads
 *
 * It is not an error to call this function with an interface name
 * for which no thread is snooping traffic. In this case the call will
 * be a no-op.
 */
void
virNWFilterDHCPSnoopEnd(const char *ifname)
{
    char *ifkey = NULL;

    virNWFilterSnoopLock();

    if (!virNWFilterSnoopState.snoopReqs)
        goto cleanup;

    if (ifname) {
        ifkey = (char *)virHashLookup(virNWFilterSnoopState.ifnameToKey,
                                      ifname);
        if (!ifkey)
            goto cleanup;

        ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                        ifname));
    }

    if (ifkey) {
        virNWFilterSnoopReqPtr req;

        req = virNWFilterSnoopReqGetByIFKey(ifkey);
        if (!req) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("ifkey \"%s\" has no req"), ifkey);
            goto cleanup;
        }

        /* protect req->ifname & req->threadkey */
        virNWFilterSnoopReqLock(req);

        /* keep valid lease req; drop interface association */
        virNWFilterSnoopCancel(&req->threadkey);

        VIR_FREE(req->ifname);

        virNWFilterSnoopReqUnlock(req);

        virNWFilterSnoopReqPut(req);
    } else {                      /* free all of them */
        virNWFilterSnoopLeaseFileClose();

        virHashRemoveAll(virNWFilterSnoopState.ifnameToKey);

        /* tell the threads to terminate */
        virNWFilterSnoopEndThreads();

        virNWFilterSnoopLeaseFileLoad();
    }

 cleanup:
    virNWFilterSnoopUnlock();
}

void
virNWFilterDHCPSnoopShutdown(void)
{
    virNWFilterSnoopEndThreads();
    virNWFilterSnoopJoinThreads();

    virNWFilterSnoopLock();

    virNWFilterSnoopLeaseFileClose();
    virHashFree(virNWFilterSnoopState.ifnameToKey);
    virHashFree(virNWFilterSnoopState.snoopReqs);

    virNWFilterSnoopUnlock();

    virNWFilterSnoopActiveLock();
    virHashFree(virNWFilterSnoopState.active);
    virNWFilterSnoopActiveUnlock();
}

#else /* HAVE_LIBPCAP */

int
virNWFilterDHCPSnoopInit(void)
{
    VIR_DEBUG("No DHCP snooping support available");
    return 0;
}

void
virNWFilterDHCPSnoopEnd(const char *ifname ATTRIBUTE_UNUSED)
{
    return;
}

void
virNWFilterDHCPSnoopShutdown(void)
{
    return;
}

int
virNWFilterDHCPSnoopReq(virNWFilterTechDriverPtr techdriver ATTRIBUTE_UNUSED,
                        const char *ifname ATTRIBUTE_UNUSED,
                        const char *linkdev ATTRIBUTE_UNUSED,
                        const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                        const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                        const char *filtername ATTRIBUTE_UNUSED,
                        virNWFilterHashTablePtr filterparams ATTRIBUTE_UNUSED,
                        virNWFilterDriverStatePtr driver ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("libvirt was not compiled with libpcap and \""
                     NWFILTER_VARNAME_CTRL_IP_LEARNING
                     "='dhcp'\" requires it."));
    return -1;
}
#endif /* HAVE_LIBPCAP */
