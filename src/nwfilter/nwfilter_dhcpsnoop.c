/*
 * nwfilter_dhcpsnoop.c: support for DHCP snooping used by a VM
 *                       on an interface
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
 * Copyright (C) 2011,2012 IBM Corp.
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

/*
 * Note about testing:
 *   On the host run in a shell:
 *      while :; do kill -SIGHUP `pidof libvirtd`; echo "HUP $RANDOM"; sleep 20; done
 *
 *   Inside a couple of VMs that for example use the 'clean-traffic' filter:
 *      while :; do kill -SIGTERM `pidof dhclient`; dhclient eth0; ifconfig eth0; done
 *
 *   On the host check the lease file and that it's periodically shortened:
 *      cat $runstatedir/libvirt/network/nwfilter.leases; date +%s
 *
 *   On the host also check that the ebtables rules 'look' ok:
 *      ebtables -t nat -L
 */
#include <config.h>

#ifdef WITH_LIBPCAP
# include <pcap.h>
#endif

#include <fcntl.h>
#include <poll.h>

#include <net/if.h>

#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_ipaddrmap.h"
#include "virnetdev.h"
#include "virfile.h"
#include "virsocketaddr.h"
#include "virthreadpool.h"
#include "configmake.h"
#include "virtime.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_dhcpsnoop");

#ifdef WITH_LIBPCAP

# define LEASEFILE_DIR RUNSTATEDIR "/libvirt/network/"
# define LEASEFILE LEASEFILE_DIR "nwfilter.leases"
# define TMPLEASEFILE LEASEFILE_DIR "nwfilter.ltmp"

struct virNWFilterSnoopState {
    /* lease file */
    int                  leaseFD;
    int                  nLeases; /* number of active leases */
    int                  wLeases; /* number of written leases */
    int                  nThreads; /* number of running threads */
    /* thread management */
    GHashTable *     snoopReqs;
    GHashTable *     ifnameToKey;
    virMutex             snoopLock;  /* protects SnoopReqs and IfNameToKey */
    GHashTable *     active;
    virMutex             activeLock; /* protects Active */
};

# define VIR_IFKEY_LEN   ((VIR_UUID_STRING_BUFLEN) + (VIR_MAC_STRING_BUFLEN))

typedef struct _virNWFilterSnoopReq virNWFilterSnoopReq;

typedef struct _virNWFilterSnoopIPLease virNWFilterSnoopIPLease;

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

    virNWFilterTechDriver *            techdriver;
    virNWFilterBindingDef *            binding;
    int                                  ifindex;
    char                                 ifkey[VIR_IFKEY_LEN];
    virNWFilterDriverState *           driver;
    /* start and end of lease list, ordered by lease time */
    virNWFilterSnoopIPLease *          start;
    virNWFilterSnoopIPLease *          end;
    char                                *threadkey;
    virErrorPtr                          threadError;

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
 * 1st: virNWFilterSnoopState.snoopLock
 * 2nd: &req->lock
 *
 * Rationale: Former protects the SnoopReqs hash, latter its contents
 */

struct _virNWFilterSnoopIPLease {
    virSocketAddr              ipAddress;
    virSocketAddr              ipServer;
    virNWFilterSnoopReq *    snoopReq;
    time_t                     timeout;
    /* timer list */
    virNWFilterSnoopIPLease *prev;
    virNWFilterSnoopIPLease *next;
};

typedef struct _virNWFilterSnoopEthHdr virNWFilterSnoopEthHdr;
struct _virNWFilterSnoopEthHdr {
    virMacAddr eh_dst;
    virMacAddr eh_src;
    uint16_t eh_type;
    uint8_t eh_data[];
} ATTRIBUTE_PACKED;
G_STATIC_ASSERT(sizeof(struct _virNWFilterSnoopEthHdr) == 14);

typedef struct _virNWFilterSnoopDHCPHdr virNWFilterSnoopDHCPHdr;
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
G_STATIC_ASSERT(sizeof(struct _virNWFilterSnoopDHCPHdr) == 236);

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
struct _virNWFilterDHCPDecodeJob {
    unsigned char packet[PCAP_PBUFSIZE];
    int caplen;
    bool fromVM;
    int *qCtr;
};

# define DHCP_PKT_RATE          10 /* pkts/sec */
# define DHCP_PKT_BURST         50 /* pkts/sec */
# define DHCP_BURST_INTERVAL_S  10 /* sec */

# define MAX_QUEUED_JOBS        (DHCP_PKT_BURST + 2 * DHCP_PKT_RATE)

typedef struct _virNWFilterSnoopRateLimitConf virNWFilterSnoopRateLimitConf;
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
static int virNWFilterSnoopReqLeaseDel(virNWFilterSnoopReq *req,
                                       virSocketAddr *ipaddr,
                                       bool update_leasefile,
                                       bool instantiate);

static void virNWFilterSnoopLeaseFileLoad(void);
static void virNWFilterSnoopLeaseFileSave(virNWFilterSnoopIPLease *ipl);

/* local variables */
static struct virNWFilterSnoopState virNWFilterSnoopState = {
    .leaseFD = -1,
};

static const unsigned char dhcp_magic[4] = { 99, 130, 83, 99 };


static char *
virNWFilterSnoopActivate(virNWFilterSnoopReq *req)
{
    g_autofree char *key = g_strdup_printf("%p-%d", req, req->ifindex);
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.activeLock);

    if (virHashAddEntry(virNWFilterSnoopState.active, key, (void *)0x1) < 0)
        return NULL;

    return g_steal_pointer(&key);
}

static void
virNWFilterSnoopCancel(char **threadKey)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.activeLock);

    if (*threadKey == NULL)
        return;

    ignore_value(virHashRemoveEntry(virNWFilterSnoopState.active, *threadKey));
    g_clear_pointer(threadKey, g_free);
}

static bool
virNWFilterSnoopIsActive(char *threadKey)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.activeLock);

    if (threadKey == NULL)
        return false;

    return virHashLookup(virNWFilterSnoopState.active, threadKey) != NULL;
}

/*
 * virNWFilterSnoopListAdd - add an IP lease to a list
 */
static void
virNWFilterSnoopListAdd(virNWFilterSnoopIPLease *plnew,
                        virNWFilterSnoopIPLease **start,
                        virNWFilterSnoopIPLease **end)
{
    virNWFilterSnoopIPLease *pl;

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
virNWFilterSnoopListDel(virNWFilterSnoopIPLease *ipl,
                        virNWFilterSnoopIPLease **start,
                        virNWFilterSnoopIPLease **end)
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
virNWFilterSnoopIPLeaseTimerAdd(virNWFilterSnoopIPLease *plnew)
{
    virNWFilterSnoopReq *req = plnew->snoopReq;

    /* protect req->start / req->end */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    virNWFilterSnoopListAdd(plnew, &req->start, &req->end);
}

/*
 * virNWFilterSnoopLeaseTimerDel - remove an IP lease from the timer list
 */
static void
virNWFilterSnoopIPLeaseTimerDel(virNWFilterSnoopIPLease *ipl)
{
    virNWFilterSnoopReq *req = ipl->snoopReq;

    /* protect req->start / req->end */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    virNWFilterSnoopListDel(ipl, &req->start, &req->end);
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
virNWFilterSnoopIPLeaseInstallRule(virNWFilterSnoopIPLease *ipl,
                                   bool instantiate)
{
    g_autofree char *ipaddr = virSocketAddrFormat(&ipl->ipAddress);
    virNWFilterSnoopReq *req = ipl->snoopReq;
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    if (!ipaddr)
        return -1;

    if (virNWFilterIPAddrMapAddIPAddr(req->binding->portdevname, ipaddr) < 0)
        return -1;

    if (!instantiate)
        return 0;

    /* instantiate the filters */

    if (!req->binding->portdevname)
        return -1;

    return virNWFilterInstantiateFilterLate(req->driver, req->binding, req->ifindex);
}

/*
 * virNWFilterSnoopIPLeaseUpdate - update the timeout on an IP lease
 */
static void
virNWFilterSnoopIPLeaseUpdate(virNWFilterSnoopIPLease *ipl, time_t timeout)
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
static virNWFilterSnoopIPLease *
virNWFilterSnoopIPLeaseGetByIP(virNWFilterSnoopIPLease *start,
                               virSocketAddr *ipaddr)
{
    virNWFilterSnoopIPLease *pl;

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
virNWFilterSnoopReqLeaseTimerRun(virNWFilterSnoopReq *req)
{
    time_t now = time(0);
    bool is_last = false;

    /* protect req->start */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    while (req->start && req->start->timeout <= now) {
        if (req->start->next == NULL ||
            req->start->next->timeout > now)
            is_last = true;
        virNWFilterSnoopReqLeaseDel(req, &req->start->ipAddress, true,
                                    is_last);
    }

    return 0;
}

/*
 * Get a reference to the given Snoop request
 */
static void
virNWFilterSnoopReqGet(virNWFilterSnoopReq *req)
{
    g_atomic_int_add(&req->refctr, 1);
}

/*
 * Create a new Snoop request. Initialize it with the given
 * interface key. The caller must release the request with a call
 * to virNWFilerSnoopReqPut(req).
 */
static virNWFilterSnoopReq *
virNWFilterSnoopReqNew(const char *ifkey)
{
    g_autofree virNWFilterSnoopReq *req = g_new0(virNWFilterSnoopReq, 1);

    if (ifkey == NULL || strlen(ifkey) != VIR_IFKEY_LEN - 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterSnoopReqNew called with invalid key \"%1$s\" (%2$zu)"),
                       NULLSTR_EMPTY(ifkey),
                       ifkey ? strlen(ifkey) : 0);
        return NULL;
    }

    req->threadStatus = THREAD_STATUS_NONE;

    if (virStrcpyStatic(req->ifkey, ifkey) < 0 ||
        virMutexInitRecursive(&req->lock) < 0) {
        return NULL;
    }

    if (virCondInit(&req->threadStatusCond) < 0) {
        virMutexDestroy(&req->lock);
        return NULL;
    }

    virNWFilterSnoopReqGet(req);
    return g_steal_pointer(&req);
}

/*
 * Free a snoop request unless it is still referenced.
 * All its associated leases are also freed.
 * The lease file is NOT rewritten.
 */
static void
virNWFilterSnoopReqFree(virNWFilterSnoopReq *req)
{
    virNWFilterSnoopIPLease *ipl;

    if (!req)
        return;

    if (g_atomic_int_get(&req->refctr) != 0)
        return;

    /* free all leases */
    for (ipl = req->start; ipl; ipl = req->start)
        virNWFilterSnoopReqLeaseDel(req, &ipl->ipAddress, false, false);

    /* free all req data */
    virNWFilterBindingDefFree(req->binding);

    virMutexDestroy(&req->lock);
    virCondDestroy(&req->threadStatusCond);
    virFreeError(req->threadError);

    g_free(req);
}

/*
 * virNWFilterSnoopReqRelease - hash table free function to kill a request
 */
static void
virNWFilterSnoopReqRelease(void *req0)
{
    virNWFilterSnoopReq *req = req0;

    if (!req)
        return;

    /* protect req->threadkey */
    VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
        if (req->threadkey)
            virNWFilterSnoopCancel(&req->threadkey);
    }

    virNWFilterSnoopReqFree(req);
}

/*
 * virNWFilterSnoopReqGetByIFKey
 *
 * Get a Snoop request given an interface key; caller must release
 * the Snoop request with a call to virNWFilterSnoopReqPut()
 */
static virNWFilterSnoopReq *
virNWFilterSnoopReqGetByIFKey(const char *ifkey)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);
    virNWFilterSnoopReq *req;

    req = virHashLookup(virNWFilterSnoopState.snoopReqs, ifkey);
    if (req)
        virNWFilterSnoopReqGet(req);

    return req;
}

/*
 * Drop the reference to the Snoop request. Don't use the req
 * after this call.
 */
static void
virNWFilterSnoopReqPut(virNWFilterSnoopReq *req)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);

    if (!req)
        return;

    if (!!g_atomic_int_dec_and_test(&req->refctr)) {
        /*
         * delete the request:
         * - if we don't find req on the global list anymore
         *   (this happens during SIGHUP)
         * we would keep the request:
         * - if we still have a valid lease, keep the req for restarts
         */
        if (virHashLookup(virNWFilterSnoopState.snoopReqs, req->ifkey) != req) {
            virNWFilterSnoopReqRelease(req);
        } else if (!req->start || req->start->timeout < time(0)) {
            ignore_value(virHashRemoveEntry(virNWFilterSnoopState.snoopReqs,
                                            req->ifkey));
        }
    }
}

/*
 * virNWFilterSnoopReqLeaseAdd - create or update an IP lease
 */
static int
virNWFilterSnoopReqLeaseAdd(virNWFilterSnoopReq *req,
                            virNWFilterSnoopIPLease *plnew,
                            bool update_leasefile)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);
    virNWFilterSnoopIPLease *pl;

    plnew->snoopReq = req;

    pl = virNWFilterSnoopIPLeaseGetByIP(req->start, &plnew->ipAddress);

    if (pl) {
        virNWFilterSnoopIPLeaseUpdate(pl, plnew->timeout);
        virLockGuardUnlock(&lock);
    } else {
        pl = g_new0(virNWFilterSnoopIPLease, 1);
        *pl = *plnew;

        if (req->threadkey && virNWFilterSnoopIPLeaseInstallRule(pl, true) < 0) {
            g_free(pl);
            return -1;
        }

        virLockGuardUnlock(&lock);

        /* put the lease on the req's list */
        virNWFilterSnoopIPLeaseTimerAdd(pl);

        g_atomic_int_add(&virNWFilterSnoopState.nLeases, 1);
    }

    if (update_leasefile)
        virNWFilterSnoopLeaseFileSave(pl);

    return 0;
}

/*
 * Restore a Snoop request -- walk its list of leases
 * and re-build the filtering rules with them
 */
static int
virNWFilterSnoopReqRestore(virNWFilterSnoopReq *req)
{
    virNWFilterSnoopIPLease *ipl;

    /* protect req->start */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    for (ipl = req->start; ipl; ipl = ipl->next) {
        /* instantiate the rules at the last lease */
        bool is_last = (ipl->next == NULL);
        if (virNWFilterSnoopIPLeaseInstallRule(ipl, is_last) < 0)
            return -1;
    }

    return 0;
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
virNWFilterSnoopReqLeaseDel(virNWFilterSnoopReq *req,
                            virSocketAddr *ipaddr, bool update_leasefile,
                            bool instantiate)
{
    int ret = 0;
    virNWFilterSnoopIPLease *ipl;
    g_autofree char *ipstr = NULL;

    /* protect req->start, req->ifname and the lease */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    ipl = virNWFilterSnoopIPLeaseGetByIP(req->start, ipaddr);
    if (ipl == NULL)
        return 0;

    ipstr = virSocketAddrFormat(&ipl->ipAddress);
    if (!ipstr) {
        return -1;
    }

    virNWFilterSnoopIPLeaseTimerDel(ipl);
    /* lease is off the list now */

    if (update_leasefile)
        virNWFilterSnoopLeaseFileSave(ipl);

    if (!req->threadkey || !instantiate)
        goto skip_instantiate;

    /* Assumes that req->binding is valid since req->threadkey
     * is only generated after req->binding is filled in during
     * virNWFilterDHCPSnoopReq processing */
    if ((virNWFilterIPAddrMapDelIPAddr(req->binding->portdevname, ipstr)) > 0) {
        ret = virNWFilterInstantiateFilterLate(req->driver,
                                               req->binding,
                                               req->ifindex);
    } else {
        virNWFilterVarValue *dhcpsrvrs =
            virHashLookup(req->binding->filterparams,
                          NWFILTER_VARNAME_DHCPSERVER);

        if (req->techdriver &&
            req->techdriver->applyDHCPOnlyRules(req->binding->portdevname,
                                                &req->binding->mac,
                                                dhcpsrvrs, false) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("virNWFilterSnoopListDel failed"));
            ret = -1;
        }

    }

 skip_instantiate:
    g_free(ipl);

    ignore_value(!!g_atomic_int_dec_and_test(&virNWFilterSnoopState.nLeases));
    return ret;
}

static int
virNWFilterSnoopDHCPGetOpt(virNWFilterSnoopDHCPHdr *pd, int len,
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
                goto error;
            if (*pleasetime)
                return -1;  /* duplicate lease time */
            memcpy(&nwint, (char *)pd->d_opts + oind + 2, sizeof(nwint));
            *pleasetime = ntohl(nwint);
            break;
        case DHCPO_MTYPE:
            if (olen - oind < 3)
                goto error;
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
                goto error;
        }
        oind += pd->d_opts[oind + 1] + 2;
    }
    return 0;
 error:
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
virNWFilterSnoopDHCPDecode(virNWFilterSnoopReq *req,
                           virNWFilterSnoopEthHdr *pep,
                           int len, bool fromVM)
{
    struct iphdr *pip;
    struct udphdr *pup;
    virNWFilterSnoopDHCPHdr *pd;
    virNWFilterSnoopIPLease ipl = { 0 };
    uint8_t mtype;
    uint32_t leasetime;
    uint32_t nwint;

    /* go through the protocol headers */
    switch (ntohs(pep->eh_type)) {
    case ETHERTYPE_IP:
        VIR_WARNINGS_NO_CAST_ALIGN
        pip = (struct iphdr *)pep->eh_data;
        VIR_WARNINGS_RESET
        len -= offsetof(virNWFilterSnoopEthHdr, eh_data);
        break;
    default:
        return -2;
    }

    if (len < 0)
        return -2;

    VIR_WARNINGS_NO_CAST_ALIGN
    pup = (struct udphdr *)((char *)pip + (pip->ihl << 2));
    VIR_WARNINGS_RESET
    len -= pip->ihl << 2;
    if (len < 0)
        return -2;

    pd = (virNWFilterSnoopDHCPHdr *) ((char *)pup + sizeof(*pup));
    len -= sizeof(*pup);
    if (len < 0)
        return -2;                 /* invalid packet length */

    /*
     * some DHCP servers send their responses as MAC broadcast replies
     * filter messages from the server also by the destination MAC
     * inside the DHCP response
     */
    if (!fromVM) {
        if (virMacAddrCmpRaw(&req->binding->mac,
                             (unsigned char *)&pd->d_chaddr) != 0)
            return -2;
    }

    if (virNWFilterSnoopDHCPGetOpt(pd, len, &mtype, &leasetime) < 0)
        return -2;

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
    g_autofree char *ext_filter = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);

    if (dir == PCAP_D_IN /* from VM */) {
        /*
         * don't want to hear about another VM's DHCP requests
         *
         * extend the filter with the macaddr of the VM; filter the
         * more unlikely parameters first, then go for the MAC
         */
        ext_filter = g_strdup_printf("%s and ether src %s", filter, macaddr);
    } else {
        /*
         * Some DHCP servers respond via MAC broadcast; we rely on later
         * filtering of responses by comparing the MAC address inside the
         * DHCP response against the one of the VM. Assuming that the
         * bridge learns the VM's MAC address quickly this should not
         * generate much more traffic than if we filtered by VM and
         * braodcast MAC as well
         */
        ext_filter = g_strdup(filter);
    }

    handle = pcap_create(ifname, pcap_errbuf);

    if (handle == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("pcap_create failed"));
        return NULL;
    }

    if (pcap_set_snaplen(handle, PCAP_PBUFSIZE) < 0 ||
        pcap_set_immediate_mode(handle, 1) < 0 ||
        pcap_activate(handle) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("setup of pcap handle failed: %1$s"),
                       pcap_geterr(handle));
        goto cleanup;
    }

    if (pcap_compile(handle, &fp, ext_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_compile: %1$s"), pcap_geterr(handle));
        goto cleanup;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_setfilter: %1$s"), pcap_geterr(handle));
        goto cleanup_freecode;
    }

    if (pcap_setdirection(handle, dir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pcap_setdirection: %1$s"),
                       pcap_geterr(handle));
        goto cleanup_freecode;
    }

    pcap_freecode(&fp);
    return handle;

 cleanup_freecode:
    pcap_freecode(&fp);
 cleanup:
    pcap_close(handle);
    return NULL;
}

/*
 * Worker function to decode the DHCP message and with that
 * also do the time-consuming work of instantiating the filters
 */
static void virNWFilterDHCPDecodeWorker(void *jobdata, void *opaque)
{
    virNWFilterSnoopReq *req = opaque;
    g_autofree virNWFilterDHCPDecodeJob *job = jobdata;
    virNWFilterSnoopEthHdr *packet = (virNWFilterSnoopEthHdr *)job->packet;

    if (virNWFilterSnoopDHCPDecode(req, packet,
                                   job->caplen, job->fromVM) == -1) {
        req->jobCompletionStatus = -1;

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Instantiation of rules failed on interface '%1$s'"),
                       req->binding->portdevname);
    }
    ignore_value(!!g_atomic_int_dec_and_test(job->qCtr));
}

/*
 * Submit a job to the worker thread doing the time-consuming work...
 */
static int
virNWFilterSnoopDHCPDecodeJobSubmit(virThreadPool *pool,
                                    virNWFilterSnoopEthHdr *pep,
                                    int len, pcap_direction_t dir,
                                    int *qCtr)
{
    virNWFilterDHCPDecodeJob *job;
    int ret;

    if (len <= MIN_VALID_DHCP_PKT_SIZE || len > sizeof(job->packet))
        return 0;

    job = g_new0(virNWFilterDHCPDecodeJob, 1);

    memcpy(job->packet, pep, len);
    job->caplen = len;
    job->fromVM = (dir == PCAP_D_IN);
    job->qCtr = qCtr;

    ret = virThreadPoolSendJob(pool, 0, job);

    if (ret == 0)
        g_atomic_int_add(qCtr, 1);
    else
        g_free(job);

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
virNWFilterSnoopRateLimit(virNWFilterSnoopRateLimitConf *rl)
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
virNWFilterSnoopRatePenalty(virNWFilterSnoopPcapConf *pc,
                            unsigned int diff, unsigned int limit)
{
    if (diff > limit) {
        unsigned long long now;

        if (virTimeMillisNowRaw(&now) < 0) {
            g_usleep(PCAP_FLOOD_TIMEOUT_MS); /* 1 ms */
            pc->penaltyTimeoutAbs = 0;
        } else {
            /* don't listen to the fd for 1 ms */
            pc->penaltyTimeoutAbs = now + PCAP_FLOOD_TIMEOUT_MS;
        }
    }
}

static int
virNWFilterSnoopAdjustPoll(virNWFilterSnoopPcapConf *pc,
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
    virNWFilterSnoopReq *req = req0;
    struct pcap_pkthdr *hdr;
    virNWFilterSnoopEthHdr *packet;
    int ifindex = 0;
    int errcount = 0;
    int tmp = -1, rv, n, pollTo;
    size_t i;
    g_autofree char *threadkey = NULL;
    virThreadPool *worker = NULL;
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

    /* protect req->binding->portdevname & req->threadkey */
    VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
        if (req->binding->portdevname && req->threadkey) {
            for (i = 0; i < G_N_ELEMENTS(pcapConf); i++) {
                pcapConf[i].handle =
                    virNWFilterSnoopDHCPOpen(req->binding->portdevname,
                                             &req->binding->mac,
                                             pcapConf[i].filter,
                                             pcapConf[i].dir);
                if (!pcapConf[i].handle) {
                    error = true;
                    break;
                }
                fds[i].fd = pcap_fileno(pcapConf[i].handle);
            }
            tmp = virNetDevGetIndex(req->binding->portdevname, &ifindex);
            threadkey = g_strdup(req->threadkey);
            worker = virThreadPoolNewFull(1, 1, 0, virNWFilterDHCPDecodeWorker,
                                          "dhcp-decode", NULL, req);
        }

        /* let creator know how well we initialized */
        if (error || !threadkey || tmp < 0 || !worker || ifindex != req->ifindex) {
            virErrorPreserveLast(&req->threadError);
            req->threadStatus = THREAD_STATUS_FAIL;
        } else {
            req->threadStatus = THREAD_STATUS_OK;
        }

        virCondSignal(&req->threadStatusCond);
    }

    if (req->threadStatus != THREAD_STATUS_OK)
        goto cleanup;

    while (!error) {
        if (virNWFilterSnoopAdjustPoll(pcapConf,
                                       G_N_ELEMENTS(pcapConf),
                                       fds, &pollTo) < 0) {
            break;
        }

        /* cap pollTo so we don't hold up the join for too long */
        if (pollTo < 0 || pollTo > SNOOP_POLL_MAX_TIMEOUT_MS)
            pollTo = SNOOP_POLL_MAX_TIMEOUT_MS;

        n = poll(fds, G_N_ELEMENTS(fds), pollTo);

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
            goto cleanup;

        for (i = 0; n > 0 && i < G_N_ELEMENTS(fds); i++) {
            if (!fds[i].revents)
                continue;

            fds[i].revents = 0;
            n--;

            rv = pcap_next_ex(pcapConf[i].handle, &hdr,
                              (const u_char **)&packet);

            if (rv < 0) {
                /* error reading from socket */
                tmp = -1;

                /* protect req->binding->portdevname */
                VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
                    if (req->binding->portdevname)
                        tmp = virNetDevValidateConfig(req->binding->portdevname, NULL, ifindex);
                }

                if (tmp <= 0) {
                    error = true;
                    break;
                }

                if (++errcount > PCAP_READ_MAXERRS) {
                    g_clear_pointer(&pcapConf[i].handle, pcap_close);

                    /* protect req->binding->portdevname */
                    VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("interface '%1$s' failing; reopening"),
                                       req->binding->portdevname);
                        if (req->binding->portdevname)
                            pcapConf[i].handle =
                                virNWFilterSnoopDHCPOpen(req->binding->portdevname,
                                                         &req->binding->mac,
                                                         pcapConf[i].filter,
                                                         pcapConf[i].dir);
                    }

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
                if (g_atomic_int_get(&pcapConf[i].qCtr) >
                    pcapConf[i].maxQSize) {
                    if (last_displayed_queue - time(0) > 10) {
                        last_displayed_queue = time(0);
                        VIR_WARN("Worker thread for interface '%s' has a "
                                 "job queue that is too long",
                                 req->binding->portdevname);
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
                                  req->binding->portdevname);
                    }
                    continue;
                }

                if (virNWFilterSnoopDHCPDecodeJobSubmit(worker, packet,
                                                      hdr->caplen,
                                                      pcapConf[i].dir,
                                                      &pcapConf[i].qCtr) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Job submission failed on interface '%1$s'"),
                                   req->binding->portdevname);
                    error = true;
                    break;
                }
            }
        } /* for all fds */
    } /* while (!error) */

    /* protect IfNameToKey */
    VIR_WITH_MUTEX_LOCK_GUARD(&virNWFilterSnoopState.snoopLock) {
        /* protect req->binding->portdevname & req->threadkey */
        VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
            virNWFilterSnoopCancel(&req->threadkey);

            ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                            req->binding->portdevname));

            g_clear_pointer(&req->binding->portdevname, g_free);
        }
    }

 cleanup:
    virThreadPoolFree(worker);

    virNWFilterSnoopReqPut(req);

    for (i = 0; i < G_N_ELEMENTS(pcapConf); i++) {
        if (pcapConf[i].handle)
            pcap_close(pcapConf[i].handle);
    }

    ignore_value(!!g_atomic_int_dec_and_test(&virNWFilterSnoopState.nThreads));

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
virNWFilterDHCPSnoopReq(virNWFilterTechDriver *techdriver,
                        virNWFilterBindingDef *binding,
                        virNWFilterDriverState *driver)
{
    virNWFilterSnoopReq *req;
    bool isnewreq;
    char ifkey[VIR_IFKEY_LEN];
    int tmp;
    virThread thread;
    virNWFilterVarValue *dhcpsrvrs;
    bool threadPuts = false;

    virNWFilterSnoopIFKeyFMT(ifkey, binding->owneruuid, &binding->mac);

    req = virNWFilterSnoopReqGetByIFKey(ifkey);
    isnewreq = (req == NULL);
    if (!isnewreq) {
        if (req->threadkey) {
            virNWFilterSnoopReqPut(req);
            return 0;
        }
        g_clear_pointer(&req->binding, virNWFilterBindingDefFree);
    } else {
        req = virNWFilterSnoopReqNew(ifkey);
        if (!req)
            return -1;
    }

    req->driver = driver;
    req->techdriver = techdriver;
    if ((tmp = virNetDevGetIndex(binding->portdevname, &req->ifindex)) < 0)
        goto exit_snoopreqput;
    if (!(req->binding = virNWFilterBindingDefCopy(binding)))
        goto exit_snoopreqput;

    /* check that all tools are available for applying the filters (late) */
    if (!techdriver->canApplyBasicRules()) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IP parameter must be provided since snooping the IP address does not work possibly due to missing tools"));
        goto exit_snoopreqput;
    }

    dhcpsrvrs = virHashLookup(binding->filterparams,
                              NWFILTER_VARNAME_DHCPSERVER);

    if (techdriver->applyDHCPOnlyRules(req->binding->portdevname,
                                       &req->binding->mac,
                                       dhcpsrvrs, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("applyDHCPOnlyRules failed - spoofing not protected!"));
        goto exit_snoopreqput;
    }

    virMutexLock(&virNWFilterSnoopState.snoopLock);

    if (virHashAddEntry(virNWFilterSnoopState.ifnameToKey,
                        req->binding->portdevname,
                        req->ifkey) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq ifname map failed on interface \"%1$s\" key \"%2$s\""),
                       binding->portdevname,
                       ifkey);
        goto exit_snoopunlock;
    }

    if (isnewreq &&
        virHashAddEntry(virNWFilterSnoopState.snoopReqs, ifkey, req) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq req add failed on interface \"%1$s\" ifkey \"%2$s\""),
                       binding->portdevname,
                       ifkey);
        goto exit_rem_ifnametokey;
    }

    /* prevent thread from holding req */
    virMutexLock(&req->lock);

    if (virThreadCreateFull(&thread, false, virNWFilterDHCPSnoopThread,
                            "dhcp-snoop", false, req) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virNWFilterDHCPSnoopReq virThreadCreate failed on interface '%1$s'"),
                       binding->portdevname);
        goto exit_snoopreq_unlock;
    }

    threadPuts = true;

    g_atomic_int_add(&virNWFilterSnoopState.nThreads, 1);

    req->threadkey = virNWFilterSnoopActivate(req);
    if (!req->threadkey) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Activation of snoop request failed on interface '%1$s'"),
                       req->binding->portdevname);
        goto exit_snoopreq_unlock;
    }

    if (virNWFilterSnoopReqRestore(req) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Restoring of leases failed on interface '%1$s'"),
                       req->binding->portdevname);
        goto exit_snoop_cancel;
    }

    /* sync with thread */
    if (virCondWait(&req->threadStatusCond, &req->lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to wait on dhcp snoop thread"));
        goto exit_snoop_cancel;
    }

    if (req->threadStatus != THREAD_STATUS_OK) {
        virErrorRestore(&req->threadError);
        goto exit_snoop_cancel;
    }

    virMutexUnlock(&req->lock);

    virMutexUnlock(&virNWFilterSnoopState.snoopLock);

    /* do not 'put' the req -- the thread will do this */

    return 0;

 exit_snoop_cancel:
    virNWFilterSnoopCancel(&req->threadkey);
 exit_snoopreq_unlock:
    virMutexUnlock(&req->lock);
 exit_rem_ifnametokey:
    virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey, binding->portdevname);
 exit_snoopunlock:
    virMutexUnlock(&virNWFilterSnoopState.snoopLock);
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
                               virNWFilterSnoopIPLease *ipl)
{
    g_autofree char *lbuf = NULL;
    g_autofree char *ipstr = virSocketAddrFormat(&ipl->ipAddress);
    g_autofree char *dhcpstr = virSocketAddrFormat(&ipl->ipServer);
    int len;

    if (!dhcpstr || !ipstr)
        return -1;

    /* time intf ip dhcpserver */
    lbuf = g_strdup_printf("%llu %s %s %s\n",
                           (unsigned long long) ipl->timeout,
                           ifkey, ipstr, dhcpstr);
    len = strlen(lbuf);

    if (safewrite(lfd, lbuf, len) != len) {
        virReportSystemError(errno, "%s", _("lease file write failed"));
        return -1;
    }

    ignore_value(g_fsync(lfd));
    return 0;
}

/*
 * Append a single lease to the end of the lease file.
 * To keep a limited number of dead leases, re-read the lease
 * file if the threshold of active leases versus written ones
 * exceeds a threshold.
 */
static void
virNWFilterSnoopLeaseFileSave(virNWFilterSnoopIPLease *ipl)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);
    virNWFilterSnoopReq *req = ipl->snoopReq;

    if (virNWFilterSnoopState.leaseFD < 0)
        virNWFilterSnoopLeaseFileOpen();
    if (virNWFilterSnoopLeaseFileWrite(virNWFilterSnoopState.leaseFD,
                                       req->ifkey, ipl) < 0)
        return;

    /* keep dead leases at < ~95% of file size */
    if (g_atomic_int_add(&virNWFilterSnoopState.wLeases, 1) >=
        g_atomic_int_get(&virNWFilterSnoopState.nLeases) * 20)
        virNWFilterSnoopLeaseFileLoad();   /* load & refresh lease file */
}

/*
 * Have requests removed that have no leases.
 * Remove all expired leases.
 * Call this function with the SnoopLock held.
 */
static int
virNWFilterSnoopPruneIter(const void *payload,
                          const char *name G_GNUC_UNUSED,
                          const void *data G_GNUC_UNUSED)
{
    virNWFilterSnoopReq *req = (virNWFilterSnoopReq *)payload;

    /* clean up orphaned, expired leases */

    /* protect req->threadkey */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    if (!req->threadkey)
        virNWFilterSnoopReqLeaseTimerRun(req);

    /*
     * have the entry removed if it has no leases and no one holds a ref
     */
    return ((req->start == NULL) && (g_atomic_int_get(&req->refctr) == 0));
}

/*
 * Iterator to write all leases of a single request to a file.
 * Call this function with the SnoopLock held.
 */
static int
virNWFilterSnoopSaveIter(void *payload,
                         const char *name G_GNUC_UNUSED,
                         void *data)
{
    virNWFilterSnoopReq *req = payload;
    int tfd = *(int *)data;
    virNWFilterSnoopIPLease *ipl;

    /* protect req->start */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    for (ipl = req->start; ipl; ipl = ipl->next)
        ignore_value(virNWFilterSnoopLeaseFileWrite(tfd, req->ifkey, ipl));

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

    if (g_mkdir_with_parents(LEASEFILE_DIR, 0700) < 0) {
        virReportError(errno, _("mkdir(\"%1$s\")"), LEASEFILE_DIR);
        return;
    }

    if (unlink(TMPLEASEFILE) < 0 && errno != ENOENT)
        virReportSystemError(errno, _("unlink(\"%1$s\")"), TMPLEASEFILE);

    /* lease file loaded, delete old one */
    tfd = open(TMPLEASEFILE, O_CREAT|O_RDWR|O_TRUNC|O_EXCL, 0644);
    if (tfd < 0) {
        virReportSystemError(errno, _("open(\"%1$s\")"), TMPLEASEFILE);
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
        virReportSystemError(errno, _("unable to close %1$s"), TMPLEASEFILE);
        /* assuming the old lease file is still better, skip the renaming */
        goto cleanup;
    }

    if (rename(TMPLEASEFILE, LEASEFILE) < 0) {
        virReportSystemError(errno, _("rename(\"%1$s\", \"%2$s\")"),
                             TMPLEASEFILE, LEASEFILE);
        unlink(TMPLEASEFILE);
    }
    g_atomic_int_set(&virNWFilterSnoopState.wLeases, 0);

 cleanup:
    virNWFilterSnoopLeaseFileOpen();
}


static void
virNWFilterSnoopLeaseFileLoad(void)
{
    char line[256], ifkey[VIR_IFKEY_LEN];
    char ipstr[INET_ADDRSTRLEN], srvstr[INET_ADDRSTRLEN];
    virNWFilterSnoopIPLease ipl;
    virNWFilterSnoopReq *req;
    time_t now;
    FILE *fp;
    int ln = 0, tmp;
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);

    fp = fopen(LEASEFILE, "r");
    time(&now);
    while (fp && fgets(line, sizeof(line), fp)) {
        unsigned long long timeout;

        if (line[strlen(line)-1] != '\n') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("virNWFilterSnoopLeaseFileLoad lease file line %1$d corrupt"),
                           ln);
            break;
        }
        ln++;
        /* key len 54 = "VMUUID"+'-'+"MAC" */
        if (sscanf(line, "%llu %54s %15s %15s",
                   &timeout, ifkey, ipstr, srvstr) < 4) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("virNWFilterSnoopLeaseFileLoad lease file line %1$d corrupt"),
                           ln);
            break;
        }
        ipl.timeout = timeout;
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
                               _("virNWFilterSnoopLeaseFileLoad req add failed on interface \"%1$s\""),
                               ifkey);
                continue;
            }
        }

        if (virSocketAddrParseIPv4(&ipl.ipAddress, ipstr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("line %1$d corrupt ipaddr \"%2$s\""),
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
}

/*
 * Wait until all threads have ended.
 */
static void
virNWFilterSnoopJoinThreads(void)
{
    while (g_atomic_int_get(&virNWFilterSnoopState.nThreads) != 0) {
        VIR_WARN("Waiting for snooping threads to terminate: %u",
                 g_atomic_int_get(&virNWFilterSnoopState.nThreads));
        g_usleep(1000 * 1000);
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
                              const char *name G_GNUC_UNUSED,
                              const void *data G_GNUC_UNUSED)
{
    virNWFilterSnoopReq *req = (virNWFilterSnoopReq *)payload;

    /* protect req->binding->portdevname */
    VIR_LOCK_GUARD lock = virLockGuardLock(&req->lock);

    if (req->binding && req->binding->portdevname) {
        ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                        req->binding->portdevname));

        /*
         * Remove all IP addresses known to be associated with this
         * interface so that a new thread will be started on this
         * interface
         */
        virNWFilterIPAddrMapDelIPAddr(req->binding->portdevname, NULL);

        g_clear_pointer(&req->binding->portdevname, g_free);
    }

    /* removal will call virNWFilterSnoopCancel() */
    return 1;
}


/*
 * Terminate all threads; keep the SnoopReqs hash allocated
 */
static void
virNWFilterSnoopEndThreads(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);

    virHashRemoveSet(virNWFilterSnoopState.snoopReqs,
                     virNWFilterSnoopRemAllReqIter,
                     NULL);
}

int
virNWFilterDHCPSnoopInit(void)
{
    if (virNWFilterSnoopState.snoopReqs)
        return 0;

    VIR_DEBUG("Initializing DHCP snooping");

    if (virMutexInitRecursive(&virNWFilterSnoopState.snoopLock) < 0)
        return -1;

    if (virMutexInit(&virNWFilterSnoopState.activeLock) < 0) {
        virMutexDestroy(&virNWFilterSnoopState.snoopLock);
        return -1;
    }

    virNWFilterSnoopState.ifnameToKey = virHashNew(NULL);
    virNWFilterSnoopState.active = virHashNew(NULL);
    virNWFilterSnoopState.snoopReqs =
        virHashNew(virNWFilterSnoopReqRelease);

    virNWFilterSnoopLeaseFileLoad();
    virNWFilterSnoopLeaseFileOpen();

    return 0;
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
    VIR_LOCK_GUARD lock = virLockGuardLock(&virNWFilterSnoopState.snoopLock);
    char *ifkey = NULL;

    if (!virNWFilterSnoopState.snoopReqs)
        return;

    if (ifname) {
        ifkey = (char *)virHashLookup(virNWFilterSnoopState.ifnameToKey,
                                      ifname);
        if (!ifkey)
            return;

        ignore_value(virHashRemoveEntry(virNWFilterSnoopState.ifnameToKey,
                                        ifname));
    }

    if (ifkey) {
        virNWFilterSnoopReq *req;

        req = virNWFilterSnoopReqGetByIFKey(ifkey);
        if (!req) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("ifkey \"%1$s\" has no req"), ifkey);
            return;
        }

        /* protect req->binding->portdevname & req->threadkey */
        VIR_WITH_MUTEX_LOCK_GUARD(&req->lock) {
            /* keep valid lease req; drop interface association */
            virNWFilterSnoopCancel(&req->threadkey);

            g_clear_pointer(&req->binding->portdevname, g_free);
        }

        virNWFilterSnoopReqPut(req);
    } else {                      /* free all of them */
        virNWFilterSnoopLeaseFileClose();

        virHashRemoveAll(virNWFilterSnoopState.ifnameToKey);

        /* tell the threads to terminate */
        virNWFilterSnoopEndThreads();

        virNWFilterSnoopLeaseFileLoad();
    }
}

void
virNWFilterDHCPSnoopShutdown(void)
{
    if (!virNWFilterSnoopState.snoopReqs)
        return;

    virNWFilterSnoopEndThreads();
    virNWFilterSnoopJoinThreads();

    VIR_WITH_MUTEX_LOCK_GUARD(&virNWFilterSnoopState.snoopLock) {
        virNWFilterSnoopLeaseFileClose();
        g_clear_pointer(&virNWFilterSnoopState.ifnameToKey, g_hash_table_unref);
        g_clear_pointer(&virNWFilterSnoopState.snoopReqs, g_hash_table_unref);
    }

    virMutexDestroy(&virNWFilterSnoopState.snoopLock);

    VIR_WITH_MUTEX_LOCK_GUARD(&virNWFilterSnoopState.activeLock) {
        g_clear_pointer(&virNWFilterSnoopState.active, g_hash_table_unref);
    }

    virMutexDestroy(&virNWFilterSnoopState.activeLock);
}

#else /* WITH_LIBPCAP */

int
virNWFilterDHCPSnoopInit(void)
{
    VIR_DEBUG("No DHCP snooping support available");
    return 0;
}

void
virNWFilterDHCPSnoopEnd(const char *ifname G_GNUC_UNUSED)
{
    return;
}

void
virNWFilterDHCPSnoopShutdown(void)
{
    return;
}

int
virNWFilterDHCPSnoopReq(virNWFilterTechDriver *techdriver G_GNUC_UNUSED,
                        virNWFilterBindingDef *binding G_GNUC_UNUSED,
                        virNWFilterDriverState *driver G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("libvirt was not compiled with libpcap and \"%1$s\" requires it"),
                     NWFILTER_VARNAME_CTRL_IP_LEARNING "='dhcp'");
    return -1;
}
#endif /* WITH_LIBPCAP */
