/*
 * Copyright (C) 2009-2015 Red Hat, Inc.
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
#include <unistd.h>

#include "virnetdevbandwidth.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevbandwidth");

void
virNetDevBandwidthFree(virNetDevBandwidth *def)
{
    if (!def)
        return;

    g_free(def->in);
    g_free(def->out);
    g_free(def);
}

static void
virNetDevBandwidthCmdAddOptimalQuantum(virCommand *cmd,
                                       const virNetDevBandwidthRate *rate)
{
    const unsigned long long mtu = 1500;
    unsigned long long r2q;

    /* When two or more classes compete for unused bandwidth they are each
     * given some number of bytes before serving other competing class. This
     * number is called quantum. It's advised in HTB docs that the number
     * should be equal to MTU. The class quantum is computed from its rate
     * divided by global r2q parameter. However, if rate is too small the
     * default value will not suffice and thus we must provide our own value.
     * */

    r2q = rate->average * 1024 / 8 / mtu;
    if (!r2q)
        r2q = 1;

    virCommandAddArg(cmd, "quantum");
    virCommandAddArgFormat(cmd, "%llu", r2q);
}

/**
 * virNetDevBandwidthManipulateFilter:
 * @ifname: interface to operate on
 * @ifmac_ptr: MAC of the interface to create filter over
 * @id: filter ID
 * @class_id: where to place traffic
 * @remove_old: whether to remove the filter
 * @create_new: whether to create the filter
 *
 * TC filters are as crucial for traffic shaping as QDiscs. While
 * QDiscs act like black boxes deciding which packets should be
 * held up and which should be sent immediately, it's the filter
 * that places a packet into the box. So, we may end up
 * constructing a set of filters on a single device (e.g. a
 * bridge) and filter the traffic into QDiscs based on the
 * originating vNET device.
 *
 * Long story short, @ifname is the interface where the filter
 * should be created. The @ifmac_ptr is the MAC address for which
 * the filter should be created (usually different to the MAC
 * address of @ifname). Then, like everything - even filters have
 * an @id which should be unique (per @ifname). And @class_id
 * tells into which QDisc should filter place the traffic.
 *
 * This function can be used for both, removing stale filter
 * (@remove_old set to true) and creating new one (@create_new
 * set to true). Both at once for the same price!
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported).
 */
static int ATTRIBUTE_NONNULL(1)
virNetDevBandwidthManipulateFilter(const char *ifname,
                                   const virMacAddr *ifmac_ptr,
                                   unsigned int id,
                                   const char *class_id,
                                   bool remove_old,
                                   bool create_new)
{
    int ret = -1;
    g_autofree char *filter_id = NULL;
    unsigned char ifmac[VIR_MAC_BUFLEN];
    char *mac[2] = {NULL, NULL};

    if (!(remove_old || create_new)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filter creation API error"));
        goto cleanup;
    }

    /* u32 filters must have 800:: prefix. Don't ask. Furthermore, handles
     * start at 800. Therefore, we want the filter ID to look like this:
     *   800::(800 + id) */
    filter_id = g_strdup_printf("800::%u", 800 + id);

    if (remove_old) {
        g_autoptr(virCommand) cmd = virCommandNew(TC);
        int cmd_ret = 0;

        virCommandAddArgList(cmd, "filter", "del", "dev", ifname,
                             "prio", "2", "handle",  filter_id, "u32", NULL);

        if (virCommandRun(cmd, &cmd_ret) < 0)
            goto cleanup;

    }

    if (create_new) {
        g_autoptr(virCommand) cmd = virCommandNew(TC);
        virMacAddrGetRaw(ifmac_ptr, ifmac);

        mac[0] = g_strdup_printf("0x%02x%02x%02x%02x", ifmac[2],
                                 ifmac[3], ifmac[4], ifmac[5]);
        mac[1] = g_strdup_printf("0x%02x%02x", ifmac[0], ifmac[1]);

        /* Okay, this not nice. But since libvirt does not necessarily track
         * interface IP address(es), and tc fw filter simply refuse to use
         * ebtables marks, we need to use u32 selector to match MAC address.
         * If libvirt will ever know something, remove this FIXME
         */
        virCommandAddArgList(cmd, "filter", "add", "dev", ifname, "protocol", "ip",
                             "prio", "2", "handle", filter_id, "u32",
                             "match", "u16", "0x0800", "0xffff", "at", "-2",
                             "match", "u32", mac[0], "0xffffffff", "at", "-12",
                             "match", "u16", mac[1], "0xffff", "at", "-14",
                             "flowid", class_id, NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(mac[1]);
    VIR_FREE(mac[0]);
    return ret;
}


/**
 * virNetDevBandwidthSet:
 * @ifname: on which interface
 * @bandwidth: rates to set (may be NULL)
 * @hierarchical_class: whether to create hierarchical class
 * @swapped: true if IN/OUT should be set contrariwise
 *
 * This function enables QoS on specified interface
 * and set given traffic limits for both, incoming
 * and outgoing traffic. Any previous setting get
 * overwritten. If @hierarchical_class is TRUE, create
 * hierarchical class. It is used to guarantee minimal
 * throughput ('floor' attribute in NIC).
 *
 * If @swapped is set, the IN part of @bandwidth is set on
 * @ifname's TX, and vice versa. If it is not set, IN is set on
 * RX and OUT on TX. This is because for some types of interfaces
 * domain and the host live on the same side of the interface (so
 * domain's RX/TX is host's RX/TX), and for some it's swapped
 * (domain's RX/TX is hosts's TX/RX).
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthSet(const char *ifname,
                      const virNetDevBandwidth *bandwidth,
                      bool hierarchical_class,
                      bool swapped)
{
    int ret = -1;
    virNetDevBandwidthRate *rx = NULL; /* From domain POV */
    virNetDevBandwidthRate *tx = NULL; /* From domain POV */
    virCommand *cmd = NULL;
    char *average = NULL;
    char *peak = NULL;
    char *burst = NULL;

    if (!bandwidth) {
        /* nothing to be enabled */
        ret = 0;
        goto cleanup;
    }

    if (geteuid() != 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Network bandwidth tuning is not available in session mode"));
        return -1;
    }

    if (!ifname) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to set bandwidth for interface because device name is unknown"));
        return -1;
    }

    if (swapped) {
        rx = bandwidth->out;
        tx = bandwidth->in;
    } else {
        rx = bandwidth->in;
        tx = bandwidth->out;
    }

    virNetDevBandwidthClear(ifname);

    if (tx && tx->average) {
        average = g_strdup_printf("%llukbps", tx->average);
        if (tx->peak)
            peak = g_strdup_printf("%llukbps", tx->peak);
        if (tx->burst)
            burst = g_strdup_printf("%llukb", tx->burst);

        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "qdisc", "add", "dev", ifname, "root",
                             "handle", "1:", "htb", "default",
                             hierarchical_class ? "2" : "1", NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        /* If we are creating a hierarchical class, all non guaranteed traffic
         * goes to the 1:2 class which will adjust 'rate' dynamically as NICs
         * with guaranteed throughput are plugged and unplugged. Class 1:1
         * exists so we don't exceed the maximum limit for the network. For each
         * NIC with guaranteed throughput a separate classid will be created.
         * NB '1:' is just a shorter notation of '1:0'.
         *
         * To get a picture how this works:
         *
         * +-----+     +---------+     +-----------+      +-----------+     +-----+
         * |     |     |  qdisc  |     | class 1:1 |      | class 1:2 |     |     |
         * | NIC |     | def 1:2 |     |   rate    |      |   rate    |     | sfq |
         * |     | --> |         | --> |   peak    | -+-> |   peak    | --> |     |
         * +-----+     +---------+     +-----------+  |   +-----------+     +-----+
         *                                            |
         *                                            |   +-----------+     +-----+
         *                                            |   | class 1:3 |     |     |
         *                                            |   |   rate    |     | sfq |
         *                                            +-> |   peak    | --> |     |
         *                                            |   +-----------+     +-----+
         *                                           ...
         *                                            |   +-----------+     +-----+
         *                                            |   | class 1:n |     |     |
         *                                            |   |   rate    |     | sfq |
         *                                            +-> |   peak    | --> |     |
         *                                                +-----------+     +-----+
         *
         * After the routing decision, when is it clear a packet is to be sent
         * via a particular NIC, it is sent to the root qdisc (queuing
         * discipline). In this case HTB (Hierarchical Token Bucket). It has
         * only one direct child class (with id 1:1) which shapes the overall
         * rate that is sent through the NIC.  This class has at least one child
         * (1:2) which is meant for all non-privileged (non guaranteed) traffic
         * from all domains. Then, for each interface with guaranteed
         * throughput, a separate class (1:n) is created. Imagine a class is a
         * box. Whenever a packet ends up in a class it is stored in this box
         * until the kernel sends it, then it is removed from box. Packets are
         * placed into boxes based on rules (filters) - e.g. depending on
         * destination IP/MAC address. If there is no rule to be applied, the
         * root qdisc has a default where such packets go (1:2 in this case).
         * Packets come in over and over again and boxes get filled more and
         * more. Imagine that kernel sends packets just once a second. So it
         * starts to traverse through this tree. It starts with the root qdisc
         * and through 1:1 it gets to 1:2. It sends packets up to 1:2's 'rate'.
         * Then it moves to 1:3 and again sends packets up to 1:3's 'rate'.  The
         * whole process is repeated until 1:n is processed. So now we have
         * ensured each class its guaranteed bandwidth. If the sum of sent data
         * doesn't exceed the 'rate' in 1:1 class, we can go further and send
         * more packets. The rest of available bandwidth is distributed to the
         * 1:2,1:3...1:n classes by ratio of their 'rate'. As soon as the root
         * 'rate' limit is reached or there are no more packets to send, we stop
         * sending and wait another second. Each class has an SFQ qdisc which
         * shuffles packets in boxes stochastically, so one sender cannot
         * starve others.
         *
         * Therefore, whenever we want to plug in a new guaranteed interface, we
         * need to create a new class and adjust the 'rate' of the 1:2 class.
         * When unplugging we do the exact opposite - remove the associated
         * class, and adjust the 'rate'.
         *
         * This description is rather long, but it is still a good idea to read
         * it before you dig into the code.
         */
        if (hierarchical_class) {
            virCommandFree(cmd);
            cmd = virCommandNew(TC);
            virCommandAddArgList(cmd, "class", "add", "dev", ifname, "parent",
                                 "1:", "classid", "1:1", "htb", "rate", average,
                                 "ceil", peak ? peak : average, NULL);
            virNetDevBandwidthCmdAddOptimalQuantum(cmd, tx);
            if (virCommandRun(cmd, NULL) < 0)
                goto cleanup;
        }
        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "class", "add", "dev", ifname, "parent",
                             hierarchical_class ? "1:1" : "1:", "classid",
                             hierarchical_class ? "1:2" : "1:1", "htb",
                             "rate", average, NULL);

        if (peak)
            virCommandAddArgList(cmd, "ceil", peak, NULL);
        if (burst)
            virCommandAddArgList(cmd, "burst", burst, NULL);

        virNetDevBandwidthCmdAddOptimalQuantum(cmd, tx);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "qdisc", "add", "dev", ifname, "parent",
                             hierarchical_class ? "1:2" : "1:1",
                             "handle", "2:", "sfq", "perturb",
                             "10", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "filter", "add", "dev", ifname, "parent",
                             "1:0", "protocol", "all", "prio", "1", "handle",
                             "1", "fw", "flowid", "1", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        VIR_FREE(average);
        VIR_FREE(peak);
        VIR_FREE(burst);
    }

    if (rx) {
        average = g_strdup_printf("%llukbps", rx->average);

        if (rx->burst) {
            burst = g_strdup_printf("%llukb", rx->burst);
        } else {
            /* Internally, tc uses uint to store burst size (in bytes).
             * Therefore, the largest value we can set is UINT_MAX bytes.
             * We're outputting the vale in KiB though. */
            unsigned long long avg = MIN(rx->average, UINT_MAX / 1024);

            burst = g_strdup_printf("%llukb", avg);
        }

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
            virCommandAddArgList(cmd, "qdisc", "add", "dev", ifname,
                                 "ingress", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        /* Set filter to match all ingress traffic */
        virCommandAddArgList(cmd, "filter", "add", "dev", ifname, "parent",
                             "ffff:", "protocol", "all", "u32", "match", "u32",
                             "0", "0", "police", "rate", average,
                             "burst", burst, "mtu", "64kb", "drop", "flowid",
                             ":1", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(average);
    VIR_FREE(peak);
    VIR_FREE(burst);
    return ret;
}

/**
 * virNetDevBandwidthClear:
 * @ifname: on which interface
 *
 * This function tries to disable QoS on specified interface
 * by deleting root and ingress qdisc. However, this may fail
 * if we try to remove the default one.
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthClear(const char *ifname)
{
    int ret = 0;
    int dummy; /* for ignoring the exit status */
    g_autoptr(virCommand) rootcmd = NULL;
    g_autoptr(virCommand) ingresscmd = NULL;

    if (!ifname)
       return 0;

    rootcmd = virCommandNew(TC);
    virCommandAddArgList(rootcmd, "qdisc", "del", "dev", ifname, "root", NULL);

    if (virCommandRun(rootcmd, &dummy) < 0)
        ret = -1;

    ingresscmd = virCommandNew(TC);
    virCommandAddArgList(ingresscmd, "qdisc",  "del", "dev", ifname, "ingress", NULL);

    if (virCommandRun(ingresscmd, &dummy) < 0)
        ret = -1;

    return ret;
}

/*
 * virNetDevBandwidthCopy:
 * @dest: destination
 * @src:  source (may be NULL)
 *
 * Returns -1 on OOM error (which gets reported),
 * 0 otherwise.
 */
int
virNetDevBandwidthCopy(virNetDevBandwidth **dest,
                       const virNetDevBandwidth *src)
{
    *dest = NULL;
    if (!src) {
        /* nothing to be copied */
        return 0;
    }

    *dest = g_new0(virNetDevBandwidth, 1);

    if (src->in) {
        (*dest)->in = g_new0(virNetDevBandwidthRate, 1);
        memcpy((*dest)->in, src->in, sizeof(*src->in));
    }

    if (src->out) {
        (*dest)->out = g_new0(virNetDevBandwidthRate, 1);
        memcpy((*dest)->out, src->out, sizeof(*src->out));
    }

    return 0;
}

bool
virNetDevBandwidthEqual(const virNetDevBandwidth *a,
                        const virNetDevBandwidth *b)
{
    if (!a && !b)
        return true;

    if (!a || !b)
        return false;

    /* in */
    if (a->in) {
        if (!b->in)
            return false;

        if (a->in->average != b->in->average ||
            a->in->peak != b->in->peak ||
            a->in->floor != b->in->floor ||
            a->in->burst != b->in->burst)
            return false;
    } else if (b->in) {
        return false;
    }

    /* out */
    if (a->out) {
        if (!b->out)
            return false;

        if (a->out->average != b->out->average ||
            a->out->peak != b->out->peak ||
            a->out->floor != b->out->floor ||
            a->out->burst != b->out->burst)
            return false;
    } else if (b->out) {
        return false;
    }

    return true;
}

/*
 * virNetDevBandwidthPlug:
 * @brname: name of the bridge
 * @net_bandwidth: QoS settings on @brname
 * @ifmac_ptr: MAC of interface
 * @bandwidth: QoS settings for interface
 * @id: unique ID (MUST be greater than 2)
 *
 * Set bridge part of interface QoS settings, e.g. guaranteed
 * bandwidth.  @id is an unique ID (among @brname) from which
 * other identifiers for class, qdisc and filter are derived.
 * However, two classes were already set up (by
 * virNetDevBandwidthSet). That's why this @id MUST be greater
 * than 2. You may want to keep passed @id, as it is used later
 * by virNetDevBandwidthUnplug.
 *
 * Returns:
 * 0 if QoS set successfully
 * -1 otherwise.
 */
int
virNetDevBandwidthPlug(const char *brname,
                       virNetDevBandwidth *net_bandwidth,
                       const virMacAddr *ifmac_ptr,
                       virNetDevBandwidth *bandwidth,
                       unsigned int id)
{
    g_autoptr(virCommand) cmd1 = NULL;
    g_autoptr(virCommand) cmd2 = NULL;
    g_autofree char *class_id = NULL;
    g_autofree char *qdisc_id = NULL;
    g_autofree char *floor = NULL;
    g_autofree char *ceil = NULL;
    char ifmacStr[VIR_MAC_STRING_BUFLEN];

    if (id <= 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid class ID %1$d"), id);
        return -1;
    }

    virMacAddrFormat(ifmac_ptr, ifmacStr);

    if (!net_bandwidth || !net_bandwidth->in) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Bridge '%1$s' has no QoS set, therefore unable to set 'floor' on '%2$s'"),
                       brname, ifmacStr);
        return -1;
    }

    class_id = g_strdup_printf("1:%x", id);
    qdisc_id = g_strdup_printf("%x:", id);
    floor = g_strdup_printf("%llukbps", bandwidth->in->floor);
    ceil = g_strdup_printf("%llukbps", net_bandwidth->in->peak ?
                           net_bandwidth->in->peak :
                           net_bandwidth->in->average);

    cmd1 = virCommandNew(TC);
    virCommandAddArgList(cmd1, "class", "add", "dev", brname, "parent", "1:1",
                         "classid", class_id, "htb", "rate", floor,
                         "ceil", ceil, NULL);
    virNetDevBandwidthCmdAddOptimalQuantum(cmd1, bandwidth->in);

    if (virCommandRun(cmd1, NULL) < 0)
        return -1;

    cmd2 = virCommandNew(TC);
    virCommandAddArgList(cmd2, "qdisc", "add", "dev", brname, "parent",
                         class_id, "handle", qdisc_id, "sfq", "perturb",
                         "10", NULL);

    if (virCommandRun(cmd2, NULL) < 0)
        return -1;

    if (virNetDevBandwidthManipulateFilter(brname, ifmac_ptr, id,
                                           class_id, false, true) < 0)
        return -1;

    return 0;
}

/*
 * virNetDevBandwidthUnplug:
 * @brname: from which bridge are we unplugging
 * @id: unique identifier (MUST be greater than 2)
 *
 * Remove QoS settings from bridge.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthUnplug(const char *brname,
                         unsigned int id)
{
    int cmd_ret = 0;
    g_autoptr(virCommand) cmd1 = NULL;
    g_autoptr(virCommand) cmd2 = NULL;
    g_autofree char *class_id = NULL;
    g_autofree char *qdisc_id = NULL;

    if (id <= 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid class ID %1$d"), id);
        return -1;
    }

    class_id = g_strdup_printf("1:%x", id);
    qdisc_id = g_strdup_printf("%x:", id);

    cmd1 = virCommandNew(TC);
    virCommandAddArgList(cmd1, "qdisc", "del", "dev", brname,
                         "handle", qdisc_id, NULL);

    /* Don't threat tc errors as fatal, but
     * try to remove as much as possible */
    if (virCommandRun(cmd1, &cmd_ret) < 0)
        return -1;

    if (virNetDevBandwidthManipulateFilter(brname, NULL, id,
                                           NULL, true, false) < 0)
        return -1;

    cmd2 = virCommandNew(TC);
    virCommandAddArgList(cmd2, "class", "del", "dev", brname,
                         "classid", class_id, NULL);

    if (virCommandRun(cmd2, &cmd_ret) < 0)
        return -1;

    return 0;
}

/**
 * virNetDevBandwidthUpdateRate:
 * @ifname: interface name
 * @id: unique identifier
 * @bandwidth: used to derive 'ceil' of class with @id
 * @new_rate: new rate
 *
 * This function updates the 'rate' attribute of HTB class.
 * It can be used whenever a new interface is plugged to a
 * bridge to adjust average throughput of non guaranteed
 * NICs.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthUpdateRate(const char *ifname,
                             unsigned int id,
                             virNetDevBandwidth *bandwidth,
                             unsigned long long new_rate)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *class_id = NULL;
    g_autofree char *rate = NULL;
    g_autofree char *ceil = NULL;

    class_id = g_strdup_printf("1:%x", id);
    rate = g_strdup_printf("%llukbps", new_rate);
    ceil = g_strdup_printf("%llukbps", bandwidth->in->peak ?
                           bandwidth->in->peak :
                           bandwidth->in->average);

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "class", "change", "dev", ifname,
                         "classid", class_id, "htb", "rate", rate,
                         "ceil", ceil, NULL);
    virNetDevBandwidthCmdAddOptimalQuantum(cmd, bandwidth->in);

    return virCommandRun(cmd, NULL);
}

/**
 * virNetDevBandwidthUpdateFilter:
 * @ifname: interface to operate on
 * @ifmac_ptr: new MAC to update the filter with
 * @id: filter ID
 *
 * Sometimes the host environment is so dynamic, that even a
 * guest's MAC addresses change on the fly. When that happens we
 * must update our QoS hierarchy so that the guest's traffic is
 * placed into the correct QDiscs.  This function updates the
 * filter for the interface @ifname with the unique identifier
 * @id so that it uses the new MAC address of the guest interface
 * @ifmac_ptr.
 *
 * Returns: 0 on success,
 *         -1 on failure (with error reported).
 */
int
virNetDevBandwidthUpdateFilter(const char *ifname,
                               const virMacAddr *ifmac_ptr,
                               unsigned int id)
{
    int ret = -1;
    char *class_id = NULL;

    class_id = g_strdup_printf("1:%x", id);

    if (virNetDevBandwidthManipulateFilter(ifname, ifmac_ptr, id,
                                           class_id, true, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(class_id);
    return ret;
}



/**
 * virNetDevBandwidthSetRootQDisc:
 * @ifname: the interface name
 * @qdisc: queueing discipline to set
 *
 * For given interface @ifname set its root queueing discipline
 * to @qdisc. This can be used to replace the default qdisc
 * (usually pfifo_fast or whatever is set in
 * /proc/sys/net/core/default_qdisc) with different qdisc.
 *
 * Returns: 0 on success,
 *         -1 if failed to exec tc (with error reported)
 *         -2 if tc failed (with no error reported)
 */
int
virNetDevBandwidthSetRootQDisc(const char *ifname,
                               const char *qdisc)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *outbuf = NULL;
    g_autofree char *errbuf = NULL;
    int status;

    /* Ideally, we would have a netlink implementation and just
     * call it here.  But honestly, I tried and failed miserably.
     * Fallback to spawning tc. */
    cmd = virCommandNewArgList(TC, "qdisc", "add", "dev", ifname,
                               "root", "handle", "0:", qdisc,
                               NULL);

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &outbuf);
    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        VIR_DEBUG("Setting qdisc failed: output='%s' err='%s'", outbuf, errbuf);
        return -2;
    }

    return 0;
}
