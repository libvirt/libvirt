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
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include <unistd.h>

#include "virnetdevbandwidth.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

void
virNetDevBandwidthFree(virNetDevBandwidthPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->in);
    VIR_FREE(def->out);
    VIR_FREE(def);
}

static void
virNetDevBandwidthCmdAddOptimalQuantum(virCommandPtr cmd,
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
    char *filter_id = NULL;
    virCommandPtr cmd = NULL;
    unsigned char ifmac[VIR_MAC_BUFLEN];
    char *mac[2] = {NULL, NULL};

    if (!(remove_old || create_new)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filter creation API error"));
        goto cleanup;
    }

    /* u32 filters must have 800:: prefix. Don't ask. */
    if (virAsprintf(&filter_id, "800::%u", id) < 0)
        goto cleanup;

    if (remove_old) {
        int cmd_ret = 0;

        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "filter", "del", "dev", ifname,
                             "prio", "2", "handle",  filter_id, "u32", NULL);

        if (virCommandRun(cmd, &cmd_ret) < 0)
            goto cleanup;

    }

    if (create_new) {
        virMacAddrGetRaw(ifmac_ptr, ifmac);

        if (virAsprintf(&mac[0], "0x%02x%02x%02x%02x", ifmac[2],
                        ifmac[3], ifmac[4], ifmac[5]) < 0 ||
            virAsprintf(&mac[1], "0x%02x%02x", ifmac[0], ifmac[1]) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
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
    VIR_FREE(filter_id);
    virCommandFree(cmd);
    return ret;
}


/**
 * virNetDevBandwidthSet:
 * @ifname: on which interface
 * @bandwidth: rates to set (may be NULL)
 * @hierarchical_class: whether to create hierarchical class
 *
 * This function enables QoS on specified interface
 * and set given traffic limits for both, incoming
 * and outgoing traffic. Any previous setting get
 * overwritten. If @hierarchical_class is TRUE, create
 * hierarchical class. It is used to guarantee minimal
 * throughput ('floor' attribute in NIC).
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthSet(const char *ifname,
                      virNetDevBandwidthPtr bandwidth,
                      bool hierarchical_class)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
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
                       _("Network bandwidth tuning is not available"
                         " in session mode"));
        return -1;
    }

    if (!ifname) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to set bandwidth for interface because "
                         "device name is unknown"));
        return -1;
    }

    virNetDevBandwidthClear(ifname);

    if (bandwidth->in && bandwidth->in->average) {
        if (virAsprintf(&average, "%llukbps", bandwidth->in->average) < 0)
            goto cleanup;
        if (bandwidth->in->peak &&
            (virAsprintf(&peak, "%llukbps", bandwidth->in->peak) < 0))
            goto cleanup;
        if (bandwidth->in->burst &&
            (virAsprintf(&burst, "%llukb", bandwidth->in->burst) < 0))
            goto cleanup;

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
         * via a particular NIC, it is sent to the root qdisc (queueing
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
            virNetDevBandwidthCmdAddOptimalQuantum(cmd, bandwidth->in);
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

        virNetDevBandwidthCmdAddOptimalQuantum(cmd, bandwidth->in);
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

    if (bandwidth->out) {
        if (virAsprintf(&average, "%llukbps", bandwidth->out->average) < 0)
            goto cleanup;
        if (virAsprintf(&burst, "%llukb", bandwidth->out->burst ?
                        bandwidth->out->burst : bandwidth->out->average) < 0)
            goto cleanup;

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
    virCommandPtr cmd = NULL;

    if (!ifname)
       return 0;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc", "del", "dev", ifname, "root", NULL);

    if (virCommandRun(cmd, &dummy) < 0)
        ret = -1;

    virCommandFree(cmd);

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc",  "del", "dev", ifname, "ingress", NULL);

    if (virCommandRun(cmd, &dummy) < 0)
        ret = -1;

    virCommandFree(cmd);

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
virNetDevBandwidthCopy(virNetDevBandwidthPtr *dest,
                       const virNetDevBandwidth *src)
{
    int ret = -1;

    *dest = NULL;
    if (!src) {
        /* nothing to be copied */
        return 0;
    }

    if (VIR_ALLOC(*dest) < 0)
        goto cleanup;

    if (src->in) {
        if (VIR_ALLOC((*dest)->in) < 0)
            goto cleanup;
        memcpy((*dest)->in, src->in, sizeof(*src->in));
    }

    if (src->out) {
        if (VIR_ALLOC((*dest)->out) < 0) {
            VIR_FREE((*dest)->in);
            goto cleanup;
        }
        memcpy((*dest)->out, src->out, sizeof(*src->out));
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        virNetDevBandwidthFree(*dest);
        *dest = NULL;
    }
    return ret;
}

bool
virNetDevBandwidthEqual(virNetDevBandwidthPtr a,
                        virNetDevBandwidthPtr b)
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

    /*out*/
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
                       virNetDevBandwidthPtr net_bandwidth,
                       const virMacAddr *ifmac_ptr,
                       virNetDevBandwidthPtr bandwidth,
                       unsigned int id)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *class_id = NULL;
    char *qdisc_id = NULL;
    char *floor = NULL;
    char *ceil = NULL;
    char ifmacStr[VIR_MAC_STRING_BUFLEN];

    if (id <= 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid class ID %d"), id);
        return -1;
    }

    virMacAddrFormat(ifmac_ptr, ifmacStr);

    if (!net_bandwidth || !net_bandwidth->in) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Bridge '%s' has no QoS set, therefore "
                         "unable to set 'floor' on '%s'"),
                       brname, ifmacStr);
        return -1;
    }

    if (virAsprintf(&class_id, "1:%x", id) < 0 ||
        virAsprintf(&qdisc_id, "%x:", id) < 0 ||
        virAsprintf(&floor, "%llukbps", bandwidth->in->floor) < 0 ||
        virAsprintf(&ceil, "%llukbps", net_bandwidth->in->peak ?
                    net_bandwidth->in->peak :
                    net_bandwidth->in->average) < 0)
        goto cleanup;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "class", "add", "dev", brname, "parent", "1:1",
                         "classid", class_id, "htb", "rate", floor,
                         "ceil", ceil, NULL);
    virNetDevBandwidthCmdAddOptimalQuantum(cmd, bandwidth->in);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    virCommandFree(cmd);
    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc", "add", "dev", brname, "parent",
                         class_id, "handle", qdisc_id, "sfq", "perturb",
                         "10", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virNetDevBandwidthManipulateFilter(brname, ifmac_ptr, id,
                                           class_id, false, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(ceil);
    VIR_FREE(floor);
    VIR_FREE(qdisc_id);
    VIR_FREE(class_id);
    virCommandFree(cmd);
    return ret;
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
    int ret = -1;
    int cmd_ret = 0;
    virCommandPtr cmd = NULL;
    char *class_id = NULL;
    char *qdisc_id = NULL;

    if (id <= 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid class ID %d"), id);
        return -1;
    }

    if (virAsprintf(&class_id, "1:%x", id) < 0 ||
        virAsprintf(&qdisc_id, "%x:", id) < 0)
        goto cleanup;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc", "del", "dev", brname,
                         "handle", qdisc_id, NULL);

    /* Don't threat tc errors as fatal, but
     * try to remove as much as possible */
    if (virCommandRun(cmd, &cmd_ret) < 0)
        goto cleanup;

    if (virNetDevBandwidthManipulateFilter(brname, NULL, id,
                                           NULL, true, false) < 0)
        goto cleanup;

    virCommandFree(cmd);
    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "class", "del", "dev", brname,
                         "classid", class_id, NULL);

    if (virCommandRun(cmd, &cmd_ret) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(qdisc_id);
    VIR_FREE(class_id);
    virCommandFree(cmd);
    return ret;
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
                             virNetDevBandwidthPtr bandwidth,
                             unsigned long long new_rate)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *class_id = NULL;
    char *rate = NULL;
    char *ceil = NULL;

    if (virAsprintf(&class_id, "1:%x", id) < 0 ||
        virAsprintf(&rate, "%llukbps", new_rate) < 0 ||
        virAsprintf(&ceil, "%llukbps", bandwidth->in->peak ?
                    bandwidth->in->peak :
                    bandwidth->in->average) < 0)
        goto cleanup;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "class", "change", "dev", ifname,
                         "classid", class_id, "htb", "rate", rate,
                         "ceil", ceil, NULL);
    virNetDevBandwidthCmdAddOptimalQuantum(cmd, bandwidth->in);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(class_id);
    VIR_FREE(rate);
    VIR_FREE(ceil);
    return ret;
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

    if (virAsprintf(&class_id, "1:%x", id) < 0)
        goto cleanup;

    if (virNetDevBandwidthManipulateFilter(ifname, ifmac_ptr, id,
                                           class_id, true, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(class_id);
    return ret;
}
