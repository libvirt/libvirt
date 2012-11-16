/*
 * Copyright (C) 2009-2012 Red Hat, Inc.
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

#include "virnetdevbandwidth.h"
#include "command.h"
#include "memory.h"
#include "virterror_internal.h"

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
            if (virCommandRun(cmd, NULL) < 0)
                goto cleanup;
        }
        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd,"class", "add", "dev", ifname, "parent",
                             hierarchical_class ? "1:1" : "1:", "classid",
                             hierarchical_class ? "1:2" : "1:1", "htb",
                             "rate", average, NULL);

        if (peak)
            virCommandAddArgList(cmd, "ceil", peak, NULL);
        if (burst)
            virCommandAddArgList(cmd, "burst", burst, NULL);

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
        virCommandAddArgList(cmd,"filter", "add", "dev", ifname, "parent",
                             "1:0", "protocol", "ip", "handle", "1", "fw",
                             "flowid", "1", NULL);

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
        virCommandAddArgList(cmd, "filter", "add", "dev", ifname, "parent",
                             "ffff:", "protocol", "ip", "u32", "match", "ip",
                             "src", "0.0.0.0/0", "police", "rate", average,
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
                       const virNetDevBandwidthPtr src)
{
    int ret = -1;

    *dest = NULL;
    if (!src) {
        /* nothing to be copied */
        return 0;
    }

    if (VIR_ALLOC(*dest) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (src->in) {
        if (VIR_ALLOC((*dest)->in) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        memcpy((*dest)->in, src->in, sizeof(*src->in));
    }

    if (src->out) {
        if (VIR_ALLOC((*dest)->out) < 0) {
            virReportOOMError();
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
    if (a->in->average != b->in->average ||
        a->in->peak != b->in->peak ||
        a->in->burst != b->in->burst)
        return false;

    /*out*/
    if (a->out->average != b->out->average ||
        a->out->peak != b->out->peak ||
        a->out->burst != b->out->burst)
        return false;

    return true;
}
