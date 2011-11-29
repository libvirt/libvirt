/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdevbandwidth.h"
#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "ignore-value.h"

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
 *
 * This function enables QoS on specified interface
 * and set given traffic limits for both, incoming
 * and outgoing traffic. Any previous setting get
 * overwritten.
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthSet(const char *ifname,
                      virNetDevBandwidthPtr bandwidth)
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

    ignore_value(virNetDevBandwidthClear(ifname));

    if (bandwidth->in) {
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
                             "handle", "1:", "htb", "default", "1", NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd,"class", "add", "dev", ifname, "parent",
                             "1:", "classid", "1:1", "htb", NULL);
        virCommandAddArgList(cmd, "rate", average, NULL);

        if (peak)
            virCommandAddArgList(cmd, "ceil", peak, NULL);
        if (burst)
            virCommandAddArgList(cmd, "burst", burst, NULL);

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
                             "burst", burst, "mtu", burst, "drop", "flowid",
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
    virCommandPtr cmd = NULL;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc", "del", "dev", ifname, "root", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc",  "del", "dev", ifname, "ingress", NULL);

    if (virCommandRun(cmd, NULL) < 0)
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
