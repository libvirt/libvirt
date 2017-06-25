/*
 * lxc_native.c: LXC native configuration import
 *
 * Copyright (c) 2014-2016 Red Hat, Inc.
 * Copyright (c) 2013-2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Cedric Bosdonnat <cbosdonnat@suse.com>
 */

#include <config.h>
#include <stdio.h>

#include "internal.h"
#include "lxc_container.h"
#include "lxc_native.h"
#include "util/viralloc.h"
#include "util/virfile.h"
#include "util/virlog.h"
#include "util/virstring.h"
#include "util/virconf.h"
#include "conf/domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_native");

static virDomainFSDefPtr
lxcCreateFSDef(int type,
               const char *src,
               const char* dst,
               bool readonly,
               unsigned long long usage)
{
    virDomainFSDefPtr def;

    if (!(def = virDomainFSDefNew()))
        return NULL;

    def->type = type;
    def->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;
    if (src && VIR_STRDUP(def->src->path, src) < 0)
        goto error;
    if (VIR_STRDUP(def->dst, dst) < 0)
        goto error;
    def->readonly = readonly;
    def->usage = usage;

    return def;

 error:
    virDomainFSDefFree(def);
    return NULL;
}

typedef struct _lxcFstab lxcFstab;
typedef lxcFstab *lxcFstabPtr;
struct _lxcFstab {
    lxcFstabPtr next;
    char *src;
    char *dst;
    char *type;
    char *options;
};

static void
lxcFstabFree(lxcFstabPtr fstab)
{
    while (fstab) {
        lxcFstabPtr next = NULL;
        next = fstab->next;

        VIR_FREE(fstab->src);
        VIR_FREE(fstab->dst);
        VIR_FREE(fstab->type);
        VIR_FREE(fstab->options);
        VIR_FREE(fstab);

        fstab = next;
    }
}

static char ** lxcStringSplit(const char *string)
{
    char *tmp;
    size_t i;
    size_t ntokens = 0;
    char **parts;
    char **result = NULL;

    if (VIR_STRDUP(tmp, string) < 0)
        return NULL;

    /* Replace potential \t by a space */
    for (i = 0; tmp[i]; i++) {
        if (tmp[i] == '\t')
            tmp[i] = ' ';
    }

    if (!(parts = virStringSplit(tmp, " ", 0)))
        goto error;

    /* Append NULL element */
    if (VIR_EXPAND_N(result, ntokens, 1) < 0)
        goto error;

    for (i = 0; parts[i]; i++) {
        if (STREQ(parts[i], ""))
            continue;

        if (VIR_EXPAND_N(result, ntokens, 1) < 0)
            goto error;

        if (VIR_STRDUP(result[ntokens-2], parts[i]) < 0)
            goto error;
    }

    VIR_FREE(tmp);
    virStringListFree(parts);
    return result;

 error:
    VIR_FREE(tmp);
    virStringListFree(parts);
    virStringListFree(result);
    return NULL;
}

static lxcFstabPtr
lxcParseFstabLine(char *fstabLine)
{
    lxcFstabPtr fstab = NULL;
    char **parts;

    if (!fstabLine || VIR_ALLOC(fstab) < 0)
        return NULL;

    if (!(parts = lxcStringSplit(fstabLine)))
        goto error;

    if (!parts[0] || !parts[1] || !parts[2] || !parts[3])
        goto error;

    if (VIR_STRDUP(fstab->src, parts[0]) < 0 ||
            VIR_STRDUP(fstab->dst, parts[1]) < 0 ||
            VIR_STRDUP(fstab->type, parts[2]) < 0 ||
            VIR_STRDUP(fstab->options, parts[3]) < 0)
        goto error;

    virStringListFree(parts);

    return fstab;

 error:
    lxcFstabFree(fstab);
    virStringListFree(parts);
    return NULL;
}

static int
lxcAddFSDef(virDomainDefPtr def,
            int type,
            const char *src,
            const char *dst,
            bool readonly,
            unsigned long long usage)
{
    virDomainFSDefPtr fsDef = NULL;

    if (!(fsDef = lxcCreateFSDef(type, src, dst, readonly, usage)))
        goto error;

    if (VIR_EXPAND_N(def->fss, def->nfss, 1) < 0)
        goto error;
    def->fss[def->nfss - 1] = fsDef;

    return 0;

 error:
    virDomainFSDefFree(fsDef);
    return -1;
}

static int
lxcSetRootfs(virDomainDefPtr def,
             virConfPtr properties)
{
    int type = VIR_DOMAIN_FS_TYPE_MOUNT;
    virConfValuePtr value;

    if (!(value = virConfGetValue(properties, "lxc.rootfs")) ||
        !value->str) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing lxc.rootfs configuration"));
        return -1;
    }

    if (STRPREFIX(value->str, "/dev/"))
        type = VIR_DOMAIN_FS_TYPE_BLOCK;

    if (lxcAddFSDef(def, type, value->str, "/", false, 0) < 0)
        return -1;

    return 0;
}

static int
lxcConvertSize(const char *size, unsigned long long *value)
{
    char *unit = NULL;

    /* Split the string into value and unit */
    if (virStrToLong_ull(size, &unit, 10, value) < 0)
        goto error;

    if (STREQ(unit, "%")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("can't convert relative size: '%s'"),
                       size);
        return -1;
    } else {
        if (virScaleInteger(value, unit, 1, ULLONG_MAX) < 0)
            goto error;
    }

    return 0;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("failed to convert size: '%s'"),
                   size);
    return -1;
}

static int
lxcAddFstabLine(virDomainDefPtr def, lxcFstabPtr fstab)
{
    const char *src = NULL;
    char *dst = NULL;
    char **options = virStringSplit(fstab->options, ",", 0);
    bool readonly;
    int type = VIR_DOMAIN_FS_TYPE_MOUNT;
    unsigned long long usage = 0;
    int ret = -1;

    if (!options)
        return -1;

    if (fstab->dst[0] != '/') {
        if (virAsprintf(&dst, "/%s", fstab->dst) < 0)
            goto cleanup;
    } else {
        if (VIR_STRDUP(dst, fstab->dst) < 0)
            goto cleanup;
    }

    /* Check that we don't add basic mounts */
    if (lxcIsBasicMountLocation(dst)) {
        ret = 0;
        goto cleanup;
    }

    if (STREQ(fstab->type, "tmpfs")) {
        char *sizeStr = NULL;
        size_t i;
        type = VIR_DOMAIN_FS_TYPE_RAM;

        for (i = 0; options[i]; i++) {
            if ((sizeStr = STRSKIP(options[i], "size="))) {
                if (lxcConvertSize(sizeStr, &usage) < 0)
                    goto cleanup;
                break;
            }
        }
        if (!sizeStr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing tmpfs size, set the size option"));
            goto cleanup;
        }
    } else {
        src = fstab->src;
    }

    /* Is it a block device that needs special favor? */
    if (STRPREFIX(fstab->src, "/dev/"))
        type = VIR_DOMAIN_FS_TYPE_BLOCK;

    /* Do we have ro in options? */
    readonly = virStringListHasString((const char **) options, "ro");

    if (lxcAddFSDef(def, type, src, dst, readonly, usage) < 0)
        goto cleanup;

    ret = 1;

 cleanup:
    VIR_FREE(dst);
    virStringListFree(options);
    return ret;
}

static int
lxcFstabWalkCallback(const char* name, virConfValuePtr value, void * data)
{
    int ret = 0;
    lxcFstabPtr fstabLine;
    virDomainDefPtr def = data;

    /* We only care about lxc.mount.entry lines */
    if (STRNEQ(name, "lxc.mount.entry"))
        return 0;

    fstabLine = lxcParseFstabLine(value->str);

    if (!fstabLine)
        return -1;

    if (lxcAddFstabLine(def, fstabLine) < 0)
        ret = -1;

    lxcFstabFree(fstabLine);
    return ret;
}

static virDomainNetDefPtr
lxcCreateNetDef(const char *type,
                const char *linkdev,
                const char *mac,
                const char *flag,
                const char *macvlanmode,
                const char *name)
{
    virDomainNetDefPtr net = NULL;
    virMacAddr macAddr;

    if (VIR_ALLOC(net) < 0)
        goto error;

    if (STREQ_NULLABLE(flag, "up"))
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
    else
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;

    if (VIR_STRDUP(net->ifname_guest, name) < 0)
        goto error;

    if (mac && virMacAddrParse(mac, &macAddr) == 0)
        net->mac = macAddr;

    if (STREQ(type, "veth")) {
        if (linkdev) {
            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            if (VIR_STRDUP(net->data.bridge.brname, linkdev) < 0)
                goto error;
        } else {
            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
        }
    } else if (STREQ(type, "macvlan")) {
        net->type = VIR_DOMAIN_NET_TYPE_DIRECT;

        if (!linkdev || VIR_STRDUP(net->data.direct.linkdev, linkdev) < 0)
            goto error;

        if (!macvlanmode || STREQ(macvlanmode, "private"))
            net->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_PRIVATE;
        else if (STREQ(macvlanmode, "vepa"))
            net->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_VEPA;
        else if (STREQ(macvlanmode, "bridge"))
            net->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_BRIDGE;
        else
            VIR_WARN("Unknown macvlan type: %s", macvlanmode);
    }

    return net;

 error:
    virDomainNetDefFree(net);
    return NULL;
}

static virDomainHostdevDefPtr
lxcCreateHostdevDef(int mode, int type, const char *data)
{
    virDomainHostdevDefPtr hostdev = virDomainHostdevDefNew(NULL);

    if (!hostdev)
        return NULL;

    hostdev->mode = mode;
    hostdev->source.caps.type = type;

    if (type == VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET &&
        VIR_STRDUP(hostdev->source.caps.u.net.ifname, data) < 0) {
        virDomainHostdevDefFree(hostdev);
        hostdev = NULL;
    }

    return hostdev;
}

typedef struct {
    virDomainDefPtr def;
    char *type;
    char *link;
    char *mac;
    char *flag;
    char *macvlanmode;
    char *vlanid;
    char *name;
    virNetDevIPAddrPtr *ips;
    size_t nips;
    char *gateway_ipv4;
    char *gateway_ipv6;
    bool privnet;
    size_t networks;
} lxcNetworkParseData;

static int
lxcAddNetworkRouteDefinition(const char *address,
                             int family,
                             virNetDevIPRoutePtr **routes,
                             size_t *nroutes)
{
    virNetDevIPRoutePtr route = NULL;
    char *familyStr = NULL;
    char *zero = NULL;

    if (VIR_STRDUP(zero, family == AF_INET ? VIR_SOCKET_ADDR_IPV4_ALL
                   : VIR_SOCKET_ADDR_IPV6_ALL) < 0)
        goto error;

    if (VIR_STRDUP(familyStr, family == AF_INET ? "ipv4" : "ipv6") < 0)
        goto error;

    if (!(route = virNetDevIPRouteCreate(_("Domain interface"), familyStr,
                                         zero, NULL, address, 0, false,
                                         0, false)))
        goto error;

    if (VIR_APPEND_ELEMENT(*routes, *nroutes, route) < 0)
        goto error;

    VIR_FREE(familyStr);
    VIR_FREE(zero);

    return 0;

 error:
    VIR_FREE(familyStr);
    VIR_FREE(zero);
    virNetDevIPRouteFree(route);
    return -1;
}

static int
lxcAddNetworkDefinition(lxcNetworkParseData *data)
{
    virDomainNetDefPtr net = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    bool isPhys, isVlan = false;
    size_t i;

    if ((data->type == NULL) || STREQ(data->type, "empty") ||
         STREQ(data->type, "") ||  STREQ(data->type, "none"))
        return 0;

    isPhys = STREQ(data->type, "phys");
    isVlan = STREQ(data->type, "vlan");
    if (data->type != NULL && (isPhys || isVlan)) {
        if (!data->link) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Missing 'link' attribute for NIC"));
            goto error;
        }
        if (!(hostdev = lxcCreateHostdevDef(VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES,
                                            VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET,
                                            data->link)))
            goto error;

        /* This still requires the user to manually setup the vlan interface
         * on the host */
        if (isVlan && data->vlanid) {
            VIR_FREE(hostdev->source.caps.u.net.ifname);
            if (virAsprintf(&hostdev->source.caps.u.net.ifname,
                            "%s.%s", data->link, data->vlanid) < 0)
                goto error;
        }

        hostdev->source.caps.u.net.ip.ips = data->ips;
        hostdev->source.caps.u.net.ip.nips = data->nips;

        if (data->gateway_ipv4 &&
            lxcAddNetworkRouteDefinition(data->gateway_ipv4, AF_INET,
                                         &hostdev->source.caps.u.net.ip.routes,
                                         &hostdev->source.caps.u.net.ip.nroutes) < 0)
                goto error;

        if (data->gateway_ipv6 &&
            lxcAddNetworkRouteDefinition(data->gateway_ipv6, AF_INET6,
                                         &hostdev->source.caps.u.net.ip.routes,
                                         &hostdev->source.caps.u.net.ip.nroutes) < 0)
                goto error;

        if (VIR_EXPAND_N(data->def->hostdevs, data->def->nhostdevs, 1) < 0)
            goto error;
        data->def->hostdevs[data->def->nhostdevs - 1] = hostdev;
    } else {
        if (!(net = lxcCreateNetDef(data->type, data->link, data->mac,
                                    data->flag, data->macvlanmode,
                                    data->name)))
            goto error;

        net->guestIP.ips = data->ips;
        net->guestIP.nips = data->nips;

        if (data->gateway_ipv4 &&
            lxcAddNetworkRouteDefinition(data->gateway_ipv4, AF_INET,
                                         &net->guestIP.routes,
                                         &net->guestIP.nroutes) < 0)
                goto error;

        if (data->gateway_ipv6 &&
            lxcAddNetworkRouteDefinition(data->gateway_ipv6, AF_INET6,
                                         &net->guestIP.routes,
                                         &net->guestIP.nroutes) < 0)
                goto error;

        if (VIR_EXPAND_N(data->def->nets, data->def->nnets, 1) < 0)
            goto error;
        data->def->nets[data->def->nnets - 1] = net;
    }

    return 1;

 error:
    for (i = 0; i < data->nips; i++)
        VIR_FREE(data->ips[i]);
    VIR_FREE(data->ips);
    virDomainNetDefFree(net);
    virDomainHostdevDefFree(hostdev);
    return -1;
}

static int
lxcNetworkWalkCallback(const char *name, virConfValuePtr value, void *data)
{
    lxcNetworkParseData *parseData = data;
    int status;

    if (STREQ(name, "lxc.network.type")) {
        /* Store the previous NIC */
        status = lxcAddNetworkDefinition(parseData);

        if (status < 0)
            return -1;
        else if (status > 0)
            parseData->networks++;
        else if (parseData->type != NULL && STREQ(parseData->type, "none"))
            parseData->privnet = false;

        /* Start a new network interface config */
        parseData->type = NULL;
        parseData->link = NULL;
        parseData->mac = NULL;
        parseData->flag = NULL;
        parseData->macvlanmode = NULL;
        parseData->vlanid = NULL;
        parseData->name = NULL;

        parseData->ips = NULL;
        parseData->nips = 0;

        /* Keep the new value */
        parseData->type = value->str;
    }
    else if (STREQ(name, "lxc.network.link"))
        parseData->link = value->str;
    else if (STREQ(name, "lxc.network.hwaddr"))
        parseData->mac = value->str;
    else if (STREQ(name, "lxc.network.flags"))
        parseData->flag = value->str;
    else if (STREQ(name, "lxc.network.macvlan.mode"))
        parseData->macvlanmode = value->str;
    else if (STREQ(name, "lxc.network.vlan.id"))
        parseData->vlanid = value->str;
    else if (STREQ(name, "lxc.network.name"))
        parseData->name = value->str;
    else if (STREQ(name, "lxc.network.ipv4") ||
             STREQ(name, "lxc.network.ipv6")) {
        int family = AF_INET;
        char **ipparts = NULL;
        virNetDevIPAddrPtr ip = NULL;

        if (VIR_ALLOC(ip) < 0)
            return -1;

        if (STREQ(name, "lxc.network.ipv6"))
            family = AF_INET6;

        ipparts = virStringSplit(value->str, "/", 2);
        if (virStringListLength((const char * const *)ipparts) != 2 ||
            virSocketAddrParse(&ip->address, ipparts[0], family) < 0 ||
            virStrToLong_ui(ipparts[1], NULL, 10, &ip->prefix) < 0) {

            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid CIDR address: '%s'"), value->str);

            virStringListFree(ipparts);
            VIR_FREE(ip);
            return -1;
        }

        virStringListFree(ipparts);

        if (VIR_APPEND_ELEMENT(parseData->ips, parseData->nips, ip) < 0) {
            VIR_FREE(ip);
            return -1;
        }
    } else if (STREQ(name, "lxc.network.ipv4.gateway")) {
        parseData->gateway_ipv4 = value->str;
    } else if (STREQ(name, "lxc.network.ipv6.gateway")) {
        parseData->gateway_ipv6 = value->str;
    } else if (STRPREFIX(name, "lxc.network")) {
        VIR_WARN("Unhandled network property: %s = %s",
                 name,
                 value->str);
    }

    return 0;
}

static int
lxcConvertNetworkSettings(virDomainDefPtr def, virConfPtr properties)
{
    int status;
    int result = -1;
    size_t i;
    lxcNetworkParseData data = {def, NULL, NULL, NULL, NULL,
                                NULL, NULL, NULL, NULL, 0,
                                NULL, NULL, true, 0};

    if (virConfWalk(properties, lxcNetworkWalkCallback, &data) < 0)
        goto error;


    /* Add the last network definition found */
    status = lxcAddNetworkDefinition(&data);

    if (status < 0)
        goto error;
    else if (status > 0)
        data.networks++;
    else if (data.type != NULL && STREQ(data.type, "none"))
        data.privnet = false;

    if (data.networks == 0 && data.privnet) {
        /* When no network type is provided LXC only adds loopback */
        def->features[VIR_DOMAIN_FEATURE_PRIVNET] = VIR_TRISTATE_SWITCH_ON;
    }
    result = 0;

    return result;

 error:
    for (i = 0; i < data.nips; i++)
        VIR_FREE(data.ips[i]);
    VIR_FREE(data.ips);
    return -1;
}

static int
lxcCreateConsoles(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;
    int nbttys = 0;
    virDomainChrDefPtr console;
    size_t i;

    if (!(value = virConfGetValue(properties, "lxc.tty")) || !value->str)
        return 0;

    if (virStrToLong_i(value->str, NULL, 10, &nbttys) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("failed to parse int: '%s'"),
                       value->str);
        return -1;
    }

    if (VIR_ALLOC_N(def->consoles, nbttys) < 0)
        return -1;

    def->nconsoles = nbttys;
    for (i = 0; i < nbttys; i++) {
        if (!(console = virDomainChrDefNew(NULL)))
            goto error;

        console->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        console->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC;
        console->target.port = i;
        console->source->type = VIR_DOMAIN_CHR_TYPE_PTY;

        def->consoles[i] = console;
    }

    return 0;

 error:
    virDomainChrDefFree(console);
    return -1;
}

static int
lxcIdmapWalkCallback(const char *name, virConfValuePtr value, void *data)
{
    virDomainDefPtr def = data;
    virDomainIdMapEntryPtr idmap = NULL;
    char type;
    unsigned long start, target, count;

    if (STRNEQ(name, "lxc.id_map") || !value->str)
        return 0;

    if (sscanf(value->str, "%c %lu %lu %lu", &type,
               &target, &start, &count) != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("invalid lxc.id_map: '%s'"),
                       value->str);
        return -1;
    }

    if (type == 'u') {
        if (VIR_EXPAND_N(def->idmap.uidmap, def->idmap.nuidmap, 1) < 0)
            return -1;
        idmap = &def->idmap.uidmap[def->idmap.nuidmap - 1];
    } else if (type == 'g') {
        if (VIR_EXPAND_N(def->idmap.gidmap, def->idmap.ngidmap, 1) < 0)
            return -1;
        idmap = &def->idmap.gidmap[def->idmap.ngidmap - 1];
    } else {
        return -1;
    }

    idmap->start = start;
    idmap->target = target;
    idmap->count = count;

    return 0;
}

static int
lxcSetMemTune(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;
    unsigned long long size = 0;

    if ((value = virConfGetValue(properties,
                "lxc.cgroup.memory.limit_in_bytes")) &&
            value->str && STRNEQ(value->str, "-1")) {
        if (lxcConvertSize(value->str, &size) < 0)
            return -1;
        size = size / 1024;
        virDomainDefSetMemoryTotal(def, size);
        def->mem.hard_limit = virMemoryLimitTruncate(size);
    }

    if ((value = virConfGetValue(properties,
                "lxc.cgroup.memory.soft_limit_in_bytes")) &&
            value->str && STRNEQ(value->str, "-1")) {
        if (lxcConvertSize(value->str, &size) < 0)
            return -1;

        def->mem.soft_limit = virMemoryLimitTruncate(size / 1024);
    }

    if ((value = virConfGetValue(properties,
                "lxc.cgroup.memory.memsw.limit_in_bytes")) &&
            value->str && STRNEQ(value->str, "-1")) {
        if (lxcConvertSize(value->str, &size) < 0)
            return -1;

        def->mem.swap_hard_limit = virMemoryLimitTruncate(size / 1024);
    }
    return 0;
}

static int
lxcSetCpuTune(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;

    if ((value = virConfGetValue(properties, "lxc.cgroup.cpu.shares")) &&
            value->str) {
        if (virStrToLong_ull(value->str, NULL, 10, &def->cputune.shares) < 0)
            goto error;
        def->cputune.sharesSpecified = true;
    }

    if ((value = virConfGetValue(properties,
                                 "lxc.cgroup.cpu.cfs_quota_us")) &&
            value->str && virStrToLong_ll(value->str, NULL, 10,
                                          &def->cputune.quota) < 0)
        goto error;

    if ((value = virConfGetValue(properties,
                                 "lxc.cgroup.cpu.cfs_period_us")) &&
            value->str && virStrToLong_ull(value->str, NULL, 10,
                                           &def->cputune.period) < 0)
        goto error;

    return 0;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("failed to parse integer: '%s'"), value->str);
    return -1;
}

static int
lxcSetCpusetTune(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;
    virBitmapPtr nodeset = NULL;

    if ((value = virConfGetValue(properties, "lxc.cgroup.cpuset.cpus")) &&
            value->str) {
        if (virBitmapParse(value->str, &def->cpumask,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;

        def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC;
    }

    if ((value = virConfGetValue(properties, "lxc.cgroup.cpuset.mems")) &&
        value->str) {
        if (virBitmapParse(value->str, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;
        if (virDomainNumatuneSet(def->numa,
                                 def->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC,
                                 VIR_DOMAIN_NUMATUNE_MEM_STRICT,
                                 nodeset) < 0) {
            virBitmapFree(nodeset);
            return -1;
        }
        virBitmapFree(nodeset);
    }

    return 0;
}

static int
lxcBlkioDeviceWalkCallback(const char *name, virConfValuePtr value, void *data)
{
    char **parts = NULL;
    virBlkioDevicePtr device = NULL;
    virDomainDefPtr def = data;
    size_t i = 0;
    char *path = NULL;
    int ret = -1;

    if (!STRPREFIX(name, "lxc.cgroup.blkio.") ||
            STREQ(name, "lxc.cgroup.blkio.weight")|| !value->str)
        return 0;

    if (!(parts = lxcStringSplit(value->str)))
        return -1;

    if (!parts[0] || !parts[1]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid %s value: '%s'"),
                       name, value->str);
        goto cleanup;
    }

    if (virAsprintf(&path, "/dev/block/%s", parts[0]) < 0)
        goto cleanup;

    /* Do we already have a device definition for this path?
     * Get that device or create a new one */
    for (i = 0; !device && i < def->blkio.ndevices; i++) {
        if (STREQ(def->blkio.devices[i].path, path))
            device = &def->blkio.devices[i];
    }
    if (!device) {
        if (VIR_EXPAND_N(def->blkio.devices, def->blkio.ndevices, 1) < 0)
            goto cleanup;
        device = &def->blkio.devices[def->blkio.ndevices - 1];
        device->path = path;
        path = NULL;
    }

    /* Set the value */
    if (STREQ(name, "lxc.cgroup.blkio.device_weight")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->weight) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse device weight: '%s'"), parts[1]);
            goto cleanup;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.read_bps_device")) {
        if (virStrToLong_ull(parts[1], NULL, 10, &device->rbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse read_bps_device: '%s'"),
                           parts[1]);
            goto cleanup;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.write_bps_device")) {
        if (virStrToLong_ull(parts[1], NULL, 10, &device->wbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse write_bps_device: '%s'"),
                           parts[1]);
            goto cleanup;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.read_iops_device")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->riops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse read_iops_device: '%s'"),
                           parts[1]);
            goto cleanup;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.write_iops_device")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->wiops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse write_iops_device: '%s'"),
                           parts[1]);
            goto cleanup;
        }
    } else {
        VIR_WARN("Unhandled blkio tune config: %s", name);
    }

    ret = 0;

 cleanup:
    virStringListFree(parts);
    VIR_FREE(path);

    return ret;
}

static int
lxcSetBlkioTune(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;

    if ((value = virConfGetValue(properties, "lxc.cgroup.blkio.weight")) &&
            value->str && virStrToLong_ui(value->str, NULL, 10,
                                          &def->blkio.weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse integer: '%s'"), value->str);
        return -1;
    }

    if (virConfWalk(properties, lxcBlkioDeviceWalkCallback, def) < 0)
        return -1;

    return 0;
}

static void
lxcSetCapDrop(virDomainDefPtr def, virConfPtr properties)
{
    virConfValuePtr value;
    char **toDrop = NULL;
    const char *capString;
    size_t i;

    if ((value = virConfGetValue(properties, "lxc.cap.drop")) && value->str)
        toDrop = virStringSplit(value->str, " ", 0);

    for (i = 0; i < VIR_DOMAIN_CAPS_FEATURE_LAST; i++) {
        capString = virDomainCapsFeatureTypeToString(i);
        if (toDrop != NULL &&
            virStringListHasString((const char **) toDrop, capString))
            def->caps_features[i] = VIR_TRISTATE_SWITCH_OFF;
    }

    def->features[VIR_DOMAIN_FEATURE_CAPABILITIES] = VIR_DOMAIN_CAPABILITIES_POLICY_ALLOW;

    virStringListFree(toDrop);
}

virDomainDefPtr
lxcParseConfigString(const char *config,
                     virCapsPtr caps,
                     virDomainXMLOptionPtr xmlopt)
{
    virDomainDefPtr vmdef = NULL;
    virConfPtr properties = NULL;
    virConfValuePtr value;

    if (!(properties = virConfReadMem(config, 0, VIR_CONF_FLAG_LXC_FORMAT)))
        return NULL;

    if (!(vmdef = virDomainDefNew()))
        goto error;

    if (virUUIDGenerate(vmdef->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        goto error;
    }

    vmdef->id = -1;
    virDomainDefSetMemoryTotal(vmdef, 64 * 1024);

    vmdef->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    vmdef->onCrash = VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY;
    vmdef->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    vmdef->virtType = VIR_DOMAIN_VIRT_LXC;

    /* Value not handled by the LXC driver, setting to
     * minimum required to make XML parsing pass */
    if (virDomainDefSetVcpusMax(vmdef, 1, xmlopt) < 0)
        goto error;

    if (virDomainDefSetVcpus(vmdef, 1) < 0)
        goto error;

    vmdef->nfss = 0;
    vmdef->os.type = VIR_DOMAIN_OSTYPE_EXE;

    if ((value = virConfGetValue(properties, "lxc.arch")) && value->str) {
        virArch arch = virArchFromString(value->str);
        if (arch == VIR_ARCH_NONE && STREQ(value->str, "x86"))
            arch = VIR_ARCH_I686;
        else if (arch == VIR_ARCH_NONE && STREQ(value->str, "amd64"))
            arch = VIR_ARCH_X86_64;
        vmdef->os.arch = arch;
    }

    if (VIR_STRDUP(vmdef->os.init, "/sbin/init") < 0)
        goto error;

    if (!(value = virConfGetValue(properties, "lxc.utsname")) ||
            !value->str || (VIR_STRDUP(vmdef->name, value->str) < 0))
        goto error;
    if (!vmdef->name && (VIR_STRDUP(vmdef->name, "unnamed") < 0))
        goto error;

    if (lxcSetRootfs(vmdef, properties) < 0)
        goto error;

    /* Look for fstab: we shouldn't have it */
    if (virConfGetValue(properties, "lxc.mount")) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("lxc.mount found, use lxc.mount.entry lines instead"));
        goto error;
    }

    /* Loop over lxc.mount.entry to add filesystem devices for them */
    if (virConfWalk(properties, lxcFstabWalkCallback, vmdef) < 0)
        goto error;

    /* Network configuration */
    if (lxcConvertNetworkSettings(vmdef, properties) < 0)
        goto error;

    /* Consoles */
    if (lxcCreateConsoles(vmdef, properties) < 0)
        goto error;

    /* lxc.id_map */
    if (virConfWalk(properties, lxcIdmapWalkCallback, vmdef) < 0)
        goto error;

    /* lxc.cgroup.memory.* */
    if (lxcSetMemTune(vmdef, properties) < 0)
        goto error;

    /* lxc.cgroup.cpu.* */
    if (lxcSetCpuTune(vmdef, properties) < 0)
        goto error;

    /* lxc.cgroup.cpuset.* */
    if (lxcSetCpusetTune(vmdef, properties) < 0)
        goto error;

    /* lxc.cgroup.blkio.* */
    if (lxcSetBlkioTune(vmdef, properties) < 0)
        goto error;

    /* lxc.cap.drop */
    lxcSetCapDrop(vmdef, properties);

    if (virDomainDefPostParse(vmdef, caps, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        goto cleanup;

    goto cleanup;

 error:
    virDomainDefFree(vmdef);
    vmdef = NULL;

 cleanup:
    virConfFree(properties);

    return vmdef;
}
