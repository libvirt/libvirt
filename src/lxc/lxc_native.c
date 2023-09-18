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
 */

#include <config.h>

#include "internal.h"
#include "lxc_container.h"
#include "lxc_native.h"
#include "util/viralloc.h"
#include "util/virlog.h"
#include "util/virstring.h"
#include "util/virconf.h"
#include "conf/domain_conf.h"
#include "conf/domain_postparse.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_native");

VIR_ENUM_IMPL(virLXCNetworkConfigEntry,
              VIR_LXC_NETWORK_CONFIG_LAST,
              "name",
              "type",
              "link",
              "hwaddr",
              "flags",
              "macvlan.mode",
              "vlan.id",
              "ipv4", /* Legacy: LXC IPv4 address */
              "ipv4.gateway",
              "ipv4.address",
              "ipv6", /* Legacy: LXC IPv6 address */
              "ipv6.gateway",
              "ipv6.address"
);

static virDomainFSDef *
lxcCreateFSDef(int type,
               const char *src,
               const char* dst,
               bool readonly,
               unsigned long long usage)
{
    virDomainFSDef *def;

    if (!(def = virDomainFSDefNew(NULL)))
        return NULL;

    def->type = type;
    def->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;
    def->src->path = g_strdup(src);
    def->dst = g_strdup(dst);
    def->readonly = readonly;
    def->usage = usage;

    return def;
}

typedef struct _lxcFstab lxcFstab;
struct _lxcFstab {
    lxcFstab *next;
    char *src;
    char *dst;
    char *type;
    char *options;
};

static void
lxcFstabFree(lxcFstab *fstab)
{
    while (fstab) {
        lxcFstab *next = NULL;
        next = fstab->next;

        g_free(fstab->src);
        g_free(fstab->dst);
        g_free(fstab->type);
        g_free(fstab->options);
        g_free(fstab);

        fstab = next;
    }
}

static char ** lxcStringSplit(const char *string)
{
    g_autofree char *tmp = NULL;
    size_t i;
    size_t ntokens = 0;
    g_auto(GStrv) parts = NULL;
    g_auto(GStrv) result = NULL;

    tmp = g_strdup(string);

    /* Replace potential \t by a space */
    for (i = 0; tmp[i]; i++) {
        if (tmp[i] == '\t')
            tmp[i] = ' ';
    }

    if (!(parts = g_strsplit(tmp, " ", 0)))
        return NULL;

    /* Append NULL element */
    VIR_EXPAND_N(result, ntokens, 1);

    for (i = 0; parts[i]; i++) {
        if (STREQ(parts[i], ""))
            continue;

        VIR_EXPAND_N(result, ntokens, 1);
        result[ntokens - 2] = g_strdup(parts[i]);
    }

    return g_steal_pointer(&result);
}

static lxcFstab *
lxcParseFstabLine(char *fstabLine)
{
    lxcFstab *fstab = NULL;
    g_auto(GStrv) parts = NULL;

    if (!fstabLine)
        return NULL;

    fstab = g_new0(lxcFstab, 1);
    if (!(parts = lxcStringSplit(fstabLine)))
        goto error;

    if (!parts[0] || !parts[1] || !parts[2] || !parts[3])
        goto error;

    fstab->src = g_strdup(parts[0]);
    fstab->dst = g_strdup(parts[1]);
    fstab->type = g_strdup(parts[2]);
    fstab->options = g_strdup(parts[3]);

    return fstab;

 error:
    lxcFstabFree(fstab);
    return NULL;
}

static int
lxcAddFSDef(virDomainDef *def,
            int type,
            const char *src,
            const char *dst,
            bool readonly,
            unsigned long long usage)
{
    virDomainFSDef *fsDef = NULL;

    if (!(fsDef = lxcCreateFSDef(type, src, dst, readonly, usage)))
        goto error;

    VIR_EXPAND_N(def->fss, def->nfss, 1);
    def->fss[def->nfss - 1] = fsDef;

    return 0;

 error:
    virDomainFSDefFree(fsDef);
    return -1;
}

static int
lxcSetRootfs(virDomainDef *def,
             virConf *properties)
{
    int type = VIR_DOMAIN_FS_TYPE_MOUNT;
    g_autofree char *value = NULL;

    if (virConfGetValueString(properties, "lxc.rootfs.path", &value) <= 0) {
        virResetLastError();

        /* Check for pre LXC 3.0 legacy key */
        if (virConfGetValueString(properties, "lxc.rootfs", &value) <= 0)
            return -1;
    }

    if (STRPREFIX(value, "/dev/"))
        type = VIR_DOMAIN_FS_TYPE_BLOCK;

    if (lxcAddFSDef(def, type, value, "/", false, 0) < 0)
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
                       _("can't convert relative size: '%1$s'"),
                       size);
        return -1;
    } else {
        if (virScaleInteger(value, unit, 1, ULLONG_MAX) < 0)
            goto error;
    }

    return 0;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("failed to convert size: '%1$s'"),
                   size);
    return -1;
}

static int
lxcAddFstabLine(virDomainDef *def, lxcFstab *fstab)
{
    const char *src = NULL;
    g_autofree char *dst = NULL;
    g_auto(GStrv) options = g_strsplit(fstab->options, ",", 0);
    bool readonly;
    int type = VIR_DOMAIN_FS_TYPE_MOUNT;
    unsigned long long usage = 0;

    if (!options)
        return -1;

    if (!g_path_is_absolute(fstab->dst)) {
        dst = g_strdup_printf("/%s", fstab->dst);
    } else {
        dst = g_strdup(fstab->dst);
    }

    /* Check that we don't add basic mounts */
    if (lxcIsBasicMountLocation(dst))
        return 0;

    if (STREQ(fstab->type, "tmpfs")) {
        char *sizeStr = NULL;
        size_t i;
        type = VIR_DOMAIN_FS_TYPE_RAM;

        for (i = 0; options[i]; i++) {
            if ((sizeStr = STRSKIP(options[i], "size="))) {
                if (lxcConvertSize(sizeStr, &usage) < 0)
                    return -1;
                break;
            }
        }
        if (!sizeStr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing tmpfs size, set the size option"));
            return -1;
        }
    } else {
        src = fstab->src;
    }

    /* Is it a block device that needs special favor? */
    if (STRPREFIX(fstab->src, "/dev/"))
        type = VIR_DOMAIN_FS_TYPE_BLOCK;

    /* Do we have ro in options? */
    readonly = g_strv_contains((const char **)options, "ro");

    if (lxcAddFSDef(def, type, src, dst, readonly, usage) < 0)
        return -1;

    return 1;
}

static int
lxcFstabWalkCallback(const char* name, virConfValue *value, void * data)
{
    int ret = 0;
    lxcFstab *fstabLine;
    virDomainDef *def = data;

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

static virDomainNetDef *
lxcCreateNetDef(const char *type,
                const char *linkdev,
                const char *mac,
                const char *flag,
                const char *macvlanmode,
                const char *name)
{
    virDomainNetDef *net = NULL;
    virMacAddr macAddr;

    if (!(net = virDomainNetDefNew(NULL)))
        goto error;

    if (STREQ_NULLABLE(flag, "up"))
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
    else
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;

    net->ifname_guest = g_strdup(name);

    if (mac && virMacAddrParse(mac, &macAddr) == 0)
        net->mac = macAddr;

    if (STREQ(type, "veth")) {
        if (linkdev) {
            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            net->data.bridge.brname = g_strdup(linkdev);
        } else {
            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
        }
    } else if (STREQ(type, "macvlan")) {
        net->type = VIR_DOMAIN_NET_TYPE_DIRECT;

        if (!linkdev)
            goto error;

        net->data.direct.linkdev = g_strdup(linkdev);

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

static virDomainHostdevDef *
lxcCreateHostdevDef(const char *data)
{
    virDomainHostdevDef *hostdev = virDomainHostdevDefNew();

    if (!hostdev)
        return NULL;

    hostdev->mode = VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES;
    hostdev->source.caps.type = VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET;
    hostdev->source.caps.u.net.ifname = g_strdup(data);

    return hostdev;
}

typedef struct _lxcNetworkParseData lxcNetworkParseData;
struct _lxcNetworkParseData {
    char *type;
    char *link;
    char *mac;
    char *flag;
    char *macvlanmode;
    char *vlanid;
    char *name;
    virNetDevIPAddr **ips;
    size_t nips;
    char *gateway_ipv4;
    char *gateway_ipv6;
    size_t index;
};

typedef struct {
    size_t ndata;
    lxcNetworkParseData **parseData;
} lxcNetworkParseDataArray;


static int
lxcAddNetworkRouteDefinition(const char *address,
                             int family,
                             virNetDevIPRoute ***routes,
                             size_t *nroutes)
{
    g_autoptr(virNetDevIPRoute) route = NULL;
    g_autofree char *familyStr = NULL;
    g_autofree char *zero = NULL;

    zero = g_strdup(family == AF_INET ? VIR_SOCKET_ADDR_IPV4_ALL : VIR_SOCKET_ADDR_IPV6_ALL);

    familyStr = g_strdup(family == AF_INET ? "ipv4" : "ipv6");

    if (!(route = virNetDevIPRouteCreate(_("Domain interface"), familyStr,
                                         zero, NULL, address, 0, false,
                                         0, false)))
        return -1;

    VIR_APPEND_ELEMENT(*routes, *nroutes, route);

    return 0;
}

static int
lxcAddNetworkDefinition(virDomainDef *def, lxcNetworkParseData *data)
{
    virDomainNetDef *net = NULL;
    virDomainHostdevDef *hostdev = NULL;
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
        if (!(hostdev = lxcCreateHostdevDef(data->link)))
            goto error;

        /* This still requires the user to manually setup the vlan interface
         * on the host */
        if (isVlan && data->vlanid) {
            g_free(hostdev->source.caps.u.net.ifname);
            hostdev->source.caps.u.net.ifname = g_strdup_printf("%s.%s",
                                                                data->link,
                                                                data->vlanid);
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

        VIR_EXPAND_N(def->hostdevs, def->nhostdevs, 1);
        def->hostdevs[def->nhostdevs - 1] = hostdev;
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

        VIR_EXPAND_N(def->nets, def->nnets, 1);
        def->nets[def->nnets - 1] = net;
    }

    return 1;

 error:
    for (i = 0; i < data->nips; i++)
        g_free(data->ips[i]);
    g_clear_pointer(&data->ips, g_free);
    virDomainNetDefFree(net);
    virDomainHostdevDefFree(hostdev);
    return -1;
}


static int
lxcNetworkParseDataIPs(const char *name,
                       virConfValue *value,
                       lxcNetworkParseData *parseData)
{
    int family = AF_INET;
    g_auto(GStrv) ipparts = NULL;
    g_autofree virNetDevIPAddr *ip = g_new0(virNetDevIPAddr, 1);

    if (STREQ(name, "ipv6") || STREQ(name, "ipv6.address"))
        family = AF_INET6;

    ipparts = g_strsplit(value->str, "/", 2);
    if (!ipparts || !ipparts[0] || !ipparts[1] ||
        virSocketAddrParse(&ip->address, ipparts[0], family) < 0 ||
        virStrToLong_ui(ipparts[1], NULL, 10, &ip->prefix) < 0) {

        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid CIDR address: '%1$s'"), value->str);
        return -1;
    }

    VIR_APPEND_ELEMENT(parseData->ips, parseData->nips, ip);

    return 0;
}


static int
lxcNetworkParseDataSuffix(const char *entry,
                          virConfValue *value,
                          lxcNetworkParseData *parseData)
{
    int elem = virLXCNetworkConfigEntryTypeFromString(entry);

    switch (elem) {
    case VIR_LXC_NETWORK_CONFIG_TYPE:
        parseData->type = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_LINK:
        parseData->link = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_HWADDR:
        parseData->mac = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_FLAGS:
        parseData->flag = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_MACVLAN_MODE:
        parseData->macvlanmode = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_VLAN_ID:
        parseData->vlanid = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_NAME:
        parseData->name = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_IPV4:
    case VIR_LXC_NETWORK_CONFIG_IPV4_ADDRESS:
    case VIR_LXC_NETWORK_CONFIG_IPV6:
    case VIR_LXC_NETWORK_CONFIG_IPV6_ADDRESS:
        if (lxcNetworkParseDataIPs(entry, value, parseData) < 0)
            return -1;
        break;
    case VIR_LXC_NETWORK_CONFIG_IPV4_GATEWAY:
        parseData->gateway_ipv4 = value->str;
        break;
    case VIR_LXC_NETWORK_CONFIG_IPV6_GATEWAY:
        parseData->gateway_ipv6 = value->str;
        break;
    default:
        VIR_WARN("Unhandled network property: %s = %s",
                 entry,
                 value->str);
        return -1;
    }

    return 0;
}


static lxcNetworkParseData *
lxcNetworkGetParseDataByIndex(lxcNetworkParseDataArray *networks,
                              unsigned int index)
{
    size_t ndata = networks->ndata;
    size_t i;

    for (i = 0; i < ndata; i++) {
        if (networks->parseData[i]->index == index)
            return networks->parseData[i];
    }

    /* Index was not found. So, it is time to add new *
     * interface and return this last position.       */
    VIR_EXPAND_N(networks->parseData, networks->ndata, 1);
    networks->parseData[ndata] = g_new0(lxcNetworkParseData, 1);
    networks->parseData[ndata]->index = index;

    return networks->parseData[ndata];
}


static int
lxcNetworkParseDataEntry(const char *name,
                         virConfValue *value,
                         lxcNetworkParseDataArray *networks)
{
    lxcNetworkParseData *parseData;
    const char *suffix_tmp = STRSKIP(name, "lxc.net.");
    char *suffix = NULL;
    unsigned long long index;

    if (virStrToLong_ull(suffix_tmp, &suffix, 10, &index) < 0)
        return -1;

    if (suffix[0] != '.')
        return -1;

    suffix++;

    if (!(parseData = lxcNetworkGetParseDataByIndex(networks, index)))
        return -1;

    return lxcNetworkParseDataSuffix(suffix, value, parseData);
}


static lxcNetworkParseData *
lxcNetworkGetParseDataByIndexLegacy(lxcNetworkParseDataArray *networks,
                                    const char *entry)
{
    int elem = virLXCNetworkConfigEntryTypeFromString(entry);
    size_t ndata = networks->ndata;

    if (elem == VIR_LXC_NETWORK_CONFIG_TYPE) {
        /* Index was not found. So, it is time to add new *
         * interface and return this last position.       */
        VIR_EXPAND_N(networks->parseData, networks->ndata, 1);
        networks->parseData[ndata] = g_new0(lxcNetworkParseData, 1);
        networks->parseData[ndata]->index = networks->ndata;

        return networks->parseData[ndata];
    }

    /* Return last element added like a stack. */
    if (ndata > 0)
        return networks->parseData[ndata - 1];

    /* Not able to retrieve an element */
    return NULL;
}


static int
lxcNetworkParseDataEntryLegacy(const char *name,
                               virConfValue *value,
                               lxcNetworkParseDataArray *networks)
{
    const char *suffix = STRSKIP(name, "lxc.network.");
    lxcNetworkParseData *parseData;

    if (!(parseData = lxcNetworkGetParseDataByIndexLegacy(networks, suffix)))
        return -1;

    return lxcNetworkParseDataSuffix(suffix, value, parseData);
}


static int
lxcNetworkWalkCallback(const char *name, virConfValue *value, void *data)
{
    lxcNetworkParseDataArray *networks = data;

    if (STRPREFIX(name, "lxc.network."))
        return lxcNetworkParseDataEntryLegacy(name, value, networks);
    if (STRPREFIX(name, "lxc.net."))
        return lxcNetworkParseDataEntry(name, value, networks);

    return 0;
}

static int
lxcConvertNetworkSettings(virDomainDef *def, virConf *properties)
{
    int status;
    bool privnet = true;
    size_t i, j;
    lxcNetworkParseDataArray networks = {0, NULL};
    int ret = -1;

    networks.parseData = g_new0(lxcNetworkParseData *, 1);

    if (virConfWalk(properties, lxcNetworkWalkCallback, &networks) < 0)
        goto error;

    for (i = 0; i < networks.ndata; i++) {
        lxcNetworkParseData *data = networks.parseData[i];

        status = lxcAddNetworkDefinition(def, data);

        if (status < 0)
            goto error;
        else if (data->type != NULL && STREQ(data->type, "none"))
            privnet = false;
    }

    if (networks.ndata == 0 && privnet) {
        /* When no network type is provided LXC only adds loopback */
        def->features[VIR_DOMAIN_FEATURE_PRIVNET] = VIR_TRISTATE_SWITCH_ON;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < networks.ndata; i++)
        g_free(networks.parseData[i]);
    g_clear_pointer(&networks.parseData, g_free);
    return ret;

 error:
    for (i = 0; i < networks.ndata; i++) {
        lxcNetworkParseData *data = networks.parseData[i];
        for (j = 0; j < data->nips; j++)
            g_free(data->ips[j]);
        g_clear_pointer(&data->ips, g_free);
    }
    goto cleanup;
}

static int
lxcCreateConsoles(virDomainDef *def, virConf *properties)
{
    g_autofree char *value = NULL;
    int nbttys = 0;
    virDomainChrDef *console;
    size_t i;

    if (virConfGetValueString(properties, "lxc.tty.max", &value) <= 0) {
        virResetLastError();

        /* Check for pre LXC 3.0 legacy key */
        if (virConfGetValueString(properties, "lxc.tty", &value) <= 0)
            return 0;
    }

    if (virStrToLong_i(value, NULL, 10, &nbttys) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("failed to parse int: '%1$s'"),
                       value);
        return -1;
    }

    def->consoles = g_new0(virDomainChrDef *, nbttys);

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
lxcIdmapWalkCallback(const char *name, virConfValue *value, void *data)
{
    virDomainDef *def = data;
    virDomainIdMapEntry *idmap = NULL;
    char type;
    unsigned long start, target, count;

    /* LXC 3.0 uses "lxc.idmap", while legacy used "lxc.id_map" */
    if (STRNEQ(name, "lxc.idmap") || !value->str) {
        if (!value->str || STRNEQ(name, "lxc.id_map"))
            return 0;
    }

    if (sscanf(value->str, "%c %lu %lu %lu", &type,
               &target, &start, &count) != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("invalid %1$s: '%2$s'"),
                       name, value->str);
        return -1;
    }

    if (type == 'u') {
        VIR_EXPAND_N(def->idmap.uidmap, def->idmap.nuidmap, 1);
        idmap = &def->idmap.uidmap[def->idmap.nuidmap - 1];
    } else if (type == 'g') {
        VIR_EXPAND_N(def->idmap.gidmap, def->idmap.ngidmap, 1);
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
lxcSetMemTune(virDomainDef *def, virConf *properties)
{
    g_autofree char *value = NULL;
    unsigned long long size = 0;

    if (virConfGetValueString(properties,
                              "lxc.cgroup.memory.limit_in_bytes",
                              &value) > 0) {
        if (lxcConvertSize(value, &size) < 0)
            return -1;
        size = size / 1024;
        virDomainDefSetMemoryTotal(def, size);
        def->mem.hard_limit = virMemoryLimitTruncate(size);
        g_clear_pointer(&value, g_free);
    }

    if (virConfGetValueString(properties,
                              "lxc.cgroup.memory.soft_limit_in_bytes",
                              &value) > 0) {
        if (lxcConvertSize(value, &size) < 0)
            return -1;
        def->mem.soft_limit = virMemoryLimitTruncate(size / 1024);
        g_clear_pointer(&value, g_free);
    }

    if (virConfGetValueString(properties,
                              "lxc.cgroup.memory.memsw.limit_in_bytes",
                              &value) > 0) {
        if (lxcConvertSize(value, &size) < 0)
            return -1;
        def->mem.swap_hard_limit = virMemoryLimitTruncate(size / 1024);
    }
    return 0;
}

static int
lxcSetCpuTune(virDomainDef *def, virConf *properties)
{
    g_autofree char *value = NULL;

    if (virConfGetValueString(properties, "lxc.cgroup.cpu.shares",
                              &value) > 0) {
        if (virStrToLong_ull(value, NULL, 10, &def->cputune.shares) < 0)
            goto error;
        def->cputune.sharesSpecified = true;
        g_clear_pointer(&value, g_free);
    }

    if (virConfGetValueString(properties, "lxc.cgroup.cpu.cfs_quota_us",
                              &value) > 0) {
        if (virStrToLong_ll(value, NULL, 10, &def->cputune.quota) < 0)
            goto error;
        g_clear_pointer(&value, g_free);
    }

    if (virConfGetValueString(properties, "lxc.cgroup.cpu.cfs_period_us",
                              &value) > 0) {
        if (virStrToLong_ull(value, NULL, 10, &def->cputune.period) < 0)
            goto error;
    }

    return 0;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("failed to parse integer: '%1$s'"), value);
    return -1;
}

static int
lxcSetCpusetTune(virDomainDef *def, virConf *properties)
{
    g_autofree char *cpus = NULL;
    g_autofree char *mems = NULL;
    g_autoptr(virBitmap) nodeset = NULL;

    if (virConfGetValueString(properties, "lxc.cgroup.cpuset.cpus",
                              &cpus) > 0) {
        if (virBitmapParse(cpus, &def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;
        def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC;
    }

    if (virConfGetValueString(properties, "lxc.cgroup.cpuset.mems",
                              &mems) > 0) {
        if (virBitmapParse(mems, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;
        if (virDomainNumatuneSet(def->numa,
                                 def->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC,
                                 VIR_DOMAIN_NUMATUNE_MEM_STRICT,
                                 nodeset) < 0)
            return -1;
    }

    return 0;
}

static int
lxcBlkioDeviceWalkCallback(const char *name, virConfValue *value, void *data)
{
    g_auto(GStrv) parts = NULL;
    virBlkioDevice *device = NULL;
    virDomainDef *def = data;
    size_t i = 0;
    g_autofree char *path = NULL;

    if (!STRPREFIX(name, "lxc.cgroup.blkio.") ||
            STREQ(name, "lxc.cgroup.blkio.weight")|| !value->str)
        return 0;

    if (!(parts = lxcStringSplit(value->str)))
        return -1;

    if (!parts[0] || !parts[1]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid %1$s value: '%2$s'"),
                       name, value->str);
        return -1;
    }

    path = g_strdup_printf("/dev/block/%s", parts[0]);

    /* Do we already have a device definition for this path?
     * Get that device or create a new one */
    for (i = 0; !device && i < def->blkio.ndevices; i++) {
        if (STREQ(def->blkio.devices[i].path, path))
            device = &def->blkio.devices[i];
    }
    if (!device) {
        VIR_EXPAND_N(def->blkio.devices, def->blkio.ndevices, 1);
        device = &def->blkio.devices[def->blkio.ndevices - 1];
        device->path = g_steal_pointer(&path);
    }

    /* Set the value */
    if (STREQ(name, "lxc.cgroup.blkio.device_weight")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->weight) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse device weight: '%1$s'"), parts[1]);
            return -1;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.read_bps_device")) {
        if (virStrToLong_ull(parts[1], NULL, 10, &device->rbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse read_bps_device: '%1$s'"),
                           parts[1]);
            return -1;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.write_bps_device")) {
        if (virStrToLong_ull(parts[1], NULL, 10, &device->wbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse write_bps_device: '%1$s'"),
                           parts[1]);
            return -1;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.read_iops_device")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->riops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse read_iops_device: '%1$s'"),
                           parts[1]);
            return -1;
        }
    } else if (STREQ(name, "lxc.cgroup.blkio.throttle.write_iops_device")) {
        if (virStrToLong_ui(parts[1], NULL, 10, &device->wiops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse write_iops_device: '%1$s'"),
                           parts[1]);
            return -1;
        }
    } else {
        VIR_WARN("Unhandled blkio tune config: %s", name);
    }

    return 0;
}

static int
lxcSetBlkioTune(virDomainDef *def, virConf *properties)
{
    g_autofree char *value = NULL;

    if (virConfGetValueString(properties, "lxc.cgroup.blkio.weight",
                              &value) > 0) {
        if (virStrToLong_ui(value, NULL, 10, &def->blkio.weight) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse integer: '%1$s'"), value);
            return -1;
        }
    }

    if (virConfWalk(properties, lxcBlkioDeviceWalkCallback, def) < 0)
        return -1;

    return 0;
}

static void
lxcSetCapDrop(virDomainDef *def, virConf *properties)
{
    g_autofree char *value = NULL;
    g_auto(GStrv) toDrop = NULL;
    const char *capString;
    size_t i;

    if (virConfGetValueString(properties, "lxc.cap.drop", &value) > 0)
        toDrop = g_strsplit(value, " ", 0);

    for (i = 0; i < VIR_DOMAIN_PROCES_CAPS_FEATURE_LAST; i++) {
        capString = virDomainProcessCapsFeatureTypeToString(i);
        if (toDrop != NULL &&
            g_strv_contains((const char **)toDrop, capString))
            def->caps_features[i] = VIR_TRISTATE_SWITCH_OFF;
    }

    def->features[VIR_DOMAIN_FEATURE_CAPABILITIES] = VIR_DOMAIN_CAPABILITIES_POLICY_ALLOW;
}

virDomainDef *
lxcParseConfigString(const char *config,
                     virCaps *caps G_GNUC_UNUSED,
                     virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainDef) vmdef = NULL;
    g_autoptr(virConf) properties = NULL;
    g_autofree char *value = NULL;

    if (!(properties = virConfReadString(config, VIR_CONF_FLAG_LXC_FORMAT)))
        return NULL;

    if (!(vmdef = virDomainDefNew(xmlopt)))
        return NULL;

    if (virUUIDGenerate(vmdef->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        return NULL;
    }

    vmdef->id = -1;
    virDomainDefSetMemoryTotal(vmdef, 64 * 1024);

    vmdef->onReboot = VIR_DOMAIN_LIFECYCLE_ACTION_RESTART;
    vmdef->onCrash = VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY;
    vmdef->onPoweroff = VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY;
    vmdef->virtType = VIR_DOMAIN_VIRT_LXC;

    /* Value not handled by the LXC driver, setting to
     * minimum required to make XML parsing pass */
    if (virDomainDefSetVcpusMax(vmdef, 1, xmlopt) < 0)
        return NULL;

    if (virDomainDefSetVcpus(vmdef, 1) < 0)
        return NULL;

    vmdef->nfss = 0;
    vmdef->os.type = VIR_DOMAIN_OSTYPE_EXE;

    if (virConfGetValueString(properties, "lxc.arch", &value) > 0) {
        virArch arch = virArchFromString(value);
        if (arch == VIR_ARCH_NONE && STREQ(value, "x86"))
            arch = VIR_ARCH_I686;
        else if (arch == VIR_ARCH_NONE && STREQ(value, "amd64"))
            arch = VIR_ARCH_X86_64;
        vmdef->os.arch = arch;
        g_clear_pointer(&value, g_free);
    }

    vmdef->os.init = g_strdup("/sbin/init");

    if (virConfGetValueString(properties, "lxc.uts.name", &value) <= 0) {
        virResetLastError();

        /* Check for pre LXC 3.0 legacy key */
        if (virConfGetValueString(properties, "lxc.utsname", &value) <= 0)
            return NULL;
    }

    vmdef->name = g_strdup(value);

    if (!vmdef->name)
        vmdef->name = g_strdup("unnamed");

    if (lxcSetRootfs(vmdef, properties) < 0)
        return NULL;

    /* LXC 3.0 uses "lxc.mount.fstab", while legacy used just "lxc.mount".
     * In either case, generate the error to use "lxc.mount.entry" instead */
    if (virConfGetValue(properties, "lxc.mount.fstab") ||
        virConfGetValue(properties, "lxc.mount")) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("lxc.mount.fstab or lxc.mount found, use lxc.mount.entry lines instead"));
        return NULL;
    }

    /* Loop over lxc.mount.entry to add filesystem devices for them */
    if (virConfWalk(properties, lxcFstabWalkCallback, vmdef) < 0)
        return NULL;

    /* Network configuration */
    if (lxcConvertNetworkSettings(vmdef, properties) < 0)
        return NULL;

    /* Consoles */
    if (lxcCreateConsoles(vmdef, properties) < 0)
        return NULL;

    /* lxc.idmap or legacy lxc.id_map */
    if (virConfWalk(properties, lxcIdmapWalkCallback, vmdef) < 0)
        return NULL;

    /* lxc.cgroup.memory.* */
    if (lxcSetMemTune(vmdef, properties) < 0)
        return NULL;

    /* lxc.cgroup.cpu.* */
    if (lxcSetCpuTune(vmdef, properties) < 0)
        return NULL;

    /* lxc.cgroup.cpuset.* */
    if (lxcSetCpusetTune(vmdef, properties) < 0)
        return NULL;

    /* lxc.cgroup.blkio.* */
    if (lxcSetBlkioTune(vmdef, properties) < 0)
        return NULL;

    /* lxc.cap.drop */
    lxcSetCapDrop(vmdef, properties);

    if (virDomainDefPostParse(vmdef, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        return NULL;

    return g_steal_pointer(&vmdef);
}
