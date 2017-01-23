/*
 * uml_conf.c: UML driver configuration
 *
 * Copyright (C) 2006-2014, 2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "uml_conf.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virconf.h"
#include "viralloc.h"
#include "nodeinfo.h"
#include "virlog.h"
#include "domain_nwfilter.h"
#include "virfile.h"
#include "vircommand.h"
#include "virnetdevtap.h"
#include "virnodesuspend.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_UML

VIR_LOG_INIT("uml.uml_conf");

virCapsPtr umlCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_UML,
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_UML,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}


static int
umlConnectTapDevice(virDomainDefPtr vm,
                    virDomainNetDefPtr net,
                    const char *bridge)
{
    bool template_ifname = false;
    int tapfd = -1;

    if (!net->ifname ||
        STRPREFIX(net->ifname, VIR_NET_GENERATED_PREFIX) ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (VIR_STRDUP(net->ifname, VIR_NET_GENERATED_PREFIX "%d") < 0)
            goto error;
        /* avoid exposing vnet%d in getXMLDesc or error outputs */
        template_ifname = true;
    }

    if (virNetDevTapCreateInBridgePort(bridge, &net->ifname, &net->mac,
                                       vm->uuid, net->backend.tap, &tapfd, 1,
                                       virDomainNetGetActualVirtPortProfile(net),
                                       virDomainNetGetActualVlan(net),
                                       0, NULL,
                                       VIR_NETDEV_TAP_CREATE_IFUP |
                                       VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
        if (template_ifname)
            VIR_FREE(net->ifname);
        goto error;
    }

    if (net->filter) {
        if (virDomainConfNWFilterInstantiate(vm->uuid, net) < 0) {
            if (template_ifname)
                VIR_FREE(net->ifname);
            goto error;
        }
    }

    VIR_FORCE_CLOSE(tapfd);
    return 0;

 error:
    VIR_FORCE_CLOSE(tapfd);
    return -1;
}

static char *
umlBuildCommandLineNet(virConnectPtr conn,
                       virDomainDefPtr vm,
                       virDomainNetDefPtr def,
                       int idx)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    /* General format:  ethNN=type,options */

    virBufferAsprintf(&buf, "eth%d=", idx);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_USER:
        /* ethNNN=slirp,macaddr */
        virBufferAddLit(&buf, "slirp");
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferAddLit(&buf, "tuntap,");
        if (def->ifname)
            virBufferAdd(&buf, def->ifname, -1);
        if (def->guestIP.nips > 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("IP address not supported for ethernet interface"));
            goto error;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vhostuser networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_SERVER:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("TCP server networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("TCP client networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_UDP:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("UDP networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_MCAST:
        /* ethNNN=tuntap,macaddr,ipaddr,port */
        virBufferAddLit(&buf, "mcast");
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        char *bridge;
        virNetworkPtr network = virNetworkLookupByName(conn,
                                                       def->data.network.name);
        if (!network) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Network '%s' not found"),
                           def->data.network.name);
            goto error;
        }
        bridge = virNetworkGetBridgeName(network);
        virObjectUnref(network);
        if (bridge == NULL)
            goto error;

        if (umlConnectTapDevice(vm, def, bridge) < 0) {
            VIR_FREE(bridge);
            goto error;
        }

        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferAsprintf(&buf, "tuntap,%s", def->ifname);
        break;
    }

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (umlConnectTapDevice(vm, def,
                                def->data.bridge.brname) < 0)
            goto error;

        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferAsprintf(&buf, "tuntap,%s", def->ifname);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("internal networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("direct networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("hostdev networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    if (def->script) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("interface script execution not supported by this driver"));
        goto error;
    }

    virBufferAsprintf(&buf, ",%s", virMacAddrFormat(&def->mac, macaddr));

    if (def->type == VIR_DOMAIN_NET_TYPE_MCAST) {
        virBufferAsprintf(&buf, ",%s,%d",
                          def->data.socket.address,
                          def->data.socket.port);
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
umlBuildCommandLineChr(virDomainChrDefPtr def,
                       const char *dev,
                       virCommandPtr cmd)
{
    char *ret = NULL;

    switch (def->source->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        if (virAsprintf(&ret, "%s%d=null", dev, def->target.port) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (virAsprintf(&ret, "%s%d=pts", dev, def->target.port) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (virAsprintf(&ret, "%s%d=tty:%s", dev, def->target.port,
                        def->source->data.file.path) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        if (virAsprintf(&ret, "%s%d=fd:0,fd:1", dev, def->target.port) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (def->source->data.tcp.listen != 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("only TCP listen is supported for chr device"));
            return NULL;
        }

        if (virAsprintf(&ret, "%s%d=port:%s", dev, def->target.port,
                        def->source->data.tcp.service) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
         {
            int fd_out;

            if ((fd_out = open(def->source->data.file.path,
                               O_WRONLY | O_APPEND | O_CREAT, 0660)) < 0) {
                virReportSystemError(errno,
                                     _("failed to open chardev file: %s"),
                                     def->source->data.file.path);
                return NULL;
            }
            if (virAsprintf(&ret, "%s%d=null,fd:%d", dev, def->target.port, fd_out) < 0) {
                VIR_FORCE_CLOSE(fd_out);
                return NULL;
            }
            virCommandPassFD(cmd, fd_out,
                             VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        }
        break;
   case VIR_DOMAIN_CHR_TYPE_PIPE:
        /* XXX could open the pipe & just pass the FDs. Be wary of
         * the effects of blocking I/O, though. */

    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_UNIX:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported chr device type %d"), def->source->type);
        break;
    }

    return ret;
}

/*
 * Null-terminate the current argument and return a pointer to the next.
 * This should follow the same rules as the Linux kernel: arguments are
 * separated by spaces; arguments can be quoted with double quotes; double
 * quotes can't be escaped.
 */
static char *umlNextArg(char *args)
{
    int in_quote = 0;

    for (; *args; args++) {
        if (*args == ' ' && !in_quote) {
            *args++ = '\0';
            break;
        }
        if (*args == '"')
            in_quote = !in_quote;
    }

    while (*args == ' ')
        args++;

    return args;
}

/*
 * Constructs a argv suitable for launching uml with config defined
 * for a given virtual machine.
 */
virCommandPtr umlBuildCommandLine(virConnectPtr conn,
                                  struct uml_driver *driver,
                                  virDomainObjPtr vm)
{
    size_t i, j;
    virCommandPtr cmd;

    cmd = virCommandNew(vm->def->os.kernel);

    virCommandAddEnvPassCommon(cmd);

    //virCommandAddArgPair(cmd, "con0", "fd:0,fd:1");
    virCommandAddArgFormat(cmd, "mem=%lluK", vm->def->mem.cur_balloon);
    virCommandAddArgPair(cmd, "umid", vm->def->name);
    virCommandAddArgPair(cmd, "uml_dir", driver->monitorDir);

    if (vm->def->os.root)
        virCommandAddArgPair(cmd, "root", vm->def->os.root);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if (!STRPREFIX(disk->dst, "ubd")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unsupported disk type '%s'"), disk->dst);
            goto error;
        }

        virCommandAddArgPair(cmd, disk->dst, virDomainDiskGetSource(disk));
    }

    for (i = 0; i < vm->def->nnets; i++) {
        char *ret = umlBuildCommandLineNet(conn, vm->def, vm->def->nets[i], i);
        if (!ret)
            goto error;
        virCommandAddArg(cmd, ret);
        VIR_FREE(ret);
    }

    for (i = 0; i < UML_MAX_CHAR_DEVICE; i++) {
        virDomainChrDefPtr chr = NULL;
        char *ret = NULL;
        for (j = 0; j < vm->def->nconsoles; j++)
            if (vm->def->consoles[j]->target.port == i)
                chr = vm->def->consoles[j];
        if (chr)
            ret = umlBuildCommandLineChr(chr, "con", cmd);
        if (!ret)
            if (virAsprintf(&ret, "con%zu=none", i) < 0)
                goto error;
        virCommandAddArg(cmd, ret);
        VIR_FREE(ret);
    }

    for (i = 0; i < UML_MAX_CHAR_DEVICE; i++) {
        virDomainChrDefPtr chr = NULL;
        char *ret = NULL;
        for (j = 0; j < vm->def->nserials; j++)
            if (vm->def->serials[j]->target.port == i)
                chr = vm->def->serials[j];
        if (chr)
            ret = umlBuildCommandLineChr(chr, "ssl", cmd);
        if (!ret)
            if (virAsprintf(&ret, "ssl%zu=none", i) < 0)
                goto error;

        virCommandAddArg(cmd, ret);
        VIR_FREE(ret);
    }

    if (vm->def->os.cmdline) {
        char *args, *next_arg;
        char *cmdline;
        if (VIR_STRDUP(cmdline, vm->def->os.cmdline) < 0)
            goto error;

        args = cmdline;
        while (*args == ' ')
            args++;

        while (*args) {
            next_arg = umlNextArg(args);
            virCommandAddArg(cmd, args);
            args = next_arg;
        }
        VIR_FREE(cmdline);
    }

    return cmd;

 error:
    virCommandFree(cmd);
    return NULL;
}
