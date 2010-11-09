/*
 * uml_conf.c: UML driver configuration
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <dirent.h>
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
#include <sys/utsname.h>

#include "uml_conf.h"
#include "uuid.h"
#include "buf.h"
#include "conf.h"
#include "util.h"
#include "memory.h"
#include "nodeinfo.h"
#include "verify.h"
#include "bridge.h"
#include "logging.h"
#include "domain_nwfilter.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_UML

#define umlLog(level, msg, ...)                                     \
        virLogMessage(__FILE__, level, 0, msg, __VA_ARGS__)

virCapsPtr umlCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN0("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (virGetHostUUID(caps->host.host_uuid)) {
        umlReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "uml",
                                         utsname.machine,
                                         STREQ(utsname.machine, "x86_64") ? 64 : 32,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "uml",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto error;

    caps->defaultConsoleTargetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_UML;

    return caps;

 error:
    virCapabilitiesFree(caps);
    return NULL;
}


static int
umlConnectTapDevice(virConnectPtr conn,
                    virDomainNetDefPtr net,
                    const char *bridge)
{
    brControl *brctl = NULL;
    int template_ifname = 0;
    int err;
    unsigned char tapmac[VIR_MAC_BUFLEN];

    if ((err = brInit(&brctl))) {
        virReportSystemError(err, "%s",
                             _("cannot initialize bridge support"));
        goto error;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, "vnet") ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (!(net->ifname = strdup("vnet%d")))
            goto no_memory;
        /* avoid exposing vnet%d in dumpxml or error outputs */
        template_ifname = 1;
    }

    memcpy(tapmac, net->mac, VIR_MAC_BUFLEN);
    tapmac[0] = 0xFE; /* Discourage bridge from using TAP dev MAC */
    if ((err = brAddTap(brctl,
                        bridge,
                        &net->ifname,
                        tapmac,
                        0,
                        NULL))) {
        if (err == ENOTSUP) {
            /* In this particular case, give a better diagnostic. */
            umlReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to add tap interface to bridge. "
                             "%s is not a bridge device"), bridge);
        } else if (err == ENOENT) {
            virReportSystemError(err, "%s",
                    _("Failed to add tap interface to bridge. Your kernel "
                      "is missing the 'tun' module or CONFIG_TUN, or you need "
                      "to add the /dev/net/tun device node."));
        } else if (template_ifname) {
            virReportSystemError(err,
                                 _("Failed to add tap interface to bridge '%s'"),
                                 bridge);
        } else {
            virReportSystemError(err,
                                 _("Failed to add tap interface '%s' to bridge '%s'"),
                                 net->ifname, bridge);
        }
        if (template_ifname)
            VIR_FREE(net->ifname);
        goto error;
    }

    if (net->filter) {
        if (virDomainConfNWFilterInstantiate(conn, net)) {
            if (template_ifname)
                VIR_FREE(net->ifname);
            goto error;
        }
    }

    brShutdown(brctl);

    return 0;

no_memory:
    virReportOOMError();
error:
    brShutdown(brctl);
    return -1;
}

static char *
umlBuildCommandLineNet(virConnectPtr conn,
                       virDomainNetDefPtr def,
                       int idx)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    /* General format:  ethNN=type,options */

    virBufferVSprintf(&buf, "eth%d=", idx);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_USER:
        /* ethNNN=slirp,macaddr */
        virBufferAddLit(&buf, "slirp");
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferAddLit(&buf, "tuntap");
        if (def->data.ethernet.ipaddr) {
            umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("IP address not supported for ethernet inteface"));
            goto error;
        }
        if (def->data.ethernet.script) {
            umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("script execution not supported for ethernet inteface"));
            goto error;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
        umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("TCP server networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
        umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("TCP client networking type not supported"));
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
            umlReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Network '%s' not found"),
                           def->data.network.name);
            goto error;
        }
        bridge = virNetworkGetBridgeName(network);
        virNetworkFree(network);
        if (bridge == NULL) {
            goto error;
        }

        if (umlConnectTapDevice(conn, def, bridge) < 0) {
            VIR_FREE(bridge);
            goto error;
        }

        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferVSprintf(&buf, "tuntap,%s", def->ifname);
        break;
    }

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (umlConnectTapDevice(conn, def, def->data.bridge.brname) < 0)
            goto error;

        /* ethNNN=tuntap,tapname,macaddr,gateway */
        virBufferVSprintf(&buf, "tuntap,%s", def->ifname);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("internal networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("direct networking type not supported"));
        goto error;

    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    virBufferVSprintf(&buf, ",%02x:%02x:%02x:%02x:%02x:%02x",
                      def->mac[0], def->mac[1], def->mac[2],
                      def->mac[3], def->mac[4], def->mac[5]);

    if (def->type == VIR_DOMAIN_NET_TYPE_MCAST) {
        virBufferVSprintf(&buf, ",%s,%d",
                          def->data.socket.address,
                          def->data.socket.port);
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
umlBuildCommandLineChr(virDomainChrDefPtr def,
                       const char *dev,
                       fd_set *keepfd)
{
    char *ret = NULL;

    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        if (virAsprintf(&ret, "%s%d=null", dev, def->target.port) < 0) {
            virReportOOMError();
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (virAsprintf(&ret, "%s%d=pts", dev, def->target.port) < 0) {
            virReportOOMError();
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (virAsprintf(&ret, "%s%d=tty:%s", dev, def->target.port,
                        def->data.file.path) < 0) {
            virReportOOMError();
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        if (virAsprintf(&ret, "%s%d=fd:0,fd:1", dev, def->target.port) < 0) {
            virReportOOMError();
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (def->data.tcp.listen != 1) {
            umlReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("only TCP listen is supported for chr device"));
            return NULL;
        }

        if (virAsprintf(&ret, "%s%d=port:%s", dev, def->target.port,
                        def->data.tcp.service) < 0) {
            virReportOOMError();
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
         {
            int fd_out;

            if ((fd_out = open(def->data.file.path,
                               O_WRONLY | O_APPEND | O_CREAT, 0660)) < 0) {
                virReportSystemError(errno,
                                     _("failed to open chardev file: %s"),
                                     def->data.file.path);
                return NULL;
            }
            if (virAsprintf(&ret, "%s%d=null,fd:%d", dev, def->target.port, fd_out) < 0) {
                virReportOOMError();
                VIR_FORCE_CLOSE(fd_out);
                return NULL;
            }
            FD_SET(fd_out, keepfd);
        }
        break;
   case VIR_DOMAIN_CHR_TYPE_PIPE:
        /* XXX could open the pipe & just pass the FDs. Be wary of
         * the effects of blocking I/O, though. */

    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_UNIX:
    default:
        umlReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported chr device type %d"), def->type);
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
int umlBuildCommandLine(virConnectPtr conn,
                        struct uml_driver *driver,
                        virDomainObjPtr vm,
                        fd_set *keepfd,
                        const char ***retargv,
                        const char ***retenv)
{
    int i, j;
    char memory[50];
    struct utsname ut;
    int qargc = 0, qarga = 0;
    const char **qargv = NULL;
    int qenvc = 0, qenva = 0;
    const char **qenv = NULL;
    char *cmdline = NULL;

    uname(&ut);

#define ADD_ARG_SPACE                                                   \
    do {                                                                \
        if (qargc == qarga) {                                           \
            qarga += 10;                                                \
            if (VIR_REALLOC_N(qargv, qarga) < 0)                        \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ARG(thisarg)                                                \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        qargv[qargc++] = thisarg;                                       \
    } while (0)

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        if ((qargv[qargc++] = strdup(thisarg)) == NULL)                 \
            goto no_memory;                                             \
    } while (0)

#define ADD_ARG_PAIR(key,val)                                           \
    do {                                                                \
        char *arg;                                                      \
        ADD_ARG_SPACE;                                                  \
        if (virAsprintf(&arg, "%s=%s", key, val) < 0)                   \
            goto no_memory;                                             \
        qargv[qargc++] = arg;                                           \
    } while (0)


#define ADD_ENV_SPACE                                                   \
    do {                                                                \
        if (qenvc == qenva) {                                           \
            qenva += 10;                                                \
            if (VIR_REALLOC_N(qenv, qenva) < 0)                         \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ENV(thisarg)                                                \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        qenv[qenvc++] = thisarg;                                        \
    } while (0)

#define ADD_ENV_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        if ((qenv[qenvc++] = strdup(thisarg)) == NULL)                  \
            goto no_memory;                                             \
    } while (0)

#define ADD_ENV_COPY(envname)                                           \
    do {                                                                \
        char *val = getenv(envname);                                    \
        char *envval;                                                   \
        ADD_ENV_SPACE;                                                  \
        if (val != NULL) {                                              \
            if (virAsprintf(&envval, "%s=%s", envname, val) < 0)        \
                goto no_memory;                                         \
            qenv[qenvc++] = envval;                                     \
        }                                                               \
    } while (0)

    snprintf(memory, sizeof(memory), "%luK", vm->def->mem.cur_balloon);

    ADD_ENV_LIT("LC_ALL=C");

    ADD_ENV_COPY("LD_PRELOAD");
    ADD_ENV_COPY("LD_LIBRARY_PATH");
    ADD_ENV_COPY("PATH");
    ADD_ENV_COPY("USER");
    ADD_ENV_COPY("LOGNAME");
    ADD_ENV_COPY("TMPDIR");

    ADD_ARG_LIT(vm->def->os.kernel);
    //ADD_ARG_PAIR("con0", "fd:0,fd:1");
    ADD_ARG_PAIR("mem", memory);
    ADD_ARG_PAIR("umid", vm->def->name);
    ADD_ARG_PAIR("uml_dir", driver->monitorDir);

    if (vm->def->os.root)
        ADD_ARG_PAIR("root", vm->def->os.root);

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if (!STRPREFIX(disk->dst, "ubd")) {
            umlReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unsupported disk type '%s'"), disk->dst);
            goto error;
        }

        ADD_ARG_PAIR(disk->dst, disk->src);
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        char *ret = umlBuildCommandLineNet(conn, vm->def->nets[i], i);
        if (!ret)
            goto error;
        ADD_ARG(ret);
    }

    for (i = 0 ; i < UML_MAX_CHAR_DEVICE ; i++) {
        char *ret = NULL;
        if (i == 0 && vm->def->console)
            ret = umlBuildCommandLineChr(vm->def->console, "con", keepfd);
        if (!ret)
            if (virAsprintf(&ret, "con%d=none", i) < 0)
                goto no_memory;
        ADD_ARG(ret);
    }

    for (i = 0 ; i < UML_MAX_CHAR_DEVICE ; i++) {
        virDomainChrDefPtr chr = NULL;
        char *ret = NULL;
        for (j = 0 ; j < vm->def->nserials ; j++)
            if (vm->def->serials[j]->target.port == i)
                chr = vm->def->serials[j];
        if (chr)
            ret = umlBuildCommandLineChr(chr, "ssl", keepfd);
        if (!ret)
            if (virAsprintf(&ret, "ssl%d=none", i) < 0)
                goto no_memory;
        ADD_ARG(ret);
    }

    if (vm->def->os.cmdline) {
        char *args, *next_arg;
        if ((cmdline = strdup(vm->def->os.cmdline)) == NULL)
            goto no_memory;

        args = cmdline;
        while (*args == ' ')
            args++;

        while (*args) {
            next_arg = umlNextArg(args);
            ADD_ARG_LIT(args);
            args = next_arg;
        }
    }

    ADD_ARG(NULL);
    ADD_ENV(NULL);

    *retargv = qargv;
    *retenv = qenv;
    return 0;

 no_memory:
    virReportOOMError();
 error:

    if (qargv) {
        for (i = 0 ; i < qargc ; i++)
            VIR_FREE((qargv)[i]);
        VIR_FREE(qargv);
    }
    if (qenv) {
        for (i = 0 ; i < qenvc ; i++)
            VIR_FREE((qenv)[i]);
        VIR_FREE(qenv);
    }
    VIR_FREE(cmdline);
    return -1;

#undef ADD_ARG
#undef ADD_ARG_LIT
#undef ADD_ARG_SPACE
#undef ADD_USBDISK
#undef ADD_ENV
#undef ADD_ENV_COPY
#undef ADD_ENV_LIT
#undef ADD_ENV_SPACE
}
