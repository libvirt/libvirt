/*
 * driver.c: core driver methods for managing qemu guests
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

#include <sys/types.h>
#include <sys/poll.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "bridge_driver.h"
#include "network_conf.h"
#include "driver.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "memory.h"
#include "uuid.h"
#include "iptables.h"
#include "bridge.h"
#include "logging.h"

#define NETWORK_PID_DIR LOCAL_STATE_DIR "/run/libvirt/network"
#define NETWORK_STATE_DIR LOCAL_STATE_DIR "/lib/libvirt/network"

#define VIR_FROM_THIS VIR_FROM_NETWORK

#define networkReportError(code, fmt...)                                \
    virReportErrorHelper(NULL, VIR_FROM_NETWORK, code, __FILE__,        \
                         __FUNCTION__, __LINE__, fmt)

/* Main driver state */
struct network_driver {
    virMutex lock;

    virNetworkObjList networks;

    iptablesContext *iptables;
    brControl *brctl;
    char *networkConfigDir;
    char *networkAutostartDir;
    char *logDir;
};


static void networkDriverLock(struct network_driver *driver)
{
    virMutexLock(&driver->lock);
}
static void networkDriverUnlock(struct network_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

static int networkShutdown(void);

static int networkStartNetworkDaemon(struct network_driver *driver,
                                     virNetworkObjPtr network);

static int networkShutdownNetworkDaemon(struct network_driver *driver,
                                        virNetworkObjPtr network);

static void networkReloadIptablesRules(struct network_driver *driver);

static struct network_driver *driverState = NULL;


static void
networkFindActiveConfigs(struct network_driver *driver) {
    unsigned int i;

    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjPtr obj = driver->networks.objs[i];
        virNetworkDefPtr tmp;
        char *config;

        virNetworkObjLock(obj);

        if ((config = virNetworkConfigFile(NETWORK_STATE_DIR,
                                           obj->def->name)) == NULL) {
            virNetworkObjUnlock(obj);
            continue;
        }

        if (access(config, R_OK) < 0) {
            VIR_FREE(config);
            virNetworkObjUnlock(obj);
            continue;
        }

        /* Try and load the live config */
        tmp = virNetworkDefParseFile(config);
        VIR_FREE(config);
        if (tmp) {
            obj->newDef = obj->def;
            obj->def = tmp;
        }

        /* If bridge exists, then mark it active */
        if (obj->def->bridge &&
            brHasBridge(driver->brctl, obj->def->bridge) == 0) {
            obj->active = 1;

            /* Finally try and read dnsmasq pid if any */
            if ((obj->def->ipAddress ||
                 obj->def->nranges) &&
                virFileReadPid(NETWORK_PID_DIR, obj->def->name,
                               &obj->dnsmasqPid) == 0) {

                /* Check its still alive */
                if (kill(obj->dnsmasqPid, 0) != 0)
                    obj->dnsmasqPid = -1;

#ifdef __linux__
                char *pidpath;

                if (virAsprintf(&pidpath, "/proc/%d/exe", obj->dnsmasqPid) < 0) {
                    virReportOOMError();
                    goto cleanup;
                }
                if (virFileLinkPointsTo(pidpath, DNSMASQ) == 0)
                    obj->dnsmasqPid = -1;
                VIR_FREE(pidpath);
#endif
            }
        }

    cleanup:
        virNetworkObjUnlock(obj);
    }
}


static void
networkAutostartConfigs(struct network_driver *driver) {
    unsigned int i;

    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);
        if (driver->networks.objs[i]->autostart &&
            !virNetworkObjIsActive(driver->networks.objs[i]) &&
            networkStartNetworkDaemon(driver, driver->networks.objs[i]) < 0) {
            /* failed to start but already logged */
        }
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
}

/**
 * networkStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
networkStartup(int privileged) {
    uid_t uid = geteuid();
    char *base = NULL;
    int err;

    if (VIR_ALLOC(driverState) < 0)
        goto error;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        goto error;
    }
    networkDriverLock(driverState);

    if (privileged) {
        if (virAsprintf(&driverState->logDir,
                        "%s/log/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        char *userdir = virGetUserDirectory(uid);

        if (!userdir)
            goto error;

        if (virAsprintf(&driverState->logDir,
                        "%s/.libvirt/qemu/log", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (virAsprintf(&driverState->networkConfigDir, "%s/qemu/networks", base) == -1)
        goto out_of_memory;

    if (virAsprintf(&driverState->networkAutostartDir, "%s/qemu/networks/autostart",
                    base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if ((err = brInit(&driverState->brctl))) {
        virReportSystemError(err, "%s",
                             _("cannot initialize bridge support"));
        goto error;
    }

    if (!(driverState->iptables = iptablesContextNew())) {
        goto out_of_memory;
    }


    if (virNetworkLoadAllConfigs(&driverState->networks,
                                 driverState->networkConfigDir,
                                 driverState->networkAutostartDir) < 0)
        goto error;

    networkFindActiveConfigs(driverState);
    networkReloadIptablesRules(driverState);
    networkAutostartConfigs(driverState);

    networkDriverUnlock(driverState);

    return 0;

out_of_memory:
    virReportOOMError();

error:
    if (driverState)
        networkDriverUnlock(driverState);

    VIR_FREE(base);
    networkShutdown();
    return -1;
}

/**
 * networkReload:
 *
 * Function to restart the QEmu daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
networkReload(void) {
    if (!driverState)
        return 0;

    networkDriverLock(driverState);
    virNetworkLoadAllConfigs(&driverState->networks,
                             driverState->networkConfigDir,
                             driverState->networkAutostartDir);
    networkReloadIptablesRules(driverState);
    networkAutostartConfigs(driverState);
    networkDriverUnlock(driverState);
    return 0;
}

/**
 * networkActive:
 *
 * Checks if the QEmu daemon is active, i.e. has an active domain or
 * an active network
 *
 * Returns 1 if active, 0 otherwise
 */
static int
networkActive(void) {
    unsigned int i;
    int active = 0;

    if (!driverState)
        return 0;

    networkDriverLock(driverState);
    for (i = 0 ; i < driverState->networks.count ; i++) {
        virNetworkObjPtr net = driverState->networks.objs[i];
        virNetworkObjLock(net);
        if (virNetworkObjIsActive(net))
            active = 1;
        virNetworkObjUnlock(net);
    }
    networkDriverUnlock(driverState);
    return active;
}

/**
 * networkShutdown:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
networkShutdown(void) {
    if (!driverState)
        return -1;

    networkDriverLock(driverState);

    /* free inactive networks */
    virNetworkObjListFree(&driverState->networks);

    VIR_FREE(driverState->logDir);
    VIR_FREE(driverState->networkConfigDir);
    VIR_FREE(driverState->networkAutostartDir);

    if (driverState->brctl)
        brShutdown(driverState->brctl);
    if (driverState->iptables)
        iptablesContextFree(driverState->iptables);

    networkDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);

    VIR_FREE(driverState);

    return 0;
}


static int
networkBuildDnsmasqArgv(virNetworkObjPtr network,
                        const char *pidfile,
                        const char ***argv) {
    int i, len, r;
    int nbleases = 0;
    char *pidfileArg;
    char buf[1024];

    /*
     * NB, be careful about syntax for dnsmasq options in long format
     *
     * If the flag has a mandatory argument, it can be given using
     * either syntax:
     *
     *     --foo bar
     *     --foo=bar
     *
     * If the flag has a optional argument, it *must* be given using
     * the syntax:
     *
     *     --foo=bar
     *
     * It is hard to determine whether a flag is optional or not,
     * without reading the dnsmasq source :-( The manpages is not
     * very explicit on this
     */

    len =
        1 + /* dnsmasq */
        1 + /* --strict-order */
        1 + /* --bind-interfaces */
        (network->def->domain?2:0) + /* --domain name */
        2 + /* --pid-file /var/run/libvirt/network/$NAME.pid */
        2 + /* --conf-file "" */
        /*2 + *//* --interface virbr0 */
        2 + /* --except-interface lo */
        2 + /* --listen-address 10.0.0.1 */
        (2 * network->def->nranges) + /* --dhcp-range 10.0.0.2,10.0.0.254 */
        /* --dhcp-lease-max=xxx if needed */
        (network->def->nranges ? 0 : 1) +
        /*  --dhcp-host 01:23:45:67:89:0a,hostname,10.0.0.3 */
        (2 * network->def->nhosts) +
        /* --enable-tftp --tftp-root /srv/tftp */
        (network->def->tftproot ? 3 : 0) +
        /* --dhcp-boot pxeboot.img[,,12.34.56.78] */
        (network->def->bootfile ? 2 : 0) +
        1;  /* NULL */

    if (VIR_ALLOC_N(*argv, len) < 0)
        goto no_memory;

#define APPEND_ARG(v, n, s) do {     \
        if (!((v)[(n)] = strdup(s))) \
            goto no_memory;          \
    } while (0)

#define APPEND_ARG_LIT(v, n, s) \
        (v)[(n)] = s

    i = 0;

    APPEND_ARG(*argv, i++, DNSMASQ);

    /*
     * Needed to ensure dnsmasq uses same algorithm for processing
     * multiple namedriver entries in /etc/resolv.conf as GLibC.
     */
    APPEND_ARG(*argv, i++, "--strict-order");
    APPEND_ARG(*argv, i++, "--bind-interfaces");

    if (network->def->domain) {
       APPEND_ARG(*argv, i++, "--domain");
       APPEND_ARG(*argv, i++, network->def->domain);
    }

    if (virAsprintf(&pidfileArg, "--pid-file=%s", pidfile) < 0)
        goto no_memory;
    APPEND_ARG_LIT(*argv, i++, pidfileArg);

    APPEND_ARG(*argv, i++, "--conf-file=");
    APPEND_ARG(*argv, i++, "");

    /*
     * XXX does not actually work, due to some kind of
     * race condition setting up ipv6 addresses on the
     * interface. A sleep(10) makes it work, but that's
     * clearly not practical
     *
     * APPEND_ARG(*argv, i++, "--interface");
     * APPEND_ARG(*argv, i++, network->def->bridge);
     */
    APPEND_ARG(*argv, i++, "--listen-address");
    APPEND_ARG(*argv, i++, network->def->ipAddress);

    APPEND_ARG(*argv, i++, "--except-interface");
    APPEND_ARG(*argv, i++, "lo");

    for (r = 0 ; r < network->def->nranges ; r++) {
        snprintf(buf, sizeof(buf), "%s,%s",
                 network->def->ranges[r].start,
                 network->def->ranges[r].end);

        APPEND_ARG(*argv, i++, "--dhcp-range");
        APPEND_ARG(*argv, i++, buf);
        nbleases += network->def->ranges[r].size;
    }

    if (network->def->nranges > 0) {
        snprintf(buf, sizeof(buf), "--dhcp-lease-max=%d", nbleases);
        APPEND_ARG(*argv, i++, buf);
    }

    for (r = 0 ; r < network->def->nhosts ; r++) {
        virNetworkDHCPHostDefPtr host = &(network->def->hosts[r]);
        if ((host->mac) && (host->name)) {
            snprintf(buf, sizeof(buf), "%s,%s,%s",
                     host->mac, host->name, host->ip);
        } else if (host->mac) {
            snprintf(buf, sizeof(buf), "%s,%s",
                     host->mac, host->ip);
        } else if (host->name) {
            snprintf(buf, sizeof(buf), "%s,%s",
                     host->name, host->ip);
        } else
            continue;

        APPEND_ARG(*argv, i++, "--dhcp-host");
        APPEND_ARG(*argv, i++, buf);
    }

    if (network->def->tftproot) {
        APPEND_ARG(*argv, i++, "--enable-tftp");
        APPEND_ARG(*argv, i++, "--tftp-root");
        APPEND_ARG(*argv, i++, network->def->tftproot);
    }
    if (network->def->bootfile) {
        snprintf(buf, sizeof(buf), "%s%s%s",
                 network->def->bootfile,
                 network->def->bootserver ? ",," : "",
                 network->def->bootserver ? network->def->bootserver : "");

        APPEND_ARG(*argv, i++, "--dhcp-boot");
        APPEND_ARG(*argv, i++, buf);
    }

#undef APPEND_ARG

    return 0;

 no_memory:
    if (*argv) {
        for (i = 0; (*argv)[i]; i++)
            VIR_FREE((*argv)[i]);
        VIR_FREE(*argv);
    }
    virReportOOMError();
    return -1;
}


static int
dhcpStartDhcpDaemon(virNetworkObjPtr network)
{
    const char **argv;
    char *pidfile;
    int ret = -1, i, err;

    network->dnsmasqPid = -1;

    if (network->def->ipAddress == NULL) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot start dhcp daemon without IP address for server"));
        return -1;
    }

    if ((err = virFileMakePath(NETWORK_PID_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             NETWORK_PID_DIR);
        return -1;
    }
    if ((err = virFileMakePath(NETWORK_STATE_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             NETWORK_STATE_DIR);
        return -1;
    }

    if (!(pidfile = virFilePid(NETWORK_PID_DIR, network->def->name))) {
        virReportOOMError();
        return -1;
    }

    argv = NULL;
    if (networkBuildDnsmasqArgv(network, pidfile, &argv) < 0) {
        VIR_FREE(pidfile);
        return -1;
    }

    if (virRun(argv, NULL) < 0)
        goto cleanup;

    /*
     * There really is no race here - when dnsmasq daemonizes,
     * its leader process stays around until its child has
     * actually written its pidfile. So by time virRun exits
     * it has waitpid'd and guaranteed the proess has started
     * and written a pid
     */

    if (virFileReadPid(NETWORK_PID_DIR, network->def->name,
                       &network->dnsmasqPid) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(pidfile);
    for (i = 0; argv[i]; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    return ret;
}

static int
networkAddMasqueradingIptablesRules(struct network_driver *driver,
                                    virNetworkObjPtr network) {
    int err;
    /* allow forwarding packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow forwarding from '%s'"),
                             network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets to the bridge interface if they are part of an existing connection */
    if ((err = iptablesAddForwardAllowRelatedIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow forwarding to '%s'"),
                             network->def->bridge);
        goto masqerr2;
    }

    /* enable masquerading */
    if ((err = iptablesAddForwardMasquerade(driver->iptables,
                                            network->def->network,
                                            network->def->forwardDev))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to enable masquerading to '%s'\n"),
                             network->def->forwardDev ? network->def->forwardDev : NULL);
        goto masqerr3;
    }

    return 1;

 masqerr3:
    iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                 network->def->network,
                                 network->def->bridge,
                                 network->def->forwardDev);
 masqerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  network->def->network,
                                  network->def->bridge,
                                  network->def->forwardDev);
 masqerr1:
    return 0;
}

static int
networkAddRoutingIptablesRules(struct network_driver *driver,
                               virNetworkObjPtr network) {
    int err;
    /* allow routing packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow routing from '%s'"),
                             network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if ((err = iptablesAddForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow routing to '%s'"),
                             network->def->bridge);
        goto routeerr2;
    }

    return 1;


 routeerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  network->def->network,
                                  network->def->bridge,
                                  network->def->forwardDev);
 routeerr1:
    return 0;
}

static int
networkAddIptablesRules(struct network_driver *driver,
                        virNetworkObjPtr network) {
    int err;

    /* allow DHCP requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 67))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow DHCP requests from '%s'"),
                             network->def->bridge);
        goto err1;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 67))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow DHCP requests from '%s'"),
                             network->def->bridge);
        goto err2;
    }

    /* allow DNS requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 53))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow DNS requests from '%s'"),
                             network->def->bridge);
        goto err3;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 53))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow DNS requests from '%s'"),
                             network->def->bridge);
        goto err4;
    }


    /* Catch all rules to block forwarding to/from bridges */

    if ((err = iptablesAddForwardRejectOut(driver->iptables, network->def->bridge))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to block outbound traffic from '%s'"),
                             network->def->bridge);
        goto err5;
    }

    if ((err = iptablesAddForwardRejectIn(driver->iptables, network->def->bridge))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to block inbound traffic to '%s'"),
                             network->def->bridge);
        goto err6;
    }

    /* Allow traffic between guests on the same bridge */
    if ((err = iptablesAddForwardAllowCross(driver->iptables, network->def->bridge))) {
        virReportSystemError(err,
                             _("failed to add iptables rule to allow cross bridge traffic on '%s'"),
                             network->def->bridge);
        goto err7;
    }


    /* If masquerading is enabled, set up the rules*/
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT &&
        !networkAddMasqueradingIptablesRules(driver, network))
        goto err8;
    /* else if routing is enabled, set up the rules*/
    else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE &&
             !networkAddRoutingIptablesRules(driver, network))
        goto err8;

    return 1;

 err8:
    iptablesRemoveForwardAllowCross(driver->iptables,
                                    network->def->bridge);
 err7:
    iptablesRemoveForwardRejectIn(driver->iptables,
                                  network->def->bridge);
 err6:
    iptablesRemoveForwardRejectOut(driver->iptables,
                                   network->def->bridge);
 err5:
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 53);
 err4:
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 53);
 err3:
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 67);
 err2:
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 67);
 err1:
    return 0;
}

static void
networkRemoveIptablesRules(struct network_driver *driver,
                         virNetworkObjPtr network) {
    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE) {
        if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT) {
            iptablesRemoveForwardMasquerade(driver->iptables,
                                                network->def->network,
                                                network->def->forwardDev);
            iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                                network->def->network,
                                                network->def->bridge,
                                                network->def->forwardDev);
        } else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE)
            iptablesRemoveForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev);

        iptablesRemoveForwardAllowOut(driver->iptables,
                                      network->def->network,
                                      network->def->bridge,
                                      network->def->forwardDev);
    }
    iptablesRemoveForwardAllowCross(driver->iptables, network->def->bridge);
    iptablesRemoveForwardRejectIn(driver->iptables, network->def->bridge);
    iptablesRemoveForwardRejectOut(driver->iptables, network->def->bridge);
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 53);
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 53);
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 67);
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 67);
}

static void
networkReloadIptablesRules(struct network_driver *driver)
{
    unsigned int i;

    VIR_INFO0(_("Reloading iptables rules"));

    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);

        if (virNetworkObjIsActive(driver->networks.objs[i])) {
            networkRemoveIptablesRules(driver, driver->networks.objs[i]);
            if (!networkAddIptablesRules(driver, driver->networks.objs[i])) {
                /* failed to add but already logged */
            }
        }

        virNetworkObjUnlock(driver->networks.objs[i]);
    }
}

/* Enable IP Forwarding. Return 0 for success, -1 for failure. */
static int
networkEnableIpForwarding(void)
{
    return virFileWriteStr("/proc/sys/net/ipv4/ip_forward", "1\n");
}

#define SYSCTL_PATH "/proc/sys"

static int networkDisableIPV6(virNetworkObjPtr network)
{
    char *field = NULL;
    int ret = -1;

    if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/disable_ipv6", network->def->bridge) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (access(field, W_OK) < 0 && errno == ENOENT) {
        VIR_DEBUG("ipv6 appears to already be disabled on %s", network->def->bridge);
        ret = 0;
        goto cleanup;
    }

    if (virFileWriteStr(field, "1") < 0) {
        virReportSystemError(errno,
                             _("cannot enable %s"), field);
        goto cleanup;
    }
    VIR_FREE(field);

    if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/accept_ra", network->def->bridge) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileWriteStr(field, "0") < 0) {
        virReportSystemError(errno,
                             _("cannot disable %s"), field);
        goto cleanup;
    }
    VIR_FREE(field);

    if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/autoconf", network->def->bridge) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileWriteStr(field, "1") < 0) {
        virReportSystemError(errno,
                             _("cannot enable %s"), field);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(field);
    return ret;
}

static int networkStartNetworkDaemon(struct network_driver *driver,
                                     virNetworkObjPtr network)
{
    int err;

    if (virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("network is already active"));
        return -1;
    }

    if ((err = brAddBridge(driver->brctl, network->def->bridge))) {
        virReportSystemError(err,
                             _("cannot create bridge '%s'"),
                             network->def->bridge);
        return -1;
    }

    if (networkDisableIPV6(network) < 0)
        goto err_delbr;

    if (brSetForwardDelay(driver->brctl, network->def->bridge, network->def->delay) < 0)
        goto err_delbr;

    if (brSetEnableSTP(driver->brctl, network->def->bridge, network->def->stp ? 1 : 0) < 0)
        goto err_delbr;

    if (network->def->ipAddress &&
        (err = brSetInetAddress(driver->brctl, network->def->bridge, network->def->ipAddress))) {
        virReportSystemError(err,
                             _("cannot set IP address on bridge '%s' to '%s'"),
                             network->def->bridge, network->def->ipAddress);
        goto err_delbr;
    }

    if (network->def->netmask &&
        (err = brSetInetNetmask(driver->brctl, network->def->bridge, network->def->netmask))) {
        virReportSystemError(err,
                             _("cannot set netmask on bridge '%s' to '%s'"),
                             network->def->bridge, network->def->netmask);
        goto err_delbr;
    }

    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 1))) {
        virReportSystemError(err,
                             _("failed to bring the bridge '%s' up"),
                             network->def->bridge);
        goto err_delbr;
    }

    if (!networkAddIptablesRules(driver, network))
        goto err_delbr1;

    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE &&
        networkEnableIpForwarding() < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to enable IP forwarding"));
        goto err_delbr2;
    }

    if ((network->def->ipAddress ||
         network->def->nranges) &&
        dhcpStartDhcpDaemon(network) < 0)
        goto err_delbr2;


    /* Persist the live configuration now we have bridge info  */
    if (virNetworkSaveConfig(NETWORK_STATE_DIR, network->def) < 0) {
        goto err_kill;
    }

    network->active = 1;

    return 0;

 err_kill:
    if (network->dnsmasqPid > 0) {
        kill(network->dnsmasqPid, SIGTERM);
        network->dnsmasqPid = -1;
    }

 err_delbr2:
    networkRemoveIptablesRules(driver, network);

 err_delbr1:
    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        char ebuf[1024];
        VIR_WARN(_("Failed to bring down bridge '%s' : %s"),
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

 err_delbr:
    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        char ebuf[1024];
        VIR_WARN(_("Failed to delete bridge '%s' : %s"),
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    return -1;
}


static int networkShutdownNetworkDaemon(struct network_driver *driver,
                                        virNetworkObjPtr network)
{
    int err;
    char *stateFile;

    VIR_INFO(_("Shutting down network '%s'"), network->def->name);

    if (!virNetworkObjIsActive(network))
        return 0;

    stateFile = virNetworkConfigFile(NETWORK_STATE_DIR, network->def->name);
    if (!stateFile)
        return -1;

    unlink(stateFile);
    VIR_FREE(stateFile);

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    networkRemoveIptablesRules(driver, network);

    char ebuf[1024];
    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        VIR_WARN(_("Failed to bring down bridge '%s' : %s"),
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        VIR_WARN(_("Failed to delete bridge '%s' : %s"),
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    /* See if its still alive and really really kill it */
    if (network->dnsmasqPid > 0 &&
        (kill(network->dnsmasqPid, 0) == 0))
        kill(network->dnsmasqPid, SIGKILL);

    network->dnsmasqPid = -1;
    network->active = 0;

    if (network->newDef) {
        virNetworkDefFree(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
    }

    return 0;
}


static virNetworkPtr networkLookupByUUID(virConnectPtr conn,
                                         const unsigned char *uuid) {
    struct network_driver *driver = conn->networkPrivateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, uuid);
    networkDriverUnlock(driver);
    if (!network) {
        networkReportError(VIR_ERR_NO_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static virNetworkPtr networkLookupByName(virConnectPtr conn,
                                         const char *name) {
    struct network_driver *driver = conn->networkPrivateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByName(&driver->networks, name);
    networkDriverUnlock(driver);
    if (!network) {
        networkReportError(VIR_ERR_NO_NETWORK,
                           _("no network with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static virDrvOpenStatus networkOpenNetwork(virConnectPtr conn,
                                           virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                           int flags ATTRIBUTE_UNUSED) {
    if (!driverState)
        return VIR_DRV_OPEN_DECLINED;

    conn->networkPrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}

static int networkCloseNetwork(virConnectPtr conn) {
    conn->networkPrivateData = NULL;
    return 0;
}

static int networkNumNetworks(virConnectPtr conn) {
    int nactive = 0, i;
    struct network_driver *driver = conn->networkPrivateData;

    networkDriverLock(driver);
    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);
        if (virNetworkObjIsActive(driver->networks.objs[i]))
            nactive++;
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
    networkDriverUnlock(driver);

    return nactive;
}

static int networkListNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct network_driver *driver = conn->networkPrivateData;
    int got = 0, i;

    networkDriverLock(driver);
    for (i = 0 ; i < driver->networks.count && got < nnames ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);
        if (virNetworkObjIsActive(driver->networks.objs[i])) {
            if (!(names[got] = strdup(driver->networks.objs[i]->def->name))) {
                virNetworkObjUnlock(driver->networks.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
    networkDriverUnlock(driver);

    return got;

 cleanup:
    networkDriverUnlock(driver);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int networkNumDefinedNetworks(virConnectPtr conn) {
    int ninactive = 0, i;
    struct network_driver *driver = conn->networkPrivateData;

    networkDriverLock(driver);
    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);
        if (!virNetworkObjIsActive(driver->networks.objs[i]))
            ninactive++;
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
    networkDriverUnlock(driver);

    return ninactive;
}

static int networkListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct network_driver *driver = conn->networkPrivateData;
    int got = 0, i;

    networkDriverLock(driver);
    for (i = 0 ; i < driver->networks.count && got < nnames ; i++) {
        virNetworkObjLock(driver->networks.objs[i]);
        if (!virNetworkObjIsActive(driver->networks.objs[i])) {
            if (!(names[got] = strdup(driver->networks.objs[i]->def->name))) {
                virNetworkObjUnlock(driver->networks.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
    networkDriverUnlock(driver);
    return got;

 cleanup:
    networkDriverUnlock(driver);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}


static int networkIsActive(virNetworkPtr net)
{
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr obj;
    int ret = -1;

    networkDriverLock(driver);
    obj = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);
    if (!obj) {
        networkReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = virNetworkObjIsActive(obj);

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}

static int networkIsPersistent(virNetworkPtr net)
{
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr obj;
    int ret = -1;

    networkDriverLock(driver);
    obj = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);
    if (!obj) {
        networkReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}


static virNetworkPtr networkCreate(virConnectPtr conn, const char *xml) {
    struct network_driver *driver = conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network = NULL;
    virNetworkPtr ret = NULL;

    networkDriverLock(driver);

    if (!(def = virNetworkDefParseString(xml)))
        goto cleanup;

    if (virNetworkSetBridgeName(&driver->networks, def, 1))
        goto cleanup;

    if (!(network = virNetworkAssignDef(&driver->networks,
                                        def)))
        goto cleanup;
    def = NULL;

    if (networkStartNetworkDaemon(driver, network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        network = NULL;
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    virNetworkDefFree(def);
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static virNetworkPtr networkDefine(virConnectPtr conn, const char *xml) {
    struct network_driver *driver = conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network = NULL;
    virNetworkPtr ret = NULL;

    networkDriverLock(driver);

    if (!(def = virNetworkDefParseString(xml)))
        goto cleanup;

    if (virNetworkSetBridgeName(&driver->networks, def, 1))
        goto cleanup;

    if (!(network = virNetworkAssignDef(&driver->networks,
                                        def)))
        goto cleanup;
    def = NULL;

    network->persistent = 1;

    if (virNetworkSaveConfig(driver->networkConfigDir,
                             network->newDef ? network->newDef : network->def) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        network = NULL;
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    virNetworkDefFree(def);
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static int networkUndefine(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network = NULL;
    int ret = -1;

    networkDriverLock(driver);

    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("network is still active"));
        goto cleanup;
    }

    if (virNetworkDeleteConfig(driver->networkConfigDir,
                               driver->networkAutostartDir,
                               network) < 0)
        goto cleanup;

    virNetworkRemoveInactive(&driver->networks,
                             network);
    network = NULL;
    ret = 0;

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static int networkStart(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    int ret = -1;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = networkStartNetworkDaemon(driver, network);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static int networkDestroy(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    int ret = -1;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("network is not active"));
        goto cleanup;
    }

    ret = networkShutdownNetworkDaemon(driver, network);
    if (!network->persistent) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        network = NULL;
    }

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static char *networkDumpXML(virNetworkPtr net, int flags ATTRIBUTE_UNUSED) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    char *ret = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);

    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virNetworkDefFormat(network->def);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static char *networkGetBridgeName(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    char *bridge = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);

    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching id"));
        goto cleanup;
    }

    if (!(network->def->bridge)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' does not have a bridge name."),
                           network->def->name);
        goto cleanup;
    }

    bridge = strdup(network->def->bridge);
    if (!bridge)
        virReportOOMError();

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return bridge;
}

static int networkGetAutostart(virNetworkPtr net,
                             int *autostart) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    int ret = -1;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);
    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    *autostart = network->autostart;
    ret = 0;

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static int networkSetAutostart(virNetworkPtr net,
                               int autostart) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(VIR_ERR_INVALID_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!network->persistent) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot set autostart for transient network"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (network->autostart != autostart) {
        if ((configFile = virNetworkConfigFile(driver->networkConfigDir, network->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virNetworkConfigFile(driver->networkAutostartDir, network->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            if (virFileMakePath(driver->networkAutostartDir)) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory '%s'"),
                                     driver->networkAutostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s' to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        network->autostart = autostart;
    }
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}


static virNetworkDriver networkDriver = {
    "Network",
    networkOpenNetwork, /* open */
    networkCloseNetwork, /* close */
    networkNumNetworks, /* numOfNetworks */
    networkListNetworks, /* listNetworks */
    networkNumDefinedNetworks, /* numOfDefinedNetworks */
    networkListDefinedNetworks, /* listDefinedNetworks */
    networkLookupByUUID, /* networkLookupByUUID */
    networkLookupByName, /* networkLookupByName */
    networkCreate, /* networkCreateXML */
    networkDefine, /* networkDefineXML */
    networkUndefine, /* networkUndefine */
    networkStart, /* networkCreate */
    networkDestroy, /* networkDestroy */
    networkDumpXML, /* networkDumpXML */
    networkGetBridgeName, /* networkGetBridgeName */
    networkGetAutostart, /* networkGetAutostart */
    networkSetAutostart, /* networkSetAutostart */
    networkIsActive,
    networkIsPersistent,
};

static virStateDriver networkStateDriver = {
    "Network",
    networkStartup,
    networkShutdown,
    networkReload,
    networkActive,
};

int networkRegister(void) {
    virRegisterNetworkDriver(&networkDriver);
    virRegisterStateDriver(&networkStateDriver);
    return 0;
}
