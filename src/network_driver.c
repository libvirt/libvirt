/*
 * driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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
#include "network_driver.h"
#include "network_conf.h"
#include "driver.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "memory.h"
#include "uuid.h"
#include "iptables.h"
#include "bridge.h"

/* Main driver state */
struct network_driver {
    virNetworkObjList networks;

    iptablesContext *iptables;
    brControl *brctl;
    char *networkConfigDir;
    char *networkAutostartDir;
    char *logDir;
};

static int networkShutdown(void);

/* networkDebug statements should be changed to use this macro instead. */

#define networkLog(level, msg...) fprintf(stderr, msg)

#define networkReportError(conn, dom, net, code, fmt...)                \
    virReportErrorHelper(conn, VIR_FROM_QEMU, code, __FILE__,         \
                           __FUNCTION__, __LINE__, fmt)


static int networkStartNetworkDaemon(virConnectPtr conn,
                                   struct network_driver *driver,
                                   virNetworkObjPtr network);

static int networkShutdownNetworkDaemon(virConnectPtr conn,
                                      struct network_driver *driver,
                                      virNetworkObjPtr network);

static struct network_driver *driverState = NULL;


static void
networkAutostartConfigs(struct network_driver *driver) {
    unsigned int i;

    for (i = 0 ; i < driver->networks.count ; i++) {
        if (driver->networks.objs[i]->autostart &&
            !virNetworkIsActive(driver->networks.objs[i]) &&
            networkStartNetworkDaemon(NULL, driver, driver->networks.objs[i]) < 0) {
            virErrorPtr err = virGetLastError();
            networkLog(NETWORK_ERR, _("Failed to autostart network '%s': %s\n"),
                       driver->networks.objs[i]->def->name,
                       err ? err->message : NULL);
        }
    }
}

/**
 * networkStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
networkStartup(void) {
    uid_t uid = geteuid();
    struct passwd *pw;
    char *base = NULL;

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (!uid) {
        if (asprintf(&driverState->logDir,
                     "%s/log/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        if (!(pw = getpwuid(uid))) {
            networkLog(NETWORK_ERR, _("Failed to find user record for uid '%d': %s\n"),
                     uid, strerror(errno));
            goto out_of_memory;
        }

        if (asprintf(&driverState->logDir,
                     "%s/.libvirt/qemu/log", pw->pw_dir) == -1)
            goto out_of_memory;

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1) {
            networkLog (NETWORK_ERR,
                      "%s", _("out of memory in asprintf\n"));
            goto out_of_memory;
        }
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (asprintf (&driverState->networkConfigDir, "%s/qemu/networks", base) == -1)
        goto out_of_memory;

    if (asprintf (&driverState->networkAutostartDir, "%s/qemu/networks/autostart",
                  base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if (virNetworkLoadAllConfigs(NULL,
                                 &driverState->networks,
                                 driverState->networkConfigDir,
                                 driverState->networkAutostartDir) < 0) {
        networkShutdown();
        return -1;
    }
    networkAutostartConfigs(driverState);

    return 0;

 out_of_memory:
    networkLog (NETWORK_ERR,
              "%s", _("networkStartup: out of memory\n"));
    VIR_FREE(base);
    VIR_FREE(driverState);
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

    virNetworkLoadAllConfigs(NULL,
                             &driverState->networks,
                             driverState->networkConfigDir,
                             driverState->networkAutostartDir);

     if (driverState->iptables) {
        networkLog(NETWORK_INFO,
                 "%s", _("Reloading iptables rules\n"));
        iptablesReloadRules(driverState->iptables);
    }

    networkAutostartConfigs(driverState);

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

    if (!driverState)
        return 0;

    for (i = 0 ; i < driverState->networks.count ; i++)
        if (virNetworkIsActive(driverState->networks.objs[i]))
            return 1;

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}

/**
 * networkShutdown:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
networkShutdown(void) {
    unsigned int i;

    if (!driverState)
        return -1;

    /* shutdown active networks */
    for (i = 0 ; i < driverState->networks.count ; i++)
        if (virNetworkIsActive(driverState->networks.objs[i]))
            networkShutdownNetworkDaemon(NULL, driverState,
                                         driverState->networks.objs[i]);

    /* free inactive networks */
    virNetworkObjListFree(&driverState->networks);

    VIR_FREE(driverState->logDir);
    VIR_FREE(driverState->networkConfigDir);
    VIR_FREE(driverState->networkAutostartDir);

    if (driverState->brctl)
        brShutdown(driverState->brctl);
    if (driverState->iptables)
        iptablesContextFree(driverState->iptables);

    VIR_FREE(driverState);

    return 0;
}


static int
networkBuildDnsmasqArgv(virConnectPtr conn,
                      virNetworkObjPtr network,
                      const char ***argv) {
    int i, len, r;
    char buf[PATH_MAX];

    len =
        1 + /* dnsmasq */
        1 + /* --keep-in-foreground */
        1 + /* --strict-order */
        1 + /* --bind-interfaces */
        (network->def->domain?2:0) + /* --domain name */
        2 + /* --pid-file "" */
        2 + /* --conf-file "" */
        /*2 + *//* --interface virbr0 */
        2 + /* --except-interface lo */
        2 + /* --listen-address 10.0.0.1 */
        1 + /* --dhcp-leasefile=path */
        (2 * network->def->nranges) + /* --dhcp-range 10.0.0.2,10.0.0.254 */
        /*  --dhcp-host 01:23:45:67:89:0a,hostname,10.0.0.3 */
        (2 * network->def->nhosts) +
        1;  /* NULL */

    if (VIR_ALLOC_N(*argv, len) < 0)
        goto no_memory;

#define APPEND_ARG(v, n, s) do {     \
        if (!((v)[(n)] = strdup(s))) \
            goto no_memory;          \
    } while (0)

    i = 0;

    APPEND_ARG(*argv, i++, DNSMASQ);

    APPEND_ARG(*argv, i++, "--keep-in-foreground");
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

    APPEND_ARG(*argv, i++, "--pid-file");
    APPEND_ARG(*argv, i++, "");

    APPEND_ARG(*argv, i++, "--conf-file");
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

    /*
     * NB, dnsmasq command line arg bug means we need to
     * use a single arg '--dhcp-leasefile=path' rather than
     * two separate args in '--dhcp-leasefile path' style
     */
    snprintf(buf, sizeof(buf), "--dhcp-leasefile=%s/lib/libvirt/dhcp-%s.leases",
             LOCAL_STATE_DIR, network->def->name);
    APPEND_ARG(*argv, i++, buf);

    for (r = 0 ; r < network->def->nranges ; r++) {
        snprintf(buf, sizeof(buf), "%s,%s",
                 network->def->ranges[r].start,
                 network->def->ranges[r].end);

        APPEND_ARG(*argv, i++, "--dhcp-range");
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

#undef APPEND_ARG

    return 0;

 no_memory:
    if (argv) {
        for (i = 0; (*argv)[i]; i++)
            VIR_FREE((*argv)[i]);
        VIR_FREE(*argv);
    }
    networkReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for dnsmasq argv"));
    return -1;
}


static int
dhcpStartDhcpDaemon(virConnectPtr conn,
                    virNetworkObjPtr network)
{
    const char **argv;
    int ret, i;

    if (network->def->ipAddress == NULL) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot start dhcp daemon without IP address for server"));
        return -1;
    }

    argv = NULL;
    if (networkBuildDnsmasqArgv(conn, network, &argv) < 0)
        return -1;

    ret = virExec(conn, argv, NULL, NULL,
                  &network->dnsmasqPid, -1, NULL, NULL, VIR_EXEC_NONBLOCK);

    for (i = 0; argv[i]; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    return ret;
}

static int
networkAddMasqueradingIptablesRules(virConnectPtr conn,
                      struct network_driver *driver,
                      virNetworkObjPtr network) {
    int err;
    /* allow forwarding packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow forwarding from '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto masqerr1;
    }

    /* allow forwarding packets to the bridge interface if they are part of an existing connection */
    if ((err = iptablesAddForwardAllowRelatedIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow forwarding to '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto masqerr2;
    }

    /* enable masquerading */
    if ((err = iptablesAddForwardMasquerade(driver->iptables,
                                            network->def->network,
                                            network->def->forwardDev))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to enable masquerading : %s\n"),
                         strerror(err));
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
networkAddRoutingIptablesRules(virConnectPtr conn,
                      struct network_driver *driver,
                      virNetworkObjPtr network) {
    int err;
    /* allow routing packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow routing from '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if ((err = iptablesAddForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow routing to '%s' : %s\n"),
                         network->def->bridge, strerror(err));
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
networkAddIptablesRules(virConnectPtr conn,
                      struct network_driver *driver,
                      virNetworkObjPtr network) {
    int err;

    if (!driver->iptables && !(driver->iptables = iptablesContextNew())) {
        networkReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for IP tables support"));
        return 0;
    }


    /* allow DHCP requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 67))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DHCP requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err1;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 67))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DHCP requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err2;
    }

    /* allow DNS requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 53))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DNS requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err3;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 53))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DNS requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err4;
    }


    /* Catch all rules to block forwarding to/from bridges */

    if ((err = iptablesAddForwardRejectOut(driver->iptables, network->def->bridge))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to block outbound traffic from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err5;
    }

    if ((err = iptablesAddForwardRejectIn(driver->iptables, network->def->bridge))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to block inbound traffic to '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err6;
    }

    /* Allow traffic between guests on the same bridge */
    if ((err = iptablesAddForwardAllowCross(driver->iptables, network->def->bridge))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow cross bridge traffic on '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err7;
    }


    /* If masquerading is enabled, set up the rules*/
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT &&
        !networkAddMasqueradingIptablesRules(conn, driver, network))
        goto err8;
    /* else if routing is enabled, set up the rules*/
    else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE &&
             !networkAddRoutingIptablesRules(conn, driver, network))
        goto err8;

    iptablesSaveRules(driver->iptables);

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
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        network->def->network,
                                        network->def->forwardDev);

        if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT)
            iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                                network->def->network,
                                                network->def->bridge,
                                                network->def->forwardDev);
        else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE)
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
    iptablesSaveRules(driver->iptables);
}

static int
networkEnableIpForwarding(void)
{
#define PROC_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

    int fd, ret;

    if ((fd = open(PROC_IP_FORWARD, O_WRONLY|O_TRUNC)) == -1)
        return 0;

    if (safewrite(fd, "1\n", 2) < 0)
        ret = 0;

    close (fd);

    return 1;

#undef PROC_IP_FORWARD
}

static int networkStartNetworkDaemon(virConnectPtr conn,
                                   struct network_driver *driver,
                                   virNetworkObjPtr network) {
    int err;

    if (virNetworkIsActive(network)) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("network is already active"));
        return -1;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot initialize bridge support: %s"), strerror(err));
        return -1;
    }

    if ((err = brAddBridge(driver->brctl, &network->def->bridge))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create bridge '%s' : %s"),
                         network->def->bridge, strerror(err));
        return -1;
    }


    if (brSetForwardDelay(driver->brctl, network->def->bridge, network->def->delay) < 0)
        goto err_delbr;

    if (brSetEnableSTP(driver->brctl, network->def->bridge, network->def->stp ? 1 : 0) < 0)
        goto err_delbr;

    if (network->def->ipAddress &&
        (err = brSetInetAddress(driver->brctl, network->def->bridge, network->def->ipAddress))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot set IP address on bridge '%s' to '%s' : %s"),
                         network->def->bridge, network->def->ipAddress, strerror(err));
        goto err_delbr;
    }

    if (network->def->netmask &&
        (err = brSetInetNetmask(driver->brctl, network->def->bridge, network->def->netmask))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot set netmask on bridge '%s' to '%s' : %s"),
                         network->def->bridge, network->def->netmask, strerror(err));
        goto err_delbr;
    }

    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 1))) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to bring the bridge '%s' up : %s"),
                         network->def->bridge, strerror(err));
        goto err_delbr;
    }

    if (!networkAddIptablesRules(conn, driver, network))
        goto err_delbr1;

    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE &&
        !networkEnableIpForwarding()) {
        networkReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to enable IP forwarding : %s"), strerror(err));
        goto err_delbr2;
    }

    if (network->def->nranges &&
        dhcpStartDhcpDaemon(conn, network) < 0)
        goto err_delbr2;

    network->active = 1;

    return 0;

 err_delbr2:
    networkRemoveIptablesRules(driver, network);

 err_delbr1:
    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        networkLog(NETWORK_WARN, _("Failed to bring down bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

 err_delbr:
    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        networkLog(NETWORK_WARN, _("Failed to delete bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    return -1;
}


static int networkShutdownNetworkDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      struct network_driver *driver,
                                      virNetworkObjPtr network) {
    int err;

    networkLog(NETWORK_INFO, _("Shutting down network '%s'\n"), network->def->name);

    if (!virNetworkIsActive(network))
        return 0;

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    networkRemoveIptablesRules(driver, network);

    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        networkLog(NETWORK_WARN, _("Failed to bring down bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        networkLog(NETWORK_WARN, _("Failed to delete bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    if (network->dnsmasqPid > 0 &&
        waitpid(network->dnsmasqPid, NULL, WNOHANG) != network->dnsmasqPid) {
        kill(network->dnsmasqPid, SIGKILL);
        if (waitpid(network->dnsmasqPid, NULL, 0) != network->dnsmasqPid)
            networkLog(NETWORK_WARN,
                     "%s", _("Got unexpected pid for dnsmasq\n"));
    }

    network->dnsmasqPid = -1;
    network->active = 0;

    if (network->newDef) {
        virNetworkDefFree(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
    }

    if (!network->configFile)
        virNetworkRemoveInactive(&driver->networks,
                                 network);

    return 0;
}


static virNetworkPtr networkLookupByUUID(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const unsigned char *uuid) {
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, uuid);
    virNetworkPtr net;

    if (!network) {
        networkReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK,
                         "%s", _("no network with matching uuid"));
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}
static virNetworkPtr networkLookupByName(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const char *name) {
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByName(&driver->networks, name);
    virNetworkPtr net;

    if (!network) {
        networkReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK,
                         "%s", _("no network with matching name"));
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
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
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;

    for (i = 0 ; i < driver->networks.count ; i++)
        if (virNetworkIsActive(driver->networks.objs[i]))
            nactive++;

    return nactive;
}

static int networkListNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    int got = 0, i;

    for (i = 0 ; i < driver->networks.count && got < nnames ; i++) {
        if (virNetworkIsActive(driver->networks.objs[i])) {
            if (!(names[got] = strdup(driver->networks.objs[i]->def->name))) {
                networkReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                                   "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
            got++;
        }
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int networkNumDefinedNetworks(virConnectPtr conn) {
    int ninactive = 0, i;
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;

    for (i = 0 ; i < driver->networks.count ; i++)
        if (!virNetworkIsActive(driver->networks.objs[i]))
            ninactive++;

    return ninactive;
}

static int networkListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    int got = 0, i;

    for (i = 0 ; i < driver->networks.count && got < nnames ; i++) {
        if (!virNetworkIsActive(driver->networks.objs[i])) {
            if (!(names[got] = strdup(driver->networks.objs[i]->def->name))) {
                networkReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                                   "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
            got++;
        }
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static virNetworkPtr networkCreate(virConnectPtr conn, const char *xml) {
 struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network;
    virNetworkPtr net;

    if (!(def = virNetworkDefParseString(conn, xml)))
        return NULL;

    if (!(network = virNetworkAssignDef(conn,
                                        &driver->networks,
                                        def))) {
        virNetworkDefFree(def);
        return NULL;
    }

    if (networkStartNetworkDaemon(conn, driver, network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static virNetworkPtr networkDefine(virConnectPtr conn, const char *xml) {
    struct network_driver *driver = (struct network_driver *)conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network;

    if (!(def = virNetworkDefParseString(conn, xml)))
        return NULL;

    if (!(network = virNetworkAssignDef(conn,
                                        &driver->networks,
                                        def))) {
        virNetworkDefFree(def);
        return NULL;
    }

    if (virNetworkSaveConfig(conn,
                             driver->networkConfigDir,
                             driver->networkAutostartDir,
                             network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        return NULL;
    }

    return virGetNetwork(conn, network->def->name, network->def->uuid);
}

static int networkUndefine(virNetworkPtr net) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    if (virNetworkIsActive(network)) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("network is still active"));
        return -1;
    }

    if (virNetworkDeleteConfig(net->conn, network) < 0)
        return -1;

    virNetworkRemoveInactive(&driver->networks,
                             network);

    return 0;
}

static int networkStart(virNetworkPtr net) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    return networkStartNetworkDaemon(net->conn, driver, network);
}

static int networkDestroy(virNetworkPtr net) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);
    int ret;

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    ret = networkShutdownNetworkDaemon(net->conn, driver, network);

    return ret;
}

static char *networkDumpXML(virNetworkPtr net, int flags ATTRIBUTE_UNUSED) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return NULL;
    }

    return virNetworkDefFormat(net->conn, network->def);
}

static char *networkGetBridgeName(virNetworkPtr net) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);
    char *bridge;
    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching id"));
        return NULL;
    }

    bridge = strdup(network->def->bridge);
    if (!bridge) {
        networkReportError(net->conn, NULL, net, VIR_ERR_NO_MEMORY,
                 "%s", _("failed to allocate space for network bridge string"));
        return NULL;
    }
    return bridge;
}

static int networkGetAutostart(virNetworkPtr net,
                             int *autostart) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    *autostart = network->autostart;

    return 0;
}

static int networkSetAutostart(virNetworkPtr net,
                             int autostart) {
    struct network_driver *driver = (struct network_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    autostart = (autostart != 0);

    if (network->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = virFileMakePath(driver->networkAutostartDir))) {
            networkReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create autostart directory %s: %s"),
                             driver->networkAutostartDir, strerror(err));
            return -1;
        }

        if (symlink(network->configFile, network->autostartLink) < 0) {
            networkReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to create symlink '%s' to '%s': %s"),
                             network->autostartLink, network->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            networkReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to delete symlink '%s': %s"),
                             network->autostartLink, strerror(errno));
            return -1;
        }
    }

    network->autostart = autostart;

    return 0;
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
};

static virStateDriver networkStateDriver = {
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

