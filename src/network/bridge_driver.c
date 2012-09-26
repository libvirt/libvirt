/*
 * bridge_driver.c: core driver methods for managing network
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/poll.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
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
#include <net/if.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "bridge_driver.h"
#include "network_conf.h"
#include "device_conf.h"
#include "driver.h"
#include "buf.h"
#include "virpidfile.h"
#include "util.h"
#include "command.h"
#include "memory.h"
#include "uuid.h"
#include "iptables.h"
#include "logging.h"
#include "dnsmasq.h"
#include "configmake.h"
#include "virnetdev.h"
#include "pci.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"
#include "virnetdevvportprofile.h"
#include "virdbus.h"
#include "virfile.h"

#define NETWORK_PID_DIR LOCALSTATEDIR "/run/libvirt/network"
#define NETWORK_STATE_DIR LOCALSTATEDIR "/lib/libvirt/network"

#define DNSMASQ_STATE_DIR LOCALSTATEDIR "/lib/libvirt/dnsmasq"
#define RADVD_STATE_DIR LOCALSTATEDIR "/lib/libvirt/radvd"

#define VIR_FROM_THIS VIR_FROM_NETWORK

/* Main driver state */
struct network_driver {
    virMutex lock;

    virNetworkObjList networks;

    iptablesContext *iptables;
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

static int networkStartNetwork(struct network_driver *driver,
                               virNetworkObjPtr network);

static int networkShutdownNetwork(struct network_driver *driver,
                                  virNetworkObjPtr network);

static int networkStartNetworkVirtual(struct network_driver *driver,
                                     virNetworkObjPtr network);

static int networkShutdownNetworkVirtual(struct network_driver *driver,
                                        virNetworkObjPtr network);

static int networkStartNetworkExternal(struct network_driver *driver,
                                     virNetworkObjPtr network);

static int networkShutdownNetworkExternal(struct network_driver *driver,
                                        virNetworkObjPtr network);

static void networkReloadIptablesRules(struct network_driver *driver);
static void networkRefreshDaemons(struct network_driver *driver);

static struct network_driver *driverState = NULL;

static char *
networkDnsmasqLeaseFileNameDefault(const char *netname)
{
    char *leasefile;

    ignore_value(virAsprintf(&leasefile, DNSMASQ_STATE_DIR "/%s.leases",
                             netname));
    return leasefile;
}

networkDnsmasqLeaseFileNameFunc networkDnsmasqLeaseFileName =
    networkDnsmasqLeaseFileNameDefault;

static char *
networkRadvdPidfileBasename(const char *netname)
{
    /* this is simple but we want to be sure it's consistently done */
    char *pidfilebase;

    ignore_value(virAsprintf(&pidfilebase, "%s-radvd", netname));
    return pidfilebase;
}

static char *
networkRadvdConfigFileName(const char *netname)
{
    char *configfile;

    ignore_value(virAsprintf(&configfile, RADVD_STATE_DIR "/%s-radvd.conf",
                             netname));
    return configfile;
}

static char *
networkBridgeDummyNicName(const char *brname)
{
    static const char dummyNicSuffix[] = "-nic";
    char *nicname;

    if (strlen(brname) + sizeof(dummyNicSuffix) > IFNAMSIZ) {
        /* because the length of an ifname is limited to IFNAMSIZ-1
         * (usually 15), and we're adding 4 more characters, we must
         * truncate the original name to 11 to fit. In order to catch
         * a possible numeric ending (eg virbr0, virbr1, etc), we grab
         * the first 8 and last 3 characters of the string.
         */
        ignore_value(virAsprintf(&nicname, "%.*s%s%s",
                                 /* space for last 3 chars + "-nic" + NULL */
                                 (int)(IFNAMSIZ - (3 + sizeof(dummyNicSuffix))),
                                 brname, brname + strlen(brname) - 3,
                                 dummyNicSuffix));
    } else {
        ignore_value(virAsprintf(&nicname, "%s%s", brname, dummyNicSuffix));
    }
    return nicname;
}

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
            virNetDevExists(obj->def->bridge) == 1) {
            obj->active = 1;

            /* Try and read dnsmasq/radvd pids if any */
            if (obj->def->ips && (obj->def->nips > 0)) {
                char *radvdpidbase;

                ignore_value(virPidFileReadIfAlive(NETWORK_PID_DIR, obj->def->name,
                                                   &obj->dnsmasqPid, DNSMASQ));

                if (!(radvdpidbase = networkRadvdPidfileBasename(obj->def->name))) {
                    virReportOOMError();
                    goto cleanup;
                }
                ignore_value(virPidFileReadIfAlive(NETWORK_PID_DIR, radvdpidbase,
                                                   &obj->radvdPid, RADVD));
                VIR_FREE(radvdpidbase);
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
            !virNetworkObjIsActive(driver->networks.objs[i])) {
            if (networkStartNetwork(driver, driver->networks.objs[i]) < 0) {
            /* failed to start but already logged */
            }
        }
        virNetworkObjUnlock(driver->networks.objs[i]);
    }
}

#if HAVE_FIREWALLD
static DBusHandlerResult
firewalld_dbus_filter_bridge(DBusConnection *connection ATTRIBUTE_UNUSED,
                             DBusMessage *message, void *user_data) {
    struct network_driver *_driverState = user_data;

    if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS,
                               "NameOwnerChanged") ||
        dbus_message_is_signal(message, "org.fedoraproject.FirewallD1",
                               "Reloaded"))
    {
        VIR_DEBUG("Reload in bridge_driver because of firewalld.");
        networkReloadIptablesRules(_driverState);
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
#endif

/**
 * networkStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
networkStartup(int privileged) {
    char *base = NULL;
#ifdef HAVE_FIREWALLD
    DBusConnection *sysbus = NULL;
#endif

    if (VIR_ALLOC(driverState) < 0)
        goto error;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        goto error;
    }
    networkDriverLock(driverState);

    if (privileged) {
        if (virAsprintf(&driverState->logDir,
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONFDIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        char *userdir = virGetUserCacheDirectory();

        if (!userdir)
            goto error;

        if (virAsprintf(&driverState->logDir,
                        "%s/qemu/log", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);

        userdir = virGetUserConfigDirectory();
        if (virAsprintf(&base, "%s", userdir) == -1) {
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

    if (!(driverState->iptables = iptablesContextNew())) {
        goto out_of_memory;
    }


    if (virNetworkLoadAllConfigs(&driverState->networks,
                                 driverState->networkConfigDir,
                                 driverState->networkAutostartDir) < 0)
        goto error;

    networkFindActiveConfigs(driverState);
    networkReloadIptablesRules(driverState);
    networkRefreshDaemons(driverState);
    networkAutostartConfigs(driverState);

    networkDriverUnlock(driverState);

#ifdef HAVE_FIREWALLD
    if (!(sysbus = virDBusGetSystemBus())) {
        virErrorPtr err = virGetLastError();
        VIR_WARN("DBus not available, disabling firewalld support "
                 "in bridge_driver: %s", err->message);
    } else {
        /* add matches for
         * NameOwnerChanged on org.freedesktop.DBus for firewalld start/stop
         * Reloaded on org.fedoraproject.FirewallD1 for firewalld reload
         */
        dbus_bus_add_match(sysbus,
                           "type='signal'"
                           ",interface='"DBUS_INTERFACE_DBUS"'"
                           ",member='NameOwnerChanged'"
                           ",arg0='org.fedoraproject.FirewallD1'",
                           NULL);
        dbus_bus_add_match(sysbus,
                           "type='signal'"
                           ",interface='org.fedoraproject.FirewallD1'"
                           ",member='Reloaded'",
                           NULL);
        dbus_connection_add_filter(sysbus, firewalld_dbus_filter_bridge,
                                   driverState, NULL);
    }
#endif

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
    networkRefreshDaemons(driverState);
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

    if (driverState->iptables)
        iptablesContextFree(driverState->iptables);

    networkDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);

    VIR_FREE(driverState);

    return 0;
}


/* networkKillDaemon:
 *
 * kill the specified pid/name, and wait a bit to make sure it's dead.
 */
static int
networkKillDaemon(pid_t pid, const char *daemonName, const char *networkName)
{
    int ii, ret = -1;
    const char *signame = "TERM";

    /* send SIGTERM, then wait up to 3 seconds for the process to
     * disappear, send SIGKILL, then wait for up to another 2
     * seconds. If that fails, log a warning and continue, hoping
     * for the best.
     */
    for (ii = 0; ii < 25; ii++) {
        int signum = 0;
        if (ii == 0)
            signum = SIGTERM;
        else if (ii == 15) {
            signum = SIGKILL;
            signame = "KILL";
        }
        if (kill(pid, signum) < 0) {
            if (errno == ESRCH) {
                ret = 0;
            } else {
                char ebuf[1024];
                VIR_WARN("Failed to terminate %s process %d "
                         "for network '%s' with SIG%s: %s",
                         daemonName, pid, networkName, signame,
                         virStrerror(errno, ebuf, sizeof(ebuf)));
            }
            goto cleanup;
        }
        /* NB: since networks have no reference count like
         * domains, there is no safe way to unlock the network
         * object temporarily, and so we can't follow the
         * procedure used by the qemu driver of 1) unlock driver
         * 2) sleep, 3) add ref to object 4) unlock object, 5)
         * re-lock driver, 6) re-lock object. We may need to add
         * that functionality eventually, but for now this
         * function is rarely used and, at worst, leaving the
         * network driver locked during this loop of sleeps will
         * have the effect of holding up any other thread trying
         * to make modifications to a network for up to 5 seconds;
         * since modifications to networks are much less common
         * than modifications to domains, this seems a reasonable
         * tradeoff in exchange for less code disruption.
         */
        usleep(20 * 1000);
    }
    VIR_WARN("Timed out waiting after SIG%s to %s process %d "
             "(network '%s')",
             signame, daemonName, pid, networkName);
cleanup:
    return ret;
}

static int
networkBuildDnsmasqHostsfile(dnsmasqContext *dctx,
                             virNetworkIpDefPtr ipdef,
                             virNetworkDNSDefPtr dnsdef)
{
    unsigned int i, j;

    for (i = 0; i < ipdef->nhosts; i++) {
        virNetworkDHCPHostDefPtr host = &(ipdef->hosts[i]);
        if ((host->mac) && VIR_SOCKET_ADDR_VALID(&host->ip))
            if (dnsmasqAddDhcpHost(dctx, host->mac, &host->ip, host->name) < 0)
                return -1;
    }

    if (dnsdef) {
        for (i = 0; i < dnsdef->nhosts; i++) {
            virNetworkDNSHostsDefPtr host = &(dnsdef->hosts[i]);
            if (VIR_SOCKET_ADDR_VALID(&host->ip)) {
                for (j = 0; j < host->nnames; j++)
                    if (dnsmasqAddHost(dctx, &host->ip, host->names[j]) < 0)
                        return -1;
            }
        }
    }

    return 0;
}


static int
networkBuildDnsmasqArgv(virNetworkObjPtr network,
                        virNetworkIpDefPtr ipdef,
                        const char *pidfile,
                        virCommandPtr cmd,
                        dnsmasqContext *dctx)
{
    int r, ret = -1;
    int nbleases = 0;
    int ii;
    char *record = NULL;
    char *recordPort = NULL;
    char *recordWeight = NULL;
    char *recordPriority = NULL;
    virNetworkIpDefPtr tmpipdef;

    /*
     * NB, be careful about syntax for dnsmasq options in long format.
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
     * without reading the dnsmasq source :-( The manpage is not
     * very explicit on this.
     */

    /*
     * Needed to ensure dnsmasq uses same algorithm for processing
     * multiple namedriver entries in /etc/resolv.conf as GLibC.
     */
    virCommandAddArgList(cmd, "--strict-order", "--bind-interfaces", NULL);

    if (network->def->domain)
        virCommandAddArgPair(cmd, "--domain", network->def->domain);
    /* need to specify local even if no domain specified */
    virCommandAddArgFormat(cmd, "--local=/%s/",
                           network->def->domain ? network->def->domain : "");
    virCommandAddArg(cmd, "--domain-needed");

    if (pidfile)
        virCommandAddArgPair(cmd, "--pid-file", pidfile);

    /* *no* conf file */
    virCommandAddArg(cmd, "--conf-file=");

    virCommandAddArgList(cmd,
                         "--except-interface", "lo",
                         NULL);

    /* If this is an isolated network, set the default route option
     * (3) to be empty to avoid setting a default route that's
     * guaranteed to not work, and set --no-resolv so that no dns
     * requests are forwarded on to the dns server listed in the
     * host's /etc/resolv.conf (since this could be used as a channel
     * to build a connection to the outside).
     */
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NONE) {
        virCommandAddArgList(cmd, "--dhcp-option=3",
                             "--no-resolv", NULL);
    }

    if (network->def->dns != NULL) {
        virNetworkDNSDefPtr dns = network->def->dns;
        int i;

        for (i = 0; i < dns->ntxtrecords; i++) {
            virCommandAddArgFormat(cmd, "--txt-record=%s,%s",
                                   dns->txtrecords[i].name,
                                   dns->txtrecords[i].value);
        }

        for (i = 0; i < dns->nsrvrecords; i++) {
            if (dns->srvrecords[i].service && dns->srvrecords[i].protocol) {
                if (dns->srvrecords[i].port) {
                    if (virAsprintf(&recordPort, "%d", dns->srvrecords[i].port) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                }
                if (dns->srvrecords[i].priority) {
                    if (virAsprintf(&recordPriority, "%d", dns->srvrecords[i].priority) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                }
                if (dns->srvrecords[i].weight) {
                    if (virAsprintf(&recordWeight, "%d", dns->srvrecords[i].weight) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                }

                if (virAsprintf(&record, "%s.%s.%s,%s,%s,%s,%s",
                                dns->srvrecords[i].service,
                                dns->srvrecords[i].protocol,
                                dns->srvrecords[i].domain   ? dns->srvrecords[i].domain : "",
                                dns->srvrecords[i].target   ? dns->srvrecords[i].target : "",
                                recordPort                  ? recordPort                : "",
                                recordPriority              ? recordPriority            : "",
                                recordWeight                ? recordWeight              : "") < 0) {
                    virReportOOMError();
                    goto cleanup;
                }

                virCommandAddArgPair(cmd, "--srv-host", record);
                VIR_FREE(record);
                VIR_FREE(recordPort);
                VIR_FREE(recordWeight);
                VIR_FREE(recordPriority);
            }
        }
    }

    /*
     * --interface does not actually work with dnsmasq < 2.47,
     * due to DAD for ipv6 addresses on the interface.
     *
     * virCommandAddArgList(cmd, "--interface", ipdef->bridge, NULL);
     *
     * So listen on all defined IPv[46] addresses
     */
    for (ii = 0;
         (tmpipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        char *ipaddr = virSocketAddrFormat(&tmpipdef->address);
        if (!ipaddr)
            goto cleanup;
        virCommandAddArgList(cmd, "--listen-address", ipaddr, NULL);
        VIR_FREE(ipaddr);
    }

    if (ipdef) {
        for (r = 0 ; r < ipdef->nranges ; r++) {
            char *saddr = virSocketAddrFormat(&ipdef->ranges[r].start);
            if (!saddr)
                goto cleanup;
            char *eaddr = virSocketAddrFormat(&ipdef->ranges[r].end);
            if (!eaddr) {
                VIR_FREE(saddr);
                goto cleanup;
            }
            virCommandAddArg(cmd, "--dhcp-range");
            virCommandAddArgFormat(cmd, "%s,%s", saddr, eaddr);
            VIR_FREE(saddr);
            VIR_FREE(eaddr);
            nbleases += virSocketAddrGetRange(&ipdef->ranges[r].start,
                                              &ipdef->ranges[r].end);
        }

        /*
         * For static-only DHCP, i.e. with no range but at least one host element,
         * we have to add a special --dhcp-range option to enable the service in
         * dnsmasq.
         */
        if (!ipdef->nranges && ipdef->nhosts) {
            char *bridgeaddr = virSocketAddrFormat(&ipdef->address);
            if (!bridgeaddr)
                goto cleanup;
            virCommandAddArg(cmd, "--dhcp-range");
            virCommandAddArgFormat(cmd, "%s,static", bridgeaddr);
            VIR_FREE(bridgeaddr);
        }

        if (ipdef->nranges > 0) {
            char *leasefile = networkDnsmasqLeaseFileName(network->def->name);
            if (!leasefile)
                goto cleanup;
            virCommandAddArgFormat(cmd, "--dhcp-leasefile=%s", leasefile);
            VIR_FREE(leasefile);
            virCommandAddArgFormat(cmd, "--dhcp-lease-max=%d", nbleases);
        }

        if (ipdef->nranges || ipdef->nhosts)
            virCommandAddArg(cmd, "--dhcp-no-override");

        /* add domain to any non-qualified hostnames in /etc/hosts or addn-hosts */
        if (network->def->domain)
           virCommandAddArg(cmd, "--expand-hosts");

        if (networkBuildDnsmasqHostsfile(dctx, ipdef, network->def->dns) < 0)
            goto cleanup;

        if (dctx->hostsfile->nhosts)
            virCommandAddArgPair(cmd, "--dhcp-hostsfile",
                                 dctx->hostsfile->path);
        if (dctx->addnhostsfile->nhosts)
            virCommandAddArgPair(cmd, "--addn-hosts",
                                 dctx->addnhostsfile->path);

        if (ipdef->tftproot) {
            virCommandAddArgList(cmd, "--enable-tftp",
                                 "--tftp-root", ipdef->tftproot,
                                 NULL);
        }
        if (ipdef->bootfile) {
            virCommandAddArg(cmd, "--dhcp-boot");
            if (VIR_SOCKET_ADDR_VALID(&ipdef->bootserver)) {
                char *bootserver = virSocketAddrFormat(&ipdef->bootserver);

                if (!bootserver)
                    goto cleanup;
                virCommandAddArgFormat(cmd, "%s%s%s",
                                       ipdef->bootfile, ",,", bootserver);
                VIR_FREE(bootserver);
            } else {
                virCommandAddArg(cmd, ipdef->bootfile);
            }
        }
    }

    ret = 0;
cleanup:
    VIR_FREE(record);
    VIR_FREE(recordPort);
    VIR_FREE(recordWeight);
    VIR_FREE(recordPriority);
    return ret;
}

int
networkBuildDhcpDaemonCommandLine(virNetworkObjPtr network, virCommandPtr *cmdout,
                                  char *pidfile, dnsmasqContext *dctx)
{
    virCommandPtr cmd = NULL;
    int ret = -1, ii;
    virNetworkIpDefPtr ipdef;

    network->dnsmasqPid = -1;

    /* Look for first IPv4 address that has dhcp defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, ii));
         ii++) {
        if (ipdef->nranges || ipdef->nhosts)
            break;
    }
    /* If no IPv4 addresses had dhcp info, pick the first (if there were any). */
    if (!ipdef)
        ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, 0);

    /* If there are no IP addresses at all (v4 or v6), return now, since
     * there won't be any address for dnsmasq to listen on anyway.
     * If there are any addresses, even if no dhcp ranges or static entries,
     * we should continue and run dnsmasq, just for the DNS capabilities.
     */
    if (!virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, 0))
        return 0;

    cmd = virCommandNew(DNSMASQ);
    if (networkBuildDnsmasqArgv(network, ipdef, pidfile, cmd, dctx) < 0) {
        goto cleanup;
    }

    if (cmdout)
        *cmdout = cmd;
    ret = 0;
cleanup:
    if (ret < 0)
        virCommandFree(cmd);
    return ret;
}

static int
networkStartDhcpDaemon(virNetworkObjPtr network)
{
    virCommandPtr cmd = NULL;
    char *pidfile = NULL;
    int ret = -1;
    dnsmasqContext *dctx = NULL;

    if (!virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, 0)) {
        /* no IPv6 addresses, so we don't need to run radvd */
        ret = 0;
        goto cleanup;
    }

    if (virFileMakePath(NETWORK_PID_DIR) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %s"),
                             NETWORK_PID_DIR);
        goto cleanup;
    }
    if (virFileMakePath(NETWORK_STATE_DIR) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %s"),
                             NETWORK_STATE_DIR);
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(NETWORK_PID_DIR, network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileMakePath(DNSMASQ_STATE_DIR) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %s"),
                             DNSMASQ_STATE_DIR);
        goto cleanup;
    }

    dctx = dnsmasqContextNew(network->def->name, DNSMASQ_STATE_DIR);
    if (dctx == NULL)
        goto cleanup;

    ret = networkBuildDhcpDaemonCommandLine(network, &cmd, pidfile, dctx);
    if (ret < 0)
        goto cleanup;

    ret = dnsmasqSave(dctx);
    if (ret < 0)
        goto cleanup;

    ret = virCommandRun(cmd, NULL);
    if (ret < 0) {
        goto cleanup;
    }

    /*
     * There really is no race here - when dnsmasq daemonizes, its
     * leader process stays around until its child has actually
     * written its pidfile. So by time virCommandRun exits it has
     * waitpid'd and guaranteed the proess has started and written a
     * pid
     */

    ret = virPidFileRead(NETWORK_PID_DIR, network->def->name,
                         &network->dnsmasqPid);
    if (ret < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(pidfile);
    virCommandFree(cmd);
    dnsmasqContextFree(dctx);
    return ret;
}

/* networkRefreshDhcpDaemon:
 *  Update dnsmasq config files, then send a SIGHUP so that it rereads
 *  them.
 *
 *  Returns 0 on success, -1 on failure.
 */
static int
networkRefreshDhcpDaemon(virNetworkObjPtr network)
{
    int ret = -1, ii;
    virNetworkIpDefPtr ipdef;
    dnsmasqContext *dctx = NULL;

    /* if there's no running dnsmasq, just start it */
    if (network->dnsmasqPid <= 0 || (kill(network->dnsmasqPid, 0) < 0))
        return networkStartDhcpDaemon(network);

    /* Look for first IPv4 address that has dhcp defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, ii));
         ii++) {
        if (ipdef->nranges || ipdef->nhosts)
            break;
    }
    /* If no IPv4 addresses had dhcp info, pick the first (if there were any). */
    if (!ipdef)
        ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, 0);

    if (!ipdef) {
        /* no <ip> elements, so nothing to do */
        return 0;
    }

    if (!(dctx = dnsmasqContextNew(network->def->name, DNSMASQ_STATE_DIR)))
        goto cleanup;

    if (networkBuildDnsmasqHostsfile(dctx, ipdef, network->def->dns) < 0)
       goto cleanup;

    if ((ret = dnsmasqSave(dctx)) < 0)
        goto cleanup;

    ret = kill(network->dnsmasqPid, SIGHUP);
cleanup:
    dnsmasqContextFree(dctx);
    return ret;
}

/* networkRestartDhcpDaemon:
 *
 * kill and restart dnsmasq, in order to update any config that is on
 * the dnsmasq commandline (and any placed in separate config files).
 *
 *  Returns 0 on success, -1 on failure.
 */
static int
networkRestartDhcpDaemon(virNetworkObjPtr network)
{
    /* if there is a running dnsmasq, kill it */
    if (network->dnsmasqPid > 0) {
        networkKillDaemon(network->dnsmasqPid, "dnsmasq",
                          network->def->name);
        network->dnsmasqPid = -1;
    }
    /* now start dnsmasq if it should be started */
    return networkStartDhcpDaemon(network);
}

static int
networkRadvdConfContents(virNetworkObjPtr network, char **configstr)
{
    virBuffer configbuf = VIR_BUFFER_INITIALIZER;;
    int ret = -1, ii;
    virNetworkIpDefPtr ipdef;
    bool v6present = false;

    *configstr = NULL;

    /* create radvd config file appropriate for this network;
     * IgnoreIfMissing allows radvd to start even when the bridge is down
     */
    virBufferAsprintf(&configbuf, "interface %s\n"
                      "{\n"
                      "  AdvSendAdvert on;\n"
                      "  AdvManagedFlag off;\n"
                      "  AdvOtherConfigFlag off;\n"
                      "  IgnoreIfMissing on;\n"
                      "\n",
                      network->def->bridge);

    /* add a section for each IPv6 address in the config */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET6, ii));
         ii++) {
        int prefix;
        char *netaddr;

        v6present = true;
        prefix = virNetworkIpDefPrefix(ipdef);
        if (prefix < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("bridge '%s' has an invalid prefix"),
                           network->def->bridge);
            goto cleanup;
        }
        if (!(netaddr = virSocketAddrFormat(&ipdef->address)))
            goto cleanup;
        virBufferAsprintf(&configbuf,
                          "  prefix %s/%d\n"
                          "  {\n"
                          "    AdvOnLink on;\n"
                          "    AdvAutonomous on;\n"
                          "    AdvRouterAddr off;\n"
                          "  };\n",
                          netaddr, prefix);
        VIR_FREE(netaddr);
    }

    /* only create the string if we found at least one IPv6 address */
    if (v6present) {
        virBufferAddLit(&configbuf, "};\n");

        if (virBufferError(&configbuf)) {
            virReportOOMError();
            goto cleanup;
        }
        if (!(*configstr = virBufferContentAndReset(&configbuf))) {
            virReportOOMError();
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    virBufferFreeAndReset(&configbuf);
    return ret;
}

/* write file and return it's name (which must be freed by caller) */
static int
networkRadvdConfWrite(virNetworkObjPtr network, char **configFile)
{
    int ret = -1;
    char *configStr = NULL;
    char *myConfigFile = NULL;

    if (!configFile)
        configFile = &myConfigFile;

    *configFile = NULL;

    if (networkRadvdConfContents(network, &configStr) < 0)
        goto cleanup;

    if (!configStr) {
        ret = 0;
        goto cleanup;
    }

    /* construct the filename */
    if (!(*configFile = networkRadvdConfigFileName(network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }
    /* write the file */
    if (virFileWriteStr(*configFile, configStr, 0600) < 0) {
        virReportSystemError(errno,
                             _("couldn't write radvd config file '%s'"),
                             *configFile);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(configStr);
    VIR_FREE(myConfigFile);
    return ret;
}

static int
networkStartRadvd(virNetworkObjPtr network)
{
    char *pidfile = NULL;
    char *radvdpidbase = NULL;
    char *configfile = NULL;
    virCommandPtr cmd = NULL;
    int ret = -1;

    network->radvdPid = -1;

    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0)) {
        /* no IPv6 addresses, so we don't need to run radvd */
        ret = 0;
        goto cleanup;
    }

    if (!virFileIsExecutable(RADVD)) {
        virReportSystemError(errno,
                             _("Cannot find %s - "
                               "Possibly the package isn't installed"),
                             RADVD);
        goto cleanup;
    }

    if (virFileMakePath(NETWORK_PID_DIR) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %s"),
                             NETWORK_PID_DIR);
        goto cleanup;
    }
    if (virFileMakePath(RADVD_STATE_DIR) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %s"),
                             RADVD_STATE_DIR);
        goto cleanup;
    }

    /* construct pidfile name */
    if (!(radvdpidbase = networkRadvdPidfileBasename(network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }
    if (!(pidfile = virPidFileBuildPath(NETWORK_PID_DIR, radvdpidbase))) {
        virReportOOMError();
        goto cleanup;
    }

    if (networkRadvdConfWrite(network, &configfile) < 0)
        goto cleanup;

    /* prevent radvd from daemonizing itself with "--debug 1", and use
     * a dummy pidfile name - virCommand will create the pidfile we
     * want to use (this is necessary because radvd's internal
     * daemonization and pidfile creation causes a race, and the
     * virPidFileRead() below will fail if we use them).
     * Unfortunately, it isn't possible to tell radvd to not create
     * its own pidfile, so we just let it do so, with a slightly
     * different name. Unused, but harmless.
     */
    cmd = virCommandNewArgList(RADVD, "--debug", "1",
                               "--config", configfile,
                               "--pidfile", NULL);
    virCommandAddArgFormat(cmd, "%s-bin", pidfile);

    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virPidFileRead(NETWORK_PID_DIR, radvdpidbase, &network->radvdPid) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    VIR_FREE(configfile);
    VIR_FREE(radvdpidbase);
    VIR_FREE(pidfile);
    return ret;
}

static int
networkRefreshRadvd(virNetworkObjPtr network)
{
    /* if there's no running radvd, just start it */
    if (network->radvdPid <= 0 || (kill(network->radvdPid, 0) < 0))
        return networkStartRadvd(network);

    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0)) {
        /* no IPv6 addresses, so we don't need to run radvd */
        return 0;
    }

    if (networkRadvdConfWrite(network, NULL) < 0)
        return -1;

    return kill(network->radvdPid, SIGHUP);
}

#if 0
/* currently unused, so it causes a build error unless we #if it out */
static int
networkRestartRadvd(virNetworkObjPtr network)
{
    char *radvdpidbase;

    /* if there is a running radvd, kill it */
    if (network->radvdPid > 0) {
        /* essentially ignore errors from the following two functions,
         * since there's really no better recovery to be done than to
         * just push ahead (and that may be exactly what's needed).
         */
        if ((networkKillDaemon(network->dnsmasqPid, "radvd",
                               network->def->name) >= 0) &&
            ((radvdpidbase = networkRadvdPidfileBasename(network->def->name))
             != NULL)) {
            virPidFileDelete(NETWORK_PID_DIR, radvdpidbase);
            VIR_FREE(radvdpidbase);
        }
        network->radvdPid = -1;
    }
    /* now start radvd if it should be started */
    return networkStartRadvd(network);
}
#endif /* #if 0 */

/* SIGHUP/restart any dnsmasq or radvd daemons.
 * This should be called when libvirtd is restarted.
 */
static void
networkRefreshDaemons(struct network_driver *driver)
{
    unsigned int i;

    VIR_INFO("Refreshing network daemons");

    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjPtr network = driver->networks.objs[i];

        virNetworkObjLock(network);
        if (virNetworkObjIsActive(network) &&
            ((network->def->forwardType == VIR_NETWORK_FORWARD_NONE) ||
             (network->def->forwardType == VIR_NETWORK_FORWARD_NAT) ||
             (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE))) {
            /* Only the three L3 network types that are configured by
             * libvirt will have a dnsmasq or radvd daemon associated
             * with them.  Here we send a SIGHUP to an existing
             * dnsmasq and/or radvd, or restart them if they've
             * disappeared.
             */
            networkRefreshDhcpDaemon(network);
            networkRefreshRadvd(network);
        }
        virNetworkObjUnlock(network);
    }
}

static int
networkAddMasqueradingIptablesRules(struct network_driver *driver,
                                    virNetworkObjPtr network,
                                    virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
                       network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets from the bridge interface */
    if (iptablesAddForwardAllowOut(driver->iptables,
                                   &ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow forwarding from '%s'"),
                       network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets to the bridge interface if they are
     * part of an existing connection
     */
    if (iptablesAddForwardAllowRelatedIn(driver->iptables,
                                         &ipdef->address,
                                         prefix,
                                         network->def->bridge,
                                         forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow forwarding to '%s'"),
                       network->def->bridge);
        goto masqerr2;
    }

    /*
     * Enable masquerading.
     *
     * We need to end up with 3 rules in the table in this order
     *
     *  1. protocol=tcp with sport mapping restriction
     *  2. protocol=udp with sport mapping restriction
     *  3. generic any protocol
     *
     * The sport mappings are required, because default IPtables
     * MASQUERADE maintain port numbers unchanged where possible.
     *
     * NFS can be configured to only "trust" port numbers < 1023.
     *
     * Guests using NAT thus need to be prevented from having port
     * numbers < 1023, otherwise they can bypass the NFS "security"
     * check on the source port number.
     *
     * Since we use '--insert' to add rules to the header of the
     * chain, we actually need to add them in the reverse of the
     * order just mentioned !
     */

    /* First the generic masquerade rule for other protocols */
    if (iptablesAddForwardMasquerade(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     NULL) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       forwardIf ?
                       _("failed to add iptables rule to enable masquerading to %s") :
                       _("failed to add iptables rule to enable masquerading"),
                       forwardIf);
        goto masqerr3;
    }

    /* UDP with a source port restriction */
    if (iptablesAddForwardMasquerade(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     "udp") < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       forwardIf ?
                       _("failed to add iptables rule to enable UDP masquerading to %s") :
                       _("failed to add iptables rule to enable UDP masquerading"),
                       forwardIf);
        goto masqerr4;
    }

    /* TCP with a source port restriction */
    if (iptablesAddForwardMasquerade(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     "tcp") < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       forwardIf ?
                       _("failed to add iptables rule to enable TCP masquerading to %s") :
                       _("failed to add iptables rule to enable TCP masquerading"),
                       forwardIf);
        goto masqerr5;
    }

    return 0;

 masqerr5:
    iptablesRemoveForwardMasquerade(driver->iptables,
                                    &ipdef->address,
                                    prefix,
                                    forwardIf,
                                    "udp");
 masqerr4:
    iptablesRemoveForwardMasquerade(driver->iptables,
                                    &ipdef->address,
                                    prefix,
                                    forwardIf,
                                    NULL);
 masqerr3:
    iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        network->def->bridge,
                                        forwardIf);
 masqerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  &ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf);
 masqerr1:
    return -1;
}

static void
networkRemoveMasqueradingIptablesRules(struct network_driver *driver,
                                       virNetworkObjPtr network,
                                       virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix >= 0) {
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        "tcp");
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        "udp");
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        NULL);

        iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                            &ipdef->address,
                                            prefix,
                                            network->def->bridge,
                                            forwardIf);
        iptablesRemoveForwardAllowOut(driver->iptables,
                                      &ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      forwardIf);
    }
}

static int
networkAddRoutingIptablesRules(struct network_driver *driver,
                               virNetworkObjPtr network,
                               virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
                       network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets from the bridge interface */
    if (iptablesAddForwardAllowOut(driver->iptables,
                                   &ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow routing from '%s'"),
                       network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if (iptablesAddForwardAllowIn(driver->iptables,
                                  &ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow routing to '%s'"),
                       network->def->bridge);
        goto routeerr2;
    }

    return 0;

routeerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  &ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf);
routeerr1:
    return -1;
}

static void
networkRemoveRoutingIptablesRules(struct network_driver *driver,
                                  virNetworkObjPtr network,
                                  virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix >= 0) {
        iptablesRemoveForwardAllowIn(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     network->def->bridge,
                                     forwardIf);

        iptablesRemoveForwardAllowOut(driver->iptables,
                                      &ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      forwardIf);
    }
}

/* Add all once/network rules required for IPv6 (if any IPv6 addresses are defined) */
static int
networkAddGeneralIp6tablesRules(struct network_driver *driver,
                               virNetworkObjPtr network)
{

    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0))
        return 0;

    /* Catch all rules to block forwarding to/from bridges */

    if (iptablesAddForwardRejectOut(driver->iptables, AF_INET6,
                                    network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to block outbound traffic from '%s'"),
                       network->def->bridge);
        goto err1;
    }

    if (iptablesAddForwardRejectIn(driver->iptables, AF_INET6,
                                   network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to block inbound traffic to '%s'"),
                       network->def->bridge);
        goto err2;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(driver->iptables, AF_INET6,
                                     network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow cross bridge traffic on '%s'"),
                       network->def->bridge);
        goto err3;
    }

    /* allow DNS over IPv6 */
    if (iptablesAddTcpInput(driver->iptables, AF_INET6,
                            network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err4;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET6,
                            network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err5;
    }

    return 0;

    /* unwind in reverse order from the point of failure */
err5:
    iptablesRemoveTcpInput(driver->iptables, AF_INET6, network->def->bridge, 53);
err4:
    iptablesRemoveForwardAllowCross(driver->iptables, AF_INET6, network->def->bridge);
err3:
    iptablesRemoveForwardRejectIn(driver->iptables, AF_INET6, network->def->bridge);
err2:
    iptablesRemoveForwardRejectOut(driver->iptables, AF_INET6, network->def->bridge);
err1:
    return -1;
}

static void
networkRemoveGeneralIp6tablesRules(struct network_driver *driver,
                                  virNetworkObjPtr network)
{
    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0))
        return;

    iptablesRemoveForwardAllowCross(driver->iptables, AF_INET6, network->def->bridge);
    iptablesRemoveForwardRejectIn(driver->iptables, AF_INET6, network->def->bridge);
    iptablesRemoveForwardRejectOut(driver->iptables, AF_INET6, network->def->bridge);
}

static int
networkAddGeneralIptablesRules(struct network_driver *driver,
                               virNetworkObjPtr network)
{
    int ii;
    virNetworkIpDefPtr ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (ii = 0;
         (ipv4def = virNetworkDefGetIpByIndex(network->def, AF_INET, ii));
         ii++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    /* allow DHCP requests through to dnsmasq */

    if (iptablesAddTcpInput(driver->iptables, AF_INET,
                            network->def->bridge, 67) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DHCP requests from '%s'"),
                       network->def->bridge);
        goto err1;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 67) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DHCP requests from '%s'"),
                       network->def->bridge);
        goto err2;
    }

    /* If we are doing local DHCP service on this network, attempt to
     * add a rule that will fixup the checksum of DHCP response
     * packets back to the guests (but report failure without
     * aborting, since not all iptables implementations support it).
     */

    if (ipv4def && (ipv4def->nranges || ipv4def->nhosts) &&
        (iptablesAddOutputFixUdpChecksum(driver->iptables,
                                         network->def->bridge, 68) < 0)) {
        VIR_WARN("Could not add rule to fixup DHCP response checksums "
                 "on network '%s'.", network->def->name);
        VIR_WARN("May need to update iptables package & kernel to support CHECKSUM rule.");
    }

    /* allow DNS requests through to dnsmasq */
    if (iptablesAddTcpInput(driver->iptables, AF_INET,
                            network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err3;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err4;
    }

    /* allow TFTP requests through to dnsmasq if necessary */
    if (ipv4def && ipv4def->tftproot &&
        iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 69) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow TFTP requests from '%s'"),
                       network->def->bridge);
        goto err5;
    }

    /* Catch all rules to block forwarding to/from bridges */

    if (iptablesAddForwardRejectOut(driver->iptables, AF_INET,
                                    network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to block outbound traffic from '%s'"),
                       network->def->bridge);
        goto err6;
    }

    if (iptablesAddForwardRejectIn(driver->iptables, AF_INET,
                                   network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to block inbound traffic to '%s'"),
                       network->def->bridge);
        goto err7;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(driver->iptables, AF_INET,
                                     network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow cross bridge traffic on '%s'"),
                       network->def->bridge);
        goto err8;
    }

    /* add IPv6 general rules, if needed */
    if (networkAddGeneralIp6tablesRules(driver, network) < 0) {
        goto err9;
    }

    return 0;

    /* unwind in reverse order from the point of failure */
err9:
    iptablesRemoveForwardAllowCross(driver->iptables, AF_INET, network->def->bridge);
err8:
    iptablesRemoveForwardRejectIn(driver->iptables, AF_INET, network->def->bridge);
err7:
    iptablesRemoveForwardRejectOut(driver->iptables, AF_INET, network->def->bridge);
err6:
    if (ipv4def && ipv4def->tftproot) {
        iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 69);
    }
err5:
    iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 53);
err4:
    iptablesRemoveTcpInput(driver->iptables, AF_INET, network->def->bridge, 53);
err3:
    iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 67);
err2:
    iptablesRemoveTcpInput(driver->iptables, AF_INET, network->def->bridge, 67);
err1:
    return -1;
}

static void
networkRemoveGeneralIptablesRules(struct network_driver *driver,
                                  virNetworkObjPtr network)
{
    int ii;
    virNetworkIpDefPtr ipv4def;

    networkRemoveGeneralIp6tablesRules(driver, network);

    for (ii = 0;
         (ipv4def = virNetworkDefGetIpByIndex(network->def, AF_INET, ii));
         ii++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    iptablesRemoveForwardAllowCross(driver->iptables, AF_INET, network->def->bridge);
    iptablesRemoveForwardRejectIn(driver->iptables, AF_INET, network->def->bridge);
    iptablesRemoveForwardRejectOut(driver->iptables, AF_INET, network->def->bridge);
    if (ipv4def && ipv4def->tftproot) {
        iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 69);
    }
    iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 53);
    iptablesRemoveTcpInput(driver->iptables, AF_INET, network->def->bridge, 53);
    if (ipv4def && (ipv4def->nranges || ipv4def->nhosts)) {
        iptablesRemoveOutputFixUdpChecksum(driver->iptables,
                                           network->def->bridge, 68);
    }
    iptablesRemoveUdpInput(driver->iptables, AF_INET, network->def->bridge, 67);
    iptablesRemoveTcpInput(driver->iptables, AF_INET, network->def->bridge, 67);
}

static int
networkAddIpSpecificIptablesRules(struct network_driver *driver,
                                  virNetworkObjPtr network,
                                  virNetworkIpDefPtr ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            return networkAddMasqueradingIptablesRules(driver, network, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkAddRoutingIptablesRules(driver, network, ipdef);
    } else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {
        return networkAddRoutingIptablesRules(driver, network, ipdef);
    }
    return 0;
}

static void
networkRemoveIpSpecificIptablesRules(struct network_driver *driver,
                                     virNetworkObjPtr network,
                                     virNetworkIpDefPtr ipdef)
{
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            networkRemoveMasqueradingIptablesRules(driver, network, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            networkRemoveRoutingIptablesRules(driver, network, ipdef);
    } else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {
        networkRemoveRoutingIptablesRules(driver, network, ipdef);
    }
}

/* Add all rules for all ip addresses (and general rules) on a network */
static int
networkAddIptablesRules(struct network_driver *driver,
                        virNetworkObjPtr network)
{
    int ii;
    virNetworkIpDefPtr ipdef;

    /* Add "once per network" rules */
    if (networkAddGeneralIptablesRules(driver, network) < 0)
        return -1;

    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        /* Add address-specific iptables rules */
        if (networkAddIpSpecificIptablesRules(driver, network, ipdef) < 0) {
            goto err;
        }
    }
    return 0;

err:
    /* The final failed call to networkAddIpSpecificIptablesRules will
     * have removed any rules it created, but we need to remove those
     * added for previous IP addresses.
     */
    while ((--ii >= 0) &&
           (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii))) {
        networkRemoveIpSpecificIptablesRules(driver, network, ipdef);
    }
    networkRemoveGeneralIptablesRules(driver, network);
    return -1;
}

/* Remove all rules for all ip addresses (and general rules) on a network */
static void
networkRemoveIptablesRules(struct network_driver *driver,
                           virNetworkObjPtr network)
{
    int ii;
    virNetworkIpDefPtr ipdef;

    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        networkRemoveIpSpecificIptablesRules(driver, network, ipdef);
    }
    networkRemoveGeneralIptablesRules(driver, network);
}

static void
networkReloadIptablesRules(struct network_driver *driver)
{
    unsigned int i;

    VIR_INFO("Reloading iptables rules");

    for (i = 0 ; i < driver->networks.count ; i++) {
        virNetworkObjPtr network = driver->networks.objs[i];

        virNetworkObjLock(network);
        if (virNetworkObjIsActive(network) &&
            ((network->def->forwardType == VIR_NETWORK_FORWARD_NONE) ||
             (network->def->forwardType == VIR_NETWORK_FORWARD_NAT) ||
             (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE))) {
            /* Only the three L3 network types that are configured by libvirt
             * need to have iptables rules reloaded.
             */
            networkRemoveIptablesRules(driver, network);
            if (networkAddIptablesRules(driver, network) < 0) {
                /* failed to add but already logged */
            }
        }
        virNetworkObjUnlock(network);
    }
}

/* Enable IP Forwarding. Return 0 for success, -1 for failure. */
static int
networkEnableIpForwarding(bool enableIPv4, bool enableIPv6)
{
    int ret = 0;
    if (enableIPv4)
        ret = virFileWriteStr("/proc/sys/net/ipv4/ip_forward", "1\n", 0);
    if (enableIPv6 && ret == 0)
        ret = virFileWriteStr("/proc/sys/net/ipv6/conf/all/forwarding", "1\n", 0);
    return ret;
}

#define SYSCTL_PATH "/proc/sys"

static int
networkSetIPv6Sysctls(virNetworkObjPtr network)
{
    char *field = NULL;
    int ret = -1;

    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0)) {
        /* Only set disable_ipv6 if there are no ipv6 addresses defined for
         * the network.
         */
        if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/disable_ipv6",
                        network->def->bridge) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (access(field, W_OK) < 0 && errno == ENOENT) {
            VIR_DEBUG("ipv6 appears to already be disabled on %s",
                      network->def->bridge);
            ret = 0;
            goto cleanup;
        }

        if (virFileWriteStr(field, "1", 0) < 0) {
            virReportSystemError(errno,
                                 _("cannot write to %s to disable IPv6 on bridge %s"),
                                 field, network->def->bridge);
            goto cleanup;
        }
        VIR_FREE(field);
    }

    /* The rest of the ipv6 sysctl tunables should always be set,
     * whether or not we're using ipv6 on this bridge.
     */

    /* Prevent guests from hijacking the host network by sending out
     * their own router advertisements.
     */
    if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/accept_ra",
                    network->def->bridge) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileWriteStr(field, "0", 0) < 0) {
        virReportSystemError(errno,
                             _("cannot disable %s"), field);
        goto cleanup;
    }
    VIR_FREE(field);

    /* All interfaces used as a gateway (which is what this is, by
     * definition), must always have autoconf=0.
     */
    if (virAsprintf(&field, SYSCTL_PATH "/net/ipv6/conf/%s/autoconf",
                    network->def->bridge) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileWriteStr(field, "0", 0) < 0) {
        virReportSystemError(errno,
                             _("cannot disable %s"), field);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(field);
    return ret;
}

#define PROC_NET_ROUTE "/proc/net/route"

/* XXX: This function can be a lot more exhaustive, there are certainly
 *      other scenarios where we can ruin host network connectivity.
 * XXX: Using a proper library is preferred over parsing /proc
 */
static int
networkCheckRouteCollision(virNetworkObjPtr network)
{
    int ret = 0, len;
    char *cur, *buf = NULL;
    enum {MAX_ROUTE_SIZE = 1024*64};

    /* Read whole routing table into memory */
    if ((len = virFileReadAll(PROC_NET_ROUTE, MAX_ROUTE_SIZE, &buf)) < 0)
        goto out;

    /* Dropping the last character shouldn't hurt */
    if (len > 0)
        buf[len-1] = '\0';

    VIR_DEBUG("%s output:\n%s", PROC_NET_ROUTE, buf);

    if (!STRPREFIX (buf, "Iface"))
        goto out;

    /* First line is just headings, skip it */
    cur = strchr(buf, '\n');
    if (cur)
        cur++;

    while (cur) {
        char iface[17], dest[128], mask[128];
        unsigned int addr_val, mask_val;
        virNetworkIpDefPtr ipdef;
        int num, ii;

        /* NUL-terminate the line, so sscanf doesn't go beyond a newline.  */
        char *nl = strchr(cur, '\n');
        if (nl) {
            *nl++ = '\0';
        }

        num = sscanf(cur, "%16s %127s %*s %*s %*s %*s %*s %127s",
                     iface, dest, mask);
        cur = nl;

        if (num != 3) {
            VIR_DEBUG("Failed to parse %s", PROC_NET_ROUTE);
            continue;
        }

        if (virStrToLong_ui(dest, NULL, 16, &addr_val) < 0) {
            VIR_DEBUG("Failed to convert network address %s to uint", dest);
            continue;
        }

        if (virStrToLong_ui(mask, NULL, 16, &mask_val) < 0) {
            VIR_DEBUG("Failed to convert network mask %s to uint", mask);
            continue;
        }

        addr_val &= mask_val;

        for (ii = 0;
             (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, ii));
             ii++) {

            unsigned int net_dest;
            virSocketAddr netmask;

            if (virNetworkIpDefNetmask(ipdef, &netmask) < 0) {
                VIR_WARN("Failed to get netmask of '%s'",
                         network->def->bridge);
                continue;
            }

            net_dest = (ipdef->address.data.inet4.sin_addr.s_addr &
                        netmask.data.inet4.sin_addr.s_addr);

            if ((net_dest == addr_val) &&
                (netmask.data.inet4.sin_addr.s_addr == mask_val)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Network is already in use by interface %s"),
                               iface);
                ret = -1;
                goto out;
            }
        }
    }

out:
    VIR_FREE(buf);
    return ret;
}

static int
networkAddAddrToBridge(virNetworkObjPtr network,
                       virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("bridge '%s' has an invalid netmask or IP address"),
                       network->def->bridge);
        return -1;
    }

    if (virNetDevSetIPv4Address(network->def->bridge,
                                &ipdef->address, prefix) < 0)
        return -1;

    return 0;
}

static int
networkStartNetworkVirtual(struct network_driver *driver,
                          virNetworkObjPtr network)
{
    int ii;
    bool v4present = false, v6present = false;
    virErrorPtr save_err = NULL;
    virNetworkIpDefPtr ipdef;
    char *macTapIfName = NULL;
    int tapfd = -1;

    /* Check to see if any network IP collides with an existing route */
    if (networkCheckRouteCollision(network) < 0)
        return -1;

    /* Create and configure the bridge device */
    if (virNetDevBridgeCreate(network->def->bridge) < 0)
        return -1;

    if (network->def->mac_specified) {
        /* To set a mac for the bridge, we need to define a dummy tap
         * device, set its mac, then attach it to the bridge. As long
         * as its mac address is lower than any other interface that
         * gets attached, the bridge will always maintain this mac
         * address.
         */
        macTapIfName = networkBridgeDummyNicName(network->def->bridge);
        if (!macTapIfName) {
            virReportOOMError();
            goto err0;
        }
        /* Keep tun fd open and interface up to allow for IPv6 DAD to happen */
        if (virNetDevTapCreateInBridgePort(network->def->bridge,
                                           &macTapIfName, &network->def->mac,
                                           NULL, &tapfd, NULL, NULL,
                                           VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE |
                                           VIR_NETDEV_TAP_CREATE_IFUP |
                                           VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
            VIR_FREE(macTapIfName);
            goto err0;
        }
    }

    /* Set bridge options */

    /* delay is configured in seconds, but virNetDevBridgeSetSTPDelay
     * expects milliseconds
     */
    if (virNetDevBridgeSetSTPDelay(network->def->bridge,
                                   network->def->delay * 1000) < 0)
        goto err1;

    if (virNetDevBridgeSetSTP(network->def->bridge,
                              network->def->stp ? true : false) < 0)
        goto err1;

    /* Disable IPv6 on the bridge if there are no IPv6 addresses
     * defined, and set other IPv6 sysctl tunables appropriately.
     */
    if (networkSetIPv6Sysctls(network) < 0)
        goto err1;

    /* Add "once per network" rules */
    if (networkAddIptablesRules(driver, network) < 0)
        goto err1;

    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            v4present = true;
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            v6present = true;

        /* Add the IP address/netmask to the bridge */
        if (networkAddAddrToBridge(network, ipdef) < 0) {
            goto err2;
        }
    }

    /* Bring up the bridge interface */
    if (virNetDevSetOnline(network->def->bridge, 1) < 0)
        goto err2;

    /* If forwardType != NONE, turn on global IP forwarding */
    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE &&
        networkEnableIpForwarding(v4present, v6present) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to enable IP forwarding"));
        goto err3;
    }


    /* start dnsmasq if there are any IP addresses (v4 or v6) */
    if ((v4present || v6present) && networkStartDhcpDaemon(network) < 0)
        goto err3;

    /* start radvd if there are any ipv6 addresses */
    if (v6present && networkStartRadvd(network) < 0)
        goto err4;

    /* DAD has happened (dnsmasq waits for it), dnsmasq is now bound to the
     * bridge's IPv6 address, so we can now set the dummy tun down.
     */
    if (tapfd >= 0) {
        if (virNetDevSetOnline(macTapIfName, false) < 0)
            goto err4;
        VIR_FORCE_CLOSE(tapfd);
    }

    if (virNetDevBandwidthSet(network->def->bridge, network->def->bandwidth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set bandwidth limits on %s"),
                       network->def->bridge);
        goto err5;
    }

    VIR_FREE(macTapIfName);

    return 0;

 err5:
    virNetDevBandwidthClear(network->def->bridge);

 err4:
    if (!save_err)
        save_err = virSaveLastError();

    if (network->dnsmasqPid > 0) {
        kill(network->dnsmasqPid, SIGTERM);
        network->dnsmasqPid = -1;
    }

 err3:
    if (!save_err)
        save_err = virSaveLastError();
    ignore_value(virNetDevSetOnline(network->def->bridge, 0));

 err2:
    if (!save_err)
        save_err = virSaveLastError();
    networkRemoveIptablesRules(driver, network);

 err1:
    if (!save_err)
        save_err = virSaveLastError();

    if (macTapIfName) {
        VIR_FORCE_CLOSE(tapfd);
        ignore_value(virNetDevTapDelete(macTapIfName));
        VIR_FREE(macTapIfName);
    }

 err0:
    if (!save_err)
        save_err = virSaveLastError();
    ignore_value(virNetDevBridgeDelete(network->def->bridge));

    if (save_err) {
        virSetError(save_err);
        virFreeError(save_err);
    }
    return -1;
}

static int networkShutdownNetworkVirtual(struct network_driver *driver,
                                        virNetworkObjPtr network)
{
    virNetDevBandwidthClear(network->def->bridge);

    if (network->radvdPid > 0) {
        char *radvdpidbase;

        kill(network->radvdPid, SIGTERM);
        /* attempt to delete the pidfile we created */
        if (!(radvdpidbase = networkRadvdPidfileBasename(network->def->name))) {
            virReportOOMError();
        } else {
            virPidFileDelete(NETWORK_PID_DIR, radvdpidbase);
            VIR_FREE(radvdpidbase);
        }
    }

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    if (network->def->mac_specified) {
        char *macTapIfName = networkBridgeDummyNicName(network->def->bridge);
        if (!macTapIfName) {
            virReportOOMError();
        } else {
            ignore_value(virNetDevTapDelete(macTapIfName));
            VIR_FREE(macTapIfName);
        }
    }

    ignore_value(virNetDevSetOnline(network->def->bridge, 0));

    networkRemoveIptablesRules(driver, network);

    ignore_value(virNetDevBridgeDelete(network->def->bridge));

    /* See if its still alive and really really kill it */
    if (network->dnsmasqPid > 0 &&
        (kill(network->dnsmasqPid, 0) == 0))
        kill(network->dnsmasqPid, SIGKILL);
    network->dnsmasqPid = -1;

    if (network->radvdPid > 0 &&
        (kill(network->radvdPid, 0) == 0))
        kill(network->radvdPid, SIGKILL);
    network->radvdPid = -1;

    return 0;
}

static int
networkStartNetworkExternal(struct network_driver *driver ATTRIBUTE_UNUSED,
                            virNetworkObjPtr network ATTRIBUTE_UNUSED)
{
    /* put anything here that needs to be done each time a network of
     * type BRIDGE, PRIVATE, VEPA, HOSTDEV or PASSTHROUGH is started. On
     * failure, undo anything you've done, and return -1. On success
     * return 0.
     */
    return 0;
}

static int networkShutdownNetworkExternal(struct network_driver *driver ATTRIBUTE_UNUSED,
                                        virNetworkObjPtr network ATTRIBUTE_UNUSED)
{
    /* put anything here that needs to be done each time a network of
     * type BRIDGE, PRIVATE, VEPA, HOSTDEV or PASSTHROUGH is shutdown. On
     * failure, undo anything you've done, and return -1. On success
     * return 0.
     */
    return 0;
}

static int
networkStartNetwork(struct network_driver *driver,
                    virNetworkObjPtr network)
{
    int ret = 0;

    if (virNetworkObjIsActive(network)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("network is already active"));
        return -1;
    }

    if (virNetworkObjSetDefTransient(network, true) < 0)
        return -1;

    switch (network->def->forwardType) {

    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
        ret = networkStartNetworkVirtual(driver, network);
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        ret = networkStartNetworkExternal(driver, network);
        break;
    }

    if (ret < 0)
        return ret;

    /* Persist the live configuration now that anything autogenerated
     * is setup.
     */
    if ((ret = virNetworkSaveStatus(NETWORK_STATE_DIR, network)) < 0) {
        goto error;
    }

    VIR_INFO("Starting up network '%s'", network->def->name);
    network->active = 1;

error:
    if (ret < 0) {
        virErrorPtr save_err = virSaveLastError();
        int save_errno = errno;
        networkShutdownNetwork(driver, network);
        virSetError(save_err);
        virFreeError(save_err);
        errno = save_errno;
    }
    return ret;
}

static int networkShutdownNetwork(struct network_driver *driver,
                                        virNetworkObjPtr network)
{
    int ret = 0;
    char *stateFile;

    VIR_INFO("Shutting down network '%s'", network->def->name);

    if (!virNetworkObjIsActive(network))
        return 0;

    stateFile = virNetworkConfigFile(NETWORK_STATE_DIR, network->def->name);
    if (!stateFile)
        return -1;

    unlink(stateFile);
    VIR_FREE(stateFile);

    switch (network->def->forwardType) {

    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
        ret = networkShutdownNetworkVirtual(driver, network);
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        ret = networkShutdownNetworkExternal(driver, network);
        break;
    }

    network->active = 0;

    if (network->newDef) {
        virNetworkDefFree(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
    }

    return ret;
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
        virReportError(VIR_ERR_NO_NETWORK,
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
        virReportError(VIR_ERR_NO_NETWORK,
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
                                           unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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

static int
networkListAllNetworks(virConnectPtr conn,
                       virNetworkPtr **nets,
                       unsigned int flags)
{
    struct network_driver *driver = conn->networkPrivateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    networkDriverLock(driver);
    ret = virNetworkList(conn, driver->networks, nets, flags);
    networkDriverUnlock(driver);

    return ret;
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
        virReportError(VIR_ERR_NO_NETWORK, NULL);
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
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}


static int
networkValidate(virNetworkDefPtr def)
{
    int ii;
    bool vlanUsed, vlanAllowed;

    /* The only type of networks that currently support transparent
     * vlan configuration are those using hostdev sr-iov devices from
     * a pool, and those using an Open vSwitch bridge.
     */

    vlanAllowed = (def->forwardType == VIR_NETWORK_FORWARD_BRIDGE &&
                   def->virtPortProfile &&
                   def->virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH);

    vlanUsed = def->vlan.nTags > 0;
    for (ii = 0; ii < def->nPortGroups && !(vlanUsed && vlanAllowed); ii++) {
        if (def->portGroups[ii].vlan.nTags > 0)
            vlanUsed = true;
        if (def->forwardType == VIR_NETWORK_FORWARD_BRIDGE &&
            def->portGroups[ii].virtPortProfile &&
            (def->portGroups[ii].virtPortProfile->virtPortType
             == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)) {
            vlanAllowed = true;
        }
    }
    if (vlanUsed && !vlanAllowed) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("<vlan> element specified for network %s, "
                         "whose type doesn't support vlan configuration"),
                       def->name);
        return -1;
    }
    return 0;
}

static virNetworkPtr networkCreate(virConnectPtr conn, const char *xml) {
    struct network_driver *driver = conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network = NULL;
    virNetworkPtr ret = NULL;

    networkDriverLock(driver);

    if (!(def = virNetworkDefParseString(xml)))
        goto cleanup;

    if (virNetworkObjIsDuplicate(&driver->networks, def, 1) < 0)
        goto cleanup;

    /* Only the three L3 network types that are configured by libvirt
     * need to have a bridge device name / mac address provided
     */
    if (def->forwardType == VIR_NETWORK_FORWARD_NONE ||
        def->forwardType == VIR_NETWORK_FORWARD_NAT ||
        def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {

        if (virNetworkSetBridgeName(&driver->networks, def, 1))
            goto cleanup;

        virNetworkSetBridgeMacAddr(def);
    }

    if (networkValidate(def) < 0)
       goto cleanup;

    /* NB: "live" is false because this transient network hasn't yet
     * been started
     */
    if (!(network = virNetworkAssignDef(&driver->networks, def, false)))
        goto cleanup;
    def = NULL;

    if (networkStartNetwork(driver, network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        network = NULL;
        goto cleanup;
    }

    VIR_INFO("Creating network '%s'", network->def->name);
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
    virNetworkIpDefPtr ipdef, ipv4def = NULL;
    virNetworkDefPtr def;
    bool freeDef = true;
    virNetworkObjPtr network = NULL;
    virNetworkPtr ret = NULL;
    int ii;
    dnsmasqContext* dctx = NULL;

    networkDriverLock(driver);

    if (!(def = virNetworkDefParseString(xml)))
        goto cleanup;

    if (virNetworkObjIsDuplicate(&driver->networks, def, 0) < 0)
        goto cleanup;

    /* Only the three L3 network types that are configured by libvirt
     * need to have a bridge device name / mac address provided
     */
    if (def->forwardType == VIR_NETWORK_FORWARD_NONE ||
        def->forwardType == VIR_NETWORK_FORWARD_NAT ||
        def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {

        if (virNetworkSetBridgeName(&driver->networks, def, 1))
            goto cleanup;

        virNetworkSetBridgeMacAddr(def);
    }

    /* We only support dhcp on one IPv4 address per defined network */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(def, AF_UNSPEC, ii));
         ii++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv4def) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Multiple dhcp sections found. "
                                     "dhcp is supported only for a "
                                     "single IPv4 address on each network"));
                    goto cleanup;
                } else {
                    ipv4def = ipdef;
                }
            }
        }
    }

    if (networkValidate(def) < 0)
       goto cleanup;

    if (!(network = virNetworkAssignDef(&driver->networks, def, false)))
        goto cleanup;
    freeDef = false;

    network->persistent = 1;

    if (virNetworkSaveConfig(driver->networkConfigDir, def) < 0) {
        virNetworkRemoveInactive(&driver->networks, network);
        network = NULL;
        goto cleanup;
    }

    if (ipv4def) {
        dctx = dnsmasqContextNew(def->name, DNSMASQ_STATE_DIR);
        if (dctx == NULL ||
            networkBuildDnsmasqHostsfile(dctx, ipv4def, def->dns) < 0 ||
            dnsmasqSave(dctx) < 0)
            goto cleanup;
    }

    VIR_INFO("Defining network '%s'", def->name);
    ret = virGetNetwork(conn, def->name, def->uuid);

cleanup:
    if (freeDef)
       virNetworkDefFree(def);
    dnsmasqContextFree(dctx);
    if (network)
        virNetworkObjUnlock(network);
    networkDriverUnlock(driver);
    return ret;
}

static int networkUndefine(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    virNetworkIpDefPtr ipdef;
    bool dhcp_present = false, v6present = false;
    int ret = -1, ii;

    networkDriverLock(driver);

    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (virNetworkObjIsActive(network)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("network is still active"));
        goto cleanup;
    }

    if (virNetworkDeleteConfig(driver->networkConfigDir,
                               driver->networkAutostartDir,
                               network) < 0)
        goto cleanup;

    /* we only support dhcp on one IPv4 address per defined network */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts)
                dhcp_present = true;
        } else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6)) {
            v6present = true;
        }
    }

    if (dhcp_present) {
        char *leasefile;
        dnsmasqContext *dctx = dnsmasqContextNew(network->def->name, DNSMASQ_STATE_DIR);
        if (dctx == NULL)
            goto cleanup;

        dnsmasqDelete(dctx);
        dnsmasqContextFree(dctx);

        leasefile = networkDnsmasqLeaseFileName(network->def->name);
        if (!leasefile)
            goto cleanup;
        unlink(leasefile);
        VIR_FREE(leasefile);
    }

    if (v6present) {
        char *configfile = networkRadvdConfigFileName(network->def->name);

        if (!configfile) {
            virReportOOMError();
            goto cleanup;
        }
        unlink(configfile);
        VIR_FREE(configfile);

        char *radvdpidbase = networkRadvdPidfileBasename(network->def->name);

        if (!(radvdpidbase)) {
            virReportOOMError();
            goto cleanup;
        }
        virPidFileDelete(NETWORK_PID_DIR, radvdpidbase);
        VIR_FREE(radvdpidbase);

    }

    VIR_INFO("Undefining network '%s'", network->def->name);
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

static int
networkUpdate(virNetworkPtr net,
              unsigned int command,
              unsigned int section,
              int parentIndex,
              const char *xml,
              unsigned int flags)
{
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network = NULL;
    int isActive, ret = -1;

    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG,
                  -1);

    networkDriverLock(driver);

    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    /* VIR_NETWORK_UPDATE_AFFECT_CURRENT means "change LIVE if network
     * is active, else change CONFIG
    */
    isActive = virNetworkObjIsActive(network);
    if ((flags & (VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG)) ==
        VIR_NETWORK_UPDATE_AFFECT_CURRENT) {
        if (isActive)
            flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;
        else
            flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
    }

    /* update the network config in memory/on disk */
    if (virNetworkObjUpdate(network, command, section, parentIndex, xml, flags) < 0)
        goto cleanup;

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        /* save updated persistent config to disk */
        if (virNetworkSaveConfig(driver->networkConfigDir,
                                 virNetworkObjGetPersistentDef(network)) < 0) {
            goto cleanup;
        }
    }

    if (isActive && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE)) {
        /* rewrite dnsmasq host files, restart dnsmasq, update iptables
         * rules, etc, according to which section was modified. Note that
         * some sections require multiple actions, so a single switch
         * statement is inadequate.
         */
        if (section == VIR_NETWORK_SECTION_BRIDGE ||
            section == VIR_NETWORK_SECTION_DOMAIN ||
            section == VIR_NETWORK_SECTION_IP ||
            section == VIR_NETWORK_SECTION_IP_DHCP_RANGE) {
            /* these sections all change things on the dnsmasq commandline,
             * so we need to kill and restart dnsmasq.
             */
            if (networkRestartDhcpDaemon(network) < 0)
                goto cleanup;

        } else if (section == VIR_NETWORK_SECTION_IP_DHCP_HOST ||
                   section == VIR_NETWORK_SECTION_DNS_HOST ||
                   section == VIR_NETWORK_SECTION_DNS_TXT ||
                   section == VIR_NETWORK_SECTION_DNS_SRV) {
            /* these sections only change things in config files, so we
             * can just update the config files and send SIGHUP to
             * dnsmasq.
             */
            if (networkRefreshDhcpDaemon(network) < 0)
                goto cleanup;

        }

        if (section == VIR_NETWORK_SECTION_IP) {
            /* only a change in IP addresses will affect radvd, and all of radvd's
             * config is stored in the conf file which will be re-read with a SIGHUP.
             */
            if (networkRefreshRadvd(network) < 0)
                goto cleanup;
        }

        if ((section == VIR_NETWORK_SECTION_IP ||
             section == VIR_NETWORK_SECTION_FORWARD ||
             section == VIR_NETWORK_SECTION_FORWARD_INTERFACE) &&
           (network->def->forwardType == VIR_NETWORK_FORWARD_NONE ||
            network->def->forwardType == VIR_NETWORK_FORWARD_NAT ||
            network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE)) {
            /* these could affect the iptables rules */
            networkRemoveIptablesRules(driver, network);
            if (networkAddIptablesRules(driver, network) < 0)
                goto cleanup;

        }

        /* save current network state to disk */
        if ((ret = virNetworkSaveStatus(NETWORK_STATE_DIR, network)) < 0)
            goto cleanup;
    }
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
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = networkStartNetwork(driver, network);

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
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!virNetworkObjIsActive(network)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("network is not active"));
        goto cleanup;
    }

    ret = networkShutdownNetwork(driver, network);
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

static char *networkGetXMLDesc(virNetworkPtr net,
                               unsigned int flags)
{
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    virNetworkDefPtr def;
    char *ret = NULL;

    virCheckFlags(VIR_NETWORK_XML_INACTIVE, NULL);

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);

    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if ((flags & VIR_NETWORK_XML_INACTIVE) && network->newDef)
        def = network->newDef;
    else
        def = network->def;

    ret = virNetworkDefFormat(def, flags);

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
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching id"));
        goto cleanup;
    }

    if (!(network->def->bridge)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_NO_NETWORK,
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
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!network->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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
            if (virFileMakePath(driver->networkAutostartDir) < 0) {
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
    .open = networkOpenNetwork, /* 0.2.0 */
    .close = networkCloseNetwork, /* 0.2.0 */
    .numOfNetworks = networkNumNetworks, /* 0.2.0 */
    .listNetworks = networkListNetworks, /* 0.2.0 */
    .numOfDefinedNetworks = networkNumDefinedNetworks, /* 0.2.0 */
    .listDefinedNetworks = networkListDefinedNetworks, /* 0.2.0 */
    .listAllNetworks = networkListAllNetworks, /* 0.10.2 */
    .networkLookupByUUID = networkLookupByUUID, /* 0.2.0 */
    .networkLookupByName = networkLookupByName, /* 0.2.0 */
    .networkCreateXML = networkCreate, /* 0.2.0 */
    .networkDefineXML = networkDefine, /* 0.2.0 */
    .networkUndefine = networkUndefine, /* 0.2.0 */
    .networkUpdate = networkUpdate, /* 0.10.2 */
    .networkCreate = networkStart, /* 0.2.0 */
    .networkDestroy = networkDestroy, /* 0.2.0 */
    .networkGetXMLDesc = networkGetXMLDesc, /* 0.2.0 */
    .networkGetBridgeName = networkGetBridgeName, /* 0.2.0 */
    .networkGetAutostart = networkGetAutostart, /* 0.2.1 */
    .networkSetAutostart = networkSetAutostart, /* 0.2.1 */
    .networkIsActive = networkIsActive, /* 0.7.3 */
    .networkIsPersistent = networkIsPersistent, /* 0.7.3 */
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

/********************************************************/

/* Private API to deal with logical switch capabilities.
 * These functions are exported so that other parts of libvirt can
 * call them, but are not part of the public API and not in the
 * driver's function table. If we ever have more than one network
 * driver, we will need to present these functions via a second
 * "backend" function table.
 */

/* networkCreateInterfacePool:
 * @netdef: the original NetDef from the network
 *
 * Creates an implicit interface pool of VF's when a PF dev is given
 */
static int
networkCreateInterfacePool(virNetworkDefPtr netdef) {
    unsigned int num_virt_fns = 0;
    char **vfname = NULL;
    struct pci_config_address **virt_fns;
    int ret = -1, ii = 0;

    if ((virNetDevGetVirtualFunctions(netdef->forwardPfs->dev,
                                      &vfname, &virt_fns, &num_virt_fns)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get Virtual functions on %s"),
                       netdef->forwardPfs->dev);
        goto finish;
    }

    if (num_virt_fns == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No Vf's present on SRIOV PF %s"),
                       netdef->forwardPfs->dev);
       goto finish;
    }

    if ((VIR_ALLOC_N(netdef->forwardIfs, num_virt_fns)) < 0) {
        virReportOOMError();
        goto finish;
    }

    netdef->nForwardIfs = num_virt_fns;

    for (ii = 0; ii < netdef->nForwardIfs; ii++) {
        if ((netdef->forwardType == VIR_NETWORK_FORWARD_BRIDGE) ||
            (netdef->forwardType == VIR_NETWORK_FORWARD_PRIVATE) ||
            (netdef->forwardType == VIR_NETWORK_FORWARD_VEPA) ||
            (netdef->forwardType == VIR_NETWORK_FORWARD_PASSTHROUGH)) {
            netdef->forwardIfs[ii].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
            if(vfname[ii]) {
                netdef->forwardIfs[ii].device.dev = strdup(vfname[ii]);
                if (!netdef->forwardIfs[ii].device.dev) {
                    virReportOOMError();
                    goto finish;
                }
            }
            else {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Direct mode types require interface names"));
                goto finish;
            }
        }
        else if (netdef->forwardType == VIR_NETWORK_FORWARD_HOSTDEV) {
            /* VF's are always PCI devices */
            netdef->forwardIfs[ii].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI;
            netdef->forwardIfs[ii].device.pci.domain = virt_fns[ii]->domain;
            netdef->forwardIfs[ii].device.pci.bus = virt_fns[ii]->bus;
            netdef->forwardIfs[ii].device.pci.slot = virt_fns[ii]->slot;
            netdef->forwardIfs[ii].device.pci.function = virt_fns[ii]->function;
        }
    }

    ret = 0;
finish:
    for (ii = 0; ii < num_virt_fns; ii++) {
        VIR_FREE(vfname[ii]);
        VIR_FREE(virt_fns[ii]);
    }
    VIR_FREE(vfname);
    VIR_FREE(virt_fns);
    return ret;
}

/* networkAllocateActualDevice:
 * @iface: the original NetDef from the domain
 *
 * Looks up the network reference by iface, allocates a physical
 * device from that network (if appropriate), and returns with the
 * virDomainActualNetDef filled in accordingly. If there are no
 * changes to be made in the netdef, then just leave the actualdef
 * empty.
 *
 * Returns 0 on success, -1 on failure.
 */
int
networkAllocateActualDevice(virDomainNetDefPtr iface)
{
    struct network_driver *driver = driverState;
    enum virDomainNetType actualType = iface->type;
    virNetworkObjPtr network = NULL;
    virNetworkDefPtr netdef = NULL;
    virPortGroupDefPtr portgroup = NULL;
    virNetDevVPortProfilePtr virtport = iface->virtPortProfile;
    virNetDevVlanPtr vlan = NULL;
    virNetworkForwardIfDefPtr dev = NULL;
    int ii;
    int ret = -1;

    /* it's handy to have this initialized if we skip directly to validate */
    if (iface->vlan.nTags > 0)
        vlan = &iface->vlan;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
        goto validate;

    virDomainActualNetDefFree(iface->data.network.actual);
    iface->data.network.actual = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByName(&driver->networks, iface->data.network.name);
    networkDriverUnlock(driver);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"),
                       iface->data.network.name);
        goto error;
    }
    netdef = network->def;

    /* portgroup can be present for any type of network, in particular
     * for bandwidth information, so we need to check for that and
     * fill it in appropriately for all forward types.
    */
    portgroup = virPortGroupFindByName(netdef, iface->data.network.portgroup);

    /* If there is already interface-specific bandwidth, just use that
     * (already in NetDef). Otherwise, if there is bandwidth info in
     * the portgroup, fill that into the ActualDef.
     */
    if (portgroup && !iface->bandwidth) {
        if (!iface->data.network.actual
            && (VIR_ALLOC(iface->data.network.actual) < 0)) {
            virReportOOMError();
            goto error;
        }

        if (virNetDevBandwidthCopy(&iface->data.network.actual->bandwidth,
                                   portgroup->bandwidth) < 0)
            goto error;
    }

    if ((netdef->forwardType == VIR_NETWORK_FORWARD_NONE) ||
        (netdef->forwardType == VIR_NETWORK_FORWARD_NAT) ||
        (netdef->forwardType == VIR_NETWORK_FORWARD_ROUTE)) {
        /* for these forward types, the actual net type really *is*
         *NETWORK; we just keep the info from the portgroup in
         * iface->data.network.actual
        */
        if (iface->data.network.actual)
            iface->data.network.actual->type = VIR_DOMAIN_NET_TYPE_NETWORK;
    } else if ((netdef->forwardType == VIR_NETWORK_FORWARD_BRIDGE) &&
               netdef->bridge) {

        /* <forward type='bridge'/> <bridge name='xxx'/>
         * is VIR_DOMAIN_NET_TYPE_BRIDGE
         */

        if (!iface->data.network.actual
            && (VIR_ALLOC(iface->data.network.actual) < 0)) {
            virReportOOMError();
            goto error;
        }

        iface->data.network.actual->type = actualType = VIR_DOMAIN_NET_TYPE_BRIDGE;
        iface->data.network.actual->data.bridge.brname = strdup(netdef->bridge);
        if (!iface->data.network.actual->data.bridge.brname) {
            virReportOOMError();
            goto error;
        }

        /* merge virtualports from interface, network, and portgroup to
         * arrive at actual virtualport to use
         */
        if (virNetDevVPortProfileMerge3(&iface->data.network.actual->virtPortProfile,
                                        iface->virtPortProfile,
                                        netdef->virtPortProfile,
                                        portgroup
                                        ? portgroup->virtPortProfile : NULL) < 0) {
            goto error;
        }
        virtport = iface->data.network.actual->virtPortProfile;
        if (virtport) {
            /* only type='openvswitch' is allowed for bridges */
            if (virtport->virtPortType != VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("<virtualport type='%s'> not supported for network "
                                 "'%s' which uses a bridge device"),
                               virNetDevVPortTypeToString(virtport->virtPortType),
                               netdef->name);
                goto error;
            }
        }

    } else if (netdef->forwardType == VIR_NETWORK_FORWARD_HOSTDEV) {

        if (!iface->data.network.actual
            && (VIR_ALLOC(iface->data.network.actual) < 0)) {
            virReportOOMError();
            goto error;
        }

        iface->data.network.actual->type = actualType = VIR_DOMAIN_NET_TYPE_HOSTDEV;
        if (netdef->nForwardPfs > 0 && netdef->nForwardIfs <= 0 &&
            networkCreateInterfacePool(netdef) < 0) {
            goto error;
        }

        /* pick first dev with 0 connections */
        for (ii = 0; ii < netdef->nForwardIfs; ii++) {
            if (netdef->forwardIfs[ii].connections == 0) {
                dev = &netdef->forwardIfs[ii];
                break;
            }
        }
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' requires exclusive access "
                             "to interfaces, but none are available"),
                           netdef->name);
            goto error;
        }
        iface->data.network.actual->data.hostdev.def.parent.type = VIR_DOMAIN_DEVICE_NET;
        iface->data.network.actual->data.hostdev.def.parent.data.net = iface;
        iface->data.network.actual->data.hostdev.def.info = &iface->info;
        iface->data.network.actual->data.hostdev.def.mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        iface->data.network.actual->data.hostdev.def.managed = netdef->managed;
        iface->data.network.actual->data.hostdev.def.source.subsys.type = dev->type;
        iface->data.network.actual->data.hostdev.def.source.subsys.u.pci = dev->device.pci;

        /* merge virtualports from interface, network, and portgroup to
         * arrive at actual virtualport to use
         */
        if (virNetDevVPortProfileMerge3(&iface->data.network.actual->virtPortProfile,
                                        iface->virtPortProfile,
                                        netdef->virtPortProfile,
                                        portgroup
                                        ? portgroup->virtPortProfile : NULL) < 0) {
            goto error;
        }
        virtport = iface->data.network.actual->virtPortProfile;
        if (virtport) {
            /* make sure type is supported for hostdev connections */
            if (virtport->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBG &&
                virtport->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("<virtualport type='%s'> not supported for network "
                                 "'%s' which uses an SR-IOV Virtual Function "
                                 "via PCI passthrough"),
                               virNetDevVPortTypeToString(virtport->virtPortType),
                               netdef->name);
                goto error;
            }
        }

    } else if ((netdef->forwardType == VIR_NETWORK_FORWARD_BRIDGE) ||
               (netdef->forwardType == VIR_NETWORK_FORWARD_PRIVATE) ||
               (netdef->forwardType == VIR_NETWORK_FORWARD_VEPA) ||
               (netdef->forwardType == VIR_NETWORK_FORWARD_PASSTHROUGH)) {

        /* <forward type='bridge|private|vepa|passthrough'> are all
         * VIR_DOMAIN_NET_TYPE_DIRECT.
         */

        if (!iface->data.network.actual
            && (VIR_ALLOC(iface->data.network.actual) < 0)) {
            virReportOOMError();
            goto error;
        }

        /* Set type=direct and appropriate <source mode='xxx'/> */
        iface->data.network.actual->type = actualType = VIR_DOMAIN_NET_TYPE_DIRECT;
        switch (netdef->forwardType) {
        case VIR_NETWORK_FORWARD_BRIDGE:
            iface->data.network.actual->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_BRIDGE;
            break;
        case VIR_NETWORK_FORWARD_PRIVATE:
            iface->data.network.actual->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_PRIVATE;
            break;
        case VIR_NETWORK_FORWARD_VEPA:
            iface->data.network.actual->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_VEPA;
            break;
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
            iface->data.network.actual->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_PASSTHRU;
            break;
        }

        /* merge virtualports from interface, network, and portgroup to
         * arrive at actual virtualport to use
         */
        if (virNetDevVPortProfileMerge3(&iface->data.network.actual->virtPortProfile,
                                        iface->virtPortProfile,
                                        netdef->virtPortProfile,
                                        portgroup
                                        ? portgroup->virtPortProfile : NULL) < 0) {
            goto error;
        }
        virtport = iface->data.network.actual->virtPortProfile;
        if (virtport) {
            /* make sure type is supported for macvtap connections */
            if (virtport->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBG &&
                virtport->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("<virtualport type='%s'> not supported for network "
                                 "'%s' which uses a macvtap device"),
                               virNetDevVPortTypeToString(virtport->virtPortType),
                               netdef->name);
                goto error;
            }
        }

        /* If there is only a single device, just return it (caller will detect
         * any error if exclusive use is required but could not be acquired).
         */
        if ((netdef->nForwardIfs <= 0) && (netdef->nForwardPfs <= 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' uses a direct mode, but "
                             "has no forward dev and no interface pool"),
                           netdef->name);
            goto error;
        } else {
            /* pick an interface from the pool */

            if (netdef->nForwardPfs > 0 && netdef->nForwardIfs == 0 &&
                networkCreateInterfacePool(netdef) < 0) {
                goto error;
            }

            /* PASSTHROUGH mode, and PRIVATE Mode + 802.1Qbh both
             * require exclusive access to a device, so current
             * connections count must be 0.  Other modes can share, so
             * just search for the one with the lowest number of
             * connections.
             */
            if ((netdef->forwardType == VIR_NETWORK_FORWARD_PASSTHROUGH) ||
                ((netdef->forwardType == VIR_NETWORK_FORWARD_PRIVATE) &&
                 iface->data.network.actual->virtPortProfile &&
                 (iface->data.network.actual->virtPortProfile->virtPortType
                  == VIR_NETDEV_VPORT_PROFILE_8021QBH))) {

                /* pick first dev with 0 connections */
                for (ii = 0; ii < netdef->nForwardIfs; ii++) {
                    if (netdef->forwardIfs[ii].connections == 0) {
                        dev = &netdef->forwardIfs[ii];
                        break;
                    }
                }
            } else {
                /* pick least used dev */
                dev = &netdef->forwardIfs[0];
                for (ii = 1; ii < netdef->nForwardIfs; ii++) {
                    if (netdef->forwardIfs[ii].connections < dev->connections)
                        dev = &netdef->forwardIfs[ii];
                }
            }
            /* dev points at the physical device we want to use */
            if (!dev) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("network '%s' requires exclusive access "
                                 "to interfaces, but none are available"),
                               netdef->name);
                goto error;
            }
            iface->data.network.actual->data.direct.linkdev = strdup(dev->device.dev);
            if (!iface->data.network.actual->data.direct.linkdev) {
                virReportOOMError();
                goto error;
            }
        }
    }

    if (virNetDevVPortProfileCheckComplete(virtport, true) < 0)
        goto error;

    /* copy appropriate vlan info to actualNet */
    if (iface->vlan.nTags > 0)
        vlan = &iface->vlan;
    else if (portgroup && portgroup->vlan.nTags > 0)
        vlan = &portgroup->vlan;
    else if (netdef && netdef->vlan.nTags > 0)
        vlan = &netdef->vlan;

    if (virNetDevVlanCopy(&iface->data.network.actual->vlan, vlan) < 0)
        goto error;

validate:
    /* make sure that everything now specified for the device is
     * actually supported on this type of network. NB: network,
     * netdev, and iface->data.network.actual may all be NULL.
     */

    if (vlan) {
        /* vlan configuration via libvirt is only supported for
         * PCI Passthrough SR-IOV devices and openvswitch bridges.
         * otherwise log an error and fail
         */
        if (!(actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV ||
              (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE &&
               virtport && virtport->virtPortType
               == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH))) {
            if (netdef) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("an interface connecting to network '%s' "
                                 "is requesting a vlan tag, but that is not "
                                 "supported for this type of network"),
                               netdef->name);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("an interface of type '%s' "
                                 "is requesting a vlan tag, but that is not "
                                 "supported for this type of connection"),
                               virDomainNetTypeToString(iface->type));
            }
            goto error;
        }
    }

    if (dev) {
        /* we are now assured of success, so mark the allocation */
        dev->connections++;
        if (actualType != VIR_DOMAIN_NET_TYPE_HOSTDEV) {
            VIR_DEBUG("Using physical device %s, %d connections",
                      dev->device.dev, dev->connections);
        } else {
            VIR_DEBUG("Using physical device %04x:%02x:%02x.%x, connections %d",
                      dev->device.pci.domain, dev->device.pci.bus,
                      dev->device.pci.slot, dev->device.pci.function,
                      dev->connections);
        }
    }

    if (netdef) {
        netdef->connections++;
        VIR_DEBUG("Using network %s, %d connections",
                  netdef->name, netdef->connections);
    }
    ret = 0;

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;

error:
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        virDomainActualNetDefFree(iface->data.network.actual);
        iface->data.network.actual = NULL;
    }
    goto cleanup;
}

/* networkNotifyActualDevice:
 * @iface:  the domain's NetDef with an "actual" device already filled in.
 *
 * Called to notify the network driver when libvirtd is restarted and
 * finds an already running domain. If appropriate it will force an
 * allocation of the actual->direct.linkdev to get everything back in
 * order.
 *
 * Returns 0 on success, -1 on failure.
 */
int
networkNotifyActualDevice(virDomainNetDefPtr iface)
{
    struct network_driver *driver = driverState;
    enum virDomainNetType actualType = virDomainNetGetActualType(iface);
    virNetworkObjPtr network;
    virNetworkDefPtr netdef;
    virNetworkForwardIfDefPtr dev = NULL;
    int ii, ret = -1;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
       return 0;

    networkDriverLock(driver);
    network = virNetworkFindByName(&driver->networks, iface->data.network.name);
    networkDriverUnlock(driver);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"),
                       iface->data.network.name);
        goto error;
    }
    netdef = network->def;

    if (!iface->data.network.actual ||
        (actualType != VIR_DOMAIN_NET_TYPE_DIRECT &&
         actualType != VIR_DOMAIN_NET_TYPE_HOSTDEV)) {
        VIR_DEBUG("Nothing to claim from network %s", iface->data.network.name);
        goto success;
    }

    if (netdef->nForwardPfs > 0 && netdef->nForwardIfs == 0 &&
        networkCreateInterfacePool(netdef) < 0) {
        goto error;
    }
    if (netdef->nForwardIfs == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%s' uses a direct or hostdev mode, "
                         "but has no forward dev and no interface pool"),
                       netdef->name);
        goto error;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        const char *actualDev;

        actualDev = virDomainNetGetActualDirectDev(iface);
        if (!actualDev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("the interface uses a direct mode, "
                             "but has no source dev"));
            goto error;
        }

        /* find the matching interface and increment its connections */
        for (ii = 0; ii < netdef->nForwardIfs; ii++) {
            if (netdef->forwardIfs[ii].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
                STREQ(actualDev, netdef->forwardIfs[ii].device.dev)) {
                dev = &netdef->forwardIfs[ii];
                break;
            }
        }
        /* dev points at the physical device we want to use */
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have dev='%s' "
                             "in use by domain"),
                           netdef->name, actualDev);
            goto error;
        }

        /* PASSTHROUGH mode and PRIVATE Mode + 802.1Qbh both require
         * exclusive access to a device, so current connections count
         * must be 0 in those cases.
         */
        if ((dev->connections > 0) &&
            ((netdef->forwardType == VIR_NETWORK_FORWARD_PASSTHROUGH) ||
             ((netdef->forwardType == VIR_NETWORK_FORWARD_PRIVATE) &&
              iface->data.network.actual->virtPortProfile &&
              (iface->data.network.actual->virtPortProfile->virtPortType
               == VIR_NETDEV_VPORT_PROFILE_8021QBH)))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' claims dev='%s' is already in "
                             "use by a different domain"),
                           netdef->name, actualDev);
            goto error;
        }

        /* we are now assured of success, so mark the allocation */
        dev->connections++;
        VIR_DEBUG("Using physical device %s, connections %d",
                  dev->device.dev, dev->connections);

    }  else /* if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) */ {
        virDomainHostdevDefPtr hostdev;

        hostdev = virDomainNetGetActualHostdev(iface);
        if (!hostdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("the interface uses a hostdev mode, "
                             "but has no hostdev"));
            goto error;
        }

        /* find the matching interface and increment its connections */
        for (ii = 0; ii < netdef->nForwardIfs; ii++) {
            if (netdef->forwardIfs[ii].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI &&
                (virDevicePCIAddressEqual(hostdev->source.subsys.u.pci,
                                          netdef->forwardIfs[ii].device.pci) == 0)) {
                dev = &netdef->forwardIfs[ii];
                break;
            }
        }
        /* dev points at the physical device we want to use */
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have "
                             "PCI device %04x:%02x:%02x.%x in use by domain"),
                           netdef->name,
                           hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
                goto error;
        }

        /* PASSTHROUGH mode, PRIVATE Mode + 802.1Qbh, and hostdev (PCI
         * passthrough) all require exclusive access to a device, so
         * current connections count must be 0 in those cases.
         */
        if ((dev->connections > 0) &&
            netdef->forwardType == VIR_NETWORK_FORWARD_HOSTDEV) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' claims the PCI device at "
                             "domain=%d bus=%d slot=%d function=%d "
                             "is already in use by a different domain"),
                           netdef->name,
                           dev->device.pci.domain, dev->device.pci.bus,
                           dev->device.pci.slot, dev->device.pci.function);
            goto error;
        }

        /* we are now assured of success, so mark the allocation */
        dev->connections++;
        VIR_DEBUG("Using physical device %04x:%02x:%02x.%x, connections %d",
                  dev->device.pci.domain, dev->device.pci.bus,
                  dev->device.pci.slot, dev->device.pci.function,
                  dev->connections);
    }

success:
    netdef->connections++;
    VIR_DEBUG("Using network %s, %d connections",
              netdef->name, netdef->connections);
    ret = 0;
cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;

error:
    goto cleanup;
}


/* networkReleaseActualDevice:
 * @iface:  a domain's NetDef (interface definition)
 *
 * Given a domain <interface> element that previously had its <actual>
 * element filled in (and possibly a physical device allocated to it),
 * free up the physical device for use by someone else, and free the
 * virDomainActualNetDef.
 *
 * Returns 0 on success, -1 on failure.
 */
int
networkReleaseActualDevice(virDomainNetDefPtr iface)
{
    struct network_driver *driver = driverState;
    enum virDomainNetType actualType = virDomainNetGetActualType(iface);
    virNetworkObjPtr network;
    virNetworkDefPtr netdef;
    virNetworkForwardIfDefPtr dev = NULL;
    int ii, ret = -1;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
       return 0;

    networkDriverLock(driver);
    network = virNetworkFindByName(&driver->networks, iface->data.network.name);
    networkDriverUnlock(driver);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"),
                       iface->data.network.name);
        goto error;
    }
    netdef = network->def;

    if ((!iface->data.network.actual) ||
        ((actualType != VIR_DOMAIN_NET_TYPE_DIRECT) &&
         (actualType != VIR_DOMAIN_NET_TYPE_HOSTDEV))) {
        VIR_DEBUG("Nothing to release to network %s", iface->data.network.name);
        goto success;
    }

    if (netdef->nForwardIfs == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%s' uses a direct/hostdev mode, but "
                         "has no forward dev and no interface pool"),
                       netdef->name);
        goto error;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        const char *actualDev;

        actualDev = virDomainNetGetActualDirectDev(iface);
        if (!actualDev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("the interface uses a direct mode, "
                             "but has no source dev"));
            goto error;
        }

        for (ii = 0; ii < netdef->nForwardIfs; ii++) {
            if (netdef->forwardIfs[ii].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
                STREQ(actualDev, netdef->forwardIfs[ii].device.dev)) {
                dev = &netdef->forwardIfs[ii];
                break;
            }
        }

        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have dev='%s' "
                             "in use by domain"),
                           netdef->name, actualDev);
            goto error;
        }

        dev->connections--;
        VIR_DEBUG("Releasing physical device %s, connections %d",
                  dev->device.dev, dev->connections);

    } else /* if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) */ {
        virDomainHostdevDefPtr hostdev;

        hostdev = virDomainNetGetActualHostdev(iface);
        if (!hostdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("the interface uses a hostdev mode, but has no hostdev"));
            goto error;
        }

        for (ii = 0; ii < netdef->nForwardIfs; ii++) {
            if (netdef->forwardIfs[ii].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI &&
                (virDevicePCIAddressEqual(hostdev->source.subsys.u.pci,
                                          netdef->forwardIfs[ii].device.pci) == 0)) {
                dev = &netdef->forwardIfs[ii];
                break;
            }
        }

        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have "
                             "PCI device %04x:%02x:%02x.%x in use by domain"),
                           netdef->name,
                           hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
                goto error;
        }

        dev->connections--;
        VIR_DEBUG("Releasing physical device %04x:%02x:%02x.%x, connections %d",
                  dev->device.pci.domain, dev->device.pci.bus,
                  dev->device.pci.slot, dev->device.pci.function,
                  dev->connections);
   }

success:
    netdef->connections--;
    VIR_DEBUG("Releasing network %s, %d connections",
              netdef->name, netdef->connections);
    ret = 0;
cleanup:
    if (network)
        virNetworkObjUnlock(network);
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        virDomainActualNetDefFree(iface->data.network.actual);
        iface->data.network.actual = NULL;
    }
    return ret;

error:
    goto cleanup;
}

/*
 * networkGetNetworkAddress:
 * @netname: the name of a network
 * @netaddr: string representation of IP address for that network.
 *
 * Attempt to return an IP (v4) address associated with the named
 * network. If a libvirt virtual network, that will be provided in the
 * configuration. For host bridge and direct (macvtap) networks, we
 * must do an ioctl to learn the address.
 *
 * Note: This function returns the 1st IPv4 address it finds. It might
 * be useful if it was more flexible, but the current use (getting a
 * listen address for qemu's vnc/spice graphics server) can only use a
 * single address anyway.
 *
 * Returns 0 on success, and puts a string (which must be free'd by
 * the caller) into *netaddr. Returns -1 on failure or -2 if
 * completely unsupported.
 */
int
networkGetNetworkAddress(const char *netname, char **netaddr)
{
    int ret = -1;
    struct network_driver *driver = driverState;
    virNetworkObjPtr network;
    virNetworkDefPtr netdef;
    virNetworkIpDefPtr ipdef;
    virSocketAddr addr;
    virSocketAddrPtr addrptr = NULL;
    char *dev_name = NULL;

    *netaddr = NULL;
    networkDriverLock(driver);
    network = virNetworkFindByName(&driver->networks, netname);
    networkDriverUnlock(driver);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"),
                       netname);
        goto error;
    }
    netdef = network->def;

    switch (netdef->forwardType) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
        /* if there's an ipv4def, get it's address */
        ipdef = virNetworkDefGetIpByIndex(netdef, AF_INET, 0);
        if (!ipdef) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have an IPv4 address"),
                           netdef->name);
            break;
        }
        addrptr = &ipdef->address;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if ((dev_name = netdef->bridge))
            break;
        /*
         * fall through if netdef->bridge wasn't set, since this is
         * also a direct-mode interface.
         */
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        if ((netdef->nForwardIfs > 0) && netdef->forwardIfs)
            dev_name = netdef->forwardIfs[0].device.dev;

        if (!dev_name) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' has no associated interface or bridge"),
                           netdef->name);
        }
        break;
    }

    if (dev_name) {
        if (virNetDevGetIPv4Address(dev_name, &addr) < 0)
            goto error;
        addrptr = &addr;
    }

    if (!(addrptr &&
          (*netaddr = virSocketAddrFormat(addrptr)))) {
        goto error;
    }

    ret = 0;
cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;

error:
    goto cleanup;
}
