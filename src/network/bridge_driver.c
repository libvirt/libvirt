/*
 * bridge_driver.c: core driver methods for managing network
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
#include "buf.h"
#include "util.h"
#include "command.h"
#include "memory.h"
#include "uuid.h"
#include "iptables.h"
#include "bridge.h"
#include "logging.h"
#include "dnsmasq.h"
#include "util/network.h"
#include "configmake.h"

#define NETWORK_PID_DIR LOCALSTATEDIR "/run/libvirt/network"
#define NETWORK_STATE_DIR LOCALSTATEDIR "/lib/libvirt/network"

#define DNSMASQ_STATE_DIR LOCALSTATEDIR "/lib/libvirt/dnsmasq"
#define RADVD_STATE_DIR LOCALSTATEDIR "/lib/libvirt/radvd"

#define VIR_FROM_THIS VIR_FROM_NETWORK

#define networkReportError(code, ...)                                   \
    virReportErrorHelper(VIR_FROM_NETWORK, code, __FILE__,              \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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

static char *
networkDnsmasqLeaseFileNameDefault(const char *netname)
{
    char *leasefile;

    virAsprintf(&leasefile, DNSMASQ_STATE_DIR "/%s.leases",
                netname);
    return leasefile;
}

networkDnsmasqLeaseFileNameFunc networkDnsmasqLeaseFileName =
    networkDnsmasqLeaseFileNameDefault;

static char *
networkRadvdPidfileBasename(const char *netname)
{
    /* this is simple but we want to be sure it's consistently done */
    char *pidfilebase;

    virAsprintf(&pidfilebase, "%s-radvd", netname);
    return pidfilebase;
}

static char *
networkRadvdConfigFileName(const char *netname)
{
    char *configfile;

    virAsprintf(&configfile, RADVD_STATE_DIR "/%s-radvd.conf",
                netname);
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
         virAsprintf(&nicname, "%.*s%s%s",
                     /* space for last 3 chars + "-nic" + NULL */
                     (int)(IFNAMSIZ - (3 + sizeof(dummyNicSuffix))),
                     brname, brname + strlen(brname) - 3, dummyNicSuffix);
    } else {
         virAsprintf(&nicname, "%s%s", brname, dummyNicSuffix);
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
            brHasBridge(driver->brctl, obj->def->bridge) == 0) {
            obj->active = 1;

            /* Try and read dnsmasq/radvd pids if any */
            if (obj->def->ips && (obj->def->nips > 0)) {
                char *pidpath, *radvdpidbase;

                if (virFileReadPid(NETWORK_PID_DIR, obj->def->name,
                                   &obj->dnsmasqPid) == 0) {
                    /* Check that it's still alive */
                    if (kill(obj->dnsmasqPid, 0) != 0)
                        obj->dnsmasqPid = -1;
                    if (virAsprintf(&pidpath, "/proc/%d/exe", obj->dnsmasqPid) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                    if (virFileLinkPointsTo(pidpath, DNSMASQ) == 0)
                        obj->dnsmasqPid = -1;
                    VIR_FREE(pidpath);
                }

                if (!(radvdpidbase = networkRadvdPidfileBasename(obj->def->name))) {
                    virReportOOMError();
                    goto cleanup;
                }
                if (virFileReadPid(NETWORK_PID_DIR, radvdpidbase,
                                   &obj->radvdPid) == 0) {
                    /* Check that it's still alive */
                    if (kill(obj->radvdPid, 0) != 0)
                        obj->radvdPid = -1;
                    if (virAsprintf(&pidpath, "/proc/%d/exe", obj->radvdPid) < 0) {
                        virReportOOMError();
                        VIR_FREE(radvdpidbase);
                        goto cleanup;
                    }
                    if (virFileLinkPointsTo(pidpath, RADVD) == 0)
                        obj->radvdPid = -1;
                    VIR_FREE(pidpath);
                }
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
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONFDIR "/libvirt")) == NULL)
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
networkBuildDnsmasqHostsfile(dnsmasqContext *dctx,
                             virNetworkIpDefPtr ipdef,
                             virNetworkDNSDefPtr dnsdef)
{
    unsigned int i, j;

    for (i = 0; i < ipdef->nhosts; i++) {
        virNetworkDHCPHostDefPtr host = &(ipdef->hosts[i]);
        if ((host->mac) && VIR_SOCKET_HAS_ADDR(&host->ip))
            if (dnsmasqAddDhcpHost(dctx, host->mac, &host->ip, host->name) < 0)
                return -1;
    }

    if (dnsdef) {
        for (i = 0; i < dnsdef->nhosts; i++) {
            virNetworkDNSHostsDefPtr host = &(dnsdef->hosts[i]);
            if (VIR_SOCKET_HAS_ADDR(&host->ip)) {
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
        virCommandAddArgList(cmd, "--domain", network->def->domain, NULL);

    if (pidfile)
        virCommandAddArgPair(cmd, "--pid-file", pidfile);

    /* *no* conf file */
    virCommandAddArg(cmd, "--conf-file=");

    virCommandAddArgList(cmd,
                         "--except-interface", "lo",
                         NULL);

    /* If this is an isolated network, set the default route option
     * (3) to be empty to avoid setting a default route that's
     * guaranteed to not work.
     */
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NONE)
        virCommandAddArg(cmd, "--dhcp-option=3");

    if (network->def->dns != NULL) {
        virNetworkDNSDefPtr dns = network->def->dns;
        int i;

        for (i = 0; i < dns->ntxtrecords; i++) {
            char *record = NULL;
            if (virAsprintf(&record, "%s,%s",
                            dns->txtrecords[i].name,
                            dns->txtrecords[i].value) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            virCommandAddArgPair(cmd, "--txt-record", record);
            VIR_FREE(record);
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
        char *ipaddr = virSocketFormatAddr(&tmpipdef->address);
        if (!ipaddr)
            goto cleanup;
        virCommandAddArgList(cmd, "--listen-address", ipaddr, NULL);
        VIR_FREE(ipaddr);
    }

    if (ipdef) {
        for (r = 0 ; r < ipdef->nranges ; r++) {
            char *saddr = virSocketFormatAddr(&ipdef->ranges[r].start);
            if (!saddr)
                goto cleanup;
            char *eaddr = virSocketFormatAddr(&ipdef->ranges[r].end);
            if (!eaddr) {
                VIR_FREE(saddr);
                goto cleanup;
            }
            virCommandAddArg(cmd, "--dhcp-range");
            virCommandAddArgFormat(cmd, "%s,%s", saddr, eaddr);
            VIR_FREE(saddr);
            VIR_FREE(eaddr);
            nbleases += virSocketGetRange(&ipdef->ranges[r].start,
                                          &ipdef->ranges[r].end);
        }

        /*
         * For static-only DHCP, i.e. with no range but at least one host element,
         * we have to add a special --dhcp-range option to enable the service in
         * dnsmasq.
         */
        if (!ipdef->nranges && ipdef->nhosts) {
            char *bridgeaddr = virSocketFormatAddr(&ipdef->address);
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
            if (VIR_SOCKET_HAS_ADDR(&ipdef->bootserver)) {
                char *bootserver = virSocketFormatAddr(&ipdef->bootserver);

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
    int err;
    dnsmasqContext *dctx = NULL;

    if ((err = virFileMakePath(NETWORK_PID_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             NETWORK_PID_DIR);
        goto cleanup;
    }
    if ((err = virFileMakePath(NETWORK_STATE_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             NETWORK_STATE_DIR);
        goto cleanup;
    }

    if (!(pidfile = virFilePid(NETWORK_PID_DIR, network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }

    if ((err = virFileMakePath(DNSMASQ_STATE_DIR)) != 0) {
        virReportSystemError(err,
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

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    /*
     * There really is no race here - when dnsmasq daemonizes, its
     * leader process stays around until its child has actually
     * written its pidfile. So by time virCommandRun exits it has
     * waitpid'd and guaranteed the proess has started and written a
     * pid
     */

    if (virFileReadPid(NETWORK_PID_DIR, network->def->name,
                       &network->dnsmasqPid) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(pidfile);
    virCommandFree(cmd);
    dnsmasqContextFree(dctx);
    return ret;
}

static int
networkStartRadvd(virNetworkObjPtr network)
{
    char *pidfile = NULL;
    char *radvdpidbase = NULL;
    virBuffer configbuf = VIR_BUFFER_INITIALIZER;;
    char *configstr = NULL;
    char *configfile = NULL;
    virCommandPtr cmd = NULL;
    int ret = -1, err, ii;
    virNetworkIpDefPtr ipdef;

    network->radvdPid = -1;

    if (!virFileIsExecutable(RADVD)) {
        virReportSystemError(errno,
                             _("Cannot find %s - "
                               "Possibly the package isn't installed"),
                             RADVD);
        goto cleanup;
    }

    if ((err = virFileMakePath(NETWORK_PID_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             NETWORK_PID_DIR);
        goto cleanup;
    }
    if ((err = virFileMakePath(RADVD_STATE_DIR)) != 0) {
        virReportSystemError(err,
                             _("cannot create directory %s"),
                             RADVD_STATE_DIR);
        goto cleanup;
    }

    /* construct pidfile name */
    if (!(radvdpidbase = networkRadvdPidfileBasename(network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }
    if (!(pidfile = virFilePid(NETWORK_PID_DIR, radvdpidbase))) {
        virReportOOMError();
        goto cleanup;
    }

    /* create radvd config file appropriate for this network */
    virBufferAsprintf(&configbuf, "interface %s\n"
                      "{\n"
                      "  AdvSendAdvert on;\n"
                      "  AdvManagedFlag off;\n"
                      "  AdvOtherConfigFlag off;\n"
                      "\n",
                      network->def->bridge);
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET6, ii));
         ii++) {
        int prefix;
        char *netaddr;

        prefix = virNetworkIpDefPrefix(ipdef);
        if (prefix < 0) {
            networkReportError(VIR_ERR_INTERNAL_ERROR,
                               _("bridge  '%s' has an invalid prefix"),
                               network->def->bridge);
            goto cleanup;
        }
        if (!(netaddr = virSocketFormatAddr(&ipdef->address)))
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

    virBufferAddLit(&configbuf, "};\n");

    if (virBufferError(&configbuf)) {
        virReportOOMError();
        goto cleanup;
    }
    if (!(configstr = virBufferContentAndReset(&configbuf))) {
        virReportOOMError();
        goto cleanup;
    }

    /* construct the filename */
    if (!(configfile = networkRadvdConfigFileName(network->def->name))) {
        virReportOOMError();
        goto cleanup;
    }
    /* write the file */
    if (virFileWriteStr(configfile, configstr, 0600) < 0) {
        virReportSystemError(errno,
                             _("couldn't write radvd config file '%s'"),
                             configfile);
        goto cleanup;
    }

    /* prevent radvd from daemonizing itself with "--debug 1", and use
     * a dummy pidfile name - virCommand will create the pidfile we
     * want to use (this is necessary because radvd's internal
     * daemonization and pidfile creation causes a race, and the
     * virFileReadPid() below will fail if we use them).
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

    if (virFileReadPid(NETWORK_PID_DIR, radvdpidbase,
                       &network->radvdPid) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    VIR_FREE(configfile);
    VIR_FREE(configstr);
    virBufferFreeAndReset(&configbuf);
    VIR_FREE(radvdpidbase);
    VIR_FREE(pidfile);
    return ret;
}

static int
networkAddMasqueradingIptablesRules(struct network_driver *driver,
                                    virNetworkObjPtr network,
                                    virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix < 0) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid prefix or netmask for '%s'"),
                           network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets from the bridge interface */
    if (iptablesAddForwardAllowOut(driver->iptables,
                                   &ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   network->def->forwardDev) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
                                         network->def->forwardDev) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
                                     network->def->forwardDev,
                                     NULL) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable masquerading to '%s'"),
                           network->def->forwardDev ? network->def->forwardDev : NULL);
        goto masqerr3;
    }

    /* UDP with a source port restriction */
    if (iptablesAddForwardMasquerade(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     network->def->forwardDev,
                                     "udp") < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable UDP masquerading to '%s'"),
                           network->def->forwardDev ? network->def->forwardDev : NULL);
        goto masqerr4;
    }

    /* TCP with a source port restriction */
    if (iptablesAddForwardMasquerade(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     network->def->forwardDev,
                                     "tcp") < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable TCP masquerading to '%s'"),
                           network->def->forwardDev ? network->def->forwardDev : NULL);
        goto masqerr5;
    }

    return 0;

 masqerr5:
    iptablesRemoveForwardMasquerade(driver->iptables,
                                    &ipdef->address,
                                    prefix,
                                    network->def->forwardDev,
                                    "udp");
 masqerr4:
    iptablesRemoveForwardMasquerade(driver->iptables,
                                    &ipdef->address,
                                    prefix,
                                    network->def->forwardDev,
                                    NULL);
 masqerr3:
    iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        network->def->bridge,
                                        network->def->forwardDev);
 masqerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  &ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  network->def->forwardDev);
 masqerr1:
    return -1;
}

static void
networkRemoveMasqueradingIptablesRules(struct network_driver *driver,
                                       virNetworkObjPtr network,
                                       virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix >= 0) {
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        network->def->forwardDev,
                                        "tcp");
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        network->def->forwardDev,
                                        "udp");
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        &ipdef->address,
                                        prefix,
                                        network->def->forwardDev,
                                        NULL);

        iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                            &ipdef->address,
                                            prefix,
                                            network->def->bridge,
                                            network->def->forwardDev);
        iptablesRemoveForwardAllowOut(driver->iptables,
                                      &ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      network->def->forwardDev);
    }
}

static int
networkAddRoutingIptablesRules(struct network_driver *driver,
                               virNetworkObjPtr network,
                               virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix < 0) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid prefix or netmask for '%s'"),
                           network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets from the bridge interface */
    if (iptablesAddForwardAllowOut(driver->iptables,
                                   &ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   network->def->forwardDev) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to allow routing from '%s'"),
                           network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if (iptablesAddForwardAllowIn(driver->iptables,
                                  &ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  network->def->forwardDev) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
                                  network->def->forwardDev);
routeerr1:
    return -1;
}

static void
networkRemoveRoutingIptablesRules(struct network_driver *driver,
                                  virNetworkObjPtr network,
                                  virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix >= 0) {
        iptablesRemoveForwardAllowIn(driver->iptables,
                                     &ipdef->address,
                                     prefix,
                                     network->def->bridge,
                                     network->def->forwardDev);

        iptablesRemoveForwardAllowOut(driver->iptables,
                                      &ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      network->def->forwardDev);
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
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add ip6tables rule to block outbound traffic from '%s'"),
                           network->def->bridge);
        goto err1;
    }

    if (iptablesAddForwardRejectIn(driver->iptables, AF_INET6,
                                   network->def->bridge) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add ip6tables rule to block inbound traffic to '%s'"),
                           network->def->bridge);
        goto err2;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(driver->iptables, AF_INET6,
                                     network->def->bridge) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add ip6tables rule to allow cross bridge traffic on '%s'"),
                           network->def->bridge);
        goto err3;
    }

    /* allow DNS over IPv6 */
    if (iptablesAddTcpInput(driver->iptables, AF_INET6,
                            network->def->bridge, 53) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add ip6tables rule to allow DNS requests from '%s'"),
                           network->def->bridge);
        goto err4;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET6,
                            network->def->bridge, 53) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to allow DHCP requests from '%s'"),
                           network->def->bridge);
        goto err1;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 67) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to allow DNS requests from '%s'"),
                           network->def->bridge);
        goto err3;
    }

    if (iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 53) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to allow DNS requests from '%s'"),
                           network->def->bridge);
        goto err4;
    }

    /* allow TFTP requests through to dnsmasq if necessary */
    if (ipv4def && ipv4def->tftproot &&
        iptablesAddUdpInput(driver->iptables, AF_INET,
                            network->def->bridge, 69) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to allow TFTP requests from '%s'"),
                           network->def->bridge);
        goto err5;
    }

    /* Catch all rules to block forwarding to/from bridges */

    if (iptablesAddForwardRejectOut(driver->iptables, AF_INET,
                                    network->def->bridge) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to block outbound traffic from '%s'"),
                           network->def->bridge);
        goto err6;
    }

    if (iptablesAddForwardRejectIn(driver->iptables, AF_INET,
                                   network->def->bridge) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to block inbound traffic to '%s'"),
                           network->def->bridge);
        goto err7;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(driver->iptables, AF_INET,
                                     network->def->bridge) < 0) {
        networkReportError(VIR_ERR_SYSTEM_ERROR,
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
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET))
            return networkAddMasqueradingIptablesRules(driver, network, ipdef);
        else if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET6))
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
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET))
            networkRemoveMasqueradingIptablesRules(driver, network, ipdef);
        else if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET6))
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
        virNetworkObjLock(driver->networks.objs[i]);
        if (virNetworkObjIsActive(driver->networks.objs[i])) {
            networkRemoveIptablesRules(driver, driver->networks.objs[i]);
            if (networkAddIptablesRules(driver, driver->networks.objs[i]) < 0) {
                /* failed to add but already logged */
            }
        }
        virNetworkObjUnlock(driver->networks.objs[i]);
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

    if (virFileWriteStr(field, "1", 0) < 0) {
        virReportSystemError(errno,
                             _("cannot enable %s"), field);
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
                networkReportError(VIR_ERR_INTERNAL_ERROR,
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
networkAddAddrToBridge(struct network_driver *driver,
                       virNetworkObjPtr network,
                       virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);

    if (prefix < 0) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("bridge '%s' has an invalid netmask or IP address"),
                           network->def->bridge);
        return -1;
    }

    if (brAddInetAddress(driver->brctl, network->def->bridge,
                         &ipdef->address, prefix) < 0) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot set IP address on bridge '%s'"),
                           network->def->bridge);
        return -1;
    }

    return 0;
}

static int
networkStartNetworkDaemon(struct network_driver *driver,
                          virNetworkObjPtr network)
{
    int ii, err;
    bool v4present = false, v6present = false;
    virErrorPtr save_err = NULL;
    virNetworkIpDefPtr ipdef;
    char *macTapIfName = NULL;

    if (virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("network is already active"));
        return -1;
    }

    /* Check to see if any network IP collides with an existing route */
    if (networkCheckRouteCollision(network) < 0)
        return -1;

    /* Create and configure the bridge device */
    if ((err = brAddBridge(driver->brctl, network->def->bridge))) {
        virReportSystemError(err,
                             _("cannot create bridge '%s'"),
                             network->def->bridge);
        return -1;
    }

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
        if ((err = brAddTap(driver->brctl, network->def->bridge,
                            &macTapIfName, network->def->mac, 0, false, NULL))) {
            virReportSystemError(err,
                                 _("cannot create dummy tap device '%s' to set mac"
                                   " address on bridge '%s'"),
                                 macTapIfName, network->def->bridge);
            VIR_FREE(macTapIfName);
            goto err0;
        }
    }

    /* Set bridge options */
    if (brSetForwardDelay(driver->brctl, network->def->bridge,
                          network->def->delay)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot set forward delay on bridge '%s'"),
                           network->def->bridge);
        goto err1;
    }

    if (brSetEnableSTP(driver->brctl, network->def->bridge,
                       network->def->stp ? 1 : 0)) {
        networkReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot set STP '%s' on bridge '%s'"),
                           network->def->stp ? "on" : "off", network->def->bridge);
        goto err1;
    }

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
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET))
            v4present = true;
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET6))
            v6present = true;

        /* Add the IP address/netmask to the bridge */
        if (networkAddAddrToBridge(driver, network, ipdef) < 0) {
            goto err2;
        }
    }

    /* Bring up the bridge interface */
    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 1))) {
        virReportSystemError(err,
                             _("failed to bring the bridge '%s' up"),
                             network->def->bridge);
        goto err2;
    }

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

    /* Persist the live configuration now we have bridge info  */
    if (virNetworkSaveConfig(NETWORK_STATE_DIR, network->def) < 0) {
        goto err5;
    }

    VIR_FREE(macTapIfName);
    VIR_INFO("Starting up network '%s'", network->def->name);
    network->active = 1;

    return 0;

 err5:
    if (!save_err)
        save_err = virSaveLastError();

    if (network->radvdPid > 0) {
        kill(network->radvdPid, SIGTERM);
        network->radvdPid = -1;
    }

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
    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        char ebuf[1024];
        VIR_WARN("Failed to bring down bridge '%s' : %s",
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

 err2:
    if (!save_err)
        save_err = virSaveLastError();
    networkRemoveIptablesRules(driver, network);

 err1:
    if (!save_err)
        save_err = virSaveLastError();

    if ((err = brDeleteTap(driver->brctl, macTapIfName))) {
        char ebuf[1024];
        VIR_WARN("Failed to delete dummy tap device '%s' on bridge '%s' : %s",
                 macTapIfName, network->def->bridge,
                 virStrerror(err, ebuf, sizeof ebuf));
    }
    VIR_FREE(macTapIfName);

 err0:
    if (!save_err)
        save_err = virSaveLastError();
    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        char ebuf[1024];
        VIR_WARN("Failed to delete bridge '%s' : %s",
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    if (save_err) {
        virSetError(save_err);
        virFreeError(save_err);
    }
    return -1;
}


static int networkShutdownNetworkDaemon(struct network_driver *driver,
                                        virNetworkObjPtr network)
{
    int err;
    char *stateFile;
    char *macTapIfName;

    VIR_INFO("Shutting down network '%s'", network->def->name);

    if (!virNetworkObjIsActive(network))
        return 0;

    stateFile = virNetworkConfigFile(NETWORK_STATE_DIR, network->def->name);
    if (!stateFile)
        return -1;

    unlink(stateFile);
    VIR_FREE(stateFile);

    if (network->radvdPid > 0) {
        char *radvdpidbase;

        kill(network->radvdPid, SIGTERM);
        /* attempt to delete the pidfile we created */
        if (!(radvdpidbase = networkRadvdPidfileBasename(network->def->name))) {
            virReportOOMError();
        } else {
            virFileDeletePid(NETWORK_PID_DIR, radvdpidbase);
            VIR_FREE(radvdpidbase);
        }
    }

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    char ebuf[1024];

    if (network->def->mac_specified) {
        macTapIfName = networkBridgeDummyNicName(network->def->bridge);
        if (!macTapIfName) {
            virReportOOMError();
        } else {
            if ((err = brDeleteTap(driver->brctl, macTapIfName))) {
                VIR_WARN("Failed to delete dummy tap device '%s' on bridge '%s' : %s",
                         macTapIfName, network->def->bridge,
                         virStrerror(err, ebuf, sizeof ebuf));
            }
            VIR_FREE(macTapIfName);
        }
    }

    if ((err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        VIR_WARN("Failed to bring down bridge '%s' : %s",
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    networkRemoveIptablesRules(driver, network);

    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        VIR_WARN("Failed to delete bridge '%s' : %s",
                 network->def->bridge, virStrerror(err, ebuf, sizeof ebuf));
    }

    /* See if its still alive and really really kill it */
    if (network->dnsmasqPid > 0 &&
        (kill(network->dnsmasqPid, 0) == 0))
        kill(network->dnsmasqPid, SIGKILL);
    network->dnsmasqPid = -1;

    if (network->radvdPid > 0 &&
        (kill(network->radvdPid, 0) == 0))
        kill(network->radvdPid, SIGKILL);
    network->radvdPid = -1;

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

    if (virNetworkObjIsDuplicate(&driver->networks, def, 1) < 0)
        goto cleanup;

    if (virNetworkSetBridgeName(&driver->networks, def, 1))
        goto cleanup;

    virNetworkSetBridgeMacAddr(def);

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
    virNetworkObjPtr network = NULL;
    virNetworkPtr ret = NULL;
    int ii;
    dnsmasqContext* dctx = NULL;

    networkDriverLock(driver);

    if (!(def = virNetworkDefParseString(xml)))
        goto cleanup;

    if (virNetworkObjIsDuplicate(&driver->networks, def, 0) < 0)
        goto cleanup;

    if (virNetworkSetBridgeName(&driver->networks, def, 1))
        goto cleanup;

    virNetworkSetBridgeMacAddr(def);

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

    /* We only support dhcp on one IPv4 address per defined network */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, ii));
         ii++) {
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv4def) {
                    networkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       "%s", _("Multiple dhcp sections found. dhcp is supported only for a single IPv4 address on each network"));
                    goto cleanup;
                } else {
                    ipv4def = ipdef;
                }
            }
        }
    }
    if (ipv4def) {
        dctx = dnsmasqContextNew(network->def->name, DNSMASQ_STATE_DIR);
        if (dctx == NULL ||
            networkBuildDnsmasqHostsfile(dctx, ipv4def, network->def->dns) < 0 ||
            dnsmasqSave(dctx) < 0)
            goto cleanup;
    }

    VIR_INFO("Defining network '%s'", network->def->name);
    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
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
        networkReportError(VIR_ERR_NO_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_OPERATION_INVALID,
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
        if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts)
                dhcp_present = true;
        } else if (VIR_SOCKET_IS_FAMILY(&ipdef->address, AF_INET6)) {
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
        virFileDeletePid(NETWORK_PID_DIR, radvdpidbase);
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

static int networkStart(virNetworkPtr net) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    int ret = -1;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);

    if (!network) {
        networkReportError(VIR_ERR_NO_NETWORK,
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
        networkReportError(VIR_ERR_NO_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!virNetworkObjIsActive(network)) {
        networkReportError(VIR_ERR_OPERATION_INVALID,
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

static char *networkGetXMLDesc(virNetworkPtr net, int flags ATTRIBUTE_UNUSED) {
    struct network_driver *driver = net->conn->networkPrivateData;
    virNetworkObjPtr network;
    char *ret = NULL;

    networkDriverLock(driver);
    network = virNetworkFindByUUID(&driver->networks, net->uuid);
    networkDriverUnlock(driver);

    if (!network) {
        networkReportError(VIR_ERR_NO_NETWORK,
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
        networkReportError(VIR_ERR_NO_NETWORK,
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
        networkReportError(VIR_ERR_NO_NETWORK,
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
        networkReportError(VIR_ERR_NO_NETWORK,
                           "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    if (!network->persistent) {
        networkReportError(VIR_ERR_OPERATION_INVALID,
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
    .open = networkOpenNetwork, /* 0.2.0 */
    .close = networkCloseNetwork, /* 0.2.0 */
    .numOfNetworks = networkNumNetworks, /* 0.2.0 */
    .listNetworks = networkListNetworks, /* 0.2.0 */
    .numOfDefinedNetworks = networkNumDefinedNetworks, /* 0.2.0 */
    .listDefinedNetworks = networkListDefinedNetworks, /* 0.2.0 */
    .networkLookupByUUID = networkLookupByUUID, /* 0.2.0 */
    .networkLookupByName = networkLookupByName, /* 0.2.0 */
    .networkCreateXML = networkCreate, /* 0.2.0 */
    .networkDefineXML = networkDefine, /* 0.2.0 */
    .networkUndefine = networkUndefine, /* 0.2.0 */
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
