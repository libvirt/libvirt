/*
 * bridge_driver.c: core driver methods for managing network
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 */

#include <config.h>

#include <sys/types.h>
#include <poll.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef WITH_SYSCTLBYNAME
# include <sys/sysctl.h>
#endif

#include "virerror.h"
#include "datatypes.h"
#include "bridge_driver.h"
#include "bridge_driver_platform.h"
#include "driver.h"
#include "virbuffer.h"
#include "virpidfile.h"
#include "vircommand.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virlog.h"
#include "virdnsmasq.h"
#include "configmake.h"
#include "virnetdev.h"
#include "virnetdevip.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"
#include "virnetdevvportprofile.h"
#include "virpci.h"
#include "virgdbus.h"
#include "virfile.h"
#include "viraccessapicheck.h"
#include "network_event.h"
#include "virhook.h"
#include "virjson.h"
#include "virnetworkportdef.h"
#include "virutil.h"

#include "netdev_bandwidth_conf.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK
#define MAX_BRIDGE_ID 256

static virMutex bridgeNameValidateMutex = VIR_MUTEX_INITIALIZER;

/**
 * VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX:
 *
 * Macro providing the upper limit on the size of leases file
 */
#define VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX (32 * 1024 * 1024)

#define SYSCTL_PATH "/proc/sys"

VIR_LOG_INIT("network.bridge_driver");

static virNetworkDriverState *network_driver;


static virNetworkDriverState *
networkGetDriver(void)
{
    /* Maybe one day we can store @network_driver in the
     * connection object, but until then, it's just a global
     * variable which is returned. */
    return network_driver;
}


extern virXMLNamespace networkDnsmasqXMLNamespace;

typedef struct _networkDnsmasqXmlNsDef networkDnsmasqXmlNsDef;
struct _networkDnsmasqXmlNsDef {
    char **options;
};


static void
networkDnsmasqDefNamespaceFree(void *nsdata)
{
    networkDnsmasqXmlNsDef *def = nsdata;
    if (!def)
        return;

    g_strfreev(def->options);

    g_free(def);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(networkDnsmasqXmlNsDef, networkDnsmasqDefNamespaceFree);


static int
networkDnsmasqDefNamespaceParseOptions(networkDnsmasqXmlNsDef *nsdef,
                                       xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    size_t i;

    if ((nnodes = virXPathNodeSet("./dnsmasq:options/dnsmasq:option",
                                  ctxt, &nodes)) < 0)
        return -1;

    if (nnodes == 0)
        return 0;

    nsdef->options = g_new0(char *, nnodes + 1);

    for (i = 0; i < nnodes; i++) {
        if (!(nsdef->options[i] = virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No dnsmasq options value specified"));
            return -1;
        }
    }

    return 0;
}


static int
networkDnsmasqDefNamespaceParse(xmlXPathContextPtr ctxt,
                                void **data)
{
    g_autoptr(networkDnsmasqXmlNsDef) nsdata = g_new0(networkDnsmasqXmlNsDef, 1);

    if (networkDnsmasqDefNamespaceParseOptions(nsdata, ctxt))
        return -1;

    if (nsdata->options)
        *data = g_steal_pointer(&nsdata);

    return 0;
}


static int
networkDnsmasqDefNamespaceFormatXML(virBuffer *buf,
                                    void *nsdata)
{
    networkDnsmasqXmlNsDef *def = nsdata;
    GStrv n;

    if (!def->options)
        return 0;

    virBufferAddLit(buf, "<dnsmasq:options>\n");
    virBufferAdjustIndent(buf, 2);

    for (n = def->options; *n; n++) {
        virBufferEscapeString(buf, "<dnsmasq:option value='%s'/>\n", *n);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</dnsmasq:options>\n");

    return 0;
}


virXMLNamespace networkDnsmasqXMLNamespace = {
    .parse = networkDnsmasqDefNamespaceParse,
    .free = networkDnsmasqDefNamespaceFree,
    .format = networkDnsmasqDefNamespaceFormatXML,
    .prefix = "dnsmasq",
    .uri = "http://libvirt.org/schemas/network/dnsmasq/1.0",
};


virNetworkXMLOption *
networkDnsmasqCreateXMLConf(void)
{
    return virNetworkXMLOptionNew(&networkDnsmasqXMLNamespace);
}


static int
networkStateCleanup(void);

static int
networkStartNetwork(virNetworkDriverState *driver,
                    virNetworkObj *obj);

static int
networkShutdownNetwork(virNetworkDriverState *driver,
                       virNetworkObj *obj);

static void
networkReloadFirewallRules(virNetworkDriverState *driver,
                           bool startup,
                           bool force);

static void
networkRefreshDaemons(virNetworkDriverState *driver);

static int
networkPlugBandwidth(virNetworkObj *obj,
                     virMacAddr *mac,
                     virNetDevBandwidth *ifaceBand,
                     unsigned int *class_id);

static int
networkUnplugBandwidth(virNetworkObj *obj,
                       virNetDevBandwidth *ifaceBand,
                       unsigned int *class_id);

static void
networkNetworkObjTaint(virNetworkObj *obj,
                       virNetworkTaintFlags taint);


static virNetworkObj *
networkObjFromNetwork(virNetworkPtr net)
{
    virNetworkDriverState *driver = networkGetDriver();
    virNetworkObj *obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    obj = virNetworkObjFindByUUID(driver->networks, net->uuid);
    if (!obj) {
        virUUIDFormat(net->uuid, uuidstr);
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching uuid '%1$s' (%2$s)"),
                       uuidstr, net->name);
    }

    return obj;
}


static int
networkRunHook(virNetworkObj *obj,
               virNetworkPortDef *port,
               int op,
               int sub_op)
{
    virNetworkDef *def;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xml = NULL;
    int hookret;

    if (virHookPresent(VIR_HOOK_DRIVER_NETWORK)) {
        if (!obj) {
            VIR_DEBUG("Not running hook as @obj is NULL");
            return 0;
        }
        def = virNetworkObjGetDef(obj);

        virBufferAddLit(&buf, "<hookData>\n");
        virBufferAdjustIndent(&buf, 2);
        if (virNetworkDefFormatBuf(&buf, def, network_driver->xmlopt, 0) < 0)
            return -1;
        if (port && virNetworkPortDefFormatBuf(&buf, port) < 0)
            return -1;

        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</hookData>");

        xml = virBufferContentAndReset(&buf);
        hookret = virHookCall(VIR_HOOK_DRIVER_NETWORK, def->name,
                              op, sub_op, NULL, xml, NULL);

        /*
         * If the script raised an error, pass it to the callee.
         */
        if (hookret < 0)
            return -1;

        networkNetworkObjTaint(obj, VIR_NETWORK_TAINT_HOOK);
    }

    return 0;
}


static char *
networkDnsmasqLeaseFileNameDefault(virNetworkDriverConfig *cfg,
                                   const char *netname)
{
    return g_strdup_printf("%s/%s.leases", cfg->dnsmasqStateDir, netname);
}


static char *
networkDnsmasqLeaseFileNameCustom(virNetworkDriverConfig *cfg,
                                  const char *bridge)
{
    return g_strdup_printf("%s/%s.status", cfg->dnsmasqStateDir, bridge);
}


static char *
networkDnsmasqConfigFileName(virNetworkDriverConfig *cfg,
                             const char *netname)
{
    return g_strdup_printf("%s/%s.conf", cfg->dnsmasqStateDir, netname);
}


/* do needed cleanup steps and remove the network from the list */
static int
networkRemoveInactive(virNetworkDriverState *driver,
                      virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    g_autofree char *leasefile = NULL;
    g_autofree char *customleasefile = NULL;
    g_autofree char *configfile = NULL;
    g_autofree char *statusfile = NULL;
    g_autofree char *macMapFile = NULL;
    g_autoptr(dnsmasqContext) dctx = NULL;
    virNetworkDef *def = virNetworkObjGetPersistentDef(obj);

    /* remove the (possibly) existing dnsmasq files */
    if (!(dctx = dnsmasqContextNew(def->name,
                                   cfg->dnsmasqStateDir))) {
        return -1;
    }

    if (!(leasefile = networkDnsmasqLeaseFileNameDefault(cfg, def->name)))
        return -1;

    if (!(customleasefile = networkDnsmasqLeaseFileNameCustom(cfg, def->bridge)))
        return -1;

    if (!(configfile = networkDnsmasqConfigFileName(cfg, def->name)))
        return -1;

    if (!(statusfile = virNetworkConfigFile(cfg->stateDir, def->name)))
        return -1;

    if (!(macMapFile = virMacMapFileName(cfg->dnsmasqStateDir, def->bridge)))
        return -1;

    /* dnsmasq */
    dnsmasqDelete(dctx);
    unlink(leasefile);
    unlink(customleasefile);
    unlink(configfile);

    /* MAC map manager */
    unlink(macMapFile);

    /* remove status file */
    unlink(statusfile);

    /* remove the network definition */
    virNetworkObjRemoveInactive(driver->networks, obj);

    return 0;
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
        nicname = g_strdup_printf("%.*s%s%s",
                                  /* space for last 3 chars + "-nic" + NULL */
                                  (int)(IFNAMSIZ - (3 + sizeof(dummyNicSuffix))),
                                  brname, brname + strlen(brname) - 3,
                                  dummyNicSuffix);
    } else {
        nicname = g_strdup_printf("%s%s", brname, dummyNicSuffix);
    }
    return nicname;
}


static int
networkNotifyPort(virNetworkObj *obj,
                  virNetworkPortDef *port);

static bool
networkUpdatePort(virNetworkPortDef *port,
                  void *opaque)
{
    virNetworkObj *obj = opaque;

    networkNotifyPort(obj, port);

    return false;
}

static int
networkSetMacMap(virNetworkDriverConfig *cfg,
                 virNetworkObj *obj)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    g_autoptr(virMacMap) macmap = NULL;
    g_autofree char *macMapFile = NULL;

    if (!(macMapFile = virMacMapFileName(cfg->dnsmasqStateDir,
                                         def->bridge)))
        return -1;
    if (!(macmap = virMacMapNew(macMapFile)))
        return -1;

    virNetworkObjSetMacMap(obj, &macmap);
    return 0;
}

static int
networkUpdateState(virNetworkObj *obj,
                   void *opaque)
{
    virNetworkDef *def;
    virNetworkDriverState *driver = opaque;
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    g_autoptr(dnsmasqCaps) dnsmasq_caps = networkGetDnsmasqCaps(driver);
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);

    if (!virNetworkObjIsActive(obj))
        return 0;

    def = virNetworkObjGetDef(obj);

    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        /* If bridge doesn't exist, then mark it inactive */
        if (!(def->bridge && virNetDevExists(def->bridge) == 1))
            virNetworkObjSetActive(obj, false);

        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->bridge) {
            if (virNetDevExists(def->bridge) != 1)
                virNetworkObjSetActive(obj, false);
            break;
        }
        /* intentionally drop through to common case for all
         * macvtap networks (forward='bridge' with no bridge
         * device defined is macvtap using its 'bridge' mode)
         */
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        /* so far no extra checks */
        break;

    case VIR_NETWORK_FORWARD_HOSTDEV:
        /* so far no extra checks */
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return -1;
    }

    virNetworkObjPortForEach(obj, networkUpdatePort, obj);

    /* Try and read dnsmasq pids of active networks */
    if (virNetworkObjIsActive(obj) && def->ips && (def->nips > 0)) {
        const char *binpath = NULL;
        pid_t dnsmasqPid;

        if (networkSetMacMap(cfg, obj) < 0)
            return -1;

        if (dnsmasq_caps)
            binpath = dnsmasqCapsGetBinaryPath(dnsmasq_caps);

        ignore_value(virPidFileReadIfAlive(cfg->pidDir,
                                           def->name,
                                           &dnsmasqPid,
                                           binpath));
        virNetworkObjSetDnsmasqPid(obj, dnsmasqPid);
    }

    return 0;
}


static int
networkAutostartConfig(virNetworkObj *obj,
                       void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);
    virNetworkDriverState *driver = opaque;

    if (!virNetworkObjIsAutostart(obj))
        return 0;

    if (virNetworkObjIsActive(obj))
        return 0;

    if (networkStartNetwork(driver, obj) >= 0)
        return 0;

    return -1;
}


#ifdef WITH_FIREWALLD
static void
firewalld_dbus_signal_callback(GDBusConnection *connection G_GNUC_UNUSED,
                               const char *senderName G_GNUC_UNUSED,
                               const char *objectPath G_GNUC_UNUSED,
                               const char *interfaceName,
                               const char *signalName,
                               GVariant *parameters,
                               gpointer user_data)
{
    virNetworkDriverState *driver = user_data;
    bool reload = false;

    if (STREQ(interfaceName, "org.fedoraproject.FirewallD1") &&
        STREQ(signalName, "Reloaded")) {
        reload = true;
        VIR_DEBUG("Reload in bridge_driver because of 'Reloaded' signal");
    } else if (STREQ(interfaceName, "org.freedesktop.DBus") &&
               STREQ(signalName, "NameOwnerChanged")) {
        char *name = NULL;
        char *old_owner = NULL;
        char *new_owner = NULL;

        g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);

        if (new_owner && *new_owner) {
            VIR_DEBUG("Reload in bridge_driver because of 'NameOwnerChanged' signal, new owner is: '%s'",
                      new_owner);
            reload = true;
        }
    }

    if (reload)
        networkReloadFirewallRules(driver, false, true);
}
#endif


/**
 * networkStateInitialize:
 *
 * Initialization function for the QEMU daemon
 */
static int
networkStateInitialize(bool privileged,
                       const char *root,
                       bool monolithic G_GNUC_UNUSED,
                       virStateInhibitCallback callback G_GNUC_UNUSED,
                       void *opaque G_GNUC_UNUSED)
{
    virNetworkDriverConfig *cfg;
    bool autostart = true;
#ifdef WITH_FIREWALLD
    GDBusConnection *sysbus = NULL;
#endif

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    network_driver = g_new0(virNetworkDriverState, 1);

    network_driver->lockFD = -1;
    if (virMutexInit(&network_driver->lock) < 0) {
        g_clear_pointer(&network_driver, g_free);
        goto error;
    }

    network_driver->privileged = privileged;

    if (!(network_driver->xmlopt = networkDnsmasqCreateXMLConf()))
        goto error;

    if (!(network_driver->config = cfg = virNetworkDriverConfigNew(privileged)))
        goto error;

    if ((network_driver->lockFD =
         virPidFileAcquire(cfg->stateDir, "driver", getpid())) < 0)
        goto error;

    /* if this fails now, it will be retried later with networkDnsmasqCapsRefresh() */
    network_driver->dnsmasqCaps = dnsmasqCapsNewFromBinary();

    if (!(network_driver->networks = virNetworkObjListNew()))
        goto error;

    if (virNetworkObjLoadAllState(network_driver->networks,
                                  cfg->stateDir,
                                  network_driver->xmlopt) < 0)
        goto error;

    if (virNetworkObjLoadAllConfigs(network_driver->networks,
                                    cfg->networkConfigDir,
                                    cfg->networkAutostartDir,
                                    network_driver->xmlopt) < 0)
        goto error;

    /* Update the internal status of all allegedly active
     * networks according to external conditions on the host
     * (i.e. anything that isn't stored directly in each
     * network's state file). */
    virNetworkObjListForEach(network_driver->networks,
                             networkUpdateState,
                             network_driver);
    virNetworkObjListPrune(network_driver->networks,
                           VIR_CONNECT_LIST_NETWORKS_INACTIVE |
                           VIR_CONNECT_LIST_NETWORKS_TRANSIENT);
    networkReloadFirewallRules(network_driver, true, false);
    networkRefreshDaemons(network_driver);

    if (virDriverShouldAutostart(cfg->stateDir, &autostart) < 0)
        goto error;

    if (autostart) {
        virNetworkObjListForEach(network_driver->networks,
                                 networkAutostartConfig,
                                 network_driver);
    }

    network_driver->networkEventState = virObjectEventStateNew();

#ifdef WITH_FIREWALLD
    if (!(sysbus = virGDBusGetSystemBus())) {
        VIR_WARN("DBus not available, disabling firewalld support "
                 "in bridge_network_driver: %s", virGetLastErrorMessage());
    } else {
        g_dbus_connection_signal_subscribe(sysbus,
                                           NULL,
                                           "org.freedesktop.DBus",
                                           "NameOwnerChanged",
                                           NULL,
                                           "org.fedoraproject.FirewallD1",
                                           G_DBUS_SIGNAL_FLAGS_NONE,
                                           firewalld_dbus_signal_callback,
                                           network_driver,
                                           NULL);
        g_dbus_connection_signal_subscribe(sysbus,
                                           NULL,
                                           "org.fedoraproject.FirewallD1",
                                           "Reloaded",
                                           NULL,
                                           NULL,
                                           G_DBUS_SIGNAL_FLAGS_NONE,
                                           firewalld_dbus_signal_callback,
                                           network_driver,
                                           NULL);
    }
#endif

    return VIR_DRV_STATE_INIT_COMPLETE;


 error:
    networkStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}


/**
 * networkStateReload:
 *
 * Function to restart the QEMU daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
networkStateReload(void)
{
    g_autoptr(virNetworkDriverConfig) cfg = NULL;

    if (!network_driver)
        return 0;

    cfg = virNetworkDriverGetConfig(network_driver);

    virNetworkObjLoadAllState(network_driver->networks,
                              cfg->stateDir,
                              network_driver->xmlopt);
    virNetworkObjLoadAllConfigs(network_driver->networks,
                                cfg->networkConfigDir,
                                cfg->networkAutostartDir,
                                network_driver->xmlopt);
    networkReloadFirewallRules(network_driver, false, false);
    networkRefreshDaemons(network_driver);
    virNetworkObjListForEach(network_driver->networks,
                             networkAutostartConfig,
                             network_driver);
    return 0;
}


/**
 * networkStateCleanup:
 *
 * Shutdown the QEMU daemon, it will stop all active domains and networks
 */
static int
networkStateCleanup(void)
{
    if (!network_driver)
        return -1;

    virObjectUnref(network_driver->networkEventState);
    virObjectUnref(network_driver->xmlopt);

    /* free inactive networks */
    virObjectUnref(network_driver->networks);

    if (network_driver->lockFD != -1) {
        g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(network_driver);

        virPidFileRelease(cfg->stateDir, "driver",
                          network_driver->lockFD);
    }

    virObjectUnref(network_driver->config);
    virObjectUnref(network_driver->dnsmasqCaps);

    virMutexDestroy(&network_driver->lock);

    g_clear_pointer(&network_driver, g_free);

    return 0;
}


static virDrvOpenStatus
networkConnectOpen(virConnectPtr conn,
                   virConnectAuthPtr auth G_GNUC_UNUSED,
                   virConf *conf G_GNUC_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (network_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("network state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!virConnectValidateURIPath(conn->uri->path,
                                   "network",
                                   network_driver->privileged))
        return VIR_DRV_OPEN_ERROR;

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int networkConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}


static int networkConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int networkConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int networkConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static int
networkConnectSupportsFeature(virConnectPtr conn, int feature)
{
    int supported;

    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    if (virDriverFeatureIsGlobal(feature, &supported))
        return supported;

    switch ((virDrvFeature) feature) {
    case VIR_DRV_FEATURE_REMOTE:
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    case VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER:
    case VIR_DRV_FEATURE_FD_PASSING:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Global feature %1$d should have already been handled"),
                       feature);
        return -1;
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
    case VIR_DRV_FEATURE_MIGRATION_V1:
    default:
        return 0;
    }
}



static char *
networkBuildDnsmasqLeaseTime(virNetworkDHCPLeaseTimeDef *lease)
{
    const char *unit;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!lease)
        return NULL;

    if (lease->expiry == 0) {
        virBufferAddLit(&buf, "infinite");
    } else {
        unit = virNetworkDHCPLeaseTimeUnitTypeToString(lease->unit);
        /* We get only first compatible char from string: 's', 'm' or 'h' */
        virBufferAsprintf(&buf, "%llu%c", lease->expiry, unit[0]);
    }

    return virBufferContentAndReset(&buf);
}


/* the following does not build a file, it builds a list
 * which is later saved into a file
 */
static int
networkBuildDnsmasqDhcpHostsList(dnsmasqContext *dctx,
                                 virNetworkIPDef *ipdef)
{
    size_t i;
    bool ipv6 = false;

    if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
        ipv6 = true;
    for (i = 0; i < ipdef->nhosts; i++) {
        virNetworkDHCPHostDef *host = &(ipdef->hosts[i]);
        g_autofree char *leasetime = networkBuildDnsmasqLeaseTime(host->lease);

        if (VIR_SOCKET_ADDR_VALID(&host->ip))
            if (dnsmasqAddDhcpHost(dctx, host->mac, &host->ip,
                                   host->name, host->id, leasetime,
                                   ipv6) < 0)
                return -1;
    }

    return 0;
}


static int
networkBuildDnsmasqHostsList(dnsmasqContext *dctx,
                             virNetworkDNSDef *dnsdef)
{
    size_t i, j;

    if (dnsdef) {
        for (i = 0; i < dnsdef->nhosts; i++) {
            virNetworkDNSHostDef *host = &(dnsdef->hosts[i]);
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
networkDnsmasqConfLocalPTRs(virBuffer *buf,
                            virNetworkDef *def)
{
    virNetworkIPDef *ip;
    size_t i;
    int rc;

    for (i = 0; i < def->nips; i++) {
        g_autofree char *ptr = NULL;

        ip = def->ips + i;

        if (ip->localPTR != VIR_TRISTATE_BOOL_YES)
            continue;

        if ((rc = virSocketAddrPTRDomain(&ip->address,
                                         virNetworkIPDefPrefix(ip),
                                         &ptr)) < 0) {
            if (rc == -2) {
                int family = VIR_SOCKET_ADDR_FAMILY(&ip->address);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PTR domain for %1$s network with prefix %2$u cannot be automatically created"),
                               (family == AF_INET) ? "IPv4" : "IPv6",
                               virNetworkIPDefPrefix(ip));
            }
            return -1;
        }

        virBufferAsprintf(buf, "local=/%s/\n", ptr);
    }

    return 0;
}


static int
networkDnsmasqConfDHCP(virBuffer *buf,
                       virNetworkIPDef *ipdef,
                       const char *bridge,
                       int *nbleases,
                       dnsmasqContext *dctx)
{
    int r;
    int prefix;

    if (!ipdef)
        return 0;

    prefix = virNetworkIPDefPrefix(ipdef);
    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("bridge '%1$s' has an invalid prefix"),
                       bridge);
        return -1;
    }
    for (r = 0; r < ipdef->nranges; r++) {
        int thisRange;
        virNetworkDHCPRangeDef range = ipdef->ranges[r];
        g_autofree char *leasetime = NULL;
        g_autofree char *saddr = NULL;
        g_autofree char *eaddr = NULL;

        if (!(saddr = virSocketAddrFormat(&range.addr.start)) ||
            !(eaddr = virSocketAddrFormat(&range.addr.end)))
            return -1;

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6)) {
            virBufferAsprintf(buf, "dhcp-range=%s,%s,%d",
                              saddr, eaddr, prefix);
        } else {
            /* IPv4 - dnsmasq requires a netmask rather than prefix */
            virSocketAddr netmask;
            g_autofree char *netmaskStr = NULL;

            if (virSocketAddrPrefixToNetmask(prefix, &netmask, AF_INET) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to translate bridge '%1$s' prefix %2$d to netmask"),
                               bridge, prefix);
                return -1;
            }

            if (!(netmaskStr = virSocketAddrFormat(&netmask)))
                return -1;
            virBufferAsprintf(buf, "dhcp-range=%s,%s,%s",
                              saddr, eaddr, netmaskStr);
        }

        if ((leasetime = networkBuildDnsmasqLeaseTime(range.lease)))
            virBufferAsprintf(buf, ",%s", leasetime);

        virBufferAddLit(buf, "\n");

        thisRange = virSocketAddrGetRange(&range.addr.start,
                                          &range.addr.end,
                                          &ipdef->address,
                                          virNetworkIPDefPrefix(ipdef));
        if (thisRange < 0)
            return -1;
        *nbleases += thisRange;
    }

    /*
     * For static-only DHCP, i.e. with no range but at least one
     * host element, we have to add a special --dhcp-range option
     * to enable the service in dnsmasq. (this is for dhcp-hosts=
     * support)
     */
    if (!ipdef->nranges && ipdef->nhosts) {
        g_autofree char *bridgeaddr = virSocketAddrFormat(&ipdef->address);
        if (!bridgeaddr)
            return -1;
        virBufferAsprintf(buf, "dhcp-range=%s,static",
                          bridgeaddr);
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            virBufferAsprintf(buf, ",%d", prefix);
        virBufferAddLit(buf, "\n");
    }

    if (networkBuildDnsmasqDhcpHostsList(dctx, ipdef) < 0)
        return -1;

    /* Note: the following is IPv4 only */
    if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
        if (ipdef->nranges || ipdef->nhosts) {
            virBufferAddLit(buf, "dhcp-no-override\n");
            virBufferAddLit(buf, "dhcp-authoritative\n");
        }

        if (ipdef->bootfile) {
            if (VIR_SOCKET_ADDR_VALID(&ipdef->bootserver)) {
                g_autofree char *bootserver = virSocketAddrFormat(&ipdef->bootserver);

                if (!bootserver)
                    return -1;
                virBufferAsprintf(buf, "dhcp-boot=%s%s%s\n",
                                  ipdef->bootfile, ",,", bootserver);
            } else {
                virBufferAsprintf(buf, "dhcp-boot=%s\n", ipdef->bootfile);
            }
        }
    }

    return 0;
}


static void
networkDnsmasqConfTFTP(virBuffer *buf,
                       virNetworkIPDef *ipdef,
                       bool *enableTFTP)
{
    if (!ipdef->tftproot)
        return;

    if (!*enableTFTP) {
        virBufferAddLit(buf, "enable-tftp\n");
        *enableTFTP = true;
    }
    virBufferAsprintf(buf, "tftp-root=%s\n", ipdef->tftproot);
}


int
networkDnsmasqConfContents(virNetworkObj *obj,
                           const char *pidfile,
                           char **configstr,
                           char **hostsfilestr,
                           dnsmasqContext *dctx,
                           dnsmasqCaps *caps G_GNUC_UNUSED)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    g_auto(virBuffer) configbuf = VIR_BUFFER_INITIALIZER;
    int nbleases = 0;
    size_t i;
    virNetworkDNSDef *dns = &def->dns;
    bool wantDNS = dns->enable != VIR_TRISTATE_BOOL_NO;
    virNetworkIPDef *ipdef = NULL;
    virNetworkIPDef *ipv4def = NULL;
    virNetworkIPDef *ipv6def = NULL;
    bool ipv6SLAAC = false;
    bool enableTFTP = false;

    *configstr = NULL;

    /*
     * All dnsmasq parameters are put into a configuration file, except the
     * command line --conf-file=parameter which specifies the location of
     * configuration file.
     *
     * All dnsmasq conf-file parameters must be specified as "foo=bar"
     * as oppose to "--foo bar" which was acceptable on the command line.
     */

    /*
     * Needed to ensure dnsmasq uses same algorithm for processing
     * multiple namedriver entries in /etc/resolv.conf as GLibC.
     */

    /* create dnsmasq config file appropriate for this network */

    /* Don't forget to update networkxml2conftest :-) */
    virBufferAsprintf(&configbuf,
                      "##WARNING:  THIS IS AN AUTO-GENERATED FILE. "
                      "CHANGES TO IT ARE LIKELY TO BE\n"
                      "##OVERWRITTEN AND LOST.  Changes to this "
                      "configuration should be made using:\n"
                      "##    virsh net-edit %s\n"
                      "## or other application using the libvirt API.\n"
                      "##\n## dnsmasq conf file created by libvirt\n"
                      "strict-order\n",
                      def->name);

    /* if dns is disabled, set its listening port to 0, which
     * tells dnsmasq to not listen
     */
    if (!wantDNS)
        virBufferAddLit(&configbuf, "port=0\n");

    if (wantDNS && def->dns.forwarders) {
        /* addNoResolv should be set to true if there are any entries
         * that specify an IP address for requests, but no domain
         * qualifier (implying that all requests otherwise "unclaimed"
         * should be sent to that address). if it is still false when
         * we've looked at all entries, it means we still need the
         * host's resolv.conf for some cases.
         */
        bool addNoResolv = false;

        for (i = 0; i < def->dns.nfwds; i++) {
            virNetworkDNSForwarder *fwd = &def->dns.forwarders[i];

            virBufferAddLit(&configbuf, "server=");
            if (fwd->domain)
                virBufferAsprintf(&configbuf, "/%s/", fwd->domain);
            if (VIR_SOCKET_ADDR_VALID(&fwd->addr)) {
                g_autofree char *addr = virSocketAddrFormat(&fwd->addr);

                if (!addr)
                    return -1;
                virBufferAsprintf(&configbuf, "%s\n", addr);
                if (!fwd->domain)
                    addNoResolv = true;
            } else {
                /* "don't forward requests for this domain" */
                virBufferAddLit(&configbuf, "#\n");
            }
        }
        if (addNoResolv)
            virBufferAddLit(&configbuf, "no-resolv\n");
    }

    if (def->domain) {
        if (def->domainLocalOnly == VIR_TRISTATE_BOOL_YES) {
            virBufferAsprintf(&configbuf,
                              "local=/%s/\n",
                              def->domain);
        }
        virBufferAsprintf(&configbuf,
                          "domain=%s\n"
                          "expand-hosts\n",
                          def->domain);
    }

    if (wantDNS &&
        networkDnsmasqConfLocalPTRs(&configbuf, def) < 0)
        return -1;

    if (wantDNS && def->dns.forwardPlainNames == VIR_TRISTATE_BOOL_NO) {
        virBufferAddLit(&configbuf, "domain-needed\n");
        /* need to specify local=// whether or not a domain is
         * specified, unless the config says we should forward "plain"
         * names (i.e. not fully qualified, no '.' characters)
         */
        virBufferAddLit(&configbuf, "local=//\n");
    }

    if (pidfile)
        virBufferAsprintf(&configbuf, "pid-file=%s\n", pidfile);

    /* dnsmasq will *always* listen on localhost unless told otherwise */
#ifdef __linux__
    virBufferAddLit(&configbuf, "except-interface=lo\n");
#else
    /* BSD family OSes and Solaris call loopback interface as lo0 */
    virBufferAddLit(&configbuf, "except-interface=lo0\n");
#endif

    /* using --bind-dynamic with only --interface (no
     * --listen-address) prevents dnsmasq from responding to dns
     * queries that arrive on some interface other than our bridge
     * interface (in other words, requests originating somewhere
     * other than one of the virtual guests connected directly to
     * this network). This was added in response to CVE 2012-3411.
     */
    virBufferAsprintf(&configbuf,
                      "bind-dynamic\n"
                      "interface=%s\n",
                      def->bridge);

    /* If this is an isolated network, set the default route option
     * (3) to be empty to avoid setting a default route that's
     * guaranteed to not work, and set no-resolv so that no dns
     * requests are forwarded on to the dns server listed in the
     * host's /etc/resolv.conf (since this could be used as a channel
     * to build a connection to the outside).
     * IPv6 RA always contains an implicit default route
     * via the sender's link-local address. The only thing we can do
     * is set the lifetime of this route to 0, i.e. disable it.
     */
    if (def->forward.type == VIR_NETWORK_FORWARD_NONE) {
        virBufferAddLit(&configbuf, "dhcp-option=3\n"
                        "no-resolv\n");
        /* interface=* (any), interval=0 (default), lifetime=0 (seconds) */
        virBufferAddLit(&configbuf, "ra-param=*,0,0\n");
    }

    if (wantDNS) {
        for (i = 0; i < dns->ntxts; i++) {
            virBufferAsprintf(&configbuf, "txt-record=%s,%s\n",
                              dns->txts[i].name,
                              dns->txts[i].value);
        }

        for (i = 0; i < dns->nsrvs; i++) {
            /* service/protocol are required, and should have been validated
             * by the parser.
             */
            if (!dns->srvs[i].service) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing required 'service' attribute in SRV record of network '%1$s'"),
                               def->name);
                return -1;
            }
            if (!dns->srvs[i].protocol) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing required 'service' attribute in SRV record of network '%1$s'"),
                               def->name);
                return -1;
            }
            /* RFC2782 requires that service and protocol be preceded by
             * an underscore.
             */
            virBufferAsprintf(&configbuf, "srv-host=_%s._%s",
                              dns->srvs[i].service, dns->srvs[i].protocol);

            /* domain is optional - it defaults to the domain of this network */
            if (dns->srvs[i].domain)
                virBufferAsprintf(&configbuf, ".%s", dns->srvs[i].domain);

            /* If target is empty or ".", that means "the service is
             * decidedly not available at this domain" (RFC2782). In that
             * case, any port, priority, or weight is irrelevant.
             */
            if (dns->srvs[i].target && STRNEQ(dns->srvs[i].target, ".")) {

                virBufferAsprintf(&configbuf, ",%s", dns->srvs[i].target);
                /* port, priority, and weight are optional, but are
                 * identified by their position in the line. If an item is
                 * unspecified, but something later in the line *is*
                 * specified, we need to give the default value for the
                 * unspecified item. (According to the dnsmasq manpage,
                 * the default for port is 1).
                 */
                if (dns->srvs[i].port ||
                    dns->srvs[i].priority || dns->srvs[i].weight)
                    virBufferAsprintf(&configbuf, ",%d",
                                      dns->srvs[i].port ? dns->srvs[i].port : 1);
                if (dns->srvs[i].priority || dns->srvs[i].weight)
                    virBufferAsprintf(&configbuf, ",%d", dns->srvs[i].priority);
                if (dns->srvs[i].weight)
                    virBufferAsprintf(&configbuf, ",%d", dns->srvs[i].weight);
            }
            virBufferAddLit(&configbuf, "\n");
        }
    }

    /* Find the first dhcp for both IPv4 and IPv6 */
    for (i = 0; (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i)); i++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv4def) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("For IPv4, multiple DHCP definitions cannot be specified."));
                    return -1;
                } else {
                    ipv4def = ipdef;
                }
            }

            networkDnsmasqConfTFTP(&configbuf, ipdef, &enableTFTP);
        }
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv6def) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("For IPv6, multiple DHCP definitions cannot be specified."));
                    return -1;
                } else {
                    ipv6def = ipdef;
                }
            } else {
                ipv6SLAAC = true;
            }
        }
    }

    if (ipv6def && ipv6SLAAC) {
        VIR_WARN("For IPv6, when DHCP is specified for one address, then "
                 "state-full Router Advertising will occur.  The additional "
                 "IPv6 addresses specified require manually configured guest "
                 "network to work properly since both state-full (DHCP) "
                 "and state-less (SLAAC) addressing are not supported "
                 "on the same network interface.");
    }

    if (networkDnsmasqConfDHCP(&configbuf, ipv4def, def->bridge, &nbleases, dctx) < 0 ||
        networkDnsmasqConfDHCP(&configbuf, ipv6def, def->bridge, &nbleases, dctx) < 0)
        return -1;

    if (nbleases > 0)
        virBufferAsprintf(&configbuf, "dhcp-lease-max=%d\n", nbleases);

    /* this is done once per interface */
    if (networkBuildDnsmasqHostsList(dctx, dns) < 0)
        return -1;

    /* Even if there are currently no static hosts, if we're
     * listening for DHCP, we should write a 0-length hosts
     * file to allow for runtime additions.
     */
    if (ipv4def || ipv6def)
        virBufferAsprintf(&configbuf, "dhcp-hostsfile=%s\n",
                          dctx->hostsfile->path);

    /* Likewise, always create this file and put it on the
     * commandline, to allow for runtime additions.
     */
    if (wantDNS) {
        virBufferAsprintf(&configbuf, "addn-hosts=%s\n",
                          dctx->addnhostsfile->path);
    }

    /* Configure DHCP to tell clients about the MTU. */
    if (def->mtu > 0)
        virBufferAsprintf(&configbuf, "dhcp-option=option:mtu,%d\n", def->mtu);

    if (ipv6def) {
        virBufferAddLit(&configbuf, "enable-ra\n");
    } else {
        for (i = 0;
             (ipdef = virNetworkDefGetIPByIndex(def, AF_INET6, i));
             i++) {
            if (!(ipdef->nranges || ipdef->nhosts)) {
                g_autofree char *bridgeaddr = virSocketAddrFormat(&ipdef->address);
                if (!bridgeaddr)
                    return -1;
                virBufferAsprintf(&configbuf,
                                  "dhcp-range=%s,ra-only\n", bridgeaddr);
            }
        }
    }

    if (def->namespaceData) {
        networkDnsmasqXmlNsDef *dnsmasqxmlns = def->namespaceData;
        GStrv n;
        for (n = dnsmasqxmlns->options; n && *n; n++)
            virBufferAsprintf(&configbuf, "%s\n", *n);
    }

    if (!(*configstr = virBufferContentAndReset(&configbuf)))
        return -1;

    *hostsfilestr = dnsmasqDhcpHostsToString(dctx->hostsfile->hosts,
                                             dctx->hostsfile->nhosts);

    return 0;
}


/* build the dnsmasq command line */
static int ATTRIBUTE_NONNULL(3)
networkBuildDhcpDaemonCommandLine(virNetworkDriverState *driver,
                                  virNetworkObj *obj,
                                  virCommand **cmdout,
                                  char *pidfile,
                                  dnsmasqContext *dctx)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    g_autoptr(dnsmasqCaps) dnsmasq_caps = networkGetDnsmasqCaps(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *configfile = NULL;
    g_autofree char *configstr = NULL;
    g_autofree char *hostsfilestr = NULL;
    g_autofree char *leaseshelper_path = NULL;

    virNetworkObjSetDnsmasqPid(obj, -1);

    if (networkDnsmasqConfContents(obj, pidfile, &configstr, &hostsfilestr,
                                   dctx, dnsmasq_caps) < 0)
        return -1;
    if (!configstr)
        return -1;

    /* construct the filename */
    if (!(configfile = networkDnsmasqConfigFileName(cfg, def->name)))
        return -1;

    /* Write the file */
    if (virFileWriteStr(configfile, configstr, 0600) < 0) {
        virReportSystemError(errno,
                             _("couldn't write dnsmasq config file '%1$s'"),
                             configfile);
        return -1;
    }

    /* This helper is used to create custom leases file for libvirt */
    if (!(leaseshelper_path = virFileFindResource("libvirt_leaseshelper",
                                                  abs_top_builddir "/src",
                                                  LIBEXECDIR)))
        return -1;

    cmd = virCommandNew(dnsmasqCapsGetBinaryPath(dnsmasq_caps));
    virCommandAddArgFormat(cmd, "--conf-file=%s", configfile);
    /* Libvirt gains full control of leases database */
    virCommandAddArgFormat(cmd, "--leasefile-ro");
    virCommandAddArgFormat(cmd, "--dhcp-script=%s", leaseshelper_path);
    virCommandAddEnvPair(cmd, "VIR_BRIDGE_NAME", def->bridge);

    *cmdout = g_steal_pointer(&cmd);
    return 0;
}


static int
networkStartDhcpDaemon(virNetworkDriverState *driver,
                       virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    virNetworkIPDef *ipdef;
    size_t i;
    bool needDnsmasq = false;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *pidfile = NULL;
    pid_t dnsmasqPid;
    g_autoptr(dnsmasqContext) dctx = NULL;

    /* see if there are any IP addresses that need a dhcp server */
    i = 0;
    while ((ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i))) {
        i++;
        if (ipdef->nranges || ipdef->nhosts || ipdef->tftproot)
            needDnsmasq = true;
    }

    /* no IP addresses at all, so we don't need to run */
    if (i == 0)
        return 0;

    /* no DHCP services needed, and user disabled DNS service */
    if (!needDnsmasq && def->dns.enable == VIR_TRISTATE_BOOL_NO)
        return 0;

    if (g_mkdir_with_parents(cfg->pidDir, 0777) < 0) {
        virReportSystemError(errno, _("cannot create directory %1$s"), cfg->pidDir);
        return -1;
    }

    if (!(pidfile = virPidFileBuildPath(cfg->pidDir, def->name)))
        return -1;

    if (g_mkdir_with_parents(cfg->dnsmasqStateDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("cannot create directory %1$s"),
                             cfg->dnsmasqStateDir);
        return -1;
    }

    dctx = dnsmasqContextNew(def->name, cfg->dnsmasqStateDir);
    if (dctx == NULL)
        return -1;

    if (networkDnsmasqCapsRefresh(driver) < 0)
        return -1;

    if (networkBuildDhcpDaemonCommandLine(driver, obj, &cmd, pidfile, dctx) < 0)
        return -1;

    if (dnsmasqSave(dctx) < 0)
        return -1;

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    /*
     * There really is no race here - when dnsmasq daemonizes, its
     * leader process stays around until its child has actually
     * written its pidfile. So by time virCommandRun exits it has
     * waitpid'd and guaranteed the proess has started and written a
     * pid
     */

    if (virPidFileRead(cfg->pidDir, def->name, &dnsmasqPid) < 0)
        return -1;

    virNetworkObjSetDnsmasqPid(obj, dnsmasqPid);

    return 0;
}


/* networkRefreshDhcpDaemon:
 *  Update dnsmasq config files, then send a SIGHUP so that it rereads
 *  them.   This only works for the dhcp-hostsfile and the
 *  addn-hosts file.
 *
 *  Returns 0 on success, -1 on failure.
 */
static int
networkRefreshDhcpDaemon(virNetworkDriverState *driver,
                         virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    size_t i;
    pid_t dnsmasqPid;
    virNetworkIPDef *ipdef;
    virNetworkIPDef *ipv4def;
    virNetworkIPDef *ipv6def;
    g_autoptr(dnsmasqContext) dctx = NULL;

    /* if no IP addresses specified, nothing to do */
    if (!virNetworkDefGetIPByIndex(def, AF_UNSPEC, 0))
        return 0;

    /* if there's no running dnsmasq, just start it */
    dnsmasqPid = virNetworkObjGetDnsmasqPid(obj);
    if (dnsmasqPid <= 0 || (kill(dnsmasqPid, 0) < 0))
        return networkStartDhcpDaemon(driver, obj);

    VIR_INFO("Refreshing dnsmasq for network %s", def->bridge);
    if (!(dctx = dnsmasqContextNew(def->name, cfg->dnsmasqStateDir)))
        return -1;

    /* Look for first IPv4 address that has dhcp defined.
     * We only support dhcp-host config on one IPv4 subnetwork
     * and on one IPv6 subnetwork.
     */
    ipv4def = NULL;
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (!ipv4def && (ipdef->nranges || ipdef->nhosts))
            ipv4def = ipdef;
    }

    ipv6def = NULL;
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_INET6, i));
         i++) {
        if (!ipv6def && (ipdef->nranges || ipdef->nhosts))
            ipv6def = ipdef;
    }

    if (ipv4def && (networkBuildDnsmasqDhcpHostsList(dctx, ipv4def) < 0))
        return -1;

    if (ipv6def && (networkBuildDnsmasqDhcpHostsList(dctx, ipv6def) < 0))
        return -1;

    if (networkBuildDnsmasqHostsList(dctx, &def->dns) < 0)
        return -1;

    if (dnsmasqSave(dctx) < 0)
        return -1;

    return kill(dnsmasqPid, SIGHUP);

}


/* networkRestartDhcpDaemon:
 *
 * kill and restart dnsmasq, in order to update any config that is on
 * the dnsmasq commandline (and any placed in separate config files).
 *
 *  Returns 0 on success, -1 on failure.
 */
static int
networkRestartDhcpDaemon(virNetworkDriverState *driver,
                         virNetworkObj *obj)
{
    pid_t dnsmasqPid = virNetworkObjGetDnsmasqPid(obj);

    /* if there is a running dnsmasq, kill it */
    if (dnsmasqPid > 0) {
        virProcessKillPainfully(dnsmasqPid, false);
        virNetworkObjSetDnsmasqPid(obj, -1);
    }
    /* now start dnsmasq if it should be started */
    return networkStartDhcpDaemon(driver, obj);
}


static int
networkRefreshDaemonsHelper(virNetworkObj *obj,
                            void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);
    virNetworkDriverState *driver = opaque;
    virNetworkDef *def = virNetworkObjGetDef(obj);

    if (virNetworkObjIsActive(obj)) {
        switch ((virNetworkForwardType) def->forward.type) {
        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
        case VIR_NETWORK_FORWARD_OPEN:
            /* Only the three L3 network types that are configured by
             * libvirt will have a dnsmasq daemon associated
             * with them.  Here we send a SIGHUP to an existing
             * dnsmasq, or restart it if it has disappeared.
             */
            networkRefreshDhcpDaemon(driver, obj);
            break;

        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
            break;

        case VIR_NETWORK_FORWARD_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardType, def->forward.type);
            return 0;
        }
    }

    return 0;
}


/* SIGHUP/restart any dnsmasq
 * This should be called when libvirtd is restarted.
 */
static void
networkRefreshDaemons(virNetworkDriverState *driver)
{
    VIR_INFO("Refreshing network daemons");
    virNetworkObjListForEach(driver->networks,
                             networkRefreshDaemonsHelper,
                             driver);
}


static int
networkReloadFirewallRulesHelper(virNetworkObj *obj,
                                 void *opaque G_GNUC_UNUSED)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);
    virNetworkDef *def = virNetworkObjGetDef(obj);

    if (virNetworkObjIsActive(obj)) {
        switch ((virNetworkForwardType) def->forward.type) {
        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
            /* Only three of the L3 network types that are configured by
             * libvirt need to have iptables rules reloaded. The 4th L3
             * network type, forward='open', doesn't need this because it
             * has no iptables rules.
             */
            networkRemoveFirewallRules(def);
            ignore_value(networkAddFirewallRules(def));
            break;

        case VIR_NETWORK_FORWARD_OPEN:
        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
            break;

        case VIR_NETWORK_FORWARD_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardType, def->forward.type);
            return 0;
        }
    }

    return 0;
}


static void
networkReloadFirewallRules(virNetworkDriverState *driver,
                           bool startup,
                           bool force)
{
    VIR_INFO("Reloading iptables rules");
    /* Ideally we'd not even register the driver when unprivilegd
     * but until we untangle the virt driver that's not viable */
    if (!driver->privileged)
        return;
    networkPreReloadFirewallRules(driver, startup, force);
    virNetworkObjListForEach(driver->networks,
                             networkReloadFirewallRulesHelper,
                             NULL);
    networkPostReloadFirewallRules(startup);
}


/* Enable IP Forwarding. Return 0 for success, -1 for failure. */
static int
networkEnableIPForwarding(bool enableIPv4,
                          bool enableIPv6)
{
    int ret = 0;
#ifdef WITH_SYSCTLBYNAME
    int enabled = 1;
    if (enableIPv4)
        ret = sysctlbyname("net.inet.ip.forwarding", NULL, 0,
                           &enabled, sizeof(enabled));
    if (enableIPv6 && ret == 0)
        ret = sysctlbyname("net.inet6.ip6.forwarding", NULL, 0,
                           &enabled, sizeof(enabled));
#else
    if (enableIPv4)
        ret = virFileWriteStr(SYSCTL_PATH "/net/ipv4/ip_forward", "1\n", 0);
    if (enableIPv6 && ret == 0)
        ret = virFileWriteStr(SYSCTL_PATH "/net/ipv6/conf/all/forwarding", "1\n", 0);

#endif
    return ret;
}


static int
networkSetIPv6Sysctl(const char *bridge,
                     const char *sysctl_field,
                     const char *sysctl_setting,
                     bool ignoreMissing)
{
    g_autofree char *field = g_strdup_printf(SYSCTL_PATH "/net/ipv6/conf/%s/%s",
                                             bridge, sysctl_field);

    if (ignoreMissing && access(field, W_OK) < 0 && errno == ENOENT)
        return -2;

    if (virFileWriteStr(field, sysctl_setting, 0) < 0) {
        virReportSystemError(errno,
                             _("cannot write to '%1$s' on bridge '%2$s'"),
                             field, bridge);
        return -1;
    }

    return 0;
}


static int
networkSetIPv6Sysctls(virNetworkObj *obj)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    bool enableIPv6 = !!virNetworkDefGetIPByIndex(def, AF_INET6, 0);
    int rc;

    /* set disable_ipv6 if there are no ipv6 addresses defined for the
     * network. But also unset it if there *are* ipv6 addresses, as we
     * can't be sure of its default value.
     */
    rc = networkSetIPv6Sysctl(def->bridge, "disable_ipv6",
                              enableIPv6 ? "0" : "1", true);
    if (rc == -2) {
        if (!enableIPv6)
            VIR_DEBUG("ipv6 appears to already be disabled on %s",
                      def->bridge);
        return 0;
    } else if (rc < 0) {
        return -1;
    }

    /* The rest of the ipv6 sysctl tunables should always be set the
     * same, whether or not we're using ipv6 on this bridge.
     */

    /* Prevent guests from hijacking the host network by sending out
     * their own router advertisements.
     */
    if (networkSetIPv6Sysctl(def->bridge, "accept_ra", "0", false) < 0)
        return -1;

    /* All interfaces used as a gateway (which is what this is, by
     * definition), must always have autoconf=0.
     */
    if (networkSetIPv6Sysctl(def->bridge, "autoconf", "0", false) < 0)
        return -1;

    return 0;
}


/* add an IP address to a bridge */
static int
networkAddAddrToBridge(virNetworkObj *obj,
                       virNetworkIPDef *ipdef)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    int prefix = virNetworkIPDefPrefix(ipdef);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("bridge '%1$s' has an invalid netmask or IP address"),
                       def->bridge);
        return -1;
    }

    if (virNetDevIPAddrAdd(def->bridge, &ipdef->address, NULL, prefix) < 0)
        return -1;

    return 0;
}


static int
networkStartHandleMACTableManagerMode(virNetworkObj *obj)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    const char *brname = def->bridge;

    if (brname &&
        def->macTableManager == VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
        if (virNetDevBridgeSetVlanFiltering(brname, true) < 0)
            return -1;
    }
    return 0;
}


/* add an IP (static) route to a bridge */
static int
networkAddRouteToBridge(virNetworkObj *obj,
                        virNetDevIPRoute *routedef)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    int prefix = virNetDevIPRouteGetPrefix(routedef);
    unsigned int metric = virNetDevIPRouteGetMetric(routedef);
    virSocketAddr *addr = virNetDevIPRouteGetAddress(routedef);
    virSocketAddr *gateway = virNetDevIPRouteGetGateway(routedef);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%1$s' has an invalid netmask or IP address in route definition"),
                       def->name);
        return -1;
    }

    if (virNetDevIPRouteAdd(def->bridge, addr, prefix, gateway, metric) < 0)
        return -1;

    return 0;
}


static int
networkStartNetworkVirtual(virNetworkDriverState *driver,
                           virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    size_t i;
    bool v4present = false, v6present = false;
    virErrorPtr save_err = NULL;
    virNetworkIPDef *ipdef;
    virNetDevIPRoute *routedef;
    bool dnsmasqStarted = false;
    bool devOnline = false;
    bool firewalRulesAdded = false;

    /* Check to see if any network IP collides with an existing route */
    if (networkCheckRouteCollision(def) < 0)
        return -1;

    /* Create and configure the bridge device */
    if (!def->bridge) {
        /* bridge name can only be empty if the config files were
         * edited directly. Otherwise networkValidate() (called after
         * parsing the XML from networkCreateXML() and
         * networkDefine()) guarantees we will have a valid bridge
         * name before this point. Since hand editing of the config
         * files is explicitly prohibited we can, with clear
         * conscience, log an error and fail at this point.
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%1$s' has no bridge name defined"),
                       def->name);
        return -1;
    }
    if (virNetDevBridgeCreate(def->bridge, &def->mac) < 0)
        return -1;

    /* Set bridge options */

    if (def->mtu && virNetDevSetMTU(def->bridge, def->mtu) < 0)
        goto error;

    /* delay is configured in seconds, but virNetDevBridgeSetSTPDelay
     * expects milliseconds
     */
    if (virNetDevBridgeSetSTPDelay(def->bridge, def->delay * 1000) < 0)
        goto error;

    if (virNetDevBridgeSetSTP(def->bridge, def->stp ? true : false) < 0)
        goto error;

    /* Disable IPv6 on the bridge if there are no IPv6 addresses
     * defined, and set other IPv6 sysctl tunables appropriately.
     */
    if (networkSetIPv6Sysctls(obj) < 0)
        goto error;

    /* Add "once per network" rules */
    if (def->forward.type != VIR_NETWORK_FORWARD_OPEN &&
        networkAddFirewallRules(def) < 0)
        goto error;

    firewalRulesAdded = true;

    for (i = 0; (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i)); i++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            v4present = true;
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            v6present = true;

        /* Add the IP address/netmask to the bridge */
        if (networkAddAddrToBridge(obj, ipdef) < 0)
            goto error;
    }

    if (networkStartHandleMACTableManagerMode(obj) < 0)
        goto error;

    /* Bring up the bridge interface */
    if (virNetDevSetOnline(def->bridge, true) < 0)
        goto error;

    devOnline = true;

    for (i = 0; i < def->nroutes; i++) {
        virSocketAddr *gateway = NULL;

        routedef = def->routes[i];
        gateway = virNetDevIPRouteGetGateway(routedef);

        /* Add the IP route to the bridge */
        /* ignore errors, error msg will be generated */
        /* but libvirt will not know and net-destroy will work. */
        if (VIR_SOCKET_ADDR_VALID(gateway)) {
            if (networkAddRouteToBridge(obj, routedef) < 0) {
                /* an error occurred adding the static route */
                continue; /* for now, do nothing */
            }
        }
    }

    /* If forward.type != NONE, turn on global IP forwarding */
    if (def->forward.type != VIR_NETWORK_FORWARD_NONE) {
        if (v6present && !virNetDevIPCheckIPv6Forwarding())
            goto error; /* Precise error message already provided */

        if (networkEnableIPForwarding(v4present, v6present) < 0) {
            virReportSystemError(errno, "%s",
                                 _("failed to enable IP forwarding"));
            goto error;
        }
    }


    /* start dnsmasq if there are any IP addresses (v4 or v6) */
    if (v4present || v6present) {
        if (networkSetMacMap(cfg, obj) < 0)
            goto error;

        if (networkStartDhcpDaemon(driver, obj) < 0)
            goto error;

        dnsmasqStarted = true;
    }

    if (virNetDevBandwidthSet(def->bridge, def->bandwidth, true, true) < 0)
        goto error;

    return 0;

 error:
    virErrorPreserveLast(&save_err);
    if (def->bandwidth)
       virNetDevBandwidthClear(def->bridge);

    if (dnsmasqStarted) {
        pid_t dnsmasqPid = virNetworkObjGetDnsmasqPid(obj);
        kill(dnsmasqPid, SIGTERM);
        virNetworkObjSetDnsmasqPid(obj, -1);
    }

    if (devOnline)
        ignore_value(virNetDevSetOnline(def->bridge, false));

    if (firewalRulesAdded &&
        def->forward.type != VIR_NETWORK_FORWARD_OPEN)
        networkRemoveFirewallRules(def);

    virNetworkObjUnrefMacMap(obj);

    ignore_value(virNetDevBridgeDelete(def->bridge));

    virErrorRestore(&save_err);
    return -1;
}


static int
networkShutdownNetworkVirtual(virNetworkObj *obj)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    pid_t dnsmasqPid;

    if (def->bandwidth)
        virNetDevBandwidthClear(def->bridge);

    virNetworkObjUnrefMacMap(obj);
    dnsmasqPid = virNetworkObjGetDnsmasqPid(obj);
    if (dnsmasqPid > 0)
        kill(dnsmasqPid, SIGTERM);

    /* We no longer create a dummy NIC, but if we've upgraded
     * from old libvirt, we still need to delete any dummy NIC
     * that might exist. Keep this logic around for a while...
     */
    if (def->mac_specified) {
        g_autofree char *macTapIfName = networkBridgeDummyNicName(def->bridge);
        if (macTapIfName && virNetDevExists(macTapIfName))
            ignore_value(virNetDevTapDelete(macTapIfName, NULL));
    }

    ignore_value(virNetDevSetOnline(def->bridge, false));

    if (def->forward.type != VIR_NETWORK_FORWARD_OPEN)
        networkRemoveFirewallRules(def);

    ignore_value(virNetDevBridgeDelete(def->bridge));

    /* See if its still alive and really really kill it */
    dnsmasqPid = virNetworkObjGetDnsmasqPid(obj);
    if (dnsmasqPid > 0 &&
        (kill(dnsmasqPid, 0) == 0))
        kill(dnsmasqPid, SIGKILL);
    virNetworkObjSetDnsmasqPid(obj, -1);

    return 0;
}


static int
networkStartNetworkBridge(virNetworkObj *obj)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);

    /* put anything here that needs to be done each time a network of
     * type BRIDGE, is started. On failure, undo anything you've done,
     * and return -1. On success return 0.
     */
    if (virNetDevBandwidthSet(def->bridge, def->bandwidth, true, true) < 0)
        goto error;

    if (networkStartHandleMACTableManagerMode(obj) < 0)
        goto error;

    return 0;

 error:
    if (def->bandwidth)
       virNetDevBandwidthClear(def->bridge);
    return -1;
}


static int
networkShutdownNetworkBridge(virNetworkObj *obj G_GNUC_UNUSED)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);

    /* put anything here that needs to be done each time a network of
     * type BRIDGE is shutdown. On failure, undo anything you've done,
     * and return -1. On success return 0.
     */
    if (def->bandwidth)
       virNetDevBandwidthClear(def->bridge);

    return 0;
}


/* networkCreateInterfacePool:
 * @netdef: the original NetDef from the network
 *
 * Creates an implicit interface pool of VF's when a PF dev is given
 */
static int
networkCreateInterfacePool(virNetworkDef *netdef)
{
    g_autoptr(virPCIVirtualFunctionList) vfs = NULL;
    int ret = -1;
    size_t i;

    if (netdef->forward.npfs == 0 || netdef->forward.nifs > 0)
       return 0;

    if (virNetDevGetVirtualFunctions(netdef->forward.pfs->dev, &vfs) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get Virtual functions on %1$s"),
                       netdef->forward.pfs->dev);
        goto cleanup;
    }

    netdef->forward.ifs = g_new0(virNetworkForwardIfDef, vfs->nfunctions);

    for (i = 0; i < vfs->nfunctions; i++) {
        virPCIDeviceAddress *thisVirtFn = vfs->functions[i].addr;
        const char *thisName = vfs->functions[i].ifname;
        virNetworkForwardIfDef *thisIf
            = &netdef->forward.ifs[netdef->forward.nifs];

        switch ((virNetworkForwardType) netdef->forward.type) {
        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
            if (thisName) {
                thisIf->device.dev = g_strdup(thisName);
                thisIf->type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
                netdef->forward.nifs++;
            } else {
                VIR_WARN("VF %zu of SRIOV PF %s couldn't be added to the "
                         "interface pool because it isn't bound "
                         "to a network driver - possibly in use elsewhere",
                         i, netdef->forward.pfs->dev);
            }
            break;

        case VIR_NETWORK_FORWARD_HOSTDEV:
            /* VF's are always PCI devices */
            thisIf->type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI;
            thisIf->device.pci.domain = thisVirtFn->domain;
            thisIf->device.pci.bus = thisVirtFn->bus;
            thisIf->device.pci.slot = thisVirtFn->slot;
            thisIf->device.pci.function = thisVirtFn->function;
            netdef->forward.nifs++;
            break;

        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
        case VIR_NETWORK_FORWARD_OPEN:
            /* by definition these will never be encountered here */
            break;

        case VIR_NETWORK_FORWARD_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardType, netdef->forward.type);
            goto cleanup;
        }
    }

    if (netdef->forward.nifs == 0) {
        /* If we don't get at least one interface in the pool, declare
         * failure
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No usable Vf's present on SRIOV PF %1$s"),
                       netdef->forward.pfs->dev);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        /* free all the entries made before error */
        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV)
                g_free(netdef->forward.ifs[i].device.dev);
        }
        netdef->forward.nifs = 0;
    }
    if (netdef->forward.nifs == 0)
        g_clear_pointer(&netdef->forward.ifs, g_free);

    return ret;
}


static int
networkStartNetworkExternal(virNetworkObj *obj)
{
    /* put anything here that needs to be done each time a network of
     * type BRIDGE, PRIVATE, VEPA, HOSTDEV or PASSTHROUGH is started. On
     * failure, undo anything you've done, and return -1. On success
     * return 0.
     */
    return networkCreateInterfacePool(virNetworkObjGetDef(obj));
}


static int
networkShutdownNetworkExternal(virNetworkObj *obj G_GNUC_UNUSED)
{
    /* put anything here that needs to be done each time a network of
     * type BRIDGE, PRIVATE, VEPA, HOSTDEV or PASSTHROUGH is shutdown. On
     * failure, undo anything you've done, and return -1. On success
     * return 0.
     */
    return 0;
}


static int
networkStartNetwork(virNetworkDriverState *driver,
                    virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    int ret = -1;

    VIR_DEBUG("driver=%p, network=%p", driver, obj);

    if (virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("network is already active"));
        return ret;
    }

    VIR_DEBUG("Beginning network startup process");

    virNetworkObjDeleteAllPorts(obj, cfg->stateDir);

    VIR_DEBUG("Setting current network def as transient");
    if (virNetworkObjSetDefTransient(obj, true, network_driver->xmlopt) < 0)
        goto cleanup;

    /* Run an early hook to set-up missing devices.
     * If the script raised an error abort the launch. */
    if (networkRunHook(obj, NULL,
                       VIR_HOOK_NETWORK_OP_START,
                       VIR_HOOK_SUBOP_BEGIN) < 0)
        goto cleanup;

    switch ((virNetworkForwardType) def->forward.type) {

    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        if (networkStartNetworkVirtual(driver, obj) < 0)
            goto cleanup;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->bridge) {
            if (networkStartNetworkBridge(obj) < 0)
                goto cleanup;
            break;
        }
        /* intentionally fall through to the macvtap/direct case for
         * VIR_NETWORK_FORWARD_BRIDGE with no bridge device defined
         * (since that is macvtap bridge mode).
         */
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        if (networkStartNetworkExternal(obj) < 0)
            goto cleanup;
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        goto cleanup;
    }

    virNetworkObjSetFloorSum(obj, 0);

    /* finally we can call the 'started' hook script if any */
    if (networkRunHook(obj, NULL,
                       VIR_HOOK_NETWORK_OP_STARTED,
                       VIR_HOOK_SUBOP_BEGIN) < 0)
        goto cleanup;

    /* Persist the live configuration now that anything autogenerated
     * is setup.
     */
    VIR_DEBUG("Writing network status to disk");
    if (virNetworkObjSaveStatus(cfg->stateDir,
                                obj, network_driver->xmlopt) < 0)
        goto cleanup;

    virNetworkObjSetActive(obj, true);
    VIR_INFO("Network '%s' started up", def->name);
    ret = 0;

 cleanup:
    if (ret < 0) {
        virErrorPtr save_err;

        virErrorPreserveLast(&save_err);
        virNetworkObjUnsetDefTransient(obj);
        networkShutdownNetwork(driver, obj);
        virErrorRestore(&save_err);
    }
    return ret;
}


static int
networkShutdownNetwork(virNetworkDriverState *driver,
                       virNetworkObj *obj)
{
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    int ret = 0;
    g_autofree char *stateFile = NULL;

    VIR_INFO("Shutting down network '%s'", def->name);

    if (!virNetworkObjIsActive(obj))
        return 0;

    stateFile = virNetworkConfigFile(cfg->stateDir, def->name);
    if (!stateFile)
        return -1;

    unlink(stateFile);

    switch ((virNetworkForwardType) def->forward.type) {

    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        ret = networkShutdownNetworkVirtual(obj);
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->bridge) {
            ret = networkShutdownNetworkBridge(obj);
            break;
        }
        /* intentionally fall through to the macvtap/direct case for
         * VIR_NETWORK_FORWARD_BRIDGE with no bridge device defined
         * (since that is macvtap bridge mode).
         */
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        ret = networkShutdownNetworkExternal(obj);
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return -1;
    }

    /* now that we know it's stopped call the hook if present */
    networkRunHook(obj, NULL, VIR_HOOK_NETWORK_OP_STOPPED,
                   VIR_HOOK_SUBOP_END);

    virNetworkObjSetActive(obj, false);
    virNetworkObjUnsetDefTransient(obj);
    return ret;
}


static virNetworkPtr
networkLookupByUUID(virConnectPtr conn,
                    const unsigned char *uuid)
{
    virNetworkDriverState *driver = networkGetDriver();
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPtr net = NULL;

    obj = virNetworkObjFindByUUID(driver->networks, uuid);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching uuid '%1$s'"),
                       uuidstr);
        goto cleanup;
    }
    def = virNetworkObjGetDef(obj);

    if (virNetworkLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    net = virGetNetwork(conn, def->name, def->uuid);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return net;
}


static virNetworkPtr
networkLookupByName(virConnectPtr conn,
                    const char *name)
{
    virNetworkDriverState *driver = networkGetDriver();
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPtr net = NULL;

    obj = virNetworkObjFindByName(driver->networks, name);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%1$s'"), name);
        goto cleanup;
    }
    def = virNetworkObjGetDef(obj);

    if (virNetworkLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    net = virGetNetwork(conn, def->name, def->uuid);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return net;
}


static int
networkConnectNumOfNetworks(virConnectPtr conn)
{
    virNetworkDriverState *driver = networkGetDriver();

    if (virConnectNumOfNetworksEnsureACL(conn) < 0)
        return -1;

    return virNetworkObjListNumOfNetworks(driver->networks, true,
                                          virConnectNumOfNetworksCheckACL,
                                          conn);
}


static int
networkConnectListNetworks(virConnectPtr conn,
                           char **const names,
                           int maxnames)
{
    virNetworkDriverState *driver = networkGetDriver();

    if (virConnectListNetworksEnsureACL(conn) < 0)
        return -1;

    return virNetworkObjListGetNames(driver->networks, true, names, maxnames,
                                     virConnectListNetworksCheckACL, conn);
}


static int
networkConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    virNetworkDriverState *driver = networkGetDriver();

    if (virConnectNumOfDefinedNetworksEnsureACL(conn) < 0)
        return -1;

    return virNetworkObjListNumOfNetworks(driver->networks, false,
                                          virConnectNumOfDefinedNetworksCheckACL,
                                          conn);
}


static int
networkConnectListDefinedNetworks(virConnectPtr conn,
                                  char **const names,
                                  int maxnames)
{
    virNetworkDriverState *driver = networkGetDriver();

    if (virConnectListDefinedNetworksEnsureACL(conn) < 0)
        return -1;

    return virNetworkObjListGetNames(driver->networks, false, names, maxnames,
                                     virConnectListDefinedNetworksCheckACL,
                                     conn);
}


static int
networkConnectListAllNetworks(virConnectPtr conn,
                              virNetworkPtr **nets,
                              unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    if (virConnectListAllNetworksEnsureACL(conn) < 0)
        return -1;

    return virNetworkObjListExport(conn, driver->networks, nets,
                                   virConnectListAllNetworksCheckACL,
                                   flags);
}


static int
networkConnectNetworkEventRegisterAny(virConnectPtr conn,
                                      virNetworkPtr net,
                                      int eventID,
                                      virConnectNetworkEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    virNetworkDriverState *driver = networkGetDriver();
    int ret = -1;

    if (virConnectNetworkEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virNetworkEventStateRegisterID(conn, driver->networkEventState,
                                       net, eventID, callback,
                                       opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}


static int
networkConnectNetworkEventDeregisterAny(virConnectPtr conn,
                                        int callbackID)
{
    virNetworkDriverState *driver = networkGetDriver();

    if (virConnectNetworkEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->networkEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}


static int
networkIsActive(virNetworkPtr net)
{
    virNetworkObj *obj;
    int ret = -1;

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    if (virNetworkIsActiveEnsureACL(net->conn, virNetworkObjGetDef(obj)) < 0)
        goto cleanup;

    ret = virNetworkObjIsActive(obj);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkIsPersistent(virNetworkPtr net)
{
    virNetworkObj *obj;
    int ret = -1;

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    if (virNetworkIsPersistentEnsureACL(net->conn, virNetworkObjGetDef(obj)) < 0)
        goto cleanup;

    ret = virNetworkObjIsPersistent(obj);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


/*
 * networkFindUnusedBridgeName() - try to find a bridge name that is
 * unused by the currently configured libvirt networks, as well as by
 * the host system itself (possibly created by someone/something other
 * than libvirt). Set this network's name to that new name.
 */
static int
networkFindUnusedBridgeName(virNetworkObjList *nets,
                            virNetworkDef *def)
{
    int id = 0;
    const char *templ = "virbr%d";
    const char *p;

    if (def->bridge &&
        (p = strchr(def->bridge, '%')) == strrchr(def->bridge, '%') &&
        p && p[1] == 'd')
        templ = def->bridge;

    do {
        g_autofree char *newname = g_strdup_printf(templ, id);

        /* check if this name is used in another libvirt network or
         * there is an existing device with that name. ignore errors
         * from virNetDevExists(), just in case it isn't implemented
         * on this platform (probably impossible).
         */
        if (!(virNetworkObjBridgeInUse(nets, newname, def->name) ||
              virNetDevExists(newname) == 1)) {
            g_free(def->bridge); /*could contain template */
            def->bridge = g_steal_pointer(&newname);
            return 0;
        }
    } while (++id <= MAX_BRIDGE_ID);

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Bridge generation exceeded max id %1$d"),
                   MAX_BRIDGE_ID);
    return -1;
}


/*
 * networkValidateBridgeName() - if no bridge name is set, or if the
 * bridge name contains a %d (indicating that this is a template for
 * the actual name) try to set an appropriate bridge name.  If a
 * bridge name *is* set, make sure it doesn't conflict with any other
 * network's bridge name.
 */
static int
networkBridgeNameValidate(virNetworkObjList *nets,
                          virNetworkDef *def)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&bridgeNameValidateMutex);

    if (def->bridge && !strstr(def->bridge, "%d")) {
        if (virNetworkObjBridgeInUse(nets, def->bridge, def->name)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("bridge name '%1$s' already in use."),
                           def->bridge);
            return -1;
        }
    } else {
        /* Allocate a bridge name */
        if (networkFindUnusedBridgeName(nets, def) < 0)
            return -1;
    }

    return 0;
}


static int
networkValidate(virNetworkDriverState *driver,
                virNetworkDef *def)
{
    size_t i, j;
    bool vlanUsed, vlanAllowed, badVlanUse = false;
    virPortGroupDef *defaultPortGroup = NULL;
    virNetworkIPDef *ipdef;
    bool ipv4def = false, ipv6def = false;
    bool bandwidthAllowed = false;
    bool usesInterface = false, usesAddress = false;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        return -1;

    /* Only the three L3 network types that are configured by libvirt
     * need to have a bridge device name / mac address provided
     */
    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        /* if no bridge name was given in the config, find a name
         * unused by any other libvirt networks and assign it.
         */
        if (networkBridgeNameValidate(driver->networks, def) < 0)
            return -1;

        virNetworkSetBridgeMacAddr(def);
        bandwidthAllowed = true;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->bridge != NULL)
            bandwidthAllowed = true;

        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        /* They are also the only types that currently support setting
         * a MAC or IP address for the host-side device (bridge), DNS
         * configuration, or network-wide bandwidth limits.
         */
        if (def->mac_specified) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <mac> element in network %1$s with forward mode='%2$s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            return -1;
        }
        if (virNetworkDefGetIPByIndex(def, AF_UNSPEC, 0)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <ip> element in network %1$s with forward mode='%2$s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            return -1;
        }
        if (def->dns.ntxts || def->dns.nhosts || def->dns.nsrvs) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <dns> element in network %1$s with forward mode='%2$s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            return -1;
        }
        if (def->domain) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <domain> element in network %1$s with forward mode='%2$s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            return -1;
        }
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return -1;
    }

    if (def->bandwidth &&
        !bandwidthAllowed) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported network-wide <bandwidth> element in network %1$s with forward mode='%2$s'"),
                       def->name,
                       virNetworkForwardTypeToString(def->forward.type));
        return -1;
    }

    /* we support configs with a single PF defined:
     *   <pf dev='eth0'/>
     * or with a list of netdev names:
     *   <interface dev='eth9'/>
     * OR a list of PCI addresses
     *   <address type='pci' domain='0' bus='4' slot='0' function='1'/>
     * but not any combination of those.
     *
     * Since <interface> and <address> are for some strange reason
     * stored in the same array, we need to cycle through it and check
     * the type of each.
     */
    for (i = 0; i < def->forward.nifs; i++) {
        virNetworkForwardIfDef *iface = &def->forward.ifs[i];
        g_autofree char *sysfs_path = NULL;

        switch ((virNetworkForwardHostdevDeviceType)iface->type) {
        case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV:
            usesInterface = true;

            if (def->forward.type == VIR_NETWORK_FORWARD_HOSTDEV) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("hostdev network '%1$s' lists '%2$s' in the device pool, but hostdev networks require all devices to be listed by PCI address, not network device name"),
                               def->name, iface->device.dev);
                return -1;
            }
            break;

        case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI: {
            usesAddress = true;

            if (def->forward.type != VIR_NETWORK_FORWARD_HOSTDEV) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("network '%1$s' has forward mode '%2$s' but lists a device by PCI address in the device pool. This is only supported for networks with forward mode 'hostdev'"),
                               def->name,
                               virNetworkForwardTypeToString(def->forward.type));
                return -1;
            }

            if (virPCIDeviceAddressGetSysfsFile(&iface->device.pci, &sysfs_path) < 0)
                return -1;

            if (!virPCIIsVirtualFunction(sysfs_path)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("device '%1$s' in network '%2$s' is not an SR-IOV Virtual Function"),
                               sysfs_path, def->name);
                return -1;
            }
            break;
        }

        case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NONE:
        case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST:
            break;
        }
    }
    if ((def->forward.npfs > 0) + usesInterface + usesAddress > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("<address>, <interface>, and <pf> elements of <forward> in network %1$s are mutually exclusive"),
                       def->name);
        return -1;
    }

    /* We only support dhcp on one IPv4 address and
     * on one IPv6 address per defined network
     */
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv4def) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Multiple IPv4 dhcp sections found -- dhcp is supported only for a single IPv4 address on each network"));
                    return -1;
                } else {
                    ipv4def = true;
                }
            }
        }
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6)) {
            if (ipdef->nranges || ipdef->nhosts) {
                if (ipv6def) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Multiple IPv6 dhcp sections found -- dhcp is supported only for a single IPv6 address on each network"));
                    return -1;
                } else {
                    ipv6def = true;
                }
            }
        }
    }

    /* The only type of networks that currently support transparent
     * vlan configuration are those using hostdev sr-iov devices from
     * a pool, and those using an Open vSwitch bridge.
     */

    vlanAllowed = (def->forward.type == VIR_NETWORK_FORWARD_HOSTDEV ||
                   def->forward.type == VIR_NETWORK_FORWARD_PASSTHROUGH ||
                   (def->forward.type == VIR_NETWORK_FORWARD_BRIDGE &&
                    def->virtPortProfile &&
                    def->virtPortProfile->virtPortType
                    == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH));

    vlanUsed = def->vlan.nTags > 0;
    for (i = 0; i < def->nPortGroups; i++) {
        if (vlanUsed || def->portGroups[i].vlan.nTags > 0) {
            /* anyone using this portgroup will get a vlan tag. Verify
             * that they will also be using an openvswitch connection,
             * as that is the only type of network that currently
             * supports a vlan tag.
             */
            if (def->portGroups[i].virtPortProfile) {
                if (def->forward.type != VIR_NETWORK_FORWARD_BRIDGE ||
                    def->portGroups[i].virtPortProfile->virtPortType
                    != VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                    badVlanUse = true;
                }
            } else if (!vlanAllowed) {
                /* virtualport taken from base network definition */
                badVlanUse = true;
            }
        }
        if (def->portGroups[i].isDefault) {
            if (defaultPortGroup) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("network '%1$s' has multiple default <portgroup> elements (%2$s and %3$s), but only one default is allowed"),
                               def->name, defaultPortGroup->name,
                               def->portGroups[i].name);
                return -1;
            }
            defaultPortGroup = &def->portGroups[i];
        }
        for (j = i + 1; j < def->nPortGroups; j++) {
            if (STREQ(def->portGroups[i].name, def->portGroups[j].name)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("multiple <portgroup> elements with the same name (%1$s) in network '%2$s'"),
                               def->portGroups[i].name, def->name);
                return -1;
            }
        }
        if (def->portGroups[i].bandwidth && !bandwidthAllowed) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <bandwidth> element in network '%1$s' in portgroup '%2$s' with forward mode='%3$s'"),
                           def->name, def->portGroups[i].name,
                           virNetworkForwardTypeToString(def->forward.type));
            return -1;
        }
    }
    if (badVlanUse ||
        (vlanUsed && !vlanAllowed && !defaultPortGroup)) {
        /* NB: if defaultPortGroup is set, we don't directly look at
         * vlanUsed && !vlanAllowed, because the network will never be
         * used without having a portgroup added in, so all necessary
         * checks were done in the loop above.
         */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("<vlan> element specified for network %1$s, whose type doesn't support vlan configuration"),
                       def->name);
        return -1;
    }

    if (def->forward.type == VIR_NETWORK_FORWARD_HOSTDEV) {
        for (i = 0; i < def->nPortGroups; i++) {
            if (def->portGroups[i].bandwidth) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported <bandwidth> element in <portgroup name='%1$s'> of network '%2$s' with forward mode='%3$s'"),
                               def->portGroups[i].name, def->name,
                               virNetworkForwardTypeToString(def->forward.type));
                return -1;
            }
        }
    }
    return 0;
}


static virNetworkPtr
networkCreateXMLFlags(virConnectPtr conn,
                      const char *xml,
                      unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDef) newDef = NULL;
    virNetworkObj *obj = NULL;
    virNetworkDef *def;
    virNetworkPtr net = NULL;
    virObjectEvent *event = NULL;

    virCheckFlags(VIR_NETWORK_CREATE_VALIDATE, NULL);

    if (!(newDef = virNetworkDefParse(xml, NULL, network_driver->xmlopt,
                                      !!(flags & VIR_NETWORK_CREATE_VALIDATE))))
        goto cleanup;

    if (virNetworkCreateXMLFlagsEnsureACL(conn, newDef) < 0)
        goto cleanup;

    if (networkValidate(driver, newDef) < 0)
        goto cleanup;

    /* NB: even though this transient network hasn't yet been started,
     * we assign the def with live = true in anticipation that it will
     * be started momentarily.
     */
    if (!(obj = virNetworkObjAssignDef(driver->networks, newDef,
                                       VIR_NETWORK_OBJ_LIST_ADD_LIVE |
                                       VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE)))
        goto cleanup;

    newDef = NULL;
    def = virNetworkObjGetDef(obj);

    if (networkStartNetwork(driver, obj) < 0) {
        virNetworkObjRemoveInactive(driver->networks, obj);
        goto cleanup;
    }

    event = virNetworkEventLifecycleNew(def->name,
                                        def->uuid,
                                        VIR_NETWORK_EVENT_STARTED,
                                        0);

    VIR_INFO("Creating network '%s'", def->name);
    net = virGetNetwork(conn, def->name, def->uuid);

 cleanup:
    virObjectEventStateQueue(driver->networkEventState, event);
    virNetworkObjEndAPI(&obj);
    return net;
}


static virNetworkPtr
networkCreateXML(virConnectPtr conn,
                 const char *xml)
{
    return networkCreateXMLFlags(conn, xml, 0);
}


static virNetworkPtr
networkDefineXMLFlags(virConnectPtr conn,
                      const char *xml,
                      unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    g_autoptr(virNetworkDef) def = NULL;
    virNetworkDef *defAlias;
    virNetworkObj *obj = NULL;
    virNetworkPtr net = NULL;
    virObjectEvent *event = NULL;

    virCheckFlags(VIR_NETWORK_DEFINE_VALIDATE, NULL);

    if (!(def = virNetworkDefParse(xml, NULL, network_driver->xmlopt,
                                   !!(flags & VIR_NETWORK_DEFINE_VALIDATE))))
        goto cleanup;

    defAlias = def; /* so we can still ref the object after nullifying def */

    if (virNetworkDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (networkValidate(driver, def) < 0)
        goto cleanup;

    if (!(obj = virNetworkObjAssignDef(driver->networks, def, 0)))
        goto cleanup;

    /* def was assigned to network object so don't autofree */
    def = NULL;

    if (virNetworkSaveConfig(cfg->networkConfigDir,
                             defAlias, network_driver->xmlopt) < 0) {
        if (!virNetworkObjIsActive(obj)) {
            virNetworkObjRemoveInactive(driver->networks, obj);
            goto cleanup;
        }
        /* if network was active already, just undo new persistent
         * definition by making it transient.
         * XXX - this isn't necessarily the correct thing to do.
         */
        virNetworkObjUpdateAssignDef(obj, NULL, false);
        goto cleanup;
    }

    event = virNetworkEventLifecycleNew(defAlias->name, defAlias->uuid,
                                        VIR_NETWORK_EVENT_DEFINED,
                                        0);

    VIR_INFO("Defining network '%s'", defAlias->name);
    net = virGetNetwork(conn, defAlias->name, defAlias->uuid);

 cleanup:
    virObjectEventStateQueue(driver->networkEventState, event);
    virNetworkObjEndAPI(&obj);
    return net;
}


static virNetworkPtr
networkDefineXML(virConnectPtr conn,
                 const char *xml)
{
    return networkDefineXMLFlags(conn, xml, 0);
}


static int
networkUndefine(virNetworkPtr net)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    int ret = -1;
    bool active = false;
    virObjectEvent *event = NULL;

    if (!(obj = networkObjFromNetwork(net)))
        goto cleanup;
    def = virNetworkObjGetDef(obj);

    if (virNetworkUndefineEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if (virNetworkObjIsActive(obj))
        active = true;

    if (!virNetworkObjIsPersistent(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("can't undefine transient network"));
        goto cleanup;
    }

    /* remove autostart link */
    if (virNetworkObjDeleteConfig(cfg->networkConfigDir,
                                  cfg->networkAutostartDir,
                                  obj) < 0)
        goto cleanup;

    event = virNetworkEventLifecycleNew(def->name,
                                        def->uuid,
                                        VIR_NETWORK_EVENT_UNDEFINED,
                                        0);

    VIR_INFO("Undefining network '%s'", def->name);
    if (!active) {
        if (networkRemoveInactive(driver, obj) < 0)
            goto cleanup;
    } else {

        /* if the network still exists, it was active, and we need to make
         * it transient (by deleting the persistent def)
         */
        virNetworkObjUpdateAssignDef(obj, NULL, false);
    }

    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->networkEventState, event);
    virNetworkObjEndAPI(&obj);
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
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj = NULL;
    virNetworkDef *def;
    int isActive, ret = -1;
    size_t i;
    virNetworkIPDef *ipdef;
    bool oldDhcpActive = false;
    bool needFirewallRefresh = false;


    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG,
                  -1);

    if (!(obj = networkObjFromNetwork(net)))
        goto cleanup;
    def = virNetworkObjGetDef(obj);

    if (virNetworkUpdateEnsureACL(net->conn, def, flags) < 0)
        goto cleanup;

    /* see if we are listening for dhcp pre-modification */
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipdef->nranges || ipdef->nhosts || ipdef->tftproot) {
            oldDhcpActive = true;
            break;
        }
    }

    if (virNetworkObjUpdateModificationImpact(obj, &flags) < 0)
        goto cleanup;

    isActive = virNetworkObjIsActive(obj);

    if (isActive && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE)) {
        /* Take care of anything that must be done before updating the
         * live NetworkDef.
         */
        switch ((virNetworkForwardType) def->forward.type) {
        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
            switch (section) {
            case VIR_NETWORK_SECTION_FORWARD:
            case VIR_NETWORK_SECTION_FORWARD_INTERFACE:
            case VIR_NETWORK_SECTION_IP:
            case VIR_NETWORK_SECTION_IP_DHCP_RANGE:
            case VIR_NETWORK_SECTION_IP_DHCP_HOST:
                /* these could affect the firewall rules, so remove the
                 * old rules (and remember to load new ones after the
                 * update).
                 */
                networkRemoveFirewallRules(def);
                needFirewallRefresh = true;
                break;
            default:
                break;
            }
            break;

        case VIR_NETWORK_FORWARD_OPEN:
        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
            break;

        case VIR_NETWORK_FORWARD_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardType, def->forward.type);
            goto cleanup;
        }
    }

    /* update the network config in memory/on disk */
    if (virNetworkObjUpdate(obj, command, section,
                            parentIndex, xml,
                            network_driver->xmlopt, flags) < 0) {
        if (needFirewallRefresh)
            ignore_value(networkAddFirewallRules(def));
        goto cleanup;
    }

    /* @def is replaced */
    def = virNetworkObjGetDef(obj);

    if (needFirewallRefresh && networkAddFirewallRules(def) < 0)
        goto cleanup;

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        /* save updated persistent config to disk */
        if (virNetworkSaveConfig(cfg->networkConfigDir,
                                 virNetworkObjGetPersistentDef(obj),
                                 network_driver->xmlopt) < 0) {
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
            section == VIR_NETWORK_SECTION_IP_DHCP_RANGE ||
            section == VIR_NETWORK_SECTION_DNS_TXT ||
            section == VIR_NETWORK_SECTION_DNS_SRV) {
            /* these sections all change things on the dnsmasq
             * commandline (i.e. in the .conf file), so we need to
             * kill and restart dnsmasq, because dnsmasq sets its uid
             * to "nobody" after it starts, and is unable to re-read
             * the conf file (owned by root, mode 600)
             */
            if (networkRestartDhcpDaemon(driver, obj) < 0)
                goto cleanup;

        } else if (section == VIR_NETWORK_SECTION_IP_DHCP_HOST) {
            /* if we previously weren't listening for dhcp and now we
             * are (or vice-versa) then we need to do a restart,
             * otherwise we just need to do a refresh (redo the config
             * files and send SIGHUP)
             */
            bool newDhcpActive = false;

            for (i = 0; (ipdef = virNetworkDefGetIPByIndex(def, AF_INET, i));
                 i++) {
                if (ipdef->nranges || ipdef->nhosts || ipdef->tftproot) {
                    newDhcpActive = true;
                    break;
                }
            }

            if ((newDhcpActive != oldDhcpActive &&
                 networkRestartDhcpDaemon(driver, obj) < 0) ||
                networkRefreshDhcpDaemon(driver, obj) < 0) {
                goto cleanup;
            }

        } else if (section == VIR_NETWORK_SECTION_DNS_HOST) {
            /* this section only changes data in an external file
             * (not the .conf file) so we can just update the config
             * files and send SIGHUP to dnsmasq.
             */
            if (networkRefreshDhcpDaemon(driver, obj) < 0)
                goto cleanup;

        }

        /* save current network state to disk */
        if ((ret = virNetworkObjSaveStatus(cfg->stateDir,
                                           obj, network_driver->xmlopt)) < 0)
            goto cleanup;
    }

    /* call the 'updated' network hook script */
    if (networkRunHook(obj, NULL, VIR_HOOK_NETWORK_OP_UPDATED,
                       VIR_HOOK_SUBOP_BEGIN) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkCreate(virNetworkPtr net)
{
    virNetworkDriverState *driver = networkGetDriver();
    virNetworkObj *obj;
    virNetworkDef *def;
    int ret = -1;
    virObjectEvent *event = NULL;

    if (!(obj = networkObjFromNetwork(net)))
        goto cleanup;
    def = virNetworkObjGetDef(obj);

    if (virNetworkCreateEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if ((ret = networkStartNetwork(driver, obj)) < 0)
        goto cleanup;

    event = virNetworkEventLifecycleNew(def->name,
                                        def->uuid,
                                        VIR_NETWORK_EVENT_STARTED,
                                        0);

 cleanup:
    virObjectEventStateQueue(driver->networkEventState, event);
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkDestroy(virNetworkPtr net)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    int ret = -1;
    virObjectEvent *event = NULL;

    if (!(obj = networkObjFromNetwork(net)))
        goto cleanup;
    def = virNetworkObjGetDef(obj);

    if (virNetworkDestroyEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    if ((ret = networkShutdownNetwork(driver, obj)) < 0)
        goto cleanup;

    virNetworkObjDeleteAllPorts(obj, cfg->stateDir);

    /* @def replaced in virNetworkObjUnsetDefTransient */
    def = virNetworkObjGetDef(obj);

    event = virNetworkEventLifecycleNew(def->name,
                                        def->uuid,
                                        VIR_NETWORK_EVENT_STOPPED,
                                        0);

    if (!virNetworkObjIsPersistent(obj) &&
        networkRemoveInactive(driver, obj) < 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    virObjectEventStateQueue(driver->networkEventState, event);
    virNetworkObjEndAPI(&obj);
    return ret;
}


static char *
networkGetXMLDesc(virNetworkPtr net,
                  unsigned int flags)
{
    virNetworkObj *obj;
    virNetworkDef *curDef;
    virNetworkDef *def;
    virNetworkDef *newDef;
    char *ret = NULL;

    virCheckFlags(VIR_NETWORK_XML_INACTIVE, NULL);

    if (!(obj = networkObjFromNetwork(net)))
        return ret;
    def = virNetworkObjGetDef(obj);
    newDef = virNetworkObjGetNewDef(obj);

    if (virNetworkGetXMLDescEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if ((flags & VIR_NETWORK_XML_INACTIVE) && newDef)
        curDef = newDef;
    else
        curDef = def;

    ret = virNetworkDefFormat(curDef, network_driver->xmlopt, flags);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static char *
networkGetBridgeName(virNetworkPtr net)
{
    virNetworkObj *obj;
    virNetworkDef *def;
    char *bridge = NULL;

    if (!(obj = networkObjFromNetwork(net)))
        return bridge;
    def = virNetworkObjGetDef(obj);

    if (virNetworkGetBridgeNameEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if (!(def->bridge)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%1$s' does not have a bridge name."),
                       def->name);
        goto cleanup;
    }

    bridge = g_strdup(def->bridge);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return bridge;
}


static int
networkGetAutostart(virNetworkPtr net,
                    int *autostart)
{
    virNetworkObj *obj;
    int ret = -1;

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    if (virNetworkGetAutostartEnsureACL(net->conn, virNetworkObjGetDef(obj)) < 0)
        goto cleanup;

    *autostart = virNetworkObjIsAutostart(obj) ? 1 : 0;
    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkSetAutostart(virNetworkPtr net,
                    int autostart)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;
    bool new_autostart;
    bool cur_autostart;
    int ret = -1;

    if (!(obj = networkObjFromNetwork(net)))
        goto cleanup;
    def = virNetworkObjGetDef(obj);

    if (virNetworkSetAutostartEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if (!virNetworkObjIsPersistent(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot set autostart for transient network"));
        goto cleanup;
    }

    new_autostart = (autostart != 0);
    cur_autostart = virNetworkObjIsAutostart(obj);
    if (cur_autostart != new_autostart) {
        if ((configFile = virNetworkConfigFile(cfg->networkConfigDir,
                                               def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virNetworkConfigFile(cfg->networkAutostartDir,
                                                  def->name)) == NULL)
            goto cleanup;

        if (new_autostart) {
            if (g_mkdir_with_parents(cfg->networkAutostartDir, 0777) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory '%1$s'"),
                                     cfg->networkAutostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%1$s' to '%2$s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%1$s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        virNetworkObjSetAutostart(obj, new_autostart);
    }

    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkGetDHCPLeases(virNetworkPtr net,
                     const char *mac,
                     virNetworkDHCPLeasePtr **leases,
                     unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    size_t i;
    size_t nleases = 0;
    int rv = -1;
    size_t size = 0;
    bool need_results = !!leases;
    long long currtime = 0;
    g_autofree char *lease_entries = NULL;
    g_autofree char *custom_lease_file = NULL;
    g_autoptr(virJSONValue) leases_array = NULL;
    g_autofree virNetworkDHCPLeasePtr *leases_ret = NULL;
    virNetworkObj *obj;
    virNetworkDef *def;
    virMacAddr mac_addr;

    virCheckFlags(0, -1);

    /* only to check if the MAC is valid */
    if (mac && virMacAddrParse(mac, &mac_addr) < 0) {
        virReportError(VIR_ERR_INVALID_MAC, "%s", mac);
        return -1;
    }

    if (!(obj = networkObjFromNetwork(net)))
        return -1;
    def = virNetworkObjGetDef(obj);

    if (virNetworkGetDHCPLeasesEnsureACL(net->conn, def) < 0)
        goto cleanup;

    /* Retrieve custom leases file location */
    custom_lease_file = networkDnsmasqLeaseFileNameCustom(cfg, def->bridge);

    /* Read entire contents */
    if (virFileReadAllQuiet(custom_lease_file,
                            VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX,
                            &lease_entries) < 0) {
        /* Not all networks are guaranteed to have leases file.
         * Only those which run dnsmasq. Therefore, if we failed
         * to read the leases file, don't report error. Return 0
         * leases instead. */
        if (errno == ENOENT) {
            rv = 0;
        } else {
            virReportSystemError(errno,
                                 _("Unable to read leases file: %1$s"),
                                 custom_lease_file);
        }
        goto cleanup;
    }

    if (STREQ(lease_entries, "")) {
        rv = 0;
        goto cleanup;
    }

    if (!(leases_array = virJSONValueFromString(lease_entries))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid json in file: %1$s"), custom_lease_file);
        goto cleanup;
    }

    if (!virJSONValueIsArray(leases_array)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed lease_entries array"));
        goto cleanup;
    }
    size = virJSONValueArraySize(leases_array);

    currtime = (long long)time(NULL);

    for (i = 0; i < size; i++) {
        virJSONValue *lease_tmp = virJSONValueArrayGet(leases_array, i);
        long long expirytime_tmp = -1;
        const char *mac_tmp = NULL;

        if (!lease_tmp) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse json"));
            goto cleanup;
        }

        if (!(mac_tmp = virJSONValueObjectGetString(lease_tmp, "mac-address"))) {
            /* leaseshelper program guarantees that lease will be stored only if
             * mac-address is known otherwise not */
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("found lease without mac-address"));
            goto cleanup;
        }

        if (mac && virMacAddrCompare(mac, mac_tmp))
            continue;

        if (virJSONValueObjectGetNumberLong(lease_tmp, "expiry-time", &expirytime_tmp) < 0) {
            /* A lease cannot be present without expiry-time */
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("found lease without expiry-time"));
            goto cleanup;
        }

        /* Do not report expired lease */
        if (expirytime_tmp > 0 && expirytime_tmp < currtime)
            continue;

        if (need_results) {
            g_autoptr(virNetworkDHCPLease) lease = g_new0(virNetworkDHCPLease, 1);
            const char *ip_tmp = NULL;
            bool ipv6 = false;
            size_t j;

            lease->expirytime = expirytime_tmp;

            if (!(ip_tmp = virJSONValueObjectGetString(lease_tmp, "ip-address"))) {
                /* A lease without ip-address makes no sense */
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("found lease without ip-address"));
                goto cleanup;
            }

            /* Unlike IPv4, IPv6 uses ':' instead of '.' as separator */
            ipv6 = strchr(ip_tmp, ':') ? true : false;
            lease->type = ipv6 ? VIR_IP_ADDR_TYPE_IPV6 : VIR_IP_ADDR_TYPE_IPV4;

            /* Obtain prefix */
            for (j = 0; j < def->nips; j++) {
                virNetworkIPDef *ipdef_tmp = &def->ips[j];

                if (ipv6 && VIR_SOCKET_ADDR_IS_FAMILY(&ipdef_tmp->address,
                                                      AF_INET6)) {
                    lease->prefix = ipdef_tmp->prefix;
                    break;
                }
                if (!ipv6 && VIR_SOCKET_ADDR_IS_FAMILY(&ipdef_tmp->address,
                                                       AF_INET)) {
                    lease->prefix = virSocketAddrGetIPPrefix(&ipdef_tmp->address,
                                                             &ipdef_tmp->netmask,
                                                             ipdef_tmp->prefix);
                    break;
                }
            }

            lease->mac = g_strdup(mac_tmp);
            lease->ipaddr = g_strdup(ip_tmp);
            lease->iface = g_strdup(def->bridge);

            /* Fields that can be NULL */
            lease->iaid = g_strdup(virJSONValueObjectGetString(lease_tmp, "iaid"));
            lease->clientid = g_strdup(virJSONValueObjectGetString(lease_tmp, "client-id"));
            lease->hostname = g_strdup(virJSONValueObjectGetString(lease_tmp, "hostname"));

            VIR_APPEND_ELEMENT(leases_ret, nleases, lease);
        } else {
            nleases++;
        }
    }

    if (leases_ret) {
        /* NULL terminated array */
        leases_ret = g_renew(virNetworkDHCPLeasePtr, leases_ret, nleases + 1);
        *leases = g_steal_pointer(&leases_ret);
    }

    rv = nleases;

 cleanup:
    virNetworkObjEndAPI(&obj);
    if (leases_ret) {
        for (i = 0; i < nleases; i++)
            virNetworkDHCPLeaseFree(leases_ret[i]);
    }
    return rv;
}


/* A unified function to log network connections and disconnections */

static void
networkLogAllocation(virNetworkDef *netdef,
                     virNetworkForwardIfDef *dev,
                     virMacAddr *mac,
                     bool inUse)
{
    char macStr[VIR_MAC_STRING_BUFLEN];
    const char *verb = inUse ? "using" : "releasing";

    virMacAddrFormat(mac, macStr);
    if (!dev) {
        VIR_INFO("MAC %s %s network %s (%d connections)",
                 macStr, verb, netdef->name, netdef->connections);
    } else {
        if (dev->type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI) {
            VIR_INFO("MAC %s %s network %s (%d connections) "
                     "physical device %04x:%02x:%02x.%x (%d connections)",
                     macStr, verb, netdef->name, netdef->connections,
                     dev->device.pci.domain, dev->device.pci.bus,
                     dev->device.pci.slot, dev->device.pci.function,
                     dev->connections);
        } else {
            VIR_INFO("MAC %s %s network %s (%d connections) "
                     "physical device %s (%d connections)",
                     macStr, verb, netdef->name, netdef->connections,
                     dev->device.dev, dev->connections);
        }
    }
}


/* Private API to deal with logical switch capabilities.
 * These functions are exported so that other parts of libvirt can
 * call them, but are not part of the public API and not in the
 * driver's function table. If we ever have more than one network
 * driver, we will need to present these functions via a second
 * "backend" function table.
 */

/* networkAllocatePort:
 * @obj: the network to allocate from
 * @port: the port definition to allocate
 *
 * Looks up the network reference by port, allocates a physical
 * device from that network (if appropriate), and returns with the
 * port configuration filled in accordingly.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
networkAllocatePort(virNetworkObj *obj,
                    virNetworkPortDef *port)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *netdef = NULL;
    virPortGroupDef *portgroup = NULL;
    virNetworkForwardIfDef *dev = NULL;
    size_t i;
    virNetDevVPortProfile *portprofile = NULL;

    netdef = virNetworkObjGetDef(obj);
    VIR_DEBUG("Allocating port from net %s", netdef->name);

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       netdef->name);
        return -1;
    }

    VIR_DEBUG("Interface port group %s", port->group);
    /* portgroup can be present for any type of network, in particular
     * for bandwidth information, so we need to check for that and
     * fill it in appropriately for all forward types.
     */
    portgroup = virPortGroupFindByName(netdef, port->group);

    if (!port->bandwidth) {
        if (portgroup && portgroup->bandwidth &&
            virNetDevBandwidthCopy(&port->bandwidth,
                                   portgroup->bandwidth) < 0)
            return -1;
    }

    if (port->vlan.nTags == 0) {
        virNetDevVlan *vlan = NULL;
        if (portgroup && portgroup->vlan.nTags > 0)
            vlan = &portgroup->vlan;
        else if (netdef->vlan.nTags > 0)
            vlan = &netdef->vlan;

        if (vlan && virNetDevVlanCopy(&port->vlan, vlan) < 0)
            return -1;
    }

    if (!port->trustGuestRxFilters) {
        if (portgroup && portgroup->trustGuestRxFilters)
            port->trustGuestRxFilters = portgroup->trustGuestRxFilters;
        else if (netdef->trustGuestRxFilters)
            port->trustGuestRxFilters = netdef->trustGuestRxFilters;
    }

    if (port->isolatedPort == VIR_TRISTATE_BOOL_ABSENT)
        port->isolatedPort = netdef->isolatedPort;

    /* merge virtualports from interface, network, and portgroup to
     * arrive at actual virtualport to use
     */
    if (virNetDevVPortProfileMerge3(&portprofile,
                                    port->virtPortProfile,
                                    netdef->virtPortProfile,
                                    portgroup
                                    ? portgroup->virtPortProfile : NULL) < 0) {
                return -1;
    }
    if (portprofile) {
        g_free(port->virtPortProfile);
        port->virtPortProfile = portprofile;
    }

    VIR_DEBUG("Processing forward type %d", netdef->forward.type);
    switch ((virNetworkForwardType) netdef->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        /* for these forward types, the actual net type really *is*
         * NETWORK; we just keep the info from the portgroup in
         * iface->data.network.actual
         */
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_NETWORK;

        port->plug.bridge.brname = g_strdup(netdef->bridge);
        port->plug.bridge.macTableManager = netdef->macTableManager;

        if (port->virtPortProfile) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("<virtualport type='%1$s'> not supported for network '%2$s' which uses IP forwarding"),
                           virNetDevVPortTypeToString(port->virtPortProfile->virtPortType),
                           netdef->name);
            return -1;
        }

        break;

    case VIR_NETWORK_FORWARD_HOSTDEV: {
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI;

        if (networkCreateInterfacePool(netdef) < 0)
            return -1;

        /* pick first dev with 0 connections */
        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].connections == 0) {
                dev = &netdef->forward.ifs[i];
                break;
            }
        }
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' requires exclusive access to interfaces, but none are available"),
                           netdef->name);
            return -1;
        }
        port->plug.hostdevpci.addr = dev->device.pci;
        port->plug.hostdevpci.driver = netdef->forward.driverName;
        port->plug.hostdevpci.managed = virTristateBoolFromBool(netdef->forward.managed);

        if (port->virtPortProfile) {
            /* make sure type is supported for hostdev connections */
            if (port->virtPortProfile->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBG &&
                port->virtPortProfile->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("<virtualport type='%1$s'> not supported for network '%2$s' which uses an SR-IOV Virtual Function via PCI passthrough"),
                               virNetDevVPortTypeToString(port->virtPortProfile->virtPortType),
                               netdef->name);
                return -1;
            }
        }
        break;
    }

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (netdef->bridge) {
            /* <forward type='bridge'/> <bridge name='xxx'/>
             * is VIR_DOMAIN_NET_TYPE_BRIDGE
             */

            port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE;
            port->plug.bridge.brname = g_strdup(netdef->bridge);
            port->plug.bridge.macTableManager = netdef->macTableManager;

            if (port->virtPortProfile) {
                /* only type='openvswitch' is allowed for bridges */
                if (port->virtPortProfile->virtPortType != VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("<virtualport type='%1$s'> not supported for network '%2$s' which uses a bridge device"),
                                   virNetDevVPortTypeToString(port->virtPortProfile->virtPortType),
                                   netdef->name);
                    return -1;
                }
            }

            break;
        }

        /* intentionally fall through to the direct case for
         * VIR_NETWORK_FORWARD_BRIDGE with no bridge device defined
         */
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        /* <forward type='bridge|private|vepa|passthrough'> are all
         * VIR_DOMAIN_NET_TYPE_DIRECT.
         */

        /* Set type=direct and appropriate <source mode='xxx'/> */
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_DIRECT;

        /* NO need to check the value returned from virNetDevMacVLanModeTypeFromString
         * it must be valid for these forward type(bridge|private|vepa|passthrough)
         */
        port->plug.direct.mode =
            virNetDevMacVLanModeTypeFromString(virNetworkForwardTypeToString(netdef->forward.type));

        if (port->virtPortProfile) {
            /* make sure type is supported for macvtap connections */
            if (port->virtPortProfile->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBG &&
                port->virtPortProfile->virtPortType != VIR_NETDEV_VPORT_PROFILE_8021QBH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("<virtualport type='%1$s'> not supported for network '%2$s' which uses a macvtap device"),
                               virNetDevVPortTypeToString(port->virtPortProfile->virtPortType),
                               netdef->name);
                return -1;
            }
        }

        /* If there is only a single device, just return it (caller will detect
         * any error if exclusive use is required but could not be acquired).
         */
        if ((netdef->forward.nifs <= 0) && (netdef->forward.npfs <= 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' uses a direct mode, but has no forward dev and no interface pool"),
                           netdef->name);
            return -1;
        } else {
            /* pick an interface from the pool */

            if (networkCreateInterfacePool(netdef) < 0)
                return -1;

            /* PASSTHROUGH mode, and PRIVATE Mode + 802.1Qbh both
             * require exclusive access to a device, so current
             * connections count must be 0.  Other modes can share, so
             * just search for the one with the lowest number of
             * connections.
             */
            if ((netdef->forward.type == VIR_NETWORK_FORWARD_PASSTHROUGH) ||
                ((netdef->forward.type == VIR_NETWORK_FORWARD_PRIVATE) &&
                 port->virtPortProfile &&
                 (port->virtPortProfile->virtPortType
                  == VIR_NETDEV_VPORT_PROFILE_8021QBH))) {

                /* pick first dev with 0 connections */
                for (i = 0; i < netdef->forward.nifs; i++) {
                    if (netdef->forward.ifs[i].connections == 0) {
                        dev = &netdef->forward.ifs[i];
                        break;
                    }
                }
            } else {
                /* pick least used dev */
                dev = &netdef->forward.ifs[0];
                for (i = 1; i < netdef->forward.nifs; i++) {
                    if (netdef->forward.ifs[i].connections < dev->connections)
                        dev = &netdef->forward.ifs[i];
                }
            }
            /* dev points at the physical device we want to use */
            if (!dev) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("network '%1$s' requires exclusive access to interfaces, but none are available"),
                               netdef->name);
                return -1;
            }
            port->plug.direct.linkdev = g_strdup(dev->device.dev);
        }
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, netdef->forward.type);
        return -1;
    }


    if (networkPlugBandwidth(obj, &port->mac, port->bandwidth,
                             &port->class_id) < 0)
        return -1;

    if (virNetworkObjMacMgrAdd(obj, cfg->dnsmasqStateDir,
                               port->ownername, &port->mac) < 0)
        return -1;

    if (virNetDevVPortProfileCheckComplete(port->virtPortProfile, true) < 0)
        return -1;

    netdef->connections++;
    if (dev)
        dev->connections++;
    /* finally we can call the 'plugged' hook script if any */
    if (networkRunHook(obj, port,
                       VIR_HOOK_NETWORK_OP_PORT_CREATED,
                       VIR_HOOK_SUBOP_BEGIN) < 0) {
        /* adjust for failure */
        netdef->connections--;
        if (dev)
            dev->connections--;
        return -1;
    }
    networkLogAllocation(netdef, dev, &port->mac, true);

    VIR_DEBUG("Port allocated");

    return 0;
}


/* networkNotifyPort:
 * @obj: the network to notify
 * @port: the port definition to notify
 *
 * Called to notify the network driver when libvirtd is restarted and
 * finds an already running domain. If appropriate it will force an
 * allocation of the actual->direct.linkdev to get everything back in
 * order.
 */
static int
networkNotifyPort(virNetworkObj *obj,
                  virNetworkPortDef *port)
{
    virNetworkDef *netdef;
    virNetworkForwardIfDef *dev = NULL;
    size_t i;

    netdef = virNetworkObjGetDef(obj);

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       netdef->name);
        return -1;
    }

    switch (port->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpectedly got a network port without a plug"));
        return -1;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        /* see if we're connected to the correct bridge */
        if (!netdef->bridge) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unexpectedly got a network port without a network bridge"));
            return -1;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        if (networkCreateInterfacePool(netdef) < 0)
            return -1;

        /* find the matching interface and increment its connections */
        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
                STREQ(port->plug.direct.linkdev,
                      netdef->forward.ifs[i].device.dev)) {
                dev = &netdef->forward.ifs[i];
                break;
            }
        }
        /* dev points at the physical device we want to use */
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' doesn't have dev='%2$s' in use by network port '%3$s'"),
                           netdef->name, port->plug.direct.linkdev,
                           port->uuid);
            return -1;
        }

        /* PASSTHROUGH mode and PRIVATE Mode + 802.1Qbh both require
         * exclusive access to a device, so current connections count
         * must be 0 in those cases.
         */
        if ((dev->connections > 0) &&
            ((netdef->forward.type == VIR_NETWORK_FORWARD_PASSTHROUGH) ||
             ((netdef->forward.type == VIR_NETWORK_FORWARD_PRIVATE) &&
              port->virtPortProfile &&
              (port->virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_8021QBH)))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' claims dev='%2$s' is already in use by a different port"),
                           netdef->name, port->plug.direct.linkdev);
            return -1;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:

        if (networkCreateInterfacePool(netdef) < 0)
            return -1;

        /* find the matching interface and increment its connections */
        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI &&
                virPCIDeviceAddressEqual(&port->plug.hostdevpci.addr,
                                         &netdef->forward.ifs[i].device.pci)) {
                dev = &netdef->forward.ifs[i];
                break;
            }
        }
        /* dev points at the physical device we want to use */
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' doesn't have PCI device %2$04x:%3$02x:%4$02x.%5$x in use by network port"),
                           netdef->name,
                           port->plug.hostdevpci.addr.domain,
                           port->plug.hostdevpci.addr.bus,
                           port->plug.hostdevpci.addr.slot,
                           port->plug.hostdevpci.addr.function);
            return -1;
        }

        /* PASSTHROUGH mode, PRIVATE Mode + 802.1Qbh, and hostdev (PCI
         * passthrough) all require exclusive access to a device, so
         * current connections count must be 0 in those cases.
         */
        if ((dev->connections > 0) &&
            netdef->forward.type == VIR_NETWORK_FORWARD_HOSTDEV) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' claims the PCI device at domain=%2$d bus=%3$d slot=%4$d function=%5$d is already in use by a different network port"),
                           netdef->name,
                           dev->device.pci.domain, dev->device.pci.bus,
                           dev->device.pci.slot, dev->device.pci.function);
            return -1;
        }

        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, port->plugtype);
        return -1;
    }

    netdef->connections++;
    if (dev)
        dev->connections++;
    /* finally we can call the 'plugged' hook script if any */
    if (networkRunHook(obj, port, VIR_HOOK_NETWORK_OP_PORT_CREATED,
                       VIR_HOOK_SUBOP_BEGIN) < 0) {
        /* adjust for failure */
        if (dev)
            dev->connections--;
        netdef->connections--;
        return -1;
    }
    networkLogAllocation(netdef, dev, &port->mac, true);

    return 0;
}


/* networkReleasePort:
 * @obj: the network to release from
 * @port: the port definition to release
 *
 * Given a domain <interface> element that previously had its <actual>
 * element filled in (and possibly a physical device allocated to it),
 * free up the physical device for use by someone else, and free the
 * virDomainActualNetDef.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
networkReleasePort(virNetworkObj *obj,
                   virNetworkPortDef *port)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *netdef;
    virNetworkForwardIfDef *dev = NULL;
    size_t i;

    netdef = virNetworkObjGetDef(obj);

    switch ((virNetworkPortPlugType)port->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        VIR_DEBUG("Releasing network device with no plug type");
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        if (networkUnplugBandwidth(obj, port->bandwidth,
                                   &port->class_id) < 0)
            return -1;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        if (netdef->forward.nifs == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' uses a direct mode, but has no forward dev and no interface pool"),
                           netdef->name);
            return -1;
        }

        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
                STREQ(port->plug.direct.linkdev, netdef->forward.ifs[i].device.dev)) {
                dev = &netdef->forward.ifs[i];
                break;
            }
        }

        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' doesn't have dev='%2$s' in use by domain"),
                           netdef->name, port->plug.direct.linkdev);
            return -1;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        if (netdef->forward.nifs == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' uses a hostdev mode, but has no forward dev and no interface pool"),
                           netdef->name);
            return -1;
        }

        for (i = 0; i < netdef->forward.nifs; i++) {
            if (netdef->forward.ifs[i].type
                == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI &&
                virPCIDeviceAddressEqual(&port->plug.hostdevpci.addr,
                                         &netdef->forward.ifs[i].device.pci)) {
                dev = &netdef->forward.ifs[i];
                break;
            }
        }

        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' doesn't have PCI device %2$04x:%3$02x:%4$02x.%5$x in use by domain"),
                           netdef->name,
                           port->plug.hostdevpci.addr.domain,
                           port->plug.hostdevpci.addr.bus,
                           port->plug.hostdevpci.addr.slot,
                           port->plug.hostdevpci.addr.function);
            return -1;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, port->plugtype);
        return -1;
    }

    virNetworkObjMacMgrDel(obj, cfg->dnsmasqStateDir, port->ownername, &port->mac);

    netdef->connections--;
    if (dev)
        dev->connections--;
    /* finally we can call the 'unplugged' hook script if any */
    networkRunHook(obj, port, VIR_HOOK_NETWORK_OP_PORT_DELETED,
                   VIR_HOOK_SUBOP_BEGIN);
    networkLogAllocation(netdef, dev, &port->mac, false);

    return 0;
}


/**
 * networkCheckBandwidth:
 * @net: network QoS
 * @ifaceBand: interface QoS (may be NULL if no QoS)
 * @oldBandwidth: new interface QoS (may be NULL if no QoS)
 * @ifaceMac: interface MAC (used in error messages for identification)
 * @new_rate: new rate for non guaranteed class
 *
 * Function checks if @ifaceBand can be satisfied on @net. However, sometimes it
 * may happen that the interface that @ifaceBand corresponds to is already
 * plugged into the @net and the bandwidth is to be updated. In that case we
 * need to check if new bandwidth can be satisfied. If that's the case
 * @ifaceBand should point to new bandwidth settings and @oldBandwidth to
 * current ones. If you want to suppress this functionality just pass
 * @oldBandwidth == NULL.
 *
 * Returns: -1 if plugging would overcommit network QoS
 *           0 if plugging is safe (@new_rate updated)
 *           1 if no QoS is set (@new_rate untouched)
 */
static int
networkCheckBandwidth(virNetworkObj *obj,
                      virNetDevBandwidth *ifaceBand,
                      virNetDevBandwidth *oldBandwidth,
                      virMacAddr *ifaceMac,
                      unsigned long long *new_rate)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    virNetDevBandwidth *netBand = def->bandwidth;
    unsigned long long tmp_floor_sum = virNetworkObjGetFloorSum(obj);
    unsigned long long tmp_new_rate = 0;
    char ifmac[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(ifaceMac, ifmac);

    if (virNetDevBandwidthHasFloor(ifaceBand) &&
        !virNetDevBandwidthSupportsFloor(def->forward.type)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Invalid use of 'floor' on interface with MAC address %1$s - 'floor' is only supported for interface type 'network' with forward type 'nat', 'route', 'open' or none"),
                       ifmac);
        return -1;
    }

    if (virNetDevBandwidthHasFloor(ifaceBand) &&
        !(netBand && netBand->in)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Invalid use of 'floor' on interface with MAC address %1$s - network '%2$s' has no inbound QoS set"),
                       ifmac, def->name);
        return -1;
    }

    if (!netBand || !netBand->in) {
        VIR_DEBUG("No network bandwidth controls present");
        /* no QoS required, claim success */
        return 1;
    }
    if (!virNetDevBandwidthHasFloor(ifaceBand) &&
        !virNetDevBandwidthHasFloor(oldBandwidth)) {

        VIR_DEBUG("No old/new interface bandwidth floor");
        /* no QoS required, claim success */
        return 1;
    }

    tmp_new_rate = netBand->in->average;
    if (oldBandwidth && oldBandwidth->in)
        tmp_floor_sum -= oldBandwidth->in->floor;
    if (ifaceBand && ifaceBand->in)
        tmp_floor_sum += ifaceBand->in->floor;

    /* check against peak */
    if (netBand->in->peak) {
        tmp_new_rate = netBand->in->peak;
        if (tmp_floor_sum > netBand->in->peak) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Cannot plug '%1$s' interface into '%2$s' because new combined inbound floor=%3$llu would overcommit peak=%4$llu on network '%5$s'"),
                           ifmac,
                           def->bridge,
                           tmp_floor_sum,
                           netBand->in->peak,
                           def->name);
            return -1;
        }
    } else if (tmp_floor_sum > netBand->in->average) {
        /* tmp_floor_sum can be between 'average' and 'peak' iff 'peak' is set.
         * Otherwise, tmp_floor_sum must be below 'average'. */
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Cannot plug '%1$s' interface into '%2$s' because new combined inbound floor=%3$llu would overcommit average=%4$llu on network '%5$s'"),
                       ifmac,
                       def->bridge,
                       tmp_floor_sum,
                       netBand->in->average,
                       def->name);
        return -1;
    }

    if (new_rate)
        *new_rate = tmp_new_rate;

    return 0;
}


/**
 * networkNextClassID:
 * @net: network object
 *
 * Find next free class ID. @net is supposed
 * to be locked already. If there is a free ID,
 * it is marked as used and returned.
 *
 * Returns next free class ID or -1 if none is available.
 */
static ssize_t
networkNextClassID(virNetworkObj *obj)
{
    ssize_t ret = 0;
    virBitmap *classIdMap = virNetworkObjGetClassIdMap(obj);

    if ((ret = virBitmapNextClearBit(classIdMap, -1)) < 0)
        ret = virBitmapSize(classIdMap);

    virBitmapSetBitExpand(classIdMap, ret);

    return ret;
}


static int
networkPlugBandwidthImpl(virNetworkObj *obj,
                         virMacAddr *mac,
                         virNetDevBandwidth *ifaceBand,
                         unsigned int *class_id,
                         unsigned long long new_rate)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def = virNetworkObjGetDef(obj);
    virBitmap *classIdMap = virNetworkObjGetClassIdMap(obj);
    unsigned long long tmp_floor_sum = virNetworkObjGetFloorSum(obj);
    ssize_t next_id = 0;
    int plug_ret;

    /* generate new class_id */
    if ((next_id = networkNextClassID(obj)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not generate next class ID"));
        return -1;
    }

    plug_ret = virNetDevBandwidthPlug(def->bridge, def->bandwidth,
                                      mac, ifaceBand, next_id);
    if (plug_ret < 0) {
        ignore_value(virNetDevBandwidthUnplug(def->bridge, next_id));
        return -1;
    }

    /* QoS was set, generate new class ID */
    *class_id = next_id;
    /* update sum of 'floor'-s of attached NICs */
    tmp_floor_sum += ifaceBand->in->floor;
    virNetworkObjSetFloorSum(obj, tmp_floor_sum);
    /* update status file */
    if (virNetworkObjSaveStatus(cfg->stateDir, obj, network_driver->xmlopt) < 0) {
        ignore_value(virBitmapClearBit(classIdMap, next_id));
        tmp_floor_sum -= ifaceBand->in->floor;
        virNetworkObjSetFloorSum(obj, tmp_floor_sum);
        *class_id = 0;
        ignore_value(virNetDevBandwidthUnplug(def->bridge, next_id));
        return -1;
    }
    /* update rate for non guaranteed NICs */
    new_rate -= tmp_floor_sum;
    if (virNetDevBandwidthUpdateRate(def->bridge, 2,
                                     def->bandwidth, new_rate) < 0)
        VIR_WARN("Unable to update rate for 1:2 class on %s bridge",
                 def->bridge);

    return 0;
}


static int
networkPlugBandwidth(virNetworkObj *obj,
                     virMacAddr *mac,
                     virNetDevBandwidth *ifaceBand,
                     unsigned int *class_id)
{
    int plug_ret;
    unsigned long long new_rate = 0;
    char ifmac[VIR_MAC_STRING_BUFLEN];

    if ((plug_ret = networkCheckBandwidth(obj, ifaceBand, NULL,
                                          mac, &new_rate)) < 0) {
        /* helper reported error */
        return -1;
    }

    if (plug_ret > 0)
        /* no QoS needs to be set; claim success */
        return 0;

    virMacAddrFormat(mac, ifmac);

    if (networkPlugBandwidthImpl(obj, mac, ifaceBand, class_id, new_rate) < 0)
        return -1;

    return 0;
}


static int
networkUnplugBandwidth(virNetworkObj *obj,
                       virNetDevBandwidth *ifaceBand,
                       unsigned int *class_id)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    virBitmap *classIdMap = virNetworkObjGetClassIdMap(obj);
    unsigned long long tmp_floor_sum = virNetworkObjGetFloorSum(obj);
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    int ret = 0;
    unsigned long long new_rate;

    if (class_id && *class_id) {
        if (!def->bandwidth || !def->bandwidth->in) {
            VIR_WARN("Network %s has no bandwidth but unplug requested",
                     def->name);
            return 0;
        }
        /* we must remove class from bridge */
        new_rate = def->bandwidth->in->average;

        if (def->bandwidth->in->peak > 0)
            new_rate = def->bandwidth->in->peak;

        ret = virNetDevBandwidthUnplug(def->bridge, *class_id);
        if (ret < 0)
            return ret;
        /* update sum of 'floor'-s of attached NICs */
        tmp_floor_sum -= ifaceBand->in->floor;
        virNetworkObjSetFloorSum(obj, tmp_floor_sum);

        /* return class ID */
        ignore_value(virBitmapClearBit(classIdMap, *class_id));
        /* update status file */
        if (virNetworkObjSaveStatus(cfg->stateDir,
                                    obj, network_driver->xmlopt) < 0) {
            tmp_floor_sum += ifaceBand->in->floor;
            virNetworkObjSetFloorSum(obj, tmp_floor_sum);
            ignore_value(virBitmapSetBit(classIdMap, *class_id));
            return ret;
        }
        /* update rate for non guaranteed NICs */
        new_rate -= tmp_floor_sum;
        if (virNetDevBandwidthUpdateRate(def->bridge, 2,
                                         def->bandwidth, new_rate) < 0)
            VIR_WARN("Unable to update rate for 1:2 class on %s bridge",
                     def->bridge);
        /* no class is associated any longer */
        *class_id = 0;
    }

    return ret;
}


static void
networkNetworkObjTaint(virNetworkObj *obj,
                       virNetworkTaintFlags taint)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);

    if (virNetworkObjTaint(obj, taint)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(def->uuid, uuidstr);

        VIR_WARN("Network name='%s' uuid=%s is tainted: %s",
                 def->name, uuidstr, virNetworkTaintTypeToString(taint));
    }
}


static int
networkUpdatePortBandwidth(virNetworkObj *obj,
                           virMacAddr *mac,
                           unsigned int *class_id,
                           virNetDevBandwidth *oldBandwidth,
                           virNetDevBandwidth *newBandwidth)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkDef *def;
    unsigned long long tmp_floor_sum;
    unsigned long long new_rate = 0;
    unsigned long long old_floor, new_floor;
    int plug_ret;

    old_floor = new_floor = 0;

    if (oldBandwidth && oldBandwidth->in)
        old_floor = oldBandwidth->in->floor;
    if (newBandwidth && newBandwidth->in)
        new_floor = newBandwidth->in->floor;

    if (new_floor == old_floor)
        return 0;

    def = virNetworkObjGetDef(obj);

    if ((plug_ret = networkCheckBandwidth(obj, newBandwidth, oldBandwidth,
                                          mac, &new_rate)) < 0) {
        /* helper reported error */
        return -1;
    }

    if (plug_ret > 0) {
        /* no QoS needs to be set; claim success */
        return 0;
    }

    /* Okay, there are three possible scenarios: */

    if (old_floor > 0 && new_floor > 0) {
        /* Either we just need to update @floor .. */

        if (virNetDevBandwidthUpdateRate(def->bridge,
                                         *class_id,
                                         def->bandwidth,
                                         new_floor) < 0)
            return -1;

        tmp_floor_sum = virNetworkObjGetFloorSum(obj);
        tmp_floor_sum -= old_floor;
        tmp_floor_sum += new_floor;
        virNetworkObjSetFloorSum(obj, tmp_floor_sum);
        new_rate -= tmp_floor_sum;

        if (virNetDevBandwidthUpdateRate(def->bridge, 2,
                                         def->bandwidth, new_rate) < 0 ||
            virNetworkObjSaveStatus(cfg->stateDir,
                                    obj, network_driver->xmlopt) < 0) {
            /* Ouch, rollback */
            tmp_floor_sum -= new_floor;
            tmp_floor_sum += old_floor;
            virNetworkObjSetFloorSum(obj, tmp_floor_sum);

            ignore_value(virNetDevBandwidthUpdateRate(def->bridge,
                                                      *class_id,
                                                      def->bandwidth,
                                                      old_floor));
            return -1;
        }
    } else if (new_floor > 0) {
        /* .. or we need to plug in new .. */

        if (networkPlugBandwidthImpl(obj, mac, newBandwidth,
                                     class_id,
                                     new_rate) < 0)
            return -1;
    } else {
        /* .. or unplug old. */

        if (networkUnplugBandwidth(obj, oldBandwidth, class_id) < 0)
            return -1;
    }

    return 0;
}


static virNetworkPortPtr
networkPortLookupByUUID(virNetworkPtr net,
                        const unsigned char *uuid)
{
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPortDef *portdef = NULL;
    virNetworkPortPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(uuid, uuidstr);

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkObjLookupPort(obj, uuid)))
        goto cleanup;

    if (virNetworkPortLookupByUUIDEnsureACL(net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    ret = virGetNetworkPort(net, uuid);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static virNetworkPortPtr
networkPortCreateXML(virNetworkPtr net,
                     const char *xmldesc,
                     unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    g_autoptr(virNetworkPortDef) portdef = NULL;
    virNetworkPortPtr ret = NULL;
    int rc;

    virCheckFlags(VIR_NETWORK_PORT_CREATE_RECLAIM |
                  VIR_NETWORK_PORT_CREATE_VALIDATE, NULL);

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkPortDefParse(xmldesc, NULL, flags)))
        goto cleanup;

    if (virNetworkPortCreateXMLEnsureACL(net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    if (portdef->plugtype == VIR_NETWORK_PORT_PLUG_TYPE_NONE) {
        if (flags & VIR_NETWORK_PORT_CREATE_RECLAIM) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Port reclaim requested but plug type is none"));
            goto cleanup;
        }
    } else {
        if (!(flags & VIR_NETWORK_PORT_CREATE_RECLAIM)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Port reclaim not requested but plug type is not none"));
            goto cleanup;
        }
    }

    if (flags & VIR_NETWORK_PORT_CREATE_RECLAIM)
        rc = networkNotifyPort(obj, portdef);
    else
        rc = networkAllocatePort(obj, portdef);
    if (rc < 0)
        goto cleanup;

    if (virNetworkObjAddPort(obj, portdef, cfg->stateDir) < 0) {
        virErrorPtr save_err;

        virErrorPreserveLast(&save_err);
        ignore_value(networkReleasePort(obj, portdef));
        virErrorRestore(&save_err);

        goto cleanup;
    }

    ret = virGetNetworkPort(net, portdef->uuid);
    portdef = NULL;
 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static char *
networkPortGetXMLDesc(virNetworkPortPtr port,
                      unsigned int flags)
{
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPortDef *portdef = NULL;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (!(obj = networkObjFromNetwork(port->net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkObjLookupPort(obj, port->uuid)))
        goto cleanup;

    if (virNetworkPortGetXMLDescEnsureACL(port->net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

   if (!(ret = virNetworkPortDefFormat(portdef)))
       goto cleanup;

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkPortDelete(virNetworkPortPtr port,
                  unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPortDef *portdef;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = networkObjFromNetwork(port->net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkObjLookupPort(obj, port->uuid)))
        goto cleanup;

    if (virNetworkPortDeleteEnsureACL(port->net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    if (networkReleasePort(obj, portdef) < 0)
        goto cleanup;

    virNetworkObjDeletePort(obj, port->uuid, cfg->stateDir);

    ret = 0;
 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkPortSetParameters(virNetworkPortPtr port,
                         virTypedParameterPtr params,
                         int nparams,
                         unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    g_autoptr(virNetworkDriverConfig) cfg = virNetworkDriverGetConfig(driver);
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPortDef *portdef;
    g_autoptr(virNetDevBandwidth) bandwidth = NULL;
    g_autofree char *dir = NULL;
    int ret = -1;
    size_t i;

    virCheckFlags(0, -1);

    if (!(obj = networkObjFromNetwork(port->net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkObjLookupPort(obj, port->uuid)))
        goto cleanup;

    if (virNetworkPortSetParametersEnsureACL(port->net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    if (!(dir = virNetworkObjGetPortStatusDir(obj, cfg->stateDir)))
        goto cleanup;

    bandwidth = g_new0(virNetDevBandwidth, 1);
    bandwidth->in = g_new0(virNetDevBandwidthRate, 1);
    bandwidth->out = g_new0(virNetDevBandwidthRate, 1);

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_IN_AVERAGE)) {
            bandwidth->in->average = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_IN_PEAK)) {
            bandwidth->in->peak = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_IN_BURST)) {
            bandwidth->in->burst = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_IN_FLOOR)) {
            bandwidth->in->floor = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_OUT_AVERAGE)) {
            bandwidth->out->average = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_OUT_PEAK)) {
            bandwidth->out->peak = param->value.ui;
        } else if (STREQ(param->field, VIR_NETWORK_PORT_BANDWIDTH_OUT_BURST)) {
            bandwidth->out->burst = param->value.ui;
        }
    }

    /* average or floor are mandatory, peak and burst are optional.
     * So if no average or floor is given, we free inbound/outbound
     * here which causes inbound/outbound to not be set. */
    if (!bandwidth->in->average && !bandwidth->in->floor)
        g_clear_pointer(&bandwidth->in, g_free);

    if (!bandwidth->out->average)
        g_clear_pointer(&bandwidth->out, g_free);

    if (networkUpdatePortBandwidth(obj,
                                   &portdef->mac,
                                   &portdef->class_id,
                                   portdef->bandwidth,
                                   bandwidth) < 0)
        goto cleanup;

    virNetDevBandwidthFree(portdef->bandwidth);
    portdef->bandwidth = g_steal_pointer(&bandwidth);

    if (virNetworkPortDefSaveStatus(portdef, dir) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkPortGetParameters(virNetworkPortPtr port,
                         virTypedParameterPtr *params,
                         int *nparams,
                         unsigned int flags)
{
    virNetworkObj *obj;
    virNetworkDef *def;
    virNetworkPortDef *portdef;
    int maxparams = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    *params = NULL;
    *nparams = 0;

    if (!(obj = networkObjFromNetwork(port->net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (!(portdef = virNetworkObjLookupPort(obj, port->uuid)))
        goto cleanup;

    if (virNetworkPortGetParametersEnsureACL(port->net->conn, def, portdef) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    if (portdef->bandwidth) {
        if ((portdef->bandwidth->in != NULL) &&
            (virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_IN_AVERAGE,
                                   portdef->bandwidth->in->average) < 0 ||
             virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_IN_PEAK,
                                   portdef->bandwidth->in->peak) < 0 ||
             virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_IN_FLOOR,
                                   portdef->bandwidth->in->floor) < 0 ||
             virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_IN_BURST,
                                   portdef->bandwidth->in->burst) < 0))
            goto cleanup;

        if ((portdef->bandwidth->out != NULL) &&
            (virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_OUT_AVERAGE,
                                   portdef->bandwidth->out->average) < 0 ||
             virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_OUT_PEAK,
                                   portdef->bandwidth->out->peak) < 0 ||
             virTypedParamsAddUInt(params, nparams, &maxparams,
                                   VIR_NETWORK_PORT_BANDWIDTH_OUT_BURST,
                                   portdef->bandwidth->out->burst) < 0))
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkListAllPorts(virNetworkPtr net,
                    virNetworkPortPtr **ports,
                    unsigned int flags)
{
    virNetworkObj *obj;
    virNetworkDef *def;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = networkObjFromNetwork(net)))
        return ret;

    def = virNetworkObjGetDef(obj);

    if (virNetworkListAllPortsEnsureACL(net->conn, def) < 0)
        goto cleanup;

    if (!virNetworkObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("network '%1$s' is not active"),
                       def->name);
        goto cleanup;
    }

    ret = virNetworkObjPortListExport(net, obj, ports,
                                      virNetworkListAllPortsCheckACL);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static int
networkSetMetadata(virNetworkPtr net,
                   int type,
                   const char *metadata,
                   const char *key,
                   const char *uri,
                   unsigned int flags)
{
    virNetworkDriverState *driver = networkGetDriver();
    virNetworkObj *obj = NULL;
    virNetworkDef *def = NULL;
    g_autoptr(virNetworkDriverConfig) cfg = NULL;
    int ret = -1;

    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG, -1);

    if (!(obj = networkObjFromNetwork(net)))
        return -1;

    cfg = virNetworkDriverGetConfig(driver);
    def = virNetworkObjGetDef(obj);

    if (virNetworkSetMetadataEnsureACL(net->conn, def, flags) < 0)
        goto cleanup;

    ret = virNetworkObjSetMetadata(obj, type, metadata, key, uri,
                                   driver->xmlopt, cfg->stateDir,
                                   cfg->networkConfigDir, flags);

    if (ret == 0) {
        virObjectEvent *event = NULL;
        event = virNetworkEventMetadataChangeNewFromObj(obj, type, uri);
        virObjectEventStateQueue(driver->networkEventState, event);
    }

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static char *
networkGetMetadata(virNetworkPtr net,
                   int type,
                   const char *uri,
                   unsigned int flags)
{
    virNetworkObj *obj = NULL;
    virNetworkDef *def = NULL;
    char *ret = NULL;

    if (!(obj = networkObjFromNetwork(net)))
        return NULL;

    def = virNetworkObjGetDef(obj);

    if (virNetworkGetMetadataEnsureACL(net->conn, def) < 0)
        goto cleanup;

    ret = virNetworkObjGetMetadata(obj, type, uri, flags);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static virNetworkDriver networkDriver = {
    .name = "bridge",
    .connectNumOfNetworks = networkConnectNumOfNetworks, /* 0.2.0 */
    .connectListNetworks = networkConnectListNetworks, /* 0.2.0 */
    .connectNumOfDefinedNetworks = networkConnectNumOfDefinedNetworks, /* 0.2.0 */
    .connectListDefinedNetworks = networkConnectListDefinedNetworks, /* 0.2.0 */
    .connectListAllNetworks = networkConnectListAllNetworks, /* 0.10.2 */
    .connectNetworkEventRegisterAny = networkConnectNetworkEventRegisterAny, /* 1.2.1 */
    .connectNetworkEventDeregisterAny = networkConnectNetworkEventDeregisterAny, /* 1.2.1 */
    .networkLookupByUUID = networkLookupByUUID, /* 0.2.0 */
    .networkLookupByName = networkLookupByName, /* 0.2.0 */
    .networkCreateXML = networkCreateXML, /* 0.2.0 */
    .networkCreateXMLFlags = networkCreateXMLFlags, /* 7.8.0 */
    .networkDefineXML = networkDefineXML, /* 0.2.0 */
    .networkDefineXMLFlags = networkDefineXMLFlags, /* 7.7.0 */
    .networkUndefine = networkUndefine, /* 0.2.0 */
    .networkUpdate = networkUpdate, /* 0.10.2 */
    .networkCreate = networkCreate, /* 0.2.0 */
    .networkDestroy = networkDestroy, /* 0.2.0 */
    .networkGetXMLDesc = networkGetXMLDesc, /* 0.2.0 */
    .networkGetBridgeName = networkGetBridgeName, /* 0.2.0 */
    .networkGetAutostart = networkGetAutostart, /* 0.2.1 */
    .networkSetAutostart = networkSetAutostart, /* 0.2.1 */
    .networkIsActive = networkIsActive, /* 0.7.3 */
    .networkIsPersistent = networkIsPersistent, /* 0.7.3 */
    .networkGetDHCPLeases = networkGetDHCPLeases, /* 1.2.6 */
    .networkPortLookupByUUID = networkPortLookupByUUID, /* 5.5.0 */
    .networkPortCreateXML = networkPortCreateXML, /* 5.5.0 */
    .networkPortGetXMLDesc = networkPortGetXMLDesc, /* 5.5.0 */
    .networkPortDelete = networkPortDelete, /* 5.5.0 */
    .networkListAllPorts = networkListAllPorts, /* 5.5.0 */
    .networkPortGetParameters = networkPortGetParameters, /* 5.5.0 */
    .networkPortSetParameters = networkPortSetParameters, /* 5.5.0 */
    .networkGetMetadata = networkGetMetadata, /* 9.7.0 */
    .networkSetMetadata = networkSetMetadata, /* 9.7.0 */
};


static virHypervisorDriver networkHypervisorDriver = {
    .name = "network",
    .connectOpen = networkConnectOpen, /* 4.1.0 */
    .connectClose = networkConnectClose, /* 4.1.0 */
    .connectIsEncrypted = networkConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = networkConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = networkConnectIsAlive, /* 4.1.0 */
    .connectSupportsFeature = networkConnectSupportsFeature, /* 7.2.0 */
};


static virConnectDriver networkConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "network", NULL },
    .hypervisorDriver = &networkHypervisorDriver,
    .networkDriver = &networkDriver,
};


static virStateDriver networkStateDriver = {
    .name = "bridge",
    .stateInitialize  = networkStateInitialize,
    .stateCleanup = networkStateCleanup,
    .stateReload = networkStateReload,
};

int
networkRegister(void)
{
    if (virRegisterConnectDriver(&networkConnectDriver, false) < 0)
        return -1;
    if (virSetSharedNetworkDriver(&networkDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&networkStateDriver) < 0)
        return -1;
    return 0;
}
