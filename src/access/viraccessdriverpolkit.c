/*
 * viraccessdriverpolkit.c: polkitd access control driver
 *
 * Copyright (C) 2012, 2014 Red Hat, Inc.
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

#include "viraccessdriverpolkit.h"
#include "virlog.h"
#include "virerror.h"
#include "virpolkit.h"

#define VIR_FROM_THIS VIR_FROM_ACCESS

VIR_LOG_INIT("access.accessdriverpolkit");

#define virAccessError(code, ...) \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__, \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#define VIR_ACCESS_DRIVER_POLKIT_ACTION_PREFIX "org.libvirt.api"

typedef struct _virAccessDriverPolkitPrivate virAccessDriverPolkitPrivate;
struct _virAccessDriverPolkitPrivate {
    bool ignore;
};


static void virAccessDriverPolkitCleanup(virAccessManager *manager G_GNUC_UNUSED)
{
}


static char *
virAccessDriverPolkitFormatAction(const char *typename,
                                  const char *permname)
{
    char *actionid = NULL;
    size_t i;

    actionid = g_strdup_printf("%s.%s.%s", VIR_ACCESS_DRIVER_POLKIT_ACTION_PREFIX,
                               typename, permname);

    for (i = 0; actionid[i]; i++)
        if (actionid[i] == '_')
            actionid[i] = '-';

    return actionid;
}


static int
virAccessDriverPolkitGetCaller(const char *actionid,
                               pid_t *pid,
                               unsigned long long *startTime,
                               uid_t *uid)
{
    g_autoptr(virIdentity) identity = virIdentityGetCurrent();
    int rc;

    if (!identity) {
        virAccessError(VIR_ERR_ACCESS_DENIED,
                       _("Policy kit denied action %1$s from <anonymous>"),
                       actionid);
        return -1;
    }

    if ((rc = virIdentityGetProcessID(identity, pid)) < 0)
        return -1;

    if (rc == 0) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No process ID available"));
        return -1;
    }

    if ((rc = virIdentityGetProcessTime(identity, startTime)) < 0)
        return -1;

    if (rc == 0) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No process start time available"));
        return -1;
    }

    if ((rc = virIdentityGetUNIXUserID(identity, uid)) < 0)
        return -1;

    if (rc == 0) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No UNIX caller UID available"));
        return -1;
    }

    return 0;
}


static int
virAccessDriverPolkitCheck(virAccessManager *manager G_GNUC_UNUSED,
                           const char *typename,
                           const char *permname,
                           const char **attrs)
{
    g_autofree char *actionid = NULL;
    pid_t pid;
    uid_t uid;
    unsigned long long startTime;
    int rv;

    if (!(actionid = virAccessDriverPolkitFormatAction(typename, permname)))
        return -1;

    if (virAccessDriverPolkitGetCaller(actionid,
                                       &pid,
                                       &startTime,
                                       &uid) < 0)
        return -1;

    VIR_DEBUG("Check action '%s' for process '%lld' time %lld uid %d",
              actionid, (long long)pid, startTime, uid);

    rv = virPolkitCheckAuth(actionid,
                            pid,
                            startTime,
                            uid,
                            attrs,
                            false);

    if (rv == 0) {
        return 1; /* Allowed */
    } else {
        if (rv == -2) {
            return 0; /* Denied */
        } else {
            return -1; /* Error */
        }
    }
}


static int
virAccessDriverPolkitCheckConnect(virAccessManager *manager,
                                  const char *driverName,
                                  virAccessPermConnect perm)
{
    const char *attrs[] = {
        "connect_driver", driverName,
        NULL,
    };

    return virAccessDriverPolkitCheck(manager,
                                      "connect",
                                      virAccessPermConnectTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckDomain(virAccessManager *manager,
                                 const char *driverName,
                                 virDomainDef *domain,
                                 virAccessPermDomain perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "domain_name", domain->name,
        "domain_uuid", uuidstr,
        NULL,
    };
    virUUIDFormat(domain->uuid, uuidstr);

    return virAccessDriverPolkitCheck(manager,
                                      "domain",
                                      virAccessPermDomainTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckInterface(virAccessManager *manager,
                                    const char *driverName,
                                    virInterfaceDef *iface,
                                    virAccessPermInterface perm)
{
    const char *attrs[] = {
        "connect_driver", driverName,
        "interface_name", iface->name,
        "interface_macaddr", iface->mac,
        NULL,
    };

    return virAccessDriverPolkitCheck(manager,
                                      "interface",
                                      virAccessPermInterfaceTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckNetwork(virAccessManager *manager,
                                  const char *driverName,
                                  virNetworkDef *network,
                                  virAccessPermNetwork perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "network_name", network->name,
        "network_uuid", uuidstr,
        NULL,
    };
    virUUIDFormat(network->uuid, uuidstr);

    return virAccessDriverPolkitCheck(manager,
                                      "network",
                                      virAccessPermNetworkTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckNetworkPort(virAccessManager *manager,
                                      const char *driverName,
                                      virNetworkDef *network,
                                      virNetworkPortDef *port,
                                      virAccessPermNetworkPort perm)
{
    char uuidstr1[VIR_UUID_STRING_BUFLEN];
    char uuidstr2[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "network_name", network->name,
        "network_uuid", uuidstr1,
        "port_uuid", uuidstr2,
        NULL,
    };
    virUUIDFormat(network->uuid, uuidstr1);
    virUUIDFormat(port->uuid, uuidstr2);

    return virAccessDriverPolkitCheck(manager,
                                      "network-port",
                                      virAccessPermNetworkPortTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckNodeDevice(virAccessManager *manager,
                                     const char *driverName,
                                     virNodeDeviceDef *nodedev,
                                     virAccessPermNodeDevice perm)
{
    const char *attrs[] = {
        "connect_driver", driverName,
        "node_device_name", nodedev->name,
        NULL,
    };

    return virAccessDriverPolkitCheck(manager,
                                      "node-device",
                                      virAccessPermNodeDeviceTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckNWFilter(virAccessManager *manager,
                                   const char *driverName,
                                   virNWFilterDef *nwfilter,
                                   virAccessPermNWFilter perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "nwfilter_name", nwfilter->name,
        "nwfilter_uuid", uuidstr,
        NULL,
    };
    virUUIDFormat(nwfilter->uuid, uuidstr);

    return virAccessDriverPolkitCheck(manager,
                                      "nwfilter",
                                      virAccessPermNWFilterTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckNWFilterBinding(virAccessManager *manager,
                                          const char *driverName,
                                          virNWFilterBindingDef *binding,
                                          virAccessPermNWFilterBinding perm)
{
    const char *attrs[] = {
        "connect_driver", driverName,
        "nwfilter_binding_portdev", binding->portdevname,
        "nwfilter_binding_linkdev", binding->linkdevname,
        "nwfilter_binding_filter", binding->filter,
        NULL,
    };

    return virAccessDriverPolkitCheck(manager,
                                      "nwfilter_binding",
                                      virAccessPermNWFilterBindingTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckSecret(virAccessManager *manager,
                                 const char *driverName,
                                 virSecretDef *secret,
                                 virAccessPermSecret perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(secret->uuid, uuidstr);

    switch (secret->usage_type) {
    default:
    case VIR_SECRET_USAGE_TYPE_NONE: {
        const char *attrs[] = {
            "connect_driver", driverName,
            "secret_uuid", uuidstr,
            NULL,
        };

        return virAccessDriverPolkitCheck(manager,
                                          "secret",
                                          virAccessPermSecretTypeToString(perm),
                                          attrs);
    }   break;
    case VIR_SECRET_USAGE_TYPE_VOLUME: {
        const char *attrs[] = {
            "connect_driver", driverName,
            "secret_uuid", uuidstr,
            "secret_usage_volume", secret->usage_id,
            NULL,
        };

        return virAccessDriverPolkitCheck(manager,
                                          "secret",
                                          virAccessPermSecretTypeToString(perm),
                                          attrs);
    }   break;
    case VIR_SECRET_USAGE_TYPE_CEPH: {
        const char *attrs[] = {
            "connect_driver", driverName,
            "secret_uuid", uuidstr,
            "secret_usage_ceph", secret->usage_id,
            NULL,
        };

        return virAccessDriverPolkitCheck(manager,
                                          "secret",
                                          virAccessPermSecretTypeToString(perm),
                                          attrs);
    }   break;
    case VIR_SECRET_USAGE_TYPE_ISCSI: {
        const char *attrs[] = {
            "connect_driver", driverName,
            "secret_uuid", uuidstr,
            "secret_usage_target", secret->usage_id,
            NULL,
        };

        return virAccessDriverPolkitCheck(manager,
                                          "secret",
                                          virAccessPermSecretTypeToString(perm),
                                          attrs);
    }   break;
    case VIR_SECRET_USAGE_TYPE_TLS: {
        const char *attrs[] = {
                    "connect_driver", driverName,
                    "secret_uuid", uuidstr,
                    "secret_usage_name", secret->usage_id,
                    NULL,
                };

        return virAccessDriverPolkitCheck(manager,
                                         "secret",
                                         virAccessPermSecretTypeToString(perm),
                                         attrs);
    }   break;
    }
}

static int
virAccessDriverPolkitCheckStoragePool(virAccessManager *manager,
                                      const char *driverName,
                                      virStoragePoolDef *pool,
                                      virAccessPermStoragePool perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "pool_name", pool->name,
        "pool_uuid", uuidstr,
        NULL,
    };
    virUUIDFormat(pool->uuid, uuidstr);

    return virAccessDriverPolkitCheck(manager,
                                      "storage-pool",
                                      virAccessPermStoragePoolTypeToString(perm),
                                      attrs);
}

static int
virAccessDriverPolkitCheckStorageVol(virAccessManager *manager,
                                     const char *driverName,
                                     virStoragePoolDef *pool,
                                     virStorageVolDef *vol,
                                     virAccessPermStorageVol perm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *attrs[] = {
        "connect_driver", driverName,
        "pool_name", pool->name,
        "pool_uuid", uuidstr,
        "vol_name", vol->name,
        "vol_key", vol->key,
        NULL,
    };
    virUUIDFormat(pool->uuid, uuidstr);

    return virAccessDriverPolkitCheck(manager,
                                      "storage-vol",
                                      virAccessPermStorageVolTypeToString(perm),
                                      attrs);
}

virAccessDriver accessDriverPolkit = {
    .privateDataLen = sizeof(virAccessDriverPolkitPrivate),
    .name = "polkit",
    .cleanup = virAccessDriverPolkitCleanup,
    .checkConnect = virAccessDriverPolkitCheckConnect,
    .checkDomain = virAccessDriverPolkitCheckDomain,
    .checkInterface = virAccessDriverPolkitCheckInterface,
    .checkNetwork = virAccessDriverPolkitCheckNetwork,
    .checkNetworkPort = virAccessDriverPolkitCheckNetworkPort,
    .checkNodeDevice = virAccessDriverPolkitCheckNodeDevice,
    .checkNWFilter = virAccessDriverPolkitCheckNWFilter,
    .checkNWFilterBinding = virAccessDriverPolkitCheckNWFilterBinding,
    .checkSecret = virAccessDriverPolkitCheckSecret,
    .checkStoragePool = virAccessDriverPolkitCheckStoragePool,
    .checkStorageVol = virAccessDriverPolkitCheckStorageVol,
};
