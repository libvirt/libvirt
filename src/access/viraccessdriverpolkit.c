/*
 * viraccessdriverpolkit.c: polkited access control driver
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
#include "viralloc.h"
#include "vircommand.h"
#include "virlog.h"
#include "virprocess.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ACCESS

VIR_LOG_INIT("access.accessdriverpolkit");

#define virAccessError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#define VIR_ACCESS_DRIVER_POLKIT_ACTION_PREFIX "org.libvirt.api"

typedef struct _virAccessDriverPolkitPrivate virAccessDriverPolkitPrivate;
typedef virAccessDriverPolkitPrivate *virAccessDriverPolkitPrivatePtr;

struct _virAccessDriverPolkitPrivate {
    bool ignore;
};


static void virAccessDriverPolkitCleanup(virAccessManagerPtr manager ATTRIBUTE_UNUSED)
{
}


static char *
virAccessDriverPolkitFormatAction(const char *typename,
                                  const char *permname)
{
    char *actionid = NULL;
    size_t i;

    if (virAsprintf(&actionid, "%s.%s.%s",
                    VIR_ACCESS_DRIVER_POLKIT_ACTION_PREFIX,
                    typename, permname) < 0)
        return NULL;

    for (i = 0; actionid[i]; i++)
        if (actionid[i] == '_')
            actionid[i] = '-';

    return actionid;
}


static char *
virAccessDriverPolkitFormatProcess(const char *actionid)
{
    virIdentityPtr identity = virIdentityGetCurrent();
    const char *callerPid = NULL;
    const char *callerTime = NULL;
    const char *callerUid = NULL;
    char *ret = NULL;
#ifndef PKCHECK_SUPPORTS_UID
    static bool polkitInsecureWarned;
#endif

    if (!identity) {
        virAccessError(VIR_ERR_ACCESS_DENIED,
                       _("Policy kit denied action %s from <anonymous>"),
                       actionid);
        return NULL;
    }
    if (virIdentityGetAttr(identity, VIR_IDENTITY_ATTR_UNIX_PROCESS_ID, &callerPid) < 0)
        goto cleanup;
    if (virIdentityGetAttr(identity, VIR_IDENTITY_ATTR_UNIX_PROCESS_TIME, &callerTime) < 0)
        goto cleanup;
    if (virIdentityGetAttr(identity, VIR_IDENTITY_ATTR_UNIX_USER_ID, &callerUid) < 0)
        goto cleanup;

    if (!callerPid) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No UNIX process ID available"));
        goto cleanup;
    }
    if (!callerTime) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No UNIX process start time available"));
        goto cleanup;
    }
    if (!callerUid) {
        virAccessError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No UNIX caller UID available"));
        goto cleanup;
    }

#ifdef PKCHECK_SUPPORTS_UID
    if (virAsprintf(&ret, "%s,%s,%s", callerPid, callerTime, callerUid) < 0)
        goto cleanup;
#else
    if (!polkitInsecureWarned) {
        VIR_WARN("No support for caller UID with pkcheck. "
                 "This deployment is known to be insecure.");
        polkitInsecureWarned = true;
    }
    if (virAsprintf(&ret, "%s,%s", callerPid, callerTime) < 0)
        goto cleanup;
#endif

 cleanup:
    virObjectUnref(identity);
    return ret;
}


static int
virAccessDriverPolkitCheck(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                           const char *typename,
                           const char *permname,
                           const char **attrs)
{
    char *actionid = NULL;
    char *process = NULL;
    virCommandPtr cmd = NULL;
    int status;
    int ret = -1;

    if (!(actionid = virAccessDriverPolkitFormatAction(typename, permname)))
        goto cleanup;

    if (!(process = virAccessDriverPolkitFormatProcess(actionid)))
        goto cleanup;

    VIR_DEBUG("Check action '%s' for process '%s'", actionid, process);

    cmd = virCommandNewArgList(PKCHECK_PATH,
                               "--action-id", actionid,
                               "--process", process,
                               NULL);

    while (attrs && attrs[0] && attrs[1]) {
        virCommandAddArgList(cmd, "--detail", attrs[0], attrs[1], NULL);
        attrs += 2;
    }

    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (status == 0) {
        ret = 1; /* Allowed */
    } else {
        if (status == 1 ||
            status == 2 ||
            status == 3) {
            ret = 0; /* Denied */
        } else {
            ret = -1; /* Error */
            virAccessError(VIR_ERR_ACCESS_DENIED,
                           _("Policy kit denied action %s from %s: "
                             "exit status %d"),
                           actionid, process, status);
        }
        goto cleanup;
    }

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(actionid);
    VIR_FREE(process);
    return ret;
}


static int
virAccessDriverPolkitCheckConnect(virAccessManagerPtr manager,
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
virAccessDriverPolkitCheckDomain(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virDomainDefPtr domain,
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
virAccessDriverPolkitCheckInterface(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virInterfaceDefPtr iface,
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
virAccessDriverPolkitCheckNetwork(virAccessManagerPtr manager,
                                  const char *driverName,
                                  virNetworkDefPtr network,
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
virAccessDriverPolkitCheckNodeDevice(virAccessManagerPtr manager,
                                     const char *driverName,
                                     virNodeDeviceDefPtr nodedev,
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
virAccessDriverPolkitCheckNWFilter(virAccessManagerPtr manager,
                                   const char *driverName,
                                   virNWFilterDefPtr nwfilter,
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
virAccessDriverPolkitCheckSecret(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virSecretDefPtr secret,
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
            "secret_usage_volume", secret->usage.volume,
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
            "secret_usage_ceph", secret->usage.ceph,
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
            "secret_usage_target", secret->usage.target,
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
virAccessDriverPolkitCheckStoragePool(virAccessManagerPtr manager,
                                      const char *driverName,
                                      virStoragePoolDefPtr pool,
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
virAccessDriverPolkitCheckStorageVol(virAccessManagerPtr manager,
                                     const char *driverName,
                                     virStoragePoolDefPtr pool,
                                     virStorageVolDefPtr vol,
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
    .checkNodeDevice = virAccessDriverPolkitCheckNodeDevice,
    .checkNWFilter = virAccessDriverPolkitCheckNWFilter,
    .checkSecret = virAccessDriverPolkitCheckSecret,
    .checkStoragePool = virAccessDriverPolkitCheckStoragePool,
    .checkStorageVol = virAccessDriverPolkitCheckStorageVol,
};
