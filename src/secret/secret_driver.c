/*
 * secret_driver.c: local driver for secret manipulation API
 *
 * Copyright (C) 2009-2016 Red Hat, Inc.
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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "datatypes.h"
#include "driver.h"
#include "virlog.h"
#include "viralloc.h"
#include "secret_conf.h"
#include "virsecretobj.h"
#include "secret_driver.h"
#include "virthread.h"
#include "viruuid.h"
#include "virerror.h"
#include "viridentity.h"
#include "virpidfile.h"
#include "configmake.h"
#include "viraccessapicheck.h"
#include "secret_event.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("secret.secret_driver");

enum { SECRET_MAX_XML_FILE = 10*1024*1024 };

/* Internal driver state */

static virMutex mutex = VIR_MUTEX_INITIALIZER;

typedef struct _virSecretDriverState virSecretDriverState;
struct _virSecretDriverState {
    bool privileged; /* readonly */
    char *embeddedRoot; /* readonly */
    int embeddedRefs;
    virSecretObjList *secrets;
    char *stateDir;
    char *configDir;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *secretEventState;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;
};

static virSecretDriverState *driver;

static virSecretObj *
secretObjFromSecret(virSecretPtr secret)
{
    virSecretObj *obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(secret->uuid, uuidstr);
    if (!(obj = virSecretObjListFindByUUID(driver->secrets, uuidstr))) {
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching uuid '%1$s'"), uuidstr);
        return NULL;
    }
    return obj;
}


static bool
secretNumOfEphemeralSecretsHelper(virConnectPtr conn G_GNUC_UNUSED,
                                  virSecretDef *def)
{
    return def->isephemeral;
}


static int
secretNumOfEphemeralSecrets(void)
{
    return virSecretObjListNumOfSecrets(driver->secrets,
                                        secretNumOfEphemeralSecretsHelper,
                                        NULL);
}


/* Driver functions */

static int
secretConnectNumOfSecrets(virConnectPtr conn)
{
    if (virConnectNumOfSecretsEnsureACL(conn) < 0)
        return -1;

    return virSecretObjListNumOfSecrets(driver->secrets,
                                        virConnectNumOfSecretsCheckACL,
                                        conn);
}


static int
secretConnectListSecrets(virConnectPtr conn,
                         char **uuids,
                         int maxuuids)
{
    memset(uuids, 0, maxuuids * sizeof(*uuids));

    if (virConnectListSecretsEnsureACL(conn) < 0)
        return -1;

    return virSecretObjListGetUUIDs(driver->secrets, uuids, maxuuids,
                                    virConnectListSecretsCheckACL, conn);
}


static int
secretConnectListAllSecrets(virConnectPtr conn,
                            virSecretPtr **secrets,
                            unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_LIST_SECRETS_FILTERS_ALL, -1);

    if (virConnectListAllSecretsEnsureACL(conn) < 0)
        return -1;

    return virSecretObjListExport(conn, driver->secrets, secrets,
                                  virConnectListAllSecretsCheckACL,
                                  flags);
}


static virSecretPtr
secretLookupByUUID(virConnectPtr conn,
                   const unsigned char *uuid)
{
    virSecretPtr ret = NULL;
    virSecretObj *obj;
    virSecretDef *def;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);
    if (!(obj = virSecretObjListFindByUUID(driver->secrets, uuidstr))) {
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching uuid '%1$s'"), uuidstr);
        goto cleanup;
    }

    def = virSecretObjGetDef(obj);
    if (virSecretLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       def->uuid,
                       def->usage_type,
                       def->usage_id);

 cleanup:
    virSecretObjEndAPI(&obj);
    return ret;
}


static virSecretPtr
secretLookupByUsage(virConnectPtr conn,
                    int usageType,
                    const char *usageID)
{
    virSecretPtr ret = NULL;
    virSecretObj *obj;
    virSecretDef *def;

    if (!(obj = virSecretObjListFindByUsage(driver->secrets,
                                            usageType, usageID))) {
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching usage '%1$s'"), usageID);
        goto cleanup;
    }

    def = virSecretObjGetDef(obj);
    if (virSecretLookupByUsageEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       def->uuid,
                       def->usage_type,
                       def->usage_id);

 cleanup:
    virSecretObjEndAPI(&obj);
    return ret;
}


static virSecretPtr
secretDefineXML(virConnectPtr conn,
                const char *xml,
                unsigned int flags)
{
    virSecretPtr ret = NULL;
    virSecretObj *obj = NULL;
    virSecretDef *objDef;
    virSecretDef *backup = NULL;
    virSecretDef *def;
    virObjectEvent *event = NULL;

    virCheckFlags(VIR_SECRET_DEFINE_VALIDATE, NULL);

    if (!(def = virSecretDefParse(xml, NULL, flags)))
        return NULL;

    if (virSecretDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(obj = virSecretObjListAdd(driver->secrets, &def,
                                    driver->configDir, &backup)))
        goto cleanup;
    objDef = virSecretObjGetDef(obj);

    if (!objDef->isephemeral) {
        if (backup && backup->isephemeral) {
            if (virSecretObjSaveData(obj) < 0)
                goto restore_backup;
        }

        if (virSecretObjSaveConfig(obj) < 0) {
            if (backup && backup->isephemeral) {
                /* Undo the virSecretObjSaveData() above; ignore errors */
                virSecretObjDeleteData(obj);
            }
            goto restore_backup;
        }
    } else if (backup && !backup->isephemeral) {
        if (virSecretObjDeleteConfig(obj) < 0)
            goto restore_backup;

        virSecretObjDeleteData(obj);
    }
    /* Saved successfully - drop old values */
    virSecretDefFree(backup);

    event = virSecretEventLifecycleNew(objDef->uuid,
                                       objDef->usage_type,
                                       objDef->usage_id,
                                       VIR_SECRET_EVENT_DEFINED,
                                       0);

    ret = virGetSecret(conn,
                       objDef->uuid,
                       objDef->usage_type,
                       objDef->usage_id);
    goto cleanup;

 restore_backup:
    /* If we have a backup, then secret was defined before, so just restore
     * the backup; otherwise, this is a new secret, thus remove it. */
    if (backup) {
        virSecretObjSetDef(obj, backup);
        def = g_steal_pointer(&objDef);
    } else {
        virSecretObjListRemove(driver->secrets, obj);
        g_clear_pointer(&obj, virObjectUnref);
    }

 cleanup:
    virSecretDefFree(def);
    virSecretObjEndAPI(&obj);

    if (secretNumOfEphemeralSecrets() > 0)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    virObjectEventStateQueue(driver->secretEventState, event);

    return ret;
}


static char *
secretGetXMLDesc(virSecretPtr secret,
                 unsigned int flags)
{
    char *ret = NULL;
    virSecretObj *obj;
    virSecretDef *def;

    virCheckFlags(0, NULL);

    if (!(obj = secretObjFromSecret(secret)))
        goto cleanup;

    def = virSecretObjGetDef(obj);
    if (virSecretGetXMLDescEnsureACL(secret->conn, def) < 0)
        goto cleanup;

    ret = virSecretDefFormat(def);

 cleanup:
    virSecretObjEndAPI(&obj);

    return ret;
}


static int
secretSetValue(virSecretPtr secret,
               const unsigned char *value,
               size_t value_size,
               unsigned int flags)
{
    int ret = -1;
    virSecretObj *obj;
    virSecretDef *def;
    virObjectEvent *event = NULL;

    virCheckFlags(0, -1);

    if (!(obj = secretObjFromSecret(secret)))
        goto cleanup;

    def = virSecretObjGetDef(obj);
    if (virSecretSetValueEnsureACL(secret->conn, def) < 0)
        goto cleanup;

    if (virSecretObjSetValue(obj, value, value_size) < 0)
        goto cleanup;

    event = virSecretEventValueChangedNew(def->uuid,
                                          def->usage_type,
                                          def->usage_id);
    ret = 0;

 cleanup:
    virSecretObjEndAPI(&obj);
    virObjectEventStateQueue(driver->secretEventState, event);

    return ret;
}


static unsigned char *
secretGetValue(virSecretPtr secret,
               size_t *value_size,
               unsigned int flags)
{
    unsigned char *ret = NULL;
    virSecretObj *obj;
    virSecretDef *def;

    virCheckFlags(0, NULL);

    if (!(obj = secretObjFromSecret(secret)))
        goto cleanup;

    def = virSecretObjGetDef(obj);
    if (virSecretGetValueEnsureACL(secret->conn, def) < 0)
        goto cleanup;

    /*
     * For historical compat we want to deny access to
     * private secrets, even if no ACL driver is
     * present.
     *
     * We need to validate the identity requesting
     * the secret value is running as the same user
     * credentials as this driver.
     *
     * ie a non-root libvirt client should not be
     * able to request the value from privileged
     * libvirt driver.
     *
     * To apply restrictions to processes running under
     * the same user account is out of scope.
     */
    if (def->isprivate) {
        int rv = virIdentityIsCurrentElevated();
        if (rv < 0)
            goto cleanup;
        if (rv == 0) {
            virReportError(VIR_ERR_INVALID_SECRET, "%s",
                           _("secret is private"));
            goto cleanup;
        }
    }

    if (!(ret = virSecretObjGetValue(obj)))
        goto cleanup;

    *value_size = virSecretObjGetValueSize(obj);

 cleanup:
    virSecretObjEndAPI(&obj);

    return ret;
}


static int
secretUndefine(virSecretPtr secret)
{
    int ret = -1;
    virSecretObj *obj;
    virSecretDef *def;
    virObjectEvent *event = NULL;

    if (!(obj = secretObjFromSecret(secret)))
        goto cleanup;

    def = virSecretObjGetDef(obj);
    if (virSecretUndefineEnsureACL(secret->conn, def) < 0)
        goto cleanup;

    if (virSecretObjDeleteConfig(obj) < 0)
        goto cleanup;

    event = virSecretEventLifecycleNew(def->uuid,
                                       def->usage_type,
                                       def->usage_id,
                                       VIR_SECRET_EVENT_UNDEFINED,
                                       0);

    virSecretObjDeleteData(obj);

    virSecretObjListRemove(driver->secrets, obj);
    g_clear_pointer(&obj, virObjectUnref);

    ret = 0;

 cleanup:
    virSecretObjEndAPI(&obj);

    if (secretNumOfEphemeralSecrets() == 0)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    virObjectEventStateQueue(driver->secretEventState, event);

    return ret;
}


static int
secretStateCleanupLocked(void)
{
    if (!driver)
        return -1;

    virObjectUnref(driver->secrets);
    VIR_FREE(driver->configDir);

    virObjectUnref(driver->secretEventState);

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

    VIR_FREE(driver->stateDir);
    VIR_FREE(driver);

    return 0;
}

static int
secretStateCleanup(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

    return secretStateCleanupLocked();
}


static int
secretStateInitialize(bool privileged,
                      const char *root,
                      bool monolithic G_GNUC_UNUSED,
                      virStateInhibitCallback callback,
                      void *opaque)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

    driver = g_new0(virSecretDriverState, 1);

    driver->lockFD = -1;
    driver->secretEventState = virObjectEventStateNew();
    driver->privileged = privileged;
    driver->inhibitCallback = callback;
    driver->inhibitOpaque = opaque;

    if (root) {
        driver->embeddedRoot = g_strdup(root);
        driver->configDir = g_strdup_printf("%s/etc/secrets", root);
        driver->stateDir = g_strdup_printf("%s/run/secrets", root);
    } else if (privileged) {
        driver->configDir = g_strdup_printf("%s/libvirt/secrets", SYSCONFDIR);
        driver->stateDir = g_strdup_printf("%s/libvirt/secrets", RUNSTATEDIR);
    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cfgdir = NULL;

        cfgdir = virGetUserConfigDirectory();
        driver->configDir = g_strdup_printf("%s/secrets/", cfgdir);

        rundir = virGetUserRuntimeDirectory();
        driver->stateDir = g_strdup_printf("%s/secrets/run", rundir);
    }

    if (g_mkdir_with_parents(driver->configDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             driver->configDir);
        goto error;
    }

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto error;
    }

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto error;

    if (!(driver->secrets = virSecretObjListNew()))
        goto error;

    if (virSecretLoadAllConfigs(driver->secrets, driver->configDir) < 0)
        goto error;

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    secretStateCleanupLocked();
    return VIR_DRV_STATE_INIT_ERROR;
}


static int
secretStateReload(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

    if (!driver)
        return -1;

    ignore_value(virSecretLoadAllConfigs(driver->secrets, driver->configDir));

    return 0;
}


static virDrvOpenStatus
secretConnectOpen(virConnectPtr conn,
                  virConnectAuthPtr auth G_GNUC_UNUSED,
                  virConf *conf G_GNUC_UNUSED,
                  unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("secret state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (driver->embeddedRoot) {
        const char *root = virURIGetParam(conn->uri, "root");
        if (!root)
            return VIR_DRV_OPEN_ERROR;

        if (STRNEQ(conn->uri->path, "/embed")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("URI must be secret:///embed"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (STRNEQ(root, driver->embeddedRoot)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot open embedded driver at path '%1$s', already open with path '%2$s'"),
                           root, driver->embeddedRoot);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (!virConnectValidateURIPath(conn->uri->path,
                                       "secret",
                                       driver->privileged))
            return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (driver->embeddedRoot) {
        VIR_WITH_MUTEX_LOCK_GUARD(&mutex) {
            if (driver->embeddedRefs == 0)
                virSetConnectSecret(conn);
            driver->embeddedRefs++;
        }
    }

    return VIR_DRV_OPEN_SUCCESS;
}

static int secretConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

    if (driver->embeddedRoot) {
        driver->embeddedRefs--;
        if (driver->embeddedRefs == 0)
            virSetConnectSecret(NULL);
    }
    return 0;
}


static int secretConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int secretConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int secretConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static int
secretConnectSecretEventRegisterAny(virConnectPtr conn,
                                    virSecretPtr secret,
                                    int eventID,
                                    virConnectSecretEventGenericCallback callback,
                                    void *opaque,
                                    virFreeCallback freecb)
{
    int callbackID = -1;

    if (virConnectSecretEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virSecretEventStateRegisterID(conn, driver->secretEventState,
                                      secret, eventID, callback,
                                      opaque, freecb, &callbackID) < 0)
        callbackID = -1;

    return callbackID;
}


static int
secretConnectSecretEventDeregisterAny(virConnectPtr conn,
                                      int callbackID)
{
    if (virConnectSecretEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->secretEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}


static virSecretDriver secretDriver = {
    .name = "secret",
    .connectNumOfSecrets = secretConnectNumOfSecrets, /* 0.7.1 */
    .connectListSecrets = secretConnectListSecrets, /* 0.7.1 */
    .connectListAllSecrets = secretConnectListAllSecrets, /* 0.10.2 */
    .secretLookupByUUID = secretLookupByUUID, /* 0.7.1 */
    .secretLookupByUsage = secretLookupByUsage, /* 0.7.1 */
    .secretDefineXML = secretDefineXML, /* 0.7.1 */
    .secretGetXMLDesc = secretGetXMLDesc, /* 0.7.1 */
    .secretSetValue = secretSetValue, /* 0.7.1 */
    .secretGetValue = secretGetValue, /* 0.7.1 */
    .secretUndefine = secretUndefine, /* 0.7.1 */
    .connectSecretEventRegisterAny = secretConnectSecretEventRegisterAny, /* 3.0.0 */
    .connectSecretEventDeregisterAny = secretConnectSecretEventDeregisterAny, /* 3.0.0 */
};


static virHypervisorDriver secretHypervisorDriver = {
    .name = "secret",
    .connectOpen = secretConnectOpen, /* 4.1.0 */
    .connectClose = secretConnectClose, /* 4.1.0 */
    .connectIsEncrypted = secretConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = secretConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = secretConnectIsAlive, /* 4.1.0 */
};


static virConnectDriver secretConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "secret", NULL },
    .embeddable = true,
    .hypervisorDriver = &secretHypervisorDriver,
    .secretDriver = &secretDriver,
};


static virStateDriver stateDriver = {
    .name = "secret",
    .stateInitialize = secretStateInitialize,
    .stateCleanup = secretStateCleanup,
    .stateReload = secretStateReload,
};


int
secretRegister(void)
{
    if (virRegisterConnectDriver(&secretConnectDriver, false) < 0)
        return -1;
    if (virSetSharedSecretDriver(&secretDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    return 0;
}
