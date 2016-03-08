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
 *
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#include <config.h>

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "base64.h"
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
#include "virfile.h"
#include "configmake.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("secret.secret_driver");

enum { SECRET_MAX_XML_FILE = 10*1024*1024 };

/* Internal driver state */

typedef struct _virSecretDriverState virSecretDriverState;
typedef virSecretDriverState *virSecretDriverStatePtr;
struct _virSecretDriverState {
    virMutex lock;
    virSecretObjListPtr secrets;
    char *configDir;
};

static virSecretDriverStatePtr driver;

static void
secretDriverLock(void)
{
    virMutexLock(&driver->lock);
}

static void
secretDriverUnlock(void)
{
    virMutexUnlock(&driver->lock);
}



static virSecretObjPtr
secretObjFromSecret(virSecretPtr secret)
{
    virSecretObjPtr obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(obj = virSecretObjListFindByUUID(driver->secrets, secret->uuid))) {
        virUUIDFormat(secret->uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching uuid '%s'"), uuidstr);
        return NULL;
    }
    return obj;
}


static int
secretEnsureDirectory(void)
{
    if (mkdir(driver->configDir, S_IRWXU) < 0 && errno != EEXIST) {
        virReportSystemError(errno, _("cannot create '%s'"),
                             driver->configDir);
        return -1;
    }
    return 0;
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
    virSecretObjPtr secret;
    virSecretDefPtr def;

    if (!(secret = virSecretObjListFindByUUID(driver->secrets, uuid))) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    def = virSecretObjGetDef(secret);
    if (virSecretLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       def->uuid,
                       def->usage_type,
                       virSecretUsageIDForDef(def));

 cleanup:
    virSecretObjEndAPI(&secret);
    return ret;
}


static virSecretPtr
secretLookupByUsage(virConnectPtr conn,
                    int usageType,
                    const char *usageID)
{
    virSecretPtr ret = NULL;
    virSecretObjPtr secret;
    virSecretDefPtr def;

    if (!(secret = virSecretObjListFindByUsage(driver->secrets,
                                               usageType, usageID))) {
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching usage '%s'"), usageID);
        goto cleanup;
    }

    def = virSecretObjGetDef(secret);
    if (virSecretLookupByUsageEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       def->uuid,
                       def->usage_type,
                       virSecretUsageIDForDef(def));

 cleanup:
    virSecretObjEndAPI(&secret);
    return ret;
}


static virSecretPtr
secretDefineXML(virConnectPtr conn,
                const char *xml,
                unsigned int flags)
{
    virSecretPtr ret = NULL;
    virSecretObjPtr secret = NULL;
    virSecretDefPtr backup = NULL;
    virSecretDefPtr new_attrs;

    virCheckFlags(0, NULL);

    if (!(new_attrs = virSecretDefParseString(xml)))
        return NULL;

    if (virSecretDefineXMLEnsureACL(conn, new_attrs) < 0)
        goto cleanup;

    if (!(secret = virSecretObjListAdd(driver->secrets, new_attrs,
                                       driver->configDir, &backup)))
        goto cleanup;

    if (!new_attrs->isephemeral) {
        if (secretEnsureDirectory() < 0)
            goto cleanup;

        if (backup && backup->isephemeral) {
            if (virSecretObjSaveData(secret) < 0)
                goto restore_backup;
        }

        if (virSecretObjSaveConfig(secret) < 0) {
            if (backup && backup->isephemeral) {
                /* Undo the virSecretObjSaveData() above; ignore errors */
                virSecretObjDeleteData(secret);
            }
            goto restore_backup;
        }
    } else if (backup && !backup->isephemeral) {
        if (virSecretObjDeleteConfig(secret) < 0)
            goto restore_backup;

        virSecretObjDeleteData(secret);
    }
    /* Saved successfully - drop old values */
    virSecretDefFree(backup);

    ret = virGetSecret(conn,
                       new_attrs->uuid,
                       new_attrs->usage_type,
                       virSecretUsageIDForDef(new_attrs));
    new_attrs = NULL;
    goto cleanup;

 restore_backup:
    /* If we have a backup, then secret was defined before, so just restore
     * the backup. The current (new_attrs) will be handled below.
     * Otherwise, this is a new secret, thus remove it.
     */
    if (backup)
        virSecretObjSetDef(secret, backup);
    else
        virSecretObjListRemove(driver->secrets, secret);

 cleanup:
    virSecretDefFree(new_attrs);
    virSecretObjEndAPI(&secret);

    return ret;
}

static char *
secretGetXMLDesc(virSecretPtr obj,
                 unsigned int flags)
{
    char *ret = NULL;
    virSecretObjPtr secret;
    virSecretDefPtr def;

    virCheckFlags(0, NULL);

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    def = virSecretObjGetDef(secret);
    if (virSecretGetXMLDescEnsureACL(obj->conn, def) < 0)
        goto cleanup;

    ret = virSecretDefFormat(def);

 cleanup:
    virSecretObjEndAPI(&secret);

    return ret;
}

static int
secretSetValue(virSecretPtr obj,
               const unsigned char *value,
               size_t value_size,
               unsigned int flags)
{
    int ret = -1;
    virSecretObjPtr secret;
    virSecretDefPtr def;

    virCheckFlags(0, -1);

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    def = virSecretObjGetDef(secret);
    if (virSecretSetValueEnsureACL(obj->conn, def) < 0)
        goto cleanup;

    if (secretEnsureDirectory() < 0)
        goto cleanup;

    if (virSecretObjSetValue(secret, value, value_size) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virSecretObjEndAPI(&secret);

    return ret;
}

static unsigned char *
secretGetValue(virSecretPtr obj,
               size_t *value_size,
               unsigned int flags,
               unsigned int internalFlags)
{
    unsigned char *ret = NULL;
    virSecretObjPtr secret;
    virSecretDefPtr def;

    virCheckFlags(0, NULL);

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    def = virSecretObjGetDef(secret);
    if (virSecretGetValueEnsureACL(obj->conn, def) < 0)
        goto cleanup;

    if ((internalFlags & VIR_SECRET_GET_VALUE_INTERNAL_CALL) == 0 &&
        def->isprivate) {
        virReportError(VIR_ERR_INVALID_SECRET, "%s",
                       _("secret is private"));
        goto cleanup;
    }

    if (!(ret = virSecretObjGetValue(secret)))
        goto cleanup;

    *value_size = virSecretObjGetValueSize(secret);

 cleanup:
    virSecretObjEndAPI(&secret);

    return ret;
}

static int
secretUndefine(virSecretPtr obj)
{
    int ret = -1;
    virSecretObjPtr secret;
    virSecretDefPtr def;

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    def = virSecretObjGetDef(secret);
    if (virSecretUndefineEnsureACL(obj->conn, def) < 0)
        goto cleanup;

    if (virSecretObjDeleteConfig(secret) < 0)
        goto cleanup;

    virSecretObjDeleteData(secret);

    virSecretObjListRemove(driver->secrets, secret);

    ret = 0;

 cleanup:
    virSecretObjEndAPI(&secret);

    return ret;
}

static int
secretStateCleanup(void)
{
    if (!driver)
        return -1;

    secretDriverLock();

    virObjectUnref(driver->secrets);
    VIR_FREE(driver->configDir);

    secretDriverUnlock();
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);

    return 0;
}

static int
secretStateInitialize(bool privileged,
                      virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                      void *opaque ATTRIBUTE_UNUSED)
{
    char *base = NULL;

    if (VIR_ALLOC(driver) < 0)
        return -1;

    if (virMutexInit(&driver->lock) < 0) {
        VIR_FREE(driver);
        return -1;
    }
    secretDriverLock();

    if (privileged) {
        if (VIR_STRDUP(base, SYSCONFDIR "/libvirt") < 0)
            goto error;
    } else {
        if (!(base = virGetUserConfigDirectory()))
            goto error;
    }
    if (virAsprintf(&driver->configDir, "%s/secrets", base) < 0)
        goto error;
    VIR_FREE(base);

    if (!(driver->secrets = virSecretObjListNew()))
        goto error;

    if (virSecretLoadAllConfigs(driver->secrets, driver->configDir) < 0)
        goto error;

    secretDriverUnlock();
    return 0;

 error:
    VIR_FREE(base);
    secretDriverUnlock();
    secretStateCleanup();
    return -1;
}

static int
secretStateReload(void)
{
    if (!driver)
        return -1;

    secretDriverLock();

    ignore_value(virSecretLoadAllConfigs(driver->secrets, driver->configDir));

    secretDriverUnlock();
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
    if (virSetSharedSecretDriver(&secretDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    return 0;
}
