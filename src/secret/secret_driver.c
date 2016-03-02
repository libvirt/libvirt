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


/* Permament secret storage */

/* Secrets are stored in virSecretDriverStatePtr->configDir.  Each secret
   has virSecretDef stored as XML in "$basename.xml".  If a value of the
   secret is defined, it is stored as base64 (with no formatting) in
   "$basename.base64".  "$basename" is in both cases the base64-encoded UUID. */

static int
secretRewriteFile(int fd,
                  void *opaque)
{
    char *data = opaque;

    if (safewrite(fd, data, strlen(data)) < 0)
        return -1;

    return 0;
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

static int
secretSaveDef(const virSecretObj *secret)
{
    char *xml = NULL;
    int ret = -1;

    if (secretEnsureDirectory() < 0)
        goto cleanup;

    if (!(xml = virSecretDefFormat(secret->def)))
        goto cleanup;

    if (virFileRewrite(secret->configFile, S_IRUSR | S_IWUSR,
                       secretRewriteFile, xml) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    return ret;
}

static int
secretSaveValue(const virSecretObj *secret)
{
    char *base64 = NULL;
    int ret = -1;

    if (secret->value == NULL)
        return 0;

    if (secretEnsureDirectory() < 0)
        goto cleanup;

    base64_encode_alloc((const char *)secret->value, secret->value_size,
                        &base64);
    if (base64 == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileRewrite(secret->base64File, S_IRUSR | S_IWUSR,
                       secretRewriteFile, base64) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(base64);
    return ret;
}

static int
secretDeleteSaved(const virSecretObj *secret)
{
    if (unlink(secret->configFile) < 0 && errno != ENOENT)
        return -1;

    /* When the XML is missing, the rest may waste disk space, but the secret
       won't be loaded again, so we have succeeded already. */
    (void)unlink(secret->base64File);

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

    if (!(secret = virSecretObjListFindByUUID(driver->secrets, uuid))) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virSecretLookupByUUIDEnsureACL(conn, secret->def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       secret->def->uuid,
                       secret->def->usage_type,
                       virSecretUsageIDForDef(secret->def));

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

    if (!(secret = virSecretObjListFindByUsage(driver->secrets,
                                               usageType, usageID))) {
        virReportError(VIR_ERR_NO_SECRET,
                       _("no secret with matching usage '%s'"), usageID);
        goto cleanup;
    }

    if (virSecretLookupByUsageEnsureACL(conn, secret->def) < 0)
        goto cleanup;

    ret = virGetSecret(conn,
                       secret->def->uuid,
                       secret->def->usage_type,
                       virSecretUsageIDForDef(secret->def));

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

    if (!new_attrs->ephemeral) {
        if (backup && backup->ephemeral) {
            if (secretSaveValue(secret) < 0)
                goto restore_backup;
        }
        if (secretSaveDef(secret) < 0) {
            if (backup && backup->ephemeral) {
                /* Undo the secretSaveValue() above; ignore errors */
                (void)unlink(secret->base64File);
            }
            goto restore_backup;
        }
    } else if (backup && !backup->ephemeral) {
        if (secretDeleteSaved(secret) < 0)
            goto restore_backup;
    }
    /* Saved successfully - drop old values */
    new_attrs = NULL;
    virSecretDefFree(backup);

    ret = virGetSecret(conn,
                       secret->def->uuid,
                       secret->def->usage_type,
                       virSecretUsageIDForDef(secret->def));
    goto cleanup;

 restore_backup:
    /* If we have a backup, then secret was defined before, so just restore
     * the backup. The current secret->def (new_attrs) will be handled below.
     * Otherwise, this is a new secret, thus remove it.
     */
    if (backup)
        secret->def = backup;
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

    virCheckFlags(0, NULL);

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    if (virSecretGetXMLDescEnsureACL(obj->conn, secret->def) < 0)
        goto cleanup;

    ret = virSecretDefFormat(secret->def);

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
    unsigned char *old_value, *new_value;
    size_t old_value_size;
    virSecretObjPtr secret;

    virCheckFlags(0, -1);

    if (VIR_ALLOC_N(new_value, value_size) < 0)
        return -1;

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    if (virSecretSetValueEnsureACL(obj->conn, secret->def) < 0)
        goto cleanup;

    old_value = secret->value;
    old_value_size = secret->value_size;

    memcpy(new_value, value, value_size);
    secret->value = new_value;
    secret->value_size = value_size;
    if (!secret->def->ephemeral) {
        if (secretSaveValue(secret) < 0)
            goto restore_backup;
    }
    /* Saved successfully - drop old value */
    if (old_value != NULL) {
        memset(old_value, 0, old_value_size);
        VIR_FREE(old_value);
    }
    new_value = NULL;

    ret = 0;
    goto cleanup;

 restore_backup:
    /* Error - restore previous state and free new value */
    secret->value = old_value;
    secret->value_size = old_value_size;
    memset(new_value, 0, value_size);

 cleanup:
    virSecretObjEndAPI(&secret);

    VIR_FREE(new_value);

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

    virCheckFlags(0, NULL);

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    if (virSecretGetValueEnsureACL(obj->conn, secret->def) < 0)
        goto cleanup;

    if (secret->value == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(obj->uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("secret '%s' does not have a value"), uuidstr);
        goto cleanup;
    }

    if ((internalFlags & VIR_SECRET_GET_VALUE_INTERNAL_CALL) == 0 &&
        secret->def->private) {
        virReportError(VIR_ERR_INVALID_SECRET, "%s",
                       _("secret is private"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(ret, secret->value_size) < 0)
        goto cleanup;
    memcpy(ret, secret->value, secret->value_size);
    *value_size = secret->value_size;

 cleanup:
    virSecretObjEndAPI(&secret);

    return ret;
}

static int
secretUndefine(virSecretPtr obj)
{
    int ret = -1;
    virSecretObjPtr secret;

    if (!(secret = secretObjFromSecret(obj)))
        goto cleanup;

    if (virSecretUndefineEnsureACL(obj->conn, secret->def) < 0)
        goto cleanup;

    if (!secret->def->ephemeral &&
        secretDeleteSaved(secret) < 0)
        goto cleanup;

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
