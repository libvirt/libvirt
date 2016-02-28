/*
 * virsecretobj.c: internal <secret> objects handling
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

#include "datatypes.h"
#include "virsecretobj.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("conf.virsecretobj");

static virClassPtr virSecretObjClass;
static virClassPtr virSecretObjListClass;
static void virSecretObjDispose(void *obj);
static void virSecretObjListDispose(void *obj);

struct _virSecretObjList {
    virObjectLockable parent;

    /* uuid string -> virSecretObj  mapping
     * for O(1), lockless lookup-by-uuid */
    virHashTable *objs;
};

struct virSecretSearchData {
    int usageType;
    const char *usageID;
};


static int
virSecretObjOnceInit(void)
{
    if (!(virSecretObjClass = virClassNew(virClassForObjectLockable(),
                                          "virSecretObj",
                                          sizeof(virSecretObj),
                                          virSecretObjDispose)))
        return -1;

    if (!(virSecretObjListClass = virClassNew(virClassForObjectLockable(),
                                              "virSecretObjList",
                                              sizeof(virSecretObjList),
                                              virSecretObjListDispose)))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virSecretObj)

virSecretObjPtr
virSecretObjNew(void)
{
    virSecretObjPtr secret;

    if (virSecretObjInitialize() < 0)
        return NULL;

    if (!(secret = virObjectLockableNew(virSecretObjClass)))
        return NULL;

    return secret;
}


void
virSecretObjEndAPI(virSecretObjPtr *secret)
{
    if (!*secret)
        return;

    virObjectUnlock(*secret);
    virObjectUnref(*secret);
    *secret = NULL;
}


virSecretObjListPtr
virSecretObjListNew(void)
{
    virSecretObjListPtr secrets;

    if (virSecretObjInitialize() < 0)
        return NULL;

    if (!(secrets = virObjectLockableNew(virSecretObjListClass)))
        return NULL;

    if (!(secrets->objs = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(secrets);
        return NULL;
    }

    return secrets;
}


static void
virSecretObjDispose(void *obj)
{
    virSecretObjPtr secret = obj;

    virSecretDefFree(secret->def);
    if (secret->value) {
        /* Wipe before free to ensure we don't leave a secret on the heap */
        memset(secret->value, 0, secret->value_size);
        VIR_FREE(secret->value);
    }
    VIR_FREE(secret->configFile);
    VIR_FREE(secret->base64File);
}


static void
virSecretObjListDispose(void *obj)
{
    virSecretObjListPtr secrets = obj;

    virHashFree(secrets->objs);
}


/**
 * virSecretObjFindByUUIDLocked:
 * @secrets: list of secret objects
 * @uuid: secret uuid to find
 *
 * This functions requires @secrets to be locked already!
 *
 * Returns: not locked, but ref'd secret object.
 */
virSecretObjPtr
virSecretObjListFindByUUIDLocked(virSecretObjListPtr secrets,
                                 const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    return virObjectRef(virHashLookup(secrets->objs, uuidstr));
}


/**
 * virSecretObjFindByUUID:
 * @secrets: list of secret objects
 * @uuid: secret uuid to find
 *
 * This function locks @secrets and finds the secret object which
 * corresponds to @uuid.
 *
 * Returns: locked and ref'd secret object.
 */
virSecretObjPtr
virSecretObjListFindByUUID(virSecretObjListPtr secrets,
                           const unsigned char *uuid)
{
    virSecretObjPtr ret;

    virObjectLock(secrets);
    ret = virSecretObjListFindByUUIDLocked(secrets, uuid);
    virObjectUnlock(secrets);
    if (ret)
        virObjectLock(ret);
    return ret;
}


static int
virSecretObjSearchName(const void *payload,
                       const void *name ATTRIBUTE_UNUSED,
                       const void *opaque)
{
    virSecretObjPtr secret = (virSecretObjPtr) payload;
    struct virSecretSearchData *data = (struct virSecretSearchData *) opaque;
    int found = 0;

    virObjectLock(secret);

    if (secret->def->usage_type != data->usageType)
        goto cleanup;

    switch (data->usageType) {
    case VIR_SECRET_USAGE_TYPE_NONE:
    /* never match this */
        break;

    case VIR_SECRET_USAGE_TYPE_VOLUME:
        if (STREQ(secret->def->usage.volume, data->usageID))
            found = 1;
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        if (STREQ(secret->def->usage.ceph, data->usageID))
            found = 1;
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        if (STREQ(secret->def->usage.target, data->usageID))
            found = 1;
        break;
    }

 cleanup:
    virObjectUnlock(secret);
    return found;
}


/**
 * virSecretObjFindByUsageLocked:
 * @secrets: list of secret objects
 * @usageType: secret usageType to find
 * @usageID: secret usage string
 *
 * This functions requires @secrets to be locked already!
 *
 * Returns: not locked, but ref'd secret object.
 */
virSecretObjPtr
virSecretObjListFindByUsageLocked(virSecretObjListPtr secrets,
                                  int usageType,
                                  const char *usageID)
{
    virSecretObjPtr ret = NULL;
    struct virSecretSearchData data = { .usageType = usageType,
                                        .usageID = usageID };

    ret = virHashSearch(secrets->objs, virSecretObjSearchName, &data);
    if (ret)
        virObjectRef(ret);
    return ret;
}


/**
 * virSecretObjFindByUsage:
 * @secrets: list of secret objects
 * @usageType: secret usageType to find
 * @usageID: secret usage string
 *
 * This function locks @secrets and finds the secret object which
 * corresponds to @usageID of @usageType.
 *
 * Returns: locked and ref'd secret object.
 */
virSecretObjPtr
virSecretObjListFindByUsage(virSecretObjListPtr secrets,
                            int usageType,
                            const char *usageID)
{
    virSecretObjPtr ret;

    virObjectLock(secrets);
    ret = virSecretObjListFindByUsageLocked(secrets, usageType, usageID);
    virObjectUnlock(secrets);
    if (ret)
        virObjectLock(ret);
    return ret;
}


/*
 * virSecretObjListRemove:
 * @secrets: list of secret objects
 * @secret: a secret object
 *
 * Remove the object from the hash table.  The caller must hold the lock
 * on the driver owning @secrets and must have also locked @secret to
 * ensure no one else is either waiting for @secret or still using it.
 */
void
virSecretObjListRemove(virSecretObjListPtr secrets,
                       virSecretObjPtr secret)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(secret->def->uuid, uuidstr);
    virObjectRef(secret);
    virObjectUnlock(secret);

    virObjectLock(secrets);
    virObjectLock(secret);
    virHashRemoveEntry(secrets->objs, uuidstr);
    virObjectUnlock(secret);
    virObjectUnref(secret);
    virObjectUnlock(secrets);
}


/*
 * virSecretObjListAddLocked:
 * @secrets: list of secret objects
 * @def: new secret definition
 * @configDir: directory to place secret config files
 * @oldDef: Former secret def (e.g. a reload path perhaps)
 *
 * Add the new def to the secret obj table hash
 *
 * This functions requires @secrets to be locked already!
 *
 * Returns pointer to secret or NULL if failure to add
 */
virSecretObjPtr
virSecretObjListAddLocked(virSecretObjListPtr secrets,
                          virSecretDefPtr def,
                          const char *configDir,
                          virSecretDefPtr *oldDef)
{
    virSecretObjPtr secret;
    virSecretObjPtr ret = NULL;
    const char *newUsageID = virSecretUsageIDForDef(def);
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *configFile = NULL, *base64File = NULL;

    if (oldDef)
        *oldDef = NULL;

    /* Is there a secret already matching this UUID */
    if ((secret = virSecretObjListFindByUUIDLocked(secrets, def->uuid))) {
        const char *oldUsageID;

        virObjectLock(secret);

        oldUsageID = virSecretUsageIDForDef(secret->def);
        if (STRNEQ(oldUsageID, newUsageID)) {
            virUUIDFormat(secret->def->uuid, uuidstr);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %s is already defined for "
                             "use with %s"),
                           uuidstr, oldUsageID);
            goto cleanup;
        }

        if (secret->def->private && !def->private) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot change private flag on existing secret"));
            goto cleanup;
        }

        if (oldDef)
            *oldDef = secret->def;
        else
            virSecretDefFree(secret->def);
        secret->def = def;
    } else {
        /* No existing secret with same UUID,
         * try look for matching usage instead */
        if ((secret = virSecretObjListFindByUsageLocked(secrets,
                                                        def->usage_type,
                                                        newUsageID))) {
            virObjectLock(secret);
            virUUIDFormat(secret->def->uuid, uuidstr);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %s already defined for "
                             "use with %s"),
                           uuidstr, newUsageID);
            goto cleanup;
        }

        /* Generate the possible configFile and base64File strings
         * using the configDir, uuidstr, and appropriate suffix
         */
        virUUIDFormat(def->uuid, uuidstr);
        if (!(configFile = virFileBuildPath(configDir, uuidstr, ".xml")) ||
            !(base64File = virFileBuildPath(configDir, uuidstr, ".base64")))
            goto cleanup;

        if (!(secret = virSecretObjNew()))
            goto cleanup;

        virObjectLock(secret);

        if (virHashAddEntry(secrets->objs, uuidstr, secret) < 0)
            goto cleanup;

        secret->def = def;
        secret->configFile = configFile;
        secret->base64File = base64File;
        configFile = NULL;
        base64File = NULL;
        virObjectRef(secret);
    }

    ret = secret;
    secret = NULL;

 cleanup:
    virSecretObjEndAPI(&secret);
    VIR_FREE(configFile);
    VIR_FREE(base64File);
    return ret;
}


virSecretObjPtr
virSecretObjListAdd(virSecretObjListPtr secrets,
                    virSecretDefPtr def,
                    const char *configDir,
                    virSecretDefPtr *oldDef)
{
    virSecretObjPtr ret;

    virObjectLock(secrets);
    ret = virSecretObjListAddLocked(secrets, def, configDir, oldDef);
    virObjectUnlock(secrets);
    return ret;
}


struct virSecretObjListGetHelperData {
    virConnectPtr conn;
    virSecretObjListACLFilter filter;
    int got;
};


static int
virSecretObjListGetHelper(void *payload,
                          const void *name ATTRIBUTE_UNUSED,
                          void *opaque)
{
    struct virSecretObjListGetHelperData *data = opaque;
    virSecretObjPtr obj = payload;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    data->got++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virSecretObjListNumOfSecrets(virSecretObjListPtr secrets,
                             virSecretObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virSecretObjListGetHelperData data = {
        .conn = conn, .filter = filter, .got = 0 };

    virObjectLock(secrets);
    virHashForEach(secrets->objs, virSecretObjListGetHelper, &data);
    virObjectUnlock(secrets);

    return data.got;
}
