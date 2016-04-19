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
#include "virhash.h"


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
