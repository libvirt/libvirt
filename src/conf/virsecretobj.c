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
