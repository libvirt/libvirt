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
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "datatypes.h"
#include "virsecretobj.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"
#include "virstring.h"
#include "base64.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("conf.virsecretobj");

struct _virSecretObj {
    virObjectLockable parent;
    char *configFile;
    char *base64File;
    virSecretDefPtr def;
    unsigned char *value;       /* May be NULL */
    size_t value_size;
};

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

static virSecretObjPtr
virSecretObjNew(void)
{
    virSecretObjPtr secret;

    if (virSecretObjInitialize() < 0)
        return NULL;

    if (!(secret = virObjectLockableNew(virSecretObjClass)))
        return NULL;

    virObjectLock(secret);

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
static virSecretObjPtr
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

    if (data->usageType != VIR_SECRET_USAGE_TYPE_NONE &&
        STREQ(secret->def->usage_id, data->usageID))
        found = 1;

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
static virSecretObjPtr
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
static virSecretObjPtr
virSecretObjListAddLocked(virSecretObjListPtr secrets,
                          virSecretDefPtr def,
                          const char *configDir,
                          virSecretDefPtr *oldDef)
{
    virSecretObjPtr secret;
    virSecretObjPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *configFile = NULL, *base64File = NULL;

    if (oldDef)
        *oldDef = NULL;

    /* Is there a secret already matching this UUID */
    if ((secret = virSecretObjListFindByUUIDLocked(secrets, def->uuid))) {
        virObjectLock(secret);

        if (STRNEQ_NULLABLE(secret->def->usage_id, def->usage_id)) {
            virUUIDFormat(secret->def->uuid, uuidstr);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %s is already defined for "
                             "use with %s"),
                           uuidstr, secret->def->usage_id);
            goto cleanup;
        }

        if (secret->def->isprivate && !def->isprivate) {
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
                                                        def->usage_id))) {
            virObjectLock(secret);
            virUUIDFormat(secret->def->uuid, uuidstr);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %s already defined for "
                             "use with %s"),
                           uuidstr, def->usage_id);
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
    char **uuids;
    int nuuids;
    bool error;
};


static int
virSecretObjListGetHelper(void *payload,
                          const void *name ATTRIBUTE_UNUSED,
                          void *opaque)
{
    struct virSecretObjListGetHelperData *data = opaque;
    virSecretObjPtr obj = payload;

    if (data->error)
        return 0;

    if (data->nuuids >= 0 && data->got == data->nuuids)
        return 0;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    if (data->uuids) {
        char *uuidstr;

        if (VIR_ALLOC_N(uuidstr, VIR_UUID_STRING_BUFLEN) < 0) {
            data->error = true;
            goto cleanup;
        }

        virUUIDFormat(obj->def->uuid, uuidstr);
        data->uuids[data->got] = uuidstr;
    }

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
        .conn = conn, .filter = filter, .got = 0,
        .uuids = NULL, .nuuids = -1, .error = false };

    virObjectLock(secrets);
    virHashForEach(secrets->objs, virSecretObjListGetHelper, &data);
    virObjectUnlock(secrets);

    return data.got;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virSecretObjMatchFlags(virSecretObjPtr secret,
                       unsigned int flags)
{
    /* filter by whether it's ephemeral */
    if (MATCH(VIR_CONNECT_LIST_SECRETS_FILTERS_EPHEMERAL) &&
        !((MATCH(VIR_CONNECT_LIST_SECRETS_EPHEMERAL) &&
           secret->def->isephemeral) ||
          (MATCH(VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL) &&
           !secret->def->isephemeral)))
        return false;

    /* filter by whether it's private */
    if (MATCH(VIR_CONNECT_LIST_SECRETS_FILTERS_PRIVATE) &&
        !((MATCH(VIR_CONNECT_LIST_SECRETS_PRIVATE) &&
           secret->def->isprivate) ||
          (MATCH(VIR_CONNECT_LIST_SECRETS_NO_PRIVATE) &&
           !secret->def->isprivate)))
        return false;

    return true;
}
#undef MATCH


struct virSecretObjListData {
    virConnectPtr conn;
    virSecretPtr *secrets;
    virSecretObjListACLFilter filter;
    unsigned int flags;
    int nsecrets;
    bool error;
};

static int
virSecretObjListExportCallback(void *payload,
                               const void *name ATTRIBUTE_UNUSED,
                               void *opaque)
{
    struct virSecretObjListData *data = opaque;
    virSecretObjPtr obj = payload;
    virSecretPtr secret = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    if (!virSecretObjMatchFlags(obj, data->flags))
        goto cleanup;

    if (!data->secrets) {
        data->nsecrets++;
        goto cleanup;
    }

    if (!(secret = virGetSecret(data->conn, obj->def->uuid,
                                obj->def->usage_type,
                                obj->def->usage_id))) {
        data->error = true;
        goto cleanup;
    }

    data->secrets[data->nsecrets++] = secret;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virSecretObjListExport(virConnectPtr conn,
                       virSecretObjListPtr secretobjs,
                       virSecretPtr **secrets,
                       virSecretObjListACLFilter filter,
                       unsigned int flags)
{
    struct virSecretObjListData data = {
        .conn = conn, .secrets = NULL,
        .filter = filter, .flags = flags,
        .nsecrets = 0, .error = false };

    virObjectLock(secretobjs);
    if (secrets &&
        VIR_ALLOC_N(data.secrets, virHashSize(secretobjs->objs) + 1) < 0) {
        virObjectUnlock(secretobjs);
        return -1;
    }

    virHashForEach(secretobjs->objs, virSecretObjListExportCallback, &data);
    virObjectUnlock(secretobjs);

    if (data.error)
        goto error;

    if (data.secrets) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.secrets, data.nsecrets + 1));
        *secrets = data.secrets;
    }

    return data.nsecrets;

 error:
    virObjectListFree(data.secrets);
    return -1;
}


int
virSecretObjListGetUUIDs(virSecretObjListPtr secrets,
                         char **uuids,
                         int nuuids,
                         virSecretObjListACLFilter filter,
                         virConnectPtr conn)
{
    int ret = -1;

    struct virSecretObjListGetHelperData data = {
        .conn = conn, .filter = filter, .got = 0,
        .uuids = uuids, .nuuids = nuuids, .error = false };

    virObjectLock(secrets);
    virHashForEach(secrets->objs, virSecretObjListGetHelper, &data);
    virObjectUnlock(secrets);

    if (data.error)
        goto cleanup;

    ret = data.got;

 cleanup:
    if (ret < 0) {
        while (data.got)
            VIR_FREE(data.uuids[--data.got]);
    }
    return ret;
}


int
virSecretObjDeleteConfig(virSecretObjPtr secret)
{
    if (!secret->def->isephemeral &&
        unlink(secret->configFile) < 0 && errno != ENOENT) {
        virReportSystemError(errno, _("cannot unlink '%s'"),
                             secret->configFile);
        return -1;
    }

    return 0;
}


void
virSecretObjDeleteData(virSecretObjPtr secret)
{
    /* The configFile will already be removed, so secret won't be
     * loaded again if this fails */
    (void)unlink(secret->base64File);
}


/* Permanent secret storage */

/* Secrets are stored in virSecretDriverStatePtr->configDir.  Each secret
   has virSecretDef stored as XML in "$basename.xml".  If a value of the
   secret is defined, it is stored as base64 (with no formatting) in
   "$basename.base64".  "$basename" is in both cases the base64-encoded UUID. */
int
virSecretObjSaveConfig(virSecretObjPtr secret)
{
    char *xml = NULL;
    int ret = -1;

    if (!(xml = virSecretDefFormat(secret->def)))
        goto cleanup;

    if (virFileRewriteStr(secret->configFile, S_IRUSR | S_IWUSR, xml) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    return ret;
}


int
virSecretObjSaveData(virSecretObjPtr secret)
{
    char *base64 = NULL;
    int ret = -1;

    if (!secret->value)
        return 0;

    if (!(base64 = virStringEncodeBase64(secret->value, secret->value_size)))
        goto cleanup;

    if (virFileRewriteStr(secret->base64File, S_IRUSR | S_IWUSR, base64) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(base64);
    return ret;
}


virSecretDefPtr
virSecretObjGetDef(virSecretObjPtr secret)
{
    return secret->def;
}


void
virSecretObjSetDef(virSecretObjPtr secret,
                   virSecretDefPtr def)
{
    secret->def = def;
}


unsigned char *
virSecretObjGetValue(virSecretObjPtr secret)
{
    unsigned char *ret = NULL;

    if (!secret->value) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(secret->def->uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("secret '%s' does not have a value"), uuidstr);
        goto cleanup;
    }

    if (VIR_ALLOC_N(ret, secret->value_size) < 0)
        goto cleanup;
    memcpy(ret, secret->value, secret->value_size);

 cleanup:
    return ret;
}


int
virSecretObjSetValue(virSecretObjPtr secret,
                     const unsigned char *value,
                     size_t value_size)
{
    unsigned char *old_value, *new_value;
    size_t old_value_size;

    if (VIR_ALLOC_N(new_value, value_size) < 0)
        return -1;

    old_value = secret->value;
    old_value_size = secret->value_size;

    memcpy(new_value, value, value_size);
    secret->value = new_value;
    secret->value_size = value_size;

    if (!secret->def->isephemeral && virSecretObjSaveData(secret) < 0)
        goto error;

    /* Saved successfully - drop old value */
    if (old_value) {
        memset(old_value, 0, old_value_size);
        VIR_FREE(old_value);
    }

    return 0;

 error:
    /* Error - restore previous state and free new value */
    secret->value = old_value;
    secret->value_size = old_value_size;
    memset(new_value, 0, value_size);
    VIR_FREE(new_value);
    return -1;
}


size_t
virSecretObjGetValueSize(virSecretObjPtr secret)
{
    return secret->value_size;
}


void
virSecretObjSetValueSize(virSecretObjPtr secret,
                         size_t value_size)
{
    secret->value_size = value_size;
}


static int
virSecretLoadValidateUUID(virSecretDefPtr def,
                          const char *file)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(def->uuid, uuidstr);

    if (!virFileMatchesNameSuffix(file, uuidstr, ".xml")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("<uuid> does not match secret file name '%s'"),
                       file);
        return -1;
    }

    return 0;
}


static int
virSecretLoadValue(virSecretObjPtr secret)
{
    int ret = -1, fd = -1;
    struct stat st;
    char *contents = NULL, *value = NULL;
    size_t value_size;

    if ((fd = open(secret->base64File, O_RDONLY)) == -1) {
        if (errno == ENOENT) {
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno, _("cannot open '%s'"),
                             secret->base64File);
        goto cleanup;
    }

    if (fstat(fd, &st) < 0) {
        virReportSystemError(errno, _("cannot stat '%s'"),
                             secret->base64File);
        goto cleanup;
    }

    if ((size_t)st.st_size != st.st_size) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("'%s' file does not fit in memory"),
                       secret->base64File);
        goto cleanup;
    }

    if (VIR_ALLOC_N(contents, st.st_size) < 0)
        goto cleanup;

    if (saferead(fd, contents, st.st_size) != st.st_size) {
        virReportSystemError(errno, _("cannot read '%s'"),
                             secret->base64File);
        goto cleanup;
    }

    VIR_FORCE_CLOSE(fd);

    if (!base64_decode_alloc(contents, st.st_size, &value, &value_size)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid base64 in '%s'"),
                       secret->base64File);
        goto cleanup;
    }
    if (value == NULL)
        goto cleanup;

    secret->value = (unsigned char *)value;
    value = NULL;
    secret->value_size = value_size;

    ret = 0;

 cleanup:
    if (value != NULL) {
        memset(value, 0, value_size);
        VIR_FREE(value);
    }
    if (contents != NULL) {
        memset(contents, 0, st.st_size);
        VIR_FREE(contents);
    }
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static virSecretObjPtr
virSecretLoad(virSecretObjListPtr secrets,
              const char *file,
              const char *path,
              const char *configDir)
{
    virSecretDefPtr def = NULL;
    virSecretObjPtr secret = NULL, ret = NULL;

    if (!(def = virSecretDefParseFile(path)))
        goto cleanup;

    if (virSecretLoadValidateUUID(def, file) < 0)
        goto cleanup;

    if (!(secret = virSecretObjListAdd(secrets, def, configDir, NULL)))
        goto cleanup;
    def = NULL;

    if (virSecretLoadValue(secret) < 0)
        goto cleanup;

    ret = secret;
    secret = NULL;

 cleanup:
    if (secret)
        virSecretObjListRemove(secrets, secret);
    virSecretDefFree(def);
    return ret;
}


int
virSecretLoadAllConfigs(virSecretObjListPtr secrets,
                        const char *configDir)
{
    DIR *dir = NULL;
    struct dirent *de;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    /* Ignore errors reported by readdir or other calls within the
     * loop (if any).  It's better to keep the secrets we managed to find. */
    while (virDirRead(dir, &de, NULL) > 0) {
        char *path;
        virSecretObjPtr secret;

        if (!virFileHasSuffix(de->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(configDir, de->d_name, NULL)))
            continue;

        if (!(secret = virSecretLoad(secrets, de->d_name, path, configDir))) {
            VIR_ERROR(_("Error reading secret: %s"),
                      virGetLastErrorMessage());
            VIR_FREE(path);
            continue;
        }

        VIR_FREE(path);
        virSecretObjEndAPI(&secret);
    }

    VIR_DIR_CLOSE(dir);
    return 0;
}
