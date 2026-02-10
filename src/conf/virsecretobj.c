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
#include "virsecret.h"
#include "virrandom.h"
#include "vircrypto.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("conf.virsecretobj");

struct _virSecretObj {
    virObjectLockable parent;
    char *configFile;
    char *secretValueFile;
    virSecretDef *def;
    unsigned char *value;       /* May be NULL */
    size_t value_size;
};

typedef struct _virSecretSchemeInfo {
    const char *suffix;
    virCryptoCipher cipher;
} virSecretSchemeInfo;

virSecretSchemeInfo schemeInfo[] = {
    { ".aes256cbc", VIR_CRYPTO_CIPHER_AES256CBC },
    { ".base64", -1 },
};

static virClass *virSecretObjClass;
static virClass *virSecretObjListClass;
static void virSecretObjDispose(void *obj);
static void virSecretObjListDispose(void *obj);

struct _virSecretObjList {
    virObjectRWLockable parent;

    /* uuid string -> virSecretObj  mapping
     * for O(1), lookup-by-uuid */
    GHashTable *objs;
};

struct virSecretSearchData {
    int usageType;
    const char *usageID;
};


static int
virSecretObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSecretObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virSecretObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virSecretObj);

static virSecretObj *
virSecretObjNew(void)
{
    virSecretObj *obj;

    if (virSecretObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virSecretObjClass)))
        return NULL;

    virObjectLock(obj);

    return obj;
}


void
virSecretObjEndAPI(virSecretObj **obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    g_clear_pointer(obj, virObjectUnref);
}


virSecretObjList *
virSecretObjListNew(void)
{
    virSecretObjList *secrets;

    if (virSecretObjInitialize() < 0)
        return NULL;

    if (!(secrets = virObjectRWLockableNew(virSecretObjListClass)))
        return NULL;

    if (!(secrets->objs = virHashNew(virObjectUnref))) {
        virObjectUnref(secrets);
        return NULL;
    }

    return secrets;
}


static void
virSecretObjDispose(void *opaque)
{
    virSecretObj *obj = opaque;

    virSecretDefFree(obj->def);
    if (obj->value) {
        /* Wipe before free to ensure we don't leave a secret on the heap */
        memset(obj->value, 0, obj->value_size);
        g_free(obj->value);
    }
    g_free(obj->configFile);
    g_free(obj->secretValueFile);
}


static void
virSecretObjListDispose(void *obj)
{
    virSecretObjList *secrets = obj;

    g_clear_pointer(&secrets->objs, g_hash_table_unref);
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
static virSecretObj *
virSecretObjListFindByUUIDLocked(virSecretObjList *secrets,
                                 const char *uuidstr)
{
    return virObjectRef(virHashLookup(secrets->objs, uuidstr));
}


/**
 * virSecretObjFindByUUID:
 * @secrets: list of secret objects
 * @uuidstr: secret uuid to find
 *
 * This function locks @secrets and finds the secret object which
 * corresponds to @uuid.
 *
 * Returns: locked and ref'd secret object.
 */
virSecretObj *
virSecretObjListFindByUUID(virSecretObjList *secrets,
                           const char *uuidstr)
{
    virSecretObj *obj;

    virObjectRWLockRead(secrets);
    obj = virSecretObjListFindByUUIDLocked(secrets, uuidstr);
    virObjectRWUnlock(secrets);
    if (obj)
        virObjectLock(obj);
    return obj;
}


static int
virSecretObjSearchName(const void *payload,
                       const char *name G_GNUC_UNUSED,
                       const void *opaque)
{
    virSecretObj *obj = (virSecretObj *) payload;
    virSecretDef *def;
    struct virSecretSearchData *data = (struct virSecretSearchData *) opaque;
    int found = 0;

    virObjectLock(obj);
    def = obj->def;

    if (def->usage_type != data->usageType)
        goto cleanup;

    if (data->usageType != VIR_SECRET_USAGE_TYPE_NONE &&
        STREQ(def->usage_id, data->usageID))
        found = 1;

 cleanup:
    virObjectUnlock(obj);
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
static virSecretObj *
virSecretObjListFindByUsageLocked(virSecretObjList *secrets,
                                  int usageType,
                                  const char *usageID)
{
    virSecretObj *obj = NULL;
    struct virSecretSearchData data = { .usageType = usageType,
                                        .usageID = usageID };

    obj = virHashSearch(secrets->objs, virSecretObjSearchName, &data, NULL);
    if (obj)
        virObjectRef(obj);
    return obj;
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
virSecretObj *
virSecretObjListFindByUsage(virSecretObjList *secrets,
                            int usageType,
                            const char *usageID)
{
    virSecretObj *obj;

    virObjectRWLockRead(secrets);
    obj = virSecretObjListFindByUsageLocked(secrets, usageType, usageID);
    virObjectRWUnlock(secrets);
    if (obj)
        virObjectLock(obj);
    return obj;
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
virSecretObjListRemove(virSecretObjList *secrets,
                       virSecretObj *obj)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virSecretDef *def;

    if (!obj)
        return;
    def = obj->def;

    virUUIDFormat(def->uuid, uuidstr);
    virObjectRef(obj);
    virObjectUnlock(obj);

    virObjectRWLockWrite(secrets);
    virObjectLock(obj);
    virHashRemoveEntry(secrets->objs, uuidstr);
    virSecretObjEndAPI(&obj);
    virObjectRWUnlock(secrets);
}


/*
 * virSecretObjListAdd:
 * @secrets: list of secret objects
 * @newdef: new secret definition
 * @configDir: directory to place secret config files
 * @oldDef: Former secret def (e.g. a reload path perhaps)
 *
 * Add the new @newdef to the secret obj table hash. Upon
 * successful the virSecret object is the owner of @newdef and
 * callers should use virSecretObjGetDef() if they need to access
 * the definition as @newdef is set to NULL.
 *
 * Returns: locked and ref'd secret or NULL if failure to add
 */
virSecretObj *
virSecretObjListAdd(virSecretObjList *secrets,
                    virSecretDef **newdef,
                    const char *configDir,
                    virSecretDef **oldDef)
{
    virSecretObj *obj;
    virSecretDef *objdef;
    virSecretObj *ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virObjectRWLockWrite(secrets);

    if (oldDef)
        *oldDef = NULL;

    virUUIDFormat((*newdef)->uuid, uuidstr);

    /* Is there a secret already matching this UUID */
    if ((obj = virSecretObjListFindByUUIDLocked(secrets, uuidstr))) {
        virObjectLock(obj);
        objdef = obj->def;

        if (STRNEQ_NULLABLE(objdef->usage_id, (*newdef)->usage_id)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %1$s is already defined for use with %2$s"),
                           uuidstr, objdef->usage_id);
            goto cleanup;
        }

        if (objdef->isprivate && !(*newdef)->isprivate) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot change private flag on existing secret"));
            goto cleanup;
        }

        if (oldDef)
            *oldDef = objdef;
        else
            virSecretDefFree(objdef);
        obj->def = g_steal_pointer(newdef);
    } else {
        /* No existing secret with same UUID,
         * try look for matching usage instead */
        if ((obj = virSecretObjListFindByUsageLocked(secrets,
                                                     (*newdef)->usage_type,
                                                     (*newdef)->usage_id))) {
            virObjectLock(obj);
            objdef = obj->def;
            virUUIDFormat(objdef->uuid, uuidstr);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a secret with UUID %1$s already defined for use with %2$s"),
                           uuidstr, (*newdef)->usage_id);
            goto cleanup;
        }

        if (!(obj = virSecretObjNew()))
            goto cleanup;
        /* Generate the possible configFile and secretValueFile strings
         * using the configDir, uuidstr, and appropriate suffix.
         * Note that secretValueFile extension is not set here. It is determined
         * based on a) existing availability of secret file (virSecretLoadValue) or
         * b) target storage format (virSecretObjSaveData)
         */
        if (!(obj->configFile = virFileBuildPath(configDir, uuidstr, ".xml")) ||
            !(obj->secretValueFile = virFileBuildPath(configDir, uuidstr, NULL)))
            goto cleanup;

        if (virHashAddEntry(secrets->objs, uuidstr, obj) < 0)
            goto cleanup;

        obj->def = g_steal_pointer(newdef);
        virObjectRef(obj);
    }

    ret = g_steal_pointer(&obj);

 cleanup:
    virSecretObjEndAPI(&obj);
    virObjectRWUnlock(secrets);
    return ret;
}


struct virSecretCountData {
    virConnectPtr conn;
    virSecretObjListACLFilter filter;
    int count;
};

static int
virSecretObjListNumOfSecretsCallback(void *payload,
                                     const char *name G_GNUC_UNUSED,
                                     void *opaque)
{
    struct virSecretCountData *data = opaque;
    virSecretObj *obj = payload;
    virSecretDef *def;

    virObjectLock(obj);
    def = obj->def;

    if (data->filter && !data->filter(data->conn, def))
        goto cleanup;

    data->count++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


struct virSecretListData {
    virConnectPtr conn;
    virSecretObjListACLFilter filter;
    int nuuids;
    char **uuids;
    int maxuuids;
    bool error;
};


static int
virSecretObjListGetUUIDsCallback(void *payload,
                                 const char *name G_GNUC_UNUSED,
                                 void *opaque)
{
    struct virSecretListData *data = opaque;
    virSecretObj *obj = payload;
    virSecretDef *def;

    if (data->error)
        return 0;

    if (data->maxuuids >= 0 && data->nuuids == data->maxuuids)
        return 0;

    virObjectLock(obj);
    def = obj->def;

    if (data->filter && !data->filter(data->conn, def))
        goto cleanup;

    if (data->uuids) {
        char *uuidstr;

        uuidstr = g_new0(char, VIR_UUID_STRING_BUFLEN);

        virUUIDFormat(def->uuid, uuidstr);
        data->uuids[data->nuuids++] = uuidstr;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virSecretObjListNumOfSecrets(virSecretObjList *secrets,
                             virSecretObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virSecretCountData data = {
        .conn = conn, .filter = filter, .count = 0 };

    virObjectRWLockRead(secrets);
    virHashForEach(secrets->objs, virSecretObjListNumOfSecretsCallback, &data);
    virObjectRWUnlock(secrets);

    return data.count;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virSecretObjMatch(virSecretObj *obj,
                  unsigned int flags)
{
    virSecretDef *def = obj->def;

    /* filter by whether it's ephemeral */
    if (MATCH(VIR_CONNECT_LIST_SECRETS_FILTERS_EPHEMERAL) &&
        !((MATCH(VIR_CONNECT_LIST_SECRETS_EPHEMERAL) &&
           def->isephemeral) ||
          (MATCH(VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL) &&
           !def->isephemeral)))
        return false;

    /* filter by whether it's private */
    if (MATCH(VIR_CONNECT_LIST_SECRETS_FILTERS_PRIVATE) &&
        !((MATCH(VIR_CONNECT_LIST_SECRETS_PRIVATE) &&
           def->isprivate) ||
          (MATCH(VIR_CONNECT_LIST_SECRETS_NO_PRIVATE) &&
           !def->isprivate)))
        return false;

    return true;
}
#undef MATCH


typedef struct _virSecretObjListExportData virSecretObjListExportData;
struct _virSecretObjListExportData {
    virConnectPtr conn;
    virSecretPtr *secrets;
    virSecretObjListACLFilter filter;
    unsigned int flags;
    int nsecrets;
    bool error;
};

static int
virSecretObjListExportCallback(void *payload,
                               const char *name G_GNUC_UNUSED,
                               void *opaque)
{
    virSecretObjListExportData *data = opaque;
    virSecretObj *obj = payload;
    virSecretDef *def;
    virSecretPtr secret = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);
    def = obj->def;

    if (data->filter && !data->filter(data->conn, def))
        goto cleanup;

    if (!virSecretObjMatch(obj, data->flags))
        goto cleanup;

    if (!data->secrets) {
        data->nsecrets++;
        goto cleanup;
    }

    if (!(secret = virGetSecret(data->conn, def->uuid,
                                def->usage_type,
                                def->usage_id))) {
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
                       virSecretObjList *secretobjs,
                       virSecretPtr **secrets,
                       virSecretObjListACLFilter filter,
                       unsigned int flags)
{
    virSecretObjListExportData data = {
        .conn = conn, .secrets = NULL,
        .filter = filter, .flags = flags,
        .nsecrets = 0, .error = false };

    virObjectRWLockRead(secretobjs);
    if (secrets)
        data.secrets = g_new0(virSecretPtr, virHashSize(secretobjs->objs) + 1);

    virHashForEach(secretobjs->objs, virSecretObjListExportCallback, &data);
    virObjectRWUnlock(secretobjs);

    if (data.error)
        goto error;

    if (data.secrets) {
        /* trim the array to the final size */
        VIR_REALLOC_N(data.secrets, data.nsecrets + 1);
        *secrets = data.secrets;
    }

    return data.nsecrets;

 error:
    virObjectListFree(data.secrets);
    return -1;
}


int
virSecretObjListGetUUIDs(virSecretObjList *secrets,
                         char **uuids,
                         int maxuuids,
                         virSecretObjListACLFilter filter,
                         virConnectPtr conn)
{
    struct virSecretListData data = {
        .conn = conn, .filter = filter, .uuids = uuids, .nuuids = 0,
        .maxuuids = maxuuids, .error = false };

    virObjectRWLockRead(secrets);
    virHashForEach(secrets->objs, virSecretObjListGetUUIDsCallback, &data);
    virObjectRWUnlock(secrets);

    if (data.error)
        goto error;

    return data.nuuids;

 error:
    while (--data.nuuids)
        VIR_FREE(data.uuids[data.nuuids]);
    return -1;
}


int
virSecretObjDeleteConfig(virSecretObj *obj)
{
    virSecretDef *def = obj->def;

    if (!def->isephemeral &&
        unlink(obj->configFile) < 0 && errno != ENOENT) {
        virReportSystemError(errno, _("cannot unlink '%1$s'"),
                             obj->configFile);
        return -1;
    }

    return 0;
}


void
virSecretObjDeleteData(virSecretObj *obj)
{
    size_t i;

    /* The configFile will already be removed, so secret won't be
     * loaded again if this fails */
    for (i = 0; i < G_N_ELEMENTS(schemeInfo); i++) {
        g_autofree char *deleteFile = g_strconcat(obj->secretValueFile, schemeInfo[i].suffix, NULL);

        ignore_value(unlink(deleteFile));
    }
}


/* Permanent secret storage */

/* Secrets are stored in virSecretDriverState *->configDir.  Each secret
   has virSecretDef stored as XML in "$basename.xml".  If a value of the
   secret is defined, it is stored as base64 (with no formatting) in
   "$basename.base64".  "$basename" is in both cases the base64-encoded UUID. */
int
virSecretObjSaveConfig(virSecretObj *obj)
{
    g_autofree char *xml = NULL;

    if (!(xml = virSecretDefFormat(obj->def)))
        return -1;

    if (virFileRewriteStr(obj->configFile, S_IRUSR | S_IWUSR, xml) < 0)
        return -1;

    return 0;
}


int
virSecretObjSaveData(virSecretObj *obj,
                     bool encryptData,
                     uint8_t *secretsEncryptionKey,
                     size_t secretsKeyLen)
{
    g_autofree char *base64 = NULL;
    g_autofree char *filename = NULL;
    size_t i;
    g_autofree unsigned char *secretbuf = NULL;
    const unsigned char *secret = NULL;
    size_t secretLen = 0;

    if (!obj->value)
        return 0;

    /* Based on whether encryption is on/off, save the secret in either
     * the latest encryption scheme or in base64 formats.
     * Subsequently, delete the other formats of the same uuid on the disk.
     */
    if (encryptData && secretsEncryptionKey) {
        g_autofree uint8_t *encryptedValue = NULL;
        size_t encryptedValueLen = 0;
        const size_t ivlen = 16;
        g_autofree unsigned char *ivbuf = g_new0(unsigned char, ivlen);

        filename = g_strconcat(obj->secretValueFile, schemeInfo[0].suffix, NULL);

        if (virRandomBytes(ivbuf, ivlen) < 0)
            return -1;

        if (virCryptoEncryptData(schemeInfo[0].cipher,
                                 secretsEncryptionKey, secretsKeyLen,
                                 ivbuf, ivlen,
                                 (uint8_t *)obj->value, obj->value_size,
                                 &encryptedValue, &encryptedValueLen) < 0)
            return -1;

        ivbuf = g_realloc(ivbuf, ivlen + encryptedValueLen);
        memcpy(ivbuf + ivlen, encryptedValue, encryptedValueLen);

        secretbuf = g_steal_pointer(&ivbuf);
        secret = secretbuf;
        secretLen = ivlen + encryptedValueLen;
    } else {
        filename = g_strconcat(obj->secretValueFile, schemeInfo[G_N_ELEMENTS(schemeInfo) - 1].suffix, NULL);
        secret = (unsigned char *) obj->value;
        secretLen = obj->value_size;
    }

    base64 = g_base64_encode(secret, secretLen);

    if (virFileRewriteStr(filename, S_IRUSR | S_IWUSR, base64) < 0)
        return -1;

    for (i = 0; i < G_N_ELEMENTS(schemeInfo); i++) {
        g_autofree char *deleteFile = g_strconcat(obj->secretValueFile, schemeInfo[i].suffix, NULL);

        if (STREQ(filename, deleteFile))
            continue;

        ignore_value(unlink(deleteFile));
    }

    return 0;
}


virSecretDef *
virSecretObjGetDef(virSecretObj *obj)
{
    return obj->def;
}


void
virSecretObjSetDef(virSecretObj *obj,
                   virSecretDef *def)
{
    obj->def = def;
}


unsigned char *
virSecretObjGetValue(virSecretObj *obj)
{
    virSecretDef *def = obj->def;
    unsigned char *ret = NULL;

    if (!obj->value) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(def->uuid, uuidstr);
        virReportError(VIR_ERR_NO_SECRET,
                       _("secret '%1$s' does not have a value"), uuidstr);
        return NULL;
    }

    ret = g_new0(unsigned char, obj->value_size);
    memcpy(ret, obj->value, obj->value_size);

    return ret;
}


int
virSecretObjSetValue(virSecretObj *obj,
                     const unsigned char *value,
                     size_t value_size,
                     bool encryptData,
                     uint8_t *secretsEncryptionKey,
                     size_t secretsKeyLen)
{
    virSecretDef *def = obj->def;
    g_autofree unsigned char *old_value = NULL;
    g_autofree unsigned char *new_value = NULL;
    size_t old_value_size;

    new_value = g_new0(unsigned char, value_size);

    old_value = obj->value;
    old_value_size = obj->value_size;

    memcpy(new_value, value, value_size);
    obj->value = g_steal_pointer(&new_value);
    obj->value_size = value_size;

    if (!def->isephemeral && virSecretObjSaveData(obj,
                                                  encryptData,
                                                  secretsEncryptionKey,
                                                  secretsKeyLen) < 0)
        goto error;

    /* Saved successfully - drop old value */
    if (old_value)
        memset(old_value, 0, old_value_size);

    return 0;

 error:
    /* Error - restore previous state and free new value */
    new_value = g_steal_pointer(&obj->value);
    obj->value = g_steal_pointer(&old_value);
    obj->value_size = old_value_size;
    memset(new_value, 0, value_size);
    return -1;
}


size_t
virSecretObjGetValueSize(virSecretObj *obj)
{
    return obj->value_size;
}


void
virSecretObjSetValueSize(virSecretObj *obj,
                         size_t value_size)
{
    obj->value_size = value_size;
}


static int
virSecretLoadValidateUUID(virSecretDef *def,
                          const char *file)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(def->uuid, uuidstr);

    if (!virStringMatchesNameSuffix(file, uuidstr, ".xml")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("<uuid> does not match secret file name '%1$s'"),
                       file);
        return -1;
    }

    return 0;
}


static int
virSecretLoadValue(virSecretObj *obj,
                   uint8_t *secretsEncryptionKey,
                   size_t secretsKeyLen)
{
    const size_t secretFileMaxLen = 10 * 1024 * 1024; /* more won't fit in the RPC buffer */
    size_t i;

    /* Find the file and match the storage scheme based on suffix. */
    for (i = 0; i < G_N_ELEMENTS(schemeInfo); i++) {
        g_autofree char *filename = g_strconcat(obj->secretValueFile,
                                                schemeInfo[i].suffix, NULL);
        g_autofree char *filecontent = NULL;
        int filelen = 0;
        g_autofree unsigned char *decoded = NULL;
        size_t decodedlen = 0;

        if (!virFileExists(filename))
            continue;

        if ((filelen = virFileReadAll(filename, secretFileMaxLen, &filecontent)) < 0)
            return -1;

        filecontent = g_realloc(filecontent, filelen + 1);
        filecontent[filelen] = '\0';

        decoded = g_base64_decode(filecontent, &decodedlen);

        virSecureErase(filecontent, filelen);

        if (schemeInfo[i].cipher == -1) {
            obj->value = g_steal_pointer(&decoded);
            obj->value_size = decodedlen;
        } else {
            size_t ivlen = 16;
            int rc;

            if (decodedlen < ivlen) {
                virReportError(VIR_ERR_INVALID_SECRET,
                               _("Encrypted secret size '%1$zu' is invalid"),
                               obj->value_size);

                virSecureErase(decoded, decodedlen);
                return -1;
            }

            rc = virCryptoDecryptData(schemeInfo[i].cipher,
                                      secretsEncryptionKey, secretsKeyLen,
                                      decoded, ivlen, /* initialization vector is stored at start of the buffer */
                                      decoded + ivlen, decodedlen - ivlen,
                                      &obj->value, &obj->value_size);

            virSecureErase(decoded, decodedlen);

            if (rc < 0)
                return -1;
        }
    }

    return 0;
}


static virSecretObj *
virSecretLoad(virSecretObjList *secrets,
              const char *file,
              const char *path,
              const char *configDir,
              uint8_t *secretsEncryptionKey,
              size_t secretsKeyLen)
{
    g_autoptr(virSecretDef) def = NULL;
    virSecretObj *obj = NULL;

    if (!(def = virSecretDefParse(NULL, path, 0)))
        return NULL;

    if (virSecretLoadValidateUUID(def, file) < 0)
        return NULL;

    if (!(obj = virSecretObjListAdd(secrets, &def, configDir, NULL)))
        return NULL;

    if (virSecretLoadValue(obj, secretsEncryptionKey, secretsKeyLen) < 0) {
        virSecretObjListRemove(secrets, obj);
        g_clear_pointer(&obj, virObjectUnref);
        return NULL;
    }

    return obj;
}


int
virSecretLoadAllConfigs(virSecretObjList *secrets,
                        const char *configDir,
                        uint8_t *secretsEncryptionKey,
                        size_t secretsKeyLen)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *de;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    /* Ignore errors reported by readdir or other calls within the
     * loop (if any).  It's better to keep the secrets we managed to find. */
    while (virDirRead(dir, &de, NULL) > 0) {
        g_autofree char *path = NULL;
        virSecretObj *obj;

        if (!virStringHasSuffix(de->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(configDir, de->d_name, NULL)))
            continue;

        if (!(obj = virSecretLoad(secrets, de->d_name, path, configDir,
                                  secretsEncryptionKey,
                                  secretsKeyLen))) {
            VIR_ERROR(_("Error reading secret: %1$s"),
                      virGetLastErrorMessage());
            continue;
        }

        virSecretObjEndAPI(&obj);
    }

    return 0;
}
