/*
 * secret_driver.c: local driver for secret manipulation API
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#include <config.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "base64.h"
#include "datatypes.h"
#include "driver.h"
#include "logging.h"
#include "memory.h"
#include "secret_conf.h"
#include "secret_driver.h"
#include "threads.h"
#include "util.h"
#include "uuid.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

enum { SECRET_MAX_XML_FILE = 10*1024*1024 };

 /* Internal driver state */

typedef struct _virSecretEntry virSecretEntry;
typedef virSecretEntry *virSecretEntryPtr;
struct _virSecretEntry {
    virSecretEntryPtr next;
    virSecretDefPtr def;
    unsigned char *value;       /* May be NULL */
    size_t value_size;
};

typedef struct _virSecretDriverState virSecretDriverState;
typedef virSecretDriverState *virSecretDriverStatePtr;
struct _virSecretDriverState {
    virMutex lock;
    virSecretEntry *secrets;
    char *directory;
};

static virSecretDriverStatePtr driverState;

static void
secretDriverLock(virSecretDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
secretDriverUnlock(virSecretDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

static virSecretEntryPtr
listUnlink(virSecretEntryPtr *pptr)
{
    virSecretEntryPtr secret;

    secret = *pptr;
    *pptr = secret->next;
    return secret;
}

static void
listInsert(virSecretEntryPtr *pptr, virSecretEntryPtr secret)
{
    secret->next = *pptr;
    *pptr = secret;
}

static void
secretFree(virSecretEntryPtr secret)
{
    if (secret == NULL)
        return;

    virSecretDefFree(secret->def);
    if (secret->value != NULL) {
        memset(secret->value, 0, secret->value_size);
        VIR_FREE(secret->value);
    }
    VIR_FREE(secret);
}

static virSecretEntryPtr *
secretFind(virSecretDriverStatePtr driver, const char *uuid)
{
    virSecretEntryPtr *pptr, s;

    for (pptr = &driver->secrets; *pptr != NULL; pptr = &s->next) {
        s = *pptr;
        if (STREQ(s->def->id, uuid))
            return pptr;
    }
    return NULL;
}

static virSecretEntryPtr
secretCreate(virConnectPtr conn, virSecretDriverStatePtr driver,
             const char *uuid)
{
    virSecretEntryPtr secret = NULL;

    if (VIR_ALLOC(secret) < 0 || VIR_ALLOC(secret->def))
        goto no_memory;
    secret->def->id = strdup(uuid);
    if (secret->def->id == NULL)
        goto no_memory;
    listInsert(&driver->secrets, secret);
    return secret;

 no_memory:
    virReportOOMError(conn);
    secretFree(secret);
    return NULL;
}

static virSecretEntryPtr
secretFindOrCreate(virConnectPtr conn, virSecretDriverStatePtr driver,
                   const char *uuid, bool *created_new)
{
    virSecretEntryPtr *pptr, secret;

    pptr = secretFind(driver, uuid);
    if (pptr != NULL) {
        if (created_new != NULL)
            *created_new = false;
        return *pptr;
    }

    secret = secretCreate(conn, driver, uuid);
    if (secret != NULL && created_new != NULL)
        *created_new = true;
    return secret;
}

 /* Permament secret storage */

/* Secrets are stored in virSecretDriverStatePtr->directory.  Each secret
   has virSecretDef stored as XML in "$basename.xml".  If a value of the
   secret is defined, it is stored as base64 (with no formatting) in
   "$basename.base64".  "$basename" is in both cases the base64-encoded UUID. */

static int
replaceFile(virConnectPtr conn, const char *filename, void *data, size_t size)
{
    char *tmp_path = NULL;
    int fd = -1, ret = -1;

    if (virAsprintf(&tmp_path, "%sXXXXXX", filename) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    fd = mkstemp (tmp_path);
    if (fd == -1) {
        virReportSystemError(conn, errno, _("mkstemp('%s') failed"), tmp_path);
        goto cleanup;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        virReportSystemError(conn, errno, _("fchmod('%s') failed"), tmp_path);
        goto cleanup;
    }

    ret = safewrite(fd, data, size);
    if (ret < 0) {
        virReportSystemError(conn, errno, _("error writing to '%s'"),
                              tmp_path);
        goto cleanup;
    }
    if (close(fd) < 0) {
        virReportSystemError(conn, errno, _("error closing '%s'"), tmp_path);
        goto cleanup;
    }
    fd = -1;

    if (rename(tmp_path, filename) < 0) {
        virReportSystemError(conn, errno, _("rename(%s, %s) failed"), tmp_path,
                             filename);
        goto cleanup;
    }
    VIR_FREE(tmp_path);
    ret = 0;

cleanup:
    if (fd != -1)
        close(fd);
    if (tmp_path != NULL) {
        unlink(tmp_path);
        VIR_FREE(tmp_path);
    }
    return ret;
}

static char *
secretComputePath(virConnectPtr conn, virSecretDriverStatePtr driver,
                  const virSecretEntry *secret, const char *suffix)
{
    char *ret, *base64_id;

    base64_encode_alloc(secret->def->id, strlen(secret->def->id), &base64_id);
    if (base64_id == NULL) {
        virReportOOMError(conn);
        return NULL;
    }

    if (virAsprintf(&ret, "%s/%s%s", driver->directory, base64_id, suffix) < 0)
        /* ret is NULL */
        virReportOOMError(conn);
    VIR_FREE(base64_id);
    return ret;
}

static char *
secretXMLPath(virConnectPtr conn, virSecretDriverStatePtr driver,
              const virSecretEntry *secret)
{
    return secretComputePath(conn, driver, secret, ".xml");
}

static char *
secretBase64Path(virConnectPtr conn, virSecretDriverStatePtr driver,
                 const virSecretEntry *secret)
{
    return secretComputePath(conn, driver, secret, ".base64");
}

static int
secretEnsureDirectory(virConnectPtr conn, virSecretDriverStatePtr driver)
{
    if (mkdir(driver->directory, S_IRWXU) < 0 && errno != EEXIST) {
        virReportSystemError(conn, errno, _("cannot create '%s'"),
                             driver->directory);
        return -1;
    }
    return 0;
}

static int
secretSaveDef(virConnectPtr conn, virSecretDriverStatePtr driver,
              const virSecretEntry *secret)
{
    char *filename = NULL, *xml = NULL;
    int ret = -1;

    if (secretEnsureDirectory(conn, driver) < 0)
        goto cleanup;

    filename = secretXMLPath(conn, driver, secret);
    if (filename == NULL)
        goto cleanup;
    xml = virSecretDefFormat(conn, secret->def);
    if (xml == NULL)
        goto cleanup;

    if (replaceFile(conn, filename, xml, strlen(xml)) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(xml);
    VIR_FREE(filename);
    return ret;
}

static int
secretSaveValue(virConnectPtr conn, virSecretDriverStatePtr driver,
                const virSecretEntry *secret)
{
    char *filename = NULL, *base64 = NULL;
    int ret = -1;

    if (secret->value == NULL)
        return 0;

    if (secretEnsureDirectory(conn, driver) < 0)
        goto cleanup;

    filename = secretBase64Path(conn, driver, secret);
    if (filename == NULL)
        goto cleanup;
    base64_encode_alloc((const char *)secret->value, secret->value_size,
                        &base64);
    if (base64 == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (replaceFile(conn, filename, base64, strlen(base64)) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(base64);
    VIR_FREE(filename);
    return ret;
}

static int
secretDeleteSaved(virConnectPtr conn, virSecretDriverStatePtr driver,
                  const virSecretEntry *secret)
{
    char *xml_filename = NULL, *value_filename = NULL;
    int ret = -1;

    xml_filename = secretXMLPath(conn, driver, secret);
    if (xml_filename == NULL)
        goto cleanup;
    value_filename = secretBase64Path(conn, driver, secret);
    if (value_filename == NULL)
        goto cleanup;

    if (unlink(xml_filename) < 0 && errno != ENOENT)
        goto cleanup;
    /* When the XML is missing, the rest may waste disk space, but the secret
       won't be loaded again, so we have succeeded already. */
    ret = 0;

    (void)unlink(value_filename);

cleanup:
    VIR_FREE(value_filename);
    VIR_FREE(xml_filename);
    return ret;
}

static int
secretLoadValidateUUID(virConnectPtr conn, virSecretDefPtr def,
                       const char *xml_basename)
{
    char *base64_id;

    if (def->id == NULL) {
        virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("<uuid> missing in secret description in '%s'"),
                             xml_basename);
        return -1;
    }

    base64_encode_alloc(def->id, strlen(def->id), &base64_id);
    if (base64_id == NULL) {
        virReportOOMError(conn);
        return -1;
    }
    if (!virFileMatchesNameSuffix(xml_basename, base64_id, ".xml")) {
        virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("<uuid> does not match secret file name '%s'"),
                             xml_basename);
        VIR_FREE(base64_id);
        return -1;
    }
    VIR_FREE(base64_id);

    return 0;
}

static int
secretLoadValue(virConnectPtr conn, virSecretDriverStatePtr driver,
                virSecretEntryPtr secret)
{
    int ret = -1, fd = -1;
    struct stat st;
    char *filename = NULL, *contents = NULL, *value = NULL;
    size_t value_size;

    filename = secretBase64Path(conn, driver, secret);
    if (filename == NULL)
        goto cleanup;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            ret = 0;
            goto cleanup;
        }
        virReportSystemError (conn, errno, _("cannot open '%s'"), filename);
        goto cleanup;
    }
    if (fstat(fd, &st) < 0) {
        virReportSystemError (conn, errno, _("cannot stat '%s'"), filename);
        goto cleanup;
    }
    if ((size_t)st.st_size != st.st_size) {
        virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("'%s' file does not fit in memory"), filename);
        goto cleanup;
    }

    if (VIR_ALLOC_N(contents, st.st_size) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    if (saferead(fd, contents, st.st_size) != st.st_size) {
        virReportSystemError (conn, errno, _("cannot read '%s'"), filename);
        goto cleanup;
    }
    close(fd);
    fd = -1;

    if (!base64_decode_alloc(contents, st.st_size, &value, &value_size)) {
        virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("invalid base64 in '%s'"), filename);
        goto cleanup;
    }
    if (value == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

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
    if (fd != -1)
        close(fd);
    VIR_FREE(filename);
    return ret;
}

static virSecretEntryPtr
secretLoad(virConnectPtr conn, virSecretDriverStatePtr driver,
           const char *xml_basename)
{
    virSecretDefPtr def;
    virSecretEntryPtr secret = NULL, ret = NULL;
    char *xml_filename;

    if (virAsprintf(&xml_filename, "%s/%s", driver->directory,
                    xml_basename) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    def = virSecretDefParseFile(conn, xml_filename);
    if (def == NULL)
        goto cleanup;
    VIR_FREE(xml_filename);

    if (secretLoadValidateUUID(conn, def, xml_basename) < 0)
        goto cleanup;

    if (VIR_ALLOC(secret) < 0)
        goto cleanup;
    secret->def = def;
    def = NULL;

    if (secretLoadValue(conn, driver, secret) < 0)
        goto cleanup;

    ret = secret;
    secret = NULL;

cleanup:
    secretFree(secret);
    virSecretDefFree(def);
    VIR_FREE(xml_filename);
    return ret;
}

static int
loadSecrets(virConnectPtr conn, virSecretDriverStatePtr driver,
            virSecretEntryPtr *dest)
{
    int ret = -1;
    DIR *dir = NULL;
    struct dirent *de;
    virSecretEntryPtr list = NULL;

    dir = opendir(driver->directory);
    if (dir == NULL) {
        if (errno == ENOENT)
            return 0;
        virReportSystemError(conn, errno, _("cannot open '%s'"),
                             driver->directory);
        goto cleanup;
    }
    while ((de = readdir(dir)) != NULL) {
        virSecretEntryPtr secret;

        if (STREQ(de->d_name, ".") || STREQ(de->d_name, ".."))
            continue;
        if (!virFileHasSuffix(de->d_name, ".xml"))
            continue;

        secret = secretLoad(conn, driver, de->d_name);
        if (secret == NULL) {
            virErrorPtr err = virGetLastError();

            VIR_ERROR(_("Error reading secret: %s\n"),
                      err != NULL ? err->message: "");
            virResetError(err);
            continue;
        }
        listInsert(&list, secret);
    }
    /* Ignore error reported by readdir(), if any.  It's better to keep the
       secrets we managed to find. */

    while (list != NULL) {
        virSecretEntryPtr s;

        s = listUnlink(&list);
        listInsert(dest, s);
    }

    ret = 0;

cleanup:
    while (list != NULL) {
        virSecretEntryPtr s;

        s = listUnlink(&list);
        secretFree(s);
    }
    if (dir != NULL)
        closedir(dir);
    return ret;
}

 /* Driver functions */

static virDrvOpenStatus
secretOpen(virConnectPtr conn, virConnectAuthPtr auth ATTRIBUTE_UNUSED,
           int flags ATTRIBUTE_UNUSED) {
    if (driverState == NULL)
        return VIR_DRV_OPEN_DECLINED;

    conn->secretPrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}

static int
secretClose(virConnectPtr conn) {
    conn->secretPrivateData = NULL;
    return 0;
}

static int
secretNumOfSecrets(virConnectPtr conn)
{
    virSecretDriverStatePtr driver = conn->secretPrivateData;
    int i;
    virSecretEntryPtr secret;

    secretDriverLock(driver);

    i = 0;
    for (secret = driver->secrets; secret != NULL; secret = secret->next)
        i++;

    secretDriverUnlock(driver);
    return i;
}

static int
secretListSecrets(virConnectPtr conn, char **uuids, int maxuuids)
{
    virSecretDriverStatePtr driver = conn->secretPrivateData;
    int i;
    virSecretEntryPtr secret;

    memset(uuids, 0, maxuuids * sizeof(*uuids));

    secretDriverLock(driver);

    i = 0;
    for (secret = driver->secrets; secret != NULL; secret = secret->next) {
        if (i == maxuuids)
            break;
        uuids[i] = strdup(secret->def->id);
        if (uuids[i] == NULL)
            goto cleanup;
        i++;
    }

    secretDriverUnlock(driver);
    return i;

cleanup:
    secretDriverUnlock(driver);

    for (i = 0; i < maxuuids; i++)
        VIR_FREE(uuids[i]);

    return -1;
}

static virSecretPtr
secretLookupByUUIDString(virConnectPtr conn, const char *uuid)
{
    virSecretDriverStatePtr driver = conn->secretPrivateData;
    virSecretPtr ret = NULL;
    virSecretEntryPtr *pptr;

    secretDriverLock(driver);

    pptr = secretFind(driver, uuid);
    if (pptr == NULL) {
        virSecretReportError(conn, VIR_ERR_NO_SECRET,
                             _("no secret with matching id '%s'"), uuid);
        goto cleanup;
    }

    ret = virGetSecret(conn, (*pptr)->def->id);

cleanup:
    secretDriverUnlock(driver);
    return ret;
}

static char *
secretGenerateUUID(virConnectPtr conn, virSecretDriverStatePtr driver)
{
    char *uuid = NULL;
    unsigned attempt;

    if (VIR_ALLOC_N(uuid, VIR_UUID_STRING_BUFLEN) < 0) {
        virReportOOMError(conn);
        goto error;
    }

    for (attempt = 0; attempt < 65536; attempt++) {
        unsigned char uuid_data[VIR_UUID_BUFLEN];

        if (virUUIDGenerate(uuid_data) < 0) {
            virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("unable to generate uuid"));
            goto error;
        }
        virUUIDFormat(uuid_data, uuid);
        if (secretFind(driver, uuid) == NULL)
            return uuid;
    }
    virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("too many conflicts when generating an uuid"));
    goto error;

error:
    VIR_FREE(uuid);
    return NULL;
}

static virSecretPtr
secretDefineXML(virConnectPtr conn, const char *xml,
                unsigned int flags ATTRIBUTE_UNUSED)
{
    virSecretDriverStatePtr driver = conn->secretPrivateData;
    virSecretPtr ret = NULL;
    virSecretEntryPtr secret;
    virSecretDefPtr backup, new_attrs;
    bool secret_is_new;

    new_attrs = virSecretDefParseString(conn, xml);
    if (new_attrs == NULL)
        return NULL;

    secretDriverLock(driver);

    if (new_attrs->id != NULL)
        secret = secretFindOrCreate(conn, driver, new_attrs->id,
                                    &secret_is_new);
    else {
        new_attrs->id = secretGenerateUUID(conn, driver);
        if (new_attrs->id == NULL)
            goto cleanup;
        secret = secretCreate(conn, driver, new_attrs->id);
        secret_is_new = true;
    }
    if (secret == NULL)
        goto cleanup;

    /* Save old values of the attributes */
    backup = secret->def;

    if (backup->private && !new_attrs->private) {
        virSecretReportError(conn, VIR_ERR_OPERATION_DENIED, "%s",
                             virErrorMsg(VIR_ERR_OPERATION_DENIED, NULL));
        goto cleanup;
    }

    secret->def = new_attrs;
    if (!new_attrs->ephemeral) {
        if (backup->ephemeral) {
            if (secretSaveValue(conn, driver, secret) < 0)
                goto restore_backup;
        }
        if (secretSaveDef(conn, driver, secret) < 0) {
            if (backup->ephemeral) {
                char *filename;

                /* Undo the secretSaveValue() above; ignore errors */
                filename = secretBase64Path(conn, driver, secret);
                if (filename != NULL)
                    (void)unlink(filename);
                VIR_FREE(filename);
            }
            goto restore_backup;
        }
    } else if (!backup->ephemeral) {
        if (secretDeleteSaved(conn, driver, secret) < 0)
            goto restore_backup;
    }
    /* Saved succesfully - drop old values */
    new_attrs = NULL;
    virSecretDefFree(backup);

    ret = virGetSecret(conn, secret->def->id);
    goto cleanup;

restore_backup:
    /* Error - restore previous state and free new attributes */
    secret->def = backup;
    if (secret_is_new) {
        /* "secret" was added to the head of the list above */
        if (listUnlink(&driverState->secrets) != secret)
            virSecretReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("list of secrets is inconsistent"));
        else
            secretFree(secret);
    }

cleanup:
    virSecretDefFree(new_attrs);
    secretDriverUnlock(driver);

    return ret;
}

static char *
secretGetXMLDesc(virSecretPtr obj, unsigned int flags ATTRIBUTE_UNUSED)
{
    virSecretDriverStatePtr driver = obj->conn->secretPrivateData;
    char *ret = NULL;
    virSecretEntryPtr *pptr;

    secretDriverLock(driver);

    pptr = secretFind(driver, obj->uuid);
    if (pptr == NULL) {
        virSecretReportError(obj->conn, VIR_ERR_NO_SECRET,
                             _("no secret with matching id '%s'"), obj->uuid);
        goto cleanup;
    }

    ret = virSecretDefFormat(obj->conn, (*pptr)->def);

cleanup:
    secretDriverUnlock(driver);

    return ret;
}

static int
secretSetValue(virSecretPtr obj, const unsigned char *value,
               size_t value_size, unsigned int flags ATTRIBUTE_UNUSED)
{
    virSecretDriverStatePtr driver = obj->conn->secretPrivateData;
    int ret = -1;
    unsigned char *old_value, *new_value;
    size_t old_value_size;
    virSecretEntryPtr secret, *pptr;

    if (VIR_ALLOC_N(new_value, value_size) < 0) {
        virReportOOMError(obj->conn);
        return -1;
    }

    secretDriverLock(driver);

    pptr = secretFind(driver, obj->uuid);
    if (pptr == NULL) {
        virSecretReportError(obj->conn, VIR_ERR_NO_SECRET,
                             _("no secret with matching id '%s'"), obj->uuid);
        goto cleanup;
    }
    secret = *pptr;

    old_value = secret->value;
    old_value_size = secret->value_size;

    memcpy(new_value, value, value_size);
    secret->value = new_value;
    secret->value_size = value_size;
    if (!secret->def->ephemeral) {
        if (secretSaveValue(obj->conn, driver, secret) < 0)
            goto restore_backup;
    }
    /* Saved succesfully - drop old value */
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
    secretDriverUnlock(driver);

    VIR_FREE(new_value);

    return ret;
}

static unsigned char *
secretGetValue(virSecretPtr obj, size_t *value_size, unsigned int flags)
{
    virSecretDriverStatePtr driver = obj->conn->secretPrivateData;
    unsigned char *ret = NULL;
    virSecretEntryPtr *pptr, secret;

    secretDriverLock(driver);

    pptr = secretFind(driver, obj->uuid);
    if (pptr == NULL) {
        virSecretReportError(obj->conn, VIR_ERR_NO_SECRET,
                             _("no secret with matching id '%s'"), obj->uuid);
        goto cleanup;
    }
    secret = *pptr;
    if (secret->value == NULL) {
        virSecretReportError(obj->conn, VIR_ERR_NO_SECRET,
                             _("secret '%s' does not have a value"), obj->uuid);
        goto cleanup;
    }

    if ((flags & VIR_SECRET_GET_VALUE_INTERNAL_CALL) == 0 &&
        secret->def->private) {
        virSecretReportError(obj->conn, VIR_ERR_OPERATION_DENIED, "%s",
                             _("secret is private"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(ret, secret->value_size) < 0) {
        virReportOOMError(obj->conn);
        goto cleanup;
    }
    memcpy(ret, secret->value, secret->value_size);
    *value_size = secret->value_size;

cleanup:
    secretDriverUnlock(driver);

    return ret;
}

static int
secretUndefine(virSecretPtr obj)
{
    virSecretDriverStatePtr driver = obj->conn->secretPrivateData;
    int ret = -1;
    virSecretEntryPtr *pptr, secret;

    secretDriverLock(driver);

    pptr = secretFind(driver, obj->uuid);
    if (pptr == NULL) {
        virSecretReportError(obj->conn, VIR_ERR_NO_SECRET,
                             _("no secret with matching id '%s'"), obj->uuid);
        goto cleanup;
    }

    secret = listUnlink(pptr);
    if (!secret->def->ephemeral) {
        if (secretDeleteSaved(obj->conn, driver, secret) < 0)
            goto restore_backup;
    }
    secretFree(secret);

    ret = 0;
    goto cleanup;

restore_backup:
    /* This may change the order of secrets in the list.  We don't care. */
    listInsert(&driver->secrets, secret);

cleanup:
    secretDriverUnlock(driver);

    return ret;
}

static int
secretDriverCleanup(void)
{
    if (driverState == NULL)
        return -1;

    secretDriverLock(driverState);

    while (driverState->secrets != NULL) {
        virSecretEntryPtr s;

        s = listUnlink(&driverState->secrets);
        secretFree(s);
    }
    VIR_FREE(driverState->directory);

    secretDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);
    VIR_FREE(driverState);

    return 0;
}

static int
secretDriverStartup(int privileged)
{
    char *base = NULL;

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        return -1;
    }
    secretDriverLock(driverState);

    if (privileged) {
        base = strdup(SYSCONF_DIR "/libvirt");
        if (base == NULL)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
        char *userdir = virGetUserDirectory(NULL, uid);

        if (!userdir)
            goto error;

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);
    }
    if (virAsprintf(&driverState->directory, "%s/secrets", base) == -1)
        goto out_of_memory;
    VIR_FREE(base);

    if (loadSecrets(NULL, driverState, &driverState->secrets) < 0)
        goto error;

    secretDriverUnlock(driverState);
    return 0;

 out_of_memory:
    VIR_ERROR0(_("Out of memory initializing secrets"));
 error:
    VIR_FREE(base);
    secretDriverUnlock(driverState);
    secretDriverCleanup();
    return -1;
}

static int
secretDriverReload(void)
{
    virSecretEntryPtr new_secrets = NULL;

    if (!driverState)
        return -1;

    secretDriverLock(driverState);

    if (loadSecrets(NULL, driverState, &new_secrets) < 0)
        goto end;

    /* Keep ephemeral secrets from current state.  Discard non-ephemeral secrets
       that were removed by the secrets directory.  */
    while (driverState->secrets != NULL) {
        virSecretEntryPtr s;

        s = listUnlink(&driverState->secrets);
        if (s->def->ephemeral)
            listInsert(&new_secrets, s);
        else
            secretFree(s);
    }
    driverState->secrets = new_secrets;

 end:
    secretDriverUnlock(driverState);
    return 0;
}

static virSecretDriver secretDriver = {
    .name = "secret",
    .open = secretOpen,
    .close = secretClose,
    .numOfSecrets = secretNumOfSecrets,
    .listSecrets = secretListSecrets,
    .lookupByUUIDString = secretLookupByUUIDString,
    .defineXML = secretDefineXML,
    .getXMLDesc = secretGetXMLDesc,
    .setValue = secretSetValue,
    .getValue = secretGetValue,
    .undefine = secretUndefine
};

static virStateDriver stateDriver = {
    .initialize = secretDriverStartup,
    .cleanup = secretDriverCleanup,
    .reload = secretDriverReload,
    .active = NULL      /* All persistent state is immediately saved to disk */
};

int
secretRegister(void)
{
    virRegisterSecretDriver(&secretDriver);
    virRegisterStateDriver(&stateDriver);
    return 0;
}
