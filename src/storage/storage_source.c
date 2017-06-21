/*
 * storage_source.c: Storage source object accessors to real storage
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

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <string.h>

#include "virerror.h"
#include "storage_source.h"
#include "storage_backend.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virhash.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_source");


static bool
virStorageFileIsInitialized(const virStorageSource *src)
{
    return src && src->drv;
}


static bool
virStorageFileSupportsBackingChainTraversal(virStorageSourcePtr src)
{
    int actualType;
    virStorageFileBackendPtr backend;

    if (!src)
        return false;
    actualType = virStorageSourceGetActualType(src);

    if (src->drv) {
        backend = src->drv->backend;
    } else {
        if (!(backend = virStorageFileBackendForTypeInternal(actualType,
                                                             src->protocol,
                                                             false)))
            return false;
    }

    return backend->storageFileGetUniqueIdentifier &&
           backend->storageFileReadHeader &&
           backend->storageFileAccess;
}


/**
 * virStorageFileSupportsSecurityDriver:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports operations needed by the security
 * driver to perform labelling
 */
bool
virStorageFileSupportsSecurityDriver(const virStorageSource *src)
{
    int actualType;
    virStorageFileBackendPtr backend;

    if (!src)
        return false;
    actualType = virStorageSourceGetActualType(src);

    if (src->drv) {
        backend = src->drv->backend;
    } else {
        if (!(backend = virStorageFileBackendForTypeInternal(actualType,
                                                             src->protocol,
                                                             false)))
            return false;
    }

    return !!backend->storageFileChown;
}


void
virStorageFileDeinit(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src))
        return;

    if (src->drv->backend &&
        src->drv->backend->backendDeinit)
        src->drv->backend->backendDeinit(src);

    VIR_FREE(src->drv);
}


/**
 * virStorageFileInitAs:
 *
 * @src: storage source definition
 * @uid: uid used to access the file, or -1 for current uid
 * @gid: gid used to access the file, or -1 for current gid
 *
 * Initialize a storage source to be used with storage driver. Use the provided
 * uid and gid if possible for the operations.
 *
 * Returns 0 if the storage file was successfully initialized, -1 if the
 * initialization failed. Libvirt error is reported.
 */
int
virStorageFileInitAs(virStorageSourcePtr src,
                     uid_t uid, gid_t gid)
{
    int actualType = virStorageSourceGetActualType(src);
    if (VIR_ALLOC(src->drv) < 0)
        return -1;

    if (uid == (uid_t) -1)
        src->drv->uid = geteuid();
    else
        src->drv->uid = uid;

    if (gid == (gid_t) -1)
        src->drv->gid = getegid();
    else
        src->drv->gid = gid;

    if (!(src->drv->backend = virStorageFileBackendForType(actualType,
                                                           src->protocol)))
        goto error;

    if (src->drv->backend->backendInit &&
        src->drv->backend->backendInit(src) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(src->drv);
    return -1;
}


/**
 * virStorageFileInit:
 *
 * See virStorageFileInitAs. The file is initialized to be accessed by the
 * current user.
 */
int
virStorageFileInit(virStorageSourcePtr src)
{
    return virStorageFileInitAs(src, -1, -1);
}


/**
 * virStorageFileCreate: Creates an empty storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileCreate(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileCreate(src);

    VIR_DEBUG("created storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileUnlink: Unlink storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileUnlink(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileUnlink(src);

    VIR_DEBUG("unlinked storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileStat: returns stat struct of a file via storage driver
 *
 * @src: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageFileStat(virStorageSourcePtr src,
                   struct stat *st)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileStat) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileStat(src, st);

    VIR_DEBUG("stat of storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileReadHeader: read the beginning bytes of a file into a buffer
 *
 * @src: file structure pointing to the file
 * @max_len: maximum number of bytes read from the storage file
 * @buf: buffer to read the data into. buffer shall be freed by caller)
 *
 * Returns the count of bytes read on success and -1 on failure, -2 if the
 * function isn't supported by the backend.
 * Libvirt error is reported on failure.
 */
ssize_t
virStorageFileReadHeader(virStorageSourcePtr src,
                         ssize_t max_len,
                         char **buf)
{
    ssize_t ret;

    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return -1;
    }

    if (!src->drv->backend->storageFileReadHeader) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("storage file header reading is not supported for "
                         "storage type %s (protocol: %s)"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -2;
    }

    ret = src->drv->backend->storageFileReadHeader(src, max_len, buf);

    VIR_DEBUG("read of storage header %p: ret=%zd", src, ret);

    return ret;
}


/*
 * virStorageFileGetUniqueIdentifier: Get a unique string describing the volume
 *
 * @src: file structure pointing to the file
 *
 * Returns a string uniquely describing a single volume (canonical path).
 * The string shall not be freed and is valid until the storage file is
 * deinitialized. Returns NULL on error and sets a libvirt error code */
const char *
virStorageFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return NULL;
    }

    if (!src->drv->backend->storageFileGetUniqueIdentifier) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unique storage file identifier not implemented for "
                          "storage type %s (protocol: %s)'"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    return src->drv->backend->storageFileGetUniqueIdentifier(src);
}


/**
 * virStorageFileAccess: Check accessibility of a storage file
 *
 * @src: storage file to check access permissions
 * @mode: accessibility check options (see man 2 access)
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileAccess(virStorageSourcePtr src,
                     int mode)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileAccess) {
        errno = ENOSYS;
        return -2;
    }

    return src->drv->backend->storageFileAccess(src, mode);
}


/**
 * virStorageFileChown: Change owner of a storage file
 *
 * @src: storage file to change owner of
 * @uid: new owner id
 * @gid: new group id
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileChown(const virStorageSource *src,
                    uid_t uid,
                    gid_t gid)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileChown) {
        errno = ENOSYS;
        return -2;
    }

    VIR_DEBUG("chown of storage file %p to %u:%u",
              src, (unsigned int)uid, (unsigned int)gid);

    return src->drv->backend->storageFileChown(src, uid, gid);
}


/* Recursive workhorse for virStorageFileGetMetadata.  */
static int
virStorageFileGetMetadataRecurse(virStorageSourcePtr src,
                                 virStorageSourcePtr parent,
                                 uid_t uid, gid_t gid,
                                 bool allow_probe,
                                 bool report_broken,
                                 virHashTablePtr cycle)
{
    int ret = -1;
    const char *uniqueName;
    char *buf = NULL;
    ssize_t headerLen;
    virStorageSourcePtr backingStore = NULL;
    int backingFormat;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u probe=%d",
              src->path, src->format,
              (unsigned int)uid, (unsigned int)gid, allow_probe);

    /* exit if we can't load information about the current image */
    if (!virStorageFileSupportsBackingChainTraversal(src))
        return 0;

    if (virStorageFileInitAs(src, uid, gid) < 0)
        return -1;

    if (virStorageFileAccess(src, F_OK) < 0) {
        if (src == parent) {
            virReportSystemError(errno,
                                 _("Cannot access storage file '%s' "
                                   "(as uid:%u, gid:%u)"),
                                 src->path, (unsigned int)uid,
                                 (unsigned int)gid);
        } else {
            virReportSystemError(errno,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s' (as uid:%u, gid:%u)"),
                                 src->path, parent->path,
                                 (unsigned int)uid, (unsigned int)gid);
        }

        goto cleanup;
    }

    if (!(uniqueName = virStorageFileGetUniqueIdentifier(src)))
        goto cleanup;

    if (virHashLookup(cycle, uniqueName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %s (%s) is self-referential"),
                       src->path, uniqueName);
        goto cleanup;
    }

    if (virHashAddEntry(cycle, uniqueName, (void *)1) < 0)
        goto cleanup;

    if ((headerLen = virStorageFileReadHeader(src, VIR_STORAGE_MAX_HEADER,
                                              &buf)) < 0)
        goto cleanup;

    if (virStorageFileGetMetadataInternal(src, buf, headerLen,
                                          &backingFormat) < 0)
        goto cleanup;

    /* check whether we need to go deeper */
    if (!src->backingStoreRaw) {
        ret = 0;
        goto cleanup;
    }

    if (!(backingStore = virStorageSourceNewFromBacking(src)))
        goto cleanup;

    if (backingFormat == VIR_STORAGE_FILE_AUTO && !allow_probe)
        backingStore->format = VIR_STORAGE_FILE_RAW;
    else if (backingFormat == VIR_STORAGE_FILE_AUTO_SAFE)
        backingStore->format = VIR_STORAGE_FILE_AUTO;
    else
        backingStore->format = backingFormat;

    if ((ret = virStorageFileGetMetadataRecurse(backingStore, parent,
                                                uid, gid,
                                                allow_probe, report_broken,
                                                cycle)) < 0) {
        if (report_broken)
            goto cleanup;

        /* if we fail somewhere midway, just accept and return a
         * broken chain */
        ret = 0;
        goto cleanup;
    }

    src->backingStore = backingStore;
    backingStore = NULL;
    ret = 0;

 cleanup:
    VIR_FREE(buf);
    virStorageFileDeinit(src);
    virStorageSourceFree(backingStore);
    return ret;
}


/**
 * virStorageFileGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Recurses through
 * the entire chain.
 *
 * Open files using UID and GID (or pass -1 for the current user/group).
 * Treat any backing files without explicit type as raw, unless ALLOW_PROBE.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If @report_broken is true, the whole function fails with a possibly sane
 * error instead of just returning a broken chain.
 *
 * Caller MUST free result after use via virStorageSourceFree.
 */
int
virStorageFileGetMetadata(virStorageSourcePtr src,
                          uid_t uid, gid_t gid,
                          bool allow_probe,
                          bool report_broken)
{
    VIR_DEBUG("path=%s format=%d uid=%u gid=%u probe=%d, report_broken=%d",
              src->path, src->format, (unsigned int)uid, (unsigned int)gid,
              allow_probe, report_broken);

    virHashTablePtr cycle = NULL;
    int ret = -1;

    if (!(cycle = virHashCreate(5, NULL)))
        return -1;

    if (src->format <= VIR_STORAGE_FILE_NONE)
        src->format = allow_probe ?
            VIR_STORAGE_FILE_AUTO : VIR_STORAGE_FILE_RAW;

    ret = virStorageFileGetMetadataRecurse(src, src, uid, gid,
                                           allow_probe, report_broken, cycle);

    virHashFree(cycle);
    return ret;
}


/**
 * virStorageFileGetBackingStoreStr:
 * @src: storage object
 *
 * Extracts the backing store string as stored in the storage volume described
 * by @src and returns it to the user. Caller is responsible for freeing it.
 * In case when the string can't be retrieved or does not exist NULL is
 * returned.
 */
char *
virStorageFileGetBackingStoreStr(virStorageSourcePtr src)
{
    virStorageSourcePtr tmp = NULL;
    char *buf = NULL;
    ssize_t headerLen;
    char *ret = NULL;

    /* exit if we can't load information about the current image */
    if (!virStorageFileSupportsBackingChainTraversal(src))
        return NULL;

    if (virStorageFileAccess(src, F_OK) < 0)
        return NULL;

    if ((headerLen = virStorageFileReadHeader(src, VIR_STORAGE_MAX_HEADER,
                                              &buf)) < 0)
        return NULL;

    if (!(tmp = virStorageSourceCopy(src, false)))
        goto cleanup;

    if (virStorageFileGetMetadataInternal(tmp, buf, headerLen, NULL) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, tmp->backingStoreRaw);

 cleanup:
    VIR_FREE(buf);
    virStorageSourceFree(tmp);

    return ret;
}
