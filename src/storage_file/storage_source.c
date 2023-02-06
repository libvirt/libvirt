/*
 * storage_source.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2017 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
#include <unistd.h>

#include "internal.h"
#include "storage_file_backend.h"
#include "storage_file_probe.h"
#include "storage_source.h"
#include "storage_source_backingstore.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"
#include "virstoragefile.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage_source");


static bool
virStorageSourceBackinStoreStringIsFile(const char *backing)
{
    char *colon;
    char *slash;

    if (!backing)
        return false;

    colon = strchr(backing, ':');
    slash = strchr(backing, '/');

    /* Reject anything that looks like a protocol (such as nbd: or
     * rbd:); if someone really does want a relative file name that
     * includes ':', they can always prefix './'.  */
    if (colon && (!slash || colon < slash))
        return false;
    return true;
}


static bool
virStorageSourceBackinStoreStringIsRelative(const char *backing)
{
    if (g_path_is_absolute(backing))
        return false;

    if (!virStorageSourceBackinStoreStringIsFile(backing))
        return false;

    return true;
}


static virStorageSource *
virStorageSourceMetadataNew(const char *path,
                            int format)
{
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    def->format = format;
    def->type = VIR_STORAGE_TYPE_FILE;

    def->path = g_strdup(path);

    return g_steal_pointer(&def);
}


/**
 * virStorageSourceGetMetadataFromBuf:
 * @path: name of file, for error messages
 * @buf: header bytes from @path
 * @len: length of @buf
 * @format: format of the storage file
 *
 * Extract metadata about the storage volume with the specified image format.
 * If image format is VIR_STORAGE_FILE_AUTO, it will probe to automatically
 * identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a format on a file
 * that might be raw if that file will then be passed to a guest, since a
 * malicious guest can turn a raw file into any other non-raw format at will.
 *
 * If the 'backingStoreRawFormat' field of the returned structure is
 * VIR_STORAGE_FILE_AUTO it indicates the image didn't specify an explicit
 * format for its backing store. Callers are advised against probing for the
 * backing store format in this case.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSource *
virStorageSourceGetMetadataFromBuf(const char *path,
                                   char *buf,
                                   size_t len,
                                   int format)
{
    virStorageSource *ret = NULL;

    if (!(ret = virStorageSourceMetadataNew(path, format)))
        return NULL;

    if (virStorageFileProbeGetMetadata(ret, buf, len) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    return ret;
}


/**
 * virStorageSourceGetMetadataFromFD:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSource *
virStorageSourceGetMetadataFromFD(const char *path,
                                  int fd,
                                  int format)

{
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    struct stat sb;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) meta = NULL;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%1$s'"), path);
        return NULL;
    }

    if (!(meta = virStorageSourceMetadataNew(path, format)))
        return NULL;

    if (S_ISDIR(sb.st_mode)) {
        /* No header to probe for directories, but also no backing file. Just
         * update the metadata.*/
        meta->type = VIR_STORAGE_TYPE_DIR;
        meta->format = VIR_STORAGE_FILE_DIR;
        return g_steal_pointer(&meta);
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%1$s'"), meta->path);
        return NULL;
    }

    if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%1$s'"), meta->path);
        return NULL;
    }

    if (virStorageFileProbeGetMetadata(meta, buf, len) < 0)
        return NULL;

    if (S_ISREG(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_FILE;
    else if (S_ISBLK(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_BLOCK;

    return g_steal_pointer(&meta);
}


/**
 * virStorageSourceChainLookup:
 * @chain: chain top to look in
 * @startFrom: move the starting point of @chain if non-NULL
 * @name: name of the file to look for in @chain
 * @diskTarget: optional disk target to validate against
 * @parent: Filled with parent virStorageSource of the returned value if non-NULL.
 *
 * Looks up a storage source definition corresponding to @name in @chain and
 * returns the corresponding virStorageSource. If @startFrom is non-NULL, the
 * lookup starts from that virStorageSource.
 *
 * @name can be:
 *  - NULL: the end of the source chain is returned
 *  - "vda[4]": Storage source with 'id' == 4 is returned. If @diskTarget is
 *              non-NULL it's also validated that the part before the square
 *              bracket matches the requested target
 *  - "/path/to/file": Literal path is matched. Symlink resolution is attempted
 *                     if the filename doesn't string-match with the path.
 */
virStorageSource *
virStorageSourceChainLookup(virStorageSource *chain,
                            virStorageSource *startFrom,
                            const char *name,
                            const char *diskTarget,
                            virStorageSource **parent)
{
    virStorageSource *prev;
    const char *start = chain->path;
    bool nameIsFile = virStorageSourceBackinStoreStringIsFile(name);
    g_autofree char *target = NULL;
    unsigned int idx = 0;

    if (diskTarget)
        start = diskTarget;

    if (!parent)
        parent = &prev;
    *parent = NULL;

    /* parse the "vda[4]" type string */
    if (name &&
        virStorageFileParseBackingStoreStr(name, &target, &idx) == 0) {
        if (diskTarget &&
            idx != 0 &&
            STRNEQ(diskTarget, target)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("requested target '%1$s' does not match target '%2$s'"),
                           target, diskTarget);
            return NULL;
        }
    }

    if (startFrom) {
        while (virStorageSourceIsBacking(chain) &&
               chain != startFrom->backingStore)
            chain = chain->backingStore;

        *parent = startFrom;
    }

    while (virStorageSourceIsBacking(chain)) {
        if (!name && !idx) {
            if (!virStorageSourceHasBacking(chain))
                break;
        } else if (idx) {
            VIR_DEBUG("%u: %s", chain->id, chain->path);
            if (idx == chain->id)
                break;
        } else {
            if (STREQ_NULLABLE(name, chain->relPath) ||
                STREQ_NULLABLE(name, chain->path))
                break;

            if (nameIsFile && virStorageSourceIsLocalStorage(chain)) {
                g_autofree char *parentDir = NULL;
                int result;

                if (*parent && virStorageSourceIsLocalStorage(*parent))
                    parentDir = g_path_get_dirname((*parent)->path);
                else
                    parentDir = g_strdup(".");

                result = virFileRelLinkPointsTo(parentDir, name,
                                                chain->path);

                if (result < 0)
                    goto error;

                if (result > 0)
                    break;
            }
        }
        *parent = chain;
        chain = chain->backingStore;
    }

    if (!virStorageSourceIsBacking(chain))
        goto error;

    return chain;

 error:
    if (idx) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find backing store index '%1$u' in chain for '%2$s'"),
                       idx, NULLSTR(start));
    } else if (name) {
        if (startFrom)
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%1$s' beneath '%2$s' in chain for '%3$s'"),
                           name, NULLSTR(startFrom->path), NULLSTR(start));
        else
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%1$s' in chain for '%2$s'"),
                           name, NULLSTR(start));
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find base image in chain for '%1$s'"),
                       NULLSTR(start));
    }
    *parent = NULL;
    return NULL;
}


/**
 * virStorageSourceChainLookupBySource:
 * @chain: chain top to look in
 * @base: storage source to look for in @chain
 * @parent: Filled with parent virStorageSource of the returned value if non-NULL.
 *
 * Looks up a storage source definition corresponding to @base in @chain.
 *
 * Returns virStorageSource within chain or NULL if not found.
 */
virStorageSource *
virStorageSourceChainLookupBySource(virStorageSource *chain,
                                    virStorageSource *base,
                                    virStorageSource **parent)
{
    virStorageSource *prev = NULL;

    if (parent)
        *parent = NULL;

    while (virStorageSourceIsBacking(chain)) {
        if (virStorageSourceIsSameLocation(chain, base))
            break;

        prev = chain;
        chain = chain->backingStore;
    }

    if (!virStorageSourceIsBacking(chain)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("could not find base disk source in disk source chain"));
        return NULL;
    }

    if (parent)
        *parent = prev;
    return chain;
}


static virStorageSource *
virStorageSourceNewFromBackingRelative(virStorageSource *parent,
                                       const char *rel)
{
    g_autofree char *dirname = NULL;
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    /* store relative name */
    def->relPath = g_strdup(rel);

    dirname = g_path_get_dirname(parent->path);

    if (STRNEQ(dirname, "/")) {
        def->path = g_strdup_printf("%s/%s", dirname, rel);
    } else {
        def->path = g_strdup_printf("/%s", rel);
    }

    if (virStorageSourceGetActualType(parent) == VIR_STORAGE_TYPE_NETWORK) {
        def->type = VIR_STORAGE_TYPE_NETWORK;

        /* copy the host network part */
        def->protocol = parent->protocol;
        if (parent->nhosts) {
            if (!(def->hosts = virStorageNetHostDefCopy(parent->nhosts,
                                                        parent->hosts)))
                return NULL;

            def->nhosts = parent->nhosts;
        }

        def->volume = g_strdup(parent->volume);
    } else {
        /* set the type to _FILE, the caller shall update it to the actual type */
        def->type = VIR_STORAGE_TYPE_FILE;
    }

    return g_steal_pointer(&def);
}


/**
 * virStorageSourceNewFromBackingAbsolute
 * @path: string representing absolute location of a storage source
 * @src: filled with virStorageSource object representing @path
 *
 * Returns 0 on success, 1 if we could parse all location data but @path
 * specified other data unrepresentable by libvirt (e.g. inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
int
virStorageSourceNewFromBackingAbsolute(const char *path,
                                       virStorageSource **src)
{
    const char *json;
    const char *dirpath;
    int rc = 0;
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    *src = NULL;

    if (virStorageSourceBackinStoreStringIsFile(path)) {
        def->type = VIR_STORAGE_TYPE_FILE;

        def->path = g_strdup(path);
    } else {
        if ((dirpath = STRSKIP(path, "fat:"))) {
            def->type = VIR_STORAGE_TYPE_DIR;
            def->format = VIR_STORAGE_FILE_FAT;
            def->path = g_strdup(dirpath);
            *src = g_steal_pointer(&def);
            return 0;
        }

        def->type = VIR_STORAGE_TYPE_NETWORK;

        VIR_DEBUG("parsing backing store string: '%s'", path);

        /* handle URI formatted backing stores */
        if ((json = STRSKIP(path, "json:")))
            rc = virStorageSourceParseBackingJSON(def, json);
        else if (strstr(path, "://"))
            rc = virStorageSourceParseBackingURI(def, path);
        else
            rc = virStorageSourceParseBackingColon(def, path);

        if (rc < 0)
            return -1;

        virStorageSourceNetworkAssignDefaultPorts(def);

        /* Some of the legacy parsers parse authentication data since they are
         * also used in other places. For backing store detection the
         * authentication data would be invalid anyways, so we clear it */
        if (def->auth) {
            g_clear_pointer(&def->auth, virStorageAuthDefFree);
        }
    }

    *src = g_steal_pointer(&def);
    return rc;
}


/**
 * virStorageSourceNewFromChild:
 * @parent: storage source parent
 * @child: returned child/backing store definition
 * @parentRaw: raw child string (backingStoreRaw)
 *
 * Creates a storage source which describes the backing image of @parent and
 * fills it into @backing depending on the passed parentRaw (backingStoreRaw)
 * and other data. Note that for local storage this function accesses the file
 * to update the actual type of the child store.
 *
 * Returns 0 on success, 1 if we could parse all location data but the child
 * store specification contained other data unrepresentable by libvirt (e.g.
 * inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
static int
virStorageSourceNewFromChild(virStorageSource *parent,
                             const char *parentRaw,
                             virStorageSource **child)
{
    struct stat st;
    g_autoptr(virStorageSource) def = NULL;
    int rc = 0;

    *child = NULL;

    if (virStorageSourceBackinStoreStringIsRelative(parentRaw)) {
        if (!(def = virStorageSourceNewFromBackingRelative(parent, parentRaw)))
            return -1;
    } else {
        if ((rc = virStorageSourceNewFromBackingAbsolute(parentRaw, &def)) < 0)
            return -1;
    }

    /* possibly update local type */
    if (def->type == VIR_STORAGE_TYPE_FILE) {
        if (stat(def->path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_DIR;
                def->format = VIR_STORAGE_FILE_DIR;
            } else if (S_ISBLK(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_BLOCK;
            }
        }
    }

    /* copy parent's labelling and other top level stuff */
    if (virStorageSourceInitChainElement(def, parent, true) < 0)
        return -1;

    def->detected = true;

    *child = g_steal_pointer(&def);
    return rc;
}


int
virStorageSourceNewFromBacking(virStorageSource *parent,
                               virStorageSource **backing)
{
    int rc;

    if ((rc = virStorageSourceNewFromChild(parent,
                                           parent->backingStoreRaw,
                                           backing)) < 0)
        return rc;

    (*backing)->format = parent->backingStoreRawFormat;
    (*backing)->readonly = true;
    return rc;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Updates src->physical depending on the actual type of storage being used.
 * To be called for domain storage source reporting as the volume code does
 * not set/use the 'type' field for the voldef->source.target
 *
 * Returns 0 on success, -1 on error. No libvirt errors are reported.
 */
int
virStorageSourceUpdatePhysicalSize(virStorageSource *src,
                                   int fd,
                                   struct stat const *sb)
{
    off_t end;
    virStorageType actual_type = virStorageSourceGetActualType(src);

    switch (actual_type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_NETWORK:
        src->physical = sb->st_size;
        break;

    case VIR_STORAGE_TYPE_BLOCK:
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1)
            return -1;

        src->physical = end;
        break;

    case VIR_STORAGE_TYPE_DIR:
        src->physical = 0;
        break;

    /* We shouldn't get VOLUME, but the switch requires all cases */
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return -1;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Update the capacity, allocation, physical values for the storage @src
 * Shared between the domain storage source for an inactive domain and the
 * voldef source target as the result is not affected by the 'type' field.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateBackingSizes(virStorageSource *src,
                                   int fd,
                                   struct stat const *sb)
{
    /* Get info for normal formats */
    if (S_ISREG(sb->st_mode) || fd == -1) {
#ifndef WIN32
        src->allocation = (unsigned long long)sb->st_blocks *
            (unsigned long long)DEV_BSIZE;
#else
        src->allocation = sb->st_size;
#endif
        /* Regular files may be sparse, so logical size (capacity) is not same
         * as actual allocation above
         */
        src->capacity = sb->st_size;

        /* Allocation tracks when the file is sparse, physical is the
         * last offset of the file. */
        src->physical = sb->st_size;
    } else if (S_ISDIR(sb->st_mode)) {
        src->allocation = 0;
        src->capacity = 0;
        src->physical = 0;
    } else if (fd >= 0) {
        off_t end;

        /* XXX this is POSIX compliant, but doesn't work for CHAR files,
         * only BLOCK. There is a Linux specific ioctl() for getting
         * size of both CHAR / BLOCK devices we should check for in
         * configure
         *
         * NB. Because we configure with AC_SYS_LARGEFILE, off_t
         * should be 64 bits on all platforms.  For block devices, we
         * have to seek (safe even if someone else is writing) to
         * determine physical size, and assume that allocation is the
         * same as physical (but can refine that assumption later if
         * qemu is still running).
         */
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t)-1) {
            virReportSystemError(errno,
                                 _("failed to seek to end of %1$s"), src->path);
            return -1;
        }
        src->physical = end;
        src->allocation = end;
        src->capacity = end;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @buf: buffer to the storage file header
 * @len: length of the storage file header
 *
 * Update the storage @src capacity.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateCapacity(virStorageSource *src,
                               char *buf,
                               ssize_t len)
{
    int format = src->format;
    g_autoptr(virStorageSource) meta = NULL;

    /* Raw files: capacity is physical size.  For all other files: if
     * the metadata has a capacity, use that, otherwise fall back to
     * physical size.  */
    if (format == VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no disk format for %1$s was specified"),
                       src->path);
        return -1;
    }

    if (format == VIR_STORAGE_FILE_RAW && !src->encryption) {
        src->capacity = src->physical;
    } else if ((meta = virStorageSourceGetMetadataFromBuf(src->path, buf,
                                                          len, format))) {
        src->capacity = meta->capacity ? meta->capacity : src->physical;
        if (src->encryption && meta->encryption)
            src->encryption->payload_offset = meta->encryption->payload_offset;
    } else {
        return -1;
    }

    if (src->encryption && src->encryption->payload_offset != -1)
        src->capacity -= src->encryption->payload_offset * 512;

    return 0;
}


/**
 * virStorageSourceRemoveLastPathComponent:
 *
 * @path: Path string to remove the last component from
 *
 * Removes the last path component of a path. This function is designed to be
 * called on file paths only (no trailing slashes in @path). Caller is
 * responsible to free the returned string.
 */
static char *
virStorageSourceRemoveLastPathComponent(const char *path)
{
    char *ret;

    ret = g_strdup(NULLSTR_EMPTY(path));

    virFileRemoveLastComponent(ret);

    return ret;
}


/*
 * virStorageSourceGetRelativeBackingPath:
 *
 * Resolve relative path to be written to the overlay of @top image when
 * collapsing the backing chain between @top and @base.
 *
 * Returns 0 on success; 1 if backing chain isn't relative and -1 on error.
 */
int
virStorageSourceGetRelativeBackingPath(virStorageSource *top,
                                       virStorageSource *base,
                                       char **relpath)
{
    virStorageSource *next;
    g_autofree char *tmp = NULL;
    g_autofree char *path = NULL;

    *relpath = NULL;

    for (next = top; virStorageSourceIsBacking(next); next = next->backingStore) {
        if (!next->relPath)
            return 1;

        if (!(tmp = virStorageSourceRemoveLastPathComponent(path)))
            return -1;

        VIR_FREE(path);

        path = g_strdup_printf("%s%s", tmp, next->relPath);

        VIR_FREE(tmp);

        if (next == base)
            break;
    }

    if (next != base) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to resolve relative backing name: base image is not in backing chain"));
        return -1;
    }

    *relpath = g_steal_pointer(&path);
    return 0;
}


/**
 * virStorageSourceFetchRelativeBackingPath:
 * @src: storage object
 * @relPath: filled with the relative path to the backing image of @src if
 *           the metadata of @src refer to it as relative.
 *
 * Fetches the backing store definition of @src by updating the metadata from
 * disk and fills 'relPath' if the backing store string is relative. The data
 * is used by virStorageSourceGetRelativeBackingPath to establish the relative
 * path between two images.
 */
int
virStorageSourceFetchRelativeBackingPath(virStorageSource *src,
                                         char **relPath)
{
    ssize_t headerLen;
    int rv;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) tmp = NULL;

    g_clear_pointer(relPath, g_free);

    /* exit if we can't load information about the current image */
    if (!virStorageSourceSupportsBackingChainTraversal(src))
        return 0;

    rv = virStorageSourceAccess(src, F_OK);
    if (rv == -2)
        return 0;
    if (rv < 0) {
        virStorageSourceReportBrokenChain(errno, src, src);
        return -1;
    }

    if ((headerLen = virStorageSourceRead(src, 0, VIR_STORAGE_MAX_HEADER,
                                          &buf)) < 0) {
        if (headerLen == -2)
            return 0;
        return -1;
    }

    if (!(tmp = virStorageSourceCopy(src, false)))
        return -1;

    if (virStorageFileProbeGetMetadata(tmp, buf, headerLen) < 0)
        return -1;

    if (virStorageSourceBackinStoreStringIsRelative(tmp->backingStoreRaw))
        *relPath = g_steal_pointer(&tmp->backingStoreRaw);

    return 0;
}


static bool
virStorageSourceIsInitialized(const virStorageSource *src)
{
    return src && src->drv;
}


/**
 * virStorageSourceGetBackendForSupportCheck:
 * @src: storage source to check support for
 * @backend: pointer to the storage backend for @src if it's supported
 *
 * Returns 0 if @src is not supported by any storage backend currently linked
 * 1 if it is supported and -1 on error with an error reported.
 */
static int
virStorageSourceGetBackendForSupportCheck(const virStorageSource *src,
                                          virStorageFileBackend **backend)
{
    virStorageType actualType;


    if (!src) {
        *backend = NULL;
        return 0;
    }

    if (src->drv) {
        virStorageDriverData *drv = src->drv;
        *backend = drv->backend;
        return 1;
    }

    actualType = virStorageSourceGetActualType(src);

    if (virStorageFileBackendForType(actualType, src->protocol, false, backend) < 0)
        return -1;

    if (!*backend)
        return 0;

    return 1;
}


int
virStorageSourceSupportsBackingChainTraversal(const virStorageSource *src)
{
    virStorageFileBackend *backend;
    int rv;

    if ((rv = virStorageSourceGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileRead &&
           backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageSourceSupportsSecurityDriver:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports operations needed by the security
 * driver to perform labelling
 */
int
virStorageSourceSupportsSecurityDriver(const virStorageSource *src)
{
    virStorageFileBackend *backend;
    int rv;

    if ((rv = virStorageSourceGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileChown ? 1 : 0;
}


/**
 * virStorageSourceSupportsAccess:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports checking if the storage source is accessible
 * for the given vm.
 */
int
virStorageSourceSupportsAccess(const virStorageSource *src)
{
    virStorageFileBackend *backend;
    int rv;

    if ((rv = virStorageSourceGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageSourceSupportsCreate:
 * @src: a storage file structure
 *
 * Check if the storage driver supports creating storage described by @src
 * via virStorageSourceCreate.
 */
int
virStorageSourceSupportsCreate(const virStorageSource *src)
{
    virStorageFileBackend *backend;
    int rv;

    if ((rv = virStorageSourceGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileCreate ? 1 : 0;
}


void
virStorageSourceDeinit(virStorageSource *src)
{
    virStorageDriverData *drv = NULL;

    if (!virStorageSourceIsInitialized(src))
        return;

    drv = src->drv;

    if (drv->backend &&
        drv->backend->backendDeinit)
        drv->backend->backendDeinit(src);

    VIR_FREE(src->drv);
}


/**
 * virStorageSourceInitAs:
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
virStorageSourceInitAs(virStorageSource *src,
                       uid_t uid, gid_t gid)
{
    virStorageType actualType = virStorageSourceGetActualType(src);
    virStorageDriverData *drv = g_new0(virStorageDriverData, 1);

    src->drv = drv;

    if (uid == (uid_t) -1)
        drv->uid = geteuid();
    else
        drv->uid = uid;

    if (gid == (gid_t) -1)
        drv->gid = getegid();
    else
        drv->gid = gid;

    if (virStorageFileBackendForType(actualType,
                                     src->protocol,
                                     true,
                                     &drv->backend) < 0)
        goto error;

    if (drv->backend->backendInit &&
        drv->backend->backendInit(src) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(src->drv);
    return -1;
}


/**
 * virStorageSourceInit:
 *
 * See virStorageSourceInitAs. The file is initialized to be accessed by the
 * current user.
 */
int
virStorageSourceInit(virStorageSource *src)
{
    return virStorageSourceInitAs(src, -1, -1);
}


/**
 * virStorageSourceCreate: Creates an empty storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageSourceCreate(virStorageSource *src)
{
    virStorageDriverData *drv = NULL;
    int ret;

    if (!virStorageSourceIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileCreate(src);

    VIR_DEBUG("created storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageSourceUnlink: Unlink storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageSourceUnlink(virStorageSource *src)
{
    virStorageDriverData *drv = NULL;
    int ret;

    if (!virStorageSourceIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileUnlink(src);

    VIR_DEBUG("unlinked storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageSourceStat: returns stat struct of a file via storage driver
 *
 * @src: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageSourceStat(virStorageSource *src,
                     struct stat *st)
{
    virStorageDriverData *drv = NULL;
    int ret;

    if (!virStorageSourceIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileStat) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileStat(src, st);

    VIR_DEBUG("stat of storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageSourceRead: read bytes from a file into a buffer
 *
 * @src: file structure pointing to the file
 * @offset: number of bytes to skip in the storage file
 * @len: maximum number of bytes read from the storage file
 * @buf: buffer to read the data into. (buffer shall be freed by caller)
 *
 * Returns the count of bytes read on success and -1 on failure, -2 if the
 * function isn't supported by the backend.
 * Libvirt error is reported on failure.
 */
ssize_t
virStorageSourceRead(virStorageSource *src,
                     size_t offset,
                     size_t len,
                     char **buf)
{
    virStorageDriverData *drv = NULL;
    ssize_t ret;

    if (!virStorageSourceIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return -1;
    }

    drv = src->drv;

    if (!drv->backend->storageFileRead)
        return -2;

    ret = drv->backend->storageFileRead(src, offset, len, buf);

    VIR_DEBUG("read '%zd' bytes from storage '%p' starting at offset '%zu'",
              ret, src, offset);

    return ret;
}


/**
 * virStorageSourceAccess: Check accessibility of a storage file
 *
 * @src: storage file to check access permissions
 * @mode: accessibility check options (see man 2 access)
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageSourceAccess(virStorageSource *src,
                       int mode)
{
    virStorageDriverData *drv = NULL;

    if (!virStorageSourceIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileAccess) {
        errno = ENOSYS;
        return -2;
    }

    return drv->backend->storageFileAccess(src, mode);
}


/**
 * virStorageSourceChown: Change owner of a storage file
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
virStorageSourceChown(const virStorageSource *src,
                      uid_t uid,
                      gid_t gid)
{
    virStorageDriverData *drv = NULL;

    if (!virStorageSourceIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileChown) {
        errno = ENOSYS;
        return -2;
    }

    VIR_DEBUG("chown of storage file %p to %u:%u",
              src, (unsigned int)uid, (unsigned int)gid);

    return drv->backend->storageFileChown(src, uid, gid);
}


/**
 * virStorageSourceReportBrokenChain:
 *
 * @errcode: errno when accessing @src
 * @src: inaccessible file in the backing chain of @parent
 * @parent: root virStorageSource being checked
 *
 * Reports the correct error message if @src is missing in the backing chain
 * for @parent.
 */
void
virStorageSourceReportBrokenChain(int errcode,
                                  virStorageSource *src,
                                  virStorageSource *parent)
{
    if (src->drv) {
        virStorageDriverData *drv = src->drv;
        unsigned int access_user = drv->uid;
        unsigned int access_group = drv->gid;

        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%1$s' (as uid:%2$u, gid:%3$u)"),
                                 src->path, access_user, access_group);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%1$s' of storage file '%2$s' (as uid:%3$u, gid:%4$u)"),
                                 src->path, parent->path, access_user, access_group);
        }
    } else {
        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%1$s'"),
                                 src->path);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%1$s' of storage file '%2$s'"),
                                 src->path, parent->path);
        }
    }
}


static int
virStorageSourceGetMetadataRecurseReadHeader(virStorageSource *src,
                                             virStorageSource *parent,
                                             uid_t uid,
                                             gid_t gid,
                                             char **buf,
                                             size_t *headerLen)
{
    int ret = -1;
    ssize_t len;

    if (virStorageSourceIsFD(src)) {
        if (!src->fdtuple) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("fd passed image source not initialized"));
            return -1;
        }

        if ((len = virFileReadHeaderFD(src->fdtuple->fds[0],
                                       VIR_STORAGE_MAX_HEADER, buf)) < 0)
            return -1;

        *headerLen = len;
        return 0;
    }

    if (virStorageSourceInitAs(src, uid, gid) < 0)
        return -1;

    if (virStorageSourceAccess(src, F_OK) < 0) {
        virStorageSourceReportBrokenChain(errno, src, parent);
        goto cleanup;
    }

    if ((len = virStorageSourceRead(src, 0, VIR_STORAGE_MAX_HEADER, buf)) < 0)
        goto cleanup;

    *headerLen = len;
    ret = 0;

 cleanup:
    virStorageSourceDeinit(src);
    return ret;
}


/* Recursive workhorse for virStorageSourceGetMetadata.  */
static int
virStorageSourceGetMetadataRecurse(virStorageSource *src,
                                   virStorageSource *parent,
                                   uid_t uid, gid_t gid,
                                   bool report_broken,
                                   size_t max_depth,
                                   unsigned int depth)
{
    virStorageFileFormat orig_format = src->format;
    size_t headerLen;
    int rv;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) backingStore = NULL;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u depth=%u",
              NULLSTR(src->path), src->format,
              (unsigned int)uid, (unsigned int)gid, depth);

    if (depth > max_depth) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %1$s is self-referential or too deeply nested"),
                       NULLSTR(src->path));
        return -1;
    }

    if (src->format == VIR_STORAGE_FILE_AUTO_SAFE)
        src->format = VIR_STORAGE_FILE_AUTO;

    /* exit if we can't load information about the current image */
    rv = virStorageSourceSupportsBackingChainTraversal(src);
    if (rv <= 0) {
        if (orig_format == VIR_STORAGE_FILE_AUTO)
            return -2;

        return rv;
    }

    if (virStorageSourceGetMetadataRecurseReadHeader(src, parent, uid, gid,
                                                     &buf, &headerLen) < 0)
        return -1;

    if (virStorageFileProbeGetMetadata(src, buf, headerLen) < 0)
        return -1;

    /* If we probed the format we MUST ensure that nothing else than the current
     * image is considered for security labelling and/or recursion. */
    if (orig_format == VIR_STORAGE_FILE_AUTO) {
        if (src->backingStoreRaw) {
            src->format = VIR_STORAGE_FILE_RAW;
            VIR_FREE(src->backingStoreRaw);
            return -2;
        }
    }

    if (src->backingStoreRaw) {
        if ((rv = virStorageSourceNewFromBacking(src, &backingStore)) < 0)
            return -1;

        /* the backing file would not be usable for VM usage */
        if (rv == 1)
            return 0;

        if ((rv = virStorageSourceGetMetadataRecurse(backingStore, parent,
                                                     uid, gid,
                                                     report_broken,
                                                     max_depth, depth + 1)) < 0) {
            if (!report_broken)
                return 0;

            if (rv == -2) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("format of backing image '%1$s' of image '%2$s' was not specified in the image metadata (See https://libvirt.org/kbase/backing_chains.html for troubleshooting)"),
                               src->backingStoreRaw, NULLSTR(src->path));
            }

            return -1;
        }

        backingStore->id = depth;
        src->backingStore = g_steal_pointer(&backingStore);
    } else {
        /* add terminator */
        src->backingStore = virStorageSourceNew();
        src->backingStore->detected = true;
    }

    return 0;
}


/**
 * virStorageSourceGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Recurses through
 * the chain up to @max_depth layers.
 *
 * Open files using UID and GID (or pass -1 for the current user/group).
 * Treat any backing files without explicit type as raw, unless ALLOW_PROBE.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If @report_broken is true, the whole function fails with a possibly sane
 * error instead of just returning a broken chain. Note that the inability for
 * libvirt to traverse a given source is not considered an error.
 *
 * Caller MUST free result after use via virObjectUnref.
 */
int
virStorageSourceGetMetadata(virStorageSource *src,
                            uid_t uid, gid_t gid,
                            size_t max_depth,
                            bool report_broken)
{
    virStorageType actualType = virStorageSourceGetActualType(src);

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u max_depth=%zu report_broken=%d",
              src->path, src->format, (unsigned int)uid, (unsigned int)gid,
              max_depth, report_broken);

    if (src->format <= VIR_STORAGE_FILE_NONE) {
        if (actualType == VIR_STORAGE_TYPE_DIR)
            src->format = VIR_STORAGE_FILE_DIR;
        else
            src->format = VIR_STORAGE_FILE_RAW;
    }

    return virStorageSourceGetMetadataRecurse(src, src, uid, gid,
                                              report_broken, max_depth, 1);
}
