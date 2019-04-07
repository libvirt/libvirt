/*
 * storage_util.c: helper functions for the storage driver
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

#include <regex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/param.h>
#include <dirent.h>
#include "dirname.h"
#ifdef __linux__
# include <sys/ioctl.h>
# include <linux/fs.h>
# ifndef FS_NOCOW_FL
#  define FS_NOCOW_FL                     0x00800000 /* Do not cow file */
# endif
# define default_mount_opts "nodev,nosuid,noexec"
#elif defined(__FreeBSD__)
# define default_mount_opts "nosuid,noexec"
#else
# define default_mount_opts ""
#endif

#if WITH_BLKID
# include <blkid.h>
#endif

#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#ifdef FICLONE
# define REFLINK_IOC_CLONE FICLONE
#elif HAVE_LINUX_BTRFS_H
# include <linux/btrfs.h>
# define REFLINK_IOC_CLONE BTRFS_IOC_CLONE
#elif HAVE_XFS_XFS_H
# include <xfs/xfs.h>
# define REFLINK_IOC_CLONE XFS_IOC_CLONE
#endif

#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "internal.h"
#include "secret_conf.h"
#include "secret_util.h"
#include "vircrypto.h"
#include "viruuid.h"
#include "virstoragefile.h"
#include "storage_util.h"
#include "virlog.h"
#include "virfile.h"
#include "virjson.h"
#include "virqemu.h"
#include "stat-time.h"
#include "virstring.h"
#include "virxml.h"
#include "virfdstream.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_util");


/* virStorageBackendNamespaceInit:
 * @poolType: virStoragePoolType
 * @xmlns: Storage Pool specific namespace callback methods
 *
 * To be called during storage backend registration to configure the
 * Storage Pool XML Namespace based on the backend's needs.
 */
int
virStorageBackendNamespaceInit(int poolType,
                               virStoragePoolXMLNamespacePtr xmlns)
{
    return virStoragePoolOptionsPoolTypeSetXMLNamespace(poolType, xmlns);
}


#define READ_BLOCK_SIZE_DEFAULT  (1024 * 1024)
#define WRITE_BLOCK_SIZE_DEFAULT (4 * 1024)

/*
 * Perform the O(1) btrfs clone operation, if possible.
 * Upon success, return 0.  Otherwise, return -1 and set errno.
 */
#ifdef REFLINK_IOC_CLONE
static inline int
reflinkCloneFile(int dest_fd, int src_fd)
{
    return ioctl(dest_fd, REFLINK_IOC_CLONE, src_fd);
}
#else
static inline int
reflinkCloneFile(int dest_fd ATTRIBUTE_UNUSED,
                 int src_fd ATTRIBUTE_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}
#endif


static int ATTRIBUTE_NONNULL(2)
virStorageBackendCopyToFD(virStorageVolDefPtr vol,
                          virStorageVolDefPtr inputvol,
                          int fd,
                          unsigned long long *total,
                          bool want_sparse,
                          bool reflink_copy)
{
    int amtread = -1;
    int ret = 0;
    size_t rbytes = READ_BLOCK_SIZE_DEFAULT;
    int wbytes = 0;
    int interval;
    struct stat st;
    VIR_AUTOFREE(char *) zerobuf = NULL;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOCLOSE inputfd = -1;

    if ((inputfd = open(inputvol->target.path, O_RDONLY)) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("could not open input path '%s'"),
                             inputvol->target.path);
        return ret;
    }

#ifdef __linux__
    if (ioctl(fd, BLKBSZGET, &wbytes) < 0)
        wbytes = 0;
#endif
    if ((wbytes == 0) && fstat(fd, &st) == 0)
        wbytes = st.st_blksize;
    if (wbytes < WRITE_BLOCK_SIZE_DEFAULT)
        wbytes = WRITE_BLOCK_SIZE_DEFAULT;

    if (VIR_ALLOC_N(zerobuf, wbytes) < 0)
        return -errno;

    if (VIR_ALLOC_N(buf, rbytes) < 0)
        return -errno;

    if (reflink_copy) {
        if (reflinkCloneFile(fd, inputfd) < 0) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("failed to clone files from '%s'"),
                                 inputvol->target.path);
            return ret;
        } else {
            VIR_DEBUG("btrfs clone finished.");
            return 0;
        }
    }

    while (amtread != 0) {
        int amtleft;

        if (*total < rbytes)
            rbytes = *total;

        if ((amtread = saferead(inputfd, buf, rbytes)) < 0) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("failed reading from file '%s'"),
                                 inputvol->target.path);
            return ret;
        }
        *total -= amtread;

        /* Loop over amt read in 512 byte increments, looking for sparse
         * blocks */
        amtleft = amtread;
        do {
            interval = ((wbytes > amtleft) ? amtleft : wbytes);
            int offset = amtread - amtleft;

            if (want_sparse && memcmp(buf+offset, zerobuf, interval) == 0) {
                if (lseek(fd, interval, SEEK_CUR) < 0) {
                    ret = -errno;
                    virReportSystemError(errno,
                                         _("cannot extend file '%s'"),
                                         vol->target.path);
                    return ret;
                }
            } else if (safewrite(fd, buf+offset, interval) < 0) {
                ret = -errno;
                virReportSystemError(errno,
                                     _("failed writing to file '%s'"),
                                     vol->target.path);
                return ret;

            }
        } while ((amtleft -= interval) > 0);
    }

    if (fdatasync(fd) < 0) {
        ret = -errno;
        virReportSystemError(errno, _("cannot sync data to file '%s'"),
                             vol->target.path);
        return ret;
    }

    if (VIR_CLOSE(inputfd) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             inputvol->target.path);
        return ret;
    }

    return 0;
}

static int
storageBackendCreateBlockFrom(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              virStorageVolDefPtr vol,
                              virStorageVolDefPtr inputvol,
                              unsigned int flags)
{
    unsigned long long remain;
    struct stat st;
    gid_t gid;
    uid_t uid;
    mode_t mode;
    bool reflink_copy = false;
    VIR_AUTOCLOSE fd = -1;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for block "
                         "volumes"));
        return -1;
    }

    if (flags & VIR_STORAGE_VOL_CREATE_REFLINK)
        reflink_copy = true;

    if ((fd = open(vol->target.path, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        return -1;
    }

    remain = vol->target.capacity;

    if (inputvol) {
        if (virStorageBackendCopyToFD(vol, inputvol, fd, &remain,
                                      false, reflink_copy) < 0)
            return -1;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno, _("stat of '%s' failed"),
                             vol->target.path);
        return -1;
    }
    uid = (vol->target.perms->uid != st.st_uid) ? vol->target.perms->uid
        : (uid_t)-1;
    gid = (vol->target.perms->gid != st.st_gid) ? vol->target.perms->gid
        : (gid_t)-1;
    if (((uid != (uid_t)-1) || (gid != (gid_t)-1))
        && (fchown(fd, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown '%s' to (%u, %u)"),
                             vol->target.path, (unsigned int)uid,
                             (unsigned int)gid);
        return -1;
    }

    mode = (vol->target.perms->mode == (mode_t)-1 ?
            VIR_STORAGE_DEFAULT_VOL_PERM_MODE : vol->target.perms->mode);
    if (fchmod(fd, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, mode);
        return -1;
    }
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        return -1;
    }

    return 0;
}

static int
createRawFile(int fd, virStorageVolDefPtr vol,
              virStorageVolDefPtr inputvol,
              bool reflink_copy)
{
    bool need_alloc = true;
    int ret = 0;
    unsigned long long pos = 0;

    /* If the new allocation is lower than the capacity of the original file,
     * the cloned volume will be sparse */
    if (inputvol &&
        vol->target.allocation < inputvol->target.capacity)
        need_alloc = false;

    /* Seek to the final size, so the capacity is available upfront
     * for progress reporting */
    if (ftruncate(fd, vol->target.capacity) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot extend file '%s'"),
                             vol->target.path);
        goto cleanup;
    }

/* Avoid issues with older kernel's <linux/fs.h> namespace pollution. */
#if HAVE_FALLOCATE - 0
    /* Try to preallocate all requested disk space, but fall back to
     * other methods if this fails with ENOSYS or EOPNOTSUPP. If allocation
     * is 0 (or less than 0), then fallocate will fail with EINVAL.
     * NOTE: do not use posix_fallocate; posix_fallocate falls back
     * to writing zeroes block by block in case fallocate isn't
     * available, and since we're going to copy data from another
     * file it doesn't make sense to write the file twice. */
    if (vol->target.allocation && need_alloc) {
        if (fallocate(fd, 0, 0, vol->target.allocation) == 0) {
            need_alloc = false;
        } else if (errno != ENOSYS && errno != EOPNOTSUPP) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("cannot allocate %llu bytes in file '%s'"),
                                 vol->target.allocation, vol->target.path);
            goto cleanup;
        }
    }
#endif

    if (inputvol) {
        unsigned long long remain = inputvol->target.capacity;
        /* allow zero blocks to be skipped if we've requested sparse
         * allocation (allocation < capacity) or we have already
         * been able to allocate the required space. */
        if ((ret = virStorageBackendCopyToFD(vol, inputvol, fd, &remain,
                                             !need_alloc, reflink_copy)) < 0)
            goto cleanup;

        /* If the new allocation is greater than the original capacity,
         * but fallocate failed, fill the rest with zeroes.
         */
        pos = inputvol->target.capacity - remain;
    }

    if (need_alloc && (vol->target.allocation - pos > 0)) {
        if (safezero(fd, pos, vol->target.allocation - pos) < 0) {
            ret = -errno;
            virReportSystemError(errno, _("cannot fill file '%s'"),
                                 vol->target.path);
            goto cleanup;
        }
    }

    if (fsync(fd) < 0) {
        ret = -errno;
        virReportSystemError(errno, _("cannot sync data to file '%s'"),
                             vol->target.path);
        goto cleanup;
    }

 cleanup:
    return ret;
}

static int
storageBackendCreateRaw(virStoragePoolObjPtr pool,
                        virStorageVolDefPtr vol,
                        virStorageVolDefPtr inputvol,
                        unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int ret = -1;
    int operation_flags;
    bool reflink_copy = false;
    mode_t open_mode = VIR_STORAGE_DEFAULT_VOL_PERM_MODE;
    bool created = false;
    VIR_AUTOCLOSE fd = -1;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for raw "
                         "volumes"));
        goto cleanup;
    }

    if (virStorageSourceHasBacking(&vol->target)) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("backing storage not supported for raw volumes"));
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_CREATE_REFLINK)
        reflink_copy = true;


    if (vol->target.encryption) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool does not support encrypted volumes"));
        goto cleanup;
    }

    operation_flags = VIR_FILE_OPEN_FORCE_MODE | VIR_FILE_OPEN_FORCE_OWNER;
    if (def->type == VIR_STORAGE_POOL_NETFS)
        operation_flags |= VIR_FILE_OPEN_FORK;

    if (vol->target.perms->mode != (mode_t)-1)
        open_mode = vol->target.perms->mode;

    if ((fd = virFileOpenAs(vol->target.path,
                            O_RDWR | O_CREAT | O_EXCL,
                            open_mode,
                            vol->target.perms->uid,
                            vol->target.perms->gid,
                            operation_flags)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create file '%s'"),
                             vol->target.path);
        goto cleanup;
    }
    created = true;

    if (vol->target.nocow) {
#ifdef __linux__
        int attr;

        /* Set NOCOW flag. This is an optimisation for btrfs.
         * The FS_IOC_SETFLAGS ioctl return value will be ignored since any
         * failure of this operation should not block the volume creation.
         */
        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) < 0) {
            virReportSystemError(errno, "%s", _("Failed to get fs flags"));
        } else {
            attr |= FS_NOCOW_FL;
            if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Failed to set NOCOW flag"));
            }
        }
#endif
    }

    if ((ret = createRawFile(fd, vol, inputvol, reflink_copy)) < 0)
        /* createRawFile already reported the exact error. */
        ret = -1;

 cleanup:
    if (ret < 0 && created)
        ignore_value(virFileRemove(vol->target.path,
                                   vol->target.perms->uid,
                                   vol->target.perms->gid));
    return ret;
}


static int
virStorageBackendCreateExecCommand(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   virCommandPtr cmd)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    struct stat st;
    gid_t gid;
    uid_t uid;
    mode_t mode = (vol->target.perms->mode == (mode_t)-1 ?
                   VIR_STORAGE_DEFAULT_VOL_PERM_MODE :
                   vol->target.perms->mode);
    bool filecreated = false;
    int ret = -1;

    if ((def->type == VIR_STORAGE_POOL_NETFS)
        && (((geteuid() == 0)
             && (vol->target.perms->uid != (uid_t)-1)
             && (vol->target.perms->uid != 0))
            || ((vol->target.perms->gid != (gid_t)-1)
                && (vol->target.perms->gid != getegid())))) {

        virCommandSetUID(cmd, vol->target.perms->uid);
        virCommandSetGID(cmd, vol->target.perms->gid);
        virCommandSetUmask(cmd, S_IRWXUGO ^ mode);

        if (virCommandRun(cmd, NULL) == 0) {
            /* command was successfully run, check if the file was created */
            if (stat(vol->target.path, &st) >= 0) {
                filecreated = true;

                /* seems qemu-img disregards umask and open/creates using 0644.
                 * If that doesn't match what we expect, then let's try to
                 * re-open the file and attempt to force the mode change.
                 */
                if (mode != (st.st_mode & S_IRWXUGO)) {
                    VIR_AUTOCLOSE fd = -1;
                    int flags = VIR_FILE_OPEN_FORK | VIR_FILE_OPEN_FORCE_MODE;

                    if ((fd = virFileOpenAs(vol->target.path, O_RDWR, mode,
                                            vol->target.perms->uid,
                                            vol->target.perms->gid,
                                            flags)) >= 0) {
                        /* Success - means we're good */
                        ret = 0;
                        goto cleanup;
                    }
                }
            }
        }
    }

    if (!filecreated) {
        /* don't change uid/gid/mode if we retry */
        virCommandSetUID(cmd, -1);
        virCommandSetGID(cmd, -1);
        virCommandSetUmask(cmd, 0);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
        if (stat(vol->target.path, &st) < 0) {
            virReportSystemError(errno,
                                 _("failed to create %s"), vol->target.path);
            goto cleanup;
        }
        filecreated = true;
    }

    uid = (vol->target.perms->uid != st.st_uid) ? vol->target.perms->uid
        : (uid_t)-1;
    gid = (vol->target.perms->gid != st.st_gid) ? vol->target.perms->gid
        : (gid_t)-1;
    if (((uid != (uid_t)-1) || (gid != (gid_t)-1))
        && (chown(vol->target.path, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown %s to (%u, %u)"),
                             vol->target.path, (unsigned int)uid,
                             (unsigned int)gid);
        goto cleanup;
    }

    if (mode != (st.st_mode & S_IRWXUGO) &&
        chmod(vol->target.path, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, mode);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0 && filecreated)
        virFileRemove(vol->target.path, vol->target.perms->uid,
                      vol->target.perms->gid);
    return ret;
}

/* Create ploop directory with ploop image and DiskDescriptor.xml
 * if function fails to create image file the directory will be deleted.*/
static int
storageBackendCreatePloop(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                          virStorageVolDefPtr vol,
                          virStorageVolDefPtr inputvol,
                          unsigned int flags)
{
    int ret = -1;
    bool created = false;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) create_tool = NULL;

    virCheckFlags(0, -1);

    if (inputvol && inputvol->target.format != VIR_STORAGE_FILE_PLOOP) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported input storage vol type %d"),
                       inputvol->target.format);
        return -1;
    }

    if (vol->target.encryption) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("encrypted ploop volumes are not supported with "
                         "ploop init"));
        return -1;
    }

    if (virStorageSourceHasBacking(&vol->target)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("copy-on-write ploop volumes are not yet supported"));
        return -1;
    }

    create_tool = virFindFileInPath("ploop");
    if (!create_tool && !inputvol) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find ploop, please install "
                               "ploop tools"));
        return -1;
    }

    if (!inputvol) {
        if ((virDirCreate(vol->target.path,
                          (vol->target.perms->mode == (mode_t)-1 ?
                           VIR_STORAGE_DEFAULT_VOL_PERM_MODE:
                           vol->target.perms->mode),
                          vol->target.perms->uid,
                          vol->target.perms->gid,
                          0)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("error creating directory for ploop volume"));
            goto cleanup;
        }
        cmd = virCommandNewArgList(create_tool, "init", "-s", NULL);
        virCommandAddArgFormat(cmd, "%lluM", VIR_DIV_UP(vol->target.capacity,
                                                        (1024 * 1024)));
        virCommandAddArgList(cmd, "-t", "ext4", NULL);
        virCommandAddArgFormat(cmd, "%s/root.hds", vol->target.path);

    } else {
        vol->target.capacity = inputvol->target.capacity;
        cmd = virCommandNewArgList("cp", "-r", inputvol->target.path,
                                   vol->target.path, NULL);
    }
    created = true;
    ret = virCommandRun(cmd, NULL);
 cleanup:
    if (ret < 0 && created)
        virFileDeleteTree(vol->target.path);
    return ret;
}


static int
storagePloopResize(virStorageVolDefPtr vol,
                   unsigned long long capacity)
{
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) resize_tool = NULL;

    resize_tool = virFindFileInPath("ploop");
    if (!resize_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop, please install ploop tools"));
        return -1;
    }
    cmd = virCommandNewArgList(resize_tool, "resize", "-s", NULL);
    virCommandAddArgFormat(cmd, "%lluM", VIR_DIV_UP(capacity, (1024 * 1024)));

    virCommandAddArgFormat(cmd, "%s/DiskDescriptor.xml", vol->target.path);

    return virCommandRun(cmd, NULL);
}


/* The _virStorageBackendQemuImgInfo separates the command line building from
 * the volume definition so that qemuDomainSnapshotCreateInactiveExternal can
 * use it without needing to deal with a volume.
 */
struct _virStorageBackendQemuImgInfo {
    int format;
    const char *type;
    const char *inputType;
    const char *path;
    unsigned long long size_arg;
    unsigned long long allocation;
    bool encryption;
    bool preallocate;
    const char *compat;
    virBitmapPtr features;
    bool nocow;

    const char *backingPath;
    int backingFormat;

    const char *inputPath;
    const char *inputFormatStr;
    int inputFormat;

    char *secretAlias;
};


static int
storageBackendCreateQemuImgOpts(virStorageEncryptionInfoDefPtr encinfo,
                                char **opts,
                                struct _virStorageBackendQemuImgInfo *info)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (info->backingPath)
        virBufferAsprintf(&buf, "backing_fmt=%s,",
                          virStorageFileFormatTypeToString(info->backingFormat));

    if (encinfo)
        virQEMUBuildQemuImgKeySecretOpts(&buf, encinfo, info->secretAlias);

    if (info->preallocate) {
        if (info->size_arg > info->allocation)
            virBufferAddLit(&buf, "preallocation=metadata,");
        else
            virBufferAddLit(&buf, "preallocation=falloc,");
    }

    if (info->nocow)
        virBufferAddLit(&buf, "nocow=on,");

    if (info->compat)
        virBufferAsprintf(&buf, "compat=%s,", info->compat);
    else if (info->format == VIR_STORAGE_FILE_QCOW2)
        virBufferAddLit(&buf, "compat=0.10,");

    if (info->features && info->format == VIR_STORAGE_FILE_QCOW2) {
        if (virBitmapIsBitSet(info->features,
                              VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS)) {
            if (STREQ_NULLABLE(info->compat, "0.10")) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("lazy_refcounts not supported with compat"
                                 " level %s"),
                               info->compat);
                goto error;
            }
            virBufferAddLit(&buf, "lazy_refcounts,");
        }
    }

    virBufferTrim(&buf, ",", -1);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    *opts = virBufferContentAndReset(&buf);
    return 0;

 error:
    virBufferFreeAndReset(&buf);
    return -1;
}


/* storageBackendCreateQemuImgCheckEncryption:
 * @format: format of file found
 * @type: TypeToString of format.type
 * @vol: pointer to volume def
 *
 * Ensure the proper setup for encryption.
 *
 * Returns 0 on success, -1 on failure w/ error set
 */
static int
storageBackendCreateQemuImgCheckEncryption(int format,
                                           const char *type,
                                           virStorageVolDefPtr vol)
{
    virStorageEncryptionPtr enc = vol->target.encryption;

    if (format == VIR_STORAGE_FILE_RAW) {
        if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported volume encryption format %d"),
                           vol->target.encryption->format);
            return -1;
        }
        if (enc->nsecrets > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("too many secrets for luks encryption"));
            return -1;
        }
        if (enc->nsecrets == 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("no secret provided for luks encryption"));
            return -1;
        }
        if (!virCryptoHaveCipher(VIR_CRYPTO_CIPHER_AES256CBC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("luks encryption usage requires encrypted "
                             "secret generation to be supported"));
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("volume encryption unsupported with format %s"), type);
        return -1;
    }

    return 0;
}


static int
storageBackendCreateQemuImgSetInput(virStorageVolDefPtr inputvol,
                                    virStorageVolEncryptConvertStep convertStep,
                                    struct _virStorageBackendQemuImgInfo *info)
{
    if (convertStep != VIR_STORAGE_VOL_ENCRYPT_CREATE) {
        if (!(info->inputPath = inputvol->target.path)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("missing input volume target path"));
            return -1;
        }
    }

    info->inputFormat = inputvol->target.format;
    if (inputvol->type == VIR_STORAGE_VOL_BLOCK)
        info->inputFormat = VIR_STORAGE_FILE_RAW;
    if (info->inputFormat == VIR_STORAGE_FILE_ISO)
        info->inputFormat = VIR_STORAGE_FILE_RAW;
    if (!(info->inputFormatStr =
          virStorageFileFormatTypeToString(info->inputFormat))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage vol type %d"),
                       info->inputFormat);
        return -1;
    }

    return 0;
}


static int
storageBackendCreateQemuImgSetBacking(virStoragePoolObjPtr pool,
                                      virStorageVolDefPtr vol,
                                      virStorageVolDefPtr inputvol,
                                      struct _virStorageBackendQemuImgInfo *info)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int accessRetCode = -1;
    VIR_AUTOFREE(char *) absolutePath = NULL;

    if (info->format == VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cannot set backing store for raw volume"));
        return -1;
    }

    info->backingFormat = vol->target.backingStore->format;
    info->backingPath = vol->target.backingStore->path;

    if (info->preallocate) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation conflicts with backing"
                         " store"));
        return -1;
    }

    /* XXX: Not strictly required: qemu-img has an option a different
     * backing store, not really sure what use it serves though, and it
     * may cause issues with lvm. Untested essentially.
     */
    if (inputvol && virStorageSourceHasBacking(&inputvol->target) &&
        STRNEQ_NULLABLE(inputvol->target.backingStore->path,
                        info->backingPath)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("a different backing store cannot be specified."));
        return -1;
    }

    if (!virStorageFileFormatTypeToString(info->backingFormat)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage vol backing store type %d"),
                       info->backingFormat);
        return -1;
    }

    /* Convert relative backing store paths to absolute paths for access
     * validation.
     */
    if ('/' != *(info->backingPath) &&
        virAsprintf(&absolutePath, "%s/%s", def->target.path,
                    info->backingPath) < 0)
        return -1;
    accessRetCode = access(absolutePath ? absolutePath :
                           info->backingPath, R_OK);
    if (accessRetCode != 0) {
        virReportSystemError(errno,
                             _("inaccessible backing store volume %s"),
                             info->backingPath);
        return -1;
    }

    return 0;
}


static int
storageBackendCreateQemuImgSetOptions(virCommandPtr cmd,
                                      virStorageEncryptionInfoDefPtr encinfo,
                                      struct _virStorageBackendQemuImgInfo *info)
{
    VIR_AUTOFREE(char *) opts = NULL;

    if (storageBackendCreateQemuImgOpts(encinfo, &opts, info) < 0)
        return -1;
    if (opts)
        virCommandAddArgList(cmd, "-o", opts, NULL);

    return 0;
}


/* Add a secret object to the command line:
 *    --object secret,id=$secretAlias,file=$secretPath
 *
 *    NB: format=raw is assumed
 */
static int
storageBackendCreateQemuImgSecretObject(virCommandPtr cmd,
                                        const char *secretPath,
                                        const char *secretAlias)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) commandStr = NULL;

    virBufferAsprintf(&buf, "secret,id=%s,file=", secretAlias);
    virQEMUBuildBufferEscapeComma(&buf, secretPath);

    if (virBufferCheckError(&buf) < 0) {
        virBufferFreeAndReset(&buf);
        return -1;
    }

    commandStr = virBufferContentAndReset(&buf);

    virCommandAddArgList(cmd, "--object", commandStr, NULL);

    return 0;
}


/* Add a --image-opts to the qemu-img resize command line:
 *    --image-opts driver=luks,file.filename=$volpath,key-secret=$secretAlias
 *
 *    NB: format=raw is assumed
 */
static int
storageBackendResizeQemuImgImageOpts(virCommandPtr cmd,
                                     const char *path,
                                     const char *secretAlias)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) commandStr = NULL;

    virBufferAsprintf(&buf, "driver=luks,key-secret=%s,file.filename=",
                      secretAlias);
    virQEMUBuildBufferEscapeComma(&buf, path);

    if (virBufferCheckError(&buf) < 0) {
        virBufferFreeAndReset(&buf);
        return -1;
    }

    commandStr = virBufferContentAndReset(&buf);

    virCommandAddArgList(cmd, "--image-opts", commandStr, NULL);

    return 0;
}


static int
virStorageBackendCreateQemuImgSetInfo(virStoragePoolObjPtr pool,
                                      virStorageVolDefPtr vol,
                                      virStorageVolDefPtr inputvol,
                                      virStorageVolEncryptConvertStep convertStep,
                                      struct _virStorageBackendQemuImgInfo *info)
{
    /* Treat output block devices as 'raw' format */
    if (vol->type == VIR_STORAGE_VOL_BLOCK)
        info->format = VIR_STORAGE_FILE_RAW;

    if (info->format == VIR_STORAGE_FILE_ISO)
        info->format = VIR_STORAGE_FILE_RAW;

    if (!(info->type = virStorageFileFormatTypeToString(info->format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage vol type %d"),
                       info->format);
        return -1;
    }

    if (inputvol &&
        !(info->inputType =
          virStorageFileFormatTypeToString(inputvol->target.format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown inputvol storage vol type %d"),
                       inputvol->target.format);
        return -1;
    }

    if (info->preallocate && info->format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation only available with qcow2"));
        return -1;
    }
    if (info->compat && info->format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("compatibility option only available with qcow2"));
        return -1;
    }
    if (info->features && info->format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("format features only available with qcow2"));
        return -1;
    }
    if (info->format == VIR_STORAGE_FILE_RAW && vol->target.encryption) {
        if (vol->target.encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
            info->type = "luks";
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only luks encryption is supported for raw files"));
            return -1;
        }
    }

    if (inputvol &&
        storageBackendCreateQemuImgSetInput(inputvol, convertStep, info) < 0)
        return -1;

    if (virStorageSourceHasBacking(&vol->target) &&
        storageBackendCreateQemuImgSetBacking(pool, vol, inputvol, info) < 0)
        return -1;

    if (info->encryption &&
        storageBackendCreateQemuImgCheckEncryption(info->format, info->type,
                                                   vol) < 0)
        return -1;

    /* Size in KB */
    info->size_arg = VIR_DIV_UP(vol->target.capacity, 1024);

    return 0;
}


/* Create a qemu-img virCommand from the supplied arguments */
virCommandPtr
virStorageBackendCreateQemuImgCmdFromVol(virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol,
                                         unsigned int flags,
                                         const char *create_tool,
                                         const char *secretPath,
                                         const char *inputSecretPath,
                                         virStorageVolEncryptConvertStep convertStep)
{
    virCommandPtr cmd = NULL;
    struct _virStorageBackendQemuImgInfo info = {
        .format = vol->target.format,
        .type = NULL,
        .inputType = NULL,
        .path = vol->target.path,
        .allocation = vol->target.allocation,
        .encryption = !!vol->target.encryption,
        .preallocate = !!(flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA),
        .compat = vol->target.compat,
        .features = vol->target.features,
        .nocow = vol->target.nocow,
        .secretAlias = NULL,
    };
    virStorageEncryptionPtr enc = vol->target.encryption;
    virStorageEncryptionPtr inputenc = inputvol ? inputvol->target.encryption : NULL;
    virStorageEncryptionInfoDefPtr encinfo = NULL;
    VIR_AUTOFREE(char *) inputSecretAlias = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    if (enc && (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_QCOW ||
                enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT) &&
        (vol->target.format == VIR_STORAGE_FILE_QCOW ||
         vol->target.format == VIR_STORAGE_FILE_QCOW2)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("creation of qcow2 encrypted image is not supported"));
        goto error;
    }

    if (inputenc && inputenc->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("encryption format of inputvol must be LUKS"));
        goto error;
    }

    if (virStorageBackendCreateQemuImgSetInfo(pool, vol, inputvol,
                                              convertStep, &info) < 0)
        goto error;

    cmd = virCommandNew(create_tool);

    /* ignore the backing volume when we're converting a volume
     * including when we're doing a two step convert during create */
    if (info.inputPath || convertStep == VIR_STORAGE_VOL_ENCRYPT_CREATE)
        info.backingPath = NULL;

    /* Converting to use encryption is a two step process - step 1 is to
     * create the image and step 2 is to convert it using special arguments */
    if (info.inputPath && convertStep == VIR_STORAGE_VOL_ENCRYPT_NONE)
        virCommandAddArgList(cmd, "convert", "-f", info.inputFormatStr,
                             "-O", info.type, NULL);
    else if (info.inputPath && convertStep == VIR_STORAGE_VOL_ENCRYPT_CONVERT)
        virCommandAddArgList(cmd, "convert", "--image-opts", "-n",
                             "--target-image-opts", NULL);
    else
        virCommandAddArgList(cmd, "create", "-f", info.type, NULL);

    if (info.backingPath)
        virCommandAddArgList(cmd, "-b", info.backingPath, NULL);

    if (enc) {
        if (!secretPath) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("path to secret data file is required"));
            goto error;
        }
        if (virAsprintf(&info.secretAlias, "%s_encrypt0", vol->name) < 0)
            goto error;
        if (storageBackendCreateQemuImgSecretObject(cmd, secretPath,
                                                    info.secretAlias) < 0)
            goto error;
        encinfo = &enc->encinfo;
    }

    if (inputenc && convertStep == VIR_STORAGE_VOL_ENCRYPT_CONVERT) {
        if (!inputSecretPath) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("path to inputvol secret data file is required"));
            goto error;
        }
        if (virAsprintf(&inputSecretAlias, "%s_encrypt0",
                        inputvol->name) < 0)
            goto error;
        if (storageBackendCreateQemuImgSecretObject(cmd, inputSecretPath,
                                                    inputSecretAlias) < 0)
            goto error;
    }

    if (convertStep != VIR_STORAGE_VOL_ENCRYPT_CONVERT) {
        if (storageBackendCreateQemuImgSetOptions(cmd, encinfo, &info) < 0)
            goto error;
        if (info.inputPath)
            virCommandAddArg(cmd, info.inputPath);
        virCommandAddArg(cmd, info.path);
        if (!info.inputPath && (info.size_arg || !info.backingPath))
            virCommandAddArgFormat(cmd, "%lluK", info.size_arg);
    } else {
        /* source */
        if (inputenc)
            virCommandAddArgFormat(cmd,
                                   "driver=luks,file.filename=%s,key-secret=%s",
                                   info.inputPath, inputSecretAlias);
        else
            virCommandAddArgFormat(cmd, "driver=%s,file.filename=%s",
                                   info.inputType ? info.inputType : "raw",
                                   info.inputPath);

        /* dest */
        if (enc)
            virCommandAddArgFormat(cmd,
                                   "driver=%s,file.filename=%s,key-secret=%s",
                                   info.type, info.path, info.secretAlias);
        else
            virCommandAddArgFormat(cmd, "driver=%s,file.filename=%s",
                                   info.type, info.path);

    }
    VIR_FREE(info.secretAlias);

    return cmd;

 error:
    VIR_FREE(info.secretAlias);
    virCommandFree(cmd);
    return NULL;
}


static char *
storageBackendCreateQemuImgSecretPath(virStoragePoolObjPtr pool,
                                      virStorageVolDefPtr vol)
{
    virStorageEncryptionPtr enc = vol->target.encryption;
    char *secretPath = NULL;
    uint8_t *secret = NULL;
    size_t secretlen = 0;
    virConnectPtr conn = NULL;
    VIR_AUTOCLOSE fd = -1;

    if (!enc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing encryption description"));
        return NULL;
    }

    if (enc->nsecrets != 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("A single <secret type='passphrase'...> "
                         "element is expected in encryption description"));
        return NULL;
    }

    conn = virGetConnectSecret();
    if (!conn)
        return NULL;

    if (!(secretPath = virStoragePoolObjBuildTempFilePath(pool, vol)))
        goto cleanup;

    if ((fd = mkostemp(secretPath, O_CLOEXEC)) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to open secret file for write"));
        goto error;
    }

    if (virSecretGetSecretString(conn, &enc->secrets[0]->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_VOLUME,
                                 &secret, &secretlen) < 0)
        goto error;

    if (safewrite(fd, secret, secretlen) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to write secret file"));
        goto error;
    }

    if ((vol->target.perms->uid != (uid_t)-1) &&
        (vol->target.perms->gid != (gid_t)-1)) {
        if (chown(secretPath, vol->target.perms->uid,
                  vol->target.perms->gid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to chown secret file"));
            goto error;
        }
    }

 cleanup:
    virObjectUnref(conn);
    VIR_DISPOSE_N(secret, secretlen);

    return secretPath;

 error:
    unlink(secretPath);
    VIR_FREE(secretPath);
    goto cleanup;
}


static int
storageBackendDoCreateQemuImg(virStoragePoolObjPtr pool,
                              virStorageVolDefPtr vol,
                              virStorageVolDefPtr inputvol,
                              unsigned int flags,
                              const char *create_tool,
                              const char *secretPath,
                              const char *inputSecretPath,
                              virStorageVolEncryptConvertStep convertStep)
{
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virStorageBackendCreateQemuImgCmdFromVol(pool, vol, inputvol,
                                                   flags, create_tool,
                                                   secretPath, inputSecretPath,
                                                   convertStep);
    if (!cmd)
        return -1;

    return virStorageBackendCreateExecCommand(pool, vol, cmd);
}


static int
storageBackendCreateQemuImg(virStoragePoolObjPtr pool,
                            virStorageVolDefPtr vol,
                            virStorageVolDefPtr inputvol,
                            unsigned int flags)
{
    int ret = -1;
    virStorageVolEncryptConvertStep convertStep = VIR_STORAGE_VOL_ENCRYPT_NONE;
    VIR_AUTOFREE(char *) create_tool = NULL;
    VIR_AUTOFREE(char *) secretPath = NULL;
    VIR_AUTOFREE(char *) inputSecretPath = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    create_tool = virFindFileInPath("qemu-img");
    if (!create_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("creation of non-raw file images is "
                         "not supported without qemu-img."));
        return -1;
    }

    if (vol->target.encryption &&
        !(secretPath = storageBackendCreateQemuImgSecretPath(pool, vol)))
        goto cleanup;

    if (inputvol && inputvol->target.encryption &&
        !(inputSecretPath = storageBackendCreateQemuImgSecretPath(pool,
                                                                  inputvol)))
        goto cleanup;

    /* Using an input file for encryption requires a multi-step process
     * to create an image of the same size as the inputvol and then to
     * convert the inputvol afterwards. */
    if ((secretPath || inputSecretPath) && inputvol)
        convertStep = VIR_STORAGE_VOL_ENCRYPT_CREATE;

    do {
        ret = storageBackendDoCreateQemuImg(pool, vol, inputvol, flags,
                                            create_tool, secretPath,
                                            inputSecretPath, convertStep);

        /* Failure to convert, attempt to delete what we created */
        if (ret < 0 && convertStep == VIR_STORAGE_VOL_ENCRYPT_CONVERT)
            ignore_value(virFileRemove(vol->target.path,
                                       vol->target.perms->uid,
                                       vol->target.perms->gid));

        if (ret < 0 || convertStep == VIR_STORAGE_VOL_ENCRYPT_NONE)
            goto cleanup;

        if (convertStep == VIR_STORAGE_VOL_ENCRYPT_CREATE)
            convertStep = VIR_STORAGE_VOL_ENCRYPT_CONVERT;
        else if (convertStep == VIR_STORAGE_VOL_ENCRYPT_CONVERT)
            convertStep = VIR_STORAGE_VOL_ENCRYPT_DONE;
    } while (convertStep != VIR_STORAGE_VOL_ENCRYPT_DONE);

 cleanup:
    if (secretPath)
        unlink(secretPath);
    if (inputSecretPath)
        unlink(inputSecretPath);
    return ret;
}


/**
 * virStorageBackendCreateVolUsingQemuImg
 * @pool: Storage Pool Object
 * @vol: Volume definition
 * @inputvol: Volume to use for creation
 * @flags: Flags for creation options
 *
 * A shim to storageBackendCreateQemuImg to allow other backends to
 * utilize qemu-img processing in order to create or alter the volume.
 *
 * NB: If a volume target format is not supplied (per usual for some
 * backends), temporarily adjust the format to be RAW. Once completed,
 * reset the format back to NONE.
 *
 * Returns: 0 on success, -1 on failure.
 */
int
virStorageBackendCreateVolUsingQemuImg(virStoragePoolObjPtr pool,
                                       virStorageVolDefPtr vol,
                                       virStorageVolDefPtr inputvol,
                                       unsigned int flags)
{
    int ret = -1;
    bool changeFormat = false;

    if (vol->target.format == VIR_STORAGE_FILE_NONE) {
        vol->target.format = VIR_STORAGE_FILE_RAW;
        changeFormat = true;
    }

    ret = storageBackendCreateQemuImg(pool, vol, inputvol, flags);

    if (changeFormat)
        vol->target.format = VIR_STORAGE_FILE_NONE;

    return ret;
}


virStorageBackendBuildVolFrom
virStorageBackendGetBuildVolFromFunction(virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol)
{
    if (!inputvol)
        return NULL;

    /* If either volume is a non-raw file vol, or uses encryption,
     * we need to use an external tool for converting
     */
    if ((vol->type == VIR_STORAGE_VOL_FILE &&
         (vol->target.format != VIR_STORAGE_FILE_RAW ||
          vol->target.encryption)) ||
        (inputvol->type == VIR_STORAGE_VOL_FILE &&
         (inputvol->target.format != VIR_STORAGE_FILE_RAW ||
          inputvol->target.encryption))) {
        return storageBackendCreateQemuImg;
    }

    if (vol->type == VIR_STORAGE_VOL_PLOOP)
        return storageBackendCreatePloop;
    if (vol->type == VIR_STORAGE_VOL_BLOCK)
        return storageBackendCreateBlockFrom;
    else
        return storageBackendCreateRaw;
}


struct diskType {
    int part_table_type;
    unsigned short offset;
    unsigned short length;
    unsigned long long magic;
};


static struct diskType const disk_types[] = {
    { VIR_STORAGE_POOL_DISK_LVM2, 0x218, 8, 0x31303020324D564CULL },
    { VIR_STORAGE_POOL_DISK_GPT,  0x200, 8, 0x5452415020494645ULL },
    { VIR_STORAGE_POOL_DISK_DVH,  0x0,   4, 0x41A9E50BULL },
    { VIR_STORAGE_POOL_DISK_MAC,  0x0,   2, 0x5245ULL },
    { VIR_STORAGE_POOL_DISK_BSD,  0x40,  4, 0x82564557ULL },
    { VIR_STORAGE_POOL_DISK_SUN,  0x1fc, 2, 0xBEDAULL },
    /*
     * NOTE: pc98 is funky; the actual signature is 0x55AA (just like dos), so
     * we can't use that.  At the moment I'm relying on the "dummy" IPL
     * bootloader data that comes from parted.  Luckily, the chances of running
     * into a pc98 machine running libvirt are approximately nil.
     */
    /*{ 0x1fe, 2, 0xAA55UL },*/
    { VIR_STORAGE_POOL_DISK_PC98, 0x0,   8, 0x314C5049000000CBULL },
    /*
     * NOTE: the order is important here; some other disk types (like GPT and
     * and PC98) also have 0x55AA at this offset.  For that reason, the DOS
     * one must be the last one.
     */
    { VIR_STORAGE_POOL_DISK_DOS,  0x1fe, 2, 0xAA55ULL },
    { -1,                         0x0,   0, 0x0ULL },
};


/*
 * virStorageBackendDetectBlockVolFormatFD
 * @target: target definition ptr of volume to update
 * @fd: fd of storage volume to update,
 * @readflags: VolReadErrorMode flags to handle read error after open
 *             is successful, but read is not.
 *
 * Returns 0 for success, -1 on a legitimate error condition, -2 if
 * the read error is desired to be ignored (along with appropriate
 * VIR_WARN of the issue).
 */
static int
virStorageBackendDetectBlockVolFormatFD(virStorageSourcePtr target,
                                        int fd,
                                        unsigned int readflags)
{
    size_t i;
    off_t start;
    unsigned char buffer[1024];
    ssize_t bytes;

    /* make sure to set the target format "unknown" to begin with */
    target->format = VIR_STORAGE_POOL_DISK_UNKNOWN;

    start = lseek(fd, 0, SEEK_SET);
    if (start < 0) {
        virReportSystemError(errno,
                             _("cannot seek to beginning of file '%s'"),
                             target->path);
        return -1;
    }
    bytes = saferead(fd, buffer, sizeof(buffer));
    if (bytes < 0) {
        if (readflags & VIR_STORAGE_VOL_READ_NOERROR) {
            VIR_WARN("ignoring failed saferead of file '%s'",
                     target->path);
            return -2;
        } else {
            virReportSystemError(errno,
                                 _("cannot read beginning of file '%s'"),
                                 target->path);
            return -1;
        }
    }

    for (i = 0; disk_types[i].part_table_type != -1; i++) {
        if (disk_types[i].offset + disk_types[i].length > bytes)
            continue;
        if (memcmp(buffer+disk_types[i].offset, &disk_types[i].magic,
            disk_types[i].length) == 0) {
            target->format = disk_types[i].part_table_type;
            break;
        }
    }

    if (target->format == VIR_STORAGE_POOL_DISK_UNKNOWN)
        VIR_DEBUG("cannot determine the target format for '%s'",
                  target->path);

    return 0;
}


/*
 * Allows caller to silently ignore files with improper mode
 *
 * Returns -1 on error. If VIR_STORAGE_VOL_OPEN_NOERROR is passed, we
 * return -2 if file mode is unexpected or the volume is a dangling
 * symbolic link.
 */
int
virStorageBackendVolOpen(const char *path, struct stat *sb,
                         unsigned int flags)
{
    int fd, mode = 0;
    char *base = last_component(path);
    bool noerror = (flags & VIR_STORAGE_VOL_OPEN_NOERROR);

    if (lstat(path, sb) < 0) {
        if (errno == ENOENT) {
            if (noerror) {
                VIR_WARN("ignoring missing file '%s'", path);
                return -2;
            }
            virReportError(VIR_ERR_NO_STORAGE_VOL,
                           _("no storage vol with matching path '%s'"),
                           path);
            return -1;
        }
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             path);
        return -1;
    }

    if (S_ISFIFO(sb->st_mode)) {
        if (noerror) {
            VIR_WARN("ignoring FIFO '%s'", path);
            return -2;
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume path '%s' is a FIFO"), path);
        return -1;
    } else if (S_ISSOCK(sb->st_mode)) {
        if (noerror) {
            VIR_WARN("ignoring socket '%s'", path);
            return -2;
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume path '%s' is a socket"), path);
        return -1;
    }

    /* O_NONBLOCK should only matter during open() for fifos and
     * sockets, which we already filtered; but using it prevents a
     * TOCTTOU race.  However, later on we will want to read() the
     * header from this fd, and virFileRead* routines require a
     * blocking fd, so fix it up after verifying we avoided a race.
     *
     * Use of virFileOpenAs allows this path to open a file using
     * the uid and gid as it was created in order to open. Since this
     * path is not using O_CREAT or O_TMPFILE, mode is meaningless.
     * Opening under user/group is especially important in an NFS
     * root-squash environment. If the target path isn't on shared
     * file system, the open will fail in the OPEN_FORK path.
     */
    if ((fd = virFileOpenAs(path, O_RDONLY|O_NONBLOCK|O_NOCTTY,
                            0, sb->st_uid, sb->st_gid,
                            VIR_FILE_OPEN_NOFORK|VIR_FILE_OPEN_FORK)) < 0) {
        if ((errno == ENOENT || errno == ELOOP) &&
            S_ISLNK(sb->st_mode) && noerror) {
            VIR_WARN("ignoring dangling symlink '%s'", path);
            return -2;
        }
        if (errno == ENOENT && noerror) {
            VIR_WARN("ignoring missing file '%s'", path);
            return -2;
        }
        if (errno == ENXIO && noerror) {
            VIR_WARN("ignoring missing fifo '%s'", path);
            return -2;
        }
        if ((errno == EACCES || errno == EPERM) && noerror) {
            VIR_WARN("ignoring permission error for '%s'", path);
            return -2;
        }

        virReportSystemError(errno, _("cannot open volume '%s'"), path);
        return -1;
    }

    if (fstat(fd, sb) < 0) {
        virReportSystemError(errno, _("cannot stat file '%s'"), path);
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    if (S_ISREG(sb->st_mode)) {
        mode = VIR_STORAGE_VOL_OPEN_REG;
    } else if (S_ISCHR(sb->st_mode)) {
        mode = VIR_STORAGE_VOL_OPEN_CHAR;
    } else if (S_ISBLK(sb->st_mode)) {
        mode = VIR_STORAGE_VOL_OPEN_BLOCK;
    } else if (S_ISDIR(sb->st_mode)) {
        mode = VIR_STORAGE_VOL_OPEN_DIR;

        if (STREQ(base, ".") ||
            STREQ(base, "..")) {
            VIR_FORCE_CLOSE(fd);
            if (noerror) {
                VIR_INFO("Skipping special dir '%s'", base);
                return -2;
            }
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot use volume path '%s'"), path);
            return -1;
        }
    } else {
        VIR_FORCE_CLOSE(fd);
        if (noerror) {
            VIR_WARN("ignoring unexpected type for file '%s'", path);
            return -2;
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected type for file '%s'"), path);
        return -1;
    }

    if (virSetBlocking(fd, true) < 0) {
        VIR_FORCE_CLOSE(fd);
        virReportSystemError(errno, _("unable to set blocking mode for '%s'"),
                             path);
        return -1;
    }

    if (!(mode & flags)) {
        VIR_FORCE_CLOSE(fd);
        if (noerror) {
            VIR_INFO("Skipping volume '%s'", path);
            return -2;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected storage mode for '%s'"), path);
        return -1;
    }

    return fd;
}

/* virStorageIsPloop function checks whether given directory is ploop volume's
 * directory.
 */
static bool
storageBackendIsPloopDir(char *path)
{
    VIR_AUTOFREE(char *) root = NULL;
    VIR_AUTOFREE(char *) desc = NULL;

    if (virAsprintf(&root, "%s/root.hds", path) < 0)
        return false;
    if (!virFileExists(root))
        return false;
    if (virAsprintf(&desc, "%s/DiskDescriptor.xml", path) < 0)
        return false;
    if (!virFileExists(desc))
        return false;

    return true;
}

/* In case of ploop volumes, path to volume is the path to the ploop
 * directory. To get information about allocation, header information
 * and etc. we need to perform virStorageBackendVolOpen and
 * virStorageBackendUpdateVolTargetFd once again.
 */
static int
storageBackendRedoPloopUpdate(virStorageSourcePtr target, struct stat *sb,
                              int *fd, unsigned int flags)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (virAsprintf(&path, "%s/root.hds", target->path) < 0)
        return -1;
    VIR_FORCE_CLOSE(*fd);
    if ((*fd = virStorageBackendVolOpen(path, sb, flags)) < 0)
        return -1;
    return virStorageBackendUpdateVolTargetInfoFD(target, *fd, sb);
}

/*
 * storageBackendUpdateVolTargetInfo
 * @voltype: Volume type
 * @target: target definition ptr of volume to update
 * @withBlockVolFormat: true if caller determined a block file
 * @openflags: various VolOpenCheckMode flags to handle errors on open
 * @readflags: VolReadErrorMode flags to handle read error after open
 *             is successful, but read is not.
 *
 * Returns 0 for success, -1 on a legitimate error condition, and -2
 * if the openflags used VIR_STORAGE_VOL_OPEN_NOERROR and some sort of
 * open error occurred. It is up to the caller to handle. A -2 may also
 * be returned if the caller passed a readflagsflag.
 */
static int
storageBackendUpdateVolTargetInfo(virStorageVolType voltype,
                                  virStorageSourcePtr target,
                                  bool withBlockVolFormat,
                                  unsigned int openflags,
                                  unsigned int readflags)
{
    int rc;
    struct stat sb;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOCLOSE fd = -1;

    if ((rc = virStorageBackendVolOpen(target->path, &sb, openflags)) < 0)
        return rc;
    fd = rc;

    if ((virStorageBackendUpdateVolTargetInfoFD(target, fd, &sb)) < 0)
        return -1;

    if ((voltype == VIR_STORAGE_VOL_FILE || voltype == VIR_STORAGE_VOL_BLOCK) &&
        target->format != VIR_STORAGE_FILE_NONE) {
        if (S_ISDIR(sb.st_mode)) {
            if (storageBackendIsPloopDir(target->path)) {
                if ((storageBackendRedoPloopUpdate(target, &sb, &fd,
                                                   openflags)) < 0)
                    return -1;
                target->format = VIR_STORAGE_FILE_PLOOP;
            } else {
                return 0;
            }
        }

        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            virReportSystemError(errno, _("cannot seek to start of '%s'"), target->path);
            return -1;
        }

        if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
            if (readflags & VIR_STORAGE_VOL_READ_NOERROR) {
                VIR_WARN("ignoring failed header read for '%s'",
                         target->path);
                return -2;
            } else {
                virReportSystemError(errno,
                                     _("cannot read header '%s'"),
                                     target->path);
                return -1;
            }
        }

        if (virStorageSourceUpdateCapacity(target, buf, len, false) < 0)
            return -1;
    }

    if (withBlockVolFormat)
        return virStorageBackendDetectBlockVolFormatFD(target, fd, readflags);

    return 0;
}

/*
 * virStorageBackendUpdateVolInfo
 * @vol: Pointer to a volume storage definition
 * @withBlockVolFormat: true if the caller determined a block file
 * @openflags: various VolOpenCheckMode flags to handle errors on open
 * @readflags: various VolReadErrorMode flags to handle errors on read
 *
 * Returns 0 for success, -1 on a legitimate error condition, and -2
 * if the openflags used VIR_STORAGE_VOL_OPEN_NOERROR and some sort of
 * open error occurred. It is up to the caller to handle.
 */
int
virStorageBackendUpdateVolInfo(virStorageVolDefPtr vol,
                               bool withBlockVolFormat,
                               unsigned int openflags,
                               unsigned int readflags)
{
    int ret;

    if ((ret = storageBackendUpdateVolTargetInfo(vol->type,
                                                 &vol->target,
                                                 withBlockVolFormat,
                                                 openflags, readflags)) < 0)
        return ret;

    if (virStorageSourceHasBacking(&vol->target) &&
        (ret = storageBackendUpdateVolTargetInfo(VIR_STORAGE_VOL_FILE,
                                                 vol->target.backingStore,
                                                 withBlockVolFormat,
                                                 VIR_STORAGE_VOL_OPEN_DEFAULT |
                                                 VIR_STORAGE_VOL_OPEN_NOERROR,
                                                 readflags)) == -1)
        return ret;

    return 0;
}

/*
 * virStorageBackendUpdateVolTargetInfoFD:
 * @target: target definition ptr of volume to update
 * @fd: fd of storage volume to update, via virStorageBackendOpenVol*, or -1
 * @sb: details about file (must match @fd, if that is provided)
 *
 * Returns 0 for success, -1 on a legitimate error condition.
 */
int
virStorageBackendUpdateVolTargetInfoFD(virStorageSourcePtr target,
                                       int fd,
                                       struct stat *sb)
{
#if WITH_SELINUX
    security_context_t filecon = NULL;
#endif

    if (virStorageSourceUpdateBackingSizes(target, fd, sb) < 0)
        return -1;

    if (!target->perms && VIR_ALLOC(target->perms) < 0)
        return -1;
    target->perms->mode = sb->st_mode & S_IRWXUGO;
    target->perms->uid = sb->st_uid;
    target->perms->gid = sb->st_gid;

    if (!target->timestamps && VIR_ALLOC(target->timestamps) < 0)
        return -1;
    target->timestamps->atime = get_stat_atime(sb);
    target->timestamps->btime = get_stat_birthtime(sb);
    target->timestamps->ctime = get_stat_ctime(sb);
    target->timestamps->mtime = get_stat_mtime(sb);

    target->type = VIR_STORAGE_TYPE_FILE;

    VIR_FREE(target->perms->label);

#if WITH_SELINUX
    /* XXX: make this a security driver call */
    if (fd >= 0) {
        if (fgetfilecon_raw(fd, &filecon) == -1) {
            if (errno != ENODATA && errno != ENOTSUP) {
                virReportSystemError(errno,
                                     _("cannot get file context of '%s'"),
                                     target->path);
                return -1;
            }
        } else {
            if (VIR_STRDUP(target->perms->label, filecon) < 0) {
                freecon(filecon);
                return -1;
            }
            freecon(filecon);
        }
    }
#endif

    return 0;
}

bool
virStorageBackendPoolPathIsStable(const char *path)
{
    if (path == NULL || STREQ(path, "/dev") || STREQ(path, "/dev/"))
        return false;

    if (!STRPREFIX(path, "/dev/"))
        return false;

    return true;
}

/*
 * Given a volume path directly in /dev/XXX, iterate over the
 * entries in the directory def->target.path and find the
 * first symlink pointing to the volume path.
 *
 * If, the target.path is /dev/, then return the original volume
 * path.
 *
 * If no symlink is found, then return the original volume path
 *
 * Typically target.path is one of the /dev/disk/by-XXX dirs
 * with stable paths.
 *
 * If 'loop' is true, we use a timeout loop to give dynamic paths
 * a change to appear.
 */
char *
virStorageBackendStablePath(virStoragePoolObjPtr pool,
                            const char *devpath,
                            bool loop)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    DIR *dh;
    struct dirent *dent;
    char *stablepath;
    int opentries = 0;
    int retry = 0;
    int direrr;

    /* Logical pools are under /dev but already have stable paths */
    if (def->type == VIR_STORAGE_POOL_LOGICAL ||
        !virStorageBackendPoolPathIsStable(def->target.path))
        goto ret_strdup;

    /* We loop here because /dev/disk/by-{id,path} may not have existed
     * before we started this operation, so we have to give it some time to
     * get created.
     */
 reopen:
    if (virDirOpenQuiet(&dh, def->target.path) < 0) {
        opentries++;
        if (loop && errno == ENOENT && opentries < 50) {
            usleep(100 * 1000);
            goto reopen;
        }
        virReportSystemError(errno,
                             _("cannot read dir '%s'"),
                             def->target.path);
        return NULL;
    }

    /* The pool is pointing somewhere like /dev/disk/by-path
     * or /dev/disk/by-id, so we need to check all symlinks in
     * the target directory and figure out which one points
     * to this device node.
     *
     * And it might need some time till the stable path shows
     * up, so add timeout to retry here.  Ignore readdir failures,
     * since we have a fallback.
     */
 retry:
    while ((direrr = virDirRead(dh, &dent, NULL)) > 0) {
        if (virAsprintf(&stablepath, "%s/%s",
                        def->target.path, dent->d_name) < 0) {
            VIR_DIR_CLOSE(dh);
            return NULL;
        }

        if (virFileLinkPointsTo(stablepath, devpath)) {
            VIR_DIR_CLOSE(dh);
            return stablepath;
        }

        VIR_FREE(stablepath);
    }

    if (!direrr && loop && ++retry < 100) {
        usleep(100 * 1000);
        goto retry;
    }

    VIR_DIR_CLOSE(dh);

 ret_strdup:
    /* Couldn't find any matching stable link so give back
     * the original non-stable dev path
     */

    ignore_value(VIR_STRDUP(stablepath, devpath));

    return stablepath;
}

/* Common/Local File System/Directory Volume API's */
static int
createFileDir(virStoragePoolObjPtr pool,
              virStorageVolDefPtr vol,
              virStorageVolDefPtr inputvol,
              unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int err;

    virCheckFlags(0, -1);

    if (inputvol) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("cannot copy from volume to a directory volume"));
        return -1;
    }

    if (virStorageSourceHasBacking(&vol->target)) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("backing storage not supported for directories volumes"));
        return -1;
    }


    if ((err = virDirCreate(vol->target.path,
                            (vol->target.perms->mode == (mode_t)-1 ?
                             VIR_STORAGE_DEFAULT_VOL_PERM_MODE :
                             vol->target.perms->mode),
                            vol->target.perms->uid,
                            vol->target.perms->gid,
                            (def->type == VIR_STORAGE_POOL_NETFS
                             ? VIR_DIR_CREATE_AS_UID : 0))) < 0) {
        return -1;
    }

    return 0;
}


/**
 * Set up a volume definition to be added to a pool's volume list, but
 * don't do any file creation or allocation. By separating the two processes,
 * we allow allocation progress reporting (by polling the volume's 'info'
 * function), and can drop the parent pool lock during the (slow) allocation.
 */
int
virStorageBackendVolCreateLocal(virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (vol->target.format == VIR_STORAGE_FILE_DIR)
        vol->type = VIR_STORAGE_VOL_DIR;
    else if (vol->target.format == VIR_STORAGE_FILE_PLOOP)
        vol->type = VIR_STORAGE_VOL_PLOOP;
    else
        vol->type = VIR_STORAGE_VOL_FILE;

    /* Volumes within a directory pools are not recursive; do not
     * allow escape to ../ or a subdir */
    if (strchr(vol->name, '/')) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume name '%s' cannot contain '/'"), vol->name);
        return -1;
    }

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    def->target.path, vol->name) < 0)
        return -1;

    if (virFileExists(vol->target.path)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume target path '%s' already exists"),
                       vol->target.path);
        return -1;
    }

    VIR_FREE(vol->key);
    return VIR_STRDUP(vol->key, vol->target.path);
}


static int
storageBackendVolBuildLocal(virStoragePoolObjPtr pool,
                            virStorageVolDefPtr vol,
                            virStorageVolDefPtr inputvol,
                            unsigned int flags)
{
    virStorageBackendBuildVolFrom create_func;

    if (inputvol) {
        if (!(create_func =
              virStorageBackendGetBuildVolFromFunction(vol, inputvol)))
            return -1;
    } else if (vol->target.format == VIR_STORAGE_FILE_RAW &&
               vol->target.encryption == NULL) {
        create_func = storageBackendCreateRaw;
    } else if (vol->target.format == VIR_STORAGE_FILE_DIR) {
        create_func = createFileDir;
    } else if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        create_func = storageBackendCreatePloop;
    } else {
        create_func = storageBackendCreateQemuImg;
    }

    if (create_func(pool, vol, inputvol, flags) < 0)
        return -1;
    return 0;
}


/**
 * Allocate a new file as a volume. This is either done directly
 * for raw/sparse files, or by calling qemu-img for
 * special kinds of files
 */
int
virStorageBackendVolBuildLocal(virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               unsigned int flags)
{
    return storageBackendVolBuildLocal(pool, vol, NULL, flags);
}


/*
 * Create a storage vol using 'inputvol' as input
 */
int
virStorageBackendVolBuildFromLocal(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   virStorageVolDefPtr inputvol,
                                   unsigned int flags)
{
    return storageBackendVolBuildLocal(pool, vol, inputvol, flags);
}


/**
 * Remove a volume - no support for BLOCK and NETWORK yet
 */
int
virStorageBackendVolDeleteLocal(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                virStorageVolDefPtr vol,
                                unsigned int flags)
{
    virCheckFlags(0, -1);

    switch ((virStorageVolType)vol->type) {
    case VIR_STORAGE_VOL_FILE:
    case VIR_STORAGE_VOL_DIR:
        if (virFileRemove(vol->target.path, vol->target.perms->uid,
                          vol->target.perms->gid) < 0) {
            /* Silently ignore failures where the vol has already gone away */
            if (errno != ENOENT) {
                if (vol->type == VIR_STORAGE_VOL_FILE)
                    virReportSystemError(errno,
                                         _("cannot unlink file '%s'"),
                                         vol->target.path);
                else
                    virReportSystemError(errno,
                                         _("cannot remove directory '%s'"),
                                         vol->target.path);
                return -1;
            }
        }
        break;
    case VIR_STORAGE_VOL_PLOOP:
        if (virFileDeleteTree(vol->target.path) < 0)
            return -1;
        break;
    case VIR_STORAGE_VOL_BLOCK:
    case VIR_STORAGE_VOL_NETWORK:
    case VIR_STORAGE_VOL_NETDIR:
    case VIR_STORAGE_VOL_LAST:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("removing block or network volumes is not supported: %s"),
                       vol->target.path);
        return -1;
    }
    return 0;
}


/* storageBackendLoadDefaultSecrets:
 * @vol: volume being refreshed
 *
 * If the volume had a secret generated, we need to regenerate the
 * encryption secret information
 *
 * Returns 0 if no secret or secret setup was successful,
 * -1 on failures w/ error message set
 */
static int
storageBackendLoadDefaultSecrets(virStorageVolDefPtr vol)
{
    virSecretPtr sec;
    virStorageEncryptionSecretPtr encsec = NULL;
    virConnectPtr conn = NULL;

    if (!vol->target.encryption || vol->target.encryption->nsecrets != 0)
        return 0;

    conn = virGetConnectSecret();
    if (!conn)
        return -1;

    /* The encryption secret for qcow2 and luks volumes use the path
     * to the volume, so look for a secret with the path. If not found,
     * then we cannot generate the secret after a refresh (or restart).
     * This may be the case if someone didn't follow instructions and created
     * a usage string that although matched with the secret usage string,
     * didn't contain the path to the volume. We won't error in that case,
     * but we also cannot find the secret. */
    sec = virSecretLookupByUsage(conn, VIR_SECRET_USAGE_TYPE_VOLUME,
                                 vol->target.path);
    virObjectUnref(conn);
    if (!sec)
        return 0;

    if (VIR_ALLOC_N(vol->target.encryption->secrets, 1) < 0 ||
        VIR_ALLOC(encsec) < 0) {
        VIR_FREE(vol->target.encryption->secrets);
        virObjectUnref(sec);
        return -1;
    }

    vol->target.encryption->nsecrets = 1;
    vol->target.encryption->secrets[0] = encsec;

    encsec->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
    encsec->seclookupdef.type = VIR_SECRET_LOOKUP_TYPE_UUID;
    virSecretGetUUID(sec, encsec->seclookupdef.u.uuid);
    virObjectUnref(sec);

    return 0;
}


/**
 * Update info about a volume's capacity/allocation
 */
int
virStorageBackendVolRefreshLocal(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 virStorageVolDefPtr vol)
{
    int ret;

    /* Refresh allocation / capacity / permissions info in case its changed */
    if ((ret = virStorageBackendUpdateVolInfo(vol, false,
                                              VIR_STORAGE_VOL_FS_OPEN_FLAGS,
                                              0)) < 0)
        return ret;

    /* Load any secrets if possible */
    return storageBackendLoadDefaultSecrets(vol);
}


static int
storageBackendResizeQemuImg(virStoragePoolObjPtr pool,
                            virStorageVolDefPtr vol,
                            unsigned long long capacity)
{
    int ret = -1;
    const char *type;
    virStorageEncryptionPtr enc = vol->target.encryption;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) img_tool = NULL;
    VIR_AUTOFREE(char *) secretPath = NULL;
    VIR_AUTOFREE(char *) secretAlias = NULL;

    if (enc && (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_QCOW ||
                enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT) &&
        (vol->target.format == VIR_STORAGE_FILE_QCOW ||
         vol->target.format == VIR_STORAGE_FILE_QCOW2)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("resize of qcow2 encrypted image is not supported"));
        return -1;
    }

    img_tool = virFindFileInPath("qemu-img");
    if (!img_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find qemu-img"));
        return -1;
    }

    if (vol->target.encryption) {
        if (vol->target.format == VIR_STORAGE_FILE_RAW)
            type = "luks";
        else
            type = virStorageFileFormatTypeToString(vol->target.format);

        storageBackendLoadDefaultSecrets(vol);

        if (storageBackendCreateQemuImgCheckEncryption(vol->target.format,
                                                       type, vol) < 0)
            goto cleanup;

        if (!(secretPath =
              storageBackendCreateQemuImgSecretPath(pool, vol)))
            goto cleanup;

        if (virAsprintf(&secretAlias, "%s_encrypt0", vol->name) < 0)
            goto cleanup;
    }

    /* Round capacity as qemu-img resize errors out on sizes which are not
     * a multiple of 512 */
    capacity = VIR_ROUND_UP(capacity, 512);

    cmd = virCommandNewArgList(img_tool, "resize", NULL);
    if (capacity < vol->target.capacity)
        virCommandAddArg(cmd, "--shrink");
    if (!vol->target.encryption) {
        virCommandAddArg(cmd, vol->target.path);
    } else {
        if (storageBackendCreateQemuImgSecretObject(cmd, secretPath,
                                                    secretAlias) < 0)
            goto cleanup;

        if (storageBackendResizeQemuImgImageOpts(cmd, vol->target.path,
                                                 secretAlias) < 0)
            goto cleanup;
    }
    virCommandAddArgFormat(cmd, "%llu", capacity);

    ret = virCommandRun(cmd, NULL);

 cleanup:
    if (secretPath)
        unlink(secretPath);
    return ret;
}


/**
 * Resize a volume
 */
int
virStorageBackendVolResizeLocal(virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol,
                                unsigned long long capacity,
                                unsigned int flags)
{
    bool pre_allocate = flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE;

    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE |
                  VIR_STORAGE_VOL_RESIZE_SHRINK, -1);

    if (vol->target.format == VIR_STORAGE_FILE_RAW && !vol->target.encryption) {
        return virStorageFileResize(vol->target.path, capacity, pre_allocate);
    } else if (vol->target.format == VIR_STORAGE_FILE_RAW && vol->target.encryption) {
        if (pre_allocate) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("preallocate is only supported for an "
                             "unencrypted raw volume"));
            return -1;
        }

        return storageBackendResizeQemuImg(pool, vol, capacity);
    } else if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        return storagePloopResize(vol, capacity);
    } else {
        if (pre_allocate) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("preallocate is only supported for raw "
                             "type volume"));
            return -1;
        }

        return storageBackendResizeQemuImg(pool, vol, capacity);
    }
}


/*
 *  Check whether the ploop image has snapshots.
 *  return: -1 - failed to check
 *           0 - no snapshots
 *           1 - at least one snapshot
 */
static int
storageBackendPloopHasSnapshots(char *path)
{
    char *snap_tool = NULL;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) output = NULL;

    snap_tool = virFindFileInPath("ploop");
    if (!snap_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find ploop, please install "
                               "ploop tools"));
        return -1;
    }

    cmd = virCommandNewArgList(snap_tool, "snapshot-list", NULL);
    virCommandAddArgFormat(cmd, "%s/DiskDescriptor.xml", path);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (!strstr(output, "root.hds."))
        return 1;

    return 0;
}


int
virStorageBackendVolUploadLocal(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                virStorageVolDefPtr vol,
                                virStreamPtr stream,
                                unsigned long long offset,
                                unsigned long long len,
                                unsigned int flags)
{
    char *target_path = vol->target.path;
    int has_snap = 0;
    bool sparse = flags & VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM;
    VIR_AUTOFREE(char *)path = NULL;

    virCheckFlags(VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM, -1);
    /* if volume has target format VIR_STORAGE_FILE_PLOOP
     * we need to restore DiskDescriptor.xml, according to
     * new contents of volume. This operation will be perfomed
     * when volUpload is fully finished. */
    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        /* Fail if the volume contains snapshots or we failed to check it.*/
        has_snap = storageBackendPloopHasSnapshots(vol->target.path);
        if (has_snap < 0) {
            return -1;
        } else if (!has_snap) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("can't upload volume, all existing snapshots"
                             " will be lost"));
            return -1;
        }

        if (virAsprintf(&path, "%s/root.hds", vol->target.path) < 0)
            return -1;
        target_path = path;
    }

    /* Not using O_CREAT because the file is required to already exist at
     * this point */
    return virFDStreamOpenBlockDevice(stream, target_path,
                                      offset, len, sparse, O_WRONLY);
}

int
virStorageBackendVolDownloadLocal(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                  virStorageVolDefPtr vol,
                                  virStreamPtr stream,
                                  unsigned long long offset,
                                  unsigned long long len,
                                  unsigned int flags)
{
    char *target_path = vol->target.path;
    int has_snap = 0;
    bool sparse = flags & VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM;
    VIR_AUTOFREE(char *) path = NULL;

    virCheckFlags(VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM, -1);
    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        has_snap = storageBackendPloopHasSnapshots(vol->target.path);
        if (has_snap < 0) {
            return -1;
        } else if (!has_snap) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("can't download volume, all existing snapshots"
                             " will be lost"));
            return -1;
        }
        if (virAsprintf(&path, "%s/root.hds", vol->target.path) < 0)
            return -1;
        target_path = path;
    }

    return virFDStreamOpenBlockDevice(stream, target_path,
                                      offset, len, sparse, O_RDONLY);
}


/* If the volume we're wiping is already a sparse file, we simply
 * truncate and extend it to its original size, filling it with
 * zeroes.  This behavior is guaranteed by POSIX:
 *
 * http://www.opengroup.org/onlinepubs/9699919799/functions/ftruncate.html
 *
 * If fildes refers to a regular file, the ftruncate() function shall
 * cause the size of the file to be truncated to length. If the size
 * of the file previously exceeded length, the extra data shall no
 * longer be available to reads on the file. If the file previously
 * was smaller than this size, ftruncate() shall increase the size of
 * the file. If the file size is increased, the extended area shall
 * appear as if it were zero-filled.
 */
static int
storageBackendVolZeroSparseFileLocal(const char *path,
                                     off_t size,
                                     int fd)
{
    if (ftruncate(fd, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to truncate volume with "
                               "path '%s' to 0 bytes"),
                             path);
        return -1;
    }

    if (ftruncate(fd, size) < 0) {
        virReportSystemError(errno,
                             _("Failed to truncate volume with "
                               "path '%s' to %ju bytes"),
                             path, (uintmax_t)size);
        return -1;
    }

    return 0;
}


static int
storageBackendWipeLocal(const char *path,
                        int fd,
                        unsigned long long wipe_len,
                        size_t writebuf_length,
                        bool zero_end)
{
    int written = 0;
    unsigned long long remaining = 0;
    off_t size;
    size_t write_size = 0;
    VIR_AUTOFREE(char *) writebuf = NULL;

    if (VIR_ALLOC_N(writebuf, writebuf_length) < 0)
        return -1;

    if (!zero_end) {
        if ((size = lseek(fd, 0, SEEK_SET)) < 0) {
            virReportSystemError(errno,
                                 _("Failed to seek to the start in volume "
                                   "with path '%s'"),
                                 path);
            return -1;
        }
    } else {
        if ((size = lseek(fd, -wipe_len, SEEK_END)) < 0) {
            virReportSystemError(errno,
                                 _("Failed to seek to %llu bytes to the end "
                                   "in volume with path '%s'"),
                                 wipe_len, path);
            return -1;
        }
    }

    VIR_DEBUG("wiping start: %zd len: %llu", (ssize_t)size, wipe_len);

    remaining = wipe_len;
    while (remaining > 0) {

        write_size = (writebuf_length < remaining) ? writebuf_length : remaining;
        written = safewrite(fd, writebuf, write_size);
        if (written < 0) {
            virReportSystemError(errno,
                                 _("Failed to write %zu bytes to "
                                   "storage volume with path '%s'"),
                                 write_size, path);

            return -1;
        }

        remaining -= written;
    }

    if (fdatasync(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot sync data to volume with path '%s'"),
                             path);
        return -1;
    }

    VIR_DEBUG("Wrote %llu bytes to volume with path '%s'", wipe_len, path);

    return 0;
}


static int
storageBackendVolWipeLocalFile(const char *path,
                               unsigned int algorithm,
                               unsigned long long allocation,
                               bool zero_end)
{
    const char *alg_char = NULL;
    struct stat st;
    VIR_AUTOCLOSE fd = -1;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    fd = open(path, O_RDWR);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("Failed to open storage volume with path '%s'"),
                             path);
        return -1;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno,
                             _("Failed to stat storage volume with path '%s'"),
                             path);
        return -1;
    }

    switch ((virStorageVolWipeAlgorithm) algorithm) {
    case VIR_STORAGE_VOL_WIPE_ALG_ZERO:
        alg_char = "zero";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_NNSA:
        alg_char = "nnsa";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_DOD:
        alg_char = "dod";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_BSI:
        alg_char = "bsi";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_GUTMANN:
        alg_char = "gutmann";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER:
        alg_char = "schneier";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7:
        alg_char = "pfitzner7";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33:
        alg_char = "pfitzner33";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_RANDOM:
        alg_char = "random";
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_TRIM:
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("'trim' algorithm not supported"));
        return -1;
    case VIR_STORAGE_VOL_WIPE_ALG_LAST:
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported algorithm %d"),
                       algorithm);
        return -1;
    }

    VIR_DEBUG("Wiping file '%s' with algorithm '%s'", path, alg_char);

    if (algorithm != VIR_STORAGE_VOL_WIPE_ALG_ZERO) {
        cmd = virCommandNew(SCRUB);
        virCommandAddArgList(cmd, "-f", "-p", alg_char, path, NULL);

        return virCommandRun(cmd, NULL);
    }

    if (S_ISREG(st.st_mode) && st.st_blocks < (st.st_size / DEV_BSIZE))
        return storageBackendVolZeroSparseFileLocal(path, st.st_size, fd);

    return storageBackendWipeLocal(path, fd, allocation, st.st_blksize,
                                   zero_end);
}


static int
storageBackendVolWipePloop(virStorageVolDefPtr vol,
                           unsigned int algorithm)
{
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) target_path = NULL;
    VIR_AUTOFREE(char *) disk_desc = NULL;
    VIR_AUTOFREE(char *) create_tool = NULL;

    create_tool = virFindFileInPath("ploop");
    if (!create_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop tools, please install them"));
        return -1;
    }

    if (virAsprintf(&target_path, "%s/root.hds", vol->target.path) < 0)
        return -1;

    if (virAsprintf(&disk_desc, "%s/DiskDescriptor.xml", vol->target.path) < 0)
        return -1;

    if (storageBackendVolWipeLocalFile(target_path, algorithm,
                                       vol->target.allocation, false) < 0)
        return -1;

    if (virFileRemove(disk_desc, 0, 0) < 0) {
        virReportError(errno, _("Failed to delete DiskDescriptor.xml of volume '%s'"),
                       vol->target.path);
        return -1;
    }
    if (virFileRemove(target_path, 0, 0) < 0) {
        virReportError(errno, _("failed to delete root.hds of volume '%s'"),
                       vol->target.path);
        return -1;
    }

    cmd = virCommandNewArgList(create_tool, "init", "-s", NULL);

    virCommandAddArgFormat(cmd, "%lluM", VIR_DIV_UP(vol->target.capacity,
                                                    (1024 * 1024)));
    virCommandAddArgList(cmd, "-t", "ext4", NULL);
    virCommandAddArg(cmd, target_path);
    return virCommandRun(cmd, NULL);
}


int
virStorageBackendVolWipeLocal(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              virStorageVolDefPtr vol,
                              unsigned int algorithm,
                              unsigned int flags)
{
    int ret = -1;

    virCheckFlags(0, -1);

    VIR_DEBUG("Wiping volume with path '%s' and algorithm %u",
              vol->target.path, algorithm);

    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        ret = storageBackendVolWipePloop(vol, algorithm);
    } else {
        ret = storageBackendVolWipeLocalFile(vol->target.path, algorithm,
                                             vol->target.allocation, false);
    }

    return ret;
}


/**
 * @pool: storage pool to build
 * @dir_create_flags: flags for directory creation
 *
 * Common code to build a directory based storage pool
 *
 * Returns 0 on success, -1 on failure
 */
int
virStorageBackendBuildLocal(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *p = NULL;
    mode_t mode;
    bool needs_create_as_uid;
    unsigned int dir_create_flags;
    VIR_AUTOFREE(char *) parent = NULL;

    if (VIR_STRDUP(parent, def->target.path) < 0)
        return -1;
    if (!(p = strrchr(parent, '/'))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("path '%s' is not absolute"),
                       def->target.path);
        return -1;
    }

    if (p != parent) {
        /* assure all directories in the path prior to the final dir
         * exist, with default uid/gid/mode. */
        *p = '\0';
        if (virFileMakePath(parent) < 0) {
            virReportSystemError(errno, _("cannot create path '%s'"),
                                 parent);
            return -1;
        }
    }

    dir_create_flags = VIR_DIR_CREATE_ALLOW_EXIST;
    needs_create_as_uid = (def->type == VIR_STORAGE_POOL_NETFS);
    mode = def->target.perms.mode;

    if (mode == (mode_t)-1 &&
        (needs_create_as_uid || !virFileExists(def->target.path)))
        mode = VIR_STORAGE_DEFAULT_POOL_PERM_MODE;
    if (needs_create_as_uid)
        dir_create_flags |= VIR_DIR_CREATE_AS_UID;

    /* Now create the final dir in the path with the uid/gid/mode
     * requested in the config. If the dir already exists, just set
     * the perms. */
    return virDirCreate(def->target.path,
                        mode,
                        def->target.perms.uid,
                        def->target.perms.gid,
                        dir_create_flags);
}


/**
 * @conn connection to report errors against
 * @pool storage pool to delete
 *
 * Delete a directory based storage pool
 *
 * Returns 0 on success, -1 on error
 */
int
virStorageBackendDeleteLocal(virStoragePoolObjPtr pool,
                             unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    virCheckFlags(0, -1);

    /* XXX delete all vols first ? */

    if (rmdir(def->target.path) < 0) {
        virReportSystemError(errno,
                             _("failed to remove pool '%s'"),
                             def->target.path);
        return -1;
    }

    return 0;
}


int
virStorageUtilGlusterExtractPoolSources(const char *host,
                                        const char *xml,
                                        virStoragePoolSourceListPtr list,
                                        virStoragePoolType pooltype)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virStoragePoolSource *src = NULL;
    size_t i;
    int nnodes;
    int ret = -1;
    VIR_AUTOFREE(xmlNodePtr *) nodes = NULL;
    VIR_AUTOFREE(char *) volname = NULL;

    if (!(doc = virXMLParseStringCtxt(xml, _("(gluster_cli_output)"), &ctxt)))
        goto cleanup;

    if ((nnodes = virXPathNodeSet("//volumes/volume", ctxt, &nodes)) < 0)
        goto cleanup;

    for (i = 0; i < nnodes; i++) {
        ctxt->node = nodes[i];

        if (!(src = virStoragePoolSourceListNewSource(list)))
            goto cleanup;

        if (!(volname = virXPathString("string(./name)", ctxt))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to extract gluster volume name"));
            goto cleanup;
        }

        if (pooltype == VIR_STORAGE_POOL_NETFS) {
            src->format = VIR_STORAGE_POOL_NETFS_GLUSTERFS;
            VIR_STEAL_PTR(src->dir, volname);
        } else if (pooltype == VIR_STORAGE_POOL_GLUSTER) {
            if (VIR_STRDUP(src->dir, "/") < 0)
                goto cleanup;
            VIR_STEAL_PTR(src->name, volname);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unsupported gluster lookup"));
            goto cleanup;
        }

        if (VIR_ALLOC_N(src->hosts, 1) < 0)
            goto cleanup;
        src->nhost = 1;

        if (VIR_STRDUP(src->hosts[0].name, host) < 0)
            goto cleanup;
    }

    ret = nnodes;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


/**
 * virStorageBackendFindGlusterPoolSources:
 * @host: host to detect volumes on
 * @pooltype: type of the pool
 * @list: list of storage pool sources to be filled
 * @report: report error if the 'gluster' cli tool is missing
 *
 * Looks up gluster volumes on @host and fills them to @list.
 *
 * @pooltype allows to influence the specific differences between netfs and
 * native gluster pools. Users should pass only VIR_STORAGE_POOL_NETFS or
 * VIR_STORAGE_POOL_GLUSTER.
 *
 * Returns number of volumes on the host on success, or -1 on error.
 */
int
virStorageBackendFindGlusterPoolSources(const char *host,
                                        virStoragePoolType pooltype,
                                        virStoragePoolSourceListPtr list,
                                        bool report)
{
    int rc;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) glusterpath = NULL;
    VIR_AUTOFREE(char *) outbuf = NULL;

    if (!(glusterpath = virFindFileInPath("gluster"))) {
        if (report) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'gluster' command line tool not found"));
            return -1;
        } else {
            return 0;
        }
    }

    cmd = virCommandNewArgList(glusterpath,
                               "--xml",
                               "--log-file=/dev/null",
                               "volume", "info", "all", NULL);

    virCommandAddArgFormat(cmd, "--remote-host=%s", host);
    virCommandSetOutputBuffer(cmd, &outbuf);

    if (virCommandRun(cmd, &rc) < 0)
        return -1;

    if (rc != 0)
        return 0;

    return virStorageUtilGlusterExtractPoolSources(host, outbuf, list, pooltype);
}


#if WITH_BLKID

typedef enum {
    VIR_STORAGE_BLKID_PROBE_ERROR = -1,
    VIR_STORAGE_BLKID_PROBE_UNDEFINED, /* Nothing found */
    VIR_STORAGE_BLKID_PROBE_UNKNOWN,   /* Don't know libvirt fs/part type */
    VIR_STORAGE_BLKID_PROBE_MATCH,     /* Matches the on disk format */
    VIR_STORAGE_BLKID_PROBE_DIFFERENT, /* Format doesn't match on disk format */
} virStorageBackendBLKIDProbeResult;

/*
 * Utility function to probe for a file system on the device using the
 * blkid "superblock" (e.g. default) APIs.
 *
 * NB: In general this helper will handle the virStoragePoolFormatFileSystem
 *     format types; however, if called from the Disk path, the initial fstype
 *     check will fail forcing the usage of the ProbePart helper.
 *
 * Returns virStorageBackendBLKIDProbeResult enum
 */
static virStorageBackendBLKIDProbeResult
virStorageBackendBLKIDFindFS(blkid_probe probe,
                             const char *device,
                             const char *format)
{
    const char *fstype = NULL;

    /* Make sure we're doing a superblock probe from the start */
    blkid_probe_enable_superblocks(probe, true);
    blkid_probe_reset_superblocks_filter(probe);

    if (blkid_do_probe(probe) != 0) {
        VIR_INFO("No filesystem found on device '%s'", device);
        return VIR_STORAGE_BLKID_PROBE_UNDEFINED;
    }

    if (blkid_probe_lookup_value(probe, "TYPE", &fstype, NULL) == 0) {
        if (STREQ(fstype, format))
            return VIR_STORAGE_BLKID_PROBE_MATCH;

        return VIR_STORAGE_BLKID_PROBE_DIFFERENT;
    }

    if (blkid_known_fstype(format) == 0)
        return VIR_STORAGE_BLKID_PROBE_UNKNOWN;

    return VIR_STORAGE_BLKID_PROBE_ERROR;
}


/*
 * Utility function to probe for a partition on the device using the
 * blkid "partitions" APIs.
 *
 * NB: In general, this API will be validating the virStoragePoolFormatDisk
 *     format types.
 *
 * Returns virStorageBackendBLKIDProbeResult enum
 */
static virStorageBackendBLKIDProbeResult
virStorageBackendBLKIDFindPart(blkid_probe probe,
                               const char *device,
                               const char *format)
{
    const char *pttype = NULL;

    /* A blkid_known_pttype on "dvh" and "pc98" returns a failure;
     * however, the blkid_do_probe for "dvh" returns "sgi" and
     * for "pc98" it returns "dos". Although "bsd" is recognized,
     * it seems that the parted created partition table is not being
     * properly recogized. Since each of these will cause problems
     * with startup comparison, let's just treat them as UNKNOWN causing
     * the caller to fallback to using PARTED */
    if (STREQ(format, "dvh") || STREQ(format, "pc98") || STREQ(format, "bsd"))
        return VIR_STORAGE_BLKID_PROBE_UNKNOWN;

    /* Make sure we're doing a partitions probe from the start */
    blkid_probe_enable_partitions(probe, true);
    blkid_probe_reset_partitions_filter(probe);

    if (blkid_do_probe(probe) != 0) {
        VIR_INFO("No partition found on device '%s'", device);
        return VIR_STORAGE_BLKID_PROBE_UNDEFINED;
    }

    if (blkid_probe_lookup_value(probe, "PTTYPE", &pttype, NULL) == 0) {
        if (STREQ(pttype, format))
            return VIR_STORAGE_BLKID_PROBE_MATCH;

        return VIR_STORAGE_BLKID_PROBE_DIFFERENT;
    }

    if (blkid_known_pttype(format) == 0)
        return VIR_STORAGE_BLKID_PROBE_UNKNOWN;

    return VIR_STORAGE_BLKID_PROBE_ERROR;
}


/*
 * @device: Path to device
 * @format: Desired format
 * @writelabel: True if desire to write the label
 *
 * Use the blkid_ APIs in order to get details regarding whether a file
 * system or partition exists on the disk already.
 *
 * Returns:
 *   -2: Force usage of PARTED for unknown types
 *   -1: An error was encountered, with error message set
 *    0: No file system found
 */
static int
virStorageBackendBLKIDFindEmpty(const char *device,
                                const char *format,
                                bool writelabel)
{
    int ret = -1;
    int rc;
    blkid_probe probe = NULL;

    VIR_DEBUG("Probe for existing filesystem/partition format %s on device %s",
              format, device);

    if (!(probe = blkid_new_probe_from_filename(device))) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                       _("Failed to create filesystem probe for device %s"),
                       device);
        return -1;
    }

    /* Look for something on FS, if it either doesn't recognize the
     * format type as a valid FS format type or it doesn't find a valid
     * format type on the device, then perform the same check using
     * partition probing. */
    rc = virStorageBackendBLKIDFindFS(probe, device, format);
    if (rc == VIR_STORAGE_BLKID_PROBE_UNDEFINED ||
        rc == VIR_STORAGE_BLKID_PROBE_UNKNOWN) {

        rc = virStorageBackendBLKIDFindPart(probe, device, format);
    }

    switch (rc) {
    case VIR_STORAGE_BLKID_PROBE_UNDEFINED:
        if (writelabel)
            ret = 0;
        else
            virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                           _("Device '%s' is unrecognized, requires build"),
                           device);
        break;

    case VIR_STORAGE_BLKID_PROBE_ERROR:
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                       _("Failed to probe for format type '%s'"), format);
        break;

    case VIR_STORAGE_BLKID_PROBE_UNKNOWN:
        ret = -2;
        break;

    case VIR_STORAGE_BLKID_PROBE_MATCH:
        if (writelabel)
            virReportError(VIR_ERR_STORAGE_POOL_BUILT,
                           _("Device '%s' already formatted using '%s'"),
                           device, format);
        else
            ret = 0;
        break;

    case VIR_STORAGE_BLKID_PROBE_DIFFERENT:
        if (writelabel)
            virReportError(VIR_ERR_STORAGE_POOL_BUILT,
                           _("Format of device '%s' does not match the "
                             "expected format '%s', forced overwrite is "
                             "necessary"),
                           device, format);
        else
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Format of device '%s' does not match the "
                             "expected format '%s'"),
                           device, format);
        break;
    }

    if (ret == 0 && blkid_do_probe(probe) != 1) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED, "%s",
                       _("Found additional probes to run, probing may "
                         "be incorrect"));
        ret = -1;
    }

    blkid_free_probe(probe);

    return ret;
}

#else /* #if WITH_BLKID */

static int
virStorageBackendBLKIDFindEmpty(const char *device ATTRIBUTE_UNUSED,
                                const char *format ATTRIBUTE_UNUSED,
                                bool writelabel ATTRIBUTE_UNUSED)
{
    return -2;
}

#endif /* #if WITH_BLKID */


#if WITH_STORAGE_DISK

typedef enum {
    VIR_STORAGE_PARTED_ERROR = -1,
    VIR_STORAGE_PARTED_MATCH,       /* Valid label found and matches format */
    VIR_STORAGE_PARTED_DIFFERENT,   /* Valid label found but not match format */
    VIR_STORAGE_PARTED_UNKNOWN,     /* No or unrecognized label */
    VIR_STORAGE_PARTED_NOPTTYPE,    /* Did not find the Partition Table type */
    VIR_STORAGE_PARTED_PTTYPE_UNK,  /* Partition Table type unknown*/
} virStorageBackendPARTEDResult;

/**
 * Check for a valid disk label (partition table) on device using
 * the PARTED command
 *
 * returns virStorageBackendPARTEDResult
 */
static virStorageBackendPARTEDResult
virStorageBackendPARTEDFindLabel(const char *device,
                                 const char *format)
{
    const char *const args[] = {
        device, "print", "--script", NULL,
    };
    char *start, *end;
    int ret = VIR_STORAGE_PARTED_ERROR;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) output = NULL;
    VIR_AUTOFREE(char *) error = NULL;

    cmd = virCommandNew(PARTED);
    virCommandAddArgSet(cmd, args);
    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &output);
    virCommandSetErrorBuffer(cmd, &error);

    /* if parted succeeds we have a valid partition table */
    ret = virCommandRun(cmd, NULL);
    if (ret < 0) {
        if ((output && strstr(output, "unrecognised disk label")) ||
            (error && strstr(error, "unrecognised disk label"))) {
            ret = VIR_STORAGE_PARTED_UNKNOWN;
        }
        return ret;
    }

    /* Search for "Partition Table:" in the output. If not present,
     * then we cannot validate the partition table type.
     */
    if (!(start = strstr(output, "Partition Table: ")) ||
        !(end = strstr(start, "\n"))) {
        VIR_DEBUG("Unable to find tag in output: %s", output);
        return VIR_STORAGE_PARTED_NOPTTYPE;
    }
    start += strlen("Partition Table: ");
    *end = '\0';

    /* on disk it's "msdos", but we document/use "dos" so deal with it here */
    if (STREQ(start, "msdos"))
        start += 2;

    /* Make sure we know about this type */
    if (virStoragePoolFormatDiskTypeFromString(start) < 0)
        return VIR_STORAGE_PARTED_PTTYPE_UNK;

    /*  Does the on disk match what the pool desired? */
    if (STREQ(start, format))
        return VIR_STORAGE_PARTED_MATCH;

    return VIR_STORAGE_PARTED_DIFFERENT;
}


/**
 * Determine whether the label on the disk is valid or in a known format
 * for the purpose of rewriting the label during build or being able to
 * start a pool on a device.
 *
 * When 'writelabel' is true, if we find a valid disk label on the device,
 * then we shouldn't be attempting to write as the volume may contain
 * data. Force the usage of the overwrite flag to the build command in
 * order to be certain. When the disk label is unrecognized, then it
 * should be safe to write.
 *
 * When 'writelabel' is false, only if we find a valid disk label on the
 * device should we allow the start since for this path we won't be
 * rewriting the label.
 *
 * Return: 0 if it's OK
 *         -1 if something's wrong
 */
static int
virStorageBackendPARTEDValidLabel(const char *device,
                                  const char *format,
                                  bool writelabel)
{
    int ret = -1;
    virStorageBackendPARTEDResult check;

    check = virStorageBackendPARTEDFindLabel(device, format);
    switch (check) {
    case VIR_STORAGE_PARTED_ERROR:
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Error checking for disk label, failed to get "
                         "disk partition information"));
        break;

    case VIR_STORAGE_PARTED_MATCH:
        if (writelabel)
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Disk label already formatted using '%s'"),
                           format);
        else
            ret = 0;
        break;

    case VIR_STORAGE_PARTED_DIFFERENT:
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Known, but different label format present, "
                         "requires build --overwrite"));
        break;

    case VIR_STORAGE_PARTED_UNKNOWN:
        if (writelabel)
            ret = 0;
        else
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Unrecognized disk label found, requires build"));
        break;

    case VIR_STORAGE_PARTED_NOPTTYPE:
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Unable to determine Partition Type, "
                         "requires build --overwrite"));
        break;

    case VIR_STORAGE_PARTED_PTTYPE_UNK:
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Unknown Partition Type, requires build --overwrite"));
        break;
    }

    return ret;
}

#else

static int
virStorageBackendPARTEDValidLabel(const char *device ATTRIBUTE_UNUSED,
                                  const char *format ATTRIBUTE_UNUSED,
                                  bool writelabel ATTRIBUTE_UNUSED)
{
    return -2;
}


#endif /* #if WITH_STORAGE_DISK */


/* virStorageBackendDeviceIsEmpty:
 * @devpath: Path to the device to check
 * @format: Desired format string
 * @writelabel: True if the caller expects to write the label
 *
 * Check if the @devpath has some sort of known file system using the
 * BLKID API if available.
 *
 * Returns true if the probe deems the device has nothing valid on it
 * or when we cannot check and we're not writing the label.
 *
 * Returns false if the probe finds something
 */
bool
virStorageBackendDeviceIsEmpty(const char *devpath,
                               const char *format,
                               bool writelabel)
{
    int ret;

    if ((ret = virStorageBackendBLKIDFindEmpty(devpath, format,
                                               writelabel)) == -2)
        ret = virStorageBackendPARTEDValidLabel(devpath, format, writelabel);

    if (ret == -2 && !writelabel)
        ret = 0;

    if (ret == -2) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Unable to probe '%s' for existing data, "
                         "forced overwrite is necessary"),
                       devpath);
    }

    return ret == 0;
}


static int
storageBackendProbeTarget(virStorageSourcePtr target,
                          virStorageEncryptionPtr *encryption)
{
    int backingStoreFormat;
    int rc;
    struct stat sb;
    VIR_AUTOUNREF(virStorageSourcePtr) meta = NULL;
    VIR_AUTOCLOSE fd = -1;

    if (encryption)
        *encryption = NULL;

    if ((rc = virStorageBackendVolOpen(target->path, &sb,
                                       VIR_STORAGE_VOL_FS_PROBE_FLAGS)) < 0)
        return rc; /* Take care to propagate rc, it is not always -1 */
    fd = rc;

    if (virStorageBackendUpdateVolTargetInfoFD(target, fd, &sb) < 0)
        return -1;

    if (S_ISDIR(sb.st_mode)) {
        if (storageBackendIsPloopDir(target->path)) {
            if (storageBackendRedoPloopUpdate(target, &sb, &fd,
                                              VIR_STORAGE_VOL_FS_PROBE_FLAGS) < 0)
                return -1;
        } else {
            target->format = VIR_STORAGE_FILE_DIR;
            return 0;
        }
    }

    if (!(meta = virStorageFileGetMetadataFromFD(target->path,
                                                 fd,
                                                 VIR_STORAGE_FILE_AUTO,
                                                 &backingStoreFormat)))
        return -1;

    if (meta->backingStoreRaw) {
        if (!(target->backingStore = virStorageSourceNewFromBacking(meta)))
            return -1;

        target->backingStore->format = backingStoreFormat;

        /* XXX: Remote storage doesn't play nicely with volumes backed by
         * remote storage. To avoid trouble, just fake the backing store is RAW
         * and put the string from the metadata as the path of the target. */
        if (!virStorageSourceIsLocalStorage(target->backingStore)) {
            virObjectUnref(target->backingStore);

            if (!(target->backingStore = virStorageSourceNew()))
                return -1;

            target->backingStore->type = VIR_STORAGE_TYPE_NETWORK;
            target->backingStore->path = meta->backingStoreRaw;
            meta->backingStoreRaw = NULL;
            target->backingStore->format = VIR_STORAGE_FILE_RAW;
        }

        if (target->backingStore->format == VIR_STORAGE_FILE_AUTO) {
            if ((rc = virStorageFileProbeFormat(target->backingStore->path,
                                                -1, -1)) < 0) {
                /* If the backing file is currently unavailable or is
                 * accessed via remote protocol only log an error, fake the
                 * format as RAW and continue. Returning -1 here would
                 * disable the whole storage pool, making it unavailable for
                 * even maintenance. */
                target->backingStore->format = VIR_STORAGE_FILE_RAW;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot probe backing volume format: %s"),
                               target->backingStore->path);
            } else {
                target->backingStore->format = rc;
            }
        }
    }

    target->format = meta->format;

    /* Default to success below this point */
    if (meta->capacity)
        target->capacity = meta->capacity;

    if (encryption && meta->encryption) {
        if (meta->encryption->payload_offset != -1)
            target->capacity -= meta->encryption->payload_offset * 512;

        *encryption = meta->encryption;
        meta->encryption = NULL;

        /* XXX ideally we'd fill in secret UUID here
         * but we cannot guarantee 'conn' is non-NULL
         * at this point in time :-(  So we only fill
         * in secrets when someone first queries a vol
         */
    }

    virBitmapFree(target->features);
    VIR_STEAL_PTR(target->features, meta->features);

    if (meta->compat) {
        VIR_FREE(target->compat);
        VIR_STEAL_PTR(target->compat, meta->compat);
    }

    return 0;
}


/**
 * virStorageBackendRefreshVolTargetUpdate:
 * @vol: Volume def that needs updating
 *
 * Attempt to probe the volume in order to get more details.
 *
 * Returns 0 on success, -2 to ignore failure, -1 on failure
 */
int
virStorageBackendRefreshVolTargetUpdate(virStorageVolDefPtr vol)
{
    int err;

    /* Real value is filled in during probe */
    vol->target.format = VIR_STORAGE_FILE_RAW;

    if ((err = storageBackendProbeTarget(&vol->target,
                                         &vol->target.encryption)) < 0) {
        if (err == -2) {
            return -2;
        } else if (err == -3) {
            /* The backing file is currently unavailable, its format is not
             * explicitly specified, the probe to auto detect the format
             * failed: continue with faked RAW format, since AUTO will
             * break virStorageVolTargetDefFormat() generating the line
             * <format type='...'/>. */
        } else {
            return -1;
        }
    }

    /* directory based volume */
    if (vol->target.format == VIR_STORAGE_FILE_DIR)
        vol->type = VIR_STORAGE_VOL_DIR;

    if (vol->target.format == VIR_STORAGE_FILE_PLOOP)
        vol->type = VIR_STORAGE_VOL_PLOOP;

    if (virStorageSourceHasBacking(&vol->target)) {
        ignore_value(storageBackendUpdateVolTargetInfo(VIR_STORAGE_VOL_FILE,
                                                       vol->target.backingStore,
                                                       false,
                                                       VIR_STORAGE_VOL_OPEN_DEFAULT, 0));
        /* If this failed, the backing file is currently unavailable,
         * the capacity, allocation, owner, group and mode are unknown.
         * An error message was raised, but we just continue. */
    }

    return 0;
}


/**
 * Iterate over the pool's directory and enumerate all disk images
 * within it. This is non-recursive.
 */
int
virStorageBackendRefreshLocal(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    DIR *dir;
    struct dirent *ent;
    struct statvfs sb;
    struct stat statbuf;
    int direrr;
    int ret = -1;
    VIR_AUTOPTR(virStorageVolDef) vol = NULL;
    VIR_AUTOCLOSE fd = -1;
    VIR_AUTOUNREF(virStorageSourcePtr) target = NULL;

    if (virDirOpen(&dir, def->target.path) < 0)
        goto cleanup;

    while ((direrr = virDirRead(dir, &ent, def->target.path)) > 0) {
        int err;

        if (virStringHasControlChars(ent->d_name)) {
            VIR_WARN("Ignoring file '%s' with control characters under '%s'",
                     ent->d_name, def->target.path);
            continue;
        }

        if (VIR_ALLOC(vol) < 0)
            goto cleanup;

        if (VIR_STRDUP(vol->name, ent->d_name) < 0)
            goto cleanup;

        vol->type = VIR_STORAGE_VOL_FILE;
        if (virAsprintf(&vol->target.path, "%s/%s",
                        def->target.path, vol->name) < 0)
            goto cleanup;

        if (VIR_STRDUP(vol->key, vol->target.path) < 0)
            goto cleanup;

        if ((err = virStorageBackendRefreshVolTargetUpdate(vol)) < 0) {
            if (err == -2) {
                /* Silently ignore non-regular files,
                 * eg 'lost+found', dangling symbolic link */
                virStorageVolDefFree(vol);
                vol = NULL;
                continue;
            }
            goto cleanup;
        }

        if (virStoragePoolObjAddVol(pool, vol) < 0)
            goto cleanup;
        vol = NULL;
    }
    if (direrr < 0)
        goto cleanup;
    VIR_DIR_CLOSE(dir);

    if (!(target = virStorageSourceNew()))
        goto cleanup;

    if ((fd = open(def->target.path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             def->target.path);
        goto cleanup;
    }

    if (fstat(fd, &statbuf) < 0) {
        virReportSystemError(errno,
                             _("cannot stat path '%s'"),
                             def->target.path);
        goto cleanup;
    }

    if (virStorageBackendUpdateVolTargetInfoFD(target, fd, &statbuf) < 0)
        goto cleanup;

    /* VolTargetInfoFD doesn't update capacity correctly for the pool case */
    if (statvfs(def->target.path, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot statvfs path '%s'"),
                             def->target.path);
        goto cleanup;
    }

    def->capacity = ((unsigned long long)sb.f_frsize *
                     (unsigned long long)sb.f_blocks);
    def->available = ((unsigned long long)sb.f_bfree *
                      (unsigned long long)sb.f_frsize);
    def->allocation = def->capacity - def->available;

    def->target.perms.mode = target->perms->mode;
    def->target.perms.uid = target->perms->uid;
    def->target.perms.gid = target->perms->gid;
    VIR_FREE(def->target.perms.label);
    if (VIR_STRDUP(def->target.perms.label, target->perms->label) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dir);
    return ret;
}


static char *
virStorageBackendSCSISerial(const char *dev,
                            bool isNPIV)
{
    int rc;
    char *serial = NULL;

    if (isNPIV)
        rc = virStorageFileGetNPIVKey(dev, &serial);
    else
        rc = virStorageFileGetSCSIKey(dev, &serial, true);
    if (rc == 0 && serial)
        return serial;

    if (rc == -2)
        return NULL;

    ignore_value(VIR_STRDUP(serial, dev));
    return serial;
}


/*
 * Attempt to create a new LUN
 *
 * Returns:
 *
 *  0  => Success
 *  -1 => Failure due to some sort of OOM or other fatal issue found when
 *        attempting to get/update information about a found volume
 *  -2 => Failure to find a stable path, not fatal, caller can try another
 */
static int
virStorageBackendSCSINewLun(virStoragePoolObjPtr pool,
                            uint32_t host ATTRIBUTE_UNUSED,
                            uint32_t bus,
                            uint32_t target,
                            uint32_t lun,
                            const char *dev)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int retval = -1;
    VIR_AUTOPTR(virStorageVolDef) vol = NULL;
    VIR_AUTOFREE(char *) devpath = NULL;

    /* Check if the pool is using a stable target path. The call to
     * virStorageBackendStablePath will fail if the pool target path
     * isn't stable and just return the strdup'd 'devpath' anyway.
     * This would be indistinguishable to failing to find the stable
     * path to the device if the virDirRead loop to search the
     * target pool path for our devpath had failed.
     */
    if (!virStorageBackendPoolPathIsStable(def->target.path) &&
        !(STREQ(def->target.path, "/dev") ||
          STREQ(def->target.path, "/dev/"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unable to use target path '%s' for dev '%s'"),
                       NULLSTR(def->target.path), dev);
        return -1;
    }

    if (VIR_ALLOC(vol) < 0)
        return -1;

    vol->type = VIR_STORAGE_VOL_BLOCK;

    /* 'host' is dynamically allocated by the kernel, first come,
     * first served, per HBA. As such it isn't suitable for use
     * in the volume name. We only need uniqueness per-pool, so
     * just leave 'host' out
     */
    if (virAsprintf(&(vol->name), "unit:%u:%u:%u", bus, target, lun) < 0)
        return -1;

    if (virAsprintf(&devpath, "/dev/%s", dev) < 0)
        return -1;

    VIR_DEBUG("Trying to create volume for '%s'", devpath);

    /* Now figure out the stable path
     *
     * XXX this method is O(N) because it scans the pool target
     * dir every time its run. Should figure out a more efficient
     * way of doing this...
     */
    if ((vol->target.path = virStorageBackendStablePath(pool,
                                                        devpath,
                                                        true)) == NULL)
        return -1;

    if (STREQ(devpath, vol->target.path) &&
        !(STREQ(def->target.path, "/dev") ||
          STREQ(def->target.path, "/dev/"))) {

        VIR_DEBUG("No stable path found for '%s' in '%s'",
                  devpath, def->target.path);

        return -2;
    }

    /* Allow a volume read failure to ignore or skip this block file */
    if ((retval = virStorageBackendUpdateVolInfo(vol, true,
                                                 VIR_STORAGE_VOL_OPEN_DEFAULT,
                                                 VIR_STORAGE_VOL_READ_NOERROR)) < 0)
        return retval;

    vol->key = virStorageBackendSCSISerial(vol->target.path,
                                           (def->source.adapter.type ==
                                            VIR_STORAGE_ADAPTER_TYPE_FC_HOST));
    if (!vol->key)
        return -1;

    def->capacity += vol->target.capacity;
    def->allocation += vol->target.allocation;

    if (virStoragePoolObjAddVol(pool, vol) < 0)
        return -1;
    vol = NULL;

    return 0;
}



static int
getNewStyleBlockDevice(const char *lun_path,
                       const char *block_name ATTRIBUTE_UNUSED,
                       char **block_device)
{
    DIR *block_dir = NULL;
    struct dirent *block_dirent = NULL;
    int retval = -1;
    int direrr;
    VIR_AUTOFREE(char *) block_path = NULL;

    if (virAsprintf(&block_path, "%s/block", lun_path) < 0)
        goto cleanup;

    VIR_DEBUG("Looking for block device in '%s'", block_path);

    if (virDirOpen(&block_dir, block_path) < 0)
        goto cleanup;

    while ((direrr = virDirRead(block_dir, &block_dirent, block_path)) > 0) {
        if (VIR_STRDUP(*block_device, block_dirent->d_name) < 0)
            goto cleanup;

        VIR_DEBUG("Block device is '%s'", *block_device);

        break;
    }

    if (direrr < 0)
        goto cleanup;

    retval = 0;

 cleanup:
    VIR_DIR_CLOSE(block_dir);
    return retval;
}


static int
getOldStyleBlockDevice(const char *lun_path ATTRIBUTE_UNUSED,
                       const char *block_name,
                       char **block_device)
{
    char *blockp = NULL;
    int retval = -1;

    /* old-style; just parse out the sd */
    if (!(blockp = strrchr(block_name, ':'))) {
        /* Hm, wasn't what we were expecting; have to give up */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse block name %s"),
                       block_name);
        goto cleanup;
    } else {
        blockp++;
        if (VIR_STRDUP(*block_device, blockp) < 0)
            goto cleanup;

        VIR_DEBUG("Block device is '%s'", *block_device);
    }

    retval = 0;
 cleanup:
    return retval;
}


/*
 * Search a device entry for the "block" file
 *
 * Returns
 *
 *   0 => Found it
 *   -1 => Fatal error
 *   -2 => Didn't find in lun_path directory
 */
static int
getBlockDevice(uint32_t host,
               uint32_t bus,
               uint32_t target,
               uint32_t lun,
               char **block_device)
{
    DIR *lun_dir = NULL;
    struct dirent *lun_dirent = NULL;
    int retval = -1;
    int direrr;
    VIR_AUTOFREE(char *) lun_path = NULL;

    *block_device = NULL;

    if (virAsprintf(&lun_path, "/sys/bus/scsi/devices/%u:%u:%u:%u",
                    host, bus, target, lun) < 0)
        goto cleanup;

    if (virDirOpen(&lun_dir, lun_path) < 0)
        goto cleanup;

    while ((direrr = virDirRead(lun_dir, &lun_dirent, lun_path)) > 0) {
        if (STRPREFIX(lun_dirent->d_name, "block")) {
            if (strlen(lun_dirent->d_name) == 5) {
                if (getNewStyleBlockDevice(lun_path,
                                           lun_dirent->d_name,
                                           block_device) < 0)
                    goto cleanup;
            } else {
                if (getOldStyleBlockDevice(lun_path,
                                           lun_dirent->d_name,
                                           block_device) < 0)
                    goto cleanup;
            }
            break;
        }
    }
    if (direrr < 0)
        goto cleanup;
    if (!*block_device) {
        retval = -2;
        goto cleanup;
    }

    retval = 0;

 cleanup:
    VIR_DIR_CLOSE(lun_dir);
    return retval;
}


/* Function to check if the type file in the given sysfs_path is a
 * Direct-Access device (i.e. type 0).  Return -1 on failure, type of
 * the device otherwise.
 */
static int
getDeviceType(uint32_t host,
              uint32_t bus,
              uint32_t target,
              uint32_t lun,
              int *type)
{
    char typestr[3];
    char *gottype, *p;
    FILE *typefile;
    VIR_AUTOFREE(char *) type_path = NULL;

    if (virAsprintf(&type_path, "/sys/bus/scsi/devices/%u:%u:%u:%u/type",
                    host, bus, target, lun) < 0)
        return -1;

    typefile = fopen(type_path, "r");
    if (typefile == NULL) {
        virReportSystemError(errno,
                             _("Could not find typefile '%s'"),
                             type_path);
        /* there was no type file; that doesn't seem right */
        return -1;
    }

    gottype = fgets(typestr, 3, typefile);
    VIR_FORCE_FCLOSE(typefile);

    if (gottype == NULL) {
        virReportSystemError(errno,
                             _("Could not read typefile '%s'"),
                             type_path);
        /* we couldn't read the type file; have to give up */
        return -1;
    }

    /* we don't actually care about p, but if you pass NULL and the last
     * character is not \0, virStrToLong_i complains
     */
    if (virStrToLong_i(typestr, &p, 10, type) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device type '%s' is not an integer"),
                       typestr);
        /* Hm, type wasn't an integer; seems strange */
        return -1;
    }

    VIR_DEBUG("Device type is %d", *type);

    return 0;
}


/*
 * Process a Logical Unit entry from the scsi host device directory
 *
 * Returns:
 *
 *  0  => Found a valid entry
 *  -1 => Some sort of fatal error
 *  -2 => non-fatal error or a non-disk entry
 */
static int
processLU(virStoragePoolObjPtr pool,
          uint32_t host,
          uint32_t bus,
          uint32_t target,
          uint32_t lun)
{
    int retval = -1;
    int device_type;
    VIR_AUTOFREE(char *) block_device = NULL;

    VIR_DEBUG("Processing LU %u:%u:%u:%u",
              host, bus, target, lun);

    if (getDeviceType(host, bus, target, lun, &device_type) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to determine if %u:%u:%u:%u is a Direct-Access LUN"),
                       host, bus, target, lun);
        return -1;
    }

    /* We don't create volumes for devices other than disk and cdrom
     * devices, but finding a device that isn't one of those types
     * isn't an error, either. */
    if (!(device_type == VIR_STORAGE_DEVICE_TYPE_DISK ||
          device_type == VIR_STORAGE_DEVICE_TYPE_ROM))
        return -2;

    VIR_DEBUG("%u:%u:%u:%u is a Direct-Access LUN",
              host, bus, target, lun);

    if ((retval = getBlockDevice(host, bus, target, lun, &block_device)) < 0) {
        VIR_DEBUG("Failed to find block device for this LUN");
        return retval;
    }

    retval = virStorageBackendSCSINewLun(pool, host, bus, target, lun,
                                         block_device);
    if (retval < 0) {
        VIR_DEBUG("Failed to create new storage volume for %u:%u:%u:%u",
                  host, bus, target, lun);
        return retval;
    }

    VIR_DEBUG("Created new storage volume for %u:%u:%u:%u successfully",
              host, bus, target, lun);

    return retval;
}


int
virStorageBackendSCSIFindLUs(virStoragePoolObjPtr pool,
                              uint32_t scanhost)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int retval = 0;
    uint32_t bus, target, lun;
    const char *device_path = "/sys/bus/scsi/devices";
    DIR *devicedir = NULL;
    struct dirent *lun_dirent = NULL;
    char devicepattern[64];
    int found = 0;

    VIR_DEBUG("Discovering LUs on host %u", scanhost);

    virWaitForDevices();

    if (virDirOpen(&devicedir, device_path) < 0)
        return -1;

    snprintf(devicepattern, sizeof(devicepattern), "%u:%%u:%%u:%%u\n", scanhost);

    while ((retval = virDirRead(devicedir, &lun_dirent, device_path)) > 0) {
        int rc;

        if (sscanf(lun_dirent->d_name, devicepattern,
                   &bus, &target, &lun) != 3) {
            continue;
        }

        VIR_DEBUG("Found possible LU '%s'", lun_dirent->d_name);

        rc = processLU(pool, scanhost, bus, target, lun);
        if (rc == -1) {
            retval = -1;
            break;
        }
        if (rc == 0)
            found++;
    }

    VIR_DIR_CLOSE(devicedir);

    if (retval < 0)
        return -1;

    VIR_DEBUG("Found %d LUs for pool %s", found, def->name);

    return found;
}


/*
 * @path: Path to the device to initialize
 * @size: Size to be cleared
 *
 * Zero out possible partition table information for the specified
 * bytes from the start of the @path and from the end of @path
 *
 * Returns 0 on success, -1 on failure with error message set
 */
int
virStorageBackendZeroPartitionTable(const char *path,
                                    unsigned long long size)
{
    if (storageBackendVolWipeLocalFile(path, VIR_STORAGE_VOL_WIPE_ALG_ZERO,
                                       size, false) < 0)
        return -1;

    return storageBackendVolWipeLocalFile(path, VIR_STORAGE_VOL_WIPE_ALG_ZERO,
                                          size, true);
}


/**
 * virStorageBackendFileSystemGetPoolSource
 * @pool: storage pool object pointer
 *
 * Allocate/return a string representing the FS storage pool source.
 * It is up to the caller to VIR_FREE the allocated string
 */
char *
virStorageBackendFileSystemGetPoolSource(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *src = NULL;

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        if (def->source.format == VIR_STORAGE_POOL_NETFS_CIFS) {
            if (virAsprintf(&src, "//%s/%s",
                            def->source.hosts[0].name,
                            def->source.dir) < 0)
                return NULL;
        } else {
            if (virAsprintf(&src, "%s:%s",
                            def->source.hosts[0].name,
                            def->source.dir) < 0)
                return NULL;
        }
    } else {
        if (VIR_STRDUP(src, def->source.devices[0].path) < 0)
            return NULL;
    }
    return src;
}


static void
virStorageBackendFileSystemMountAddOptions(virCommandPtr cmd,
                                           virStoragePoolDefPtr def,
                                           const char *providedOpts)
{
    VIR_AUTOFREE(char *) mountOpts = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (*default_mount_opts != '\0')
        virBufferAsprintf(&buf, "%s,", default_mount_opts);

    if (providedOpts)
        virBufferAsprintf(&buf, "%s,", providedOpts);

    if (def->namespaceData) {
        size_t i;
        virStoragePoolFSMountOptionsDefPtr opts = def->namespaceData;
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        for (i = 0; i < opts->noptions; i++)
            virBufferAsprintf(&buf, "%s,", opts->options[i]);

        virUUIDFormat(def->uuid, uuidstr);
        VIR_WARN("Storage Pool name='%s' uuid='%s' is tainted by custom "
                 "mount_opts from XML", def->name, uuidstr);
    }

    virBufferTrim(&buf, ",", -1);
    mountOpts = virBufferContentAndReset(&buf);

    if (mountOpts)
        virCommandAddArgList(cmd, "-o", mountOpts, NULL);
}


static void
virStorageBackendFileSystemMountNFSArgs(virCommandPtr cmd,
                                        const char *src,
                                        virStoragePoolDefPtr def,
                                        const char *nfsVers)
{
    virCommandAddArgList(cmd, src, def->target.path, NULL);
    virStorageBackendFileSystemMountAddOptions(cmd, def, nfsVers);
}


static void
virStorageBackendFileSystemMountGlusterArgs(virCommandPtr cmd,
                                            const char *src,
                                            virStoragePoolDefPtr def)
{
    const char *fmt;

    fmt = virStoragePoolFormatFileSystemNetTypeToString(def->source.format);
    virCommandAddArgList(cmd, "-t", fmt, src, def->target.path, NULL);
    virStorageBackendFileSystemMountAddOptions(cmd, def, "direct-io-mode=1");
}


static void
virStorageBackendFileSystemMountCIFSArgs(virCommandPtr cmd,
                                         const char *src,
                                         virStoragePoolDefPtr def)
{
    const char *fmt;

    fmt = virStoragePoolFormatFileSystemNetTypeToString(def->source.format);
    virCommandAddArgList(cmd, "-t", fmt, src, def->target.path, NULL);
    virStorageBackendFileSystemMountAddOptions(cmd, def, "guest");
}


static void
virStorageBackendFileSystemMountDefaultArgs(virCommandPtr cmd,
                                            const char *src,
                                            virStoragePoolDefPtr def,
                                            const char *nfsVers)
{
    const char *fmt;

    if (def->type == VIR_STORAGE_POOL_FS)
        fmt = virStoragePoolFormatFileSystemTypeToString(def->source.format);
    else
        fmt = virStoragePoolFormatFileSystemNetTypeToString(def->source.format);
    virCommandAddArgList(cmd, "-t", fmt, src, def->target.path, NULL);
    virStorageBackendFileSystemMountAddOptions(cmd, def, nfsVers);
}


virCommandPtr
virStorageBackendFileSystemMountCmd(const char *cmdstr,
                                    virStoragePoolDefPtr def,
                                    const char *src)
{
    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    bool netauto = (def->type == VIR_STORAGE_POOL_NETFS &&
                    def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    bool glusterfs = (def->type == VIR_STORAGE_POOL_NETFS &&
                      def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS);
    bool cifsfs = (def->type == VIR_STORAGE_POOL_NETFS &&
                   def->source.format == VIR_STORAGE_POOL_NETFS_CIFS);
    virCommandPtr cmd = NULL;
    VIR_AUTOFREE(char *) nfsVers = NULL;

    if (def->type == VIR_STORAGE_POOL_NETFS && def->source.protocolVer > 0 &&
        virAsprintf(&nfsVers, "nfsvers=%u", def->source.protocolVer) < 0)
        return NULL;

    cmd = virCommandNew(cmdstr);
    if (netauto)
        virStorageBackendFileSystemMountNFSArgs(cmd, src, def, nfsVers);
    else if (glusterfs)
        virStorageBackendFileSystemMountGlusterArgs(cmd, src, def);
    else if (cifsfs)
        virStorageBackendFileSystemMountCIFSArgs(cmd, src, def);
    else
        virStorageBackendFileSystemMountDefaultArgs(cmd, src, def, nfsVers);
    return cmd;
}


virCommandPtr
virStorageBackendLogicalChangeCmd(const char *cmdstr,
                                  virStoragePoolDefPtr def,
                                  bool on)
{
    return virCommandNewArgList(cmdstr,
                                on ? "-aly" : "-aln",
                                def->source.name,
                                NULL);
}
