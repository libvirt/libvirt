/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2016 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include "dirname.h"
#ifdef __linux__
# include <sys/ioctl.h>
# include <linux/fs.h>
# ifndef FS_NOCOW_FL
#  define FS_NOCOW_FL                     0x00800000 /* Do not cow file */
# endif
#endif

#if WITH_BLKID
# include <blkid/blkid.h>
#endif

#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#if HAVE_LINUX_BTRFS_H
# include <linux/btrfs.h>
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
#include "storage_backend.h"
#include "virlog.h"
#include "virfile.h"
#include "virjson.h"
#include "virqemu.h"
#include "stat-time.h"
#include "virstring.h"
#include "virxml.h"
#include "fdstream.h"

#if WITH_STORAGE_LVM
# include "storage_backend_logical.h"
#endif
#if WITH_STORAGE_ISCSI
# include "storage_backend_iscsi.h"
#endif
#if WITH_STORAGE_SCSI
# include "storage_backend_scsi.h"
#endif
#if WITH_STORAGE_MPATH
# include "storage_backend_mpath.h"
#endif
#if WITH_STORAGE_DISK
# include "storage_backend_disk.h"
#endif
#if WITH_STORAGE_DIR
# include "storage_backend_fs.h"
#endif
#if WITH_STORAGE_RBD
# include "storage_backend_rbd.h"
#endif
#if WITH_STORAGE_SHEEPDOG
# include "storage_backend_sheepdog.h"
#endif
#if WITH_STORAGE_GLUSTER
# include "storage_backend_gluster.h"
#endif
#if WITH_STORAGE_ZFS
# include "storage_backend_zfs.h"
#endif

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend");

static virStorageBackendPtr backends[] = {
#if WITH_STORAGE_DIR
    &virStorageBackendDirectory,
#endif
#if WITH_STORAGE_FS
    &virStorageBackendFileSystem,
    &virStorageBackendNetFileSystem,
#endif
#if WITH_STORAGE_LVM
    &virStorageBackendLogical,
#endif
#if WITH_STORAGE_ISCSI
    &virStorageBackendISCSI,
#endif
#if WITH_STORAGE_SCSI
    &virStorageBackendSCSI,
#endif
#if WITH_STORAGE_MPATH
    &virStorageBackendMpath,
#endif
#if WITH_STORAGE_DISK
    &virStorageBackendDisk,
#endif
#if WITH_STORAGE_RBD
    &virStorageBackendRBD,
#endif
#if WITH_STORAGE_SHEEPDOG
    &virStorageBackendSheepdog,
#endif
#if WITH_STORAGE_GLUSTER
    &virStorageBackendGluster,
#endif
#if WITH_STORAGE_ZFS
    &virStorageBackendZFS,
#endif
    NULL
};


static virStorageFileBackendPtr fileBackends[] = {
#if WITH_STORAGE_FS
    &virStorageFileBackendFile,
    &virStorageFileBackendBlock,
#endif
#if WITH_STORAGE_GLUSTER
    &virStorageFileBackendGluster,
#endif
    NULL
};


#define READ_BLOCK_SIZE_DEFAULT  (1024 * 1024)
#define WRITE_BLOCK_SIZE_DEFAULT (4 * 1024)

/*
 * Perform the O(1) btrfs clone operation, if possible.
 * Upon success, return 0.  Otherwise, return -1 and set errno.
 */
#if HAVE_LINUX_BTRFS_H
static inline int
btrfsCloneFile(int dest_fd, int src_fd)
{
    return ioctl(dest_fd, BTRFS_IOC_CLONE, src_fd);
}
#else
static inline int
btrfsCloneFile(int dest_fd ATTRIBUTE_UNUSED,
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
    int inputfd = -1;
    int amtread = -1;
    int ret = 0;
    size_t rbytes = READ_BLOCK_SIZE_DEFAULT;
    int wbytes = 0;
    int interval;
    char *zerobuf = NULL;
    char *buf = NULL;
    struct stat st;

    if ((inputfd = open(inputvol->target.path, O_RDONLY)) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("could not open input path '%s'"),
                             inputvol->target.path);
        goto cleanup;
    }

#ifdef __linux__
    if (ioctl(fd, BLKBSZGET, &wbytes) < 0)
        wbytes = 0;
#endif
    if ((wbytes == 0) && fstat(fd, &st) == 0)
        wbytes = st.st_blksize;
    if (wbytes < WRITE_BLOCK_SIZE_DEFAULT)
        wbytes = WRITE_BLOCK_SIZE_DEFAULT;

    if (VIR_ALLOC_N(zerobuf, wbytes) < 0) {
        ret = -errno;
        goto cleanup;
    }

    if (VIR_ALLOC_N(buf, rbytes) < 0) {
        ret = -errno;
        goto cleanup;
    }

    if (reflink_copy) {
        if (btrfsCloneFile(fd, inputfd) < 0) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("failed to clone files from '%s'"),
                                 inputvol->target.path);
            goto cleanup;
        } else {
            VIR_DEBUG("btrfs clone finished.");
            goto cleanup;
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
            goto cleanup;
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
                    goto cleanup;
                }
            } else if (safewrite(fd, buf+offset, interval) < 0) {
                ret = -errno;
                virReportSystemError(errno,
                                     _("failed writing to file '%s'"),
                                     vol->target.path);
                goto cleanup;

            }
        } while ((amtleft -= interval) > 0);
    }

    if (fdatasync(fd) < 0) {
        ret = -errno;
        virReportSystemError(errno, _("cannot sync data to file '%s'"),
                             vol->target.path);
        goto cleanup;
    }


    if (VIR_CLOSE(inputfd) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             inputvol->target.path);
        goto cleanup;
    }
    inputfd = -1;

 cleanup:
    VIR_FORCE_CLOSE(inputfd);

    VIR_FREE(zerobuf);
    VIR_FREE(buf);

    return ret;
}

static int
virStorageBackendCreateBlockFrom(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 virStorageVolDefPtr vol,
                                 virStorageVolDefPtr inputvol,
                                 unsigned int flags)
{
    int fd = -1;
    int ret = -1;
    unsigned long long remain;
    struct stat st;
    gid_t gid;
    uid_t uid;
    mode_t mode;
    bool reflink_copy = false;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for block "
                         "volumes"));
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_CREATE_REFLINK)
        reflink_copy = true;

    if ((fd = open(vol->target.path, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    remain = vol->target.capacity;

    if (inputvol) {
        if (virStorageBackendCopyToFD(vol, inputvol, fd, &remain,
                                      false, reflink_copy) < 0)
            goto cleanup;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno, _("stat of '%s' failed"),
                             vol->target.path);
        goto cleanup;
    }
    uid = (vol->target.perms->uid != st.st_uid) ? vol->target.perms->uid
        : (uid_t) -1;
    gid = (vol->target.perms->gid != st.st_gid) ? vol->target.perms->gid
        : (gid_t) -1;
    if (((uid != (uid_t) -1) || (gid != (gid_t) -1))
        && (fchown(fd, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown '%s' to (%u, %u)"),
                             vol->target.path, (unsigned int) uid,
                             (unsigned int) gid);
        goto cleanup;
    }

    mode = (vol->target.perms->mode == (mode_t) -1 ?
            VIR_STORAGE_DEFAULT_VOL_PERM_MODE : vol->target.perms->mode);
    if (fchmod(fd, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, mode);
        goto cleanup;
    }
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        goto cleanup;
    }
    fd = -1;

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);

    return ret;
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

int
virStorageBackendCreateRaw(virConnectPtr conn ATTRIBUTE_UNUSED,
                           virStoragePoolObjPtr pool,
                           virStorageVolDefPtr vol,
                           virStorageVolDefPtr inputvol,
                           unsigned int flags)
{
    int ret = -1;
    int fd = -1;
    int operation_flags;
    bool reflink_copy = false;
    mode_t open_mode = VIR_STORAGE_DEFAULT_VOL_PERM_MODE;
    bool created = false;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for raw "
                         "volumes"));
        goto cleanup;
    }

    if (vol->target.backingStore) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("backing storage not supported for raw volumes"));
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_CREATE_REFLINK)
        reflink_copy = true;


    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool does not support encrypted volumes"));
        goto cleanup;
    }

    operation_flags = VIR_FILE_OPEN_FORCE_MODE | VIR_FILE_OPEN_FORCE_OWNER;
    if (pool->def->type == VIR_STORAGE_POOL_NETFS)
        operation_flags |= VIR_FILE_OPEN_FORK;

    if (vol->target.perms->mode != (mode_t) -1)
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
    VIR_FORCE_CLOSE(fd);
    return ret;
}

static int
virStorageGenerateSecretUUID(virConnectPtr conn,
                             unsigned char *uuid)
{
    unsigned attempt;

    for (attempt = 0; attempt < 65536; attempt++) {
        virSecretPtr tmp;
        if (virUUIDGenerate(uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to generate uuid"));
            return -1;
        }
        tmp = conn->secretDriver->secretLookupByUUID(conn, uuid);
        if (tmp == NULL)
            return 0;

        virObjectUnref(tmp);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("too many conflicts when generating a uuid"));

    return -1;
}

static int
virStorageGenerateQcowEncryption(virConnectPtr conn,
                                 virStorageVolDefPtr vol)
{
    virSecretDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virStorageEncryptionPtr enc;
    virStorageEncryptionSecretPtr enc_secret = NULL;
    virSecretPtr secret = NULL;
    char *xml;
    unsigned char value[VIR_STORAGE_QCOW_PASSPHRASE_SIZE];
    int ret = -1;

    if (conn->secretDriver == NULL ||
        conn->secretDriver->secretLookupByUUID == NULL ||
        conn->secretDriver->secretDefineXML == NULL ||
        conn->secretDriver->secretSetValue == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret storage not supported"));
        goto cleanup;
    }

    enc = vol->target.encryption;
    if (enc->nsecrets != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("secrets already defined"));
        goto cleanup;
    }

    if (VIR_ALLOC(enc_secret) < 0 || VIR_REALLOC_N(enc->secrets, 1) < 0 ||
        VIR_ALLOC(def) < 0)
        goto cleanup;

    def->isephemeral = false;
    def->isprivate = false;
    if (virStorageGenerateSecretUUID(conn, def->uuid) < 0)
        goto cleanup;

    def->usage_type = VIR_SECRET_USAGE_TYPE_VOLUME;
    if (VIR_STRDUP(def->usage_id, vol->target.path) < 0)
        goto cleanup;
    xml = virSecretDefFormat(def);
    virSecretDefFree(def);
    def = NULL;
    if (xml == NULL)
        goto cleanup;

    secret = conn->secretDriver->secretDefineXML(conn, xml, 0);
    if (secret == NULL) {
        VIR_FREE(xml);
        goto cleanup;
    }
    VIR_FREE(xml);

    if (virStorageGenerateQcowPassphrase(value) < 0)
        goto cleanup;

    if (conn->secretDriver->secretSetValue(secret, value, sizeof(value), 0) < 0)
        goto cleanup;

    enc_secret->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
    enc_secret->seclookupdef.type = VIR_SECRET_LOOKUP_TYPE_UUID;
    memcpy(enc_secret->seclookupdef.u.uuid, secret->uuid, VIR_UUID_BUFLEN);
    enc->format = VIR_STORAGE_ENCRYPTION_FORMAT_QCOW;
    enc->secrets[0] = enc_secret; /* Space for secrets[0] allocated above */
    enc_secret = NULL;
    enc->nsecrets = 1;

    ret = 0;

 cleanup:
    if (secret != NULL) {
        if (ret != 0 &&
            conn->secretDriver->secretUndefine != NULL)
            conn->secretDriver->secretUndefine(secret);
        virObjectUnref(secret);
    }
    virBufferFreeAndReset(&buf);
    virSecretDefFree(def);
    VIR_FREE(enc_secret);
    return ret;
}

static int
virStorageBackendCreateExecCommand(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   virCommandPtr cmd)
{
    struct stat st;
    gid_t gid;
    uid_t uid;
    mode_t mode = (vol->target.perms->mode == (mode_t) -1 ?
                   VIR_STORAGE_DEFAULT_VOL_PERM_MODE :
                   vol->target.perms->mode);
    bool filecreated = false;
    int ret = -1;

    if ((pool->def->type == VIR_STORAGE_POOL_NETFS)
        && (((geteuid() == 0)
             && (vol->target.perms->uid != (uid_t) -1)
             && (vol->target.perms->uid != 0))
            || ((vol->target.perms->gid != (gid_t) -1)
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
                    int fd = -1;
                    int flags = VIR_FILE_OPEN_FORK | VIR_FILE_OPEN_FORCE_MODE;

                    if ((fd = virFileOpenAs(vol->target.path, O_RDWR, mode,
                                            vol->target.perms->uid,
                                            vol->target.perms->gid,
                                            flags)) >= 0) {
                        /* Success - means we're good */
                        VIR_FORCE_CLOSE(fd);
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
        : (uid_t) -1;
    gid = (vol->target.perms->gid != st.st_gid) ? vol->target.perms->gid
        : (gid_t) -1;
    if (((uid != (uid_t) -1) || (gid != (gid_t) -1))
        && (chown(vol->target.path, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown %s to (%u, %u)"),
                             vol->target.path, (unsigned int) uid,
                             (unsigned int) gid);
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
int
virStorageBackendCreatePloop(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                             virStorageVolDefPtr vol,
                             virStorageVolDefPtr inputvol,
                             unsigned int flags)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *create_tool = NULL;
    bool created = false;

    virCheckFlags(0, -1);

    if (inputvol && inputvol->target.format != VIR_STORAGE_FILE_PLOOP) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported input storage vol type %d"),
                       inputvol->target.format);
        return -1;
    }

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("encrypted ploop volumes are not supported with "
                         "ploop init"));
        return -1;
    }

    if (vol->target.backingStore != NULL) {
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
                          (vol->target.perms->mode == (mode_t) -1 ?
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
    virCommandFree(cmd);
    VIR_FREE(create_tool);
    if (ret < 0 && created)
        virFileDeleteTree(vol->target.path);
    return ret;
}

int
virStoragePloopResize(virStorageVolDefPtr vol,
                      unsigned long long capacity)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *resize_tool = NULL;

    resize_tool = virFindFileInPath("ploop");
    if (!resize_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop, please install ploop tools"));
        return -1;
    }
    cmd = virCommandNewArgList(resize_tool, "resize", "-s", NULL);
    virCommandAddArgFormat(cmd, "%lluM", VIR_DIV_UP(capacity, (1024 * 1024)));

    virCommandAddArgFormat(cmd, "%s/DiskDescriptor.xml", vol->target.path);

    ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    VIR_FREE(resize_tool);
    return ret;
}

/* Flag values shared w/ storagevolxml2argvtest.c.
 *
 * QEMU_IMG_BACKING_FORMAT_OPTIONS (added in qemu 0.11)
 * QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT
 *    was made necessary due to 2.0 change to change the default
 *    qcow2 file format from 0.10 to 1.1.
 */
enum {
    QEMU_IMG_BACKING_FORMAT_OPTIONS = 0,
    QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT,
};

static bool
virStorageBackendQemuImgSupportsCompat(const char *qemuimg)
{
    bool ret = false;
    char *output;
    virCommandPtr cmd = NULL;

    cmd = virCommandNewArgList(qemuimg, "create", "-o", "?", "-f", "qcow2",
                               "/dev/null", NULL);

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (strstr(output, "\ncompat "))
        ret = true;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(output);
    return ret;
}


static int
virStorageBackendQEMUImgBackingFormat(const char *qemuimg)
{
    /* As of QEMU 0.11 the [-o options] support was added via qemu
     * commit id '9ea2ea71', so we start with that base and figure
     * out what else we have */
    int ret = QEMU_IMG_BACKING_FORMAT_OPTIONS;

    /* QEMU 2.0 changed to using a format that only QEMU 1.1 and newer
     * understands. Since we still support QEMU 0.12 and newer, we need
     * to be able to handle the previous format as can be set via a
     * compat=0.10 option. */
    if (virStorageBackendQemuImgSupportsCompat(qemuimg))
        ret = QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT;

    return ret;
}

/* The _virStorageBackendQemuImgInfo separates the command line building from
 * the volume definition so that qemuDomainSnapshotCreateInactiveExternal can
 * use it without needing to deal with a volume.
 */
struct _virStorageBackendQemuImgInfo {
    int format;
    const char *path;
    unsigned long long size_arg;
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
    const char *secretPath;
};


static int
virStorageBackendCreateQemuImgOpts(virStorageEncryptionInfoDefPtr enc,
                                   char **opts,
                                   struct _virStorageBackendQemuImgInfo info)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (info.format == VIR_STORAGE_FILE_RAW && enc) {
        virQEMUBuildLuksOpts(&buf, enc, info.secretAlias);
    } else {
        if (info.backingPath)
            virBufferAsprintf(&buf, "backing_fmt=%s,",
                              virStorageFileFormatTypeToString(info.backingFormat));
        if (info.encryption)
            virBufferAddLit(&buf, "encryption=on,");
        if (info.preallocate)
            virBufferAddLit(&buf, "preallocation=metadata,");
    }

    if (info.nocow)
        virBufferAddLit(&buf, "nocow=on,");

    if (info.compat)
        virBufferAsprintf(&buf, "compat=%s,", info.compat);

    if (info.features && info.format == VIR_STORAGE_FILE_QCOW2) {
        if (virBitmapIsBitSet(info.features,
                              VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS)) {
            if (STREQ_NULLABLE(info.compat, "0.10")) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("lazy_refcounts not supported with compat"
                                 " level %s"),
                               info.compat);
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


/* virStorageBackendCreateQemuImgCheckEncryption:
 * @format: format of file found
 * @conn: pointer to connection
 * @vol: pointer to volume def
 *
 * Ensure the proper setup for encryption.
 *
 * Returns 0 on success, -1 on failure w/ error set
 */
static int
virStorageBackendCreateQemuImgCheckEncryption(int format,
                                              const char *type,
                                              virConnectPtr conn,
                                              virStorageVolDefPtr vol)
{
    virStorageEncryptionPtr enc = vol->target.encryption;

    if (format == VIR_STORAGE_FILE_QCOW || format == VIR_STORAGE_FILE_QCOW2) {
        if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_QCOW &&
            enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported volume encryption format %d"),
                           vol->target.encryption->format);
            return -1;
        }
        if (enc->nsecrets > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("too many secrets for qcow encryption"));
            return -1;
        }
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT ||
            enc->nsecrets == 0) {
            if (virStorageGenerateQcowEncryption(conn, vol) < 0)
                return -1;
        }
    } else if (format == VIR_STORAGE_FILE_RAW) {
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
virStorageBackendCreateQemuImgSetInput(virStorageVolDefPtr inputvol,
                                       struct _virStorageBackendQemuImgInfo *info)
{
    if (!(info->inputPath = inputvol->target.path)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing input volume target path"));
        return -1;
    }

    info->inputFormat = inputvol->target.format;
    if (inputvol->type == VIR_STORAGE_VOL_BLOCK)
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
virStorageBackendCreateQemuImgSetBacking(virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol,
                                         struct _virStorageBackendQemuImgInfo *info)
{
    int accessRetCode = -1;
    char *absolutePath = NULL;

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
    if (inputvol && inputvol->target.backingStore &&
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
        virAsprintf(&absolutePath, "%s/%s", pool->def->target.path,
                    info->backingPath) < 0)
        return -1;
    accessRetCode = access(absolutePath ? absolutePath :
                           info->backingPath, R_OK);
    VIR_FREE(absolutePath);
    if (accessRetCode != 0) {
        virReportSystemError(errno,
                             _("inaccessible backing store volume %s"),
                             info->backingPath);
        return -1;
    }

    return 0;
}


static int
virStorageBackendCreateQemuImgSetOptions(virCommandPtr cmd,
                                         int imgformat,
                                         virStorageEncryptionInfoDefPtr enc,
                                         struct _virStorageBackendQemuImgInfo info)
{
    char *opts = NULL;

    if (info.format == VIR_STORAGE_FILE_QCOW2 && !info.compat &&
        imgformat >= QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT)
        info.compat = "0.10";

    if (virStorageBackendCreateQemuImgOpts(enc, &opts, info) < 0)
        return -1;
    if (opts)
        virCommandAddArgList(cmd, "-o", opts, NULL);
    VIR_FREE(opts);

    return 0;
}


/* Add a secret object to the command line:
 *    --object secret,id=$secretAlias,file=$secretPath
 *
 *    NB: format=raw is assumed
 */
static int
virStorageBackendCreateQemuImgSecretObject(virCommandPtr cmd,
                                           virStorageVolDefPtr vol,
                                           struct _virStorageBackendQemuImgInfo *info)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *commandStr = NULL;

    if (virAsprintf(&info->secretAlias, "%s_luks0", vol->name) < 0)
        return -1;

    virBufferAsprintf(&buf, "secret,id=%s,file=", info->secretAlias);
    virQEMUBuildBufferEscapeComma(&buf, info->secretPath);

    if (virBufferCheckError(&buf) < 0) {
        virBufferFreeAndReset(&buf);
        return -1;
    }

    commandStr = virBufferContentAndReset(&buf);

    virCommandAddArgList(cmd, "--object", commandStr, NULL);

    VIR_FREE(commandStr);
    return 0;
}


/* Create a qemu-img virCommand from the supplied binary path,
 * volume definitions and imgformat
 */
virCommandPtr
virStorageBackendCreateQemuImgCmdFromVol(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol,
                                         unsigned int flags,
                                         const char *create_tool,
                                         int imgformat,
                                         const char *secretPath)
{
    virCommandPtr cmd = NULL;
    const char *type;
    struct _virStorageBackendQemuImgInfo info = {
        .format = vol->target.format,
        .path = vol->target.path,
        .encryption = vol->target.encryption != NULL,
        .preallocate = !!(flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA),
        .compat = vol->target.compat,
        .features = vol->target.features,
        .nocow = vol->target.nocow,
        .secretPath = secretPath,
        .secretAlias = NULL,
    };
    virStorageEncryptionInfoDefPtr enc = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    /* Treat output block devices as 'raw' format */
    if (vol->type == VIR_STORAGE_VOL_BLOCK)
        info.format = VIR_STORAGE_FILE_RAW;

    if (!(type = virStorageFileFormatTypeToString(info.format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage vol type %d"),
                       info.format);
        return NULL;
    }

    if (info.preallocate && info.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation only available with qcow2"));
        return NULL;
    }
    if (info.compat && info.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("compatibility option only available with qcow2"));
        return NULL;
    }
    if (info.features && info.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("format features only available with qcow2"));
        return NULL;
    }
    if (info.format == VIR_STORAGE_FILE_RAW &&
        vol->target.encryption != NULL) {
        if (inputvol) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use inputvol with encrypted raw volume"));
            return NULL;
        }
        if (!info.encryption) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing encryption description"));
            return NULL;
        }
        if (vol->target.encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
            type = "luks";
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only luks encryption is supported for raw files"));
            return NULL;
        }
    }

    if (inputvol &&
        virStorageBackendCreateQemuImgSetInput(inputvol, &info) < 0)
        return NULL;

    if (vol->target.backingStore &&
        virStorageBackendCreateQemuImgSetBacking(pool, vol, inputvol,
                                                 &info) < 0)
        return NULL;

    if (info.encryption &&
        virStorageBackendCreateQemuImgCheckEncryption(info.format, type,
                                                      conn, vol) < 0)
        return NULL;


    /* Size in KB */
    info.size_arg = VIR_DIV_UP(vol->target.capacity, 1024);

    cmd = virCommandNew(create_tool);

    /* ignore the backing volume when we're converting a volume */
    if (info.inputPath)
        info.backingPath = NULL;

    if (info.inputPath)
        virCommandAddArgList(cmd, "convert", "-f", info.inputFormatStr,
                             "-O", type, NULL);
    else
        virCommandAddArgList(cmd, "create", "-f", type, NULL);

    if (info.backingPath)
        virCommandAddArgList(cmd, "-b", info.backingPath, NULL);

    if (info.format == VIR_STORAGE_FILE_RAW &&
        vol->target.encryption != NULL &&
        vol->target.encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        if (virStorageBackendCreateQemuImgSecretObject(cmd, vol, &info) < 0) {
            VIR_FREE(info.secretAlias);
            virCommandFree(cmd);
            return NULL;
        }
        enc = &vol->target.encryption->encinfo;
    }

    if (virStorageBackendCreateQemuImgSetOptions(cmd, imgformat,
                                                 enc, info) < 0) {
        VIR_FREE(info.secretAlias);
        virCommandFree(cmd);
        return NULL;
    }
    VIR_FREE(info.secretAlias);

    if (info.inputPath)
        virCommandAddArg(cmd, info.inputPath);
    virCommandAddArg(cmd, info.path);
    if (!info.inputPath && (info.size_arg || !info.backingPath))
        virCommandAddArgFormat(cmd, "%lluK", info.size_arg);

    return cmd;
}


static char *
virStorageBackendCreateQemuImgSecretPath(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol)
{
    virStorageEncryptionPtr enc = vol->target.encryption;
    char *secretPath = NULL;
    int fd = -1;
    uint8_t *secret = NULL;
    size_t secretlen = 0;

    if (!enc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing encryption description"));
        return NULL;
    }

    if (!conn || !conn->secretDriver ||
        !conn->secretDriver->secretLookupByUUID ||
        !conn->secretDriver->secretLookupByUsage ||
        !conn->secretDriver->secretGetValue) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to look up encryption secret"));
        return NULL;
    }

    if (!(secretPath = virStoragePoolObjBuildTempFilePath(pool, vol)))
        goto cleanup;

    if ((fd = mkostemp(secretPath, O_CLOEXEC)) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to open luks secret file for write"));
        goto error;
    }

    if (virSecretGetSecretString(conn, &enc->secrets[0]->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_VOLUME,
                                 &secret, &secretlen) < 0)
        goto error;

    if (safewrite(fd, secret, secretlen) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to write luks secret file"));
        goto error;
    }
    VIR_FORCE_CLOSE(fd);

    if ((vol->target.perms->uid != (uid_t) -1) &&
        (vol->target.perms->gid != (gid_t) -1)) {
        if (chown(secretPath, vol->target.perms->uid,
                  vol->target.perms->gid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to chown luks secret file"));
            goto error;
        }
    }

 cleanup:
    VIR_DISPOSE_N(secret, secretlen);
    VIR_FORCE_CLOSE(fd);

    return secretPath;

 error:
    unlink(secretPath);
    VIR_FREE(secretPath);
    goto cleanup;
}


int
virStorageBackendCreateQemuImg(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               virStorageVolDefPtr inputvol,
                               unsigned int flags)
{
    int ret = -1;
    char *create_tool;
    int imgformat;
    virCommandPtr cmd;
    char *secretPath = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    create_tool = virFindFileInPath("qemu-img");
    if (!create_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("creation of non-raw file images is "
                         "not supported without qemu-img."));
        return -1;
    }

    imgformat = virStorageBackendQEMUImgBackingFormat(create_tool);
    if (imgformat < 0)
        goto cleanup;

    if (vol->target.format == VIR_STORAGE_FILE_RAW &&
        vol->target.encryption &&
        vol->target.encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        if (!(secretPath =
              virStorageBackendCreateQemuImgSecretPath(conn, pool, vol)))
            goto cleanup;
    }

    cmd = virStorageBackendCreateQemuImgCmdFromVol(conn, pool, vol, inputvol,
                                                   flags, create_tool,
                                                   imgformat, secretPath);
    if (!cmd)
        goto cleanup;

    ret = virStorageBackendCreateExecCommand(pool, vol, cmd);

    virCommandFree(cmd);
 cleanup:
    if (secretPath) {
        unlink(secretPath);
        VIR_FREE(secretPath);
    }
    VIR_FREE(create_tool);
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
          vol->target.encryption != NULL)) ||
        (inputvol->type == VIR_STORAGE_VOL_FILE &&
         (inputvol->target.format != VIR_STORAGE_FILE_RAW ||
          inputvol->target.encryption != NULL))) {
        return virStorageBackendCreateQemuImg;
    }

    if (vol->type == VIR_STORAGE_VOL_PLOOP)
        return virStorageBackendCreatePloop;
    if (vol->type == VIR_STORAGE_VOL_BLOCK)
        return virStorageBackendCreateBlockFrom;
    else
        return virStorageBackendCreateRaw;
}


virStorageBackendPtr
virStorageBackendForType(int type)
{
    size_t i;
    for (i = 0; backends[i]; i++)
        if (backends[i]->type == type)
            return backends[i];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing backend for pool type %d (%s)"),
                   type, NULLSTR(virStoragePoolTypeToString(type)));
    return NULL;
}


virStorageFileBackendPtr
virStorageFileBackendForTypeInternal(int type,
                                     int protocol,
                                     bool report)
{
    size_t i;

    for (i = 0; fileBackends[i]; i++) {
        if (fileBackends[i]->type == type) {
            if (type == VIR_STORAGE_TYPE_NETWORK &&
                fileBackends[i]->protocol != protocol)
                continue;

            return fileBackends[i];
        }
    }

    if (!report)
        return NULL;

    if (type == VIR_STORAGE_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for network files "
                         "using %s protocol"),
                       virStorageNetProtocolTypeToString(protocol));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for '%s' storage"),
                       virStorageTypeToString(type));
    }

    return NULL;
}


virStorageFileBackendPtr
virStorageFileBackendForType(int type,
                             int protocol)
{
    return virStorageFileBackendForTypeInternal(type, protocol, true);
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
bool
virStorageBackendIsPloopDir(char *path)
{
    bool ret = false;
    char *root = NULL;
    char *desc = NULL;
    if (virAsprintf(&root, "%s/root.hds", path) < 0)
        return ret;
    if (!virFileExists(root))
        goto cleanup;
    if (virAsprintf(&desc, "%s/DiskDescriptor.xml", path) < 0)
        goto cleanup;
    if (!virFileExists(desc))
        goto cleanup;

    ret = true;
 cleanup:
    VIR_FREE(root);
    VIR_FREE(desc);
    return ret;
}

/* In case of ploop volumes, path to volume is the path to the ploop
 * directory. To get information about allocation, header information
 * and etc. we need to perform virStorageBackendVolOpen and
 * virStorageBackendUpdateVolTargetFd once again.
 */
int
virStorageBackendRedoPloopUpdate(virStorageSourcePtr target, struct stat *sb,
                                 int *fd, unsigned int flags)
{
    char *path = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/root.hds", target->path) < 0)
        return -1;
    VIR_FORCE_CLOSE(*fd);
    if ((*fd = virStorageBackendVolOpen(path, sb, flags)) < 0)
        goto cleanup;
    ret = virStorageBackendUpdateVolTargetInfoFD(target, *fd, sb);

 cleanup:

    VIR_FREE(path);
    return ret;
}

/*
 * virStorageBackendUpdateVolTargetInfo
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
int
virStorageBackendUpdateVolTargetInfo(virStorageSourcePtr target,
                                     bool withBlockVolFormat,
                                     unsigned int openflags,
                                     unsigned int readflags)
{
    int ret, fd = -1;
    struct stat sb;
    char *buf = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;

    if ((ret = virStorageBackendVolOpen(target->path, &sb, openflags)) < 0)
        goto cleanup;
    fd = ret;

    if ((ret = virStorageBackendUpdateVolTargetInfoFD(target, fd, &sb)) < 0)
        goto cleanup;

    if (target->type == VIR_STORAGE_VOL_FILE &&
        target->format != VIR_STORAGE_FILE_NONE) {
        if (S_ISDIR(sb.st_mode)) {
            if (virStorageBackendIsPloopDir(target->path)) {
                if ((ret = virStorageBackendRedoPloopUpdate(target, &sb, &fd,
                                                            openflags)) < 0)
                    goto cleanup;
                target->format = VIR_STORAGE_FILE_PLOOP;
            } else {
                ret = 0;
                goto cleanup;
            }
        }

        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            virReportSystemError(errno, _("cannot seek to start of '%s'"), target->path);
            ret = -1;
            goto cleanup;
        }

        if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
            if (readflags & VIR_STORAGE_VOL_READ_NOERROR) {
                VIR_WARN("ignoring failed header read for '%s'",
                         target->path);
                ret = -2;
            } else {
                virReportSystemError(errno,
                                     _("cannot read header '%s'"),
                                     target->path);
                ret = -1;
            }
            goto cleanup;
        }

        if (virStorageSourceUpdateCapacity(target, buf, len, false) < 0) {
            ret = -1;
            goto cleanup;
        }
    }

    if (withBlockVolFormat) {
        if ((ret = virStorageBackendDetectBlockVolFormatFD(target, fd,
                                                           readflags)) < 0)
            goto cleanup;
    }

 cleanup:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(buf);
    return ret;
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

    if ((ret = virStorageBackendUpdateVolTargetInfo(&vol->target,
                                                    withBlockVolFormat,
                                                    openflags, readflags)) < 0)
        return ret;

    if (vol->target.backingStore &&
        (ret = virStorageBackendUpdateVolTargetInfo(vol->target.backingStore,
                                                    withBlockVolFormat,
                                                    VIR_STORAGE_VOL_OPEN_DEFAULT |
                                                    VIR_STORAGE_VOL_OPEN_NOERROR,
                                                    readflags) < 0))
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
 * entries in the directory pool->def->target.path and find the
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
    DIR *dh;
    struct dirent *dent;
    char *stablepath;
    int opentries = 0;
    int retry = 0;
    int direrr;

    /* Logical pools are under /dev but already have stable paths */
    if (pool->def->type == VIR_STORAGE_POOL_LOGICAL ||
        !virStorageBackendPoolPathIsStable(pool->def->target.path))
        goto ret_strdup;

    /* We loop here because /dev/disk/by-{id,path} may not have existed
     * before we started this operation, so we have to give it some time to
     * get created.
     */
 reopen:
    if (virDirOpenQuiet(&dh, pool->def->target.path) < 0) {
        opentries++;
        if (loop && errno == ENOENT && opentries < 50) {
            usleep(100 * 1000);
            goto reopen;
        }
        virReportSystemError(errno,
                             _("cannot read dir '%s'"),
                             pool->def->target.path);
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
                        pool->def->target.path,
                        dent->d_name) == -1) {
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

/*
 *  Check whether the ploop image has snapshots.
 *  return: -1 - failed to check
 *           0 - no snapshots
 *           1 - at least one snapshot
 */
static int
virStorageBackendPloopHasSnapshots(char *path)
{
    virCommandPtr cmd = NULL;
    char *output = NULL;
    char *snap_tool = NULL;
    int ret = -1;

    snap_tool = virFindFileInPath("ploop");
    if (!snap_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find ploop, please install "
                               "ploop tools"));
        return ret;
    }

    cmd = virCommandNewArgList(snap_tool, "snapshot-list", NULL);
    virCommandAddArgFormat(cmd, "%s/DiskDescriptor.xml", path);
    virCommandSetOutputBuffer(cmd, &output);

    if ((ret = virCommandRun(cmd, NULL)) < 0)
        goto cleanup;

    if (!strstr(output, "root.hds.")) {
        ret = 1;
        goto cleanup;
    }
    ret = 0;

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}

int
virStorageBackendVolUploadLocal(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                virStorageVolDefPtr vol,
                                virStreamPtr stream,
                                unsigned long long offset,
                                unsigned long long len,
                                unsigned int flags)
{
    char *path = NULL;
    char *target_path = vol->target.path;
    int ret = -1;
    int has_snap = 0;

    virCheckFlags(0, -1);
    /* if volume has target format VIR_STORAGE_FILE_PLOOP
     * we need to restore DiskDescriptor.xml, according to
     * new contents of volume. This operation will be perfomed
     * when volUpload is fully finished. */
    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        /* Fail if the volume contains snapshots or we failed to check it.*/
        has_snap = virStorageBackendPloopHasSnapshots(vol->target.path);
        if (has_snap < 0) {
            goto cleanup;
        } else if (!has_snap) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("can't upload volume, all existing snapshots"
                             " will be lost"));
            goto cleanup;
        }

        if (virAsprintf(&path, "%s/root.hds", vol->target.path) < 0)
            return -1;
        target_path = path;
    }

    /* Not using O_CREAT because the file is required to already exist at
     * this point */
    ret = virFDStreamOpenBlockDevice(stream, target_path,
                                     offset, len, O_WRONLY);

 cleanup:
    VIR_FREE(path);
    return ret;
}

int
virStorageBackendVolDownloadLocal(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                  virStorageVolDefPtr vol,
                                  virStreamPtr stream,
                                  unsigned long long offset,
                                  unsigned long long len,
                                  unsigned int flags)
{
    char *path = NULL;
    char *target_path = vol->target.path;
    int ret = -1;
    int has_snap = 0;

    virCheckFlags(0, -1);
    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        has_snap = virStorageBackendPloopHasSnapshots(vol->target.path);
        if (has_snap < 0) {
            goto cleanup;
        } else if (!has_snap) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("can't download volume, all existing snapshots"
                             " will be lost"));
            goto cleanup;
        }
        if (virAsprintf(&path, "%s/root.hds", vol->target.path) < 0)
            goto cleanup;
        target_path = path;
    }

    ret = virFDStreamOpenBlockDevice(stream, target_path,
                                     offset, len, O_RDONLY);

 cleanup:
    VIR_FREE(path);
    return ret;
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
virStorageBackendVolZeroSparseFileLocal(const char *path,
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
virStorageBackendWipeLocal(const char *path,
                           int fd,
                           unsigned long long wipe_len,
                           size_t writebuf_length)
{
    int ret = -1, written = 0;
    unsigned long long remaining = 0;
    size_t write_size = 0;
    char *writebuf = NULL;

    VIR_DEBUG("wiping start: 0 len: %llu", wipe_len);

    if (VIR_ALLOC_N(writebuf, writebuf_length) < 0)
        goto cleanup;

    if (lseek(fd, 0, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Failed to seek to the start in volume "
                               "with path '%s'"),
                             path);
        goto cleanup;
    }

    remaining = wipe_len;
    while (remaining > 0) {

        write_size = (writebuf_length < remaining) ? writebuf_length : remaining;
        written = safewrite(fd, writebuf, write_size);
        if (written < 0) {
            virReportSystemError(errno,
                                 _("Failed to write %zu bytes to "
                                   "storage volume with path '%s'"),
                                 write_size, path);

            goto cleanup;
        }

        remaining -= written;
    }

    if (fdatasync(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot sync data to volume with path '%s'"),
                             path);
        goto cleanup;
    }

    VIR_DEBUG("Wrote %llu bytes to volume with path '%s'", wipe_len, path);

    ret = 0;

 cleanup:
    VIR_FREE(writebuf);
    return ret;
}


static int
virStorageBackendVolWipeLocalFile(const char *path,
                                  unsigned int algorithm,
                                  unsigned long long allocation)
{
    int ret = -1, fd = -1;
    const char *alg_char = NULL;
    struct stat st;
    virCommandPtr cmd = NULL;

    fd = open(path, O_RDWR);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("Failed to open storage volume with path '%s'"),
                             path);
        goto cleanup;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno,
                             _("Failed to stat storage volume with path '%s'"),
                             path);
        goto cleanup;
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
        goto cleanup;
    case VIR_STORAGE_VOL_WIPE_ALG_LAST:
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported algorithm %d"),
                       algorithm);
        goto cleanup;
    }

    VIR_DEBUG("Wiping file '%s' with algorithm '%s'", path, alg_char);

    if (algorithm != VIR_STORAGE_VOL_WIPE_ALG_ZERO) {
        cmd = virCommandNew(SCRUB);
        virCommandAddArgList(cmd, "-f", "-p", alg_char, path, NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        ret = 0;
    } else {
        if (S_ISREG(st.st_mode) && st.st_blocks < (st.st_size / DEV_BSIZE)) {
            ret = virStorageBackendVolZeroSparseFileLocal(path, st.st_size, fd);
        } else {
            ret = virStorageBackendWipeLocal(path,
                                             fd,
                                             allocation,
                                             st.st_blksize);
        }
        if (ret < 0)
            goto cleanup;
    }

 cleanup:
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static int
virStorageBackendVolWipePloop(virStorageVolDefPtr vol,
                              unsigned int algorithm)
{
    virCommandPtr cmd = NULL;
    char *target_path = NULL;
    char *disk_desc = NULL;
    char *create_tool = NULL;

    int ret = -1;

    create_tool = virFindFileInPath("ploop");
    if (!create_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop tools, please install them"));
        return -1;
    }

    if (virAsprintf(&target_path, "%s/root.hds", vol->target.path) < 0)
        goto cleanup;

    if (virAsprintf(&disk_desc, "%s/DiskDescriptor.xml", vol->target.path) < 0)
        goto cleanup;

    if (virStorageBackendVolWipeLocalFile(target_path,
                                          algorithm,
                                          vol->target.allocation) < 0)
        goto cleanup;

    if (virFileRemove(disk_desc, 0, 0) < 0) {
        virReportError(errno, _("Failed to delete DiskDescriptor.xml of volume '%s'"),
                       vol->target.path);
        goto cleanup;
    }
    if (virFileRemove(target_path, 0, 0) < 0) {
        virReportError(errno, _("failed to delete root.hds of volume '%s'"),
                       vol->target.path);
        goto cleanup;
    }

    cmd = virCommandNewArgList(create_tool, "init", "-s", NULL);

    virCommandAddArgFormat(cmd, "%lluM", VIR_DIV_UP(vol->target.capacity,
                                                    (1024 * 1024)));
    virCommandAddArgList(cmd, "-t", "ext4", NULL);
    virCommandAddArg(cmd, target_path);
    ret = virCommandRun(cmd, NULL);

 cleanup:
    VIR_FREE(disk_desc);
    VIR_FREE(target_path);
    VIR_FREE(create_tool);
    virCommandFree(cmd);
    return ret;
}


int
virStorageBackendVolWipeLocal(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              virStorageVolDefPtr vol,
                              unsigned int algorithm,
                              unsigned int flags)
{
    int ret = -1;

    virCheckFlags(0, -1);

    VIR_DEBUG("Wiping volume with path '%s' and algorithm %u",
              vol->target.path, algorithm);

    if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        ret = virStorageBackendVolWipePloop(vol, algorithm);
    } else {
        ret = virStorageBackendVolWipeLocalFile(vol->target.path,
                                                algorithm,
                                                vol->target.allocation);
    }

    return ret;
}


#ifdef GLUSTER_CLI
int
virStorageBackendFindGlusterPoolSources(const char *host,
                                        int pooltype,
                                        virStoragePoolSourceListPtr list)
{
    char *outbuf = NULL;
    virCommandPtr cmd = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *nodes = NULL;
    virStoragePoolSource *src = NULL;
    size_t i;
    int nnodes;
    int rc;

    int ret = -1;

    cmd = virCommandNewArgList(GLUSTER_CLI,
                               "--xml",
                               "--log-file=/dev/null",
                               "volume", "info", "all", NULL);

    virCommandAddArgFormat(cmd, "--remote-host=%s", host);
    virCommandSetOutputBuffer(cmd, &outbuf);

    if (virCommandRun(cmd, &rc) < 0)
        goto cleanup;

    if (rc != 0) {
        VIR_INFO("failed to query host '%s' for gluster volumes: %s",
                 host, outbuf);
        ret = 0;
        goto cleanup;
    }

    if (!(doc = virXMLParseStringCtxt(outbuf, _("(gluster_cli_output)"),
                                      &ctxt)))
        goto cleanup;

    if ((nnodes = virXPathNodeSet("//volumes/volume", ctxt, &nodes)) <= 0) {
        VIR_INFO("no gluster volumes available on '%s'", host);
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < nnodes; i++) {
        ctxt->node = nodes[i];

        if (!(src = virStoragePoolSourceListNewSource(list)))
            goto cleanup;

        if (!(src->dir = virXPathString("string(//name)", ctxt))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to extract gluster volume name"));
            goto cleanup;
        }

        if (VIR_ALLOC_N(src->hosts, 1) < 0)
            goto cleanup;
        src->nhost = 1;

        if (VIR_STRDUP(src->hosts[0].name, host) < 0)
            goto cleanup;

        src->format = pooltype;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    VIR_FREE(outbuf);
    virCommandFree(cmd);
    return ret;
}
#else /* #ifdef GLUSTER_CLI */
int
virStorageBackendFindGlusterPoolSources(const char *host ATTRIBUTE_UNUSED,
                                        int pooltype ATTRIBUTE_UNUSED,
                                        virStoragePoolSourceListPtr list ATTRIBUTE_UNUSED)
{
    VIR_INFO("gluster cli tool not installed");
    return 0;
}
#endif /* #ifdef GLUSTER_CLI */


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
     * for "pc98" it returns "dos". So since those will cause problems
     * with startup comparison, let's just treat them as UNKNOWN causing
     * the caller to fallback to using PARTED */
    if (STREQ(format, "dvh") || STREQ(format, "pc98"))
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
        if (rc == VIR_STORAGE_BLKID_PROBE_UNKNOWN) {
            ret = -2;
            goto cleanup;
        }
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
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                       _("Not capable of probing for format type '%s', "
                         "requires build --overwrite"),
                       format);
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
        virReportError(VIR_ERR_STORAGE_POOL_BUILT,
                       _("Device '%s' formatted cannot overwrite using '%s', "
                         "requires build --overwrite"),
                       device, format);
        break;
    }

    if (ret == 0 && blkid_do_probe(probe) != 1) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED, "%s",
                       _("Found additional probes to run, probing may "
                         "be incorrect"));
        ret = -1;
    }

 cleanup:
    blkid_free_probe(probe);

    return ret;
}

#else /* #if WITH_BLKID */

static int
virStorageBackendBLKIDFindEmpty(const char *device ATTRIBUTE_UNUSED,
                                const char *format ATTRIBUTE_UNUSED,
                                bool writelabel ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("probing for filesystems is unsupported "
                     "by this build"));
    return -2;
}

#endif /* #if WITH_BLKID */


#if WITH_STORAGE_DISK

static int
virStorageBackendPARTEDValidLabel(const char *device,
                                  const char *format,
                                  bool writelabel)
{
    return virStorageBackendDiskValidLabel(device, format, writelabel);
}

#else

static int
virStorageBackendPARTEDValidLabel(const char *device ATTRIBUTE_UNUSED,
                                  const char *format ATTRIBUTE_UNUSED,
                                  bool writelabel ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("PARTED is unsupported by this build"));
    return -1;
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
 * and returns false if the probe finds something
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

    return ret == 0;
}
