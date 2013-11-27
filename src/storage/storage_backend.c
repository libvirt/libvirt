/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2013 Red Hat, Inc.
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
#endif

#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "internal.h"
#include "secret_conf.h"
#include "viruuid.h"
#include "virstoragefile.h"
#include "storage_backend.h"
#include "virlog.h"
#include "virfile.h"
#include "stat-time.h"
#include "virstring.h"

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

#define VIR_FROM_THIS VIR_FROM_STORAGE

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
    NULL
};

enum {
    TOOL_QEMU_IMG,
    TOOL_KVM_IMG,
    TOOL_QCOW_CREATE,
};

#define READ_BLOCK_SIZE_DEFAULT  (1024 * 1024)
#define WRITE_BLOCK_SIZE_DEFAULT (4 * 1024)

static int ATTRIBUTE_NONNULL(2)
virStorageBackendCopyToFD(virStorageVolDefPtr vol,
                          virStorageVolDefPtr inputvol,
                          int fd,
                          unsigned long long *total,
                          bool want_sparse)
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
    if (ioctl(fd, BLKBSZGET, &wbytes) < 0) {
        wbytes = 0;
    }
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

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for block "
                         "volumes"));
        goto cleanup;
    }

    if ((fd = open(vol->target.path, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    remain = vol->allocation;

    if (inputvol) {
        int res = virStorageBackendCopyToFD(vol, inputvol,
                                            fd, &remain, false);
        if (res < 0)
            goto cleanup;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno, _("stat of '%s' failed"),
                             vol->target.path);
        goto cleanup;
    }
    uid = (vol->target.perms.uid != st.st_uid) ? vol->target.perms.uid : (uid_t) -1;
    gid = (vol->target.perms.gid != st.st_gid) ? vol->target.perms.gid : (gid_t) -1;
    if (((uid != (uid_t) -1) || (gid != (gid_t) -1))
        && (fchown(fd, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown '%s' to (%u, %u)"),
                             vol->target.path, (unsigned int) uid,
                             (unsigned int) gid);
        goto cleanup;
    }
    if (fchmod(fd, vol->target.perms.mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, vol->target.perms.mode);
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
              virStorageVolDefPtr inputvol)
{
    bool need_alloc = true;
    int ret = 0;
    unsigned long long remain;

    /* Seek to the final size, so the capacity is available upfront
     * for progress reporting */
    if (ftruncate(fd, vol->capacity) < 0) {
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
    if (vol->allocation) {
        if (fallocate(fd, 0, 0, vol->allocation) == 0) {
            need_alloc = false;
        } else if (errno != ENOSYS && errno != EOPNOTSUPP) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("cannot allocate %llu bytes in file '%s'"),
                                 vol->allocation, vol->target.path);
            goto cleanup;
        }
    }
#endif

    remain = vol->allocation;

    if (inputvol) {
        /* allow zero blocks to be skipped if we've requested sparse
         * allocation (allocation < capacity) or we have already
         * been able to allocate the required space. */
        bool want_sparse = !need_alloc ||
                           (vol->allocation < inputvol->capacity);

        ret = virStorageBackendCopyToFD(vol, inputvol, fd, &remain, want_sparse);
        if (ret < 0) {
            goto cleanup;
        }
    }

    if (remain && need_alloc) {
        if (safezero(fd, vol->allocation - remain, remain) < 0) {
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

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported for raw "
                         "volumes"));
        goto cleanup;
    }

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool does not support encrypted volumes"));
        goto cleanup;
    }

    operation_flags = VIR_FILE_OPEN_FORCE_MODE | VIR_FILE_OPEN_FORCE_OWNER;
    if (pool->def->type == VIR_STORAGE_POOL_NETFS)
        operation_flags |= VIR_FILE_OPEN_FORK;

    if ((fd = virFileOpenAs(vol->target.path,
                            O_RDWR | O_CREAT | O_EXCL,
                            vol->target.perms.mode,
                            vol->target.perms.uid,
                            vol->target.perms.gid,
                            operation_flags)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create file '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    if ((ret = createRawFile(fd, vol, inputvol)) < 0)
        /* createRawFile already reported the exact error. */
        ret = -1;

cleanup:
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

        virSecretFree(tmp);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("too many conflicts when generating an uuid"));

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

    def->ephemeral = false;
    def->private = false;
    if (virStorageGenerateSecretUUID(conn, def->uuid) < 0)
        goto cleanup;

    def->usage_type = VIR_SECRET_USAGE_TYPE_VOLUME;
    if (VIR_STRDUP(def->usage.volume, vol->target.path) < 0)
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
    memcpy(enc_secret->uuid, secret->uuid, VIR_UUID_BUFLEN);
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
        virSecretFree(secret);
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
    bool filecreated = false;

    if ((pool->def->type == VIR_STORAGE_POOL_NETFS)
        && (((geteuid() == 0)
             && (vol->target.perms.uid != (uid_t) -1)
             && (vol->target.perms.uid != 0))
            || ((vol->target.perms.gid != (gid_t) -1)
                && (vol->target.perms.gid != getegid())))) {

        virCommandSetUID(cmd, vol->target.perms.uid);
        virCommandSetGID(cmd, vol->target.perms.gid);

        if (virCommandRun(cmd, NULL) == 0) {
            /* command was successfully run, check if the file was created */
            if (stat(vol->target.path, &st) >=0)
                filecreated = true;
        }
    }

    /* don't change uid/gid if we retry */
    virCommandSetUID(cmd, -1);
    virCommandSetGID(cmd, -1);

    if (!filecreated) {
        if (virCommandRun(cmd, NULL) < 0) {
            return -1;
        }
        if (stat(vol->target.path, &st) < 0) {
            virReportSystemError(errno,
                                 _("failed to create %s"), vol->target.path);
            return -1;
        }
    }

    uid = (vol->target.perms.uid != st.st_uid) ? vol->target.perms.uid : (uid_t) -1;
    gid = (vol->target.perms.gid != st.st_gid) ? vol->target.perms.gid : (gid_t) -1;
    if (((uid != (uid_t) -1) || (gid != (gid_t) -1))
        && (chown(vol->target.path, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown %s to (%u, %u)"),
                             vol->target.path, (unsigned int) uid,
                             (unsigned int) gid);
        return -1;
    }
    if (chmod(vol->target.path, vol->target.perms.mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, vol->target.perms.mode);
        return -1;
    }
    return 0;
}

enum {
    QEMU_IMG_BACKING_FORMAT_NONE = 0,
    QEMU_IMG_BACKING_FORMAT_FLAG,
    QEMU_IMG_BACKING_FORMAT_OPTIONS,
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
    char *help = NULL;
    char *start;
    char *end;
    char *tmp;
    int ret = -1;
    int exitstatus;
    virCommandPtr cmd = virCommandNewArgList(qemuimg, "-h", NULL);

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);
    virCommandClearCaps(cmd);

    /* qemuimg doesn't return zero exit status on -h,
     * therefore we need to provide pointer for storing
     * exit status, although we don't parse it any later */
    if (virCommandRun(cmd, &exitstatus) < 0)
        goto cleanup;

    if ((start = strstr(help, " create ")) == NULL ||
        (end = strstr(start, "\n")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse qemu-img output '%s'"),
                       help);
        goto cleanup;
    }
    if (((tmp = strstr(start, "-F fmt")) && tmp < end) ||
        ((tmp = strstr(start, "-F backing_fmt")) && tmp < end)) {
        ret = QEMU_IMG_BACKING_FORMAT_FLAG;
    } else if ((tmp = strstr(start, "[-o options]")) && tmp < end) {
        if (virStorageBackendQemuImgSupportsCompat(qemuimg))
            ret = QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT;
        else
            ret = QEMU_IMG_BACKING_FORMAT_OPTIONS;
    } else {
        ret = QEMU_IMG_BACKING_FORMAT_NONE;
    }

cleanup:
    virCommandFree(cmd);
    VIR_FREE(help);
    return ret;
}

static int
virStorageBackendCreateQemuImgOpts(char **opts,
                                   const char *backingType,
                                   bool encryption,
                                   bool preallocate,
                                   int format,
                                   const char *compat,
                                   virBitmapPtr features)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool b;
    size_t i;

    if (backingType)
        virBufferAsprintf(&buf, "backing_fmt=%s,", backingType);
    if (encryption)
        virBufferAddLit(&buf, "encryption=on,");
    if (preallocate)
        virBufferAddLit(&buf, "preallocation=metadata,");

    if (compat)
        virBufferAsprintf(&buf, "compat=%s,", compat);
    if (features && format == VIR_STORAGE_FILE_QCOW2) {
        for (i = 0; i < VIR_STORAGE_FILE_FEATURE_LAST; i++) {
            ignore_value(virBitmapGetBit(features, i, &b));
            if (b) {
                switch ((enum virStorageFileFeature) i) {
                case VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS:
                    if (STREQ_NULLABLE(compat, "0.10")) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       _("Feature %s not supported with compat"
                                         " level %s"),
                                       virStorageFileFeatureTypeToString(i),
                                       compat);
                        goto error;
                    }
                    break;

                /* coverity[dead_error_begin] */
                case VIR_STORAGE_FILE_FEATURE_LAST:
                    ;
                }
                virBufferAsprintf(&buf, "%s,",
                                  virStorageFileFeatureTypeToString(i));
            }
        }
    }

    virBufferTrim(&buf, ",", -1);

    if (virBufferError(&buf))
        goto no_memory;

    *opts = virBufferContentAndReset(&buf);
    return 0;

no_memory:
    virReportOOMError();
error:
    virBufferFreeAndReset(&buf);
    return -1;
}

virCommandPtr
virStorageBackendCreateQemuImgCmd(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  virStorageVolDefPtr inputvol,
                                  unsigned int flags,
                                  const char *create_tool,
                                  int imgformat)
{
    virCommandPtr cmd = NULL;
    bool do_encryption = (vol->target.encryption != NULL);
    unsigned long long int size_arg;
    bool preallocate = !!(flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA);
    const char *type;
    const char *backingType = NULL;
    const char *inputPath = NULL;
    const char *inputType = NULL;
    const char *compat = vol->target.compat;
    char *opts = NULL;
    bool convert = false;
    bool backing = false;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    /* Treat output block devices as 'raw' format */
    type = virStorageFileFormatTypeToString(vol->type == VIR_STORAGE_VOL_BLOCK ?
                                            VIR_STORAGE_FILE_RAW :
                                            vol->target.format);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage vol type %d"),
                       vol->target.format);
        return NULL;
    }

    if (preallocate && vol->target.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation only available with qcow2"));
        return NULL;
    }
    if (vol->target.compat && vol->target.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("compatibility option only available with qcow2"));
        return NULL;
    }
    if (vol->target.features && vol->target.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("format features only available with qcow2"));
        return NULL;
    }

    if (inputvol) {
        if (!(inputPath = inputvol->target.path)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("missing input volume target path"));
            return NULL;
        }

        inputType = virStorageFileFormatTypeToString(inputvol->type == VIR_STORAGE_VOL_BLOCK ?
                                                     VIR_STORAGE_FILE_RAW :
                                                     inputvol->target.format);

        if (!inputType) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown storage vol type %d"),
                           inputvol->target.format);
            return NULL;
        }

    }

    if (vol->backingStore.path) {
        int accessRetCode = -1;
        char *absolutePath = NULL;

        backingType = virStorageFileFormatTypeToString(vol->backingStore.format);

        if (preallocate) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("metadata preallocation conflicts with backing"
                             " store"));
            return NULL;
        }

        /* XXX: Not strictly required: qemu-img has an option a different
         * backing store, not really sure what use it serves though, and it
         * may cause issues with lvm. Untested essentially.
         */
        if (inputvol &&
            STRNEQ_NULLABLE(inputvol->backingStore.path, vol->backingStore.path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("a different backing store cannot be specified."));
            return NULL;
        }

        if (backingType == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown storage vol backing store type %d"),
                           vol->backingStore.format);
            return NULL;
        }

        /* Convert relative backing store paths to absolute paths for access
         * validation.
         */
        if ('/' != *(vol->backingStore.path) &&
            virAsprintf(&absolutePath, "%s/%s", pool->def->target.path,
                        vol->backingStore.path) < 0)
            return NULL;
        accessRetCode = access(absolutePath ? absolutePath
                               : vol->backingStore.path, R_OK);
        VIR_FREE(absolutePath);
        if (accessRetCode != 0) {
            virReportSystemError(errno,
                                 _("inaccessible backing store volume %s"),
                                 vol->backingStore.path);
            return NULL;
        }
    }

    if (do_encryption) {
        virStorageEncryptionPtr enc;

        if (vol->target.format != VIR_STORAGE_FILE_QCOW &&
            vol->target.format != VIR_STORAGE_FILE_QCOW2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("qcow volume encryption unsupported with "
                             "volume format %s"), type);
            return NULL;
        }
        enc = vol->target.encryption;
        if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_QCOW &&
            enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported volume encryption format %d"),
                           vol->target.encryption->format);
            return NULL;
        }
        if (enc->nsecrets > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("too many secrets for qcow encryption"));
            return NULL;
        }
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT ||
            enc->nsecrets == 0) {
            if (virStorageGenerateQcowEncryption(conn, vol) < 0)
                return NULL;
        }
    }

    /* Size in KB */
    size_arg = VIR_DIV_UP(vol->capacity, 1024);

    cmd = virCommandNew(create_tool);

    convert = !!inputvol;
    backing = !inputvol && vol->backingStore.path;

    if (convert)
        virCommandAddArgList(cmd, "convert", "-f", inputType, "-O", type, NULL);
    else
        virCommandAddArgList(cmd, "create", "-f", type, NULL);

    if (backing)
        virCommandAddArgList(cmd, "-b", vol->backingStore.path, NULL);

    if (imgformat >= QEMU_IMG_BACKING_FORMAT_OPTIONS) {
        if (vol->target.format == VIR_STORAGE_FILE_QCOW2 && !compat &&
            imgformat == QEMU_IMG_BACKING_FORMAT_OPTIONS_COMPAT)
            compat = "0.10";

        if (virStorageBackendCreateQemuImgOpts(&opts,
                                               backing ? backingType : NULL,
                                               do_encryption, preallocate,
                                               vol->target.format,
                                               compat,
                                               vol->target.features) < 0) {
            virCommandFree(cmd);
            return NULL;
        }
        if (opts)
            virCommandAddArgList(cmd, "-o", opts, NULL);
        VIR_FREE(opts);
    } else {
        if (backing) {
            if (imgformat == QEMU_IMG_BACKING_FORMAT_FLAG)
                virCommandAddArgList(cmd, "-F", backingType, NULL);
            else
                VIR_DEBUG("Unable to set backing store format for %s with %s",
                          vol->target.path, create_tool);
        }
        if (do_encryption)
            virCommandAddArg(cmd, "-e");
    }

    if (convert)
        virCommandAddArg(cmd, inputPath);
    virCommandAddArg(cmd, vol->target.path);
    if (!convert)
        virCommandAddArgFormat(cmd, "%lluK", size_arg);

    return cmd;
}

static int
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

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    /* KVM is usually ahead of qemu on features, so try that first */
    create_tool = virFindFileInPath("kvm-img");
    if (!create_tool)
        create_tool = virFindFileInPath("qemu-img");

    if (!create_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find kvm-img or qemu-img"));
        return -1;
    }

    imgformat = virStorageBackendQEMUImgBackingFormat(create_tool);
    if (imgformat < 0)
        goto cleanup;

    cmd = virStorageBackendCreateQemuImgCmd(conn, pool, vol, inputvol, flags,
                                            create_tool, imgformat);
    if (!cmd)
        goto cleanup;

    ret = virStorageBackendCreateExecCommand(pool, vol, cmd);

    virCommandFree(cmd);
cleanup:
    VIR_FREE(create_tool);
    return ret;
}

/*
 * Xen removed the fully-functional qemu-img, and replaced it
 * with a partially functional qcow-create. Go figure ??!?
 */
static int
virStorageBackendCreateQcowCreate(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  virStorageVolDefPtr inputvol,
                                  unsigned int flags)
{
    int ret;
    char *size;
    virCommandPtr cmd;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

    if (flags & VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata preallocation is not supported with "
                         "qcow-create"));
        return -1;
    }

    if (inputvol) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot copy from volume with qcow-create"));
        return -1;
    }

    if (vol->target.format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported storage vol type %d"),
                       vol->target.format);
        return -1;
    }
    if (vol->backingStore.path != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("copy-on-write image not supported with "
                         "qcow-create"));
        return -1;
    }
    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("encrypted volumes not supported with "
                               "qcow-create"));
        return -1;
    }

    /* Size in MB - yes different units to qemu-img :-( */
    if (virAsprintf(&size, "%llu",
                    VIR_DIV_UP(vol->capacity, (1024 * 1024))) < 0)
        return -1;

    cmd = virCommandNewArgList("qcow-create", size, vol->target.path, NULL);

    ret = virStorageBackendCreateExecCommand(pool, vol, cmd);
    virCommandFree(cmd);
    VIR_FREE(size);

    return ret;
}

virStorageBackendBuildVolFrom
virStorageBackendFSImageToolTypeToFunc(int tool_type)
{
    switch (tool_type) {
    case TOOL_KVM_IMG:
    case TOOL_QEMU_IMG:
        return virStorageBackendCreateQemuImg;
    case TOOL_QCOW_CREATE:
        return virStorageBackendCreateQcowCreate;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown file create tool type '%d'."),
                       tool_type);
    }

    return NULL;
}

int
virStorageBackendFindFSImageTool(char **tool)
{
    int tool_type = -1;
    char *tmp = NULL;

    if ((tmp = virFindFileInPath("kvm-img")) != NULL) {
        tool_type = TOOL_KVM_IMG;
    } else if ((tmp = virFindFileInPath("qemu-img")) != NULL) {
        tool_type = TOOL_QEMU_IMG;
    } else if ((tmp = virFindFileInPath("qcow-create")) != NULL) {
        tool_type = TOOL_QCOW_CREATE;
    }

    if (tool)
        *tool = tmp;
    else
        VIR_FREE(tmp);

    return tool_type;
}

virStorageBackendBuildVolFrom
virStorageBackendGetBuildVolFromFunction(virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol)
{
    int tool_type;

    if (!inputvol)
        return NULL;

    /* If either volume is a non-raw file vol, we need to use an external
     * tool for converting
     */
    if ((vol->type == VIR_STORAGE_VOL_FILE &&
         vol->target.format != VIR_STORAGE_FILE_RAW) ||
        (inputvol->type == VIR_STORAGE_VOL_FILE &&
         inputvol->target.format != VIR_STORAGE_FILE_RAW)) {

        if ((tool_type = virStorageBackendFindFSImageTool(NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("creation of non-raw file images is "
                             "not supported without qemu-img."));
            return NULL;
        }

        return virStorageBackendFSImageToolTypeToFunc(tool_type);
    }

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
                   _("missing backend for pool type %d"), type);
    return NULL;
}


/*
 * Allows caller to silently ignore files with improper mode
 *
 * Returns -1 on error, -2 if file mode is unexpected or the
 * volume is a dangling symbolic link.
 */
int
virStorageBackendVolOpenCheckMode(const char *path, struct stat *sb,
                                  unsigned int flags)
{
    int fd, mode = 0;
    char *base = last_component(path);

    if (lstat(path, sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             path);
        return -1;
    }

    if (S_ISFIFO(sb->st_mode)) {
        VIR_WARN("ignoring FIFO '%s'", path);
        return -2;
    } else if (S_ISSOCK(sb->st_mode)) {
        VIR_WARN("ignoring socket '%s'", path);
        return -2;
    }

    /* O_NONBLOCK should only matter during open() for fifos and
     * sockets, which we already filtered; but using it prevents a
     * TOCTTOU race.  However, later on we will want to read() the
     * header from this fd, and virFileRead* routines require a
     * blocking fd, so fix it up after verifying we avoided a
     * race.  */
    if ((fd = open(path, O_RDONLY|O_NONBLOCK|O_NOCTTY)) < 0) {
        if ((errno == ENOENT || errno == ELOOP) &&
            S_ISLNK(sb->st_mode)) {
            VIR_WARN("ignoring dangling symlink '%s'", path);
            return -2;
        }

        virReportSystemError(errno,
                             _("cannot open volume '%s'"),
                             path);
        return -1;
    }

    if (fstat(fd, sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             path);
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
            VIR_INFO("Skipping special dir '%s'", base);
            return -2;
        }
    } else {
        VIR_WARN("ignoring unexpected type for file '%s'", path);
        VIR_FORCE_CLOSE(fd);
        return -2;
    }

    if (virSetBlocking(fd, true) < 0) {
        virReportSystemError(errno, _("unable to set blocking mode for '%s'"),
                             path);
        VIR_FORCE_CLOSE(fd);
        return -2;
    }

    if (!(mode & flags)) {
        VIR_FORCE_CLOSE(fd);
        VIR_INFO("Skipping volume '%s'", path);

        if (mode & VIR_STORAGE_VOL_OPEN_ERROR) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected storage mode for '%s'"), path);
            return -1;
        }

        return -2;
    }

    return fd;
}

int virStorageBackendVolOpen(const char *path)
{
    struct stat sb;
    return virStorageBackendVolOpenCheckMode(path, &sb,
                                             VIR_STORAGE_VOL_OPEN_DEFAULT);
}

int
virStorageBackendUpdateVolTargetInfo(virStorageVolTargetPtr target,
                                     unsigned long long *allocation,
                                     unsigned long long *capacity,
                                     unsigned int openflags)
{
    int ret, fd;
    struct stat sb;

    if ((ret = virStorageBackendVolOpenCheckMode(target->path, &sb,
                                                 openflags)) < 0)
        return ret;

    fd = ret;
    ret = virStorageBackendUpdateVolTargetInfoFD(target,
                                                 fd,
                                                 &sb,
                                                 allocation,
                                                 capacity);

    VIR_FORCE_CLOSE(fd);

    return ret;
}

int
virStorageBackendUpdateVolInfoFlags(virStorageVolDefPtr vol,
                                    int withCapacity,
                                    unsigned int openflags)
{
    int ret;

    if ((ret = virStorageBackendUpdateVolTargetInfo(&vol->target,
                                    &vol->allocation,
                                    withCapacity ? &vol->capacity : NULL,
                                    openflags)) < 0)
        return ret;

    if (vol->backingStore.path &&
        (ret = virStorageBackendUpdateVolTargetInfo(&vol->backingStore,
                                            NULL, NULL,
                                            VIR_STORAGE_VOL_OPEN_DEFAULT)) < 0)
        return ret;

    return 0;
}

int virStorageBackendUpdateVolInfo(virStorageVolDefPtr vol,
                                   int withCapacity)
{
    return virStorageBackendUpdateVolInfoFlags(vol, withCapacity,
                                               VIR_STORAGE_VOL_OPEN_DEFAULT);
}

/*
 * virStorageBackendUpdateVolTargetInfoFD:
 * @target: target definition ptr of volume to update
 * @fd: fd of storage volume to update, via virStorageBackendOpenVol*, or -1
 * @sb: details about file (must match @fd, if that is provided)
 * @allocation: If not NULL, updated allocation information will be stored
 * @capacity: If not NULL, updated capacity info will be stored
 *
 * Returns 0 for success, -1 on a legitimate error condition.
 */
int
virStorageBackendUpdateVolTargetInfoFD(virStorageVolTargetPtr target,
                                       int fd,
                                       struct stat *sb,
                                       unsigned long long *allocation,
                                       unsigned long long *capacity)
{
#if WITH_SELINUX
    security_context_t filecon = NULL;
#endif

    if (allocation) {
        if (S_ISREG(sb->st_mode)) {
#ifndef WIN32
            *allocation = (unsigned long long)sb->st_blocks *
                          (unsigned long long)DEV_BSIZE;
#else
            *allocation = sb->st_size;
#endif
            /* Regular files may be sparse, so logical size (capacity) is not same
             * as actual allocation above
             */
            if (capacity)
                *capacity = sb->st_size;
        } else if (S_ISDIR(sb->st_mode)) {
            *allocation = 0;
            if (capacity)
                *capacity = 0;

        } else if (fd >= 0) {
            off_t end;
            /* XXX this is POSIX compliant, but doesn't work for CHAR files,
             * only BLOCK. There is a Linux specific ioctl() for getting
             * size of both CHAR / BLOCK devices we should check for in
             * configure
             */
            end = lseek(fd, 0, SEEK_END);
            if (end == (off_t)-1) {
                virReportSystemError(errno,
                                     _("cannot seek to end of file '%s'"),
                                     target->path);
                return -1;
            }
            *allocation = end;
            if (capacity)
                *capacity = end;
        }
    }

    target->perms.mode = sb->st_mode & S_IRWXUGO;
    target->perms.uid = sb->st_uid;
    target->perms.gid = sb->st_gid;

    if (!target->timestamps && VIR_ALLOC(target->timestamps) < 0)
        return -1;
    target->timestamps->atime = get_stat_atime(sb);
    target->timestamps->btime = get_stat_birthtime(sb);
    target->timestamps->ctime = get_stat_ctime(sb);
    target->timestamps->mtime = get_stat_mtime(sb);

    VIR_FREE(target->perms.label);

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
            if (VIR_STRDUP(target->perms.label, filecon) < 0) {
                freecon(filecon);
                return -1;
            }
            freecon(filecon);
        }
    }
#endif

    return 0;
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


int
virStorageBackendDetectBlockVolFormatFD(virStorageVolTargetPtr target,
                                        int fd)
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
        virReportSystemError(errno,
                             _("cannot read beginning of file '%s'"),
                             target->path);
        return -1;
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

    return 0;
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

    /* Short circuit if pool has no target, or if its /dev */
    if (pool->def->target.path == NULL ||
        STREQ(pool->def->target.path, "/dev") ||
        STREQ(pool->def->target.path, "/dev/"))
        goto ret_strdup;

    /* Skip whole thing for a pool which isn't in /dev
     * so we don't mess filesystem/dir based pools
     */
    if (!STRPREFIX(pool->def->target.path, "/dev"))
        goto ret_strdup;

    /* Logical pools are under /dev but already have stable paths */
    if (pool->def->type == VIR_STORAGE_POOL_LOGICAL)
        goto ret_strdup;

    /* We loop here because /dev/disk/by-{id,path} may not have existed
     * before we started this operation, so we have to give it some time to
     * get created.
     */
 reopen:
    if ((dh = opendir(pool->def->target.path)) == NULL) {
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
     * up, so add timeout to retry here.
     */
 retry:
    while ((dent = readdir(dh)) != NULL) {
        if (dent->d_name[0] == '.')
            continue;

        if (virAsprintf(&stablepath, "%s/%s",
                        pool->def->target.path,
                        dent->d_name) == -1) {
            closedir(dh);
            return NULL;
        }

        if (virFileLinkPointsTo(stablepath, devpath)) {
            closedir(dh);
            return stablepath;
        }

        VIR_FREE(stablepath);
    }

    if (loop && ++retry < 100) {
        usleep(100 * 1000);
        goto retry;
    }

    closedir(dh);

 ret_strdup:
    /* Couldn't find any matching stable link so give back
     * the original non-stable dev path
     */

    ignore_value(VIR_STRDUP(stablepath, devpath));

    return stablepath;
}


#ifndef WIN32
/*
 * Run an external program.
 *
 * Read its output and apply a series of regexes to each line
 * When the entire set of regexes has matched consecutively
 * then run a callback passing in all the matches
 */
int
virStorageBackendRunProgRegex(virStoragePoolObjPtr pool,
                              virCommandPtr cmd,
                              int nregex,
                              const char **regex,
                              int *nvars,
                              virStorageBackendListVolRegexFunc func,
                              void *data, const char *prefix)
{
    int fd = -1, err, ret = -1;
    FILE *list = NULL;
    regex_t *reg;
    regmatch_t *vars = NULL;
    char line[1024];
    int maxReg = 0;
    size_t i, j;
    int totgroups = 0, ngroup = 0, maxvars = 0;
    char **groups;

    /* Compile all regular expressions */
    if (VIR_ALLOC_N(reg, nregex) < 0)
        return -1;

    for (i = 0; i < nregex; i++) {
        err = regcomp(&reg[i], regex[i], REG_EXTENDED);
        if (err != 0) {
            char error[100];
            regerror(err, &reg[i], error, sizeof(error));
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to compile regex %s"), error);
            for (j = 0; j < i; j++)
                regfree(&reg[j]);
            VIR_FREE(reg);
            return -1;
        }

        totgroups += nvars[i];
        if (nvars[i] > maxvars)
            maxvars = nvars[i];

    }

    /* Storage for matched variables */
    if (VIR_ALLOC_N(groups, totgroups) < 0)
        goto cleanup;
    if (VIR_ALLOC_N(vars, maxvars+1) < 0)
        goto cleanup;

    virCommandSetOutputFD(cmd, &fd);
    if (virCommandRunAsync(cmd, NULL) < 0) {
        goto cleanup;
    }

    if ((list = VIR_FDOPEN(fd, "r")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot read fd"));
        goto cleanup;
    }

    while (fgets(line, sizeof(line), list) != NULL) {
        char *p = NULL;
        /* Strip trailing newline */
        int len = strlen(line);
        if (len && line[len-1] == '\n')
            line[len-1] = '\0';

        /* ignore any command prefix */
        if (prefix)
            p = STRSKIP(line, prefix);
        if (!p)
            p = line;

        for (i = 0; i <= maxReg && i < nregex; i++) {
            if (regexec(&reg[i], p, nvars[i]+1, vars, 0) == 0) {
                maxReg++;

                if (i == 0)
                    ngroup = 0;

                /* NULL terminate each captured group in the line */
                for (j = 0; j < nvars[i]; j++) {
                    /* NB vars[0] is the full pattern, so we offset j by 1 */
                    p[vars[j+1].rm_eo] = '\0';
                    if (VIR_STRDUP(groups[ngroup++], p + vars[j+1].rm_so) < 0)
                        goto cleanup;
                }

                /* We're matching on the last regex, so callback time */
                if (i == (nregex-1)) {
                    if (((*func)(pool, groups, data)) < 0)
                        goto cleanup;

                    /* Release matches & restart to matching the first regex */
                    for (j = 0; j < totgroups; j++)
                        VIR_FREE(groups[j]);
                    maxReg = 0;
                    ngroup = 0;
                }
            }
        }
    }

    ret = virCommandWait(cmd, NULL);
cleanup:
    if (groups) {
        for (j = 0; j < totgroups; j++)
            VIR_FREE(groups[j]);
        VIR_FREE(groups);
    }
    VIR_FREE(vars);

    for (i = 0; i < nregex; i++)
        regfree(&reg[i]);

    VIR_FREE(reg);

    VIR_FORCE_FCLOSE(list);
    VIR_FORCE_CLOSE(fd);

    return ret;
}

/*
 * Run an external program and read from its standard output
 * a stream of tokens from IN_STREAM, applying FUNC to
 * each successive sequence of N_COLUMNS tokens.
 * If FUNC returns < 0, stop processing input and return -1.
 * Return -1 if N_COLUMNS == 0.
 * Return -1 upon memory allocation error.
 * If the number of input tokens is not a multiple of N_COLUMNS,
 * then the final FUNC call will specify a number smaller than N_COLUMNS.
 * If there are no input tokens (empty input), call FUNC with N_COLUMNS == 0.
 */
int
virStorageBackendRunProgNul(virStoragePoolObjPtr pool,
                            virCommandPtr cmd,
                            size_t n_columns,
                            virStorageBackendListVolNulFunc func,
                            void *data)
{
    size_t n_tok = 0;
    int fd = -1;
    FILE *fp = NULL;
    char **v;
    int ret = -1;
    size_t i;

    if (n_columns == 0)
        return -1;

    if (VIR_ALLOC_N(v, n_columns) < 0)
        return -1;
    for (i = 0; i < n_columns; i++)
        v[i] = NULL;

    virCommandSetOutputFD(cmd, &fd);
    if (virCommandRunAsync(cmd, NULL) < 0) {
        goto cleanup;
    }

    if ((fp = VIR_FDOPEN(fd, "r")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot open file using fd"));
        goto cleanup;
    }

    while (1) {
        char *buf = NULL;
        size_t buf_len = 0;
        /* Be careful: even when it returns -1,
           this use of getdelim allocates memory.  */
        ssize_t tok_len = getdelim(&buf, &buf_len, 0, fp);
        v[n_tok] = buf;
        if (tok_len < 0) {
            /* Maybe EOF, maybe an error.
               If n_tok > 0, then we know it's an error.  */
            if (n_tok && func(pool, n_tok, v, data) < 0)
                goto cleanup;
            break;
        }
        ++n_tok;
        if (n_tok == n_columns) {
            if (func(pool, n_tok, v, data) < 0)
                goto cleanup;
            n_tok = 0;
            for (i = 0; i < n_columns; i++) {
                VIR_FREE(v[i]);
            }
        }
    }

    if (feof(fp) < 0) {
        virReportSystemError(errno, "%s",
                             _("read error on pipe"));
        goto cleanup;
    }

    ret = virCommandWait(cmd, NULL);
 cleanup:
    for (i = 0; i < n_columns; i++)
        VIR_FREE(v[i]);
    VIR_FREE(v);

    VIR_FORCE_FCLOSE(fp);
    VIR_FORCE_CLOSE(fd);

    return ret;
}

#else /* WIN32 */

int
virStorageBackendRunProgRegex(virConnectPtr conn,
                              virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              const char *const*prog ATTRIBUTE_UNUSED,
                              int nregex ATTRIBUTE_UNUSED,
                              const char **regex ATTRIBUTE_UNUSED,
                              int *nvars ATTRIBUTE_UNUSED,
                              virStorageBackendListVolRegexFunc func ATTRIBUTE_UNUSED,
                              void *data ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("%s not implemented on Win32"), __FUNCTION__);
    return -1;
}

int
virStorageBackendRunProgNul(virConnectPtr conn,
                            virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                            const char **prog ATTRIBUTE_UNUSED,
                            size_t n_columns ATTRIBUTE_UNUSED,
                            virStorageBackendListVolNulFunc func ATTRIBUTE_UNUSED,
                            void *data ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("%s not implemented on Win32"), __FUNCTION__);
    return -1;
}
#endif /* WIN32 */
