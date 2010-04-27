/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#if HAVE_REGEX_H
# include <regex.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>

#if HAVE_SELINUX
# include <selinux/selinux.h>
#endif

#include "datatypes.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "internal.h"
#include "secret_conf.h"
#include "uuid.h"
#include "storage_file.h"
#include "storage_backend.h"
#include "logging.h"

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
    NULL
};

static int track_allocation_progress = 0;

enum {
    TOOL_QEMU_IMG,
    TOOL_KVM_IMG,
    TOOL_QCOW_CREATE,
};

static int ATTRIBUTE_NONNULL (2)
virStorageBackendCopyToFD(virStorageVolDefPtr vol,
                          virStorageVolDefPtr inputvol,
                          int fd,
                          unsigned long long *total,
                          int is_dest_file)
{
    int inputfd = -1;
    int amtread = -1;
    int ret = -1;
    unsigned long long remain;
    size_t bytes = 1024 * 1024;
    char zerobuf[512];
    char *buf = NULL;

    if ((inputfd = open(inputvol->target.path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("could not open input path '%s'"),
                             inputvol->target.path);
        goto cleanup;
    }

    bzero(&zerobuf, sizeof(zerobuf));

    if (VIR_ALLOC_N(buf, bytes) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    remain = *total;

    while (amtread != 0) {
        int amtleft;

        if (remain < bytes)
            bytes = remain;

        if ((amtread = saferead(inputfd, buf, bytes)) < 0) {
            virReportSystemError(errno,
                                 _("failed reading from file '%s'"),
                                 inputvol->target.path);
            goto cleanup;
        }
        remain -= amtread;

        /* Loop over amt read in 512 byte increments, looking for sparse
         * blocks */
        amtleft = amtread;
        do {
            int interval = ((512 > amtleft) ? amtleft : 512);
            int offset = amtread - amtleft;

            if (is_dest_file && memcmp(buf+offset, zerobuf, interval) == 0) {
                if (lseek(fd, interval, SEEK_CUR) < 0) {
                    virReportSystemError(errno,
                                         _("cannot extend file '%s'"),
                                         vol->target.path);
                    goto cleanup;
                }
            } else if (safewrite(fd, buf+offset, interval) < 0) {
                virReportSystemError(errno,
                                     _("failed writing to file '%s'"),
                                     vol->target.path);
                goto cleanup;

            }
        } while ((amtleft -= 512) > 0);
    }

    if (inputfd != -1 && close(inputfd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             inputvol->target.path);
        goto cleanup;
    }
    inputfd = -1;

    *total -= remain;
    ret = 0;

cleanup:
    if (inputfd != -1)
        close(inputfd);

    VIR_FREE(buf);

    return ret;
}

static int
virStorageBackendCreateBlockFrom(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 virStorageVolDefPtr vol,
                                 virStorageVolDefPtr inputvol,
                                 unsigned int flags ATTRIBUTE_UNUSED)
{
    int fd = -1;
    int ret = -1;
    unsigned long long remain;
    struct stat st;
    gid_t gid;
    uid_t uid;

    if ((fd = open(vol->target.path, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    remain = vol->allocation;

    if (inputvol) {
        int res = virStorageBackendCopyToFD(vol, inputvol,
                                            fd, &remain, 0);
        if (res < 0)
            goto cleanup;
    }

    if (fstat(fd, &st) == -1) {
        ret = errno;
        virReportSystemError(errno, _("stat of '%s' failed"),
                             vol->target.path);
        goto cleanup;
    }
    uid = (vol->target.perms.uid != st.st_uid) ? vol->target.perms.uid : -1;
    gid = (vol->target.perms.gid != st.st_gid) ? vol->target.perms.gid : -1;
    if (((uid != -1) || (gid != -1))
        && (fchown(fd, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown '%s' to (%u, %u)"),
                             vol->target.path, uid, gid);
        goto cleanup;
    }
    if (fchmod(fd, vol->target.perms.mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             vol->target.path, vol->target.perms.mode);
        goto cleanup;
    }
    if (close(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        goto cleanup;
    }
    fd = -1;

    ret = 0;
cleanup:
    if (fd != -1)
        close(fd);

    return ret;
}

struct createRawFileOpHookData {
    virStorageVolDefPtr vol;
    virStorageVolDefPtr inputvol;
};

static int createRawFileOpHook(int fd, void *data) {
    struct createRawFileOpHookData *hdata = data;
    int ret = 0;
    unsigned long long remain;

    /* Seek to the final size, so the capacity is available upfront
     * for progress reporting */
    if (ftruncate(fd, hdata->vol->capacity) < 0) {
        ret = errno;
        virReportSystemError(errno,
                             _("cannot extend file '%s'"),
                             hdata->vol->target.path);
        goto cleanup;
    }

    remain = hdata->vol->allocation;

    if (hdata->inputvol) {
        int res = virStorageBackendCopyToFD(hdata->vol, hdata->inputvol,
                                            fd, &remain, 1);
        if (res < 0)
            ret = -res;
            goto cleanup;
    }

    if (remain) {
        if (track_allocation_progress) {

            while (remain) {
                /* Allocate in chunks of 512MiB: big-enough chunk
                 * size and takes approx. 9s on ext3. A progress
                 * update every 9s is a fair-enough trade-off
                 */
                unsigned long long bytes = 512 * 1024 * 1024;

                if (bytes > remain)
                    bytes = remain;
                if (safezero(fd, 0, hdata->vol->allocation - remain,
                             bytes) != 0) {
                    ret = errno;
                    virReportSystemError(errno, _("cannot fill file '%s'"),
                                         hdata->vol->target.path);
                    goto cleanup;
                }
                remain -= bytes;
            }
        } else { /* No progress bars to be shown */
            if (safezero(fd, 0, 0, remain) != 0) {
                ret = errno;
                virReportSystemError(errno, _("cannot fill file '%s'"),
                                     hdata->vol->target.path);
                goto cleanup;
            }
        }

        if (fsync(fd) < 0) {
            ret = errno;
            virReportSystemError(errno, _("cannot sync data to file '%s'"),
                                 hdata->vol->target.path);
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

int
virStorageBackendCreateRaw(virConnectPtr conn ATTRIBUTE_UNUSED,
                           virStoragePoolObjPtr pool,
                           virStorageVolDefPtr vol,
                           virStorageVolDefPtr inputvol,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret = -1;
    int createstat;
    struct createRawFileOpHookData hdata = { vol, inputvol };

    if (vol->target.encryption != NULL) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support encrypted "
                                      "volumes"));
        goto cleanup;
    }

    uid_t uid = (vol->target.perms.uid == -1) ? getuid() : vol->target.perms.uid;
    gid_t gid = (vol->target.perms.gid == -1) ? getgid() : vol->target.perms.gid;

    if ((createstat = virFileOperation(vol->target.path,
                                       O_RDWR | O_CREAT | O_EXCL,
                                       vol->target.perms.mode, uid, gid,
                                       createRawFileOpHook, &hdata,
                                       VIR_FILE_OP_FORCE_PERMS |
                                       (pool->def->type == VIR_STORAGE_POOL_NETFS
                                        ? VIR_FILE_OP_AS_UID : 0))) < 0) {
    virReportSystemError(createstat,
                         _("cannot create path '%s'"),
                         vol->target.path);
    goto cleanup;
    }

    ret = 0;
cleanup:
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
            virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                  _("unable to generate uuid"));
            return -1;
        }
        tmp = conn->secretDriver->lookupByUUID(conn, uuid);
        if (tmp == NULL)
            return 0;

        virSecretFree(tmp);
    }

    virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        conn->secretDriver->lookupByUUID == NULL ||
        conn->secretDriver->defineXML == NULL ||
        conn->secretDriver->setValue == NULL) {
        virStorageReportError(VIR_ERR_NO_SUPPORT, "%s",
                              _("secret storage not supported"));
        goto cleanup;
    }

    enc = vol->target.encryption;
    if (enc->nsecrets != 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                              _("secrets already defined"));
        goto cleanup;
    }

    if (VIR_ALLOC(enc_secret) < 0 || VIR_REALLOC_N(enc->secrets, 1) < 0 ||
        VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    def->ephemeral = 0;
    def->private = 0;
    if (virStorageGenerateSecretUUID(conn, def->uuid) < 0)
        goto cleanup;

    def->usage_type = VIR_SECRET_USAGE_TYPE_VOLUME;
    def->usage.volume = strdup(vol->target.path);
    if (def->usage.volume == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    xml = virSecretDefFormat(def);
    virSecretDefFree(def);
    def = NULL;
    if (xml == NULL)
        goto cleanup;

    secret = conn->secretDriver->defineXML(conn, xml, 0);
    if (secret == NULL) {
        VIR_FREE(xml);
        goto cleanup;
    }
    VIR_FREE(xml);

    if (virStorageGenerateQcowPassphrase(value) < 0)
        goto cleanup;

    if (conn->secretDriver->setValue(secret, value, sizeof(value), 0) < 0)
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
            conn->secretDriver->undefine != NULL)
            conn->secretDriver->undefine(secret);
        virSecretFree(secret);
    }
    virBufferFreeAndReset(&buf);
    virSecretDefFree(def);
    VIR_FREE(enc_secret);
    return ret;
}

static int virStorageBuildSetUIDHook(void *data) {
    virStorageVolDefPtr vol = data;

    if ((vol->target.perms.gid != -1)
        && (setgid(vol->target.perms.gid) != 0)) {
        virReportSystemError(errno,
                             _("Cannot set gid to %u before creating %s"),
                             vol->target.perms.gid, vol->target.path);
        return -1;
    }
    if ((vol->target.perms.uid != -1)
        && (setuid(vol->target.perms.uid) != 0)) {
        virReportSystemError(errno,
                             _("Cannot set uid to %u before creating %s"),
                             vol->target.perms.uid, vol->target.path);
        return -1;
    }
    return 0;
}

static int virStorageBackendCreateExecCommand(virStoragePoolObjPtr pool,
                                              virStorageVolDefPtr vol,
                                              const char **cmdargv) {
    struct stat st;
    gid_t gid;
    uid_t uid;
    int filecreated = 0;

    if ((pool->def->type == VIR_STORAGE_POOL_NETFS)
        && (((getuid() == 0)
             && (vol->target.perms.uid != -1)
             && (vol->target.perms.uid != 0))
            || ((vol->target.perms.gid != -1)
                && (vol->target.perms.gid != getgid())))) {
        if (virRunWithHook(cmdargv,
                           virStorageBuildSetUIDHook, vol, NULL) == 0) {
            /* command was successfully run, check if the file was created */
            if (stat(vol->target.path, &st) >=0)
                filecreated = 1;
        }
    }
    if (!filecreated) {
        if (virRun(cmdargv, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Cannot run %s to create %s"),
                                 cmdargv[0], vol->target.path);
            return -1;
        }
        if (stat(vol->target.path, &st) < 0) {
            virReportSystemError(errno,
                                 _("%s failed to create %s"),
                                 cmdargv[0], vol->target.path);
            return -1;
        }
    }

    uid = (vol->target.perms.uid != st.st_uid) ? vol->target.perms.uid : -1;
    gid = (vol->target.perms.gid != st.st_gid) ? vol->target.perms.gid : -1;
    if (((uid != -1) || (gid != -1))
        && (chown(vol->target.path, uid, gid) < 0)) {
        virReportSystemError(errno,
                             _("cannot chown %s to (%u, %u)"),
                             vol->target.path, uid, gid);
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

static int
virStorageBackendCreateQemuImg(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               virStorageVolDefPtr inputvol,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret;
    char size[100];
    char *create_tool;
    short use_kvmimg;

    const char *type = virStorageFileFormatTypeToString(vol->target.format);
    const char *backingType = vol->backingStore.path ?
        virStorageFileFormatTypeToString(vol->backingStore.format) : NULL;

    const char *inputBackingPath = (inputvol ? inputvol->backingStore.path
                                             : NULL);
    const char *inputPath = inputvol ? inputvol->target.path : NULL;
    /* Treat input block devices as 'raw' format */
    const char *inputType = inputPath ?
                            virStorageFileFormatTypeToString(inputvol->type == VIR_STORAGE_VOL_BLOCK ? VIR_STORAGE_FILE_RAW : inputvol->target.format) :
                            NULL;

    const char **imgargv;
    /* The extra NULL field is for indicating encryption (-e). */
    const char *imgargvnormal[] = {
        NULL, "create",
        "-f", type,
        vol->target.path,
        size,
        NULL,
        NULL
    };
    /* Extra NULL fields are for including "backingType" when using
     * kvm-img (-F backingType), and for indicating encryption (-e).
     */
    const char *imgargvbacking[] = {
        NULL, "create",
        "-f", type,
        "-b", vol->backingStore.path,
        vol->target.path,
        size,
        NULL,
        NULL,
        NULL,
        NULL
    };
    const char *convargv[] = {
        NULL, "convert",
        "-f", inputType,
        "-O", type,
        inputPath,
        vol->target.path,
        NULL,
    };

    if (type == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage vol type %d"),
                              vol->target.format);
        return -1;
    }
    if (inputvol && inputType == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage vol type %d"),
                              inputvol->target.format);
        return -1;
    }

    if (vol->backingStore.path) {

        /* XXX: Not strictly required: qemu-img has an option a different
         * backing store, not really sure what use it serves though, and it
         * may cause issues with lvm. Untested essentially.
         */
        if (inputvol &&
            (!inputBackingPath ||
             STRNEQ(inputBackingPath, vol->backingStore.path))) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("a different backing store can not "
                                          "be specified."));
            return -1;
        }

        if (backingType == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("unknown storage vol backing store type %d"),
                                  vol->backingStore.format);
            return -1;
        }
        if (access(vol->backingStore.path, R_OK) != 0) {
            virReportSystemError(errno,
                                 _("inaccessible backing store volume %s"),
                                 vol->backingStore.path);
            return -1;
        }
    }

    if (vol->target.encryption != NULL) {
        virStorageEncryptionPtr enc;

        if (vol->target.format != VIR_STORAGE_FILE_QCOW &&
            vol->target.format != VIR_STORAGE_FILE_QCOW2) {
            virStorageReportError(VIR_ERR_NO_SUPPORT,
                                  _("qcow volume encryption unsupported with "
                                    "volume format %s"), type);
            return -1;
        }
        enc = vol->target.encryption;
        if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_QCOW &&
            enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT) {
            virStorageReportError(VIR_ERR_NO_SUPPORT,
                                  _("unsupported volume encryption format %d"),
                                  vol->target.encryption->format);
            return -1;
        }
        if (enc->nsecrets > 1) {
            virStorageReportError(VIR_ERR_INVALID_STORAGE_VOL, "%s",
                                  _("too many secrets for qcow encryption"));
            return -1;
        }
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT ||
            enc->nsecrets == 0) {
            if (virStorageGenerateQcowEncryption(conn, vol) < 0)
                return -1;
        }
    }

    if ((create_tool = virFindFileInPath("kvm-img")) != NULL)
        use_kvmimg = 1;
    else if ((create_tool = virFindFileInPath("qemu-img")) != NULL)
        use_kvmimg = 0;
    else {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unable to find kvm-img or qemu-img"));
        return -1;
    }

    if (inputvol) {
        convargv[0] = create_tool;
        imgargv = convargv;
    } else if (vol->backingStore.path) {
        imgargvbacking[0] = create_tool;
        if (use_kvmimg) {
            imgargvbacking[6] = "-F";
            imgargvbacking[7] = backingType;
            imgargvbacking[8] = vol->target.path;
            imgargvbacking[9] = size;
            if (vol->target.encryption != NULL)
                imgargvbacking[10] = "-e";
        } else if (vol->target.encryption != NULL)
            imgargvbacking[8] = "-e";
        imgargv = imgargvbacking;
    } else {
        imgargvnormal[0] = create_tool;
        imgargv = imgargvnormal;
        if (vol->target.encryption != NULL)
            imgargv[6] = "-e";
    }


    /* Size in KB */
    snprintf(size, sizeof(size), "%lluK", vol->capacity/1024);

    ret = virStorageBackendCreateExecCommand(pool, vol, imgargv);
    VIR_FREE(imgargv[0]);

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
                                  unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret;
    char size[100];
    const char *imgargv[4];

    if (inputvol) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                              _("cannot copy from volume with qcow-create"));
        return -1;
    }

    if (vol->target.format != VIR_STORAGE_FILE_QCOW2) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("unsupported storage vol type %d"),
                              vol->target.format);
        return -1;
    }
    if (vol->backingStore.path != NULL) {
        virStorageReportError(VIR_ERR_NO_SUPPORT, "%s",
                              _("copy-on-write image not supported with "
                                      "qcow-create"));
        return -1;
    }
    if (vol->target.encryption != NULL) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("encrypted volumes not supported with "
                                      "qcow-create"));
        return -1;
    }

    /* Size in MB - yes different units to qemu-img :-( */
    snprintf(size, sizeof(size), "%llu", vol->capacity/1024/1024);

    imgargv[0] = virFindFileInPath("qcow-create");
    imgargv[1] = size;
    imgargv[2] = vol->target.path;
    imgargv[3] = NULL;

    ret = virStorageBackendCreateExecCommand(pool, vol, imgargv);
    VIR_FREE(imgargv[0]);

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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
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
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("creation of non-raw file images is "
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
virStorageBackendForType(int type) {
    unsigned int i;
    for (i = 0; backends[i]; i++)
        if (backends[i]->type == type)
            return backends[i];

    virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                          _("missing backend for pool type %d"), type);
    return NULL;
}


int
virStorageBackendUpdateVolTargetInfo(virStorageVolTargetPtr target,
                                     unsigned long long *allocation,
                                     unsigned long long *capacity)
{
    int ret, fd;

    if ((fd = open(target->path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot open volume '%s'"),
                             target->path);
        return -1;
    }

    ret = virStorageBackendUpdateVolTargetInfoFD(target,
                                                 fd,
                                                 allocation,
                                                 capacity);

    close(fd);

    return ret;
}

int
virStorageBackendUpdateVolInfo(virStorageVolDefPtr vol,
                               int withCapacity)
{
    int ret;

    if ((ret = virStorageBackendUpdateVolTargetInfo(&vol->target,
                                                    &vol->allocation,
                                                    withCapacity ? &vol->capacity : NULL)) < 0)
        return ret;

    if (vol->backingStore.path &&
        (ret = virStorageBackendUpdateVolTargetInfo(&vol->backingStore,
                                                    NULL, NULL)) < 0)
        return ret;

    return 0;
}

/*
 * virStorageBackendUpdateVolTargetInfoFD:
 * @conn: connection to report errors on
 * @target: target definition ptr of volume to update
 * @fd: fd of storage volume to update
 * @allocation: If not NULL, updated allocation information will be stored
 * @capacity: If not NULL, updated capacity info will be stored
 *
 * Returns 0 for success-1 on a legitimate error condition,
 *    -2 if passed FD isn't a regular, char, or block file.
 */
int
virStorageBackendUpdateVolTargetInfoFD(virStorageVolTargetPtr target,
                                       int fd,
                                       unsigned long long *allocation,
                                       unsigned long long *capacity)
{
    struct stat sb;
#if HAVE_SELINUX
    security_context_t filecon = NULL;
#endif

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             target->path);
        return -1;
    }

    if (!S_ISREG(sb.st_mode) &&
        !S_ISCHR(sb.st_mode) &&
        !S_ISBLK(sb.st_mode))
        return -2;

    if (allocation) {
        if (S_ISREG(sb.st_mode)) {
#ifndef __MINGW32__
            *allocation = (unsigned long long)sb.st_blocks *
                          (unsigned long long)DEV_BSIZE;
#else
            *allocation = sb.st_size;
#endif
            /* Regular files may be sparse, so logical size (capacity) is not same
             * as actual allocation above
             */
            if (capacity)
                *capacity = sb.st_size;
        } else {
            off_t end;
            /* XXX this is POSIX compliant, but doesn't work for for CHAR files,
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

    target->perms.mode = sb.st_mode & S_IRWXUGO;
    target->perms.uid = sb.st_uid;
    target->perms.gid = sb.st_gid;

    VIR_FREE(target->perms.label);

#if HAVE_SELINUX
    /* XXX: make this a security driver call */
    if (fgetfilecon(fd, &filecon) == -1) {
        if (errno != ENODATA && errno != ENOTSUP) {
            virReportSystemError(errno,
                                 _("cannot get file context of '%s'"),
                                 target->path);
            return -1;
        } else {
            target->perms.label = NULL;
        }
    } else {
        target->perms.label = strdup(filecon);
        if (target->perms.label == NULL) {
            virReportOOMError();
            return -1;
        }
        freecon(filecon);
    }
#else
    target->perms.label = NULL;
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
virStorageBackendUpdateVolTargetFormatFD(virStorageVolTargetPtr target,
                                         int fd)
{
    int i;
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
 */
char *
virStorageBackendStablePath(virStoragePoolObjPtr pool,
                            const char *devpath)
{
    DIR *dh;
    struct dirent *dent;
    char *stablepath;
    int opentries = 0;

    /* Short circuit if pool has no target, or if its /dev */
    if (pool->def->target.path == NULL ||
        STREQ(pool->def->target.path, "/dev") ||
        STREQ(pool->def->target.path, "/dev/"))
        goto ret_strdup;

    /* Skip whole thing for a pool which isn't in /dev
     * so we don't mess will filesystem/dir based pools
     */
    if (!STRPREFIX(pool->def->target.path, "/dev"))
        goto ret_strdup;

    /* We loop here because /dev/disk/by-{id,path} may not have existed
     * before we started this operation, so we have to give it some time to
     * get created.
     */
 reopen:
    if ((dh = opendir(pool->def->target.path)) == NULL) {
        opentries++;
        if (errno == ENOENT && opentries < 50) {
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
     * to this device node
     */
    while ((dent = readdir(dh)) != NULL) {
        if (dent->d_name[0] == '.')
            continue;

        if (virAsprintf(&stablepath, "%s/%s",
                        pool->def->target.path,
                        dent->d_name) == -1) {
            virReportOOMError();
            closedir(dh);
            return NULL;
        }

        if (virFileLinkPointsTo(stablepath, devpath)) {
            closedir(dh);
            return stablepath;
        }

        VIR_FREE(stablepath);
    }

    closedir(dh);

 ret_strdup:
    /* Couldn't find any matching stable link so give back
     * the original non-stable dev path
     */

    stablepath = strdup(devpath);

    if (stablepath == NULL)
        virReportOOMError();

    return stablepath;
}


#ifndef __MINGW32__
/*
 * Run an external program.
 *
 * Read its output and apply a series of regexes to each line
 * When the entire set of regexes has matched consecutively
 * then run a callback passing in all the matches
 */
int
virStorageBackendRunProgRegex(virStoragePoolObjPtr pool,
                              const char *const*prog,
                              int nregex,
                              const char **regex,
                              int *nvars,
                              virStorageBackendListVolRegexFunc func,
                              void *data,
                              int *outexit)
{
    int fd = -1, exitstatus, err, failed = 1;
    pid_t child = 0;
    FILE *list = NULL;
    regex_t *reg;
    regmatch_t *vars = NULL;
    char line[1024];
    int maxReg = 0, i, j;
    int totgroups = 0, ngroup = 0, maxvars = 0;
    char **groups;

    /* Compile all regular expressions */
    if (VIR_ALLOC_N(reg, nregex) < 0) {
        virReportOOMError();
        return -1;
    }

    for (i = 0 ; i < nregex ; i++) {
        err = regcomp(&reg[i], regex[i], REG_EXTENDED);
        if (err != 0) {
            char error[100];
            regerror(err, &reg[i], error, sizeof(error));
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to compile regex %s"), error);
            for (j = 0 ; j <= i ; j++)
                regfree(&reg[j]);
            VIR_FREE(reg);
            return -1;
        }

        totgroups += nvars[i];
        if (nvars[i] > maxvars)
            maxvars = nvars[i];

    }

    /* Storage for matched variables */
    if (VIR_ALLOC_N(groups, totgroups) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (VIR_ALLOC_N(vars, maxvars+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }


    /* Run the program and capture its output */
    if (virExec(prog, NULL, NULL,
                &child, -1, &fd, NULL, VIR_EXEC_NONE) < 0) {
        goto cleanup;
    }

    if ((list = fdopen(fd, "r")) == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot read fd"));
        goto cleanup;
    }

    while (fgets(line, sizeof(line), list) != NULL) {
        /* Strip trailing newline */
        int len = strlen(line);
        if (len && line[len-1] == '\n')
            line[len-1] = '\0';

        for (i = 0 ; i <= maxReg && i < nregex ; i++) {
            if (regexec(&reg[i], line, nvars[i]+1, vars, 0) == 0) {
                maxReg++;

                if (i == 0)
                    ngroup = 0;

                /* NULL terminate each captured group in the line */
                for (j = 0 ; j < nvars[i] ; j++) {
                    /* NB vars[0] is the full pattern, so we offset j by 1 */
                    line[vars[j+1].rm_eo] = '\0';
                    if ((groups[ngroup++] =
                         strdup(line + vars[j+1].rm_so)) == NULL) {
                        virReportOOMError();
                        goto cleanup;
                    }
                }

                /* We're matching on the last regex, so callback time */
                if (i == (nregex-1)) {
                    if (((*func)(pool, groups, data)) < 0)
                        goto cleanup;

                    /* Release matches & restart to matching the first regex */
                    for (j = 0 ; j < totgroups ; j++)
                        VIR_FREE(groups[j]);
                    maxReg = 0;
                    ngroup = 0;
                }
            }
        }
    }

    failed = 0;

 cleanup:
    if (groups) {
        for (j = 0 ; j < totgroups ; j++)
            VIR_FREE(groups[j]);
        VIR_FREE(groups);
    }
    VIR_FREE(vars);

    for (i = 0 ; i < nregex ; i++)
        regfree(&reg[i]);

    VIR_FREE(reg);

    if (list)
        fclose(list);
    else {
        if (fd >= 0)
            close(fd);
    }

    while ((err = waitpid(child, &exitstatus, 0) == -1) && errno == EINTR);

    /* Don't bother checking exit status if we already failed */
    if (failed)
        return -1;

    if (err == -1) {
        virReportSystemError(errno,
                             _("failed to wait for command '%s'"),
                             prog[0]);
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (outexit != NULL)
                *outexit = WEXITSTATUS(exitstatus);
        } else {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("command did not exit cleanly"));
            return -1;
        }
    }

    return 0;
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
                            const char **prog,
                            size_t n_columns,
                            virStorageBackendListVolNulFunc func,
                            void *data)
{
    size_t n_tok = 0;
    int fd = -1, exitstatus;
    pid_t child = 0;
    FILE *fp = NULL;
    char **v;
    int err = -1;
    int w_err;
    int i;

    if (n_columns == 0)
        return -1;

    if (VIR_ALLOC_N(v, n_columns) < 0) {
        virReportOOMError();
        return -1;
    }
    for (i = 0; i < n_columns; i++)
        v[i] = NULL;

    /* Run the program and capture its output */
    if (virExec(prog, NULL, NULL,
                &child, -1, &fd, NULL, VIR_EXEC_NONE) < 0) {
        goto cleanup;
    }

    if ((fp = fdopen(fd, "r")) == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot read fd"));
        goto cleanup;
    }

    while (1) {
        char *buf = NULL;
        size_t buf_len = 0;
        /* Be careful: even when it returns -1,
           this use of getdelim allocates memory.  */
        ssize_t tok_len = getdelim (&buf, &buf_len, 0, fp);
        v[n_tok] = buf;
        if (tok_len < 0) {
            /* Maybe EOF, maybe an error.
               If n_tok > 0, then we know it's an error.  */
            if (n_tok && func (pool, n_tok, v, data) < 0)
                goto cleanup;
            break;
        }
        ++n_tok;
        if (n_tok == n_columns) {
            if (func (pool, n_tok, v, data) < 0)
                goto cleanup;
            n_tok = 0;
            for (i = 0; i < n_columns; i++) {
                VIR_FREE(v[i]);
            }
        }
    }

    if (feof (fp))
        err = 0;
    else
        virReportSystemError(errno,
                             _("read error on pipe to '%s'"), prog[0]);

 cleanup:
    for (i = 0; i < n_columns; i++)
        VIR_FREE(v[i]);
    VIR_FREE(v);

    if (fp)
        fclose (fp);
    else
        close (fd);

    while ((w_err = waitpid (child, &exitstatus, 0) == -1) && errno == EINTR)
        /* empty */ ;

    /* Don't bother checking exit status if we already failed */
    if (err < 0)
        return -1;

    if (w_err == -1) {
        virReportSystemError(errno,
                             _("failed to wait for command '%s'"),
                             prog[0]);
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (WEXITSTATUS(exitstatus) != 0) {
                virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                      _("non-zero exit status from command %d"),
                                      WEXITSTATUS(exitstatus));
                return -1;
            }
        } else {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("command did not exit cleanly"));
            return -1;
        }
    }

    return 0;
}

#else

int
virStorageBackendRunProgRegex(virConnectPtr conn,
                              virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              const char *const*prog ATTRIBUTE_UNUSED,
                              int nregex ATTRIBUTE_UNUSED,
                              const char **regex ATTRIBUTE_UNUSED,
                              int *nvars ATTRIBUTE_UNUSED,
                              virStorageBackendListVolRegexFunc func ATTRIBUTE_UNUSED,
                              void *data ATTRIBUTE_UNUSED,
                              int *outexit ATTRIBUTE_UNUSED)
{
    virStorageReportError(VIR_ERR_INTERNAL_ERROR, _("%s not implemented on Win32"), __FUNCTION__);
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
    virStorageReportError(VIR_ERR_INTERNAL_ERROR, _("%s not implemented on Win32"), __FUNCTION__);
    return -1;
}
#endif
