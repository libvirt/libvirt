/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2008 Red Hat, Inc.
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
#include <regex.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "node_device.h"

#include "storage_backend.h"

#if WITH_STORAGE_LVM
#include "storage_backend_logical.h"
#endif
#if WITH_STORAGE_ISCSI
#include "storage_backend_iscsi.h"
#endif
#if WITH_STORAGE_SCSI
#include "storage_backend_scsi.h"
#endif
#if WITH_STORAGE_DISK
#include "storage_backend_disk.h"
#endif
#if WITH_STORAGE_DIR
#include "storage_backend_fs.h"
#endif

#ifndef DEV_BSIZE
#define DEV_BSIZE 512
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

static int
virStorageBackendCopyToFD(virConnectPtr conn,
                          virStorageVolDefPtr vol,
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

    if (inputvol) {
        if ((inputfd = open(inputvol->target.path, O_RDONLY)) < 0) {
            virReportSystemError(conn, errno,
                                 _("could not open input path '%s'"),
                                 inputvol->target.path);
            goto cleanup;
        }
    }

    bzero(&zerobuf, sizeof(zerobuf));

    if (VIR_ALLOC_N(buf, bytes) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    remain = *total;

    while (amtread != 0) {
        int amtleft;

        if (remain < bytes)
            bytes = remain;

        if ((amtread = saferead(inputfd, buf, bytes)) < 0) {
            virReportSystemError(conn, errno,
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
                    virReportSystemError(conn, errno,
                                         _("cannot extend file '%s'"),
                                         vol->target.path);
                    goto cleanup;
                }
            } else if (safewrite(fd, buf+offset, interval) < 0) {
                virReportSystemError(conn, errno,
                                     _("failed writing to file '%s'"),
                                     vol->target.path);
                goto cleanup;

            }
        } while ((amtleft -= 512) > 0);
    }

    if (inputfd != -1 && close(inputfd) < 0) {
        virReportSystemError(conn, errno,
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

    return ret;
}

static int
virStorageBackendCreateBlockFrom(virConnectPtr conn,
                                 virStorageVolDefPtr vol,
                                 virStorageVolDefPtr inputvol,
                                 unsigned int flags ATTRIBUTE_UNUSED)
{
    int fd = -1;
    int ret = -1;
    unsigned long long remain;

    if ((fd = open(vol->target.path, O_RDWR)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    remain = vol->allocation;

    if (inputvol) {
        int res = virStorageBackendCopyToFD(conn, vol, inputvol,
                                            fd, &remain, 0);
        if (res < 0)
            goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(conn, errno,
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

int
virStorageBackendCreateRaw(virConnectPtr conn,
                           virStorageVolDefPtr vol,
                           virStorageVolDefPtr inputvol,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    int fd = -1;
    int ret = -1;
    unsigned long long remain;
    char *buf = NULL;

    if ((fd = open(vol->target.path, O_RDWR | O_CREAT | O_EXCL,
                   vol->target.perms.mode)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    /* Seek to the final size, so the capacity is available upfront
     * for progress reporting */
    if (ftruncate(fd, vol->capacity) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot extend file '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    remain = vol->allocation;

    if (inputvol) {
        int res = virStorageBackendCopyToFD(conn, vol, inputvol,
                                            fd, &remain, 1);
        if (res < 0)
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
                int r;

                if (bytes > remain)
                    bytes = remain;
                if ((r = safezero(fd, 0, vol->allocation - remain,
                                  bytes)) != 0) {
                    virReportSystemError(conn, r,
                                         _("cannot fill file '%s'"),
                                         vol->target.path);
                    goto cleanup;
                }
                remain -= bytes;
            }
        } else { /* No progress bars to be shown */
            int r;

            if ((r = safezero(fd, 0, 0, remain)) != 0) {
                virReportSystemError(conn, r,
                                     _("cannot fill file '%s'"),
                                     vol->target.path);
                goto cleanup;
            }
        }
    }

    if (close(fd) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        goto cleanup;
    }
    fd = -1;

    ret = 0;
cleanup:
    if (fd != -1)
        close(fd);
    VIR_FREE(buf);

    return ret;
}

static int
virStorageBackendCreateQemuImg(virConnectPtr conn,
                               virStorageVolDefPtr vol,
                               virStorageVolDefPtr inputvol,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    char size[100];
    char *create_tool;
    short use_kvmimg;

    const char *type = virStorageVolFormatFileSystemTypeToString(vol->target.format);
    const char *backingType = vol->backingStore.path ?
        virStorageVolFormatFileSystemTypeToString(vol->backingStore.format) : NULL;

    const char *inputBackingPath = (inputvol ? inputvol->backingStore.path
                                             : NULL);
    const char *inputPath = inputvol ? inputvol->target.path : NULL;
    /* Treat input block devices as 'raw' format */
    const char *inputType = inputPath ?
                            virStorageVolFormatFileSystemTypeToString(inputvol->type == VIR_STORAGE_VOL_BLOCK ? VIR_STORAGE_VOL_FILE_RAW : inputvol->target.format) :
                            NULL;

    const char **imgargv;
    const char *imgargvnormal[] = {
        NULL, "create",
        "-f", type,
        vol->target.path,
        size,
        NULL,
    };
    /* Extra NULL fields are for including "backingType" when using
     * kvm-img. It's -F backingType
     */
    const char *imgargvbacking[] = {
        NULL, "create",
        "-f", type,
        "-b", vol->backingStore.path,
        vol->target.path,
        size,
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
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage vol type %d"),
                              vol->target.format);
        return -1;
    }
    if (inputvol && inputType == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("a different backing store can not "
                                          "be specified."));
            return -1;
        }

        if (backingType == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown storage vol backing store type %d"),
                                  vol->backingStore.format);
            return -1;
        }
        if (access(vol->backingStore.path, R_OK) != 0) {
            virReportSystemError(conn, errno,
                                 _("inaccessible backing store volume %s"),
                                 vol->backingStore.path);
            return -1;
        }
    }

    if ((create_tool = virFindFileInPath("kvm-img")) != NULL)
        use_kvmimg = 1;
    else if ((create_tool = virFindFileInPath("qemu-img")) != NULL)
        use_kvmimg = 0;
    else {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
        }
        imgargv = imgargvbacking;
    } else {
        imgargvnormal[0] = create_tool;
        imgargv = imgargvnormal;
    }


    /* Size in KB */
    snprintf(size, sizeof(size), "%lluK", vol->capacity/1024);

    if (virRun(conn, imgargv, NULL) < 0) {
        VIR_FREE(imgargv[0]);
        return -1;
    }

    VIR_FREE(imgargv[0]);

    return 0;
}

/*
 * Xen removed the fully-functional qemu-img, and replaced it
 * with a partially functional qcow-create. Go figure ??!?
 */
static int
virStorageBackendCreateQcowCreate(virConnectPtr conn,
                                  virStorageVolDefPtr vol,
                                  virStorageVolDefPtr inputvol,
                                  unsigned int flags ATTRIBUTE_UNUSED)
{
    char size[100];
    const char *imgargv[4];

    if (inputvol) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                              _("cannot copy from volume with qcow-create"));
        return -1;
    }

    if (vol->target.format != VIR_STORAGE_VOL_FILE_QCOW2) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("unsupported storage vol type %d"),
                              vol->target.format);
        return -1;
    }
    if (vol->backingStore.path != NULL) {
        virStorageReportError(conn, VIR_ERR_NO_SUPPORT, "%s",
                              _("copy-on-write image not supported with "
                                      "qcow-create"));
        return -1;
    }

    /* Size in MB - yes different units to qemu-img :-( */
    snprintf(size, sizeof(size), "%llu", vol->capacity/1024/1024);

    imgargv[0] = virFindFileInPath("qcow-create");
    imgargv[1] = size;
    imgargv[2] = vol->target.path;
    imgargv[3] = NULL;

    if (virRun(conn, imgargv, NULL) < 0) {
        VIR_FREE(imgargv[0]);
        return -1;
    }

    VIR_FREE(imgargv[0]);

    return 0;
}

virStorageBackendBuildVolFrom
virStorageBackendFSImageToolTypeToFunc(virConnectPtr conn, int tool_type)
{
    switch (tool_type) {
    case TOOL_KVM_IMG:
    case TOOL_QEMU_IMG:
        return virStorageBackendCreateQemuImg;
    case TOOL_QCOW_CREATE:
        return virStorageBackendCreateQcowCreate;
    default:
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
virStorageBackendGetBuildVolFromFunction(virConnectPtr conn,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol)
{
    int tool_type;

    if (!inputvol)
        return NULL;

    /* If either volume is a non-raw file vol, we need to use an external
     * tool for converting
     */
    if ((vol->type == VIR_STORAGE_VOL_FILE &&
         vol->target.format != VIR_STORAGE_VOL_FILE_RAW) ||
        (inputvol->type == VIR_STORAGE_VOL_FILE &&
         inputvol->target.format != VIR_STORAGE_VOL_FILE_RAW)) {

        if ((tool_type = virStorageBackendFindFSImageTool(NULL)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("creation of non-raw file images is "
                                          "not supported without qemu-img."));
            return NULL;
        }

        return virStorageBackendFSImageToolTypeToFunc(conn, tool_type);
    }

    if (vol->type == VIR_STORAGE_VOL_BLOCK)
        return virStorageBackendCreateBlockFrom;
    else
        return virStorageBackendCreateRaw;
}

#if defined(UDEVADM) || defined(UDEVSETTLE)
void virWaitForDevices(virConnectPtr conn)
{
#ifdef UDEVADM
    const char *const settleprog[] = { UDEVADM, "settle", NULL };
#else
    const char *const settleprog[] = { UDEVSETTLE, NULL };
#endif
    int exitstatus;

    if (access(settleprog[0], X_OK) != 0)
        return;

    /*
     * NOTE: we ignore errors here; this is just to make sure that any device
     * nodes that are being created finish before we try to scan them.
     * If this fails for any reason, we still have the backup of polling for
     * 5 seconds for device nodes.
     */
    virRun(conn, settleprog, &exitstatus);
}
#else
void virWaitForDevices(virConnectPtr conn ATTRIBUTE_UNUSED) {}
#endif


virStorageBackendPtr
virStorageBackendForType(int type) {
    unsigned int i;
    for (i = 0; backends[i]; i++)
        if (backends[i]->type == type)
            return backends[i];

    virStorageReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                          _("missing backend for pool type %d"), type);
    return NULL;
}


int
virStorageBackendUpdateVolTargetInfo(virConnectPtr conn,
                                     virStorageVolTargetPtr target,
                                     unsigned long long *allocation,
                                     unsigned long long *capacity)
{
    int ret, fd;

    if ((fd = open(target->path, O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open volume '%s'"),
                             target->path);
        return -1;
    }

    ret = virStorageBackendUpdateVolTargetInfoFD(conn,
                                                 target,
                                                 fd,
                                                 allocation,
                                                 capacity);

    close(fd);

    return ret;
}

int
virStorageBackendUpdateVolInfo(virConnectPtr conn,
                               virStorageVolDefPtr vol,
                               int withCapacity)
{
    int ret;

    if ((ret = virStorageBackendUpdateVolTargetInfo(conn,
                                                    &vol->target,
                                                    &vol->allocation,
                                                    withCapacity ? &vol->capacity : NULL)) < 0)
        return ret;

    if (vol->backingStore.path &&
        (ret = virStorageBackendUpdateVolTargetInfo(conn,
                                                    &vol->backingStore,
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
virStorageBackendUpdateVolTargetInfoFD(virConnectPtr conn,
                                       virStorageVolTargetPtr target,
                                       int fd,
                                       unsigned long long *allocation,
                                       unsigned long long *capacity)
{
    struct stat sb;
#if HAVE_SELINUX
    security_context_t filecon = NULL;
#endif

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(conn, errno,
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
                virReportSystemError(conn, errno,
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
            virReportSystemError(conn, errno,
                                 _("cannot get file context of '%s'"),
                                 target->path);
            return -1;
        } else {
            target->perms.label = NULL;
        }
    } else {
        target->perms.label = strdup(filecon);
        if (target->perms.label == NULL) {
            virReportOOMError(conn);
            return -1;
        }
        freecon(filecon);
    }
#else
    target->perms.label = NULL;
#endif

    return 0;
}

void virStorageBackendWaitForDevices(virConnectPtr conn)
{
    virWaitForDevices(conn);
    return;
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
virStorageBackendStablePath(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
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
        virReportSystemError(conn, errno,
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
            virReportOOMError(conn);
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
        virReportOOMError(conn);

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
virStorageBackendRunProgRegex(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
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
        virReportOOMError(conn);
        return -1;
    }

    for (i = 0 ; i < nregex ; i++) {
        err = regcomp(&reg[i], regex[i], REG_EXTENDED);
        if (err != 0) {
            char error[100];
            regerror(err, &reg[i], error, sizeof(error));
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
        virReportOOMError(conn);
        goto cleanup;
    }
    if (VIR_ALLOC_N(vars, maxvars+1) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }


    /* Run the program and capture its output */
    if (virExec(conn, prog, NULL, NULL,
                &child, -1, &fd, NULL, VIR_EXEC_NONE) < 0) {
        goto cleanup;
    }

    if ((list = fdopen(fd, "r")) == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
                        virReportOOMError(conn);
                        goto cleanup;
                    }
                }

                /* We're matching on the last regex, so callback time */
                if (i == (nregex-1)) {
                    if (((*func)(conn, pool, groups, data)) < 0)
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
    else
        close(fd);

    while ((err = waitpid(child, &exitstatus, 0) == -1) && errno == EINTR);

    /* Don't bother checking exit status if we already failed */
    if (failed)
        return -1;

    if (err == -1) {
        virReportSystemError(conn, errno,
                             _("failed to wait for command '%s'"),
                             prog[0]);
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (outexit != NULL)
                *outexit = WEXITSTATUS(exitstatus);
        } else {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
virStorageBackendRunProgNul(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
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
        virReportOOMError(conn);
        return -1;
    }
    for (i = 0; i < n_columns; i++)
        v[i] = NULL;

    /* Run the program and capture its output */
    if (virExec(conn, prog, NULL, NULL,
                &child, -1, &fd, NULL, VIR_EXEC_NONE) < 0) {
        goto cleanup;
    }

    if ((fp = fdopen(fd, "r")) == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
            if (n_tok && func (conn, pool, n_tok, v, data) < 0)
                goto cleanup;
            break;
        }
        ++n_tok;
        if (n_tok == n_columns) {
            if (func (conn, pool, n_tok, v, data) < 0)
                goto cleanup;
            n_tok = 0;
            for (i = 0; i < n_columns; i++) {
                free (v[i]);
                v[i] = NULL;
            }
        }
    }

    if (feof (fp))
        err = 0;
    else
        virReportSystemError(conn, errno,
                             _("read error on pipe to '%s'"), prog[0]);

 cleanup:
    for (i = 0; i < n_columns; i++)
        free (v[i]);
    free (v);

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
        virReportSystemError(conn, errno,
                             _("failed to wait for command '%s'"),
                             prog[0]);
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (WEXITSTATUS(exitstatus) != 0) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("non-zero exit status from command %d"),
                                      WEXITSTATUS(exitstatus));
                return -1;
            }
        } else {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, _("%s not implemented on Win32"), __FUNCTION__);
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
    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, _("%s not implemented on Win32"), __FUNCTION__);
    return -1;
}
#endif
