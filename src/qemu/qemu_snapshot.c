/*
 * qemu_snapshot.c: snapshot related implementation
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

#include "qemu_snapshot.h"

#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_block.h"
#include "qemu_process.h"
#include "qemu_migration.h"
#include "qemu_command.h"
#include "qemu_security.h"
#include "qemu_saveimage.h"

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "domain_audit.h"
#include "locking/domain_lock.h"
#include "libvirt_internal.h"
#include "virxml.h"
#include "virstring.h"
#include "virdomainsnapshotobjlist.h"
#include "virqemu.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_snapshot");


/* Looks up snapshot object from VM and name */
virDomainMomentObjPtr
qemuSnapObjFromName(virDomainObjPtr vm,
                    const char *name)
{
    virDomainMomentObjPtr snap = NULL;
    snap = virDomainSnapshotFindByName(vm->snapshots, name);
    if (!snap)
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("no domain snapshot with matching name '%s'"),
                       name);

    return snap;
}


/* Looks up snapshot object from VM and snapshotPtr */
virDomainMomentObjPtr
qemuSnapObjFromSnapshot(virDomainObjPtr vm,
                        virDomainSnapshotPtr snapshot)
{
    return qemuSnapObjFromName(vm, snapshot->name);
}


/* Count how many snapshots in a set are external snapshots.  */
static int
qemuSnapshotCountExternal(void *payload,
                          const char *name G_GNUC_UNUSED,
                          void *data)
{
    virDomainMomentObjPtr snap = payload;
    int *count = data;

    if (virDomainSnapshotIsExternal(snap))
        (*count)++;
    return 0;
}


/* Return -1 if request is not sent to agent due to misconfig, -2 if request
 * is sent but failed, and number of frozen filesystems on success. If -2 is
 * returned, FSThaw should be called revert the quiesced status. */
int
qemuSnapshotFSFreeze(virDomainObjPtr vm,
                     const char **mountpoints,
                     unsigned int nmountpoints)
{
    qemuAgentPtr agent;
    int frozen;

    if (!qemuDomainAgentAvailable(vm, true))
        return -1;

    agent = qemuDomainObjEnterAgent(vm);
    frozen = qemuAgentFSFreeze(agent, mountpoints, nmountpoints);
    qemuDomainObjExitAgent(vm, agent);
    return frozen < 0 ? -2 : frozen;
}


/* Return -1 on error, otherwise number of thawed filesystems. */
int
qemuSnapshotFSThaw(virDomainObjPtr vm,
                   bool report)
{
    qemuAgentPtr agent;
    int thawed;
    virErrorPtr err = NULL;

    if (!qemuDomainAgentAvailable(vm, report))
        return -1;

    agent = qemuDomainObjEnterAgent(vm);
    if (!report)
        virErrorPreserveLast(&err);
    thawed = qemuAgentFSThaw(agent);
    qemuDomainObjExitAgent(vm, agent);

    virErrorRestore(&err);

    return thawed;
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotCreateInactiveInternal(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMomentObjPtr snap)
{
    return qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-c", false);
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotCreateInactiveExternal(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMomentObjPtr snap,
                                   bool reuse)
{
    size_t i;
    virDomainSnapshotDiskDefPtr snapdisk;
    virDomainDiskDefPtr defdisk;
    virCommandPtr cmd = NULL;
    const char *qemuImgPath;
    virBitmapPtr created = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virDomainSnapshotDefPtr snapdef = virDomainSnapshotObjGetDef(snap);

    if (!(qemuImgPath = qemuFindQemuImgBinary(driver)))
        goto cleanup;

    created = virBitmapNew(snapdef->ndisks);

    /* If reuse is true, then qemuSnapshotPrepare already
     * ensured that the new files exist, and it was up to the user to
     * create them correctly.  */
    for (i = 0; i < snapdef->ndisks && !reuse; i++) {
        snapdisk = &(snapdef->disks[i]);
        defdisk = vm->def->disks[i];
        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!snapdisk->src->format)
            snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;

        if (qemuDomainStorageSourceValidateDepth(defdisk->src, 1, defdisk->dst) < 0)
            goto cleanup;

        /* creates cmd line args: qemu-img create -f qcow2 -o */
        if (!(cmd = virCommandNewArgList(qemuImgPath,
                                         "create",
                                         "-f",
                                         virStorageFileFormatTypeToString(snapdisk->src->format),
                                         "-o",
                                         NULL)))
            goto cleanup;

        /* adds cmd line arg: backing_fmt=format,backing_file=/path/to/backing/file */
        virBufferAsprintf(&buf, "backing_fmt=%s,backing_file=",
                          virStorageFileFormatTypeToString(defdisk->src->format));
        virQEMUBuildBufferEscapeComma(&buf, defdisk->src->path);
        virCommandAddArgBuffer(cmd, &buf);

        /* adds cmd line args: /path/to/target/file */
        virQEMUBuildBufferEscapeComma(&buf, snapdisk->src->path);
        virCommandAddArgBuffer(cmd, &buf);

        /* If the target does not exist, we're going to create it possibly */
        if (!virFileExists(snapdisk->src->path))
            ignore_value(virBitmapSetBit(created, i));

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = NULL;
    }

    /* update disk definitions */
    for (i = 0; i < snapdef->ndisks; i++) {
        g_autoptr(virStorageSource) newsrc = NULL;

        snapdisk = &(snapdef->disks[i]);
        defdisk = vm->def->disks[i];

        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!(newsrc = virStorageSourceCopy(snapdisk->src, false)))
            goto cleanup;

        if (virStorageSourceInitChainElement(newsrc, defdisk->src, false) < 0)
            goto cleanup;

        if (!reuse &&
            virStorageSourceHasBacking(defdisk->src)) {
            defdisk->src->readonly = true;
            newsrc->backingStore = g_steal_pointer(&defdisk->src);
        } else {
            virObjectUnref(defdisk->src);
        }

        defdisk->src = g_steal_pointer(&newsrc);
    }

    if (virDomainDefSave(vm->def, driver->xmlopt, cfg->configDir) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);

    /* unlink images if creation has failed */
    if (ret < 0 && created) {
        ssize_t bit = -1;
        while ((bit = virBitmapNextSetBit(created, bit)) >= 0) {
            snapdisk = &(snapdef->disks[bit]);
            if (unlink(snapdisk->src->path) < 0)
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->src->path);
        }
    }
    virBitmapFree(created);

    return ret;
}


/* The domain is expected to be locked and active. */
static int
qemuSnapshotCreateActiveInternal(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainMomentObjPtr snap,
                                 unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    bool resume = false;
    virDomainSnapshotDefPtr snapdef = virDomainSnapshotObjGetDef(snap);
    int ret = -1;

    if (!qemuMigrationSrcIsAllowed(driver, vm, false, 0))
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* savevm monitor command pauses the domain emitting an event which
         * confuses libvirt since it's not notified when qemu resumes the
         * domain. Thus we stop and start CPUs ourselves.
         */
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_SNAPSHOT) < 0)
            goto cleanup;

        resume = true;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        resume = false;
        goto cleanup;
    }

    ret = qemuMonitorCreateSnapshot(priv->mon, snap->def->name);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0)
        goto cleanup;

    if (!(snapdef->cookie = (virObjectPtr) qemuDomainSaveCookieNew(vm)))
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        QEMU_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
    }

 cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }
    }

    virObjectEventStateQueue(driver->domainEventState, event);

    return ret;
}


static int
qemuSnapshotPrepareDiskShared(virDomainSnapshotDiskDefPtr snapdisk,
                              virDomainDiskDefPtr domdisk)
{
    if (!domdisk->src->shared || domdisk->src->readonly)
        return 0;

    if (!qemuBlockStorageSourceSupportsConcurrentAccess(snapdisk->src)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shared access for disk '%s' requires use of "
                         "supported storage format"), domdisk->dst);
        return -1;
    }

    return 0;
}


static int
qemuSnapshotPrepareDiskExternalInactive(virDomainSnapshotDiskDefPtr snapdisk,
                                        virDomainDiskDefPtr domdisk)
{
    int domDiskType = virStorageSourceGetActualType(domdisk->src);
    int snapDiskType = virStorageSourceGetActualType(snapdisk->src);

    switch ((virStorageType)domDiskType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) domdisk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_SSH:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("external inactive snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(domdisk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(domDiskType));
        return -1;
    }

    switch ((virStorageType)snapDiskType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        break;

    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(snapDiskType));
        return -1;
    }

    if (qemuSnapshotPrepareDiskShared(snapdisk, domdisk) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotPrepareDiskExternalActive(virDomainObjPtr vm,
                                      virDomainSnapshotDiskDefPtr snapdisk,
                                      virDomainDiskDefPtr domdisk,
                                      bool blockdev)
{
    int actualType = virStorageSourceGetActualType(snapdisk->src);

    if (domdisk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("external active snapshots are not supported on scsi "
                         "passthrough devices"));
        return -1;
    }

    if (!qemuDomainDiskBlockJobIsSupported(vm, domdisk))
        return -1;

    switch ((virStorageType)actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        /* defer all of the checking to either qemu or libvirt's blockdev code */
        if (blockdev)
            break;

        switch ((virStorageNetProtocol) snapdisk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            break;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_SSH:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("external active snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(snapdisk->src->protocol));
            return -1;

        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external active snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    if (qemuSnapshotPrepareDiskShared(snapdisk, domdisk) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotPrepareDiskExternal(virDomainObjPtr vm,
                                virDomainDiskDefPtr disk,
                                virDomainSnapshotDiskDefPtr snapdisk,
                                bool active,
                                bool reuse,
                                bool blockdev)
{
    struct stat st;
    int err;
    int rc;

    if (disk->src->readonly && !(reuse || blockdev)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("external snapshot for readonly disk %s "
                         "is not supported"), disk->dst);
        return -1;
    }

    if (qemuTranslateSnapshotDiskSourcePool(snapdisk) < 0)
        return -1;

    if (!active) {
        if (virDomainDiskTranslateSourcePool(disk) < 0)
            return -1;

        if (qemuSnapshotPrepareDiskExternalInactive(snapdisk, disk) < 0)
            return -1;
    } else {
        if (qemuSnapshotPrepareDiskExternalActive(vm, snapdisk, disk, blockdev) < 0)
            return -1;
    }

    if (virStorageSourceIsLocalStorage(snapdisk->src)) {
        if (virStorageFileInit(snapdisk->src) < 0)
            return -1;

        rc = virStorageFileStat(snapdisk->src, &st);
        err = errno;

        virStorageFileDeinit(snapdisk->src);

        if (rc < 0) {
            if (err != ENOENT) {
                virReportSystemError(err,
                                     _("unable to stat for disk %s: %s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            } else if (reuse) {
                virReportSystemError(err,
                                     _("missing existing file for disk %s: %s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            }
        } else if (!S_ISBLK(st.st_mode) && st.st_size && !reuse) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("external snapshot file for disk %s already "
                             "exists and is not a block device: %s"),
                           snapdisk->name, snapdisk->src->path);
            return -1;
        }
    }

    return 0;
}


static int
qemuSnapshotPrepareDiskInternal(virDomainDiskDefPtr disk,
                                bool active)
{
    int actualType;

    /* active disks are handled by qemu itself so no need to worry about those */
    if (active)
        return 0;

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        return -1;

    actualType = virStorageSourceGetActualType(disk->src);

    switch ((virStorageType)actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        return 0;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) disk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_SSH:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("internal inactive snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(disk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("internal inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuSnapshotPrepare(virDomainObjPtr vm,
                    virDomainSnapshotDefPtr def,
                    unsigned int *flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
    size_t i;
    bool active = virDomainObjIsActive(vm);
    bool reuse = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    bool found_internal = false;
    bool forbid_internal = false;
    int external = 0;

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDefPtr disk = &def->disks[i];
        virDomainDiskDefPtr dom_disk = vm->def->disks[i];

        if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_NONE &&
            qemuDomainDiskBlockJobIsActive(dom_disk))
            return -1;

        switch ((virDomainSnapshotLocation) disk->snapshot) {
        case VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL:
            found_internal = true;

            if (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT && active) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("active qemu domains require external disk "
                                 "snapshots; disk %s requested internal"),
                               disk->name);
                return -1;
            }

            if (qemuSnapshotPrepareDiskInternal(dom_disk,
                                                active) < 0)
                return -1;

            if (dom_disk->src->format > 0 &&
                dom_disk->src->format != VIR_STORAGE_FILE_QCOW2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("internal snapshot for disk %s unsupported "
                                 "for storage type %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(dom_disk->src->format));
                return -1;
            }
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL:
            if (!disk->src->format) {
                disk->src->format = VIR_STORAGE_FILE_QCOW2;
            } else if (disk->src->format != VIR_STORAGE_FILE_QCOW2 &&
                       disk->src->format != VIR_STORAGE_FILE_QED) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot format for disk %s "
                                 "is unsupported: %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(disk->src->format));
                return -1;
            }

            if (qemuSnapshotPrepareDiskExternal(vm, dom_disk, disk,
                                                active, reuse, blockdev) < 0)
                return -1;

            external++;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_NONE:
            /* Remember seeing a disk that has snapshot disabled */
            if (!virStorageSourceIsEmpty(dom_disk->src) &&
                !dom_disk->src->readonly)
                forbid_internal = true;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT:
        case VIR_DOMAIN_SNAPSHOT_LOCATION_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected code path"));
            return -1;
        }
    }

    if (!found_internal && !external &&
        def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nothing selected for snapshot"));
        return -1;
    }

    /* internal snapshot requires a disk image to store the memory image to, and
     * also disks can't be excluded from an internal snapshot */
    if ((def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && !found_internal) ||
        (found_internal && forbid_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("internal and full system snapshots require all "
                         "disks to be selected for snapshot"));
        return -1;
    }

    /* disk snapshot requires at least one disk */
    if (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT && !external) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("disk-only snapshots require at least "
                         "one disk to be selected for snapshot"));
        return -1;
    }

    /* For now, we don't allow mixing internal and external disks.
     * XXX technically, we could mix internal and external disks for
     * offline snapshots */
    if ((found_internal && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL && found_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("mixing internal and external targets for a snapshot "
                         "is not yet supported"));
        return -1;
    }

    /* internal snapshots + pflash based loader have the following problems:
     * - if the variable store is raw, the snapshot fails
     * - allowing a qcow2 image as the varstore would make it eligible to receive
     *   the vmstate dump, which would make it huge
     * - offline snapshot would not snapshot the varstore at all
     *
     * Avoid the issues by forbidding internal snapshot with pflash completely.
     */
    if (found_internal &&
        virDomainDefHasOldStyleUEFI(vm->def)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("internal snapshots of a VM with pflash based "
                         "firmware are not supported"));
        return -1;
    }

    /* Alter flags to let later users know what we learned.  */
    if (external && !active)
        *flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;

    return 0;
}


struct _qemuSnapshotDiskData {
    virStorageSourcePtr src;
    bool initialized; /* @src was initialized in the storage driver */
    bool created; /* @src was created by the snapshot code */
    bool prepared; /* @src was prepared using qemuDomainStorageSourceAccessAllow */
    virDomainDiskDefPtr disk;
    char *relPath; /* relative path component to fill into original disk */
    qemuBlockStorageSourceChainDataPtr crdata;
    bool blockdevadded;

    virStorageSourcePtr persistsrc;
    virDomainDiskDefPtr persistdisk;
};

typedef struct _qemuSnapshotDiskData qemuSnapshotDiskData;
typedef qemuSnapshotDiskData *qemuSnapshotDiskDataPtr;


static void
qemuSnapshotDiskCleanup(qemuSnapshotDiskDataPtr data,
                        size_t ndata,
                        virDomainObjPtr vm,
                        qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    virErrorPtr orig_err;
    size_t i;

    if (!data)
        return;

    virErrorPreserveLast(&orig_err);

    for (i = 0; i < ndata; i++) {
        /* on success of the snapshot the 'src' and 'persistsrc' properties will
         * be set to NULL by qemuSnapshotDiskUpdateSource */
        if (data[i].src) {
            if (data[i].blockdevadded) {
                if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {

                    qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm),
                                                         data[i].crdata->srcdata[0]);
                    ignore_value(qemuDomainObjExitMonitor(driver, vm));
                }
            }

            if (data[i].created &&
                virStorageFileUnlink(data[i].src) < 0) {
                VIR_WARN("Unable to remove just-created %s",
                         NULLSTR(data[i].src->path));
            }

            if (data[i].initialized)
                virStorageFileDeinit(data[i].src);

            if (data[i].prepared)
                qemuDomainStorageSourceAccessRevoke(driver, vm, data[i].src);

            virObjectUnref(data[i].src);
        }
        virObjectUnref(data[i].persistsrc);
        VIR_FREE(data[i].relPath);
        qemuBlockStorageSourceChainDataFree(data[i].crdata);
    }

    VIR_FREE(data);
    virErrorRestore(&orig_err);
}


struct _qemuSnapshotDiskContext {
    qemuSnapshotDiskDataPtr dd;
    size_t ndd;

    virJSONValuePtr actions;

    /* needed for automatic cleanup of 'dd' */
    virDomainObjPtr vm;
    qemuDomainAsyncJob asyncJob;
};

typedef struct _qemuSnapshotDiskContext qemuSnapshotDiskContext;
typedef qemuSnapshotDiskContext *qemuSnapshotDiskContextPtr;


static qemuSnapshotDiskContextPtr
qemuSnapshotDiskContextNew(size_t ndisks,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob)
{
    qemuSnapshotDiskContextPtr ret = g_new0(qemuSnapshotDiskContext, 1);

    ret->dd = g_new0(qemuSnapshotDiskData, ndisks);
    ret->actions = virJSONValueNewArray();
    ret->vm = vm;
    ret->asyncJob = asyncJob;

    return ret;
}


static void
qemuSnapshotDiskContextCleanup(qemuSnapshotDiskContextPtr snapctxt)
{
    if (!snapctxt)
        return;

    virJSONValueFree(snapctxt->actions);

    qemuSnapshotDiskCleanup(snapctxt->dd, snapctxt->ndd, snapctxt->vm, snapctxt->asyncJob);

    g_free(snapctxt);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuSnapshotDiskContext, qemuSnapshotDiskContextCleanup);


/**
 * qemuSnapshotDiskBitmapsPropagate:
 *
 * This function propagates any active persistent bitmap present in the original
 * image into the new snapshot. This is necessary to keep tracking the changed
 * blocks in the active bitmaps as the backing file will become read-only.
 * We leave the original bitmap active as in cases when the overlay is
 * discarded (snapshot revert with abandoning the history) everything works as
 * expected.
 */
static int
qemuSnapshotDiskBitmapsPropagate(qemuSnapshotDiskDataPtr dd,
                                 virJSONValuePtr actions,
                                 virHashTablePtr blockNamedNodeData)
{
    qemuBlockNamedNodeDataPtr entry;
    size_t i;

    if (!(entry = virHashLookup(blockNamedNodeData, dd->disk->src->nodeformat)))
        return 0;

    for (i = 0; i < entry->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmapPtr bitmap = entry->bitmaps[i];

        /* we don't care about temporary, inconsistent, or disabled bitmaps */
        if (!bitmap->persistent || !bitmap->recording || bitmap->inconsistent)
            continue;

        if (qemuMonitorTransactionBitmapAdd(actions, dd->src->nodeformat,
                                            bitmap->name, true, false,
                                            bitmap->granularity) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSnapshotDiskPrepareOneBlockdev(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   qemuSnapshotDiskDataPtr dd,
                                   virQEMUDriverConfigPtr cfg,
                                   bool reuse,
                                   virHashTablePtr blockNamedNodeData,
                                   qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virStorageSource) terminator = NULL;
    int rc;

    /* create a terminator for the snapshot disks so that qemu does not try
     * to open them at first */
    terminator = virStorageSourceNew();

    if (qemuDomainPrepareStorageSourceBlockdev(dd->disk, dd->src,
                                               priv, cfg) < 0)
        return -1;

    if (!(dd->crdata = qemuBuildStorageSourceChainAttachPrepareBlockdevTop(dd->src,
                                                                           terminator,
                                                                           priv->qemuCaps)))
        return -1;

    if (reuse) {
        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            return -1;

        rc = qemuBlockStorageSourceAttachApply(qemuDomainGetMonitor(vm),
                                               dd->crdata->srcdata[0]);

        if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
            return -1;
    } else {
        if (qemuBlockStorageSourceCreateDetectSize(blockNamedNodeData,
                                                   dd->src, dd->disk->src) < 0)
            return -1;

        if (qemuBlockStorageSourceCreate(vm, dd->src, dd->disk->src,
                                         NULL, dd->crdata->srcdata[0],
                                         asyncJob) < 0)
            return -1;
    }

    dd->blockdevadded = true;
    return 0;
}


static int
qemuSnapshotDiskPrepareOne(virDomainObjPtr vm,
                           virQEMUDriverConfigPtr cfg,
                           virDomainDiskDefPtr disk,
                           virDomainSnapshotDiskDefPtr snapdisk,
                           qemuSnapshotDiskDataPtr dd,
                           virHashTablePtr blockNamedNodeData,
                           bool reuse,
                           bool updateConfig,
                           qemuDomainAsyncJob asyncJob,
                           virJSONValuePtr actions)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
    virDomainDiskDefPtr persistdisk;
    bool supportsCreate;
    bool updateRelativeBacking = false;

    dd->disk = disk;

    if (qemuDomainStorageSourceValidateDepth(disk->src, 1, disk->dst) < 0)
        return -1;

    if (!(dd->src = virStorageSourceCopy(snapdisk->src, false)))
        return -1;

    if (virStorageSourceInitChainElement(dd->src, dd->disk->src, false) < 0)
        return -1;

    /* modify disk in persistent definition only when the source is the same */
    if (updateConfig &&
        vm->newDef &&
        (persistdisk = virDomainDiskByTarget(vm->newDef, dd->disk->dst)) &&
        virStorageSourceIsSameLocation(dd->disk->src, persistdisk->src)) {

        dd->persistdisk = persistdisk;

        if (!(dd->persistsrc = virStorageSourceCopy(dd->src, false)))
            return -1;

        if (virStorageSourceInitChainElement(dd->persistsrc,
                                             dd->persistdisk->src, false) < 0)
            return -1;
    }

    supportsCreate = virStorageFileSupportsCreate(dd->src);

    /* relative backing store paths need to be updated so that relative
     * block commit still works. With blockdev we must update it when doing
     * commit anyways so it's skipped here */
    if (!blockdev &&
        virStorageFileSupportsBackingChainTraversal(dd->src))
        updateRelativeBacking = true;

    if (supportsCreate || updateRelativeBacking) {
        if (qemuDomainStorageFileInit(driver, vm, dd->src, NULL) < 0)
            return -1;

        dd->initialized = true;

        if (reuse) {
            if (updateRelativeBacking) {
                g_autofree char *backingStoreStr = NULL;

                if (virStorageFileGetBackingStoreStr(dd->src, &backingStoreStr) < 0)
                    return -1;
                if (backingStoreStr != NULL) {
                    if (virStorageIsRelative(backingStoreStr))
                        dd->relPath = g_steal_pointer(&backingStoreStr);
                }
            }
        } else {
            /* pre-create the image file so that we can label it before handing it to qemu */
            if (supportsCreate && dd->src->type != VIR_STORAGE_TYPE_BLOCK) {
                if (virStorageFileCreate(dd->src) < 0) {
                    virReportSystemError(errno, _("failed to create image file '%s'"),
                                         NULLSTR(dd->src->path));
                    return -1;
                }
                dd->created = true;
            }
        }
    }

    /* set correct security, cgroup and locking options on the new image */
    if (qemuDomainStorageSourceAccessAllow(driver, vm, dd->src,
                                           false, true, true) < 0)
        return -1;

    dd->prepared = true;

    if (blockdev) {
        if (qemuSnapshotDiskPrepareOneBlockdev(driver, vm, dd, cfg, reuse,
                                               blockNamedNodeData, asyncJob) < 0)
            return -1;

        if (qemuSnapshotDiskBitmapsPropagate(dd, actions, blockNamedNodeData) < 0)
            return -1;

        if (qemuBlockSnapshotAddBlockdev(actions, dd->disk, dd->src) < 0)
            return -1;
    } else {
        if (qemuBlockSnapshotAddLegacy(actions, dd->disk, dd->src, reuse) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuSnapshotDiskPrepareActiveExternal:
 *
 * Collects and prepares a list of structures that hold information about disks
 * that are selected for the snapshot.
 */
static qemuSnapshotDiskContextPtr
qemuSnapshotDiskPrepareActiveExternal(virDomainObjPtr vm,
                                      virDomainMomentObjPtr snap,
                                      virQEMUDriverConfigPtr cfg,
                                      bool reuse,
                                      virHashTablePtr blockNamedNodeData,
                                      qemuDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    size_t i;
    virDomainSnapshotDefPtr snapdef = virDomainSnapshotObjGetDef(snap);

    snapctxt = qemuSnapshotDiskContextNew(snapdef->ndisks, vm, asyncJob);

    for (i = 0; i < snapdef->ndisks; i++) {
        if (snapdef->disks[i].snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
            continue;

        if (qemuSnapshotDiskPrepareOne(vm, cfg, vm->def->disks[i],
                                       snapdef->disks + i,
                                       snapctxt->dd + snapctxt->ndd++,
                                       blockNamedNodeData,
                                       reuse,
                                       true,
                                       asyncJob,
                                       snapctxt->actions) < 0)
            return NULL;
    }

    return g_steal_pointer(&snapctxt);
}


static qemuSnapshotDiskContextPtr
qemuSnapshotDiskPrepareDisksTransient(virDomainObjPtr vm,
                                      virQEMUDriverConfigPtr cfg,
                                      virHashTablePtr blockNamedNodeData,
                                      qemuDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    size_t i;

    snapctxt = qemuSnapshotDiskContextNew(vm->def->ndisks, vm, asyncJob);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr domdisk = vm->def->disks[i];
        g_autoptr(virDomainSnapshotDiskDef) snapdisk = g_new0(virDomainSnapshotDiskDef, 1);

        if (!domdisk->transient)
            continue;

        /* validation code makes sure that we do this only for local disks
         * with a file source */
        snapdisk->name = g_strdup(domdisk->dst);
        snapdisk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
        snapdisk->src = virStorageSourceNew();
        snapdisk->src->type = VIR_STORAGE_TYPE_FILE;
        snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;
        snapdisk->src->path = g_strdup_printf("%s.TRANSIENT", domdisk->src->path);

        if (virFileExists(snapdisk->src->path)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("Overlay file '%s' for transient disk '%s' already exists"),
                           snapdisk->src->path, domdisk->dst);
            return NULL;
        }

        if (qemuSnapshotDiskPrepareOne(vm, cfg, domdisk, snapdisk,
                                       snapctxt->dd + snapctxt->ndd++,
                                       blockNamedNodeData,
                                       false,
                                       false,
                                       asyncJob,
                                       snapctxt->actions) < 0)
            return NULL;
    }

    return g_steal_pointer(&snapctxt);
}


static void
qemuSnapshotDiskUpdateSourceRenumber(virStorageSourcePtr src)
{
    virStorageSourcePtr next;
    unsigned int idx = 1;

    for (next = src->backingStore; virStorageSourceIsBacking(next); next = next->backingStore)
        next->id = idx++;
}


/**
 * qemuSnapshotDiskUpdateSource:
 * @vm: domain object
 * @dd: snapshot disk data object
 *
 * Updates disk definition after a successful snapshot.
 */
static void
qemuSnapshotDiskUpdateSource(virDomainObjPtr vm,
                             qemuSnapshotDiskDataPtr dd)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;

    /* storage driver access won'd be needed */
    if (dd->initialized)
        virStorageFileDeinit(dd->src);

    if (qemuSecurityMoveImageMetadata(driver, vm, dd->disk->src, dd->src) < 0)
        VIR_WARN("Unable to move disk metadata on vm %s", vm->def->name);

    /* unlock the write lock on the original image as qemu will no longer write to it */
    virDomainLockImageDetach(driver->lockManager, vm, dd->disk->src);

    /* unlock also the new image if the VM is paused to follow the locking semantics */
    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING)
        virDomainLockImageDetach(driver->lockManager, vm, dd->src);

    /* the old disk image is now readonly */
    dd->disk->src->readonly = true;

    dd->disk->src->relPath = g_steal_pointer(&dd->relPath);
    dd->src->backingStore = g_steal_pointer(&dd->disk->src);
    dd->disk->src = g_steal_pointer(&dd->src);

    /* fix numbering of disks */
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV))
        qemuSnapshotDiskUpdateSourceRenumber(dd->disk->src);

    if (dd->persistdisk) {
        dd->persistdisk->src->readonly = true;
        dd->persistsrc->backingStore = g_steal_pointer(&dd->persistdisk->src);
        dd->persistdisk->src = g_steal_pointer(&dd->persistsrc);
    }
}


static int
qemuSnapshotDiskCreate(qemuSnapshotDiskContextPtr snapctxt,
                       virQEMUDriverConfigPtr cfg)
{
    qemuDomainObjPrivatePtr priv = snapctxt->vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    size_t i;
    int rc;

    /* check whether there's anything to do */
    if (snapctxt->ndd == 0)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, snapctxt->vm, snapctxt->asyncJob) < 0)
        return -1;

    rc = qemuMonitorTransaction(priv->mon, &snapctxt->actions);

    if (qemuDomainObjExitMonitor(driver, snapctxt->vm) < 0)
        rc = -1;

    for (i = 0; i < snapctxt->ndd; i++) {
        qemuSnapshotDiskDataPtr dd = snapctxt->dd + i;

        virDomainAuditDisk(snapctxt->vm, dd->disk->src, dd->src, "snapshot", rc >= 0);

        if (rc == 0)
            qemuSnapshotDiskUpdateSource(snapctxt->vm, dd);
    }

    if (rc < 0)
        return -1;

    if (virDomainObjSave(snapctxt->vm, driver->xmlopt, cfg->stateDir) < 0 ||
        (snapctxt->vm->newDef && virDomainDefSave(snapctxt->vm->newDef, driver->xmlopt,
                                        cfg->configDir) < 0))
        return -1;

    return 0;
}


/* The domain is expected to be locked and active. */
static int
qemuSnapshotCreateActiveExternalDisks(virDomainObjPtr vm,
                                      virDomainMomentObjPtr snap,
                                      virHashTablePtr blockNamedNodeData,
                                      unsigned int flags,
                                      virQEMUDriverConfigPtr cfg,
                                      qemuDomainAsyncJob asyncJob)
{
    bool reuse = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;

    if (virDomainObjCheckActive(vm) < 0)
        return -1;

    /* prepare a list of objects to use in the vm definition so that we don't
     * have to roll back later */
    if (!(snapctxt = qemuSnapshotDiskPrepareActiveExternal(vm, snap, cfg, reuse,
                                                           blockNamedNodeData, asyncJob)))
        return -1;

    if (qemuSnapshotDiskCreate(snapctxt, cfg) < 0)
        return -1;

    return 0;
}


/**
 * qemuSnapshotCreateDisksTransient:
 * @vm: domain object
 * @asyncJob: qemu async job type
 *
 * Creates overlays on top of disks which are configured as <transient/>. Note
 * that the validation code ensures that <transient> disks have appropriate
 * configuration.
 */
int
qemuSnapshotCreateDisksTransient(virDomainObjPtr vm,
                                 qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    g_autoptr(virHashTable) blockNamedNodeData = NULL;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV)) {
        if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
            return -1;

        if (!(snapctxt = qemuSnapshotDiskPrepareDisksTransient(vm, cfg,
                                                               blockNamedNodeData,
                                                               asyncJob)))
            return -1;

        if (qemuSnapshotDiskCreate(snapctxt, cfg) < 0)
            return -1;
    }

    /* the overlays are established, so they can be deleted on shutdown */
    priv->inhibitDiskTransientDelete = false;

    return 0;
}


static int
qemuSnapshotCreateActiveExternal(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainMomentObjPtr snap,
                                 virQEMUDriverConfigPtr cfg,
                                 unsigned int flags)
{
    virObjectEventPtr event;
    bool resume = false;
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *xml = NULL;
    virDomainSnapshotDefPtr snapdef = virDomainSnapshotObjGetDef(snap);
    bool memory = snapdef->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    bool memory_unlink = false;
    int thaw = 0; /* 1 if freeze succeeded, -1 if freeze failed */
    bool pmsuspended = false;
    int compressed;
    g_autoptr(virCommand) compressor = NULL;
    virQEMUSaveDataPtr data = NULL;
    g_autoptr(virHashTable) blockNamedNodeData = NULL;

    /* If quiesce was requested, then issue a freeze command, and a
     * counterpart thaw command when it is actually sent to agent.
     * The command will fail if the guest is paused or the guest agent
     * is not running, or is already quiesced.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) {
        int freeze;

        if (qemuDomainObjBeginAgentJob(driver, vm, QEMU_AGENT_JOB_MODIFY) < 0)
            goto cleanup;

        if (virDomainObjCheckActive(vm) < 0) {
            qemuDomainObjEndAgentJob(vm);
            goto cleanup;
        }

        freeze = qemuSnapshotFSFreeze(vm, NULL, 0);
        qemuDomainObjEndAgentJob(vm);

        if (freeze < 0) {
            /* the helper reported the error */
            if (freeze == -2)
                thaw = -1; /* the command is sent but agent failed */
            goto cleanup;
        }
        thaw = 1;
    }

    /* We need to track what state the guest is in, since taking the
     * snapshot may alter that state and we must restore it later.  */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PMSUSPENDED) {
        pmsuspended = true;
    } else if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* For full system external snapshots (those with memory), the guest
         * must pause (either by libvirt up front, or by qemu after
         * _LIVE converges). */
        if (memory)
            resume = true;

        if (memory && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE)) {
            if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SNAPSHOT,
                                    QEMU_ASYNC_JOB_SNAPSHOT) < 0)
                goto cleanup;

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto cleanup;
            }

            resume = true;
        }
    }

    /* We need to collect reply from 'query-named-block-nodes' prior to the
     * migration step as qemu deactivates bitmaps after migration so the result
     * would be wrong */
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV) &&
        !(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, QEMU_ASYNC_JOB_SNAPSHOT)))
        goto cleanup;

    /* do the memory snapshot if necessary */
    if (memory) {
        /* check if migration is possible */
        if (!qemuMigrationSrcIsAllowed(driver, vm, false, 0))
            goto cleanup;

        priv->job.current->statsType = QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP;

        /* allow the migration job to be cancelled or the domain to be paused */
        qemuDomainObjSetAsyncJobMask(vm, (QEMU_JOB_DEFAULT_MASK |
                                          JOB_MASK(QEMU_JOB_SUSPEND) |
                                          JOB_MASK(QEMU_JOB_MIGRATION_OP)));

        if ((compressed = qemuSaveImageGetCompressionProgram(cfg->snapshotImageFormat,
                                                             &compressor,
                                                             "snapshot", false)) < 0)
            goto cleanup;

        if (!(xml = qemuDomainDefFormatLive(driver, priv->qemuCaps,
                                            vm->def, priv->origCPU,
                                            true, true)) ||
            !(snapdef->cookie = (virObjectPtr) qemuDomainSaveCookieNew(vm)))
            goto cleanup;

        if (!(data = virQEMUSaveDataNew(xml,
                                        (qemuDomainSaveCookiePtr) snapdef->cookie,
                                        resume, compressed, driver->xmlopt)))
            goto cleanup;
        xml = NULL;

        if ((ret = qemuSaveImageCreate(driver, vm, snapdef->file, data,
                                      compressor, 0,
                                      QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
            goto cleanup;

        /* the memory image was created, remove it on errors */
        memory_unlink = true;

        /* forbid any further manipulation */
        qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_DEFAULT_MASK);
    }

    /* the domain is now paused if a memory snapshot was requested */

    if ((ret = qemuSnapshotCreateActiveExternalDisks(vm, snap,
                                                     blockNamedNodeData, flags, cfg,
                                                     QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
        goto cleanup;

    /* the snapshot is complete now */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        QEMU_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
        thaw = 0;
        virObjectEventStateQueue(driver->domainEventState, event);
    } else if (memory && pmsuspended) {
        /* qemu 1.3 is unable to save a domain in pm-suspended (S3)
         * state; so we must emit an event stating that it was
         * converted to paused.  */
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    ret = 0;

 cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        virObjectEventStateQueue(driver->domainEventState, event);
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }

        ret = -1;
    }

    if (thaw != 0 &&
        qemuDomainObjBeginAgentJob(driver, vm, QEMU_AGENT_JOB_MODIFY) >= 0 &&
        virDomainObjIsActive(vm)) {
        if (qemuSnapshotFSThaw(vm, ret == 0 && thaw > 0) < 0) {
            /* helper reported the error, if it was needed */
            if (thaw > 0)
                ret = -1;
        }

        qemuDomainObjEndAgentJob(vm);
    }

    virQEMUSaveDataFree(data);
    if (memory_unlink && ret < 0)
        unlink(snapdef->file);

    return ret;
}


virDomainSnapshotPtr
qemuSnapshotCreateXML(virDomainPtr domain,
                      virDomainObjPtr vm,
                      const char *xmlDesc,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = domain->conn->privateData;
    g_autofree char *xml = NULL;
    virDomainMomentObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virDomainMomentObjPtr current = NULL;
    bool update_current = true;
    bool redefine = flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    unsigned int parse_flags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;
    int align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    bool align_match = true;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainSnapshotState state;
    g_autoptr(virDomainSnapshotDef) def = NULL;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA |
                  VIR_DOMAIN_SNAPSHOT_CREATE_HALT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY |
                  VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC |
                  VIR_DOMAIN_SNAPSHOT_CREATE_LIVE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE, NULL);

    VIR_REQUIRE_FLAG_RET(VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE,
                         VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY,
                         NULL);
    VIR_EXCLUSIVE_FLAGS_RET(VIR_DOMAIN_SNAPSHOT_CREATE_LIVE,
                            VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE,
                            NULL);

    if ((redefine && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) ||
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA))
        update_current = false;
    if (redefine)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (qemuDomainSupportsCheckpointsBlockjobs(vm) < 0)
        goto cleanup;

    if (!vm->persistent && (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot halt after transient domain snapshot"));
        goto cleanup;
    }
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) ||
        !virDomainObjIsActive(vm))
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_VALIDATE;

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, driver->xmlopt,
                                                priv->qemuCaps, NULL, parse_flags)))
        goto cleanup;

    /* reject snapshot names containing slashes or starting with dot as
     * snapshot definitions are saved in files named by the snapshot name */
    if (!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        if (strchr(def->parent.name, '/')) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%s': "
                             "name can't contain '/'"),
                           def->parent.name);
            goto cleanup;
        }

        if (def->parent.name[0] == '.') {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%s': "
                             "name can't start with '.'"),
                           def->parent.name);
            goto cleanup;
        }
    }

    /* reject the VIR_DOMAIN_SNAPSHOT_CREATE_LIVE flag where not supported */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE &&
        (!virDomainObjIsActive(vm) ||
         def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live snapshot creation is supported only "
                         "during full system snapshots"));
        goto cleanup;
    }

    /* allow snapshots only in certain states */
    state = redefine ? def->state : vm->state.state;
    switch (state) {
        /* valid states */
    case VIR_DOMAIN_SNAPSHOT_RUNNING:
    case VIR_DOMAIN_SNAPSHOT_PAUSED:
    case VIR_DOMAIN_SNAPSHOT_SHUTDOWN:
    case VIR_DOMAIN_SNAPSHOT_SHUTOFF:
    case VIR_DOMAIN_SNAPSHOT_CRASHED:
        break;

    case VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT:
        if (!redefine) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %s"),
                           virDomainSnapshotStateTypeToString(state));
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_SNAPSHOT_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support taking snapshots of "
                         "PMSUSPENDED guests"));
        goto cleanup;

        /* invalid states */
    case VIR_DOMAIN_SNAPSHOT_NOSTATE:
    case VIR_DOMAIN_SNAPSHOT_BLOCKED: /* invalid state, unused in qemu */
    case VIR_DOMAIN_SNAPSHOT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %s"),
                       virDomainSnapshotStateTypeToString(state));
        goto cleanup;
    }

    /* We are going to modify the domain below. Internal snapshots would use
     * a regular job, so we need to set the job mask to disallow query as
     * 'savevm' blocks the monitor. External snapshot will then modify the
     * job mask appropriately. */
    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SNAPSHOT,
                                   VIR_DOMAIN_JOB_OPERATION_SNAPSHOT, flags) < 0)
        goto cleanup;

    qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_NONE);

    if (redefine) {
        if (virDomainSnapshotRedefinePrep(vm, &def, &snap,
                                          driver->xmlopt,
                                          flags) < 0)
            goto endjob;
    } else {
        /* Easiest way to clone inactive portion of vm->def is via
         * conversion in and back out of xml.  */
        if (!(xml = qemuDomainDefFormatLive(driver, priv->qemuCaps,
                                            vm->def, priv->origCPU,
                                            true, true)) ||
            !(def->parent.dom = virDomainDefParseString(xml, driver->xmlopt,
                                                        priv->qemuCaps,
                                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto endjob;

        if (vm->newDef) {
            def->parent.inactiveDom = virDomainDefCopy(vm->newDef,
                                                       driver->xmlopt, priv->qemuCaps, true);
            if (!def->parent.inactiveDom)
                goto endjob;
        }

        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
            align_match = false;
            if (virDomainObjIsActive(vm))
                def->state = VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT;
            else
                def->state = VIR_DOMAIN_SNAPSHOT_SHUTOFF;
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
        } else if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            def->state = virDomainObjGetState(vm, NULL);
            align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
            align_match = false;
        } else {
            def->state = virDomainObjGetState(vm, NULL);

            if (virDomainObjIsActive(vm) &&
                def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("internal snapshot of a running VM "
                                 "must include the memory state"));
                goto endjob;
            }

            def->memory = (def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF ?
                           VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                           VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL);
        }
        if (virDomainSnapshotAlignDisks(def, align_location,
                                        align_match) < 0 ||
            qemuSnapshotPrepare(vm, def, &flags) < 0)
            goto endjob;
    }

    if (!snap) {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, def)))
            goto endjob;

        def = NULL;
    }

    current = virDomainSnapshotGetCurrent(vm->snapshots);
    if (current) {
        if (!redefine)
            snap->def->parent_name = g_strdup(current->def->name);
    }

    /* actually do the snapshot */
    if (redefine) {
        /* XXX Should we validate that the redefined snapshot even
         * makes sense, such as checking that qemu-img recognizes the
         * snapshot name in at least one of the domain's disks?  */
    } else if (virDomainObjIsActive(vm)) {
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY ||
            virDomainSnapshotObjGetDef(snap)->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            /* external full system or disk snapshot */
            if (qemuSnapshotCreateActiveExternal(driver, vm, snap, cfg, flags) < 0)
                goto endjob;
        } else {
            /* internal full system */
            if (qemuSnapshotCreateActiveInternal(driver, vm, snap, flags) < 0)
                goto endjob;
        }
    } else {
        /* inactive; qemuSnapshotPrepare guaranteed that we
         * aren't mixing internal and external, and altered flags to
         * contain DISK_ONLY if there is an external disk.  */
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            bool reuse = !!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);

            if (qemuSnapshotCreateInactiveExternal(driver, vm, snap, reuse) < 0)
                goto endjob;
        } else {
            if (qemuSnapshotCreateInactiveInternal(driver, vm, snap) < 0)
                goto endjob;
        }
    }

    /* If we fail after this point, there's not a whole lot we can
     * do; we've successfully taken the snapshot, and we are now running
     * on it, so we have to go forward the best we can
     */
    snapshot = virGetDomainSnapshot(domain, snap->def->name);

 endjob:
    if (snapshot && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        if (update_current)
            virDomainSnapshotSetCurrent(vm->snapshots, snap);
        if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                            driver->xmlopt,
                                            cfg->snapshotDir) < 0) {
            /* if writing of metadata fails, error out rather than trying
             * to silently carry on without completing the snapshot */
            virObjectUnref(snapshot);
            snapshot = NULL;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to save metadata for snapshot %s"),
                           snap->def->name);
            virDomainSnapshotObjListRemove(vm->snapshots, snap);
        } else {
            virDomainSnapshotLinkParent(vm->snapshots, snap);
        }
    } else if (snap) {
        virDomainSnapshotObjListRemove(vm->snapshots, snap);
    }

    qemuDomainObjEndAsyncJob(driver, vm);

 cleanup:
    return snapshot;
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotRevertInactive(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainMomentObjPtr snap)
{
    /* Try all disks, but report failure if we skipped any.  */
    int ret = qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-a", true);
    return ret > 0 ? -1 : ret;
}


int
qemuSnapshotRevert(virDomainObjPtr vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags)
{
    virQEMUDriverPtr driver = snapshot->domain->conn->privateData;
    int ret = -1;
    virDomainMomentObjPtr snap = NULL;
    virDomainSnapshotDefPtr snapdef;
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    int detail;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;
    virDomainDefPtr config = NULL;
    virDomainDefPtr inactiveConfig = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    bool was_stopped = false;
    qemuDomainSaveCookiePtr cookie;
    virCPUDefPtr origCPU = NULL;
    unsigned int start_flags = VIR_QEMU_PROCESS_START_GEN_VMID;
    bool defined = false;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED |
                  VIR_DOMAIN_SNAPSHOT_REVERT_FORCE, -1);

    /* We have the following transitions, which create the following events:
     * 1. inactive -> inactive: none
     * 2. inactive -> running:  EVENT_STARTED
     * 3. inactive -> paused:   EVENT_STARTED, EVENT_PAUSED
     * 4. running  -> inactive: EVENT_STOPPED
     * 5. running  -> running:  none
     * 6. running  -> paused:   EVENT_PAUSED
     * 7. paused   -> inactive: EVENT_STOPPED
     * 8. paused   -> running:  EVENT_RESUMED
     * 9. paused   -> paused:   none
     * Also, several transitions occur even if we fail partway through,
     * and use of FORCE can cause multiple transitions.
     */

    if (qemuDomainHasBlockjob(vm, false)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has active block job"));
        goto cleanup;
    }

    if (qemuProcessBeginJob(driver, vm,
                            VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_REVERT,
                            flags) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;
    snapdef = virDomainSnapshotObjGetDef(snap);

    if (!vm->persistent &&
        snapdef->state != VIR_DOMAIN_SNAPSHOT_RUNNING &&
        snapdef->state != VIR_DOMAIN_SNAPSHOT_PAUSED &&
        (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domain needs to request run or pause "
                         "to revert to inactive snapshot"));
        goto endjob;
    }

    if (virDomainSnapshotIsExternal(snap)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("revert to external snapshot not supported yet"));
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
        if (!snap->def->dom) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                           _("snapshot '%s' lacks domain '%s' rollback info"),
                           snap->def->name, vm->def->name);
            goto endjob;
        }
        if (virDomainObjIsActive(vm) &&
            !(snapdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
              snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED) &&
            (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                      VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("must respawn qemu to start inactive snapshot"));
            goto endjob;
        }
        if (vm->hasManagedSave &&
            !(snapdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
              snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED)) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("snapshot without memory state, removal of "
                             "existing managed saved state strongly "
                             "recommended to avoid corruption"));
            goto endjob;
        }
    }

    if (snap->def->dom) {
        config = virDomainDefCopy(snap->def->dom,
                                  driver->xmlopt, priv->qemuCaps, true);
        if (!config)
            goto endjob;
    }

    if (snap->def->inactiveDom) {
        inactiveConfig = virDomainDefCopy(snap->def->inactiveDom,
                                          driver->xmlopt, priv->qemuCaps, true);
        if (!inactiveConfig)
            goto endjob;
    } else {
        /* Inactive domain definition is missing:
         * - either this is an old active snapshot and we need to copy the
         *   active definition as an inactive one
         * - or this is an inactive snapshot which means config contains the
         *   inactive definition.
         */
        if (snapdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
            snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED) {
            inactiveConfig = virDomainDefCopy(snap->def->dom,
                                              driver->xmlopt, priv->qemuCaps, true);
            if (!inactiveConfig)
                goto endjob;
        } else {
            inactiveConfig = g_steal_pointer(&config);
        }
    }

    cookie = (qemuDomainSaveCookiePtr) snapdef->cookie;

    switch ((virDomainSnapshotState) snapdef->state) {
    case VIR_DOMAIN_SNAPSHOT_RUNNING:
    case VIR_DOMAIN_SNAPSHOT_PAUSED:
        start_flags |= VIR_QEMU_PROCESS_START_PAUSED;

        /* Transitions 2, 3, 5, 6, 8, 9 */
        /* When using the loadvm monitor command, qemu does not know
         * whether to pause or run the reverted domain, and just stays
         * in the same state as before the monitor command, whether
         * that is paused or running.  We always pause before loadvm,
         * to have finer control.  */
        if (virDomainObjIsActive(vm)) {
            /* Transitions 5, 6, 8, 9 */
            /* Check for ABI compatibility. We need to do this check against
             * the migratable XML or it will always fail otherwise */
            if (config) {
                bool compatible;

                /* Replace the CPU in config and put the original one in priv
                 * once we're done. When we have the updated CPU def in the
                 * cookie, we don't want to replace the CPU in migratable def
                 * when doing ABI checks to make sure the current CPU exactly
                 * matches the one used at the time the snapshot was taken.
                 */
                if (cookie && cookie->cpu && config->cpu) {
                    origCPU = config->cpu;
                    if (!(config->cpu = virCPUDefCopy(cookie->cpu)))
                        goto endjob;

                    compatible = qemuDomainDefCheckABIStability(driver,
                                                                priv->qemuCaps,
                                                                vm->def,
                                                                config);
                } else {
                    compatible = qemuDomainCheckABIStability(driver, vm, config);
                }

                /* If using VM GenID, there is no way currently to change
                 * the genid for the running guest, so set an error,
                 * mark as incompatible, and don't allow change of genid
                 * if the revert force flag would start the guest again. */
                if (compatible && config->genidRequested) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("domain genid update requires restart"));
                    compatible = false;
                    start_flags &= ~VIR_QEMU_PROCESS_START_GEN_VMID;
                }

                if (!compatible) {
                    virErrorPtr err = virGetLastError();

                    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
                        /* Re-spawn error using correct category. */
                        if (err->code == VIR_ERR_CONFIG_UNSUPPORTED)
                            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                                           err->str2);
                        goto endjob;
                    }
                    virResetError(err);
                    qemuProcessStop(driver, vm,
                                    VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                                    QEMU_ASYNC_JOB_START, 0);
                    virDomainAuditStop(vm, "from-snapshot");
                    detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
                    event = virDomainEventLifecycleNewFromObj(vm,
                                                     VIR_DOMAIN_EVENT_STOPPED,
                                                     detail);
                    virObjectEventStateQueue(driver->domainEventState, event);
                    goto load;
                }
            }

            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
                /* Transitions 5, 6 */
                if (qemuProcessStopCPUs(driver, vm,
                                        VIR_DOMAIN_PAUSED_FROM_SNAPSHOT,
                                        QEMU_ASYNC_JOB_START) < 0)
                    goto endjob;
                if (!virDomainObjIsActive(vm)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("guest unexpectedly quit"));
                    goto endjob;
                }
            }

            if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                               QEMU_ASYNC_JOB_START) < 0)
                goto endjob;
            rc = qemuMonitorLoadSnapshot(priv->mon, snap->def->name);
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto endjob;
            if (rc < 0) {
                /* XXX resume domain if it was running before the
                 * failed loadvm attempt? */
                goto endjob;
            }
            if (config) {
                virCPUDefFree(priv->origCPU);
                priv->origCPU = g_steal_pointer(&origCPU);
            }

            if (cookie && !cookie->slirpHelper)
                priv->disableSlirp = true;

            if (inactiveConfig) {
                virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
                inactiveConfig = NULL;
                defined = true;
            }
        } else {
            /* Transitions 2, 3 */
        load:
            was_stopped = true;

            if (inactiveConfig) {
                virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
                inactiveConfig = NULL;
                defined = true;
            }

            if (config) {
                virDomainObjAssignDef(vm, config, true, NULL);
                config = NULL;
            }

            /* No cookie means libvirt which saved the domain was too old to
             * mess up the CPU definitions.
             */
            if (cookie &&
                qemuDomainFixupCPUs(vm, &cookie->cpu) < 0)
                goto cleanup;

            rc = qemuProcessStart(snapshot->domain->conn, driver, vm,
                                  cookie ? cookie->cpu : NULL,
                                  QEMU_ASYNC_JOB_START, NULL, -1, NULL, snap,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  start_flags);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             detail);
            if (rc < 0)
                goto endjob;
        }

        /* Touch up domain state.  */
        if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING) &&
            (snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED ||
             (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            /* Transitions 3, 6, 9 */
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
            if (was_stopped) {
                /* Transition 3, use event as-is and add event2 */
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);
            } /* else transition 6 and 9 use event as-is */
        } else {
            /* Transitions 2, 5, 8 */
            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto endjob;
            }
            rc = qemuProcessStartCPUs(driver, vm,
                                      VIR_DOMAIN_RUNNING_FROM_SNAPSHOT,
                                      QEMU_ASYNC_JOB_START);
            if (rc < 0)
                goto endjob;
            virObjectUnref(event);
            event = NULL;
            if (was_stopped) {
                /* Transition 2 */
                detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STARTED,
                                                 detail);
            }
        }
        break;

    case VIR_DOMAIN_SNAPSHOT_SHUTDOWN:
    case VIR_DOMAIN_SNAPSHOT_SHUTOFF:
    case VIR_DOMAIN_SNAPSHOT_CRASHED:
        /* Transitions 1, 4, 7 */
        /* Newer qemu -loadvm refuses to revert to the state of a snapshot
         * created by qemu-img snapshot -c.  If the domain is running, we
         * must take it offline; then do the revert using qemu-img.
         */

        if (virDomainObjIsActive(vm)) {
            /* Transitions 4, 7 */
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                            QEMU_ASYNC_JOB_START, 0);
            virDomainAuditStop(vm, "from-snapshot");
            detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             detail);
        }

        if (qemuSnapshotRevertInactive(driver, vm, snap) < 0) {
            qemuDomainRemoveInactive(driver, vm);
            qemuProcessEndJob(driver, vm);
            goto cleanup;
        }

        if (inactiveConfig) {
            virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
            inactiveConfig = NULL;
            defined = true;
        }

        if (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                     VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
            /* Flush first event, now do transition 2 or 3 */
            bool paused = (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED) != 0;

            start_flags |= paused ? VIR_QEMU_PROCESS_START_PAUSED : 0;

            virObjectEventStateQueue(driver->domainEventState, event);
            rc = qemuProcessStart(snapshot->domain->conn, driver, vm, NULL,
                                  QEMU_ASYNC_JOB_START, NULL, -1, NULL, NULL,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  start_flags);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            if (rc < 0) {
                qemuDomainRemoveInactive(driver, vm);
                qemuProcessEndJob(driver, vm);
                goto cleanup;
            }
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             detail);
            if (paused) {
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);
            }
        }
        break;

    case VIR_DOMAIN_SNAPSHOT_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support reversion of snapshot taken in "
                         "PMSUSPENDED state"));
        goto endjob;

    case VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT:
        /* Rejected earlier as an external snapshot */
    case VIR_DOMAIN_SNAPSHOT_NOSTATE:
    case VIR_DOMAIN_SNAPSHOT_BLOCKED:
    case VIR_DOMAIN_SNAPSHOT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid target domain state '%s'. Refusing "
                         "snapshot reversion"),
                       virDomainSnapshotStateTypeToString(snapdef->state));
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuProcessEndJob(driver, vm);

 cleanup:
    if (ret == 0) {
        virDomainSnapshotSetCurrent(vm->snapshots, snap);
        if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                            driver->xmlopt,
                                            cfg->snapshotDir) < 0) {
            virDomainSnapshotSetCurrent(vm->snapshots, NULL);
            ret = -1;
        }
    }
    if (ret == 0 && defined && vm->persistent &&
        !(ret = virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                                 driver->xmlopt, cfg->configDir))) {
        detail = VIR_DOMAIN_EVENT_DEFINED_FROM_SNAPSHOT;
        virObjectEventStateQueue(driver->domainEventState,
            virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              detail));
    }
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, event2);
    virCPUDefFree(origCPU);
    virDomainDefFree(config);
    virDomainDefFree(inactiveConfig);

    return ret;
}


typedef struct _virQEMUMomentReparent virQEMUMomentReparent;
typedef virQEMUMomentReparent *virQEMUMomentReparentPtr;
struct _virQEMUMomentReparent {
    const char *dir;
    virDomainMomentObjPtr parent;
    virDomainObjPtr vm;
    virDomainXMLOptionPtr xmlopt;
    int err;
    int (*writeMetadata)(virDomainObjPtr, virDomainMomentObjPtr,
                         virDomainXMLOptionPtr, const char *);
};


static int
qemuSnapshotChildrenReparent(void *payload,
                             const char *name G_GNUC_UNUSED,
                             void *data)
{
    virDomainMomentObjPtr moment = payload;
    virQEMUMomentReparentPtr rep = data;

    if (rep->err < 0)
        return 0;

    VIR_FREE(moment->def->parent_name);

    if (rep->parent->def)
        moment->def->parent_name = g_strdup(rep->parent->def->name);

    rep->err = rep->writeMetadata(rep->vm, moment, rep->xmlopt,
                                  rep->dir);
    return 0;
}


int
qemuSnapshotDelete(virDomainObjPtr vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags)
{
    virQEMUDriverPtr driver = snapshot->domain->conn->privateData;
    int ret = -1;
    virDomainMomentObjPtr snap = NULL;
    virQEMUMomentRemove rem;
    virQEMUMomentReparent rep;
    bool metadata_only = !!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY);
    int external = 0;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, -1);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;

    if (!metadata_only) {
        if (!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) &&
            virDomainSnapshotIsExternal(snap))
            external++;
        if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                     VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY))
            virDomainMomentForEachDescendant(snap,
                                             qemuSnapshotCountExternal,
                                             &external);
        if (external) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("deletion of %d external disk snapshots not "
                             "supported yet"), external);
            goto endjob;
        }
    }

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        rem.driver = driver;
        rem.vm = vm;
        rem.metadata_only = metadata_only;
        rem.err = 0;
        rem.current = virDomainSnapshotGetCurrent(vm->snapshots);
        rem.found = false;
        rem.momentDiscard = qemuDomainSnapshotDiscard;
        virDomainMomentForEachDescendant(snap, qemuDomainMomentDiscardAll,
                                         &rem);
        if (rem.err < 0)
            goto endjob;
        if (rem.found) {
            virDomainSnapshotSetCurrent(vm->snapshots, snap);
            if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) {
                if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                                    driver->xmlopt,
                                                    cfg->snapshotDir) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("failed to set snapshot '%s' as current"),
                                   snap->def->name);
                    virDomainSnapshotSetCurrent(vm->snapshots, NULL);
                    goto endjob;
                }
            }
        }
    } else if (snap->nchildren) {
        rep.dir = cfg->snapshotDir;
        rep.parent = snap->parent;
        rep.vm = vm;
        rep.err = 0;
        rep.xmlopt = driver->xmlopt;
        rep.writeMetadata = qemuDomainSnapshotWriteMetadata;
        virDomainMomentForEachChild(snap,
                                    qemuSnapshotChildrenReparent,
                                    &rep);
        if (rep.err < 0)
            goto endjob;
        virDomainMomentMoveChildren(snap, snap->parent);
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) {
        virDomainMomentDropChildren(snap);
        ret = 0;
    } else {
        ret = qemuDomainSnapshotDiscard(driver, vm, snap, true, metadata_only);
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    return ret;
}
