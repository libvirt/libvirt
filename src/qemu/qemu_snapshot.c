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

#include <fcntl.h>

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
#include "virdomainsnapshotobjlist.h"
#include "virqemu.h"
#include "storage_source.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_snapshot");


/**
 * qemuSnapshotSetCurrent: Set currently active snapshot
 *
 * @vm: domain object
 * @newcurrent: snapshot object to set as current/active
 *
 * Sets @newcurrent as the 'current' snapshot of @vm. This helper ensures that
 * the snapshot which was 'current' previously is updated.
 */
static void
qemuSnapshotSetCurrent(virDomainObj *vm,
                       virDomainMomentObj *newcurrent)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainMomentObj *oldcurrent = virDomainSnapshotGetCurrent(vm->snapshots);

    virDomainSnapshotSetCurrent(vm->snapshots, newcurrent);

    /* we need to write out metadata for the old snapshot to update the
     * 'active' property */
    if (oldcurrent &&
        oldcurrent != newcurrent) {
        if (qemuDomainSnapshotWriteMetadata(vm, oldcurrent, driver->xmlopt, cfg->snapshotDir) < 0)
            VIR_WARN("failed to update old current snapshot");
    }
}


/* Looks up snapshot object from VM and name */
virDomainMomentObj *
qemuSnapObjFromName(virDomainObj *vm,
                    const char *name)
{
    virDomainMomentObj *snap = NULL;
    snap = virDomainSnapshotFindByName(vm->snapshots, name);
    if (!snap)
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("no domain snapshot with matching name '%1$s'"),
                       name);

    return snap;
}


/* Looks up snapshot object from VM and snapshotPtr */
virDomainMomentObj *
qemuSnapObjFromSnapshot(virDomainObj *vm,
                        virDomainSnapshotPtr snapshot)
{
    return qemuSnapObjFromName(vm, snapshot->name);
}


int
qemuSnapshotFSFreeze(virDomainObj *vm,
                     const char **mountpoints,
                     unsigned int nmountpoints)
{
    qemuAgent *agent;
    int frozen;

    if (!qemuDomainAgentAvailable(vm, true))
        return -1;

    agent = qemuDomainObjEnterAgent(vm);
    frozen = qemuAgentFSFreeze(agent, mountpoints, nmountpoints);
    qemuDomainObjExitAgent(vm, agent);
    return frozen;
}


/* Return -1 on error, otherwise number of thawed filesystems. */
int
qemuSnapshotFSThaw(virDomainObj *vm,
                   bool report)
{
    qemuAgent *agent;
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


static int
qemuSnapshotDomainDefUpdateDisk(virDomainDef *domdef,
                                virDomainSnapshotDef *snapdef,
                                bool reuse)
{
    size_t i;

    for (i = 0; i < snapdef->ndisks; i++) {
        g_autoptr(virStorageSource) newsrc = NULL;
        virDomainSnapshotDiskDef *snapdisk = &(snapdef->disks[i]);
        virDomainDiskDef *defdisk = virDomainDiskByName(domdef, snapdisk->name, false);

        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!defdisk)
            continue;

        if (!(newsrc = virStorageSourceCopy(snapdisk->src, false)))
            return -1;

        if (virStorageSourceInitChainElement(newsrc, defdisk->src, false) < 0)
            return -1;

        if (!reuse &&
            virStorageSourceHasBacking(defdisk->src)) {
            defdisk->src->readonly = true;
            newsrc->backingStore = g_steal_pointer(&defdisk->src);
        } else {
            virObjectUnref(defdisk->src);
        }

        defdisk->src = g_steal_pointer(&newsrc);
    }

    return 0;
}


/**
 * qemuSnapshotCreateQcow2Files:
 * @driver: QEMU driver
 * @def: domain definition
 * @snapdef: snapshot definition
 * @created: bitmap to store which disks were created
 *
 * Create new qcow2 images based on snapshot definition @snapdef and use
 * domain definition @def as source for backing images.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuSnapshotCreateQcow2Files(virQEMUDriver *driver,
                             virDomainDef *def,
                             virDomainSnapshotDef *snapdef,
                             virBitmap *created)
{
    size_t i;
    const char *qemuImgPath;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virDomainSnapshotDiskDef *snapdisk = NULL;
    virDomainDiskDef *defdisk = NULL;

    if (!(qemuImgPath = qemuFindQemuImgBinary(driver)))
        return -1;

    for (i = 0; i < snapdef->ndisks; i++) {
        g_autoptr(virCommand) cmd = NULL;
        snapdisk = &(snapdef->disks[i]);
        defdisk = def->disks[i];

        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!snapdisk->src->format)
            snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;

        if (qemuDomainStorageSourceValidateDepth(defdisk->src, 1, defdisk->dst) < 0)
            return -1;

        /* creates cmd line args: qemu-img create -f qcow2 -o */
        if (!(cmd = virCommandNewArgList(qemuImgPath,
                                         "create",
                                         "-f",
                                         virStorageFileFormatTypeToString(snapdisk->src->format),
                                         "-o",
                                         NULL)))
            return -1;

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
            return -1;
    }

    return 0;
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotCreateInactiveInternal(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainMomentObj *snap)
{
    return qemuDomainSnapshotForEachQcow2(driver, vm->def, snap, "-c", false);
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotCreateInactiveExternal(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainMomentObj *snap,
                                   bool reuse)
{
    virDomainSnapshotDiskDef *snapdisk;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    g_autoptr(virBitmap) created = virBitmapNew(snapdef->ndisks);

    /* If reuse is true, then qemuSnapshotPrepare already
     * ensured that the new files exist, and it was up to the user to
     * create them correctly.  */
    if (!reuse && qemuSnapshotCreateQcow2Files(driver, vm->def, snapdef, created) < 0)
        goto cleanup;

    /* update disk definitions */
    if (qemuSnapshotDomainDefUpdateDisk(vm->def, snapdef, reuse) < 0)
        goto cleanup;

    if (virDomainDefSave(vm->def, driver->xmlopt, cfg->configDir) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
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

    return ret;
}


/* The domain is expected to be locked and active. */
static int
qemuSnapshotCreateActiveInternal(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 virDomainMomentObj *snap,
                                 unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event = NULL;
    bool resume = false;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    int ret = -1;

    if (!qemuMigrationSrcIsAllowed(vm, false, VIR_ASYNC_JOB_SNAPSHOT, 0))
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* savevm monitor command pauses the domain emitting an event which
         * confuses libvirt since it's not notified when qemu resumes the
         * domain. Thus we stop and start CPUs ourselves.
         */
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                VIR_ASYNC_JOB_SNAPSHOT) < 0)
            goto cleanup;

        resume = true;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_SNAPSHOT) < 0) {
        resume = false;
        goto cleanup;
    }

    ret = qemuMonitorCreateSnapshot(priv->mon, snap->def->name);
    qemuDomainObjExitMonitor(vm);
    if (ret < 0)
        goto cleanup;

    if (!(snapdef->cookie = (virObject *) qemuDomainSaveCookieNew(vm)))
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        VIR_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
    }

 cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             VIR_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_API_ERROR);
        }
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }
    }

    virObjectEventStateQueue(driver->domainEventState, event);

    return ret;
}


static int
qemuSnapshotPrepareDiskShared(virDomainSnapshotDiskDef *snapdisk,
                              virDomainDiskDef *domdisk)
{
    if (!domdisk->src->shared || domdisk->src->readonly)
        return 0;

    if (!qemuBlockStorageSourceSupportsConcurrentAccess(snapdisk->src)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shared access for disk '%1$s' requires use of supported storage format"),
                       domdisk->dst);
        return -1;
    }

    return 0;
}


static int
qemuSnapshotPrepareDiskExternalInactive(virDomainSnapshotDiskDef *snapdisk,
                                        virDomainDiskDef *domdisk)
{
    virStorageType domDiskType = virStorageSourceGetActualType(domdisk->src);
    virStorageType snapDiskType = virStorageSourceGetActualType(snapdisk->src);

    switch (domDiskType) {
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
        case VIR_STORAGE_NET_PROTOCOL_NFS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("external inactive snapshots are not supported on 'network' disks using '%1$s' protocol"),
                           virStorageNetProtocolTypeToString(domdisk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on '%1$s' disks"),
                       virStorageTypeToString(domDiskType));
        return -1;
    }

    switch (snapDiskType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        break;

    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on '%1$s' disks"),
                       virStorageTypeToString(snapDiskType));
        return -1;
    }

    if (qemuSnapshotPrepareDiskShared(snapdisk, domdisk) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotPrepareDiskExternalActive(virDomainSnapshotDiskDef *snapdisk,
                                      virDomainDiskDef *domdisk)
{
    virStorageType actualType = virStorageSourceGetActualType(snapdisk->src);

    if (snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_MANUAL)
        return 0;

    if (domdisk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("external active snapshots are not supported on scsi passthrough devices"));
        return -1;
    }

    if (!qemuDomainDiskBlockJobIsSupported(domdisk))
        return -1;

    switch (actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_NETWORK:
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external active snapshots are not supported on '%1$s' disks"),
                       virStorageTypeToString(actualType));
        return -1;
    }

    if (qemuSnapshotPrepareDiskShared(snapdisk, domdisk) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotPrepareDiskExternal(virDomainDiskDef *disk,
                                virDomainSnapshotDiskDef *snapdisk,
                                bool active,
                                bool reuse)
{
    if (!snapdisk->src->format) {
        snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;
    } else if (snapdisk->src->format != VIR_STORAGE_FILE_QCOW2 &&
               snapdisk->src->format != VIR_STORAGE_FILE_QED) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("external snapshot format for disk %1$s is unsupported: %2$s"),
                       snapdisk->name,
                       virStorageFileFormatTypeToString(snapdisk->src->format));
        return -1;
    }

    if (snapdisk->src->metadataCacheMaxSize > 0) {
        if (snapdisk->src->format != VIR_STORAGE_FILE_QCOW2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("metadata cache max size control is supported only with qcow2 images"));
            return -1;
        }
    }

    if (qemuTranslateSnapshotDiskSourcePool(snapdisk) < 0)
        return -1;

    if (!active) {
        if (virDomainDiskTranslateSourcePool(disk) < 0)
            return -1;

        if (qemuSnapshotPrepareDiskExternalInactive(snapdisk, disk) < 0)
            return -1;
    } else {
        if (qemuSnapshotPrepareDiskExternalActive(snapdisk, disk) < 0)
            return -1;
    }

    if (virStorageSourceIsLocalStorage(snapdisk->src)) {
        struct stat st;
        int err;
        int rc;

        if (virStorageSourceInit(snapdisk->src) < 0)
            return -1;

        rc = virStorageSourceStat(snapdisk->src, &st);
        err = errno;

        virStorageSourceDeinit(snapdisk->src);

        if (rc < 0) {
            if (err != ENOENT) {
                virReportSystemError(err,
                                     _("unable to stat for disk %1$s: %2$s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            }

            if (reuse) {
                virReportSystemError(err,
                                     _("missing existing file for disk %1$s: %2$s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            }

            if (snapdisk->src->type == VIR_STORAGE_TYPE_BLOCK) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("block device snapshot target '%1$s' doesn't exist"),
                               snapdisk->src->path);
                return -1;
            }
        } else {
            /* at this point VIR_STORAGE_TYPE_DIR was already rejected */
            if ((snapdisk->src->type == VIR_STORAGE_TYPE_BLOCK && !S_ISBLK(st.st_mode)) ||
                (snapdisk->src->type == VIR_STORAGE_TYPE_FILE && !S_ISREG(st.st_mode))) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("mismatch between configured type for snapshot disk '%1$s' and the type of existing file '%2$s'"),
                               snapdisk->name, snapdisk->src->path);
                return -1;
            }

            if (!reuse &&
                snapdisk->src->type == VIR_STORAGE_TYPE_FILE &&
                st.st_size > 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot file for disk %1$s already exists and is not a block device: %2$s"),
                               snapdisk->name, snapdisk->src->path);
                return -1;
            }
        }
    }

    return 0;
}


static int
qemuSnapshotPrepareDiskInternal(virDomainDiskDef *disk,
                                bool active)
{
    virStorageType actualType;

    /* active disks are handled by qemu itself so no need to worry about those */
    if (active)
        return 0;

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        return -1;

    actualType = virStorageSourceGetActualType(disk->src);

    switch (actualType) {
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
        case VIR_STORAGE_NET_PROTOCOL_NFS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("internal inactive snapshots are not supported on 'network' disks using '%1$s' protocol"),
                           virStorageNetProtocolTypeToString(disk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("internal inactive snapshots are not supported on '%1$s' disks"),
                       virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuSnapshotPrepare(virDomainObj *vm,
                    virDomainSnapshotDef *def,
                    bool *has_manual,
                    unsigned int *flags)
{
    size_t i;
    bool active = virDomainObjIsActive(vm);
    bool reuse = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    bool found_internal = false;
    bool forbid_internal = false;
    int external = 0;

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDef *disk = &def->disks[i];
        virDomainDiskDef *dom_disk = vm->def->disks[i];

        if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_NO &&
            qemuDomainDiskBlockJobIsActive(dom_disk))
            return -1;

        switch ((virDomainSnapshotLocation) disk->snapshot) {
        case VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL:
            found_internal = true;

            if (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT && active) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("active qemu domains require external disk snapshots; disk %1$s requested internal"),
                               disk->name);
                return -1;
            }

            if (qemuSnapshotPrepareDiskInternal(dom_disk,
                                                active) < 0)
                return -1;

            if (dom_disk->src->format > 0 &&
                dom_disk->src->format != VIR_STORAGE_FILE_QCOW2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("internal snapshot for disk %1$s unsupported for storage type %2$s"),
                               disk->name,
                               virStorageFileFormatTypeToString(dom_disk->src->format));
                return -1;
            }
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL:
            if (qemuSnapshotPrepareDiskExternal(dom_disk, disk, active, reuse) < 0)
                return -1;

            external++;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_MANUAL:
            *has_manual = true;
            forbid_internal = true;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_NO:
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
        def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nothing selected for snapshot"));
        return -1;
    }

    /* internal snapshot requires a disk image to store the memory image to, and
     * also disks can't be excluded from an internal snapshot */
    if ((def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && !found_internal) ||
        (found_internal && forbid_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("internal and full system snapshots require all disks to be selected for snapshot"));
        return -1;
    }

    /* disk snapshot requires at least one disk */
    if (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT && !external) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("disk-only snapshots require at least one disk to be selected for snapshot"));
        return -1;
    }

    /* For now, we don't allow mixing internal and external disks.
     * XXX technically, we could mix internal and external disks for
     * offline snapshots */
    if ((found_internal && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL && found_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("mixing internal and external targets for a snapshot is not yet supported"));
        return -1;
    }

    /* internal snapshots + pflash based loader have the following problems:
     * - if the variable store is raw, the snapshot fails
     * - allowing a qcow2 image as the varstore would make it eligible to receive
     *   the vmstate dump, which would make it huge
     *
     * While offline snapshot would not snapshot the varstore at all, this used
     * to work as auto-detected UEFI firmware was not present in the offline
     * definition. Since in most cases the varstore doesn't change it's usually
     * not an issue. Allow this as there are existing users of this case.
     *
     * Avoid the issues by forbidding internal snapshot with pflash if the
     * VM is active.
     */
    if (active &&
        found_internal &&
        virDomainDefHasOldStyleUEFI(vm->def)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("internal snapshots of a VM with pflash based firmware are not supported"));
        return -1;
    }

    /* Alter flags to let later users know what we learned.  */
    if (external && !active)
        *flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;

    return 0;
}


struct _qemuSnapshotDiskData {
    virStorageSource *src;
    bool initialized; /* @src was initialized in the storage driver */
    bool created; /* @src was created by the snapshot code */
    bool prepared; /* @src was prepared using qemuDomainStorageSourceAccessAllow */
    virDomainDiskDef *disk;
    char *relPath; /* relative path component to fill into original disk */
    qemuBlockStorageSourceChainData *crdata;
    bool blockdevadded;

    virStorageSource *persistsrc;
    virDomainDiskDef *persistdisk;
};

typedef struct _qemuSnapshotDiskData qemuSnapshotDiskData;


static void
qemuSnapshotDiskCleanup(qemuSnapshotDiskData *data,
                        size_t ndata,
                        virDomainObj *vm,
                        virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
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
                if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) == 0) {

                    qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm),
                                                         data[i].crdata->srcdata[0]);
                    qemuDomainObjExitMonitor(vm);
                }
            }

            if (data[i].created &&
                virStorageSourceUnlink(data[i].src) < 0) {
                VIR_WARN("Unable to remove just-created %s",
                         NULLSTR(data[i].src->path));
            }

            if (data[i].initialized)
                virStorageSourceDeinit(data[i].src);

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
    qemuSnapshotDiskData *dd;
    size_t ndd;

    virJSONValue *actions;

    virQEMUDriverConfig *cfg;

    /* needed for automatic cleanup of 'dd' */
    virDomainObj *vm;
    virDomainAsyncJob asyncJob;
};

typedef struct _qemuSnapshotDiskContext qemuSnapshotDiskContext;


qemuSnapshotDiskContext *
qemuSnapshotDiskContextNew(size_t ndisks,
                           virDomainObj *vm,
                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    qemuSnapshotDiskContext *ret = g_new0(qemuSnapshotDiskContext, 1);

    ret->dd = g_new0(qemuSnapshotDiskData, ndisks);
    ret->actions = virJSONValueNewArray();
    ret->vm = vm;
    ret->cfg = virQEMUDriverGetConfig(driver);
    ret->asyncJob = asyncJob;

    return ret;
}


void
qemuSnapshotDiskContextCleanup(qemuSnapshotDiskContext *snapctxt)
{
    if (!snapctxt)
        return;

    virJSONValueFree(snapctxt->actions);

    qemuSnapshotDiskCleanup(snapctxt->dd, snapctxt->ndd, snapctxt->vm, snapctxt->asyncJob);

    virObjectUnref(snapctxt->cfg);

    g_free(snapctxt);
}


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
qemuSnapshotDiskBitmapsPropagate(qemuSnapshotDiskData *dd,
                                 virJSONValue *actions,
                                 GHashTable *blockNamedNodeData)
{
    qemuBlockNamedNodeData *entry;
    size_t i;

    if (!(entry = virHashLookup(blockNamedNodeData,
                                qemuBlockStorageSourceGetEffectiveNodename(dd->disk->src))))
        return 0;

    for (i = 0; i < entry->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmap *bitmap = entry->bitmaps[i];

        /* we don't care about temporary, inconsistent, or disabled bitmaps */
        if (!bitmap->persistent || !bitmap->recording || bitmap->inconsistent)
            continue;

        if (qemuMonitorTransactionBitmapAdd(actions,
                                            qemuBlockStorageSourceGetEffectiveNodename(dd->src),
                                            bitmap->name, true, false,
                                            bitmap->granularity) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSnapshotDiskPrepareOneBlockdev(virDomainObj *vm,
                                   qemuSnapshotDiskData *dd,
                                   virQEMUDriverConfig *cfg,
                                   bool reuse,
                                   GHashTable *blockNamedNodeData,
                                   virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virStorageSource) terminator = NULL;
    int rc;

    /* create a terminator for the snapshot disks so that qemu does not try
     * to open them at first */
    terminator = virStorageSourceNew();

    if (qemuDomainPrepareStorageSourceBlockdev(dd->disk, dd->src,
                                               priv, cfg) < 0)
        return -1;

    if (!(dd->crdata = qemuBuildStorageSourceChainAttachPrepareBlockdevTop(dd->src,
                                                                           terminator)))
        return -1;

    if (reuse) {
        if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
            return -1;

        rc = qemuBlockStorageSourceAttachApply(qemuDomainGetMonitor(vm),
                                               dd->crdata->srcdata[0]);

        qemuDomainObjExitMonitor(vm);
        if (rc < 0)
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


int
qemuSnapshotDiskPrepareOne(qemuSnapshotDiskContext *snapctxt,
                           virDomainDiskDef *disk,
                           virDomainSnapshotDiskDef *snapdisk,
                           GHashTable *blockNamedNodeData,
                           bool reuse,
                           bool updateConfig)
{
    virDomainObj *vm = snapctxt->vm;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virDomainDiskDef *persistdisk;
    qemuSnapshotDiskData *dd = snapctxt->dd + snapctxt->ndd++;

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

    if (virStorageSourceSupportsCreate(dd->src)) {
        if (qemuDomainStorageFileInit(driver, vm, dd->src, NULL) < 0)
            return -1;

        dd->initialized = true;

        if (!reuse) {
            /* pre-create the image file so that we can label it before handing it to qemu */
            if (dd->src->type != VIR_STORAGE_TYPE_BLOCK) {
                if (virStorageSourceCreate(dd->src) < 0) {
                    virReportSystemError(errno, _("failed to create image file '%1$s'"),
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

    if (qemuSnapshotDiskPrepareOneBlockdev(vm, dd, snapctxt->cfg, reuse,
                                           blockNamedNodeData, snapctxt->asyncJob) < 0)
        return -1;

    if (qemuSnapshotDiskBitmapsPropagate(dd, snapctxt->actions, blockNamedNodeData) < 0)
        return -1;

    if (qemuBlockSnapshotAddBlockdev(snapctxt->actions, dd->disk, dd->src) < 0)
        return -1;

    return 0;
}


/**
 * qemuSnapshotDiskPrepareActiveExternal:
 *
 * Collects and prepares a list of structures that hold information about disks
 * that are selected for the snapshot.
 */
static qemuSnapshotDiskContext *
qemuSnapshotDiskPrepareActiveExternal(virDomainObj *vm,
                                      virDomainMomentObj *snap,
                                      bool reuse,
                                      GHashTable *blockNamedNodeData,
                                      virDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    size_t i;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

    snapctxt = qemuSnapshotDiskContextNew(snapdef->ndisks, vm, asyncJob);

    for (i = 0; i < snapdef->ndisks; i++) {
        if (snapdef->disks[i].snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (qemuSnapshotDiskPrepareOne(snapctxt,
                                       vm->def->disks[i],
                                       snapdef->disks + i,
                                       blockNamedNodeData,
                                       reuse,
                                       true) < 0)
            return NULL;
    }

    return g_steal_pointer(&snapctxt);
}


virDomainSnapshotDiskDef *
qemuSnapshotGetTransientDiskDef(virDomainDiskDef *domdisk,
                                const char *suffix)
{
    g_autoptr(virDomainSnapshotDiskDef) snapdisk = g_new0(virDomainSnapshotDiskDef, 1);

    snapdisk->name = g_strdup(domdisk->dst);
    snapdisk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    snapdisk->src = virStorageSourceNew();
    snapdisk->src->type = VIR_STORAGE_TYPE_FILE;
    snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;
    snapdisk->src->path = g_strdup_printf("%s.TRANSIENT-%s",
                                          domdisk->src->path, suffix);

    if (virFileExists(snapdisk->src->path)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Overlay file '%1$s' for transient disk '%2$s' already exists"),
                       snapdisk->src->path, domdisk->dst);
        return NULL;
    }

    return g_steal_pointer(&snapdisk);
}


/**
 * qemuSnapshotDiskUpdateSource:
 * @vm: domain object
 * @dd: snapshot disk data object
 *
 * Updates disk definition after a successful snapshot.
 */
static void
qemuSnapshotDiskUpdateSource(virDomainObj *vm,
                             qemuSnapshotDiskData *dd)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;

    /* storage driver access won'd be needed */
    if (dd->initialized)
        virStorageSourceDeinit(dd->src);

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

    if (dd->persistdisk) {
        dd->persistdisk->src->readonly = true;
        dd->persistsrc->backingStore = g_steal_pointer(&dd->persistdisk->src);
        dd->persistdisk->src = g_steal_pointer(&dd->persistsrc);
    }
}


int
qemuSnapshotDiskCreate(qemuSnapshotDiskContext *snapctxt)
{
    qemuDomainObjPrivate *priv = snapctxt->vm->privateData;
    virQEMUDriver *driver = priv->driver;
    size_t i;
    int rc;

    /* check whether there's anything to do */
    if (snapctxt->ndd == 0)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(snapctxt->vm, snapctxt->asyncJob) < 0)
        return -1;

    rc = qemuMonitorTransaction(priv->mon, &snapctxt->actions);

    qemuDomainObjExitMonitor(snapctxt->vm);

    for (i = 0; i < snapctxt->ndd; i++) {
        qemuSnapshotDiskData *dd = snapctxt->dd + i;

        virDomainAuditDisk(snapctxt->vm, dd->disk->src, dd->src, "snapshot", rc >= 0);

        if (rc == 0)
            qemuSnapshotDiskUpdateSource(snapctxt->vm, dd);
    }

    if (rc < 0)
        return -1;

    if (virDomainObjSave(snapctxt->vm, driver->xmlopt, snapctxt->cfg->stateDir) < 0 ||
        (snapctxt->vm->newDef && virDomainDefSave(snapctxt->vm->newDef, driver->xmlopt,
                                                  snapctxt->cfg->configDir) < 0))
        return -1;

    return 0;
}


/* The domain is expected to be locked and active. */
static int
qemuSnapshotCreateActiveExternalDisks(virDomainObj *vm,
                                      virDomainMomentObj *snap,
                                      GHashTable *blockNamedNodeData,
                                      unsigned int flags,
                                      virDomainAsyncJob asyncJob)
{
    bool reuse = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;

    if (virDomainObjCheckActive(vm) < 0)
        return -1;

    /* prepare a list of objects to use in the vm definition so that we don't
     * have to roll back later */
    if (!(snapctxt = qemuSnapshotDiskPrepareActiveExternal(vm, snap, reuse,
                                                           blockNamedNodeData, asyncJob)))
        return -1;

    if (qemuSnapshotDiskCreate(snapctxt) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotCreateActiveExternal(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 virDomainMomentObj *snap,
                                 virQEMUDriverConfig *cfg,
                                 bool has_manual,
                                 unsigned int flags)
{
    virObjectEvent *event;
    bool resume = false;
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *xml = NULL;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    bool memory = snapdef->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    bool memory_unlink = false;
    bool memory_existing = false;
    bool thaw = false;
    bool pmsuspended = false;
    int compressed;
    g_autoptr(virCommand) compressor = NULL;
    virQEMUSaveData *data = NULL;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;

    /* If quiesce was requested, then issue a freeze command, and a
     * counterpart thaw command when it is actually sent to agent.
     * The command will fail if the guest is paused or the guest agent
     * is not running, or is already quiesced.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) {
        int frozen;

        if (virDomainObjBeginAgentJob(vm, VIR_AGENT_JOB_MODIFY) < 0)
            goto cleanup;

        if (virDomainObjCheckActive(vm) < 0) {
            virDomainObjEndAgentJob(vm);
            goto cleanup;
        }

        frozen = qemuSnapshotFSFreeze(vm, NULL, 0);
        virDomainObjEndAgentJob(vm);

        if (frozen < 0)
            goto cleanup;

        if (frozen > 0)
            thaw = true;
    }

    /* We need to track what state the guest is in, since taking the
     * snapshot may alter that state and we must restore it later.  */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PMSUSPENDED) {
        pmsuspended = true;
    } else if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* For full system external snapshots (those with memory), the guest
         * must pause (either by libvirt up front, or by qemu after
         * _LIVE converges). We don't want to unpause it though if user has
         * elected to manually snapshot some disks */
        if (memory && !has_manual)
            resume = true;

        /* we need to pause the VM even when we aren't taking a memory snapshot
         * when the user wants to manually snapshot some disks */
        if (((memory || has_manual) && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE)))  {
            if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SNAPSHOT,
                                    VIR_ASYNC_JOB_SNAPSHOT) < 0)
                goto cleanup;

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto cleanup;
            }
        }
    }

    /* We need to collect reply from 'query-named-block-nodes' prior to the
     * migration step as qemu deactivates bitmaps after migration so the result
     * would be wrong */
    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_SNAPSHOT)))
        goto cleanup;

    /* do the memory snapshot if necessary */
    if (memory) {
        /* check if migration is possible */
        if (!qemuMigrationSrcIsAllowed(vm, false, VIR_ASYNC_JOB_SNAPSHOT, 0))
            goto cleanup;

        qemuDomainJobSetStatsType(vm->job->current,
                                  QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP);

        /* allow the migration job to be cancelled or the domain to be paused */
        qemuDomainObjSetAsyncJobMask(vm, (VIR_JOB_DEFAULT_MASK |
                                          JOB_MASK(VIR_JOB_SUSPEND) |
                                          JOB_MASK(VIR_JOB_MIGRATION_OP)));

        if ((compressed = qemuSaveImageGetCompressionProgram(cfg->snapshotImageFormat,
                                                             &compressor,
                                                             "snapshot", false)) < 0)
            goto cleanup;

        if (!(xml = qemuDomainDefFormatLive(driver, priv->qemuCaps,
                                            vm->def, priv->origCPU,
                                            true, true)) ||
            !(snapdef->cookie = (virObject *) qemuDomainSaveCookieNew(vm)))
            goto cleanup;

        if (!(data = virQEMUSaveDataNew(xml,
                                        (qemuDomainSaveCookie *) snapdef->cookie,
                                        resume, compressed, driver->xmlopt)))
            goto cleanup;
        xml = NULL;

        memory_existing = virFileExists(snapdef->memorysnapshotfile);

        if ((ret = qemuSaveImageCreate(driver, vm, snapdef->memorysnapshotfile,
                                       data, compressor, 0,
                                       VIR_ASYNC_JOB_SNAPSHOT)) < 0)
            goto cleanup;

        /* the memory image was created, remove it on errors */
        if (!memory_existing)
            memory_unlink = true;

        /* forbid any further manipulation */
        qemuDomainObjSetAsyncJobMask(vm, VIR_JOB_DEFAULT_MASK);
    }

    /* the domain is now paused if a memory snapshot was requested */

    if ((ret = qemuSnapshotCreateActiveExternalDisks(vm, snap,
                                                     blockNamedNodeData, flags,
                                                     VIR_ASYNC_JOB_SNAPSHOT)) < 0)
        goto cleanup;

    /* the snapshot is complete now */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        VIR_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
        thaw = false;
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
                             VIR_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        virObjectEventStateQueue(driver->domainEventState, event);
        if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_API_ERROR);
        }
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }

        ret = -1;
    }

    if (thaw &&
        virDomainObjBeginAgentJob(vm, VIR_AGENT_JOB_MODIFY) >= 0 &&
        virDomainObjIsActive(vm)) {
        /* report error only on an otherwise successful snapshot */
        if (qemuSnapshotFSThaw(vm, ret == 0) < 0)
            ret = -1;

        virDomainObjEndAgentJob(vm);
    }

    virQEMUSaveDataFree(data);
    if (memory_unlink && ret < 0)
        unlink(snapdef->memorysnapshotfile);

    return ret;
}


static virDomainSnapshotDef*
qemuSnapshotCreateXMLParse(virDomainObj *vm,
                           virQEMUDriver *driver,
                           const char *xmlDesc,
                           unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    unsigned int parse_flags = 0;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) ||
        !virDomainObjIsActive(vm))
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_VALIDATE;

    return virDomainSnapshotDefParseString(xmlDesc, driver->xmlopt,
                                           priv->qemuCaps, NULL, parse_flags);
}


static int
qemuSnapshotCreateXMLValidateDef(virDomainObj *vm,
                                 virDomainSnapshotDef *def,
                                 unsigned int flags)
{
    bool redefine = flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    virDomainSnapshotState state;

    /* reject snapshot names containing slashes or starting with dot as
     * snapshot definitions are saved in files named by the snapshot name */
    if (!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        if (strchr(def->parent.name, '/')) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%1$s': name can't contain '/'"),
                           def->parent.name);
            return -1;
        }

        if (def->parent.name[0] == '.') {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%1$s': name can't start with '.'"),
                           def->parent.name);
            return -1;
        }
    }

    /* reject the VIR_DOMAIN_SNAPSHOT_CREATE_LIVE flag where not supported */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE &&
        (!virDomainObjIsActive(vm) ||
         def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live snapshot creation is supported only during full system snapshots"));
        return -1;
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
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %1$s"),
                           virDomainSnapshotStateTypeToString(state));
            return -1;
        }
        break;

    case VIR_DOMAIN_SNAPSHOT_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support taking snapshots of PMSUSPENDED guests"));
        return -1;

        /* invalid states */
    case VIR_DOMAIN_SNAPSHOT_NOSTATE:
    case VIR_DOMAIN_SNAPSHOT_BLOCKED: /* invalid state, unused in qemu */
    case VIR_DOMAIN_SNAPSHOT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %1$s"),
                       virDomainSnapshotStateTypeToString(state));
        return -1;
    }

    return 0;
}


static int
qemuSnapshotCreateAlignDisks(virDomainObj *vm,
                             virDomainSnapshotDef *def,
                             virQEMUDriver *driver,
                             unsigned int flags)
{
    g_autofree char *xml = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainSnapshotLocation align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;

    /* Easiest way to clone inactive portion of vm->def is via
     * conversion in and back out of xml.  */
    if (!(xml = qemuDomainDefFormatLive(driver, priv->qemuCaps,
                                        vm->def, priv->origCPU,
                                        true, true)) ||
        !(def->parent.dom = virDomainDefParseString(xml, driver->xmlopt,
                                                    priv->qemuCaps,
                                                    VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                    VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        return -1;

    if (vm->newDef) {
        def->parent.inactiveDom = virDomainDefCopy(vm->newDef,
                                                   driver->xmlopt, priv->qemuCaps, true);
        if (!def->parent.inactiveDom)
            return -1;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
        if (virDomainObjIsActive(vm))
            def->state = VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT;
        else
            def->state = VIR_DOMAIN_SNAPSHOT_SHUTOFF;
        def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;
    } else if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        def->state = virDomainObjGetState(vm, NULL);
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    } else {
        def->state = virDomainObjGetState(vm, NULL);

        if (virDomainObjIsActive(vm) &&
            def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NO) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("internal snapshot of a running VM must include the memory state"));
            return -1;
        }

        if (def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF)
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;
        else
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    }
    if (virDomainSnapshotAlignDisks(def, NULL, align_location, true, false) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotCreateWriteMetadata(virDomainObj *vm,
                                virDomainMomentObj *snap,
                                virQEMUDriver *driver,
                                virQEMUDriverConfig *cfg)
{
    if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                        driver->xmlopt,
                                        cfg->snapshotDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to save metadata for snapshot %1$s"),
                       snap->def->name);
        return -1;
    }

    virDomainSnapshotLinkParent(vm->snapshots, snap);

    return 0;
}


static void
qemuSnapshotClearRevertdisks(virDomainMomentObj *current)
{
    virDomainSnapshotDef *curdef = NULL;

    if (!current)
        return;

    curdef = virDomainSnapshotObjGetDef(current);

    if (curdef->revertdisks) {
        size_t i;

        for (i = 0; i < curdef->nrevertdisks; i++)
            virDomainSnapshotDiskDefClear(&curdef->revertdisks[i]);

        g_clear_pointer(&curdef->revertdisks, g_free);
        curdef->nrevertdisks = 0;
    }
}


static virDomainSnapshotPtr
qemuSnapshotRedefine(virDomainObj *vm,
                     virDomainPtr domain,
                     virDomainSnapshotDef *snapdeftmp,
                     virQEMUDriver *driver,
                     virQEMUDriverConfig *cfg,
                     unsigned int flags)
{
    virDomainMomentObj *snap = NULL;
    virDomainMomentObj *current = virDomainSnapshotGetCurrent(vm->snapshots);
    virDomainSnapshotPtr ret = NULL;
    g_autoptr(virDomainSnapshotDef) snapdef = virObjectRef(snapdeftmp);

    if (virDomainSnapshotRedefinePrep(vm, snapdef, &snap, driver->xmlopt, flags) < 0)
        return NULL;

    if (snap) {
        virDomainSnapshotReplaceDef(snap, &snapdef);
    } else {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, &snapdef)))
            return NULL;
    }

    /* XXX Should we validate that the redefined snapshot even
     * makes sense, such as checking that qemu-img recognizes the
     * snapshot name in at least one of the domain's disks?  */

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT) {
        qemuSnapshotClearRevertdisks(current);
        qemuSnapshotSetCurrent(vm, snap);
    }

    if (qemuSnapshotCreateWriteMetadata(vm, snap, driver, cfg) < 0)
        goto error;

    ret = virGetDomainSnapshot(domain, snap->def->name);
    if (!ret)
        goto error;

    return ret;

 error:
    virDomainSnapshotObjListRemove(vm->snapshots, snap);
    return NULL;
}


static virDomainSnapshotPtr
qemuSnapshotCreate(virDomainObj *vm,
                   virDomainPtr domain,
                   virDomainSnapshotDef *snapdeftmp,
                   virQEMUDriver *driver,
                   virQEMUDriverConfig *cfg,
                   unsigned int flags)
{
    g_autoptr(virDomainSnapshotDef) snapdef = virObjectRef(snapdeftmp);
    g_autoptr(virDomainMomentObj) tmpsnap = NULL;
    virDomainMomentObj *snap = NULL;
    virDomainMomentObj *current = NULL;
    virDomainSnapshotPtr ret = NULL;
    bool has_manual = false; /* user wants to manually snapshot some disks */

    if (qemuSnapshotCreateAlignDisks(vm, snapdef, driver, flags) < 0)
        return NULL;

    if (qemuSnapshotPrepare(vm, snapdef, &has_manual, &flags) < 0)
        return NULL;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA) {
        snap = tmpsnap = virDomainMomentObjNew();
        snap->def = &snapdef->parent;
        snapdef = NULL;
    } else {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, &snapdef)))
            return NULL;

        if ((current = virDomainSnapshotGetCurrent(vm->snapshots))) {
            snap->def->parent_name = g_strdup(current->def->name);
        }
    }

    /* actually do the snapshot */
    if (virDomainObjIsActive(vm)) {
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY ||
            virDomainSnapshotObjGetDef(snap)->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            /* external full system or disk snapshot */
            if (qemuSnapshotCreateActiveExternal(driver, vm, snap, cfg, has_manual, flags) < 0)
                goto error;
        } else {
            /* internal full system */
            if (qemuSnapshotCreateActiveInternal(driver, vm, snap, flags) < 0)
                goto error;
        }
    } else {
        /* inactive; qemuSnapshotPrepare guaranteed that we
         * aren't mixing internal and external, and altered flags to
         * contain DISK_ONLY if there is an external disk.  */
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            bool reuse = !!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);

            if (qemuSnapshotCreateInactiveExternal(driver, vm, snap, reuse) < 0)
                goto error;
        } else {
            if (qemuSnapshotCreateInactiveInternal(driver, vm, snap) < 0)
                goto error;
        }
    }

    if (!tmpsnap) {
        qemuSnapshotClearRevertdisks(current);
        qemuSnapshotSetCurrent(vm, snap);

        if (qemuSnapshotCreateWriteMetadata(vm, snap, driver, cfg) < 0)
            goto error;
    }

    ret = virGetDomainSnapshot(domain, snap->def->name);
    if (!ret)
        goto error;

    return ret;

 error:
    if (!tmpsnap)
        virDomainSnapshotObjListRemove(vm->snapshots, snap);
    return NULL;
}


virDomainSnapshotPtr
qemuSnapshotCreateXML(virDomainPtr domain,
                      virDomainObj *vm,
                      const char *xmlDesc,
                      unsigned int flags)
{
    virQEMUDriver *driver = domain->conn->privateData;
    virDomainSnapshotPtr snapshot = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
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

    if (qemuDomainSupportsCheckpointsBlockjobs(vm) < 0)
        return NULL;

    if (!vm->persistent && (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot halt after transient domain snapshot"));
        return NULL;
    }

    if (!(def = qemuSnapshotCreateXMLParse(vm, driver, xmlDesc, flags)))
        return NULL;

    if (qemuSnapshotCreateXMLValidateDef(vm, def, flags) < 0)
        return NULL;

    /* We are going to modify the domain below. Internal snapshots would use
     * a regular job, so we need to set the job mask to disallow query as
     * 'savevm' blocks the monitor. External snapshot will then modify the
     * job mask appropriately. */
    if (virDomainObjBeginAsyncJob(vm, VIR_ASYNC_JOB_SNAPSHOT,
                                   VIR_DOMAIN_JOB_OPERATION_SNAPSHOT, flags) < 0)
        return NULL;

    qemuDomainObjSetAsyncJobMask(vm, VIR_JOB_NONE);

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) {
        snapshot = qemuSnapshotRedefine(vm, domain, def, driver, cfg, flags);
    } else {
        snapshot = qemuSnapshotCreate(vm, domain, def, driver, cfg, flags);
    }

    virDomainObjEndAsyncJob(vm);

    return snapshot;
}


static int
qemuSnapshotRevertValidate(virDomainObj *vm,
                           virDomainMomentObj *snap,
                           virDomainSnapshotDef *snapdef,
                           unsigned int flags)
{
    if (!vm->persistent &&
        snapdef->state != VIR_DOMAIN_SNAPSHOT_RUNNING &&
        snapdef->state != VIR_DOMAIN_SNAPSHOT_PAUSED &&
        (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domain needs to request run or pause to revert to inactive snapshot"));
        return -1;
    }

    if (!snap->def->dom) {
        virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                       _("snapshot '%1$s' lacks domain '%2$s' rollback info"),
                       snap->def->name, vm->def->name);
        return -1;
    }

    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
        if (vm->hasManagedSave &&
            !(snapdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
              snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED)) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("snapshot without memory state, removal of existing managed saved state strongly recommended to avoid corruption"));
            return -1;
        }
    }

    return 0;
}


static int
qemuSnapshotRevertPrep(virDomainMomentObj *snap,
                       virDomainSnapshotDef *snapdef,
                       virQEMUDriver *driver,
                       virDomainObj *vm,
                       virDomainDef **retConfig,
                       virDomainDef **retInactiveConfig)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virDomainDef) config = NULL;
    g_autoptr(virDomainDef) inactiveConfig = NULL;

    config = virDomainDefCopy(snap->def->dom,
                              driver->xmlopt, priv->qemuCaps, true);
    if (!config)
        return -1;

    if (STRNEQ(config->name, vm->def->name)) {
        VIR_FREE(config->name);
        config->name = g_strdup(vm->def->name);
    }

    if (snap->def->inactiveDom) {
        inactiveConfig = virDomainDefCopy(snap->def->inactiveDom,
                                          driver->xmlopt, priv->qemuCaps, true);
        if (!inactiveConfig)
            return -1;

        if (STRNEQ(inactiveConfig->name, vm->def->name)) {
            VIR_FREE(inactiveConfig->name);
            inactiveConfig->name = g_strdup(vm->def->name);
        }
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
                return -1;
        } else {
            inactiveConfig = g_steal_pointer(&config);
        }
    }

    *retConfig = g_steal_pointer(&config);
    *retInactiveConfig = g_steal_pointer(&inactiveConfig);

    return 0;
}


static int
qemuSnapshotRevertWriteMetadata(virDomainObj *vm,
                                virDomainMomentObj *snap,
                                virQEMUDriver *driver,
                                virQEMUDriverConfig *cfg,
                                bool defined)
{
    qemuSnapshotSetCurrent(vm, snap);
    if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                        driver->xmlopt,
                                        cfg->snapshotDir) < 0) {
        virDomainSnapshotSetCurrent(vm->snapshots, NULL);
        return -1;
    }

    if (defined && vm->persistent) {
        int detail;
        virObjectEvent *event = NULL;
        virDomainDef *saveDef = vm->newDef ? vm->newDef : vm->def;

        if (virDomainDefSave(saveDef, driver->xmlopt, cfg->configDir) < 0)
            return -1;

        detail = VIR_DOMAIN_EVENT_DEFINED_FROM_SNAPSHOT;
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_DEFINED,
                                                  detail);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    return 0;
}


typedef struct _qemuSnapshotRevertMemoryData {
    int fd;
    char *path;
    virQEMUSaveData *data;
} qemuSnapshotRevertMemoryData;

static void
qemuSnapshotClearRevertMemoryData(qemuSnapshotRevertMemoryData *memdata)
{
    VIR_FORCE_CLOSE(memdata->fd);
    virQEMUSaveDataFree(memdata->data);
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(qemuSnapshotRevertMemoryData, qemuSnapshotClearRevertMemoryData);


/**
 * qemuSnapshotRevertExternalPrepare:
 * @vm: domain object
 * @tmpsnapdef: temporary snapshot definition
 * @snap: snapshot object we are reverting to
 * @config: live domain definition
 * @inactiveConfig: offline domain definition
 * @memdata: struct with data to load memory state
 *
 * Prepare new temporary snapshot definition @tmpsnapdef that will
 * be used while creating new overlay files after reverting to snapshot
 * @snap. In case we are reverting to snapshot with memory state it will
 * open it and store necessary data in @memdata. Caller is responsible
 * to clear the data by using qemuSnapshotClearRevertMemoryData().
 *
 * Returns 0 in success, -1 on error.
 */
static int
qemuSnapshotRevertExternalPrepare(virDomainObj *vm,
                                  virDomainSnapshotDef *tmpsnapdef,
                                  virDomainMomentObj *snap,
                                  virDomainDef *config,
                                  virDomainDef *inactiveConfig,
                                  qemuSnapshotRevertMemoryData *memdata)
{
    size_t i;
    bool active = virDomainObjIsActive(vm);
    virDomainDef *domdef = NULL;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

    if (config) {
        domdef = config;
    } else {
        domdef = inactiveConfig;
    }

    /* We need this to generate creation timestamp that is used as default
     * snapshot name. */
    if (virDomainMomentDefPostParse(&tmpsnapdef->parent) < 0)
        return -1;

    if (virDomainSnapshotAlignDisks(tmpsnapdef, domdef,
                                    VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL,
                                    false, true) < 0) {
        return -1;
    }

    for (i = 0; i < tmpsnapdef->ndisks; i++) {
        virDomainSnapshotDiskDef *snapdisk = &tmpsnapdef->disks[i];
        virDomainDiskDef *domdisk = domdef->disks[i];

        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (qemuSnapshotPrepareDiskExternal(domdisk, snapdisk, active, false) < 0)
            return -1;
    }

    if (memdata && snapdef->memorysnapshotfile) {
        virQEMUDriver *driver = ((qemuDomainObjPrivate *) vm->privateData)->driver;
        g_autoptr(virDomainDef) savedef = NULL;

        memdata->path = snapdef->memorysnapshotfile;
        memdata->fd = qemuSaveImageOpen(driver, NULL, memdata->path,
                                        &savedef, &memdata->data,
                                        false, NULL,
                                        false, false);

        if (memdata->fd < 0)
            return -1;

        if (!virDomainDefCheckABIStability(savedef, domdef, driver->xmlopt))
            return -1;
    }

    return 0;
}


/**
 * qemuSnapshotRevertExternalActive:
 * @vm: domain object
 * @tmpsnapdef: temporary snapshot definition
 *
 * Creates a new disk overlays using the temporary snapshot
 * definition @tmpsnapdef for running VM by calling QMP APIs.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuSnapshotRevertExternalActive(virDomainObj *vm,
                                 virDomainSnapshotDef *tmpsnapdef)
{
    size_t i;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;

    snapctxt = qemuSnapshotDiskContextNew(tmpsnapdef->ndisks, vm, VIR_ASYNC_JOB_SNAPSHOT);

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_SNAPSHOT)))
        return -1;

    for (i = 0; i < tmpsnapdef->ndisks; i++) {
        if (tmpsnapdef->disks[i].snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (qemuSnapshotDiskPrepareOne(snapctxt,
                                       vm->def->disks[i],
                                       tmpsnapdef->disks + i,
                                       blockNamedNodeData,
                                       false,
                                       true) < 0)
            return -1;
    }

    if (qemuSnapshotDiskCreate(snapctxt) < 0)
        return -1;

    return 0;
}


/**
 * qemuSnapshotRevertExternalInactive:
 * @vm: domain object
 * @tmpsnapdef: temporary snapshot definition
 * @domdef: offline domain definition
 *
 * Creates a new disk overlays using the temporary snapshot
 * definition @tmpsnapdef for offline VM by calling qemu-img.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuSnapshotRevertExternalInactive(virDomainObj *vm,
                                   virDomainSnapshotDef *tmpsnapdef,
                                   virDomainDef *domdef)
{
    virQEMUDriver *driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    g_autoptr(virBitmap) created = NULL;

    created = virBitmapNew(tmpsnapdef->ndisks);

    if (qemuSnapshotDomainDefUpdateDisk(domdef, tmpsnapdef, false) < 0)
        return -1;

    if (qemuSnapshotCreateQcow2Files(driver, domdef, tmpsnapdef, created) < 0) {
        ssize_t bit = -1;
        virErrorPtr err = NULL;

        virErrorPreserveLast(&err);

        while ((bit = virBitmapNextSetBit(created, bit)) >= 0) {
            virDomainSnapshotDiskDef *snapdisk = &(tmpsnapdef->disks[bit]);

            if (virStorageSourceInit(snapdisk->src) < 0 ||
                virStorageSourceUnlink(snapdisk->src) < 0) {
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->src->path);
            }
        }

        virErrorRestore(&err);

        return -1;
    }

    return 0;
}


/**
 * qemuSnapshotRevertExternalFinish:
 * @vm: domain object
 * @tmpsnapdef: temporary snapshot definition
 * @snap: snapshot object we are reverting to
 *
 * Finishes disk overlay creation by removing existing overlays that
 * will no longer be used if there are any and updating snapshot @snap
 * metadata and current snapshot metadata so it can be saved once the
 * revert is completed.
 */
static void
qemuSnapshotRevertExternalFinish(virDomainObj *vm,
                                 virDomainSnapshotDef *tmpsnapdef,
                                 virDomainMomentObj *snap)
{
    size_t i;
    virDomainMomentObj *curSnap = virDomainSnapshotGetCurrent(vm->snapshots);
    virDomainSnapshotDef *curdef = virDomainSnapshotObjGetDef(curSnap);
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

    if (curdef->revertdisks) {
        for (i = 0; i < curdef->nrevertdisks; i++) {
            virDomainSnapshotDiskDef *snapdisk = &(curdef->revertdisks[i]);

            if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
                continue;

            if (virStorageSourceInit(snapdisk->src) < 0 ||
                virStorageSourceUnlink(snapdisk->src) < 0) {
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->src->path);
            }

            virDomainSnapshotDiskDefClear(snapdisk);
        }

        g_clear_pointer(&curdef->revertdisks, g_free);
        curdef->nrevertdisks = 0;
    } else {
        for (i = 0; i < curdef->ndisks; i++) {
            virDomainSnapshotDiskDef *snapdisk = &(curdef->disks[i]);

            if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
                continue;

            if (virStorageSourceInit(snapdisk->src) < 0 ||
                virStorageSourceUnlink(snapdisk->src) < 0) {
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->src->path);
            }
        }
    }

    if (snap->nchildren != 0) {
        snapdef->revertdisks = g_steal_pointer(&tmpsnapdef->disks);
        snapdef->nrevertdisks = tmpsnapdef->ndisks;
        tmpsnapdef->ndisks = 0;
    } else {
        for (i = 0; i < snapdef->ndisks; i++) {
            virDomainSnapshotDiskDefClear(&snapdef->disks[i]);
        }
        g_free(snapdef->disks);
        snapdef->disks = g_steal_pointer(&tmpsnapdef->disks);
        snapdef->ndisks = tmpsnapdef->ndisks;
        tmpsnapdef->ndisks = 0;
    }
}


static int
qemuSnapshotRevertActive(virDomainObj *vm,
                         virDomainSnapshotPtr snapshot,
                         virDomainMomentObj *snap,
                         virDomainSnapshotDef *snapdef,
                         virQEMUDriver *driver,
                         virQEMUDriverConfig *cfg,
                         virDomainDef **config,
                         virDomainDef **inactiveConfig,
                         unsigned int start_flags,
                         unsigned int flags)
{
    virObjectEvent *event = NULL;
    virObjectEvent *event2 = NULL;
    virDomainMomentObj *loadSnap = NULL;
    int detail;
    bool defined = false;
    int rc;
    g_autoptr(virDomainSnapshotDef) tmpsnapdef = NULL;
    g_auto(qemuSnapshotRevertMemoryData) memdata = { -1, NULL, NULL };
    bool started = false;

    start_flags |= VIR_QEMU_PROCESS_START_PAUSED;

    /* Transitions 2, 3, 5, 6, 8, 9 */
    if (virDomainObjIsActive(vm)) {
        /* Transitions 5, 6, 8, 9 */
        qemuProcessStop(driver, vm,
                        VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        VIR_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STOPPED,
                                                  detail);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (virDomainSnapshotIsExternal(snap)) {
        if (!(tmpsnapdef = virDomainSnapshotDefNew()))
            return -1;

        if (qemuSnapshotRevertExternalPrepare(vm, tmpsnapdef, snap,
                                              *config, *inactiveConfig,
                                              &memdata) < 0) {
            return -1;
        }
    } else {
        loadSnap = snap;
    }

    if (*inactiveConfig) {
        virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
        defined = true;
    }

    virDomainObjAssignDef(vm, config, true, NULL);

    if (qemuProcessStartWithMemoryState(snapshot->domain->conn, driver, vm,
                                        &memdata.fd, memdata.path, loadSnap,
                                        memdata.data, VIR_ASYNC_JOB_SNAPSHOT,
                                        start_flags, "from-snapshot",
                                        &started) < 0) {
        if (started) {
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                            VIR_ASYNC_JOB_SNAPSHOT,
                            VIR_QEMU_PROCESS_STOP_MIGRATED);
        }
        return -1;
    }

    detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     detail);
    virObjectEventStateQueue(driver->domainEventState, event);

    if (virDomainSnapshotIsExternal(snap)) {
        if (qemuSnapshotRevertExternalActive(vm, tmpsnapdef) < 0)
            return -1;

        qemuSnapshotRevertExternalFinish(vm, tmpsnapdef, snap);
    }

    /* Touch up domain state.  */
    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING) &&
        (snapdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED ||
         (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
        /* Transitions 3, 6, 9 */
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
        detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
        event2 = virDomainEventLifecycleNewFromObj(vm,
                                          VIR_DOMAIN_EVENT_SUSPENDED,
                                          detail);
        virObjectEventStateQueue(driver->domainEventState, event2);
    } else {
        /* Transitions 2, 5, 8 */
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            return -1;
        }
        rc = qemuProcessStartCPUs(driver, vm,
                                  VIR_DOMAIN_RUNNING_FROM_SNAPSHOT,
                                  VIR_ASYNC_JOB_SNAPSHOT);
        if (rc < 0)
            return -1;
    }

    return qemuSnapshotRevertWriteMetadata(vm, snap, driver, cfg, defined);
}


/* The domain is expected to be locked and inactive. */
static int
qemuSnapshotInternalRevertInactive(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainMomentObj *snap)
{
    size_t i;

    /* Prefer action on the disks in use at the time the snapshot was
     * created; but fall back to current definition if dealing with a
     * snapshot created prior to libvirt 0.9.5.  */
    virDomainDef *def = snap->def->dom;

    if (!def)
        def = vm->def;

    for (i = 0; i < def->ndisks; i++) {
        if (virDomainDiskTranslateSourcePool(def->disks[i]) < 0)
            return -1;
    }

    /* Try all disks, but report failure if we skipped any.  */
    if (qemuDomainSnapshotForEachQcow2(driver, def, snap, "-a", true) != 0)
        return -1;

    return 0;
}


static int
qemuSnapshotRevertInactive(virDomainObj *vm,
                           virDomainSnapshotPtr snapshot,
                           virDomainMomentObj *snap,
                           virQEMUDriver *driver,
                           virQEMUDriverConfig *cfg,
                           virDomainDef **inactiveConfig,
                           unsigned int start_flags,
                           unsigned int flags)
{
    virObjectEvent *event = NULL;
    virObjectEvent *event2 = NULL;
    int detail;
    bool defined = false;
    int rc;
    g_autoptr(virDomainSnapshotDef) tmpsnapdef = NULL;

    /* Transitions 1, 4, 7 */
    /* Newer qemu -loadvm refuses to revert to the state of a snapshot
     * created by qemu-img snapshot -c.  If the domain is running, we
     * must take it offline; then do the revert using qemu-img.
     */

    if (virDomainObjIsActive(vm)) {
        /* Transitions 4, 7 */
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        VIR_ASYNC_JOB_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         detail);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (virDomainSnapshotIsExternal(snap)) {
        if (!(tmpsnapdef = virDomainSnapshotDefNew()))
            return -1;

        if (qemuSnapshotRevertExternalPrepare(vm, tmpsnapdef, snap,
                                              NULL, *inactiveConfig, NULL) < 0) {
            return -1;
        }

        if (qemuSnapshotRevertExternalInactive(vm, tmpsnapdef,
                                               *inactiveConfig) < 0) {
            return -1;
        }

        qemuSnapshotRevertExternalFinish(vm, tmpsnapdef, snap);
    } else {
        if (qemuSnapshotInternalRevertInactive(driver, vm, snap) < 0) {
            qemuDomainRemoveInactive(driver, vm, 0, false);
            return -1;
        }
    }

    if (*inactiveConfig) {
        virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
        defined = true;
    }

    if (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                 VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
        /* Flush first event, now do transition 2 or 3 */
        bool paused = (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED) != 0;

        start_flags |= paused ? VIR_QEMU_PROCESS_START_PAUSED : 0;

        rc = qemuProcessStart(snapshot->domain->conn, driver, vm, NULL,
                              VIR_ASYNC_JOB_SNAPSHOT, NULL, -1, NULL, NULL,
                              VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                              start_flags);
        virDomainAuditStart(vm, "from-snapshot", rc >= 0);
        if (rc < 0) {
            qemuDomainRemoveInactive(driver, vm, 0, false);
            return -1;
        }
        detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         detail);
        virObjectEventStateQueue(driver->domainEventState, event);
        if (paused) {
            detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
            event2 = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_SUSPENDED,
                                              detail);
            virObjectEventStateQueue(driver->domainEventState, event2);
        }
    }

    return qemuSnapshotRevertWriteMetadata(vm, snap, driver, cfg, defined);
}


int
qemuSnapshotRevert(virDomainObj *vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags)
{
    virQEMUDriver *driver = snapshot->domain->conn->privateData;
    int ret = -1;
    virDomainMomentObj *snap = NULL;
    virDomainSnapshotDef *snapdef;
    g_autoptr(virDomainDef) config = NULL;
    g_autoptr(virDomainDef) inactiveConfig = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    unsigned int start_flags = VIR_QEMU_PROCESS_START_GEN_VMID;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED |
                  VIR_DOMAIN_SNAPSHOT_REVERT_FORCE |
                  VIR_DOMAIN_SNAPSHOT_REVERT_RESET_NVRAM, -1);

    if (flags & VIR_DOMAIN_SNAPSHOT_REVERT_RESET_NVRAM)
        start_flags |= VIR_QEMU_PROCESS_START_RESET_NVRAM;

    /* We have the following transitions, which create the following events:
     * 1. inactive -> inactive: none
     * 2. inactive -> running:  EVENT_STARTED
     * 3. inactive -> paused:   EVENT_STARTED, EVENT_SUSPENDED
     * 4. running  -> inactive: EVENT_STOPPED
     * 5. running  -> running:  EVENT_STOPPED, EVENT_STARTED
     * 6. running  -> paused:   EVENT_STOPPED, EVENT_STARTED, EVENT_SUSPENDED
     * 7. paused   -> inactive: EVENT_STOPPED
     * 8. paused   -> running:  EVENT_STOPPED, EVENT_STARTED
     * 9. paused   -> paused:   EVENT_STOPPED, EVENT_STARTED, EVENT_SUSPENDED
     * Also, several transitions occur even if we fail partway through.
     */

    if (qemuDomainHasBlockjob(vm, false)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has active block job"));
        return -1;
    }

    if (virDomainObjBeginAsyncJob(vm, VIR_ASYNC_JOB_SNAPSHOT,
                                  VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_REVERT,
                                  flags) < 0) {
        return -1;
    }

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;
    snapdef = virDomainSnapshotObjGetDef(snap);

    if (qemuSnapshotRevertValidate(vm, snap, snapdef, flags) < 0)
        goto endjob;

    if (qemuSnapshotRevertPrep(snap, snapdef, driver, vm,
                               &config, &inactiveConfig) < 0) {
        goto endjob;
    }

    switch ((virDomainSnapshotState) snapdef->state) {
    case VIR_DOMAIN_SNAPSHOT_RUNNING:
    case VIR_DOMAIN_SNAPSHOT_PAUSED:
        ret = qemuSnapshotRevertActive(vm, snapshot, snap, snapdef,
                                       driver, cfg,
                                       &config, &inactiveConfig,
                                       start_flags, flags);
        goto endjob;

    case VIR_DOMAIN_SNAPSHOT_SHUTDOWN:
    case VIR_DOMAIN_SNAPSHOT_SHUTOFF:
    case VIR_DOMAIN_SNAPSHOT_CRASHED:
        ret = qemuSnapshotRevertInactive(vm, snapshot, snap,
                                         driver, cfg,
                                         &inactiveConfig,
                                         start_flags, flags);
        goto endjob;

    case VIR_DOMAIN_SNAPSHOT_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support reversion of snapshot taken in PMSUSPENDED state"));
        goto endjob;

    case VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT:
        /* Rejected earlier as an external snapshot */
    case VIR_DOMAIN_SNAPSHOT_NOSTATE:
    case VIR_DOMAIN_SNAPSHOT_BLOCKED:
    case VIR_DOMAIN_SNAPSHOT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid target domain state '%1$s'. Refusing snapshot reversion"),
                       virDomainSnapshotStateTypeToString(snapdef->state));
        goto endjob;
    }

 endjob:
    virDomainObjEndAsyncJob(vm);

    return ret;
}


typedef struct _qemuSnapshotDeleteExternalData {
    virDomainSnapshotDiskDef *snapDisk; /* snapshot disk definition */
    virDomainDiskDef *domDisk; /* VM disk definition */
    virStorageSource *diskSrc; /* source of disk we are deleting */
    virDomainMomentObj *parentSnap;
    virDomainDiskDef *parentDomDisk; /* disk definition from snapshot metadata */
    virStorageSource *parentDiskSrc; /* backing disk source of the @diskSrc */
    virStorageSource *prevDiskSrc; /* source of disk for which @diskSrc is
                                      backing disk */
    GSList *disksWithBacking; /* list of storage source data for which the
                                 deleted storage source is backing store */
    qemuBlockJobData *job;
    bool merge;
} qemuSnapshotDeleteExternalData;


static void
qemuSnapshotDeleteExternalDataFree(qemuSnapshotDeleteExternalData *data)
{
    if (!data)
        return;

    virObjectUnref(data->job);
    g_slist_free_full(data->disksWithBacking, g_free);

    g_free(data);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuSnapshotDeleteExternalData, qemuSnapshotDeleteExternalDataFree);


/**
 * qemuSnapshotFindParentSnapForDisk:
 * @snap: snapshot object that is about to be deleted
 * @snapDisk: snapshot disk definition
 *
 * Find parent snapshot object that contains snapshot of the @snapDisk.
 * It may not be the next snapshot in the snapshot tree as the disk in
 * question may be skipped by using VIR_DOMAIN_SNAPSHOT_LOCATION_NO.
 *
 * Returns virDomainMomentObj* on success or NULL if there is no parent
 * snapshot containing the @snapDisk.
 * */
static virDomainMomentObj*
qemuSnapshotFindParentSnapForDisk(virDomainMomentObj *snap,
                                  virDomainSnapshotDiskDef *snapDisk)
{
    virDomainMomentObj *parentSnap = snap->parent;

    while (parentSnap) {
        ssize_t i;
        virDomainSnapshotDef *parentSnapdef = virDomainSnapshotObjGetDef(parentSnap);

        if (!parentSnapdef)
            break;

        for (i = 0; i < parentSnapdef->ndisks; i++) {
            virDomainSnapshotDiskDef *parentSnapDisk = &(parentSnapdef->disks[i]);

            if (parentSnapDisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_NO &&
                STREQ(snapDisk->name, parentSnapDisk->name)) {
                return parentSnap;
            }
        }

        parentSnap = parentSnap->parent;
    }

    return NULL;
}


struct _qemuSnapshotDisksWithBackingStoreData {
    virStorageSource *diskSrc;
    uid_t uid;
    gid_t gid;
};


struct _qemuSnapshotDisksWithBackingStoreIterData {
    virDomainMomentObj *current;
    virStorageSource *diskSrc;
    GSList **disksWithBacking;
    virQEMUDriverConfig *cfg;
};


static int
qemuSnapshotDiskHasBackingDisk(void *payload,
                               const char *name G_GNUC_UNUSED,
                               void *opaque)
{
    virDomainMomentObj *snap = payload;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    struct _qemuSnapshotDisksWithBackingStoreIterData *iterdata = opaque;
    ssize_t i;

    /* skip snapshots that are within the active snapshot tree as it will be handled
     * by qemu */
    if (virDomainMomentIsAncestor(iterdata->current, snap) || iterdata->current == snap)
        return 0;

    for (i = 0; i < snapdef->parent.dom->ndisks; i++) {
        virDomainDiskDef *disk = snapdef->parent.dom->disks[i];
        uid_t uid;
        gid_t gid;

        if (!virStorageSourceIsLocalStorage(disk->src))
            continue;

        qemuDomainGetImageIds(iterdata->cfg, snapdef->parent.dom, disk->src,
                              NULL, &uid, &gid);

        if (!disk->src->backingStore)
            ignore_value(virStorageSourceGetMetadata(disk->src, uid, gid, 1, false));

        if (virStorageSourceIsSameLocation(disk->src->backingStore, iterdata->diskSrc)) {
            struct _qemuSnapshotDisksWithBackingStoreData *data =
                g_new0(struct _qemuSnapshotDisksWithBackingStoreData, 1);

            data->diskSrc = disk->src;
            data->uid = uid;
            data->gid = gid;

            *iterdata->disksWithBacking = g_slist_prepend(*iterdata->disksWithBacking, data);
        }
    }

    return 0;
}


static void
qemuSnapshotGetDisksWithBackingStore(virDomainObj *vm,
                                     virDomainMomentObj *snap,
                                     qemuSnapshotDeleteExternalData *data)
{
    struct _qemuSnapshotDisksWithBackingStoreIterData iterData;
    virQEMUDriver *driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    iterData.current = virDomainSnapshotGetCurrent(vm->snapshots);
    iterData.diskSrc = data->diskSrc;
    iterData.disksWithBacking = &data->disksWithBacking;
    iterData.cfg = cfg;

    virDomainMomentForEachDescendant(snap, qemuSnapshotDiskHasBackingDisk, &iterData);
}


/**
 * qemuSnapshotDeleteExternalPrepareData:
 * @vm: domain object
 * @snap: snapshot object
 * @merge: whether we are just deleting image or not
 * @externalData: prepared data to delete external snapshot
 *
 * Validate if we can delete selected snapshot @snap and prepare all necessary
 * data that will be used when deleting snapshot as @externalData.
 *
 * If @merge is set to true we will merge the deleted snapshot into parent one
 * instead of just deleting it. This is necessary when operating on snapshot
 * that has existing overlay files.
 *
 * Returns -1 on error, 0 on success.
 */
static int
qemuSnapshotDeleteExternalPrepareData(virDomainObj *vm,
                                      virDomainMomentObj *snap,
                                      bool merge,
                                      GSList **externalData)
{
    ssize_t i;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    g_autoslist(qemuSnapshotDeleteExternalData) ret = NULL;

    for (i = 0; i < snapdef->ndisks; i++) {
        g_autofree qemuSnapshotDeleteExternalData *data = NULL;
        virDomainSnapshotDiskDef *snapDisk = &(snapdef->disks[i]);

        if (snapDisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (snapDisk->snapshotDeleteInProgress) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("snapshot disk '%1$s' was target of not completed snapshot delete"),
                           snapDisk->name);
            return -1;
        }

        data = g_new0(qemuSnapshotDeleteExternalData, 1);
        data->snapDisk = snapDisk;
        data->merge = merge;

        data->parentDomDisk = virDomainDiskByTarget(snapdef->parent.dom,
                                                    data->snapDisk->name);
        if (!data->parentDomDisk) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to find disk '%1$s' in snapshot VM XML"),
                           snapDisk->name);
            return -1;
        }

        if (data->merge) {
            data->domDisk = qemuDomainDiskByName(vm->def, snapDisk->name);
            if (!data->domDisk)
                return -1;

            if (virDomainObjIsActive(vm)) {
                data->diskSrc = virStorageSourceChainLookupBySource(data->domDisk->src,
                                                                    data->snapDisk->src,
                                                                    &data->prevDiskSrc);
                if (!data->diskSrc)
                    return -1;

                if (!virStorageSourceIsSameLocation(data->diskSrc, data->snapDisk->src)) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("VM disk source and snapshot disk source are not the same"));
                    return -1;
                }

                data->parentDiskSrc = data->diskSrc->backingStore;
                if (!virStorageSourceIsBacking(data->parentDiskSrc)) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("failed to find parent disk source in backing chain"));
                    return -1;
                }

                if (!virStorageSourceIsSameLocation(data->parentDiskSrc,
                                                    data->parentDomDisk->src)) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("snapshot VM disk source and parent disk source are not the same"));
                    return -1;
                }

                qemuSnapshotGetDisksWithBackingStore(vm, snap, data);
            }

            data->parentSnap = qemuSnapshotFindParentSnapForDisk(snap, data->snapDisk);

            if (data->parentSnap && !virDomainSnapshotIsExternal(data->parentSnap)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("deleting external snapshot that has internal snapshot as parent not supported"));
                return -1;
            }
        }

        ret = g_slist_prepend(ret, g_steal_pointer(&data));
    }

    ret = g_slist_reverse(ret);
    *externalData = g_steal_pointer(&ret);

    return 0;
}


/**
 * qemuSnapshotDeleteExternalPrepare:
 * @vm: domain object
 * @snap: snapshot object we are deleting
 * @flags: flags passed to virDomainSnapshotDelete
 * @externalData: pointer to GSList of qemuSnapshotDeleteExternalData
 * @stop_qemu: pointer to boolean indicating QEMU process was started
 *
 * Validates and prepares data for snapshot @snap we are deleting and
 * store it in @externalData. For offline VMs we need to start QEMU
 * process in order to delete external snapshots and caller will need
 * to stop that process, @stop_qemu will be set to True.
 *
 * Return 0 on success, -1 on error.
 */
static int
qemuSnapshotDeleteExternalPrepare(virDomainObj *vm,
                                  virDomainMomentObj *snap,
                                  unsigned int flags,
                                  GSList **externalData,
                                  bool *stop_qemu)
{
    virQEMUDriver *driver = ((qemuDomainObjPrivate *) vm->privateData)->driver;
    g_autoslist(qemuSnapshotDeleteExternalData) tmpData = NULL;

    if (!virDomainSnapshotIsExternal(snap))
        return 0;

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        return 0;
    }

    /* Leaf non-active snapshot doesn't have overlay files for the disk images
     * so there is no need to do any merge and we can just delete the files
     * directly. */
    if (snap != virDomainSnapshotGetCurrent(vm->snapshots) &&
        snap->nchildren == 0) {
        if (qemuSnapshotDeleteExternalPrepareData(vm, snap, false, externalData) < 0)
            return -1;
    } else {
        /* this also serves as validation whether the snapshot can be deleted */
        if (qemuSnapshotDeleteExternalPrepareData(vm, snap, true, &tmpData) < 0)
            return -1;

        if (!virDomainObjIsActive(vm)) {
            if (qemuProcessStart(NULL, driver, vm, NULL, VIR_ASYNC_JOB_SNAPSHOT,
                                 NULL, -1, NULL, NULL,
                                 VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                 VIR_QEMU_PROCESS_START_PAUSED) < 0) {
                return -1;
            }

            *stop_qemu = true;

            /* Call the prepare again as some data require that the VM is
             * running to get everything we need. */
            if (qemuSnapshotDeleteExternalPrepareData(vm, snap, true, externalData) < 0)
                return -1;
        } else {
            qemuDomainJobPrivate *jobPriv = vm->job->privateData;

            *externalData = g_steal_pointer(&tmpData);

            /* If the VM is running we need to indicate that the async snapshot
             * job is snapshot delete job. */
            jobPriv->snapshotDelete = true;

            qemuDomainSaveStatus(vm);
        }
    }

    return 0;
}


typedef struct _virQEMUMomentReparent virQEMUMomentReparent;
struct _virQEMUMomentReparent {
    const char *dir;
    virDomainMomentObj *parent;
    virDomainObj *vm;
    virDomainXMLOption *xmlopt;
    int err;
    int (*writeMetadata)(virDomainObj *, virDomainMomentObj *,
                         virDomainXMLOption *, const char *);
};


static int
qemuSnapshotChildrenReparent(void *payload,
                             const char *name G_GNUC_UNUSED,
                             void *data)
{
    virDomainMomentObj *moment = payload;
    virQEMUMomentReparent *rep = data;

    if (rep->err < 0)
        return 0;

    VIR_FREE(moment->def->parent_name);

    if (rep->parent->def)
        moment->def->parent_name = g_strdup(rep->parent->def->name);

    rep->err = rep->writeMetadata(rep->vm, moment, rep->xmlopt,
                                  rep->dir);
    return 0;
}


typedef struct _qemuSnapshotUpdateDisksData qemuSnapshotUpdateDisksData;
struct _qemuSnapshotUpdateDisksData {
    virDomainMomentObj *snap;
    virDomainObj *vm;
    int error;
};


/**
 * qemuSnapshotUpdateDisksSingle:
 * @snap: snapshot object where we are updating disks
 * @def: active or inactive definition from @snap
 * @parentDef: parent snapshot object of snapshot that we are deleting
 * @snapDisk: snapshot disk definition from snapshot we are deleting
 *
 * When deleting external snapshots we need to modify remaining metadata
 * files stored by libvirt.
 *
 * The first part updates only metadata for external snapshots where we need
 * to update the disk source in the domain definition stored within the
 * snapshot metadata. There is no need to do it for internal snapshots as
 * they don't create new disk files.
 *
 * The second part needs to be done for all metadata files. Both internal and
 * external snapshot metadata files have in the domain definition backingStore
 * that could contain the deleted disk.
 *
 * Returns 0 on success, -1 on error.
 * */
static int
qemuSnapshotUpdateDisksSingle(virDomainMomentObj *snap,
                              virDomainDef *def,
                              virDomainDef *parentDef,
                              virDomainSnapshotDiskDef *snapDisk)
{
    virDomainDiskDef *disk = NULL;

    if (!(disk = virDomainDiskByName(def, snapDisk->name, true)))
        return 0;

    if (virDomainSnapshotIsExternal(snap)) {
        virDomainDiskDef *parentDisk = NULL;

        if (!(parentDisk = qemuDomainDiskByName(parentDef, snapDisk->name)))
            return -1;

        if (virStorageSourceIsSameLocation(snapDisk->src, disk->src)) {
            virObjectUnref(disk->src);
            disk->src = virStorageSourceCopy(parentDisk->src, false);
        }
    }

    if (disk->src->backingStore) {
        virStorageSource *cur = disk->src;
        virStorageSource *next = disk->src->backingStore;

        while (next) {
            if (virStorageSourceIsSameLocation(snapDisk->src, next)) {
                cur->backingStore = next->backingStore;
                next->backingStore = NULL;
                virObjectUnref(next);
                break;
            }

            cur = next;
            next = cur->backingStore;
        }
    }

    return 0;
}


static int
qemuSnapshotDeleteUpdateDisks(void *payload,
                              const char *name G_GNUC_UNUSED,
                              void *opaque)
{
    virDomainMomentObj *snap = payload;
    qemuSnapshotUpdateDisksData *data = opaque;
    qemuDomainObjPrivate *priv = data->vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(data->snap);
    ssize_t i;

    for (i = 0; i < snapdef->ndisks; i++) {
        virDomainSnapshotDiskDef *snapDisk = &(snapdef->disks[i]);

        if (snapDisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NO)
            continue;

        if (qemuSnapshotUpdateDisksSingle(snap, snap->def->dom,
                                          data->snap->def->dom, snapDisk) < 0) {
            data->error = -1;
        }

        if (snap->def->inactiveDom) {
            virDomainDef *dom = data->snap->def->inactiveDom;

            if (!dom)
                dom = data->snap->def->dom;

            if (qemuSnapshotUpdateDisksSingle(snap, snap->def->inactiveDom,
                                              dom, snapDisk) < 0) {
                data->error = -1;
            }
        }
    }

    if (qemuDomainSnapshotWriteMetadata(data->vm,
                                        snap,
                                        driver->xmlopt,
                                        cfg->snapshotDir) < 0) {
        data->error = -1;
    }

    return 0;
}


/* Deleting external snapshot is started by running qemu block-commit job.
 * We need to wait for all block-commit jobs to be 'ready' or 'pending' to
 * continue with external snapshot deletion. */
static int
qemuSnapshotDeleteBlockJobIsRunning(qemuBlockjobState state)
{
    switch (state) {
    case QEMU_BLOCKJOB_STATE_NEW:
    case QEMU_BLOCKJOB_STATE_RUNNING:
    case QEMU_BLOCKJOB_STATE_ABORTING:
    case QEMU_BLOCKJOB_STATE_PIVOTING:
        return 1;

    case QEMU_BLOCKJOB_STATE_COMPLETED:
    case QEMU_BLOCKJOB_STATE_FAILED:
    case QEMU_BLOCKJOB_STATE_CANCELLED:
    case QEMU_BLOCKJOB_STATE_READY:
    case QEMU_BLOCKJOB_STATE_CONCLUDED:
    case QEMU_BLOCKJOB_STATE_PENDING:
    case QEMU_BLOCKJOB_STATE_LAST:
        break;
    }

    return 0;
}


/* When finishing or aborting qemu blockjob we only need to know if the
 * job is still active or not. */
static int
qemuSnapshotDeleteBlockJobIsActive(qemuBlockjobState state)
{
    switch (state) {
    case QEMU_BLOCKJOB_STATE_READY:
    case QEMU_BLOCKJOB_STATE_NEW:
    case QEMU_BLOCKJOB_STATE_RUNNING:
    case QEMU_BLOCKJOB_STATE_ABORTING:
    case QEMU_BLOCKJOB_STATE_PENDING:
    case QEMU_BLOCKJOB_STATE_PIVOTING:
        return 1;

    case QEMU_BLOCKJOB_STATE_COMPLETED:
    case QEMU_BLOCKJOB_STATE_FAILED:
    case QEMU_BLOCKJOB_STATE_CANCELLED:
    case QEMU_BLOCKJOB_STATE_CONCLUDED:
    case QEMU_BLOCKJOB_STATE_LAST:
        break;
    }

    return 0;
}


/* Wait for qemu blockjob to finish 'block-commit' operation until it is
 * ready to be finished by calling 'block-pivot' or 'block-finalize'. */
static int
qemuSnapshotDeleteBlockJobRunning(virDomainObj *vm,
                                  qemuBlockJobData *job)
{
    int rc;
    qemuBlockJobUpdate(vm, job, VIR_ASYNC_JOB_SNAPSHOT);

    while ((rc = qemuSnapshotDeleteBlockJobIsRunning(job->state)) > 0) {
        if (qemuDomainObjWait(vm) < 0)
            return -1;
        qemuBlockJobUpdate(vm, job, VIR_ASYNC_JOB_SNAPSHOT);
    }

    if (rc < 0)
        return -1;

    return 0;
}


/* Wait for qemu blockjob to be done after 'block-pivot' or 'block-finalize'
 * was started. */
static int
qemuSnapshotDeleteBlockJobFinishing(virDomainObj *vm,
                                    qemuBlockJobData *job)
{
    int rc;
    qemuBlockJobUpdate(vm, job, VIR_ASYNC_JOB_SNAPSHOT);

    while ((rc = qemuSnapshotDeleteBlockJobIsActive(job->state)) > 0) {
        if (qemuDomainObjWait(vm) < 0)
            return -1;
        qemuBlockJobUpdate(vm, job, VIR_ASYNC_JOB_SNAPSHOT);
    }

    if (rc < 0)
        return -1;

    return 0;
}


/**
 * qemuSnapshotSetInvalid:
 * @vm: vm object
 * @snap: snapshot object that contains parent disk
 * @disk: disk from the snapshot we are deleting
 * @invalid: boolean to set/unset invalid state
 *
 * @snap should point to a ancestor snapshot from the snapshot tree that
 * affected the @disk which doesn't have to be the direct parent.
 *
 * When setting snapshot with parent disk as invalid due to snapshot being
 * deleted we should not mark the whole snapshot as invalid but only the
 * affected disks because the snapshot can contain other disks that we are
 * not modifying at the moment.
 *
 * Return 0 on success, -1 on error.
 * */
static int
qemuSnapshotSetInvalid(virDomainObj *vm,
                       virDomainMomentObj *snap,
                       virDomainSnapshotDiskDef *disk,
                       bool invalid)
{
    ssize_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainSnapshotDef *snapdef = NULL;

    if (!snap)
        return 0;

    snapdef = virDomainSnapshotObjGetDef(snap);
    if (!snapdef)
        return 0;

    for (i = 0; i < snapdef->ndisks; i++) {
        virDomainSnapshotDiskDef *snapDisk = &(snapdef->disks[i]);

        if (STREQ(snapDisk->name, disk->name))
            snapDisk->snapshotDeleteInProgress = invalid;
    }

    return qemuDomainSnapshotWriteMetadata(vm, snap, driver->xmlopt, cfg->snapshotDir);
}


static void
qemuSnapshotUpdateBackingStore(virDomainObj *vm,
                               qemuSnapshotDeleteExternalData *data)
{
    GSList *cur = NULL;
    const char *qemuImgPath;
    virQEMUDriver *driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

    if (!(qemuImgPath = qemuFindQemuImgBinary(driver)))
        return;

    for (cur = data->disksWithBacking; cur; cur = g_slist_next(cur)) {
        struct _qemuSnapshotDisksWithBackingStoreData *backingData = cur->data;
        g_autoptr(virCommand) cmd = NULL;

        /* creates cmd line args: qemu-img create -f qcow2 -o */
        if (!(cmd = virCommandNewArgList(qemuImgPath,
                                         "rebase",
                                         "-u",
                                         "-F",
                                         virStorageFileFormatTypeToString(data->parentDiskSrc->format),
                                         "-f",
                                         virStorageFileFormatTypeToString(backingData->diskSrc->format),
                                         "-b",
                                         data->parentDiskSrc->path,
                                         backingData->diskSrc->path,
                                         NULL)))
            continue;

        virCommandSetUID(cmd, backingData->uid);
        virCommandSetGID(cmd, backingData->gid);

        ignore_value(virCommandRun(cmd, NULL));
    }
}


static int
qemuSnapshotDiscardExternal(virDomainObj *vm,
                            virDomainMomentObj *snap,
                            GSList *externalData)
{
    GSList *cur = NULL;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

    for (cur = externalData; cur; cur = g_slist_next(cur)) {
        qemuSnapshotDeleteExternalData *data = cur->data;
        virTristateBool autofinalize = VIR_TRISTATE_BOOL_NO;
        unsigned int commitFlags = VIR_DOMAIN_BLOCK_COMMIT_DELETE;

        if (data->merge) {
            if (data->domDisk->src == data->diskSrc) {
                commitFlags |= VIR_DOMAIN_BLOCK_COMMIT_ACTIVE;
                autofinalize = VIR_TRISTATE_BOOL_YES;
            }

            if (qemuSnapshotSetInvalid(vm, data->parentSnap, data->snapDisk, true) < 0)
                goto error;

            data->job = qemuBlockCommit(vm,
                                        data->domDisk,
                                        data->parentDiskSrc,
                                        data->diskSrc,
                                        data->prevDiskSrc,
                                        0,
                                        VIR_ASYNC_JOB_SNAPSHOT,
                                        autofinalize,
                                        commitFlags);

            if (!data->job)
                goto error;
        } else {
            if (virStorageSourceInit(data->parentDomDisk->src) < 0 ||
                virStorageSourceUnlink(data->parentDomDisk->src) < 0) {
                VIR_WARN("Failed to remove snapshot image '%s'",
                         data->snapDisk->name);
            }
        }
    }

    for (cur = externalData; cur; cur = g_slist_next(cur)) {
        qemuSnapshotDeleteExternalData *data = cur->data;

        if (!data->merge)
            continue;

        if (qemuSnapshotDeleteBlockJobRunning(vm, data->job) < 0)
            goto error;

        if (data->job->state == QEMU_BLOCKJOB_STATE_FAILED) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("block commit failed while deleting disk '%1$s' snapshot: '%2$s'"),
                           data->snapDisk->name, data->job->errmsg);
            goto error;
        }
    }

    for (cur = externalData; cur; cur = g_slist_next(cur)) {
        qemuSnapshotDeleteExternalData *data = cur->data;

        if (!data->merge)
            continue;

        if (data->job->state == QEMU_BLOCKJOB_STATE_READY) {
            if (qemuBlockPivot(vm, data->job, VIR_ASYNC_JOB_SNAPSHOT, NULL) < 0)
                goto error;
        } else if (data->job->state == QEMU_BLOCKJOB_STATE_PENDING) {
            if (qemuBlockFinalize(vm, data->job, VIR_ASYNC_JOB_SNAPSHOT) < 0)
                goto error;
        }

        if (qemuSnapshotDeleteBlockJobFinishing(vm, data->job) < 0)
            goto error;

        if (data->job->state == QEMU_BLOCKJOB_STATE_FAILED) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("finishing block job failed while deleting disk '%1$s' snapshot: '%2$s'"),
                           data->snapDisk->name, data->job->errmsg);
            goto error;
        }

        qemuBlockJobSyncEnd(vm, data->job, VIR_ASYNC_JOB_SNAPSHOT);

        qemuSnapshotUpdateBackingStore(vm, data);

        if (qemuSnapshotSetInvalid(vm, data->parentSnap, data->snapDisk, false) < 0)
            goto error;
    }

    if (snapdef->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL &&
        snapdef->memorysnapshotfile) {
        if (unlink(snapdef->memorysnapshotfile) < 0) {
            VIR_WARN("failed to remove memory snapshot '%s'",
                     snapdef->memorysnapshotfile);
        }
    }

    return 0;

 error:
    for (cur = externalData; cur; cur = g_slist_next(cur)) {
        qemuDomainObjPrivate *priv = vm->privateData;
        qemuSnapshotDeleteExternalData *data = cur->data;

        if (!data->job)
            continue;

        qemuBlockJobUpdate(vm, data->job, VIR_ASYNC_JOB_SNAPSHOT);

        if (qemuSnapshotDeleteBlockJobIsActive(data->job->state)) {
            if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_SNAPSHOT) == 0) {
                ignore_value(qemuMonitorBlockJobCancel(priv->mon, data->job->name, false));
                qemuDomainObjExitMonitor(vm);

                data->job->state = QEMU_BLOCKJOB_STATE_ABORTING;
            }
        }

        qemuBlockJobSyncEnd(vm, data->job, VIR_ASYNC_JOB_SNAPSHOT);
    }

    return -1;
}


static int
qemuSnapshotDeleteUpdateParent(virDomainObj *vm,
                               virDomainMomentObj *parent)
{
    size_t i;
    virQEMUDriver *driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainSnapshotDef *parentDef = virDomainSnapshotObjGetDef(parent);

    if (!parentDef)
        return 0;

    if (!parentDef->revertdisks)
        return 0;

    for (i = 0; i < parentDef->ndisks; i++) {
        virDomainSnapshotDiskDefClear(&parentDef->disks[i]);
    }
    g_free(parentDef->disks);

    parentDef->disks = g_steal_pointer(&parentDef->revertdisks);
    parentDef->ndisks = parentDef->nrevertdisks;
    parentDef->nrevertdisks = 0;

    if (qemuDomainSnapshotWriteMetadata(vm,
                                        parent,
                                        driver->xmlopt,
                                        cfg->snapshotDir) < 0) {
        return -1;
    }

    return 0;
}


static int
qemuSnapshotDiscardMetadata(virDomainObj *vm,
                            virDomainMomentObj *snap,
                            bool update_parent)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *snapFile = NULL;
    int ret = 0;

    if (update_parent && snap->nchildren) {
        virQEMUMomentReparent rep;
        qemuSnapshotUpdateDisksData data;

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
            ret = -1;

        data.snap = snap;
        data.vm = vm;
        data.error = 0;
        virDomainMomentForEachDescendant(snap,
                                         qemuSnapshotDeleteUpdateDisks,
                                         &data);
        if (data.error < 0)
            ret = -1;

        virDomainMomentMoveChildren(snap, snap->parent);
    }

    if (update_parent && snap->parent) {
        if (qemuSnapshotDeleteUpdateParent(vm, snap->parent) < 0)
            ret = -1;
    }

    snapFile = g_strdup_printf("%s/%s/%s.xml", cfg->snapshotDir, vm->def->name,
                               snap->def->name);

    if (snap == virDomainSnapshotGetCurrent(vm->snapshots)) {
        virDomainSnapshotSetCurrent(vm->snapshots, NULL);
        if (update_parent && snap->def->parent_name) {
            virDomainMomentObj *parentsnap = NULL;
            parentsnap = virDomainSnapshotFindByName(vm->snapshots,
                                                     snap->def->parent_name);
            if (!parentsnap) {
                VIR_WARN("missing parent snapshot matching name '%s'",
                         snap->def->parent_name);
            } else {
                virDomainSnapshotSetCurrent(vm->snapshots, parentsnap);
                if (qemuDomainSnapshotWriteMetadata(vm, parentsnap,
                                                    driver->xmlopt,
                                                    cfg->snapshotDir) < 0) {
                    VIR_WARN("failed to set parent snapshot '%s' as current",
                             snap->def->parent_name);
                    virDomainSnapshotSetCurrent(vm->snapshots, NULL);
                }
            }
        }
    }

    if (unlink(snapFile) < 0)
        VIR_WARN("Failed to unlink %s", snapFile);
    if (update_parent)
        virDomainMomentDropParent(snap);
    virDomainSnapshotObjListRemove(vm->snapshots, snap);

    return ret;
}


/* Discard one snapshot (or its metadata), without reparenting any children.  */
static int
qemuSnapshotDiscardImpl(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainMomentObj *snap,
                        GSList *externalData,
                        bool update_parent,
                        bool metadata_only)
{
    if (!metadata_only) {
        if (!virDomainObjIsActive(vm)) {
            size_t i;
            /* Ignore any skipped disks */

            /* Prefer action on the disks in use at the time the snapshot was
             * created; but fall back to current definition if dealing with a
             * snapshot created prior to libvirt 0.9.5.  */
            virDomainDef *def = snap->def->dom;

            if (!def)
                def = vm->def;

            for (i = 0; i < def->ndisks; i++) {
                if (virDomainDiskTranslateSourcePool(def->disks[i]) < 0)
                    return -1;
            }

            if (virDomainSnapshotIsExternal(snap)) {
                if (qemuSnapshotDiscardExternal(vm, snap, externalData) < 0)
                    return -1;
            } else {
                if (qemuDomainSnapshotForEachQcow2(driver, def, snap, "-d", true) < 0)
                    return -1;
            }
        } else {
            if (virDomainSnapshotIsExternal(snap)) {
                if (qemuSnapshotDiscardExternal(vm, snap, externalData) < 0)
                    return -1;
            } else {
                /* Similarly as internal snapshot creation we would use a regular job
                 * here so set a mask to forbid any other job. */
                qemuDomainObjSetAsyncJobMask(vm, VIR_JOB_NONE);
                if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_SNAPSHOT) < 0)
                    return -1;
                /* we continue on even in the face of error */
                qemuMonitorDeleteSnapshot(qemuDomainGetMonitor(vm), snap->def->name);
                qemuDomainObjExitMonitor(vm);
                qemuDomainObjSetAsyncJobMask(vm, VIR_JOB_DEFAULT_MASK);
            }
        }
    }

    if (qemuSnapshotDiscardMetadata(vm, snap, update_parent) < 0)
        return -1;

    return 0;
}


static int
qemuSnapshotDiscard(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virDomainMomentObj *snap,
                    bool update_parent,
                    bool metadata_only)
{
    return qemuSnapshotDiscardImpl(driver, vm, snap, NULL, update_parent, metadata_only);
}


int
qemuSnapshotDiscardAllMetadata(virQEMUDriver *driver,
                               virDomainObj *vm)
{
    virQEMUMomentRemove rem = {
        .driver = driver,
        .vm = vm,
        .metadata_only = true,
        .momentDiscard = qemuSnapshotDiscard,
    };

    virDomainSnapshotForEach(vm->snapshots, qemuDomainMomentDiscardAll, &rem);
    virDomainSnapshotObjListRemoveAll(vm->snapshots);

    return rem.err;
}


static int
qemuSnapshotDeleteSingle(virDomainObj *vm,
                         virDomainMomentObj *snap,
                         GSList *externalData,
                         bool metadata_only)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;

    return qemuSnapshotDiscardImpl(driver, vm, snap, externalData, true, metadata_only);
}


struct qemuSnapshotDeleteAllData {
    virDomainObj *vm;
    bool metadata_only;
    int error;
};


static int
qemuSnapshotDeleteAllHelper(void *payload,
                            const char *name G_GNUC_UNUSED,
                            void *opaque)
{
    int error;
    virDomainMomentObj *snap = payload;
    struct qemuSnapshotDeleteAllData *data = opaque;

    error = qemuSnapshotDeleteSingle(data->vm, snap, NULL, data->metadata_only);

    if (error != 0)
        data->error = error;

    return 0;
}


/**
 * qemuSnapshotDeleteChildren:
 * @vm: domain object
 * @snap: snapshot object
 * @metadata_only: if true only snapshots metadata are deleted
 * @children_only: if true only snapshot children are deleted
 *
 * Delete children snapshots of snapshot provided by @snap. If @metadata_only
 * is true only snapshot metadata files are delete, disk data are left intact.
 * If @children_only is true it will delete only children snapshots of @snap
 * and leave @snap intact.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuSnapshotDeleteChildren(virDomainObj *vm,
                           virDomainMomentObj *snap,
                           bool metadata_only,
                           bool children_only)
{
    struct qemuSnapshotDeleteAllData data = {
        .vm = vm,
        .metadata_only = metadata_only,
    };

    virDomainMomentForEachDescendant(snap, qemuSnapshotDeleteAllHelper, &data);

    if (data.error < 0)
        return -1;

    if (!children_only &&
        qemuSnapshotDeleteSingle(vm, snap, NULL, metadata_only) < 0) {
        return -1;
    }

    return 0;
}


typedef struct {
    int external;
    int internal;
} qemuSnapshotCount;


static int
qemuSnapshotCountExternalInternal(void *payload,
                                  const char *name G_GNUC_UNUSED,
                                  void *data)
{
    virDomainMomentObj *snap = payload;
    qemuSnapshotCount *count = data;

    if (virDomainSnapshotIsExternal(snap)) {
        count->external++;
    } else {
        count->internal++;
    }

    return 0;
}


static int
qemuSnapshotDeleteValidate(virDomainObj *vm,
                           virDomainMomentObj *snap,
                           unsigned int flags)
{
    if (!virDomainSnapshotIsExternal(snap) &&
        virDomainObjIsActive(vm)) {
        ssize_t i;
        virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

        for (i = 0; i < snapdef->ndisks; i++) {
            virDomainSnapshotDiskDef *snapDisk = &(snapdef->disks[i]);
            virDomainDiskDef *vmdisk = NULL;
            virDomainDiskDef *disk = NULL;

            vmdisk = qemuDomainDiskByName(vm->def, snapDisk->name);
            disk = qemuDomainDiskByName(snapdef->parent.dom, snapDisk->name);

            if (!virStorageSourceIsSameLocation(vmdisk->src, disk->src)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("disk image '%1$s' for internal snapshot '%2$s' is not the same as disk image currently used by VM"),
                               snapDisk->name, snap->def->name);
                return -1;
            }
        }
    }

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        qemuSnapshotCount count = { 0 };

        virDomainMomentForEachDescendant(snap,
                                         qemuSnapshotCountExternalInternal,
                                         &count);

        if (count.external > 0 && count.internal > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of external and internal children disk snapshots not supported"));
            return -1;
        }

        if (count.external > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of external children disk snapshots not supported"));
            return -1;
        }
    }

    if (virDomainSnapshotIsExternal(snap)) {
        virDomainMomentObj *current = virDomainSnapshotGetCurrent(vm->snapshots);

        if (qemuDomainHasBlockjob(vm, false)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot delete external snapshots when there is another active block job"));
            return -1;
        }

        if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of external disk snapshots with children not supported"));
            return -1;
        }

        if (snap == current && snap->nchildren != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of active external snapshot that is not a leaf snapshot is not supported"));
            return -1;
        }

        if (snap != current && snap->nchildren != 0 &&
            virDomainMomentIsAncestor(snap, current)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of non-leaf external snapshot that is not in active chain is not supported"));
            return -1;
        }

        if (snap->nchildren > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deletion of external disk snapshot with multiple children snapshots not supported"));
            return -1;
        }
    }

    return 0;
}


int
qemuSnapshotDelete(virDomainObj *vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags)
{
    int ret = -1;
    virDomainMomentObj *snap = NULL;
    bool metadata_only = !!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY);
    bool stop_qemu = false;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoslist(qemuSnapshotDeleteExternalData) externalData = NULL;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, -1);

    if (virDomainObjBeginAsyncJob(vm, VIR_ASYNC_JOB_SNAPSHOT,
                                  VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_DELETE,
                                  flags) < 0) {
        return -1;
    }

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;

    if (!metadata_only) {
        if (qemuSnapshotDeleteValidate(vm, snap, flags) < 0)
            goto endjob;

        if (qemuSnapshotDeleteExternalPrepare(vm, snap, flags,
                                              &externalData, &stop_qemu) < 0) {
            goto endjob;
        }
    }

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        bool children_only = !!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY);
        ret = qemuSnapshotDeleteChildren(vm, snap, metadata_only, children_only);
    } else {
        ret = qemuSnapshotDeleteSingle(vm, snap, externalData, metadata_only);
    }

 endjob:
    if (stop_qemu) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN,
                        VIR_ASYNC_JOB_SNAPSHOT, 0);
    }

    virDomainObjEndAsyncJob(vm);

    return ret;
}
