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
#include "virstoragefile.h"
#include "virstring.h"
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
                       _("no domain snapshot with matching name '%s'"),
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


/* Count how many snapshots in a set are external snapshots.  */
static int
qemuSnapshotCountExternal(void *payload,
                          const char *name G_GNUC_UNUSED,
                          void *data)
{
    virDomainMomentObj *snap = payload;
    int *count = data;

    if (virDomainSnapshotIsExternal(snap))
        (*count)++;
    return 0;
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
    size_t i;
    virDomainSnapshotDiskDef *snapdisk;
    virDomainDiskDef *defdisk;
    const char *qemuImgPath;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);
    g_autoptr(virBitmap) created = virBitmapNew(snapdef->ndisks);

    if (!(qemuImgPath = qemuFindQemuImgBinary(driver)))
        goto cleanup;

    /* If reuse is true, then qemuSnapshotPrepare already
     * ensured that the new files exist, and it was up to the user to
     * create them correctly.  */
    for (i = 0; i < snapdef->ndisks && !reuse; i++) {
        g_autoptr(virCommand) cmd = NULL;
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
    qemuDomainObjExitMonitor(driver, vm);
    if (ret < 0)
        goto cleanup;

    if (!(snapdef->cookie = (virObject *) qemuDomainSaveCookieNew(vm)))
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
qemuSnapshotPrepareDiskShared(virDomainSnapshotDiskDef *snapdisk,
                              virDomainDiskDef *domdisk)
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
qemuSnapshotPrepareDiskExternalInactive(virDomainSnapshotDiskDef *snapdisk,
                                        virDomainDiskDef *domdisk)
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
        case VIR_STORAGE_NET_PROTOCOL_NFS:
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
    case VIR_STORAGE_TYPE_VHOST_USER:
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
    case VIR_STORAGE_TYPE_VHOST_USER:
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
qemuSnapshotPrepareDiskExternalActive(virDomainObj *vm,
                                      virDomainSnapshotDiskDef *snapdisk,
                                      virDomainDiskDef *domdisk,
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
        case VIR_STORAGE_NET_PROTOCOL_NFS:
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
    case VIR_STORAGE_TYPE_VHOST_USER:
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
qemuSnapshotPrepareDiskExternal(virDomainObj *vm,
                                virDomainDiskDef *disk,
                                virDomainSnapshotDiskDef *snapdisk,
                                bool active,
                                bool reuse,
                                bool blockdev)
{

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
                                     _("unable to stat for disk %s: %s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            }

            if (reuse) {
                virReportSystemError(err,
                                     _("missing existing file for disk %s: %s"),
                                     snapdisk->name, snapdisk->src->path);
                return -1;
            } else {
                if (snapdisk->src->type == VIR_STORAGE_TYPE_BLOCK) {
                    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                                   _("block device snapshot target '%s' doesn't exist"),
                                   snapdisk->src->path);
                    return -1;
                }
            }
        } else {
            /* at this point VIR_STORAGE_TYPE_DIR was already rejected */
            if ((snapdisk->src->type == VIR_STORAGE_TYPE_BLOCK && !S_ISBLK(st.st_mode)) ||
                (snapdisk->src->type == VIR_STORAGE_TYPE_FILE && !S_ISREG(st.st_mode))) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("mismatch between configured type for snapshot disk '%s' and the type of existing file '%s'"),
                               snapdisk->name, snapdisk->src->path);
                return -1;
            }

            if (!reuse &&
                snapdisk->src->type == VIR_STORAGE_TYPE_FILE &&
                st.st_size > 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot file for disk %s already exists and is not a block device: %s"),
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
        case VIR_STORAGE_NET_PROTOCOL_NFS:
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
    case VIR_STORAGE_TYPE_VHOST_USER:
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
qemuSnapshotPrepare(virDomainObj *vm,
                    virDomainSnapshotDef *def,
                    unsigned int *flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
    size_t i;
    bool active = virDomainObjIsActive(vm);
    bool reuse = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    bool found_internal = false;
    bool forbid_internal = false;
    int external = 0;

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDef *disk = &def->disks[i];
        virDomainDiskDef *dom_disk = vm->def->disks[i];

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

            if (disk->src->metadataCacheMaxSize > 0) {
                if (disk->src->format != VIR_STORAGE_FILE_QCOW2) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("metadata cache max size control is supported only with qcow2 images"));
                    return -1;
                }

                if (!blockdev) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("metadata cache max size control is not supported with this QEMU binary"));
                    return -1;
                }
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
                        qemuDomainAsyncJob asyncJob)
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
                if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {

                    qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm),
                                                         data[i].crdata->srcdata[0]);
                    qemuDomainObjExitMonitor(driver, vm);
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
    qemuDomainAsyncJob asyncJob;
};

typedef struct _qemuSnapshotDiskContext qemuSnapshotDiskContext;


qemuSnapshotDiskContext *
qemuSnapshotDiskContextNew(size_t ndisks,
                           virDomainObj *vm,
                           qemuDomainAsyncJob asyncJob)
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

    if (!(entry = virHashLookup(blockNamedNodeData, dd->disk->src->nodeformat)))
        return 0;

    for (i = 0; i < entry->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmap *bitmap = entry->bitmaps[i];

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
qemuSnapshotDiskPrepareOneBlockdev(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   qemuSnapshotDiskData *dd,
                                   virQEMUDriverConfig *cfg,
                                   bool reuse,
                                   GHashTable *blockNamedNodeData,
                                   qemuDomainAsyncJob asyncJob)
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
        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            return -1;

        rc = qemuBlockStorageSourceAttachApply(qemuDomainGetMonitor(vm),
                                               dd->crdata->srcdata[0]);

        qemuDomainObjExitMonitor(driver, vm);
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
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
    virDomainDiskDef *persistdisk;
    bool supportsCreate;
    bool updateRelativeBacking = false;
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

    supportsCreate = virStorageSourceSupportsCreate(dd->src);

    /* relative backing store paths need to be updated so that relative
     * block commit still works. With blockdev we must update it when doing
     * commit anyways so it's skipped here */
    if (!blockdev &&
        virStorageSourceSupportsBackingChainTraversal(dd->src))
        updateRelativeBacking = true;

    if (supportsCreate || updateRelativeBacking) {
        if (qemuDomainStorageFileInit(driver, vm, dd->src, NULL) < 0)
            return -1;

        dd->initialized = true;

        if (reuse) {
            if (updateRelativeBacking &&
                virStorageSourceFetchRelativeBackingPath(dd->src, &dd->relPath) < 0)
                return -1;
        } else {
            /* pre-create the image file so that we can label it before handing it to qemu */
            if (supportsCreate && dd->src->type != VIR_STORAGE_TYPE_BLOCK) {
                if (virStorageSourceCreate(dd->src) < 0) {
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
        if (qemuSnapshotDiskPrepareOneBlockdev(driver, vm, dd, snapctxt->cfg, reuse,
                                               blockNamedNodeData, snapctxt->asyncJob) < 0)
            return -1;

        if (qemuSnapshotDiskBitmapsPropagate(dd, snapctxt->actions, blockNamedNodeData) < 0)
            return -1;

        if (qemuBlockSnapshotAddBlockdev(snapctxt->actions, dd->disk, dd->src) < 0)
            return -1;
    } else {
        if (qemuBlockSnapshotAddLegacy(snapctxt->actions, dd->disk, dd->src, reuse) < 0)
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
static qemuSnapshotDiskContext *
qemuSnapshotDiskPrepareActiveExternal(virDomainObj *vm,
                                      virDomainMomentObj *snap,
                                      bool reuse,
                                      GHashTable *blockNamedNodeData,
                                      qemuDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    size_t i;
    virDomainSnapshotDef *snapdef = virDomainSnapshotObjGetDef(snap);

    snapctxt = qemuSnapshotDiskContextNew(snapdef->ndisks, vm, asyncJob);

    for (i = 0; i < snapdef->ndisks; i++) {
        if (snapdef->disks[i].snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
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
                       _("Overlay file '%s' for transient disk '%s' already exists"),
                       snapdisk->src->path, domdisk->dst);
        return NULL;
    }

    return g_steal_pointer(&snapdisk);
}


static void
qemuSnapshotDiskUpdateSourceRenumber(virStorageSource *src)
{
    virStorageSource *next;
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

    /* fix numbering of disks */
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV))
        qemuSnapshotDiskUpdateSourceRenumber(dd->disk->src);

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

    if (qemuDomainObjEnterMonitorAsync(driver, snapctxt->vm, snapctxt->asyncJob) < 0)
        return -1;

    rc = qemuMonitorTransaction(priv->mon, &snapctxt->actions);

    qemuDomainObjExitMonitor(driver, snapctxt->vm);

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
                                      qemuDomainAsyncJob asyncJob)
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

        if (qemuDomainObjBeginAgentJob(driver, vm, QEMU_AGENT_JOB_MODIFY) < 0)
            goto cleanup;

        if (virDomainObjCheckActive(vm) < 0) {
            qemuDomainObjEndAgentJob(vm);
            goto cleanup;
        }

        frozen = qemuSnapshotFSFreeze(vm, NULL, 0);
        qemuDomainObjEndAgentJob(vm);

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

        qemuDomainJobSetStatsType(priv->job.current,
                                  QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP);

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
                                       QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
            goto cleanup;

        /* the memory image was created, remove it on errors */
        if (!memory_existing)
            memory_unlink = true;

        /* forbid any further manipulation */
        qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_DEFAULT_MASK);
    }

    /* the domain is now paused if a memory snapshot was requested */

    if ((ret = qemuSnapshotCreateActiveExternalDisks(vm, snap,
                                                     blockNamedNodeData, flags,
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

    if (thaw &&
        qemuDomainObjBeginAgentJob(driver, vm, QEMU_AGENT_JOB_MODIFY) >= 0 &&
        virDomainObjIsActive(vm)) {
        /* report error only on an otherwise successful snapshot */
        if (qemuSnapshotFSThaw(vm, ret == 0) < 0)
            ret = -1;

        qemuDomainObjEndAgentJob(vm);
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
    unsigned int parse_flags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;

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
                           _("invalid snapshot name '%s': "
                             "name can't contain '/'"),
                           def->parent.name);
            return -1;
        }

        if (def->parent.name[0] == '.') {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%s': "
                             "name can't start with '.'"),
                           def->parent.name);
            return -1;
        }
    }

    /* reject the VIR_DOMAIN_SNAPSHOT_CREATE_LIVE flag where not supported */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE &&
        (!virDomainObjIsActive(vm) ||
         def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live snapshot creation is supported only "
                         "during full system snapshots"));
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
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %s"),
                           virDomainSnapshotStateTypeToString(state));
            return -1;
        }
        break;

    case VIR_DOMAIN_SNAPSHOT_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support taking snapshots of "
                         "PMSUSPENDED guests"));
        return -1;

        /* invalid states */
    case VIR_DOMAIN_SNAPSHOT_NOSTATE:
    case VIR_DOMAIN_SNAPSHOT_BLOCKED: /* invalid state, unused in qemu */
    case VIR_DOMAIN_SNAPSHOT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %s"),
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
        def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
    } else if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        def->state = virDomainObjGetState(vm, NULL);
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    } else {
        def->state = virDomainObjGetState(vm, NULL);

        if (virDomainObjIsActive(vm) &&
            def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("internal snapshot of a running VM "
                             "must include the memory state"));
            return -1;
        }

        def->memory = (def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF ?
                       VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                       VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL);
    }
    if (virDomainSnapshotAlignDisks(def, NULL, align_location, true) < 0)
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
                       _("unable to save metadata for snapshot %s"),
                       snap->def->name);
        return -1;
    }

    virDomainSnapshotLinkParent(vm->snapshots, snap);

    return 0;
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

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)
        qemuSnapshotSetCurrent(vm, snap);

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

    if (qemuSnapshotCreateAlignDisks(vm, snapdef, driver, flags) < 0)
        return NULL;

    if (qemuSnapshotPrepare(vm, snapdef, &flags) < 0)
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
            if (qemuSnapshotCreateActiveExternal(driver, vm, snap, cfg, flags) < 0)
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
    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SNAPSHOT,
                                   VIR_DOMAIN_JOB_OPERATION_SNAPSHOT, flags) < 0)
        return NULL;

    qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_NONE);

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) {
        snapshot = qemuSnapshotRedefine(vm, domain, def, driver, cfg, flags);
    } else {
        snapshot = qemuSnapshotCreate(vm, domain, def, driver, cfg, flags);
    }

    qemuDomainObjEndAsyncJob(driver, vm);

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

    if (virDomainSnapshotIsExternal(snap)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("revert to external snapshot not supported yet"));
        return -1;
    }

    if (!snap->def->dom) {
        virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                       _("snapshot '%s' lacks domain '%s' rollback info"),
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
    int detail;
    bool defined = false;
    qemuDomainSaveCookie *cookie = (qemuDomainSaveCookie *) snapdef->cookie;
    int rc;

    start_flags |= VIR_QEMU_PROCESS_START_PAUSED;

    /* Transitions 2, 3, 5, 6, 8, 9 */
    if (virDomainObjIsActive(vm)) {
        /* Transitions 5, 6, 8, 9 */
        qemuProcessStop(driver, vm,
                        VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT,
                        QEMU_ASYNC_JOB_START, 0);
        virDomainAuditStop(vm, "from-snapshot");
        detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STOPPED,
                                                  detail);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (*inactiveConfig) {
        virDomainObjAssignDef(vm, inactiveConfig, false, NULL);
        defined = true;
    }

    virDomainObjAssignDef(vm, config, true, NULL);

    /* No cookie means libvirt which saved the domain was too old to
     * mess up the CPU definitions.
     */
    if (cookie &&
        qemuDomainFixupCPUs(vm, &cookie->cpu) < 0)
        return -1;

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
    virObjectEventStateQueue(driver->domainEventState, event);
    if (rc < 0)
        return -1;

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
                                  QEMU_ASYNC_JOB_START);
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
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (qemuSnapshotInternalRevertInactive(driver, vm, snap) < 0) {
        qemuDomainRemoveInactive(driver, vm);
        return -1;
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
                              QEMU_ASYNC_JOB_START, NULL, -1, NULL, NULL,
                              VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                              start_flags);
        virDomainAuditStart(vm, "from-snapshot", rc >= 0);
        if (rc < 0) {
            qemuDomainRemoveInactive(driver, vm);
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

    if (qemuProcessBeginJob(driver, vm,
                            VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_REVERT,
                            flags) < 0)
        return -1;

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

 endjob:
    qemuProcessEndJob(driver, vm);

    return ret;
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


int
qemuSnapshotDelete(virDomainObj *vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags)
{
    virQEMUDriver *driver = snapshot->domain->conn->privateData;
    int ret = -1;
    virDomainMomentObj *snap = NULL;
    virQEMUMomentRemove rem;
    virQEMUMomentReparent rep;
    bool metadata_only = !!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY);
    int external = 0;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, -1);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        return -1;

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
            qemuSnapshotSetCurrent(vm, snap);

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

    return ret;
}
