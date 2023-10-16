/*
 * qemu_checkpoint.c: checkpoint related implementation
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

#include "qemu_checkpoint.h"
#include "qemu_capabilities.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_block.h"

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "virxml.h"
#include "virdomaincheckpointobjlist.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_checkpoint");

/**
 * qemuCheckpointSetCurrent: Set currently active checkpoint
 *
 * @vm: domain object
 * @newcurrent: checkpoint object to set as current/active
 *
 * Sets @newcurrent as the 'current' checkpoint of @vm. This helper ensures that
 * the checkpoint which was 'current' previously is updated.
 */
static void
qemuCheckpointSetCurrent(virDomainObj *vm,
                       virDomainMomentObj *newcurrent)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainMomentObj *oldcurrent = virDomainCheckpointGetCurrent(vm->checkpoints);

    virDomainCheckpointSetCurrent(vm->checkpoints, newcurrent);

    /* we need to write out metadata for the old checkpoint to update the
     * 'active' property */
    if (oldcurrent &&
        oldcurrent != newcurrent) {
        if (qemuCheckpointWriteMetadata(vm, oldcurrent, driver->xmlopt, cfg->checkpointDir) < 0)
            VIR_WARN("failed to update old current checkpoint");
    }
}


/* Looks up the domain object from checkpoint and unlocks the
 * driver. The returned domain object is locked and ref'd and the
 * caller must call virDomainObjEndAPI() on it. */
virDomainObj *
qemuDomObjFromCheckpoint(virDomainCheckpointPtr checkpoint)
{
    return qemuDomainObjFromDomain(checkpoint->domain);
}


/* Looks up checkpoint object from VM and name */
virDomainMomentObj *
qemuCheckpointObjFromName(virDomainObj *vm,
                          const char *name)
{
    virDomainMomentObj *chk = NULL;
    chk = virDomainCheckpointFindByName(vm->checkpoints, name);
    if (!chk)
        virReportError(VIR_ERR_NO_DOMAIN_CHECKPOINT,
                       _("no domain checkpoint with matching name '%1$s'"),
                       name);

    return chk;
}


/* Looks up checkpoint object from VM and checkpointPtr */
virDomainMomentObj *
qemuCheckpointObjFromCheckpoint(virDomainObj *vm,
                                virDomainCheckpointPtr checkpoint)
{
    return qemuCheckpointObjFromName(vm, checkpoint->name);
}


int
qemuCheckpointWriteMetadata(virDomainObj *vm,
                            virDomainMomentObj *checkpoint,
                            virDomainXMLOption *xmlopt,
                            const char *checkpointDir)
{
    unsigned int flags = VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE;
    virDomainCheckpointDef *def = virDomainCheckpointObjGetDef(checkpoint);
    g_autofree char *newxml = NULL;
    g_autofree char *chkDir = NULL;
    g_autofree char *chkFile = NULL;

    newxml = virDomainCheckpointDefFormat(def, xmlopt, flags);
    if (newxml == NULL)
        return -1;

    chkDir = g_strdup_printf("%s/%s", checkpointDir, vm->def->name);
    if (g_mkdir_with_parents(chkDir, 0777) < 0) {
        virReportSystemError(errno, _("cannot create checkpoint directory '%1$s'"),
                             chkDir);
        return -1;
    }

    chkFile = g_strdup_printf("%s/%s.xml", chkDir, def->parent.name);

    return virXMLSaveFile(chkFile, NULL, "checkpoint-edit", newxml);
}


int
qemuCheckpointDiscardDiskBitmaps(virStorageSource *src,
                                 GHashTable *blockNamedNodeData,
                                 const char *delbitmap,
                                 virJSONValue *actions,
                                 const char *diskdst,
                                 GSList **reopenimages)
{
    virStorageSource *n;
    bool found = false;

    /* find the backing chain entry with bitmap named '@delbitmap' */
    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        qemuBlockNamedNodeDataBitmap *bitmapdata;

        if (!(bitmapdata = qemuBlockNamedNodeDataGetBitmapByName(blockNamedNodeData,
                                                                 n, delbitmap)))
            continue;

        found = true;

        if (qemuMonitorTransactionBitmapRemove(actions,
                                               qemuBlockStorageSourceGetEffectiveNodename(n),
                                               bitmapdata->name) < 0)
            return -1;

        if (n != src)
            *reopenimages = g_slist_prepend(*reopenimages, n);
    }

    if (!found) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("bitmap '%1$s' not found in backing chain of '%2$s'"),
                       delbitmap, diskdst);
        return -1;
    }

    return 0;
}


static int
qemuCheckpointDiscardBitmaps(virDomainObj *vm,
                             virDomainCheckpointDef *chkdef)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    int rc = -1;
    g_autoptr(virJSONValue) actions = NULL;
    size_t i;
    g_autoptr(GSList) reopenimages = NULL;
    g_autoptr(GSList) relabelimages = NULL;
    GSList *next;

    actions = virJSONValueNewArray();

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_NONE)))
        return -1;

    for (i = 0; i < chkdef->ndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = &chkdef->disks[i];
        virDomainDiskDef *domdisk = virDomainDiskByTarget(vm->def, chkdisk->name);

        /* domdisk can be missing e.g. when it was unplugged */
        if (!domdisk)
            continue;

        if (chkdisk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        if (!chkdisk->bitmap) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing bitmap name for disk '%1$s' of checkpoint '%2$s'"),
                           chkdisk->name, chkdef->parent.name);
            return -1;
        }

        if (qemuCheckpointDiscardDiskBitmaps(domdisk->src, blockNamedNodeData,
                                             chkdisk->bitmap,
                                             actions, domdisk->dst,
                                             &reopenimages) < 0)
            return -1;
    }

    /* label any non-top images for read-write access */
    for (next = reopenimages; next; next = next->next) {
        virStorageSource *src = next->data;

        if (qemuDomainStorageSourceAccessAllow(driver, vm, src,
                                               false, false, false) < 0)
            goto relabel;

        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN) &&
            qemuBlockReopenReadWrite(vm, src, VIR_ASYNC_JOB_NONE) < 0)
            goto relabel;

        relabelimages = g_slist_prepend(relabelimages, src);
    }

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorTransaction(priv->mon, &actions);
    qemuDomainObjExitMonitor(vm);

 relabel:
    for (next = relabelimages; next; next = next->next) {
        virStorageSource *src = next->data;

        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN))
            ignore_value(qemuBlockReopenReadOnly(vm, src, VIR_ASYNC_JOB_NONE));

        ignore_value(qemuDomainStorageSourceAccessAllow(driver, vm, src,
                                                        true, false, false));
    }

    return rc;
}


static int
qemuCheckpointDiscard(virQEMUDriver *driver,
                      virDomainObj *vm,
                      virDomainMomentObj *chk,
                      bool update_parent,
                      bool metadata_only)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *chkFile = NULL;
    bool chkcurrent = chk == virDomainCheckpointGetCurrent(vm->checkpoints);

    if (!metadata_only && !virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot remove checkpoint from inactive domain"));
        return -1;
    }

    chkFile = g_strdup_printf("%s/%s/%s.xml", cfg->checkpointDir, vm->def->name,
                              chk->def->name);

    if (!metadata_only) {
        virDomainCheckpointDef *chkdef = virDomainCheckpointObjGetDef(chk);
        if (qemuCheckpointDiscardBitmaps(vm, chkdef) < 0)
            return -1;
    }

    if (chkcurrent) {
        virDomainMomentObj *parent = NULL;

        virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
        parent = virDomainCheckpointFindByName(vm->checkpoints,
                                               chk->def->parent_name);

        if (update_parent && parent) {
            virDomainCheckpointSetCurrent(vm->checkpoints, parent);
            if (qemuCheckpointWriteMetadata(vm, parent,
                                            driver->xmlopt,
                                            cfg->checkpointDir) < 0) {
                VIR_WARN("failed to set parent checkpoint '%s' as current",
                         chk->def->parent_name);
                virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
            }
        }
    }

    if (unlink(chkFile) < 0)
        VIR_WARN("Failed to unlink %s", chkFile);
    if (update_parent)
        virDomainMomentDropParent(chk);
    virDomainCheckpointObjListRemove(vm->checkpoints, chk);

    return 0;
}


int
qemuCheckpointDiscardAllMetadata(virQEMUDriver *driver,
                                       virDomainObj *vm)
{
    virQEMUMomentRemove rem = {
        .driver = driver,
        .vm = vm,
        .metadata_only = true,
        .momentDiscard = qemuCheckpointDiscard,
    };

    virDomainCheckpointForEach(vm->checkpoints, qemuDomainMomentDiscardAll,
                               &rem);
    virDomainCheckpointObjListRemoveAll(vm->checkpoints);

    return rem.err;
}


/* Called inside job lock */
static int
qemuCheckpointPrepare(virQEMUDriver *driver,
                      virDomainObj *vm,
                      virDomainCheckpointDef *def)
{
    size_t i;
    g_autofree char *xml = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;

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

    if (virDomainCheckpointAlignDisks(def) < 0)
        return -1;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDef *disk = &def->disks[i];

        if (disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        if (STRNEQ(disk->bitmap, def->parent.name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("bitmap for disk '%1$s' must match checkpoint name '%2$s'"),
                           disk->name, def->parent.name);
            return -1;
        }

        if (vm->def->disks[i]->src->format != VIR_STORAGE_FILE_QCOW2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("checkpoint for disk %1$s unsupported for storage type %2$s"),
                           disk->name,
                           virStorageFileFormatTypeToString(
                               vm->def->disks[i]->src->format));
            return -1;
        }

        if (!qemuDomainDiskBlockJobIsSupported(vm->def->disks[i]))
            return -1;
    }

    return 0;
}

static int
qemuCheckpointAddActions(virDomainObj *vm,
                         virJSONValue *actions,
                         virDomainCheckpointDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = &def->disks[i];
        virDomainDiskDef *domdisk = virDomainDiskByTarget(vm->def, chkdisk->name);

        /* checkpoint definition validator mandates that the corresponding
         * domdisk should exist */
        if (!domdisk ||
            chkdisk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        if (qemuMonitorTransactionBitmapAdd(actions,
                                            qemuBlockStorageSourceGetEffectiveNodename(domdisk->src),
                                            chkdisk->bitmap, true, false, 0) < 0)
            return -1;
    }
    return 0;
}


static int
qemuCheckpointRedefineValidateBitmaps(virDomainObj *vm,
                                      virDomainCheckpointDef *chkdef)
{
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    size_t i;

    if (virDomainObjCheckActive(vm) < 0)
        return -1;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_NONE)))
        return -1;

    for (i = 0; i < chkdef->ndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = chkdef->disks + i;
        virDomainDiskDef *domdisk;

        if (chkdisk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        /* we tolerate missing disks due to possible detach */
        if (!(domdisk = virDomainDiskByTarget(vm->def, chkdisk->name)))
            continue;

        if (!qemuBlockBitmapChainIsValid(domdisk->src, chkdef->parent.name,
                                         blockNamedNodeData)) {
            virReportError(VIR_ERR_CHECKPOINT_INCONSISTENT,
                           _("missing or broken bitmap '%1$s' for disk '%2$s'"),
                           chkdef->parent.name, domdisk->dst);
            return -1;
        }
    }

    return 0;
}


static virDomainMomentObj *
qemuCheckpointRedefine(virDomainObj *vm,
                       virDomainCheckpointDef **def,
                       bool *update_current,
                       bool validate_bitmaps)
{
    if (virDomainCheckpointRedefinePrep(vm, *def, update_current) < 0)
        return NULL;

    if (validate_bitmaps &&
        qemuCheckpointRedefineValidateBitmaps(vm, *def) < 0)
        return NULL;

    return virDomainCheckpointRedefineCommit(vm, def);
}


int
qemuCheckpointCreateCommon(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainCheckpointDef **def,
                           virJSONValue **actions,
                           virDomainMomentObj **chk)
{
    g_autoptr(virJSONValue) tmpactions = NULL;
    virDomainMomentObj *parent;

    if (qemuCheckpointPrepare(driver, vm, *def) < 0)
        return -1;

    if ((parent = virDomainCheckpointGetCurrent(vm->checkpoints)))
        (*def)->parent.parent_name = g_strdup(parent->def->name);

    tmpactions = virJSONValueNewArray();

    if (qemuCheckpointAddActions(vm, tmpactions, *def) < 0)
        return -1;

    if (!(*chk = virDomainCheckpointAssignDef(vm->checkpoints, *def)))
        return -1;

    *def = NULL;

    *actions = g_steal_pointer(&tmpactions);
    return 0;
}


/**
 * qemuCheckpointRollbackMetadata:
 * @vm: domain object
 * @chk: checkpoint object
 *
 * If @chk is not null remove the @chk object from the list of checkpoints of @vm.
 */
void
qemuCheckpointRollbackMetadata(virDomainObj *vm,
                               virDomainMomentObj *chk)
{
    if (!chk)
        return;

    virDomainCheckpointObjListRemove(vm->checkpoints, chk);
}


static virDomainMomentObj *
qemuCheckpointCreate(virQEMUDriver *driver,
                     virDomainObj *vm,
                     virDomainCheckpointDef **def)
{
    g_autoptr(virJSONValue) actions = NULL;
    virDomainMomentObj *chk = NULL;
    int rc;

    if (qemuCheckpointCreateCommon(driver, vm, def, &actions, &chk) < 0)
        return NULL;

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorTransaction(qemuDomainGetMonitor(vm), &actions);
    qemuDomainObjExitMonitor(vm);
    if (rc < 0) {
        qemuCheckpointRollbackMetadata(vm, chk);
        return NULL;
    }

    return chk;
}


int
qemuCheckpointCreateFinalize(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virQEMUDriverConfig *cfg,
                             virDomainMomentObj *chk,
                             bool update_current)
{
    if (update_current)
        qemuCheckpointSetCurrent(vm, chk);

    if (qemuCheckpointWriteMetadata(vm, chk,
                                    driver->xmlopt,
                                    cfg->checkpointDir) < 0) {
        /* if writing of metadata fails, error out rather than trying
         * to silently carry on without completing the checkpoint */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to save metadata for checkpoint %1$s"),
                       chk->def->name);
        qemuCheckpointRollbackMetadata(vm, chk);
        return -1;
    }

    virDomainCheckpointLinkParent(vm->checkpoints, chk);

    return 0;
}


virDomainCheckpointPtr
qemuCheckpointCreateXML(virDomainPtr domain,
                        virDomainObj *vm,
                        const char *xmlDesc,
                        unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virDomainMomentObj *chk = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    bool update_current = true;
    bool redefine = flags & VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE;
    bool validate_bitmaps = flags & VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE;
    unsigned int parse_flags = 0;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virDomainCheckpointDef) def = NULL;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE |
                  VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE, NULL);

    if (redefine) {
        parse_flags |= VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE;
        update_current = false;
    }

    if (!redefine) {
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot create checkpoint for inactive domain"));
            return NULL;
        }

        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_INCREMENTAL_BACKUP)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("incremental backup is not supported yet"));
            return NULL;
        }
    }

    if (!(def = virDomainCheckpointDefParseString(xmlDesc, driver->xmlopt,
                                                  priv->qemuCaps, parse_flags)))
        return NULL;
    /* Unlike snapshots, the RNG schema already ensured a sane filename. */

    /* We are going to modify the domain below. */
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        return NULL;

    if (redefine) {
        chk = qemuCheckpointRedefine(vm, &def, &update_current, validate_bitmaps);
    } else {
        chk = qemuCheckpointCreate(driver, vm, &def);
    }

    if (!chk)
        goto endjob;

    if (qemuCheckpointCreateFinalize(driver, vm, cfg, chk, update_current) < 0)
        goto endjob;

    /* If we fail after this point, there's not a whole lot we can do;
     * we've successfully created the checkpoint, so we have to go
     * forward the best we can.
     */
    checkpoint = virGetDomainCheckpoint(domain, chk->def->name);

 endjob:
    virDomainObjEndJob(vm);

    return checkpoint;
}


struct qemuCheckpointDiskMap {
    virDomainCheckpointDiskDef *chkdisk;
    virDomainDiskDef *domdisk;
};


static int
qemuCheckpointGetXMLDescUpdateSize(virDomainObj *vm,
                                   virDomainCheckpointDef *chkdef)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) nodedataMerge = NULL;
    g_autoptr(GHashTable) nodedataStats = NULL;
    g_autofree struct qemuCheckpointDiskMap *diskmap = NULL;
    g_autoptr(virJSONValue) recoveractions = NULL;
    g_autoptr(virJSONValue) mergeactions = virJSONValueNewArray();
    g_autoptr(virJSONValue) cleanupactions = virJSONValueNewArray();
    int rc = 0;
    size_t ndisks = 0;
    size_t i;
    int ret = -1;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        return -1;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!(nodedataMerge = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_NONE)))
        goto endjob;

    /* enumerate disks relevant for the checkpoint which are also present in the
     * domain */
    diskmap = g_new0(struct qemuCheckpointDiskMap, chkdef->ndisks);

    for (i = 0; i < chkdef->ndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = chkdef->disks + i;
        virDomainDiskDef *domdisk;

        chkdisk->size = 0;
        chkdisk->sizeValid = false;

        if (chkdisk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        if (!(domdisk = virDomainDiskByTarget(vm->def, chkdisk->name)))
            continue;

        if (!qemuBlockBitmapChainIsValid(domdisk->src, chkdef->parent.name, nodedataMerge))
            continue;

        diskmap[ndisks].chkdisk = chkdisk;
        diskmap[ndisks].domdisk = domdisk;
        ndisks++;
    }

    if (ndisks == 0) {
        ret = 0;
        goto endjob;
    }

    /* we need to calculate the merged bitmap to obtain accurate data */
    for (i = 0; i < ndisks; i++) {
        virDomainDiskDef *domdisk = diskmap[i].domdisk;
        g_autoptr(virJSONValue) actions = NULL;

        /* possibly delete leftovers from previous cases */
        if (qemuBlockNamedNodeDataGetBitmapByName(nodedataMerge, domdisk->src,
                                                  "libvirt-tmp-size-xml")) {
            if (!recoveractions)
                recoveractions = virJSONValueNewArray();

            if (qemuMonitorTransactionBitmapRemove(recoveractions,
                                                   qemuBlockStorageSourceGetEffectiveNodename(domdisk->src),
                                                   "libvirt-tmp-size-xml") < 0)
                goto endjob;
        }

        if (qemuBlockGetBitmapMergeActions(domdisk->src, NULL, domdisk->src,
                                           chkdef->parent.name, "libvirt-tmp-size-xml",
                                           NULL, &actions, nodedataMerge) < 0)
            goto endjob;

        if (virJSONValueArrayConcat(mergeactions, actions) < 0)
            goto endjob;

        if (qemuMonitorTransactionBitmapRemove(cleanupactions,
                                               qemuBlockStorageSourceGetEffectiveNodename(domdisk->src),
                                               "libvirt-tmp-size-xml") < 0)
            goto endjob;
    }

    qemuDomainObjEnterMonitor(vm);

    if (rc == 0 && recoveractions)
        rc = qemuMonitorTransaction(priv->mon, &recoveractions);

    if (rc == 0)
        rc = qemuMonitorTransaction(priv->mon, &mergeactions);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto endjob;

    /* now do a final refresh */
    if (!(nodedataStats = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_NONE)))
        goto endjob;

    qemuDomainObjEnterMonitor(vm);

    rc = qemuMonitorTransaction(priv->mon, &cleanupactions);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto endjob;

    /* update disks */
    for (i = 0; i < ndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = diskmap[i].chkdisk;
        virDomainDiskDef *domdisk = diskmap[i].domdisk;
        qemuBlockNamedNodeDataBitmap *bitmap;

        if ((bitmap = qemuBlockNamedNodeDataGetBitmapByName(nodedataStats, domdisk->src,
                                                            "libvirt-tmp-size-xml"))) {
            chkdisk->size = bitmap->dirtybytes;
            chkdisk->sizeValid = true;
        }
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);
    return ret;
}


char *
qemuCheckpointGetXMLDesc(virDomainObj *vm,
                         virDomainCheckpointPtr checkpoint,
                         unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virDomainMomentObj *chk = NULL;
    virDomainCheckpointDef *chkdef;
    unsigned int format_flags;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_XML_SECURE |
                  VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN |
                  VIR_DOMAIN_CHECKPOINT_XML_SIZE, NULL);

    if (!(chk = qemuCheckpointObjFromCheckpoint(vm, checkpoint)))
        return NULL;

    chkdef = virDomainCheckpointObjGetDef(chk);

    if (flags & VIR_DOMAIN_CHECKPOINT_XML_SIZE &&
        qemuCheckpointGetXMLDescUpdateSize(vm, chkdef) < 0)
        return NULL;

    format_flags = virDomainCheckpointFormatConvertXMLFlags(flags);
    return virDomainCheckpointDefFormat(chkdef, driver->xmlopt,
                                        format_flags);
}


struct virQEMUCheckpointReparent {
    const char *dir;
    virDomainMomentObj *parent;
    virDomainObj *vm;
    virDomainXMLOption *xmlopt;
    int err;
};


static int
qemuCheckpointReparentChildren(void *payload,
                               const char *name G_GNUC_UNUSED,
                               void *data)
{
    virDomainMomentObj *moment = payload;
    struct virQEMUCheckpointReparent *rep = data;

    if (rep->err < 0)
        return 0;

    VIR_FREE(moment->def->parent_name);

    if (rep->parent->def)
        moment->def->parent_name = g_strdup(rep->parent->def->name);

    rep->err = qemuCheckpointWriteMetadata(rep->vm, moment,
                                           rep->xmlopt, rep->dir);
    return 0;
}


int
qemuCheckpointDelete(virDomainObj *vm,
                     virDomainCheckpointPtr checkpoint,
                     unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    virDomainMomentObj *chk = NULL;
    virQEMUMomentRemove rem;
    struct virQEMUCheckpointReparent rep;
    bool metadata_only = !!(flags & VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY);

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN |
                  VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY, -1);

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        return -1;

    if (!metadata_only) {
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot delete checkpoint for inactive domain"));
            goto endjob;
        }

        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_INCREMENTAL_BACKUP)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("incremental backup is not supported yet"));
            goto endjob;
        }
    }

    if (!(chk = qemuCheckpointObjFromCheckpoint(vm, checkpoint)))
        goto endjob;

    if (flags & (VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN |
                 VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY)) {
        rem.driver = driver;
        rem.vm = vm;
        rem.metadata_only = metadata_only;
        rem.err = 0;
        rem.current = virDomainCheckpointGetCurrent(vm->checkpoints);
        rem.found = false;
        rem.momentDiscard = qemuCheckpointDiscard;
        virDomainMomentForEachDescendant(chk, qemuDomainMomentDiscardAll,
                                         &rem);
        if (rem.err < 0)
            goto endjob;
        if (rem.found) {
            qemuCheckpointSetCurrent(vm, chk);

            if (flags & VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY) {
                if (qemuCheckpointWriteMetadata(vm, chk,
                                                driver->xmlopt,
                                                cfg->checkpointDir) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("failed to set checkpoint '%1$s' as current"),
                                   chk->def->name);
                    virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
                    goto endjob;
                }
            }
        }
    } else if (chk->nchildren) {
        rep.dir = cfg->checkpointDir;
        rep.parent = chk->parent;
        rep.vm = vm;
        rep.err = 0;
        rep.xmlopt = driver->xmlopt;
        virDomainMomentForEachChild(chk, qemuCheckpointReparentChildren,
                                    &rep);
        if (rep.err < 0)
            goto endjob;
        virDomainMomentMoveChildren(chk, chk->parent);
    }

    if (flags & VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY) {
        virDomainMomentDropChildren(chk);
        ret = 0;
    } else {
        ret = qemuCheckpointDiscard(driver, vm, chk, true, metadata_only);
    }

 endjob:
    virDomainObjEndJob(vm);
    return ret;
}
