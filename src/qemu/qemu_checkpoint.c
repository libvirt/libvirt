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
#include "qemu_monitor_json.h"
#include "qemu_domain.h"

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "libvirt_internal.h"
#include "virxml.h"
#include "virstring.h"
#include "virdomaincheckpointobjlist.h"
#include "virdomainsnapshotobjlist.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_checkpoint");

/* Looks up the domain object from checkpoint and unlocks the
 * driver. The returned domain object is locked and ref'd and the
 * caller must call virDomainObjEndAPI() on it. */
virDomainObjPtr
qemuDomObjFromCheckpoint(virDomainCheckpointPtr checkpoint)
{
    return qemuDomainObjFromDomain(checkpoint->domain);
}


/* Looks up checkpoint object from VM and name */
virDomainMomentObjPtr
qemuCheckpointObjFromName(virDomainObjPtr vm,
                          const char *name)
{
    virDomainMomentObjPtr chk = NULL;
    chk = virDomainCheckpointFindByName(vm->checkpoints, name);
    if (!chk)
        virReportError(VIR_ERR_NO_DOMAIN_CHECKPOINT,
                       _("no domain checkpoint with matching name '%s'"),
                       name);

    return chk;
}


/* Looks up checkpoint object from VM and checkpointPtr */
virDomainMomentObjPtr
qemuCheckpointObjFromCheckpoint(virDomainObjPtr vm,
                                virDomainCheckpointPtr checkpoint)
{
    return qemuCheckpointObjFromName(vm, checkpoint->name);
}


/* Called inside job lock */
static int
qemuCheckpointPrepare(virQEMUDriverPtr driver,
                      virCapsPtr caps,
                      virDomainObjPtr vm,
                      virDomainCheckpointDefPtr def)
{
    int ret = -1;
    size_t i;
    char *xml = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    /* Easiest way to clone inactive portion of vm->def is via
     * conversion in and back out of xml.  */
    if (!(xml = qemuDomainDefFormatLive(driver, priv->qemuCaps,
                                        vm->def, priv->origCPU,
                                        true, true)) ||
        !(def->parent.dom = virDomainDefParseString(xml, caps, driver->xmlopt,
                                                    priv->qemuCaps,
                                                    VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                    VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (virDomainCheckpointAlignDisks(def) < 0)
        goto cleanup;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDefPtr disk = &def->disks[i];

        if (disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;

        if (vm->def->disks[i]->src->format != VIR_STORAGE_FILE_QCOW2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("checkpoint for disk %s unsupported "
                             "for storage type %s"),
                           disk->name,
                           virStorageFileFormatTypeToString(
                               vm->def->disks[i]->src->format));
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    return ret;
}

static int
qemuCheckpointAddActions(virDomainObjPtr vm,
                         virJSONValuePtr actions,
                         virDomainMomentObjPtr old_current,
                         virDomainCheckpointDefPtr def)
{
    size_t i, j;
    virDomainCheckpointDefPtr olddef;
    virDomainMomentObjPtr parent;
    bool search_parents;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDef *disk = &def->disks[i];
        const char *node;

        if (disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
            continue;
        node = qemuDomainDiskNodeFormatLookup(vm, disk->name);
        if (qemuMonitorJSONTransactionAdd(actions,
                                          "block-dirty-bitmap-add",
                                          "s:node", node,
                                          "s:name", disk->bitmap,
                                          "b:persistent", true,
                                          NULL) < 0)
            return -1;

        /* We only want one active bitmap for a disk along the
         * checkpoint chain, then later differential backups will
         * merge the bitmaps (only one active) between the bounding
         * checkpoint and the leaf checkpoint.  If the same disks are
         * involved in each checkpoint, this search terminates in one
         * iteration; but it is also possible to have to search
         * further than the immediate parent to find another
         * checkpoint with a bitmap on the same disk.  */
        search_parents = true;
        for (parent = old_current; search_parents && parent;
             parent = virDomainCheckpointFindByName(vm->checkpoints,
                                                    olddef->parent.parent_name)) {
            olddef = virDomainCheckpointObjGetDef(parent);
            for (j = 0; j < olddef->ndisks; j++) {
                virDomainCheckpointDiskDef *disk2;

                disk2 = &olddef->disks[j];
                if (STRNEQ(disk->name, disk2->name) ||
                    disk2->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP)
                    continue;
                if (qemuMonitorJSONTransactionAdd(actions,
                                                  "block-dirty-bitmap-disable",
                                                  "s:node", node,
                                                  "s:name", disk2->bitmap,
                                                  NULL) < 0)
                    return -1;
                search_parents = false;
                break;
            }
        }
    }
    return 0;
}


virDomainCheckpointPtr
qemuCheckpointCreateXML(virDomainPtr domain,
                        virDomainObjPtr vm,
                        const char *xmlDesc,
                        unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    virDomainMomentObjPtr chk = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    bool update_current = true;
    bool redefine = flags & VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE;
    unsigned int parse_flags = 0;
    virDomainMomentObjPtr other = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    virJSONValuePtr actions = NULL;
    int ret;
    VIR_AUTOUNREF(virDomainCheckpointDefPtr) def = NULL;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE, NULL);
    /* TODO: VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE */

    if (redefine) {
        parse_flags |= VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE;
        update_current = false;
    }

    if (virDomainSnapshotObjListNum(vm->snapshots, NULL, 0) > 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot create checkpoint while snapshot exists"));
        goto cleanup;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BITMAP_MERGE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("qemu binary lacks persistent bitmaps support"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot create checkpoint for inactive domain"));
        goto cleanup;
    }

    if (!(def = virDomainCheckpointDefParseString(xmlDesc, caps, driver->xmlopt,
                                                  priv->qemuCaps, parse_flags)))
        goto cleanup;
    /* Unlike snapshots, the RNG schema already ensured a sane filename. */

    /* We are going to modify the domain below. */
    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (redefine) {
        if (virDomainCheckpointRedefinePrep(vm, &def, &chk,
                                            driver->xmlopt,
                                            &update_current) < 0)
            goto endjob;
    } else if (qemuCheckpointPrepare(driver, caps, vm, def) < 0) {
        goto endjob;
    }

    if (!chk) {
        if (!(chk = virDomainCheckpointAssignDef(vm->checkpoints, def)))
            goto endjob;

        def = NULL;
    }

    other = virDomainCheckpointGetCurrent(vm->checkpoints);
    if (other) {
        if (!redefine &&
            VIR_STRDUP(chk->def->parent_name, other->def->name) < 0)
            goto endjob;
        if (update_current) {
            virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
            if (qemuDomainCheckpointWriteMetadata(vm, other,
                                                  driver->caps, driver->xmlopt,
                                                  cfg->checkpointDir) < 0)
                goto endjob;
        }
    }

    /* actually do the checkpoint */
    if (redefine) {
        /* XXX Should we validate that the redefined checkpoint even
         * makes sense, such as checking that qemu-img recognizes the
         * checkpoint bitmap name in at least one of the domain's disks?  */
    } else {
        if (!(actions = virJSONValueNewArray()))
            goto endjob;
        if (qemuCheckpointAddActions(vm, actions, other,
                                     virDomainCheckpointObjGetDef(chk)) < 0)
            goto endjob;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorTransaction(priv->mon, &actions);
        if (qemuDomainObjExitMonitor(driver, vm) < 0 || ret < 0)
            goto endjob;
    }

    /* If we fail after this point, there's not a whole lot we can do;
     * we've successfully created the checkpoint, so we have to go
     * forward the best we can.
     */
    checkpoint = virGetDomainCheckpoint(domain, chk->def->name);

 endjob:
    if (checkpoint) {
        if (update_current)
            virDomainCheckpointSetCurrent(vm->checkpoints, chk);
        if (qemuDomainCheckpointWriteMetadata(vm, chk, driver->caps,
                                              driver->xmlopt,
                                              cfg->checkpointDir) < 0) {
            /* if writing of metadata fails, error out rather than trying
             * to silently carry on without completing the checkpoint */
            virObjectUnref(checkpoint);
            checkpoint = NULL;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to save metadata for checkpoint %s"),
                           chk->def->name);
            virDomainCheckpointObjListRemove(vm->checkpoints, chk);
        } else {
            virDomainCheckpointLinkParent(vm->checkpoints, chk);
        }
    } else if (chk) {
        virDomainCheckpointObjListRemove(vm->checkpoints, chk);
    }

    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virJSONValueFree(actions);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return checkpoint;
}


char *
qemuCheckpointGetXMLDesc(virDomainObjPtr vm,
                         virDomainCheckpointPtr checkpoint,
                         unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    virDomainMomentObjPtr chk = NULL;
    virDomainCheckpointDefPtr chkdef;
    unsigned int format_flags;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_XML_SECURE |
                  VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN, NULL);

    if (!(chk = qemuCheckpointObjFromCheckpoint(vm, checkpoint)))
        return NULL;

    chkdef = virDomainCheckpointObjGetDef(chk);

    format_flags = virDomainCheckpointFormatConvertXMLFlags(flags);
    return virDomainCheckpointDefFormat(chkdef, driver->caps, driver->xmlopt,
                                        format_flags);
}


struct virQEMUCheckpointReparent {
    const char *dir;
    virDomainMomentObjPtr parent;
    virDomainObjPtr vm;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    int err;
};


static int
qemuCheckpointReparentChildren(void *payload,
                               const void *name ATTRIBUTE_UNUSED,
                               void *data)
{
    virDomainMomentObjPtr moment = payload;
    struct virQEMUCheckpointReparent *rep = data;

    if (rep->err < 0)
        return 0;

    VIR_FREE(moment->def->parent_name);

    if (rep->parent->def &&
        VIR_STRDUP(moment->def->parent_name, rep->parent->def->name) < 0) {
        rep->err = -1;
        return 0;
    }

    rep->err = qemuDomainCheckpointWriteMetadata(rep->vm, moment, rep->caps,
                                                 rep->xmlopt, rep->dir);
    return 0;
}


int
qemuCheckpointDelete(virDomainObjPtr vm,
                     virDomainCheckpointPtr checkpoint,
                     unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    VIR_AUTOUNREF(virQEMUDriverConfigPtr) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    virDomainMomentObjPtr chk = NULL;
    virQEMUMomentRemove rem;
    struct virQEMUCheckpointReparent rep;
    bool metadata_only = !!(flags & VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY);

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN |
                  VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY, -1);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        return -1;

    if (!metadata_only) {
        /* Until qemu-img supports offline bitmap deletion, we are stuck
         * with requiring a running guest */
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot delete checkpoint for inactive domain"));
            goto endjob;
        }
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BITMAP_MERGE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("qemu binary lacks persistent bitmaps support"));
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
        rem.momentDiscard = qemuDomainCheckpointDiscard;
        virDomainMomentForEachDescendant(chk, qemuDomainMomentDiscardAll,
                                         &rem);
        if (rem.err < 0)
            goto endjob;
        if (rem.found) {
            virDomainCheckpointSetCurrent(vm->checkpoints, chk);
            if (flags & VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY) {
                if (qemuDomainCheckpointWriteMetadata(vm, chk, driver->caps,
                                                      driver->xmlopt,
                                                      cfg->checkpointDir) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("failed to set checkpoint '%s' as current"),
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
        rep.caps = driver->caps;
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
        ret = qemuDomainCheckpointDiscard(driver, vm, chk, true, metadata_only);
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);
    return ret;
}
