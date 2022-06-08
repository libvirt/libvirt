/*
 * qemu_checkpoint.h: Implementation and handling of checkpoint
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

#pragma once

#include "virconftypes.h"
#include "qemu_conf.h"

virDomainObj *
qemuDomObjFromCheckpoint(virDomainCheckpointPtr checkpoint);

virDomainMomentObj *
qemuCheckpointObjFromCheckpoint(virDomainObj *vm,
                                virDomainCheckpointPtr checkpoint);

virDomainMomentObj *
qemuCheckpointObjFromName(virDomainObj *vm,
                          const char *name);

int
qemuCheckpointDiscardAllMetadata(virQEMUDriver *driver,
                                 virDomainObj *vm);

virDomainCheckpointPtr
qemuCheckpointCreateXML(virDomainPtr domain,
                        virDomainObj *vm,
                        const char *xmlDesc,
                        unsigned int flags);


char *
qemuCheckpointGetXMLDesc(virDomainObj *vm,
                         virDomainCheckpointPtr checkpoint,
                         unsigned int flags);

int
qemuCheckpointDelete(virDomainObj *vm,
                     virDomainCheckpointPtr checkpoint,
                     unsigned int flags);

int
qemuCheckpointCreateCommon(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainCheckpointDef **def,
                           virJSONValue **actions,
                           virDomainMomentObj **chk);

int
qemuCheckpointCreateFinalize(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virQEMUDriverConfig *cfg,
                             virDomainMomentObj *chk,
                             bool update_current);

void
qemuCheckpointRollbackMetadata(virDomainObj *vm,
                               virDomainMomentObj *chk);

int
qemuCheckpointDiscardDiskBitmaps(virStorageSource *src,
                                 GHashTable *blockNamedNodeData,
                                 const char *delbitmap,
                                 virJSONValue *actions,
                                 const char *diskdst,
                                 GSList **reopenimages);

int
qemuCheckpointWriteMetadata(virDomainObj *vm,
                            virDomainMomentObj *checkpoint,
                            virDomainXMLOption *xmlopt,
                            const char *checkpointDir);
