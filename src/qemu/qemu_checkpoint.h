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
#include "datatypes.h"
#include "qemu_conf.h"

virDomainObjPtr
qemuDomObjFromCheckpoint(virDomainCheckpointPtr checkpoint);

virDomainMomentObjPtr
qemuCheckpointObjFromCheckpoint(virDomainObjPtr vm,
                                virDomainCheckpointPtr checkpoint);

virDomainMomentObjPtr
qemuCheckpointObjFromName(virDomainObjPtr vm,
                          const char *name);

int
qemuCheckpointDiscardAllMetadata(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm);

virDomainCheckpointPtr
qemuCheckpointCreateXML(virDomainPtr domain,
                        virDomainObjPtr vm,
                        const char *xmlDesc,
                        unsigned int flags);


char *
qemuCheckpointGetXMLDesc(virDomainObjPtr vm,
                         virDomainCheckpointPtr checkpoint,
                         unsigned int flags);

int
qemuCheckpointDelete(virDomainObjPtr vm,
                     virDomainCheckpointPtr checkpoint,
                     unsigned int flags);

int
qemuCheckpointCreateCommon(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virCapsPtr caps,
                           virDomainCheckpointDefPtr *def,
                           virJSONValuePtr *actions,
                           virDomainMomentObjPtr *chk);
