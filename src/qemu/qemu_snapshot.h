/*
 * qemu_snapshot.h: Implementation and handling of snapshots
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
#include "qemu_domainjob.h"

virDomainMomentObjPtr
qemuSnapObjFromName(virDomainObjPtr vm,
                    const char *name);

virDomainMomentObjPtr
qemuSnapObjFromSnapshot(virDomainObjPtr vm,
                        virDomainSnapshotPtr snapshot);

int
qemuSnapshotFSFreeze(virDomainObjPtr vm,
                     const char **mountpoints,
                     unsigned int nmountpoints);
int
qemuSnapshotFSThaw(virDomainObjPtr vm,
                   bool report);

virDomainSnapshotPtr
qemuSnapshotCreateXML(virDomainPtr domain,
                      virDomainObjPtr vm,
                      const char *xmlDesc,
                      unsigned int flags);

int
qemuSnapshotRevert(virDomainObjPtr vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags);

int
qemuSnapshotDelete(virDomainObjPtr vm,
                   virDomainSnapshotPtr snapshot,
                   unsigned int flags);

int
qemuSnapshotCreateDisksTransient(virDomainObjPtr vm,
                                 qemuDomainAsyncJob asyncJob);
