/*
 * qemu_backup.h: Implementation and handling of the backup jobs
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

int
qemuBackupBegin(virDomainObjPtr vm,
                const char *backupXML,
                const char *checkpointXML,
                unsigned int flags);

char *
qemuBackupGetXMLDesc(virDomainObjPtr vm,
                     unsigned int flags);

void
qemuBackupJobCancelBlockjobs(virDomainObjPtr vm,
                             virDomainBackupDefPtr backup,
                             bool terminatebackup,
                             int asyncJob);

void
qemuBackupNotifyBlockjobEnd(virDomainObjPtr vm,
                            virDomainDiskDefPtr disk,
                            qemuBlockjobState state,
                            const char *errmsg,
                            unsigned long long cur,
                            unsigned long long end,
                            int asyncJob);

void
qemuBackupJobTerminate(virDomainObjPtr vm,
                       qemuDomainJobStatus jobstatus);

int
qemuBackupGetJobInfoStats(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          qemuDomainJobInfoPtr jobInfo);

/* exported for testing */
int
qemuBackupDiskPrepareOneBitmapsChain(virStorageSourcePtr backingChain,
                                     virStorageSourcePtr targetsrc,
                                     const char *targetbitmap,
                                     const char *incremental,
                                     virJSONValuePtr actions,
                                     GHashTable *blockNamedNodeData);
