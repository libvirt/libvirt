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
qemuBackupBegin(virDomainObj *vm,
                const char *backupXML,
                const char *checkpointXML,
                unsigned int flags);

char *
qemuBackupGetXMLDesc(virDomainObj *vm,
                     unsigned int flags);

void
qemuBackupJobCancelBlockjobs(virDomainObj *vm,
                             virDomainBackupDef *backup,
                             bool terminatebackup,
                             int asyncJob);

void
qemuBackupNotifyBlockjobEnd(virDomainObj *vm,
                            virDomainDiskDef *disk,
                            qemuBlockjobState state,
                            const char *errmsg,
                            unsigned long long cur,
                            unsigned long long end,
                            int asyncJob);

void
qemuBackupJobTerminate(virDomainObj *vm,
                       virDomainJobStatus jobstatus);

int
qemuBackupGetJobInfoStats(virDomainObj *vm,
                          virDomainJobData *jobData);

/* exported for testing */
int
qemuBackupDiskPrepareOneBitmapsChain(virStorageSource *backingChain,
                                     virStorageSource *targetsrc,
                                     const char *targetbitmap,
                                     const char *incremental,
                                     virJSONValue *actions,
                                     GHashTable *blockNamedNodeData);
