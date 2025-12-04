/*
 * qemu_saveimage.h: Infrastructure for saving qemu state to a file
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

#include "qemu_domain.h"
#include "qemu_saveimage_format.h"

/* It would be nice to replace 'Qemud' with 'Qemu' but
 * this magic string is ABI, so it can't be changed
 */
#define QEMU_SAVE_MAGIC   "LibvirtQemudSave"
#define QEMU_SAVE_PARTIAL "LibvirtQemudPart"
#define QEMU_SAVE_VERSION 2

G_STATIC_ASSERT(sizeof(QEMU_SAVE_MAGIC) == sizeof(QEMU_SAVE_PARTIAL));

/* enum virQEMUSaveFormat is declared in qemu_saveimage_format.h */
VIR_ENUM_DECL(qemuSaveFormat);

typedef struct _virQEMUSaveHeader virQEMUSaveHeader;
struct _virQEMUSaveHeader {
    char magic[sizeof(QEMU_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t data_len;
    uint32_t was_running;
    uint32_t format;
    uint32_t cookieOffset;
    uint32_t unused[14];
};


typedef struct _virQEMUSaveData virQEMUSaveData;
struct _virQEMUSaveData {
    virQEMUSaveHeader header;
    char *xml;
    char *cookie;
};


virDomainDef *
qemuSaveImageUpdateDef(virQEMUDriver *driver,
                       virDomainDef *def,
                       const char *newxml);

int
qemuSaveImageStartVM(virConnectPtr conn,
                     virQEMUDriver *driver,
                     virDomainObj *vm,
                     int *fd,
                     virQEMUSaveData *data,
                     const char *path,
                     qemuMigrationParams *restoreParams,
                     bool start_paused,
                     bool reset_nvram,
                     virDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

bool
qemuSaveImageIsCorrupt(virQEMUDriver *driver,
                       const char *path)
    ATTRIBUTE_NONNULL(2);

int
qemuSaveImageGetMetadata(virQEMUDriver *driver,
                         virQEMUCaps *qemuCaps,
                         const char *path,
                         int (*ensureACL)(virConnectPtr, virDomainDef *),
                         virConnectPtr conn,
                         virDomainDef **ret_def,
                         virQEMUSaveData **ret_data)
    ATTRIBUTE_NONNULL(6) ATTRIBUTE_NONNULL(7);

int
qemuSaveImageOpen(virQEMUDriver *driver,
                  const char *path,
                  bool bypass_cache,
                  bool sparse,
                  virFileWrapperFd **wrapperFd,
                  bool open_write)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
qemuSaveImageGetCompressionProgram(virQEMUSaveFormat format,
                                   virCommand **compressor,
                                   const char *styleFormat)
    ATTRIBUTE_NONNULL(2);

int
qemuSaveImageDecompressionStart(virQEMUSaveData *data,
                                int *fd,
                                int *intermediatefd,
                                char **errbuf,
                                virCommand **retcmd);

int
qemuSaveImageDecompressionStop(virCommand *cmd,
                               int *fd,
                               int *intermediatefd,
                               char *errbuf,
                               bool started,
                               const char *path);

int
qemuSaveImageCreate(virQEMUDriver *driver,
                    virDomainObj *vm,
                    const char *path,
                    virQEMUSaveData *data,
                    virCommand *compressor,
                    qemuMigrationParams *saveParams,
                    unsigned int flags,
                    virDomainAsyncJob asyncJob);

int
virQEMUSaveDataWrite(virQEMUSaveData *data,
                     int fd,
                     const char *path);

virQEMUSaveData *
virQEMUSaveDataNew(char *domXML,
                   qemuDomainSaveCookie *cookieObj,
                   bool running,
                   virQEMUSaveFormat format,
                   virDomainXMLOption *xmlopt);

void
virQEMUSaveDataFree(virQEMUSaveData *data);
