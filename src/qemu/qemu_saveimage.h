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

#include "qemu_conf.h"
#include "qemu_domain.h"

/* It would be nice to replace 'Qemud' with 'Qemu' but
 * this magic string is ABI, so it can't be changed
 */
#define QEMU_SAVE_MAGIC   "LibvirtQemudSave"
#define QEMU_SAVE_PARTIAL "LibvirtQemudPart"
#define QEMU_SAVE_VERSION 2

G_STATIC_ASSERT(sizeof(QEMU_SAVE_MAGIC) == sizeof(QEMU_SAVE_PARTIAL));

typedef enum {
    QEMU_SAVE_FORMAT_RAW = 0,
    QEMU_SAVE_FORMAT_GZIP = 1,
    QEMU_SAVE_FORMAT_BZIP2 = 2,
    /*
     * Deprecated by xz and never used as part of a release
     * QEMU_SAVE_FORMAT_LZMA
     */
    QEMU_SAVE_FORMAT_XZ = 3,
    QEMU_SAVE_FORMAT_LZOP = 4,
    QEMU_SAVE_FORMAT_ZSTD = 5,
    /* Note: add new members only at the end.
       These values are used in the on-disk format.
       Do not change or re-use numbers. */

    QEMU_SAVE_FORMAT_LAST
} virQEMUSaveFormat;
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
                         virDomainDef **ret_def,
                         virQEMUSaveData **ret_data)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

int
qemuSaveImageOpen(virQEMUDriver *driver,
                  const char *path,
                  bool bypass_cache,
                  virFileWrapperFd **wrapperFd,
                  bool open_write)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
qemuSaveImageGetCompressionProgram(int format,
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
                   int format,
                   virDomainXMLOption *xmlopt);

void
virQEMUSaveDataFree(virQEMUSaveData *data);
