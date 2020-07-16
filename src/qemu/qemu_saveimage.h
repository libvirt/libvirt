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
#include "datatypes.h"

#include "qemu_conf.h"
#include "qemu_domainjob.h"
#include "qemu_domain.h"

/* It would be nice to replace 'Qemud' with 'Qemu' but
 * this magic string is ABI, so it can't be changed
 */
#define QEMU_SAVE_MAGIC   "LibvirtQemudSave"
#define QEMU_SAVE_PARTIAL "LibvirtQemudPart"
#define QEMU_SAVE_VERSION 2

G_STATIC_ASSERT(sizeof(QEMU_SAVE_MAGIC) == sizeof(QEMU_SAVE_PARTIAL));

typedef struct _virQEMUSaveHeader virQEMUSaveHeader;
typedef virQEMUSaveHeader *virQEMUSaveHeaderPtr;
struct _virQEMUSaveHeader {
    char magic[sizeof(QEMU_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t data_len;
    uint32_t was_running;
    uint32_t compressed;
    uint32_t cookieOffset;
    uint32_t unused[14];
};


typedef struct _virQEMUSaveData virQEMUSaveData;
typedef virQEMUSaveData *virQEMUSaveDataPtr;
struct _virQEMUSaveData {
    virQEMUSaveHeader header;
    char *xml;
    char *cookie;
};


virDomainDefPtr
qemuSaveImageUpdateDef(virQEMUDriverPtr driver,
                       virDomainDefPtr def,
                       const char *newxml);

int
qemuSaveImageStartVM(virConnectPtr conn,
                     virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     int *fd,
                     virQEMUSaveDataPtr data,
                     const char *path,
                     bool start_paused,
                     qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

int
qemuSaveImageOpen(virQEMUDriverPtr driver,
                  virQEMUCapsPtr qemuCaps,
                  const char *path,
                  virDomainDefPtr *ret_def,
                  virQEMUSaveDataPtr *ret_data,
                  bool bypass_cache,
                  virFileWrapperFdPtr *wrapperFd,
                  bool open_write,
                  bool unlink_corrupt)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
qemuSaveImageGetCompressionProgram(const char *imageFormat,
                                   virCommandPtr *compressor,
                                   const char *styleFormat,
                                   bool use_raw_on_fail)
    ATTRIBUTE_NONNULL(2);

int
qemuSaveImageCreate(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    const char *path,
                    virQEMUSaveDataPtr data,
                    virCommandPtr compressor,
                    unsigned int flags,
                    qemuDomainAsyncJob asyncJob);

int
virQEMUSaveDataWrite(virQEMUSaveDataPtr data,
                     int fd,
                     const char *path);

virQEMUSaveDataPtr
virQEMUSaveDataNew(char *domXML,
                   qemuDomainSaveCookiePtr cookieObj,
                   bool running,
                   int compressed,
                   virDomainXMLOptionPtr xmlopt);

void
virQEMUSaveDataFree(virQEMUSaveDataPtr data);
