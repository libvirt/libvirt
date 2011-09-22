/*
 * storage_encryption_conf.h: volume encryption information
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#ifndef __VIR_STORAGE_ENCRYPTION_H__
# define __VIR_STORAGE_ENCRYPTION_H__

# include "internal.h"
# include "buf.h"
# include "util.h"

# include <libxml/tree.h>

enum virStorageEncryptionSecretType {
    VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE = 0,

    VIR_STORAGE_ENCRYPTION_SECRET_TYPE_LAST
};
VIR_ENUM_DECL(virStorageEncryptionSecretType)

typedef struct _virStorageEncryptionSecret virStorageEncryptionSecret;
typedef virStorageEncryptionSecret *virStorageEncryptionSecretPtr;
struct _virStorageEncryptionSecret {
    int type;                   /* enum virStorageEncryptionSecretType */
    unsigned char uuid[VIR_UUID_BUFLEN];
};

enum virStorageEncryptionFormat {
    /* "default" is only valid for volume creation */
    VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT = 0,
    VIR_STORAGE_ENCRYPTION_FORMAT_QCOW, /* Both qcow and qcow2 */

    VIR_STORAGE_ENCRYPTION_FORMAT_LAST,
};
VIR_ENUM_DECL(virStorageEncryptionFormat)

typedef struct _virStorageEncryption virStorageEncryption;
typedef virStorageEncryption *virStorageEncryptionPtr;
struct _virStorageEncryption {
    int format;            /* enum virStorageEncryptionFormat */

    size_t nsecrets;
    virStorageEncryptionSecretPtr *secrets;
};

void virStorageEncryptionFree(virStorageEncryptionPtr enc);

virStorageEncryptionPtr virStorageEncryptionParseNode(xmlDocPtr xml,
                                                      xmlNodePtr root);
int virStorageEncryptionFormat(virBufferPtr buf,
                               virStorageEncryptionPtr enc);

/* A helper for VIR_STORAGE_ENCRYPTION_FORMAT_QCOW */
enum {
  VIR_STORAGE_QCOW_PASSPHRASE_SIZE = 16
};

int virStorageGenerateQcowPassphrase(unsigned char *dest);

#endif /* __VIR_STORAGE_ENCRYPTION_H__ */
