/*
 * virstoragefile.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2017 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
#include "virstoragefilebackend.h"

#include <unistd.h>
#include <fcntl.h>
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "c-ctype.h"
#include "vircommand.h"
#include "virhash.h"
#include "virendian.h"
#include "virstring.h"
#include "virutil.h"
#include "viruri.h"
#include "dirname.h"
#include "virbuffer.h"
#include "virjson.h"
#include "virstorageencryption.h"
#include "virsecret.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("util.storagefile");

static virClassPtr virStorageSourceClass;

VIR_ENUM_IMPL(virStorage,
              VIR_STORAGE_TYPE_LAST,
              "none",
              "file",
              "block",
              "dir",
              "network",
              "volume",
);

VIR_ENUM_IMPL(virStorageFileFormat,
              VIR_STORAGE_FILE_LAST,
              "none",
              "raw", "dir", "bochs",
              "cloop", "dmg", "iso",
              "vpc", "vdi",
              /* Not direct file formats, but used for various drivers */
              "fat", "vhd", "ploop",
              /* Formats with backing file below here */
              "cow", "qcow", "qcow2", "qed", "vmdk",
);

VIR_ENUM_IMPL(virStorageFileFeature,
              VIR_STORAGE_FILE_FEATURE_LAST,
              "lazy_refcounts",
);

VIR_ENUM_IMPL(virStorageNetProtocol,
              VIR_STORAGE_NET_PROTOCOL_LAST,
              "none",
              "nbd",
              "rbd",
              "sheepdog",
              "gluster",
              "iscsi",
              "http",
              "https",
              "ftp",
              "ftps",
              "tftp",
              "ssh",
              "vxhs",
);

VIR_ENUM_IMPL(virStorageNetHostTransport,
              VIR_STORAGE_NET_HOST_TRANS_LAST,
              "tcp",
              "unix",
              "rdma",
);

VIR_ENUM_IMPL(virStorageSourcePoolMode,
              VIR_STORAGE_SOURCE_POOL_MODE_LAST,
              "default",
              "host",
              "direct",
);

VIR_ENUM_IMPL(virStorageAuth,
              VIR_STORAGE_AUTH_TYPE_LAST,
              "none", "chap", "ceph",
);

enum lv_endian {
    LV_LITTLE_ENDIAN = 1, /* 1234 */
    LV_BIG_ENDIAN         /* 4321 */
};

enum {
    BACKING_STORE_OK,
    BACKING_STORE_INVALID,
    BACKING_STORE_ERROR,
};

#define FILE_TYPE_VERSIONS_LAST 3

struct FileEncryptionInfo {
    int format; /* Encryption format to assign */

    int magicOffset; /* Byte offset of the magic */
    const char *magic; /* Optional string of magic */

    enum lv_endian endian; /* Endianness of file format */

    int versionOffset;    /* Byte offset from start of file
                           * where we find version number,
                           * -1 to always fail the version test,
                           * -2 to always pass the version test */
    int versionSize;      /* Size in bytes of version data (0, 2, or 4) */
    int versionNumbers[FILE_TYPE_VERSIONS_LAST];
                          /* Version numbers to validate. Zeroes are ignored. */

    int modeOffset; /* Byte offset of the format native encryption mode */
    char modeValue; /* Value expected at offset */

    int payloadOffset; /* start offset of the volume data (in 512 byte sectors) */
};

/* Either 'magic' or 'extension' *must* be provided */
struct FileTypeInfo {
    int magicOffset;    /* Byte offset of the magic */
    const char *magic;  /* Optional string of file magic
                         * to check at head of file */
    const char *extension; /* Optional file extension to check */
    enum lv_endian endian; /* Endianness of file format */

    int versionOffset;    /* Byte offset from start of file
                           * where we find version number,
                           * -1 to always fail the version test,
                           * -2 to always pass the version test */
    int versionSize;      /* Size in bytes of version data (0, 2, or 4) */
    int versionNumbers[FILE_TYPE_VERSIONS_LAST];
                          /* Version numbers to validate. Zeroes are ignored. */
    int sizeOffset;       /* Byte offset from start of file
                           * where we find capacity info,
                           * -1 to use st_size as capacity */
    int sizeBytes;        /* Number of bytes for size field */
    int sizeMultiplier;   /* A scaling factor if size is not in bytes */
                          /* Store a COW base image path (possibly relative),
                           * or NULL if there is no COW base image, to RES;
                           * return BACKING_STORE_* */
    const struct FileEncryptionInfo *cryptInfo; /* Encryption info */
    int (*getBackingStore)(char **res, int *format,
                           const char *buf, size_t buf_size);
    int (*getFeatures)(virBitmapPtr *features, int format,
                       char *buf, ssize_t len);
};


static int cowGetBackingStore(char **, int *,
                              const char *, size_t);
static int qcow1GetBackingStore(char **, int *,
                                const char *, size_t);
static int qcow2GetBackingStore(char **, int *,
                                const char *, size_t);
static int qcow2GetFeatures(virBitmapPtr *features, int format,
                            char *buf, ssize_t len);
static int vmdk4GetBackingStore(char **, int *,
                                const char *, size_t);
static int
qedGetBackingStore(char **, int *, const char *, size_t);

#define QCOWX_HDR_VERSION (4)
#define QCOWX_HDR_BACKING_FILE_OFFSET (QCOWX_HDR_VERSION+4)
#define QCOWX_HDR_BACKING_FILE_SIZE (QCOWX_HDR_BACKING_FILE_OFFSET+8)
#define QCOWX_HDR_IMAGE_SIZE (QCOWX_HDR_BACKING_FILE_SIZE+4+4)

#define QCOW1_HDR_CRYPT (QCOWX_HDR_IMAGE_SIZE+8+1+1+2)
#define QCOW2_HDR_CRYPT (QCOWX_HDR_IMAGE_SIZE+8)

#define QCOW1_HDR_TOTAL_SIZE (QCOW1_HDR_CRYPT+4+8)
#define QCOW2_HDR_TOTAL_SIZE (QCOW2_HDR_CRYPT+4+4+8+8+4+4+8)

#define QCOW2_HDR_EXTENSION_END 0
#define QCOW2_HDR_EXTENSION_BACKING_FORMAT 0xE2792ACA

#define QCOW2v3_HDR_FEATURES_INCOMPATIBLE (QCOW2_HDR_TOTAL_SIZE)
#define QCOW2v3_HDR_FEATURES_COMPATIBLE (QCOW2v3_HDR_FEATURES_INCOMPATIBLE+8)
#define QCOW2v3_HDR_FEATURES_AUTOCLEAR (QCOW2v3_HDR_FEATURES_COMPATIBLE+8)

/* The location of the header size [4 bytes] */
#define QCOW2v3_HDR_SIZE       (QCOW2_HDR_TOTAL_SIZE+8+8+8+4)

#define QED_HDR_FEATURES_OFFSET (4+4+4+4)
#define QED_HDR_IMAGE_SIZE (QED_HDR_FEATURES_OFFSET+8+8+8+8)
#define QED_HDR_BACKING_FILE_OFFSET (QED_HDR_IMAGE_SIZE+8)
#define QED_HDR_BACKING_FILE_SIZE (QED_HDR_BACKING_FILE_OFFSET+4)
#define QED_F_BACKING_FILE 0x01
#define QED_F_BACKING_FORMAT_NO_PROBE 0x04

#define PLOOP_IMAGE_SIZE_OFFSET 36
#define PLOOP_SIZE_MULTIPLIER 512

#define LUKS_HDR_MAGIC_LEN 6
#define LUKS_HDR_VERSION_LEN 2
#define LUKS_HDR_CIPHER_NAME_LEN 32
#define LUKS_HDR_CIPHER_MODE_LEN 32
#define LUKS_HDR_HASH_SPEC_LEN 32
#define LUKS_HDR_PAYLOAD_LEN 4

/* Format described by qemu commit id '3e308f20e' */
#define LUKS_HDR_VERSION_OFFSET LUKS_HDR_MAGIC_LEN
#define LUKS_HDR_PAYLOAD_OFFSET (LUKS_HDR_MAGIC_LEN+\
                                 LUKS_HDR_VERSION_LEN+\
                                 LUKS_HDR_CIPHER_NAME_LEN+\
                                 LUKS_HDR_CIPHER_MODE_LEN+\
                                 LUKS_HDR_HASH_SPEC_LEN)

static struct FileEncryptionInfo const luksEncryptionInfo[] = {
    {
        .format = VIR_STORAGE_ENCRYPTION_FORMAT_LUKS,

        /* Magic is 'L','U','K','S', 0xBA, 0xBE */
        .magicOffset = 0,
        .magic = "\x4c\x55\x4b\x53\xba\xbe",
        .endian = LV_BIG_ENDIAN,

        .versionOffset  = LUKS_HDR_VERSION_OFFSET,
        .versionSize = LUKS_HDR_VERSION_LEN,
        .versionNumbers = {1},

        .modeOffset = -1,
        .modeValue = -1,

        .payloadOffset = LUKS_HDR_PAYLOAD_OFFSET,
    },
    { 0 }
};

static struct FileEncryptionInfo const qcow1EncryptionInfo[] = {
    {
        .format = VIR_STORAGE_ENCRYPTION_FORMAT_QCOW,

        .magicOffset = 0,
        .magic = NULL,
        .endian = LV_BIG_ENDIAN,

        .versionOffset  = -1,
        .versionSize = 0,
        .versionNumbers = {},

        .modeOffset = QCOW1_HDR_CRYPT,
        .modeValue = 1,

        .payloadOffset = -1,
    },
    { 0 }
};

static struct FileEncryptionInfo const qcow2EncryptionInfo[] = {
    {
        .format = VIR_STORAGE_ENCRYPTION_FORMAT_QCOW,

        .magicOffset = 0,
        .magic = NULL,
        .endian = LV_BIG_ENDIAN,

        .versionOffset  = -1,
        .versionSize = 0,
        .versionNumbers = {},

        .modeOffset = QCOW2_HDR_CRYPT,
        .modeValue = 1,

        .payloadOffset = -1,
    },
    { 0 }
};

static struct FileTypeInfo const fileTypeInfo[] = {
    [VIR_STORAGE_FILE_NONE] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                                -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_RAW] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0,
                               luksEncryptionInfo,
                               NULL, NULL },
    [VIR_STORAGE_FILE_DIR] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_BOCHS] = {
        /*"Bochs Virtual HD Image", */ /* Untested */
        0, NULL, NULL,
        LV_LITTLE_ENDIAN, 64, 4, {0x20000},
        32+16+16+4+4+4+4+4, 8, 1, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_CLOOP] = {
        /* #!/bin/sh
           #V2.0 Format
           modprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1
        */ /* Untested */
        0, NULL, NULL,
        LV_LITTLE_ENDIAN, -1, 0, {0},
        -1, 0, 0, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_DMG] = {
        /* XXX QEMU says there's no magic for dmg,
         * /usr/share/misc/magic lists double magic (both offsets
         * would have to match) but then disables that check. */
        0, NULL, ".dmg",
        0, -1, 0, {0},
        -1, 0, 0, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_ISO] = {
        32769, "CD001", ".iso",
        LV_LITTLE_ENDIAN, -2, 0, {0},
        -1, 0, 0, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_VPC] = {
        0, "conectix", NULL,
        LV_BIG_ENDIAN, 12, 4, {0x10000},
        8 + 4 + 4 + 8 + 4 + 4 + 2 + 2 + 4, 8, 1, NULL, NULL, NULL
    },
    /* TODO: add getBackingStore function */
    [VIR_STORAGE_FILE_VDI] = {
        64, "\x7f\x10\xda\xbe", ".vdi",
        LV_LITTLE_ENDIAN, 68, 4, {0x00010001},
        64 + 5 * 4 + 256 + 7 * 4, 8, 1, NULL, NULL, NULL},

    /* Not direct file formats, but used for various drivers */
    [VIR_STORAGE_FILE_FAT] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_VHD] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_PLOOP] = { 0, "WithouFreSpacExt", NULL, LV_LITTLE_ENDIAN,
                                 -2, 0, {0}, PLOOP_IMAGE_SIZE_OFFSET, 0,
                                 PLOOP_SIZE_MULTIPLIER, NULL, NULL, NULL },

    /* All formats with a backing store probe below here */
    [VIR_STORAGE_FILE_COW] = {
        0, "OOOM", NULL,
        LV_BIG_ENDIAN, 4, 4, {2},
        4+4+1024+4, 8, 1, NULL, cowGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW] = {
        0, "QFI", NULL,
        LV_BIG_ENDIAN, 4, 4, {1},
        QCOWX_HDR_IMAGE_SIZE, 8, 1,
        qcow1EncryptionInfo,
        qcow1GetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW2] = {
        0, "QFI", NULL,
        LV_BIG_ENDIAN, 4, 4, {2, 3},
        QCOWX_HDR_IMAGE_SIZE, 8, 1,
        qcow2EncryptionInfo,
        qcow2GetBackingStore,
        qcow2GetFeatures
    },
    [VIR_STORAGE_FILE_QED] = {
        /* https://wiki.qemu.org/Features/QED */
        0, "QED", NULL,
        LV_LITTLE_ENDIAN, -2, 0, {0},
        QED_HDR_IMAGE_SIZE, 8, 1, NULL, qedGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_VMDK] = {
        0, "KDMV", NULL,
        LV_LITTLE_ENDIAN, 4, 4, {1, 2, 3},
        4+4+4, 8, 512, NULL, vmdk4GetBackingStore, NULL
    },
};
verify(ARRAY_CARDINALITY(fileTypeInfo) == VIR_STORAGE_FILE_LAST);


/* qcow2 compatible features in the order they appear on-disk */
enum qcow2CompatibleFeature {
    QCOW2_COMPATIBLE_FEATURE_LAZY_REFCOUNTS = 0,

    QCOW2_COMPATIBLE_FEATURE_LAST
};

/* conversion to virStorageFileFeature */
static const int qcow2CompatibleFeatureArray[] = {
    VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS,
};
verify(ARRAY_CARDINALITY(qcow2CompatibleFeatureArray) ==
       QCOW2_COMPATIBLE_FEATURE_LAST);

static int
cowGetBackingStore(char **res,
                   int *format,
                   const char *buf,
                   size_t buf_size)
{
#define COW_FILENAME_MAXLEN 1024
    *res = NULL;
    *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size < 4+4+ COW_FILENAME_MAXLEN)
        return BACKING_STORE_INVALID;
    if (buf[4+4] == '\0') { /* cow_header_v2.backing_file[0] */
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }

    if (VIR_STRNDUP(*res, (const char*)buf + 4 + 4, COW_FILENAME_MAXLEN) < 0)
        return BACKING_STORE_ERROR;
    return BACKING_STORE_OK;
}


static int
qcow2GetBackingStoreFormat(int *format,
                           const char *buf,
                           size_t buf_size,
                           size_t extension_start,
                           size_t extension_end)
{
    size_t offset = extension_start;

    /*
     * The extensions take format of
     *
     * int32: magic
     * int32: length
     * byte[length]: payload
     *
     * Unknown extensions can be ignored by skipping
     * over "length" bytes in the data stream.
     */
    while (offset < (buf_size-8) &&
           offset < (extension_end-8)) {
        unsigned int magic = virReadBufInt32BE(buf + offset);
        unsigned int len = virReadBufInt32BE(buf + offset + 4);

        offset += 8;

        if ((offset + len) < offset)
            break;

        if ((offset + len) > buf_size)
            break;

        switch (magic) {
        case QCOW2_HDR_EXTENSION_END:
            goto done;

        case QCOW2_HDR_EXTENSION_BACKING_FORMAT:
            if (buf[offset+len] != '\0')
                break;
            *format = virStorageFileFormatTypeFromString(buf+offset);
            if (*format <= VIR_STORAGE_FILE_NONE)
                return -1;
        }

        offset += len;
    }

 done:

    return 0;
}


static int
qcowXGetBackingStore(char **res,
                     int *format,
                     const char *buf,
                     size_t buf_size,
                     bool isQCow2 ATTRIBUTE_UNUSED)
{
    unsigned long long offset;
    unsigned int size;
    unsigned long long start;
    int version;

    *res = NULL;
    *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size < QCOWX_HDR_BACKING_FILE_OFFSET+8+4)
        return BACKING_STORE_INVALID;
    offset = virReadBufInt64BE(buf + QCOWX_HDR_BACKING_FILE_OFFSET);
    if (offset > buf_size)
        return BACKING_STORE_INVALID;

    if (offset == 0) {
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }

    size = virReadBufInt32BE(buf + QCOWX_HDR_BACKING_FILE_SIZE);
    if (size == 0) {
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }
    if (size > 1023)
        return BACKING_STORE_INVALID;
    if (offset + size > buf_size || offset + size < offset)
        return BACKING_STORE_INVALID;
    if (VIR_ALLOC_N(*res, size + 1) < 0)
        return BACKING_STORE_ERROR;
    memcpy(*res, buf + offset, size);
    (*res)[size] = '\0';

    /*
     * Traditionally QCow2 files had a layout of
     *
     * [header]
     * [backingStoreName]
     *
     * Although the backingStoreName typically followed
     * the header immediately, this was not required by
     * the format. By specifying a higher byte offset for
     * the backing file offset in the header, it was
     * possible to leave space between the header and
     * start of backingStore.
     *
     * This hack is now used to store extensions to the
     * qcow2 format:
     *
     * [header]
     * [extensions]
     * [backingStoreName]
     *
     * Thus the file region to search for extensions is
     * between the end of the header (QCOW2_HDR_TOTAL_SIZE)
     * and the start of the backingStoreName (offset)
     *
     * for qcow2 v3 images, the length of the header
     * is stored at QCOW2v3_HDR_SIZE
     */

    version = virReadBufInt32BE(buf + QCOWX_HDR_VERSION);
    if (version >= 2) {
        /* QCow1 doesn't have the extensions capability
         * used to store backing format */
        if (version == 2)
            start = QCOW2_HDR_TOTAL_SIZE;
        else
            start = virReadBufInt32BE(buf + QCOW2v3_HDR_SIZE);
        if (qcow2GetBackingStoreFormat(format, buf, buf_size,
                                       start, offset) < 0)
            return BACKING_STORE_INVALID;
    }

    return BACKING_STORE_OK;
}


static int
qcow1GetBackingStore(char **res,
                     int *format,
                     const char *buf,
                     size_t buf_size)
{
    return qcowXGetBackingStore(res, format, buf, buf_size, false);
}

static int
qcow2GetBackingStore(char **res,
                     int *format,
                     const char *buf,
                     size_t buf_size)
{
    return qcowXGetBackingStore(res, format, buf, buf_size, true);
}


static int
vmdk4GetBackingStore(char **res,
                     int *format,
                     const char *buf,
                     size_t buf_size)
{
    static const char prefix[] = "parentFileNameHint=\"";
    char *start, *end;
    size_t len;
    int ret = BACKING_STORE_ERROR;
    VIR_AUTOFREE(char *) desc = NULL;

    if (VIR_ALLOC_N(desc, VIR_STORAGE_MAX_HEADER) < 0)
        goto cleanup;

    *res = NULL;
    /*
     * Technically this should have been VMDK, since
     * VMDK spec / VMware impl only support VMDK backed
     * by VMDK. QEMU isn't following this though and
     * does probing on VMDK backing files, hence we set
     * AUTO
     */
    *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size <= 0x200) {
        ret = BACKING_STORE_INVALID;
        goto cleanup;
    }
    len = buf_size - 0x200;
    if (len > VIR_STORAGE_MAX_HEADER)
        len = VIR_STORAGE_MAX_HEADER;
    memcpy(desc, buf + 0x200, len);
    desc[len] = '\0';
    start = strstr(desc, prefix);
    if (start == NULL) {
        *format = VIR_STORAGE_FILE_NONE;
        ret = BACKING_STORE_OK;
        goto cleanup;
    }
    start += strlen(prefix);
    end = strchr(start, '"');
    if (end == NULL) {
        ret = BACKING_STORE_INVALID;
        goto cleanup;
    }
    if (end == start) {
        *format = VIR_STORAGE_FILE_NONE;
        ret = BACKING_STORE_OK;
        goto cleanup;
    }
    *end = '\0';
    if (VIR_STRDUP(*res, start) < 0)
        goto cleanup;

    ret = BACKING_STORE_OK;

 cleanup:
    return ret;
}

static int
qedGetBackingStore(char **res,
                   int *format,
                   const char *buf,
                   size_t buf_size)
{
    unsigned long long flags;
    unsigned long offset, size;

    *res = NULL;
    /* Check if this image has a backing file */
    if (buf_size < QED_HDR_FEATURES_OFFSET+8)
        return BACKING_STORE_INVALID;
    flags = virReadBufInt64LE(buf + QED_HDR_FEATURES_OFFSET);
    if (!(flags & QED_F_BACKING_FILE)) {
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }

    /* Parse the backing file */
    if (buf_size < QED_HDR_BACKING_FILE_OFFSET+8)
        return BACKING_STORE_INVALID;
    offset = virReadBufInt32LE(buf + QED_HDR_BACKING_FILE_OFFSET);
    if (offset > buf_size)
        return BACKING_STORE_INVALID;
    size = virReadBufInt32LE(buf + QED_HDR_BACKING_FILE_SIZE);
    if (size == 0)
        return BACKING_STORE_OK;
    if (offset + size > buf_size || offset + size < offset)
        return BACKING_STORE_INVALID;
    if (VIR_ALLOC_N(*res, size + 1) < 0)
        return BACKING_STORE_ERROR;
    memcpy(*res, buf + offset, size);
    (*res)[size] = '\0';

    if (flags & QED_F_BACKING_FORMAT_NO_PROBE)
        *format = VIR_STORAGE_FILE_RAW;
    else
        *format = VIR_STORAGE_FILE_AUTO_SAFE;

    return BACKING_STORE_OK;
}


static bool
virStorageFileMatchesMagic(int magicOffset,
                           const char *magic,
                           char *buf,
                           size_t buflen)
{
    int mlen;

    if (magic == NULL)
        return false;

    /* Validate magic data */
    mlen = strlen(magic);
    if (magicOffset + mlen > buflen)
        return false;

    if (memcmp(buf + magicOffset, magic, mlen) != 0)
        return false;

    return true;
}


static bool
virStorageFileMatchesExtension(const char *extension,
                               const char *path)
{
    if (extension == NULL)
        return false;

    if (virStringHasCaseSuffix(path, extension))
        return true;

    return false;
}


static bool
virStorageFileMatchesVersion(int versionOffset,
                             int versionSize,
                             const int *versionNumbers,
                             int endian,
                             char *buf,
                             size_t buflen)
{
    int version;
    size_t i;

    /* Validate version number info */
    if (versionOffset == -1)
        return false;

    /* -2 == non-versioned file format, so trivially match */
    if (versionOffset == -2)
        return true;

    /* A positive versionOffset, requires using a valid versionSize */
    if (versionSize != 2 && versionSize != 4)
        return false;

    if ((versionOffset + versionSize) > buflen)
        return false;

    if (endian == LV_LITTLE_ENDIAN) {
        if (versionSize == 4)
            version = virReadBufInt32LE(buf +
                                        versionOffset);
        else
            version = virReadBufInt16LE(buf +
                                        versionOffset);
    } else {
        if (versionSize == 4)
            version = virReadBufInt32BE(buf +
                                        versionOffset);
        else
            version = virReadBufInt16BE(buf +
                                        versionOffset);
    }

    for (i = 0;
         i < FILE_TYPE_VERSIONS_LAST && versionNumbers[i];
         i++) {
        VIR_DEBUG("Compare detected version %d vs one of the expected versions %d",
                  version, versionNumbers[i]);
        if (version == versionNumbers[i])
            return true;
    }

    return false;
}

bool
virStorageIsFile(const char *backing)
{
    char *colon;
    char *slash;

    if (!backing)
        return false;

    colon = strchr(backing, ':');
    slash = strchr(backing, '/');

    /* Reject anything that looks like a protocol (such as nbd: or
     * rbd:); if someone really does want a relative file name that
     * includes ':', they can always prefix './'.  */
    if (colon && (!slash || colon < slash))
        return false;
    return true;
}


bool
virStorageIsRelative(const char *backing)
{
    if (backing[0] == '/')
        return false;

    if (!virStorageIsFile(backing))
        return false;

    return true;
}


static int
virStorageFileProbeFormatFromBuf(const char *path,
                                 char *buf,
                                 size_t buflen)
{
    int format = VIR_STORAGE_FILE_RAW;
    size_t i;
    int possibleFormat = VIR_STORAGE_FILE_RAW;
    VIR_DEBUG("path=%s, buf=%p, buflen=%zu", path, buf, buflen);

    /* First check file magic */
    for (i = 0; i < VIR_STORAGE_FILE_LAST; i++) {
        if (virStorageFileMatchesMagic(fileTypeInfo[i].magicOffset,
                                       fileTypeInfo[i].magic,
                                       buf, buflen)) {
            if (!virStorageFileMatchesVersion(fileTypeInfo[i].versionOffset,
                                              fileTypeInfo[i].versionSize,
                                              fileTypeInfo[i].versionNumbers,
                                              fileTypeInfo[i].endian,
                                              buf, buflen)) {
                possibleFormat = i;
                continue;
            }
            format = i;
            goto cleanup;
        }
    }

    if (possibleFormat != VIR_STORAGE_FILE_RAW)
        VIR_WARN("File %s matches %s magic, but version is wrong. "
                 "Please report new version to libvir-list@redhat.com",
                 path, virStorageFileFormatTypeToString(possibleFormat));

    /* No magic, so check file extension */
    for (i = 0; i < VIR_STORAGE_FILE_LAST; i++) {
        if (virStorageFileMatchesExtension(fileTypeInfo[i].extension, path)) {
            format = i;
            goto cleanup;
        }
    }

 cleanup:
    VIR_DEBUG("format=%d", format);
    return format;
}


static int
qcow2GetFeatures(virBitmapPtr *features,
                 int format,
                 char *buf,
                 ssize_t len)
{
    int version = -1;
    virBitmapPtr feat = NULL;
    uint64_t bits;
    size_t i;

    version = virReadBufInt32BE(buf + fileTypeInfo[format].versionOffset);

    if (version == 2)
        return 0;

    if (len < QCOW2v3_HDR_SIZE)
        return -1;

    if (!(feat = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST)))
        return -1;

    /* todo: check for incompatible or autoclear features? */
    bits = virReadBufInt64BE(buf + QCOW2v3_HDR_FEATURES_COMPATIBLE);
    for (i = 0; i < QCOW2_COMPATIBLE_FEATURE_LAST; i++) {
        if (bits & ((uint64_t) 1 << i))
            ignore_value(virBitmapSetBit(feat, qcow2CompatibleFeatureArray[i]));
    }

    *features = feat;
    return 0;
}


static bool
virStorageFileHasEncryptionFormat(const struct FileEncryptionInfo *info,
                                  char *buf,
                                  size_t len)
{
    if (!info->magic && info->modeOffset == -1)
        return false; /* Shouldn't happen - expect at least one */

    if (info->magic) {
        if (!virStorageFileMatchesMagic(info->magicOffset,
                                        info->magic,
                                        buf, len))
            return false;

        if (info->versionOffset != -1 &&
            !virStorageFileMatchesVersion(info->versionOffset,
                                          info->versionSize,
                                          info->versionNumbers,
                                          info->endian,
                                          buf, len))
            return false;

        return true;
    } else if (info->modeOffset != -1) {
        int crypt_format;

        if (info->modeOffset >= len)
            return false;

        crypt_format = virReadBufInt32BE(buf + info->modeOffset);
        if (crypt_format != info->modeValue)
            return false;

        return true;
    } else {
        return false;
    }
}


static int
virStorageFileGetEncryptionPayloadOffset(const struct FileEncryptionInfo *info,
                                         char *buf)
{
    int payload_offset = -1;

    if (info->payloadOffset != -1) {
        if (info->endian == LV_LITTLE_ENDIAN)
            payload_offset = virReadBufInt32LE(buf + info->payloadOffset);
        else
            payload_offset = virReadBufInt32BE(buf + info->payloadOffset);
    }

    return payload_offset;
}


/* Given a header in BUF with length LEN, as parsed from the storage file
 * assuming it has the given FORMAT, populate information into META
 * with information about the file and its backing store. Return format
 * of the backing store as BACKING_FORMAT. PATH and FORMAT have to be
 * pre-populated in META.
 *
 * Note that this function may be called repeatedly on @meta, so it must
 * clean up any existing allocated memory which would be overwritten.
 */
static int
virStorageFileGetMetadataInternal(virStorageSourcePtr meta,
                                  char *buf,
                                  size_t len,
                                  int *backingFormat)
{
    int dummy;
    size_t i;

    if (!backingFormat)
        backingFormat = &dummy;

    VIR_DEBUG("path=%s, buf=%p, len=%zu, meta->format=%d",
              meta->path, buf, len, meta->format);

    if (meta->format == VIR_STORAGE_FILE_AUTO)
        meta->format = virStorageFileProbeFormatFromBuf(meta->path, buf, len);

    if (meta->format <= VIR_STORAGE_FILE_NONE ||
        meta->format >= VIR_STORAGE_FILE_LAST) {
        virReportSystemError(EINVAL, _("unknown storage file meta->format %d"),
                             meta->format);
        return -1;
    }

    if (fileTypeInfo[meta->format].cryptInfo != NULL) {
        for (i = 0; fileTypeInfo[meta->format].cryptInfo[i].format != 0; i++) {
            if (virStorageFileHasEncryptionFormat(&fileTypeInfo[meta->format].cryptInfo[i],
                                                  buf, len)) {
                int expt_fmt = fileTypeInfo[meta->format].cryptInfo[i].format;
                if (!meta->encryption) {
                    if (VIR_ALLOC(meta->encryption) < 0)
                        return -1;

                    meta->encryption->format = expt_fmt;
                } else {
                    if (meta->encryption->format != expt_fmt) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("encryption format %d doesn't match "
                                         "expected format %d"),
                                       meta->encryption->format, expt_fmt);
                        return -1;
                    }
                }
                meta->encryption->payload_offset =
                    virStorageFileGetEncryptionPayloadOffset(&fileTypeInfo[meta->format].cryptInfo[i], buf);
            }
        }
    }

    /* XXX we should consider moving virStorageBackendUpdateVolInfo
     * code into this method, for non-magic files
     */
    if (!fileTypeInfo[meta->format].magic)
        return 0;

    /* Optionally extract capacity from file */
    if (fileTypeInfo[meta->format].sizeOffset != -1) {
        if ((fileTypeInfo[meta->format].sizeOffset + 8) > len)
            return 0;

        if (fileTypeInfo[meta->format].endian == LV_LITTLE_ENDIAN)
            meta->capacity = virReadBufInt64LE(buf +
                                               fileTypeInfo[meta->format].sizeOffset);
        else
            meta->capacity = virReadBufInt64BE(buf +
                                               fileTypeInfo[meta->format].sizeOffset);
        /* Avoid unlikely, but theoretically possible overflow */
        if (meta->capacity > (ULLONG_MAX /
                              fileTypeInfo[meta->format].sizeMultiplier))
            return 0;
        meta->capacity *= fileTypeInfo[meta->format].sizeMultiplier;
    }

    VIR_FREE(meta->backingStoreRaw);
    if (fileTypeInfo[meta->format].getBackingStore != NULL) {
        int store = fileTypeInfo[meta->format].getBackingStore(&meta->backingStoreRaw,
                                                               backingFormat,
                                                               buf, len);
        if (store == BACKING_STORE_INVALID)
            return 0;

        if (store == BACKING_STORE_ERROR)
            return -1;
    }

    virBitmapFree(meta->features);
    meta->features = NULL;
    if (fileTypeInfo[meta->format].getFeatures != NULL &&
        fileTypeInfo[meta->format].getFeatures(&meta->features, meta->format, buf, len) < 0)
        return -1;

    VIR_FREE(meta->compat);
    if (meta->format == VIR_STORAGE_FILE_QCOW2 && meta->features &&
        VIR_STRDUP(meta->compat, "1.1") < 0)
        return -1;

    return 0;
}


/**
 * virStorageFileProbeFormat:
 *
 * Probe for the format of 'path', returning the detected
 * disk format.
 *
 * Callers are advised never to trust the returned 'format'
 * unless it is listed as VIR_STORAGE_FILE_RAW, since a
 * malicious guest can turn a raw file into any other non-raw
 * format at will.
 *
 * Best option: Don't use this function
 */
int
virStorageFileProbeFormat(const char *path, uid_t uid, gid_t gid)
{
    struct stat sb;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    VIR_AUTOCLOSE fd = -1;
    VIR_AUTOFREE(char *) header = NULL;

    if ((fd = virFileOpenAs(path, O_RDONLY, 0, uid, gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%s'"), path);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno, _("cannot stat file '%s'"), path);
        return -1;
    }

    /* No header to probe for directories */
    if (S_ISDIR(sb.st_mode))
        return VIR_STORAGE_FILE_DIR;

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot set to start of '%s'"), path);
        return -1;
    }

    if ((len = virFileReadHeaderFD(fd, len, &header)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), path);
        return -1;
    }

    return virStorageFileProbeFormatFromBuf(path, header, len);
}


static virStorageSourcePtr
virStorageFileMetadataNew(const char *path,
                          int format)
{
    VIR_AUTOUNREF(virStorageSourcePtr) def = NULL;
    virStorageSourcePtr ret = NULL;

    if (!(def = virStorageSourceNew()))
        return NULL;

    def->format = format;
    def->type = VIR_STORAGE_TYPE_FILE;

    if (VIR_STRDUP(def->path, path) < 0)
        return NULL;

    VIR_STEAL_PTR(ret, def);
    return ret;
}


/**
 * virStorageFileGetMetadataFromBuf:
 * @path: name of file, for error messages
 * @buf: header bytes from @path
 * @len: length of @buf
 * @format: format of the storage file
 * @backingFormat: format of @backing
 *
 * Extract metadata about the storage volume with the specified image format.
 * If image format is VIR_STORAGE_FILE_AUTO, it will probe to automatically
 * identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a format on a file
 * that might be raw if that file will then be passed to a guest, since a
 * malicious guest can turn a raw file into any other non-raw format at will.
 *
 * If the returned @backingFormat is VIR_STORAGE_FILE_AUTO it indicates the
 * image didn't specify an explicit format for its backing store. Callers are
 * advised against probing for the backing store format in this case.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromBuf(const char *path,
                                 char *buf,
                                 size_t len,
                                 int format,
                                 int *backingFormat)
{
    virStorageSourcePtr ret = NULL;
    int dummy;

    if (!backingFormat)
        backingFormat = &dummy;

    if (!(ret = virStorageFileMetadataNew(path, format)))
        return NULL;

    if (virStorageFileGetMetadataInternal(ret, buf, len,
                                          backingFormat) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    return ret;
}


/**
 * virStorageFileGetMetadataFromFD:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromFD(const char *path,
                                int fd,
                                int format,
                                int *backingFormat)

{
    virStorageSourcePtr ret = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    struct stat sb;
    int dummy;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) meta = NULL;

    if (!backingFormat)
        backingFormat = &dummy;

    *backingFormat = VIR_STORAGE_FILE_NONE;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"), path);
        return NULL;
    }

    if (!(meta = virStorageFileMetadataNew(path, format)))
        return NULL;

    if (S_ISDIR(sb.st_mode)) {
        /* No header to probe for directories, but also no backing file. Just
         * update the metadata.*/
        meta->type = VIR_STORAGE_TYPE_DIR;
        meta->format = VIR_STORAGE_FILE_DIR;
        VIR_STEAL_PTR(ret, meta);
        return ret;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%s'"), meta->path);
        return NULL;
    }

    if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), meta->path);
        return NULL;
    }

    if (virStorageFileGetMetadataInternal(meta, buf, len, backingFormat) < 0)
        return NULL;

    if (S_ISREG(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_FILE;
    else if (S_ISBLK(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_BLOCK;

    VIR_STEAL_PTR(ret, meta);
    return ret;
}


/**
 * virStorageFileChainCheckBroken
 *
 * If CHAIN is broken, set *brokenFile to the broken file name,
 * otherwise set it to NULL. Caller MUST free *brokenFile after use.
 * Return 0 on success (including when brokenFile is set), negative on
 * error (allocation failure).
 */
int
virStorageFileChainGetBroken(virStorageSourcePtr chain,
                             char **brokenFile)
{
    virStorageSourcePtr tmp;

    *brokenFile = NULL;

    if (!chain)
        return 0;

    for (tmp = chain; virStorageSourceIsBacking(tmp); tmp = tmp->backingStore) {
        /* Break when we hit end of chain; report error if we detected
         * a missing backing file, infinite loop, or other error */
        if (!tmp->backingStore && tmp->backingStoreRaw) {
            if (VIR_STRDUP(*brokenFile, tmp->backingStoreRaw) < 0)
                return -1;

           return 0;
        }
    }

    return 0;
}


/**
 * virStorageFileResize:
 *
 * Change the capacity of the raw storage file at 'path'.
 */
int
virStorageFileResize(const char *path,
                     unsigned long long capacity,
                     bool pre_allocate)
{
    int rc;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(path, O_RDWR)) < 0) {
        virReportSystemError(errno, _("Unable to open '%s'"), path);
        return -1;
    }

    if (pre_allocate) {
        if ((rc = virFileAllocate(fd, 0, capacity)) != 0) {
            if (rc == -2) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("preallocate is not supported on this platform"));
            } else {
                virReportSystemError(errno,
                                     _("Failed to pre-allocate space for "
                                       "file '%s'"), path);
            }
            return -1;
        }
    }

    if (ftruncate(fd, capacity) < 0) {
        virReportSystemError(errno,
                             _("Failed to truncate file '%s'"), path);
        return -1;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Unable to save '%s'"), path);
        return -1;
    }

    return 0;
}


int virStorageFileIsClusterFS(const char *path)
{
    /* These are coherent cluster filesystems known to be safe for
     * migration with cache != none
     */
    return virFileIsSharedFSType(path,
                                 VIR_FILE_SHFS_GFS2 |
                                 VIR_FILE_SHFS_OCFS |
                                 VIR_FILE_SHFS_CEPH);
}

#ifdef LVS
int virStorageFileGetLVMKey(const char *path,
                            char **key)
{
    /*
     *  # lvs --noheadings --unbuffered --nosuffix --options "uuid" LVNAME
     *    06UgP5-2rhb-w3Bo-3mdR-WeoL-pytO-SAa2ky
     */
    int status;
    int ret = -1;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(LVS, "--noheadings",
                               "--unbuffered", "--nosuffix",
                               "--options", "uuid", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, key);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */

    if (status == 0 && *key) {
        char *nl;
        char *tmp = *key;

        /* Find first non-space character */
        while (*tmp && c_isspace(*tmp))
            tmp++;
        /* Kill leading spaces */
        if (tmp != *key)
            memmove(*key, tmp, strlen(tmp)+1);

        /* Kill trailing newline */
        if ((nl = strchr(*key, '\n')))
            *nl = '\0';
    }

    ret = 0;

 cleanup:
    if (*key && STREQ(*key, ""))
        VIR_FREE(*key);

    return ret;
}
#else
int virStorageFileGetLVMKey(const char *path,
                            char **key ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, _("Unable to get LVM key for %s"), path);
    return -1;
}
#endif

#ifdef WITH_UDEV
/* virStorageFileGetSCSIKey
 * @path: Path to the SCSI device
 * @key: Unique key to be returned
 * @ignoreError: Used to not report ENOSYS
 *
 * Using a udev specific function, query the @path to get and return a
 * unique @key for the caller to use.
 *
 * Returns:
 *     0 On success, with the @key filled in or @key=NULL if the
 *       returned string was empty.
 *    -1 When WITH_UDEV is undefined and a system error is reported
 *    -2 When WITH_UDEV is defined, but calling virCommandRun fails
 */
int
virStorageFileGetSCSIKey(const char *path,
                         char **key,
                         bool ignoreError ATTRIBUTE_UNUSED)
{
    int status;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virCommandNewArgList("/lib/udev/scsi_id",
                               "--replace-whitespace",
                               "--whitelisted",
                               "--device", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, key);
    if (virCommandRun(cmd, &status) < 0)
        return -2;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */
    if (status == 0 && *key) {
        char *nl = strchr(*key, '\n');
        if (nl)
            *nl = '\0';
    }

    if (*key && STREQ(*key, ""))
        VIR_FREE(*key);

    return 0;
}
#else
int virStorageFileGetSCSIKey(const char *path,
                             char **key ATTRIBUTE_UNUSED,
                             bool ignoreError)
{
    if (!ignoreError)
        virReportSystemError(ENOSYS, _("Unable to get SCSI key for %s"), path);
    return -1;
}
#endif


#ifdef WITH_UDEV
/* virStorageFileGetNPIVKey
 * @path: Path to the NPIV device
 * @key: Unique key to be returned
 *
 * Using a udev specific function, query the @path to get and return a
 * unique @key for the caller to use. Unlike the GetSCSIKey method, an
 * NPIV LUN is uniquely identified by its ID_TARGET_PORT value.
 *
 * Returns:
 *     0 On success, with the @key filled in or @key=NULL if the
 *       returned output string didn't have the data we need to
 *       formulate a unique key value
 *    -1 When WITH_UDEV is undefined and a system error is reported
 *    -2 When WITH_UDEV is defined, but calling virCommandRun fails
 */
# define ID_SERIAL "ID_SERIAL="
# define ID_TARGET_PORT "ID_TARGET_PORT="
int
virStorageFileGetNPIVKey(const char *path,
                         char **key)
{
    int status;
    const char *serial;
    const char *port;
    VIR_AUTOFREE(char *) outbuf = NULL;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virCommandNewArgList("/lib/udev/scsi_id",
                               "--replace-whitespace",
                               "--whitelisted",
                               "--export",
                               "--device", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, &status) < 0)
        return -2;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */
    if (status == 0 && *outbuf &&
        (serial = strstr(outbuf, ID_SERIAL)) &&
        (port = strstr(outbuf, ID_TARGET_PORT))) {
        char *tmp;

        serial += strlen(ID_SERIAL);
        port += strlen(ID_TARGET_PORT);

        if ((tmp = strchr(serial, '\n')))
            *tmp = '\0';

        if ((tmp = strchr(port, '\n')))
            *tmp = '\0';

        if (*serial != '\0' && *port != '\0')
            ignore_value(virAsprintf(key, "%s_PORT%s", serial, port));
    }

    return 0;
}
#else
int virStorageFileGetNPIVKey(const char *path ATTRIBUTE_UNUSED,
                             char **key ATTRIBUTE_UNUSED)
{
    return -1;
}
#endif

/**
 * virStorageFileParseBackingStoreStr:
 * @str: backing store specifier string to parse
 * @target: returns target device portion of the string
 * @chainIndex: returns the backing store portion of the string
 *
 * Parses the backing store specifier string such as vda[1], or sda into
 * components and returns them via arguments. If the string did not specify an
 * index, 0 is assumed.
 *
 * Returns 0 on success -1 on error
 */
int
virStorageFileParseBackingStoreStr(const char *str,
                                   char **target,
                                   unsigned int *chainIndex)
{
    size_t nstrings;
    unsigned int idx = 0;
    char *suffix;
    VIR_AUTOSTRINGLIST strings = NULL;

    *chainIndex = 0;

    if (!(strings = virStringSplitCount(str, "[", 2, &nstrings)))
        return -1;

    if (nstrings == 2) {
        if (virStrToLong_uip(strings[1], &suffix, 10, &idx) < 0 ||
            STRNEQ(suffix, "]"))
            return -1;
    }

    if (target &&
        VIR_STRDUP(*target, strings[0]) < 0)
        return -1;

    *chainIndex = idx;
    return 0;
}


int
virStorageFileParseChainIndex(const char *diskTarget,
                              const char *name,
                              unsigned int *chainIndex)
{
    unsigned int idx = 0;
    VIR_AUTOFREE(char *) target = NULL;

    *chainIndex = 0;

    if (!name || !diskTarget)
        return 0;

    if (virStorageFileParseBackingStoreStr(name, &target, &idx) < 0)
        return 0;

    if (idx == 0)
        return 0;

    if (STRNEQ(diskTarget, target)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested target '%s' does not match target '%s'"),
                       target, diskTarget);
        return -1;
    }

    *chainIndex = idx;

    return 0;
}


/**
 * virStorageSourceIsBacking:
 * @src: storage source
 *
 * Returns true if @src is a eligible backing store structure. Useful
 * for iterators.
 */
bool
virStorageSourceIsBacking(const virStorageSource *src)
{
    return src && src->type != VIR_STORAGE_TYPE_NONE;
}

/**
 * virStorageSourceHasBacking:
 * @src: storage source
 *
 * Returns true if @src has backing store/chain.
 */
bool
virStorageSourceHasBacking(const virStorageSource *src)
{
    return virStorageSourceIsBacking(src) && src->backingStore &&
           src->backingStore->type != VIR_STORAGE_TYPE_NONE;
}


/* Given a @chain, look for the backing store @name that is a backing file
 * of @startFrom (or any member of @chain if @startFrom is NULL) and return
 * that location within the chain.  @chain must always point to the top of
 * the chain.  Pass NULL for @name and 0 for @idx to find the base of the
 * chain.  Pass nonzero @idx to find the backing source according to its
 * position in the backing chain.  If @parent is not NULL, set *@parent to
 * the preferred name of the parent (or to NULL if @name matches the start
 * of the chain).  Since the results point within @chain, they must not be
 * independently freed. Reports an error and returns NULL if @name is not
 * found.
 */
virStorageSourcePtr
virStorageFileChainLookup(virStorageSourcePtr chain,
                          virStorageSourcePtr startFrom,
                          const char *name,
                          unsigned int idx,
                          virStorageSourcePtr *parent)
{
    virStorageSourcePtr prev;
    const char *start = chain->path;
    char *parentDir = NULL;
    bool nameIsFile = virStorageIsFile(name);

    if (!parent)
        parent = &prev;
    *parent = NULL;

    if (startFrom) {
        while (virStorageSourceIsBacking(chain) &&
               chain != startFrom->backingStore)
            chain = chain->backingStore;

        *parent = startFrom;
    }

    while (virStorageSourceIsBacking(chain)) {
        if (!name && !idx) {
            if (!virStorageSourceHasBacking(chain))
                break;
        } else if (idx) {
            VIR_DEBUG("%u: %s", chain->id, chain->path);
            if (idx == chain->id)
                break;
        } else {
            if (STREQ_NULLABLE(name, chain->relPath) ||
                STREQ_NULLABLE(name, chain->path))
                break;

            if (nameIsFile && virStorageSourceIsLocalStorage(chain)) {
                if (*parent && virStorageSourceIsLocalStorage(*parent))
                    parentDir = mdir_name((*parent)->path);
                else
                    ignore_value(VIR_STRDUP_QUIET(parentDir, "."));

                if (!parentDir) {
                    virReportOOMError();
                    goto error;
                }

                int result = virFileRelLinkPointsTo(parentDir, name,
                                                    chain->path);

                VIR_FREE(parentDir);

                if (result < 0)
                    goto error;

                if (result > 0)
                    break;
            }
        }
        *parent = chain;
        chain = chain->backingStore;
    }

    if (!virStorageSourceIsBacking(chain))
        goto error;

    return chain;

 error:
    if (idx) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find backing store index %u in chain "
                         "for '%s'"),
                       idx, NULLSTR(start));
    } else if (name) {
        if (startFrom)
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%s' beneath '%s' in "
                             "chain for '%s'"), name, NULLSTR(startFrom->path),
                           NULLSTR(start));
        else
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%s' in chain for '%s'"),
                           name, NULLSTR(start));
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find base image in chain for '%s'"),
                       NULLSTR(start));
    }
    *parent = NULL;
    return NULL;
}


void
virStorageNetHostDefClear(virStorageNetHostDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->socket);
}


void
virStorageNetHostDefFree(size_t nhosts,
                         virStorageNetHostDefPtr hosts)
{
    size_t i;

    if (!hosts)
        return;

    for (i = 0; i < nhosts; i++)
        virStorageNetHostDefClear(&hosts[i]);

    VIR_FREE(hosts);
}


static void
virStoragePermsFree(virStoragePermsPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->label);
    VIR_FREE(def);
}


virStorageNetHostDefPtr
virStorageNetHostDefCopy(size_t nhosts,
                         virStorageNetHostDefPtr hosts)
{
    virStorageNetHostDefPtr ret = NULL;
    size_t i;

    if (VIR_ALLOC_N(ret, nhosts) < 0)
        goto error;

    for (i = 0; i < nhosts; i++) {
        virStorageNetHostDefPtr src = &hosts[i];
        virStorageNetHostDefPtr dst = &ret[i];

        dst->transport = src->transport;
        dst->port = src->port;

        if (VIR_STRDUP(dst->name, src->name) < 0)
            goto error;

        if (VIR_STRDUP(dst->socket, src->socket) < 0)
            goto error;
    }

    return ret;

 error:
    virStorageNetHostDefFree(nhosts, ret);
    return NULL;
}


void
virStorageAuthDefFree(virStorageAuthDefPtr authdef)
{
    if (!authdef)
        return;

    VIR_FREE(authdef->username);
    VIR_FREE(authdef->secrettype);
    virSecretLookupDefClear(&authdef->seclookupdef);
    VIR_FREE(authdef);
}


virStorageAuthDefPtr
virStorageAuthDefCopy(const virStorageAuthDef *src)
{
    virStorageAuthDefPtr ret = NULL;
    VIR_AUTOPTR(virStorageAuthDef) authdef = NULL;

    if (VIR_ALLOC(authdef) < 0)
        return NULL;

    if (VIR_STRDUP(authdef->username, src->username) < 0)
        return NULL;
    /* Not present for storage pool, but used for disk source */
    if (VIR_STRDUP(authdef->secrettype, src->secrettype) < 0)
        return NULL;
    authdef->authType = src->authType;

    if (virSecretLookupDefCopy(&authdef->seclookupdef, &src->seclookupdef) < 0)
        return NULL;

    VIR_STEAL_PTR(ret, authdef);
    return ret;
}


virStorageAuthDefPtr
virStorageAuthDefParse(xmlNodePtr node,
                       xmlXPathContextPtr ctxt)
{
    xmlNodePtr saveNode = ctxt->node;
    virStorageAuthDefPtr ret = NULL;
    xmlNodePtr secretnode = NULL;
    VIR_AUTOPTR(virStorageAuthDef) authdef = NULL;
    VIR_AUTOFREE(char *) authtype = NULL;

    ctxt->node = node;

    if (VIR_ALLOC(authdef) < 0)
        goto cleanup;

    if (!(authdef->username = virXPathString("string(./@username)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing username for auth"));
        goto cleanup;
    }

    authdef->authType = VIR_STORAGE_AUTH_TYPE_NONE;
    authtype = virXPathString("string(./@type)", ctxt);
    if (authtype) {
        /* Used by the storage pool instead of the secret type field
         * to define whether chap or ceph being used
         */
        if ((authdef->authType = virStorageAuthTypeFromString(authtype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown auth type '%s'"), authtype);
            goto cleanup;
        }
    }

    if (!(secretnode = virXPathNode("./secret ", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <secret> element in auth"));
        goto cleanup;
    }

    /* Used by the domain disk xml parsing in order to ensure the
     * <secret type='%s' value matches the expected secret type for
     * the style of disk (iscsi is chap, nbd is ceph). For some reason
     * the virSecretUsageType{From|To}String() cannot be linked here
     * and because only the domain parsing code cares - just keep
     * it as a string.
     */
    authdef->secrettype = virXMLPropString(secretnode, "type");

    if (virSecretLookupParseSecret(secretnode, &authdef->seclookupdef) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, authdef);

 cleanup:
    ctxt->node = saveNode;

    return ret;
}


void
virStorageAuthDefFormat(virBufferPtr buf,
                        virStorageAuthDefPtr authdef)
{
    if (authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE) {
        virBufferEscapeString(buf, "<auth username='%s'>\n", authdef->username);
    } else {
        virBufferAsprintf(buf, "<auth type='%s' ",
                          virStorageAuthTypeToString(authdef->authType));
        virBufferEscapeString(buf, "username='%s'>\n", authdef->username);
    }

    virBufferAdjustIndent(buf, 2);
    virSecretLookupFormatSecret(buf, authdef->secrettype,
                                &authdef->seclookupdef);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</auth>\n");
}


void
virStoragePRDefFree(virStoragePRDefPtr prd)
{
    if (!prd)
        return;

    VIR_FREE(prd->path);
    VIR_FREE(prd->mgralias);
    VIR_FREE(prd);
}


virStoragePRDefPtr
virStoragePRDefParseXML(xmlXPathContextPtr ctxt)
{
    virStoragePRDefPtr prd;
    virStoragePRDefPtr ret = NULL;
    VIR_AUTOFREE(char *) managed = NULL;
    VIR_AUTOFREE(char *) type = NULL;
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) mode = NULL;

    if (VIR_ALLOC(prd) < 0)
        return NULL;

    if (!(managed = virXPathString("string(./@managed)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing @managed attribute for <reservations/>"));
        goto cleanup;
    }

    if ((prd->managed = virTristateBoolTypeFromString(managed)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid value for 'managed': %s"), managed);
        goto cleanup;
    }

    type = virXPathString("string(./source[1]/@type)", ctxt);
    path = virXPathString("string(./source[1]/@path)", ctxt);
    mode = virXPathString("string(./source[1]/@mode)", ctxt);

    if (prd->managed == VIR_TRISTATE_BOOL_NO || type || path || mode) {
        if (!type) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing connection type for <reservations/>"));
            goto cleanup;
        }

        if (!path) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing path for <reservations/>"));
            goto cleanup;
        }

        if (!mode) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing connection mode for <reservations/>"));
            goto cleanup;
        }
    }

    if (type && STRNEQ(type, "unix")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported connection type for <reservations/>: %s"),
                       type);
        goto cleanup;
    }

    if (mode && STRNEQ(mode, "client")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported connection mode for <reservations/>: %s"),
                       mode);
        goto cleanup;
    }

    VIR_STEAL_PTR(prd->path, path);
    VIR_STEAL_PTR(ret, prd);

 cleanup:
    virStoragePRDefFree(prd);
    return ret;
}


void
virStoragePRDefFormat(virBufferPtr buf,
                      virStoragePRDefPtr prd,
                      bool migratable)
{
    virBufferAsprintf(buf, "<reservations managed='%s'",
                      virTristateBoolTypeToString(prd->managed));
    if (prd->path &&
        (prd->managed == VIR_TRISTATE_BOOL_NO || !migratable)) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAddLit(buf, "<source type='unix'");
        virBufferEscapeString(buf, " path='%s'", prd->path);
        virBufferAddLit(buf, " mode='client'/>\n");
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</reservations>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


bool
virStoragePRDefIsEqual(virStoragePRDefPtr a,
                       virStoragePRDefPtr b)
{
    if (!a && !b)
        return true;

    if (!a || !b)
        return false;

    if (a->managed != b->managed ||
        STRNEQ_NULLABLE(a->path, b->path))
        return false;

    return true;
}


bool
virStoragePRDefIsManaged(virStoragePRDefPtr prd)
{
    return prd && prd->managed == VIR_TRISTATE_BOOL_YES;
}


bool
virStorageSourceChainHasManagedPR(virStorageSourcePtr src)
{
    virStorageSourcePtr n;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (virStoragePRDefIsManaged(n->pr))
            return true;
    }

    return false;
}


static virStoragePRDefPtr
virStoragePRDefCopy(virStoragePRDefPtr src)
{
    virStoragePRDefPtr copy = NULL;
    virStoragePRDefPtr ret = NULL;

    if (VIR_ALLOC(copy) < 0)
        return NULL;

    copy->managed = src->managed;

    if (VIR_STRDUP(copy->path, src->path) < 0 ||
        VIR_STRDUP(copy->mgralias, src->mgralias) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, copy);

 cleanup:
    virStoragePRDefFree(copy);
    return ret;
}


virSecurityDeviceLabelDefPtr
virStorageSourceGetSecurityLabelDef(virStorageSourcePtr src,
                                    const char *model)
{
    size_t i;

    for (i = 0; i < src->nseclabels; i++) {
        if (STREQ_NULLABLE(src->seclabels[i]->model, model))
            return src->seclabels[i];
    }

    return NULL;
}


static void
virStorageSourceSeclabelsClear(virStorageSourcePtr def)
{
    size_t i;

    if (def->seclabels) {
        for (i = 0; i < def->nseclabels; i++)
            virSecurityDeviceLabelDefFree(def->seclabels[i]);
        VIR_FREE(def->seclabels);
    }
}


static int
virStorageSourceSeclabelsCopy(virStorageSourcePtr to,
                              const virStorageSource *from)
{
    size_t i;

    if (from->nseclabels == 0)
        return 0;

    if (VIR_ALLOC_N(to->seclabels, from->nseclabels) < 0)
        return -1;
    to->nseclabels = from->nseclabels;

    for (i = 0; i < to->nseclabels; i++) {
        if (!(to->seclabels[i] = virSecurityDeviceLabelDefCopy(from->seclabels[i])))
            goto error;
    }

    return 0;

 error:
    virStorageSourceSeclabelsClear(to);
    return -1;
}


static virStorageTimestampsPtr
virStorageTimestampsCopy(const virStorageTimestamps *src)
{
    virStorageTimestampsPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    memcpy(ret, src, sizeof(*src));

    return ret;
}


static virStoragePermsPtr
virStoragePermsCopy(const virStoragePerms *src)
{
    virStoragePermsPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->mode = src->mode;
    ret->uid = src->uid;
    ret->gid = src->gid;

    if (VIR_STRDUP(ret->label, src->label) < 0)
        goto error;

    return ret;

 error:
    virStoragePermsFree(ret);
    return NULL;
}


static virStorageSourcePoolDefPtr
virStorageSourcePoolDefCopy(const virStorageSourcePoolDef *src)
{
    virStorageSourcePoolDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->voltype = src->voltype;
    ret->pooltype = src->pooltype;
    ret->actualtype = src->actualtype;
    ret->mode = src->mode;

    if (VIR_STRDUP(ret->pool, src->pool) < 0 ||
        VIR_STRDUP(ret->volume, src->volume) < 0)
        goto error;

    return ret;

 error:
    virStorageSourcePoolDefFree(ret);
    return NULL;
}


/**
 * virStorageSourcePtr:
 *
 * Deep-copies a virStorageSource structure. If @backing chain is true
 * then also copies the backing chain recursively, otherwise just
 * the top element is copied. This function doesn't copy the
 * storage driver access structure and thus the struct needs to be initialized
 * separately.
 */
virStorageSourcePtr
virStorageSourceCopy(const virStorageSource *src,
                     bool backingChain)
{
    virStorageSourcePtr ret = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) def = NULL;

    if (!(def = virStorageSourceNew()))
        return NULL;

    def->id = src->id;
    def->type = src->type;
    def->protocol = src->protocol;
    def->format = src->format;
    def->capacity = src->capacity;
    def->allocation = src->allocation;
    def->has_allocation = src->has_allocation;
    def->physical = src->physical;
    def->readonly = src->readonly;
    def->shared = src->shared;
    def->haveTLS = src->haveTLS;
    def->tlsFromConfig = src->tlsFromConfig;
    def->detected = src->detected;
    def->debugLevel = src->debugLevel;
    def->debug = src->debug;
    def->iomode = src->iomode;
    def->cachemode = src->cachemode;
    def->discard = src->discard;
    def->detect_zeroes = src->detect_zeroes;

    /* storage driver metadata are not copied */
    def->drv = NULL;

    if (VIR_STRDUP(def->path, src->path) < 0 ||
        VIR_STRDUP(def->volume, src->volume) < 0 ||
        VIR_STRDUP(def->relPath, src->relPath) < 0 ||
        VIR_STRDUP(def->backingStoreRaw, src->backingStoreRaw) < 0 ||
        VIR_STRDUP(def->snapshot, src->snapshot) < 0 ||
        VIR_STRDUP(def->configFile, src->configFile) < 0 ||
        VIR_STRDUP(def->nodeformat, src->nodeformat) < 0 ||
        VIR_STRDUP(def->nodestorage, src->nodestorage) < 0 ||
        VIR_STRDUP(def->compat, src->compat) < 0 ||
        VIR_STRDUP(def->tlsAlias, src->tlsAlias) < 0 ||
        VIR_STRDUP(def->tlsCertdir, src->tlsCertdir) < 0)
        return NULL;

    if (src->nhosts) {
        if (!(def->hosts = virStorageNetHostDefCopy(src->nhosts, src->hosts)))
            return NULL;

        def->nhosts = src->nhosts;
    }

    if (src->srcpool &&
        !(def->srcpool = virStorageSourcePoolDefCopy(src->srcpool)))
        return NULL;

    if (src->features &&
        !(def->features = virBitmapNewCopy(src->features)))
        return NULL;

    if (src->encryption &&
        !(def->encryption = virStorageEncryptionCopy(src->encryption)))
        return NULL;

    if (src->perms &&
        !(def->perms = virStoragePermsCopy(src->perms)))
        return NULL;

    if (src->timestamps &&
        !(def->timestamps = virStorageTimestampsCopy(src->timestamps)))
        return NULL;

    if (virStorageSourceSeclabelsCopy(def, src) < 0)
        return NULL;

    if (src->auth &&
        !(def->auth = virStorageAuthDefCopy(src->auth)))
        return NULL;

    if (src->pr &&
        !(def->pr = virStoragePRDefCopy(src->pr)))
        return NULL;

    if (virStorageSourceInitiatorCopy(&def->initiator, &src->initiator))
        return NULL;

    if (backingChain && src->backingStore) {
        if (!(def->backingStore = virStorageSourceCopy(src->backingStore,
                                                       true)))
            return NULL;
    }

    VIR_STEAL_PTR(ret, def);
    return ret;
}


/**
 * virStorageSourceIsSameLocation:
 *
 * Returns true if the sources @a and @b point to the same storage location.
 * This does not compare any other configuration option
 */
bool
virStorageSourceIsSameLocation(virStorageSourcePtr a,
                               virStorageSourcePtr b)
{
    size_t i;

    /* there are multiple possibilities to define an empty source */
    if (virStorageSourceIsEmpty(a) &&
        virStorageSourceIsEmpty(b))
        return true;

    if (virStorageSourceGetActualType(a) != virStorageSourceGetActualType(b))
        return false;

    if (STRNEQ_NULLABLE(a->path, b->path) ||
        STRNEQ_NULLABLE(a->volume, b->volume) ||
        STRNEQ_NULLABLE(a->snapshot, b->snapshot))
        return false;

    if (a->type == VIR_STORAGE_TYPE_NETWORK) {
        if (a->protocol != b->protocol ||
            a->nhosts != b->nhosts)
            return false;

        for (i = 0; i < a->nhosts; i++) {
            if (a->hosts[i].transport != b->hosts[i].transport ||
                a->hosts[i].port != b->hosts[i].port ||
                STRNEQ_NULLABLE(a->hosts[i].name, b->hosts[i].name) ||
                STRNEQ_NULLABLE(a->hosts[i].socket, b->hosts[i].socket))
                return false;
        }
    }

    return true;
}


/**
 * virStorageSourceInitChainElement:
 * @newelem: New backing chain element disk source
 * @old: Existing top level disk source
 * @transferLabels: Transfer security labels.
 *
 * Transfers relevant information from the existing disk source to the new
 * backing chain element if they weren't supplied so that labelling info
 * and possibly other stuff is correct.
 *
 * If @transferLabels is true, security labels from the existing disk are copied
 * to the new disk. Otherwise the default domain imagelabel label will be used.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceInitChainElement(virStorageSourcePtr newelem,
                                 virStorageSourcePtr old,
                                 bool transferLabels)
{
    int ret = -1;

    if (transferLabels &&
        !newelem->seclabels &&
        virStorageSourceSeclabelsCopy(newelem, old) < 0)
        goto cleanup;

    newelem->shared = old->shared;
    newelem->readonly = old->readonly;

    ret = 0;

 cleanup:
    return ret;
}


void
virStorageSourcePoolDefFree(virStorageSourcePoolDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->pool);
    VIR_FREE(def->volume);

    VIR_FREE(def);
}


/**
 * virStorageSourceGetActualType:
 * @def: storage source definition
 *
 * Returns type of @def. In case when the type is VIR_STORAGE_TYPE_VOLUME
 * and virDomainDiskTranslateSourcePool was called on @def the actual type
 * of the storage volume is returned rather than VIR_STORAGE_TYPE_VOLUME.
 */
int
virStorageSourceGetActualType(const virStorageSource *def)
{
    if (def->type == VIR_STORAGE_TYPE_VOLUME &&
        def->srcpool &&
        def->srcpool->actualtype != VIR_STORAGE_TYPE_NONE)
        return def->srcpool->actualtype;

    return def->type;
}


bool
virStorageSourceIsLocalStorage(const virStorageSource *src)
{
    virStorageType type = virStorageSourceGetActualType(src);

    switch (type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
        return true;

    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_LAST:
    case VIR_STORAGE_TYPE_NONE:
        return false;
    }

    return false;
}


/**
 * virStorageSourceIsEmpty:
 *
 * @src: disk source to check
 *
 * Returns true if the guest disk has no associated host storage source
 * (such as an empty cdrom drive).
 */
bool
virStorageSourceIsEmpty(virStorageSourcePtr src)
{
    if (virStorageSourceIsLocalStorage(src) && !src->path)
        return true;

    if (src->type == VIR_STORAGE_TYPE_NONE)
        return true;

    if (src->type == VIR_STORAGE_TYPE_NETWORK &&
        src->protocol == VIR_STORAGE_NET_PROTOCOL_NONE)
        return true;

    return false;
}


/**
 * virStorageSourceIsBlockLocal:
 * @src: disk source definition
 *
 * Returns true if @src describes a locally accessible block storage source.
 * This includes block devices and host-mapped iSCSI volumes.
 */
bool
virStorageSourceIsBlockLocal(const virStorageSource *src)
{
    return virStorageSourceGetActualType(src) == VIR_STORAGE_TYPE_BLOCK;
}


/**
 * virStorageSourceBackingStoreClear:
 *
 * @src: disk source to clear
 *
 * Clears information about backing store of the current storage file.
 */
void
virStorageSourceBackingStoreClear(virStorageSourcePtr def)
{
    if (!def)
        return;

    VIR_FREE(def->relPath);
    VIR_FREE(def->backingStoreRaw);

    /* recursively free backing chain */
    virObjectUnref(def->backingStore);
    def->backingStore = NULL;
}


void
virStorageSourceClear(virStorageSourcePtr def)
{
    if (!def)
        return;

    VIR_FREE(def->path);
    VIR_FREE(def->volume);
    VIR_FREE(def->snapshot);
    VIR_FREE(def->configFile);
    virStorageSourcePoolDefFree(def->srcpool);
    virBitmapFree(def->features);
    VIR_FREE(def->compat);
    virStorageEncryptionFree(def->encryption);
    virStoragePRDefFree(def->pr);
    virStorageSourceSeclabelsClear(def);
    virStoragePermsFree(def->perms);
    VIR_FREE(def->timestamps);

    virStorageNetHostDefFree(def->nhosts, def->hosts);
    virStorageAuthDefFree(def->auth);
    virObjectUnref(def->privateData);

    VIR_FREE(def->nodestorage);
    VIR_FREE(def->nodeformat);

    virStorageSourceBackingStoreClear(def);

    VIR_FREE(def->tlsAlias);
    VIR_FREE(def->tlsCertdir);

    virStorageSourceInitiatorClear(&def->initiator);

    /* clear everything except the class header as the object APIs
     * will break otherwise */
    memset((char *) def + sizeof(def->parent), 0,
           sizeof(*def) - sizeof(def->parent));
}


static void
virStorageSourceDispose(void *obj)
{
    virStorageSourcePtr src = obj;

    virStorageSourceClear(src);
}


static int
virStorageSourceOnceInit(void)
{
    if (!VIR_CLASS_NEW(virStorageSource, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virStorageSource);


virStorageSourcePtr
virStorageSourceNew(void)
{
    if (virStorageSourceInitialize() < 0)
        return NULL;

    return virObjectNew(virStorageSourceClass);
}


static virStorageSourcePtr
virStorageSourceNewFromBackingRelative(virStorageSourcePtr parent,
                                       const char *rel)
{
    virStorageSourcePtr ret = NULL;
    VIR_AUTOFREE(char *) dirname = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) def = NULL;

    if (!(def = virStorageSourceNew()))
        return NULL;

    /* store relative name */
    if (VIR_STRDUP(def->relPath, parent->backingStoreRaw) < 0)
        return NULL;

    if (!(dirname = mdir_name(parent->path))) {
        virReportOOMError();
        return NULL;
    }

    if (STRNEQ(dirname, "/")) {
        if (virAsprintf(&def->path, "%s/%s", dirname, rel) < 0)
            return NULL;
    } else {
        if (virAsprintf(&def->path, "/%s", rel) < 0)
            return NULL;
    }

    if (virStorageSourceGetActualType(parent) == VIR_STORAGE_TYPE_NETWORK) {
        def->type = VIR_STORAGE_TYPE_NETWORK;

        /* copy the host network part */
        def->protocol = parent->protocol;
        if (parent->nhosts) {
            if (!(def->hosts = virStorageNetHostDefCopy(parent->nhosts,
                                                        parent->hosts)))
                return NULL;

            def->nhosts = parent->nhosts;
        }

        if (VIR_STRDUP(def->volume, parent->volume) < 0)
            return NULL;
    } else {
        /* set the type to _FILE, the caller shall update it to the actual type */
        def->type = VIR_STORAGE_TYPE_FILE;
    }

    VIR_STEAL_PTR(ret, def);
    return ret;
}


static int
virStorageSourceParseBackingURI(virStorageSourcePtr src,
                                const char *uristr)
{
    VIR_AUTOPTR(virURI) uri = NULL;
    const char *path = NULL;
    VIR_AUTOSTRINGLIST scheme = NULL;

    if (!(uri = virURIParse(uristr))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse backing file location '%s'"),
                       uristr);
        return -1;
    }

    if (VIR_ALLOC(src->hosts) < 0)
        return -1;

    src->nhosts = 1;

    if (!(scheme = virStringSplit(uri->scheme, "+", 2)))
        return -1;

    if (!scheme[0] ||
        (src->protocol = virStorageNetProtocolTypeFromString(scheme[0])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
                       NULLSTR(scheme[0]));
        return -1;
    }

    if (scheme[1] &&
        (src->hosts->transport = virStorageNetHostTransportTypeFromString(scheme[1])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid protocol transport type '%s'"),
                       scheme[1]);
        return -1;
    }

    /* handle socket stored as a query */
    if (uri->query) {
        if (VIR_STRDUP(src->hosts->socket, STRSKIP(uri->query, "socket=")) < 0)
            return -1;
    }

    /* uri->path is NULL if the URI does not contain slash after host:
     * transport://host:port */
    if (uri->path)
        path = uri->path;
    else
        path = "";

    /* possibly skip the leading slash  */
    if (path[0] == '/')
        path++;

    /* NBD allows empty export name (path) */
    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_NBD &&
        path[0] == '\0')
        path = NULL;

    if (VIR_STRDUP(src->path, path) < 0)
        return -1;

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_GLUSTER) {
        char *tmp;

        if (!src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("missing volume name and path for gluster volume"));
            return -1;
        }

        if (!(tmp = strchr(src->path, '/')) ||
            tmp == src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("missing volume name or file name in "
                             "gluster source path '%s'"), src->path);
            return -1;
        }

        src->volume = src->path;

        if (VIR_STRDUP(src->path, tmp + 1) < 0)
            return -1;

        tmp[0] = '\0';
    }

    src->hosts->port = uri->port;

    if (VIR_STRDUP(src->hosts->name, uri->server) < 0)
        return -1;

    /* Libvirt doesn't handle inline authentication. Make the caller aware. */
    if (uri->user)
        return 1;

    return 0;
}


static int
virStorageSourceRBDAddHost(virStorageSourcePtr src,
                           char *hostport)
{
    char *port;
    size_t skip;
    VIR_AUTOSTRINGLIST parts = NULL;

    if (VIR_EXPAND_N(src->hosts, src->nhosts, 1) < 0)
        return -1;

    if ((port = strchr(hostport, ']'))) {
        /* ipv6, strip brackets */
        hostport += 1;
        skip = 3;
    } else {
        port = strstr(hostport, "\\:");
        skip = 2;
    }

    if (port) {
        *port = '\0';
        port += skip;
        if (virStringParsePort(port, &src->hosts[src->nhosts - 1].port) < 0)
            goto error;
    }

    parts = virStringSplit(hostport, "\\:", 0);
    if (!parts)
        goto error;
    src->hosts[src->nhosts-1].name = virStringListJoin((const char **)parts, ":");
    if (!src->hosts[src->nhosts-1].name)
        goto error;

    src->hosts[src->nhosts-1].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    src->hosts[src->nhosts-1].socket = NULL;

    return 0;

 error:
    VIR_FREE(src->hosts[src->nhosts-1].name);
    return -1;
}


int
virStorageSourceParseRBDColonString(const char *rbdstr,
                                    virStorageSourcePtr src)
{
    char *p, *e, *next;
    VIR_AUTOFREE(char *) options = NULL;
    VIR_AUTOPTR(virStorageAuthDef) authdef = NULL;

    /* optionally skip the "rbd:" prefix if provided */
    if (STRPREFIX(rbdstr, "rbd:"))
        rbdstr += strlen("rbd:");

    if (VIR_STRDUP(src->path, rbdstr) < 0)
        return -1;

    p = strchr(src->path, ':');
    if (p) {
        if (VIR_STRDUP(options, p + 1) < 0)
            return -1;
        *p = '\0';
    }

    /* snapshot name */
    if ((p = strchr(src->path, '@'))) {
        if (VIR_STRDUP(src->snapshot, p + 1) < 0)
            return -1;
        *p = '\0';
    }

    /* pool vs. image name */
    if ((p = strchr(src->path, '/'))) {
        VIR_STEAL_PTR(src->volume, src->path);
        if (VIR_STRDUP(src->path, p + 1) < 0)
            return -1;
        *p = '\0';
    }

    /* options */
    if (!options)
        return 0; /* all done */

    p = options;
    while (*p) {
        /* find : delimiter or end of string */
        for (e = p; *e && *e != ':'; ++e) {
            if (*e == '\\') {
                e++;
                if (*e == '\0')
                    break;
            }
        }
        if (*e == '\0') {
            next = e;    /* last kv pair */
        } else {
            next = e + 1;
            *e = '\0';
        }

        if (STRPREFIX(p, "id=")) {
            /* formulate authdef for src->auth */
            if (src->auth) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("duplicate 'id' found in '%s'"), src->path);
                return -1;
            }
            if (VIR_ALLOC(authdef) < 0)
                return -1;

            if (VIR_STRDUP(authdef->username, p + strlen("id=")) < 0)
                return -1;

            if (VIR_STRDUP(authdef->secrettype,
                           virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_CEPH)) < 0)
                return -1;
            VIR_STEAL_PTR(src->auth, authdef);
            src->authInherited = true;

            /* Cannot formulate a secretType (eg, usage or uuid) given
             * what is provided.
             */
        }
        if (STRPREFIX(p, "mon_host=")) {
            char *h, *sep;

            h = p + strlen("mon_host=");
            while (h < e) {
                for (sep = h; sep < e; ++sep) {
                    if (*sep == '\\' && (sep[1] == ',' ||
                                         sep[1] == ';' ||
                                         sep[1] == ' ')) {
                        *sep = '\0';
                        sep += 2;
                        break;
                    }
                }

                if (virStorageSourceRBDAddHost(src, h) < 0)
                    return -1;

                h = sep;
            }
        }

        if (STRPREFIX(p, "conf=") &&
            VIR_STRDUP(src->configFile, p + strlen("conf=")) < 0)
            return -1;

        p = next;
    }
    return 0;
}


static int
virStorageSourceParseNBDColonString(const char *nbdstr,
                                    virStorageSourcePtr src)
{
    VIR_AUTOSTRINGLIST backing = NULL;
    const char *exportname;

    if (!(backing = virStringSplit(nbdstr, ":", 0)))
        return -1;

    /* we know that backing[0] now equals to "nbd" */

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        return -1;

    src->nhosts = 1;
    src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

    /* format: [] denotes optional sections, uppercase are variable strings
     * nbd:unix:/PATH/TO/SOCKET[:exportname=EXPORTNAME]
     * nbd:HOSTNAME:PORT[:exportname=EXPORTNAME]
     */
    if (!backing[1]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing remote information in '%s' for protocol nbd"),
                       nbdstr);
        return -1;
    } else if (STREQ(backing[1], "unix")) {
        if (!backing[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing unix socket path in nbd backing string %s"),
                           nbdstr);
            return -1;
        }

        if (VIR_STRDUP(src->hosts->socket, backing[2]) < 0)
            return -1;

   } else {
        if (VIR_STRDUP(src->hosts->name, backing[1]) < 0)
            return -1;

        if (!backing[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing port in nbd string '%s'"),
                           nbdstr);
            return -1;
        }

        if (virStringParsePort(backing[2], &src->hosts->port) < 0)
            return -1;
    }

    if ((exportname = strstr(nbdstr, "exportname="))) {
        exportname += strlen("exportname=");
        if (VIR_STRDUP(src->path, exportname) < 0)
            return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingColon(virStorageSourcePtr src,
                                  const char *path)
{
    const char *p;
    VIR_AUTOFREE(char *) protocol = NULL;

    if (!(p = strchr(path, ':'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol string '%s'"),
                       path);
        return -1;
    }

    if (VIR_STRNDUP(protocol, path, p - path) < 0)
        return -1;

    if ((src->protocol = virStorageNetProtocolTypeFromString(protocol)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
                       protocol);
        return -1;
    }

    switch ((virStorageNetProtocol) src->protocol) {
    case VIR_STORAGE_NET_PROTOCOL_NBD:
        if (virStorageSourceParseNBDColonString(path, src) < 0)
            return -1;
        break;

    case VIR_STORAGE_NET_PROTOCOL_RBD:
        if (virStorageSourceParseRBDColonString(path, src) < 0)
            return -1;
        break;

    case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
    case VIR_STORAGE_NET_PROTOCOL_LAST:
    case VIR_STORAGE_NET_PROTOCOL_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store parser is not implemented for protocol %s"),
                       protocol);
        return -1;

    case VIR_STORAGE_NET_PROTOCOL_HTTP:
    case VIR_STORAGE_NET_PROTOCOL_HTTPS:
    case VIR_STORAGE_NET_PROTOCOL_FTP:
    case VIR_STORAGE_NET_PROTOCOL_FTPS:
    case VIR_STORAGE_NET_PROTOCOL_TFTP:
    case VIR_STORAGE_NET_PROTOCOL_ISCSI:
    case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
    case VIR_STORAGE_NET_PROTOCOL_SSH:
    case VIR_STORAGE_NET_PROTOCOL_VXHS:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed backing store path for protocol %s"),
                       protocol);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONInternal(virStorageSourcePtr src,
                                         virJSONValuePtr json);


static int
virStorageSourceParseBackingJSONPath(virStorageSourcePtr src,
                                     virJSONValuePtr json,
                                     int type)
{
    const char *path;

    if (!(path = virJSONValueObjectGetString(json, "filename"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'filename' field in JSON backing volume "
                         "definition"));
        return -1;
    }

    if (VIR_STRDUP(src->path, path) < 0)
        return -1;

    src->type = type;
    return 0;
}


static int
virStorageSourceParseBackingJSONUriStr(virStorageSourcePtr src,
                                       const char *uri,
                                       int protocol)
{
    int rc;

    if ((rc = virStorageSourceParseBackingURI(src, uri)) < 0)
        return -1;

    if (src->protocol != protocol) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("expected protocol '%s' but got '%s' in URI JSON volume "
                         "definition"),
                       virStorageNetProtocolTypeToString(protocol),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -1;
    }

    return rc;
}


static int
virStorageSourceParseBackingJSONUri(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    int protocol)
{
    const char *uri;

    if (!(uri = virJSONValueObjectGetString(json, "url"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'url' in JSON backing volume definition"));
        return -1;
    }

    return virStorageSourceParseBackingJSONUriStr(src, uri, protocol);
}


static int
virStorageSourceParseBackingJSONInetSocketAddress(virStorageNetHostDefPtr host,
                                                  virJSONValuePtr json)
{
    const char *hostname;
    const char *port;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON "
                         "backing volume definition"));
        return -1;
    }

    hostname = virJSONValueObjectGetString(json, "host");
    port = virJSONValueObjectGetString(json, "port");

    if (!hostname) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing hostname for tcp backing server in "
                         "JSON backing volume definition"));
        return -1;
    }

    host->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

    if (VIR_STRDUP(host->name, hostname) < 0 ||
        virStringParsePort(port, &host->port) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONSocketAddress(virStorageNetHostDefPtr host,
                                              virJSONValuePtr json)
{
    const char *type;
    const char *socket;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON "
                         "backing volume definition"));
        return -1;
    }

    if (!(type = virJSONValueObjectGetString(json, "type"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing socket address type in "
                         "JSON backing volume definition"));
        return -1;
    }

    if (STREQ(type, "tcp") || STREQ(type, "inet")) {
        return virStorageSourceParseBackingJSONInetSocketAddress(host, json);

    } else if (STREQ(type, "unix")) {
        host->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;

        socket = virJSONValueObjectGetString(json, "path");

        /* check for old spelling for gluster protocol */
        if (!socket)
            socket = virJSONValueObjectGetString(json, "socket");

        if (!socket) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("missing socket path for udp backing server in "
                             "JSON backing volume definition"));
            return -1;
        }

        if (VIR_STRDUP(host->socket, socket) < 0)
            return -1;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store protocol '%s' is not yet supported"),
                       type);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONGluster(virStorageSourcePtr src,
                                        virJSONValuePtr json,
                                        int opaque ATTRIBUTE_UNUSED)
{
    const char *uri = virJSONValueObjectGetString(json, "filename");
    const char *volume = virJSONValueObjectGetString(json, "volume");
    const char *path = virJSONValueObjectGetString(json, "path");
    virJSONValuePtr server = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;

    /* legacy URI based syntax passed via 'filename' option */
    if (uri)
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_GLUSTER);

    if (!volume || !path || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'volume', 'path' or 'server' attribute in "
                         "JSON backing definition for gluster volume"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;

    if (VIR_STRDUP(src->volume, volume) < 0 ||
        VIR_STRDUP(src->path, path) < 0)
        return -1;

    nservers = virJSONValueArraySize(server);
    if (nservers == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("at least 1 server is necessary in "
                         "JSON backing definition for gluster volume"));

        return -1;
    }

    if (VIR_ALLOC_N(src->hosts, nservers) < 0)
        return -1;
    src->nhosts = nservers;

    for (i = 0; i < nservers; i++) {
        if (virStorageSourceParseBackingJSONSocketAddress(src->hosts + i,
                                                          virJSONValueArrayGet(server, i)) < 0)
            return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONiSCSI(virStorageSourcePtr src,
                                      virJSONValuePtr json,
                                      int opaque ATTRIBUTE_UNUSED)
{
    const char *transport = virJSONValueObjectGetString(json, "transport");
    const char *portal = virJSONValueObjectGetString(json, "portal");
    const char *target = virJSONValueObjectGetString(json, "target");
    const char *lun = virJSONValueObjectGetStringOrNumber(json, "lun");
    const char *uri;
    char *port;

    /* legacy URI based syntax passed via 'filename' option */
    if ((uri = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_ISCSI);

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    if (!lun)
        lun = "0";

    if (VIR_ALLOC(src->hosts) < 0)
        return -1;

    src->nhosts = 1;

    if (STRNEQ_NULLABLE(transport, "tcp")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("only TCP transport is supported for iSCSI volumes"));
        return -1;
    }

    src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

    if (!portal) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'portal' address in iSCSI backing definition"));
        return -1;
    }

    if (!target) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'target' in iSCSI backing definition"));
        return -1;
    }

    if (VIR_STRDUP(src->hosts->name, portal) < 0)
        return -1;

    if ((port = strrchr(src->hosts->name, ':')) &&
        !strchr(port, ']')) {
        if (virStringParsePort(port + 1, &src->hosts->port) < 0)
            return -1;

        *port = '\0';
    }

    if (virAsprintf(&src->path, "%s/%s", target, lun) < 0)
        return -1;

    /* Libvirt doesn't handle inline authentication. Make the caller aware. */
    if (virJSONValueObjectGetString(json, "user") ||
        virJSONValueObjectGetString(json, "password"))
        return 1;

    return 0;
}


static int
virStorageSourceParseBackingJSONNbd(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    int opaque ATTRIBUTE_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    const char *export = virJSONValueObjectGetString(json, "export");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!path && !host && !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host specification of NBD server in JSON "
                         "backing volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;

    if (VIR_STRDUP(src->path, export) < 0)
        return -1;

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        return -1;
    src->nhosts = 1;

    if (server) {
        if (virStorageSourceParseBackingJSONSocketAddress(src->hosts, server) < 0)
            return -1;
    } else {
        if (path) {
            src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
            if (VIR_STRDUP(src->hosts[0].socket, path) < 0)
                return -1;
        } else {
            src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            if (VIR_STRDUP(src->hosts[0].name, host) < 0)
                return -1;

            if (virStringParsePort(port, &src->hosts[0].port) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONSheepdog(virStorageSourcePtr src,
                                         virJSONValuePtr json,
                                         int opaque ATTRIBUTE_UNUSED)
{
    const char *filename;
    const char *vdi = virJSONValueObjectGetString(json, "vdi");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    /* legacy URI based syntax passed via 'filename' option */
    if ((filename = virJSONValueObjectGetString(json, "filename"))) {
        if (strstr(filename, "://"))
            return virStorageSourceParseBackingJSONUriStr(src, filename,
                                                          VIR_STORAGE_NET_PROTOCOL_SHEEPDOG);

        /* libvirt doesn't implement a parser for the legacy non-URI syntax */
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing sheepdog URI in JSON backing volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;

    if (!vdi) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("missing sheepdog vdi name"));
        return -1;
    }

    if (VIR_STRDUP(src->path, vdi) < 0)
        return -1;

    if (VIR_ALLOC(src->hosts) < 0)
        return -1;

    src->nhosts = 1;

    if (virStorageSourceParseBackingJSONSocketAddress(src->hosts, server) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONSSH(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    int opaque ATTRIBUTE_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!(host || server) || !path) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host/server or path of SSH JSON backing "
                         "volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_SSH;

    if (VIR_STRDUP(src->path, path) < 0)
        return -1;

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        return -1;
    src->nhosts = 1;

    if (server) {
        if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts,
                                                              server) < 0)
            return -1;
    } else {
        src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

        if (VIR_STRDUP(src->hosts[0].name, host) < 0 ||
            virStringParsePort(port, &src->hosts[0].port) < 0)
            return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONRBD(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    int opaque ATTRIBUTE_UNUSED)
{
    const char *filename;
    const char *pool = virJSONValueObjectGetString(json, "pool");
    const char *image = virJSONValueObjectGetString(json, "image");
    const char *conf = virJSONValueObjectGetString(json, "conf");
    const char *snapshot = virJSONValueObjectGetString(json, "snapshot");
    virJSONValuePtr servers = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;
    int ret = -1;

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;

    /* legacy syntax passed via 'filename' option */
    if ((filename = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseRBDColonString(filename, src);

    if (!pool || !image) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing pool or image name in ceph backing volume "
                         "JSON specification"));
        return -1;
    }

    if (VIR_STRDUP(src->volume, pool) < 0 ||
        VIR_STRDUP(src->path, image) < 0 ||
        VIR_STRDUP(src->snapshot, snapshot) < 0 ||
        VIR_STRDUP(src->configFile, conf) < 0)
        goto cleanup;

    if (servers) {
        nservers = virJSONValueArraySize(servers);

        if (VIR_ALLOC_N(src->hosts, nservers) < 0)
            goto cleanup;

        src->nhosts = nservers;

        for (i = 0; i < nservers; i++) {
            if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts + i,
                                                                  virJSONValueArrayGet(servers, i)) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}

static int
virStorageSourceParseBackingJSONRaw(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    int opaque ATTRIBUTE_UNUSED)
{
    /* There are no interesting attributes in raw driver.
     * Treat it as pass-through.
     */
    return virStorageSourceParseBackingJSONInternal(src, json);
}


static int
virStorageSourceParseBackingJSONVxHS(virStorageSourcePtr src,
                                     virJSONValuePtr json,
                                     int opaque ATTRIBUTE_UNUSED)
{
    const char *vdisk_id = virJSONValueObjectGetString(json, "vdisk-id");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!vdisk_id || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'vdisk-id' or 'server' attribute in "
                         "JSON backing definition for VxHS volume"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_VXHS;

    if (VIR_STRDUP(src->path, vdisk_id) < 0)
        return -1;

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        return -1;
    src->nhosts = 1;

    if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts,
                                                          server) < 0)
        return -1;

    return 0;
}


struct virStorageSourceJSONDriverParser {
    const char *drvname;
    /**
     * The callback gets a pre-allocated storage source @src and the JSON
     * object to parse. The callback shall return -1 on error and report error
     * 0 on success and 1 in cases when the configuration itself is valid, but
     * can't be converted to libvirt's configuration (e.g. inline authentication
     * credentials are present).
     */
    int (*func)(virStorageSourcePtr src, virJSONValuePtr json, int opaque);
    int opaque;
};

static const struct virStorageSourceJSONDriverParser jsonParsers[] = {
    {"file", virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_FILE},
    {"host_device", virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_BLOCK},
    {"host_cdrom", virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_BLOCK},
    {"http", virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_HTTP},
    {"https", virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_HTTPS},
    {"ftp", virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_FTP},
    {"ftps", virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_FTPS},
    {"tftp", virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_TFTP},
    {"gluster", virStorageSourceParseBackingJSONGluster, 0},
    {"iscsi", virStorageSourceParseBackingJSONiSCSI, 0},
    {"nbd", virStorageSourceParseBackingJSONNbd, 0},
    {"sheepdog", virStorageSourceParseBackingJSONSheepdog, 0},
    {"ssh", virStorageSourceParseBackingJSONSSH, 0},
    {"rbd", virStorageSourceParseBackingJSONRBD, 0},
    {"raw", virStorageSourceParseBackingJSONRaw, 0},
    {"vxhs", virStorageSourceParseBackingJSONVxHS, 0},
};



static int
virStorageSourceParseBackingJSONInternal(virStorageSourcePtr src,
                                         virJSONValuePtr json)
{
    VIR_AUTOPTR(virJSONValue) deflattened = NULL;
    virJSONValuePtr file;
    const char *drvname;
    size_t i;
    VIR_AUTOFREE(char *) str = NULL;

    if (!(deflattened = virJSONValueObjectDeflatten(json)))
        return -1;

    if (!(file = virJSONValueObjectGetObject(deflattened, "file"))) {
        str = virJSONValueToString(json, false);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume definition '%s' lacks 'file' object"),
                       NULLSTR(str));
        return -1;
    }

    if (!(drvname = virJSONValueObjectGetString(file, "driver"))) {
        str = virJSONValueToString(json, false);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume definition '%s' lacks driver name"),
                       NULLSTR(str));
        return -1;
    }

    for (i = 0; i < ARRAY_CARDINALITY(jsonParsers); i++) {
        if (STREQ(drvname, jsonParsers[i].drvname))
            return jsonParsers[i].func(src, file, jsonParsers[i].opaque);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing parser implementation for JSON backing volume "
                     "driver '%s'"), drvname);
    return -1;
}


static int
virStorageSourceParseBackingJSON(virStorageSourcePtr src,
                                 const char *json)
{
    VIR_AUTOPTR(virJSONValue) root = NULL;

    if (!(root = virJSONValueFromString(json)))
        return -1;

    return virStorageSourceParseBackingJSONInternal(src, root);
}


/**
 * virStorageSourceNewFromBackingAbsolute
 * @path: string representing absolute location of a storage source
 * @src: filled with virStorageSource object representing @path
 *
 * Returns 0 on success, 1 if we could parse all location data but @path
 * specified other data unrepresentable by libvirt (e.g. inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
int
virStorageSourceNewFromBackingAbsolute(const char *path,
                                       virStorageSourcePtr *src)
{
    const char *json;
    int rc = 0;
    VIR_AUTOUNREF(virStorageSourcePtr) def = NULL;

    *src = NULL;

    if (!(def = virStorageSourceNew()))
        return -1;

    if (virStorageIsFile(path)) {
        def->type = VIR_STORAGE_TYPE_FILE;

        if (VIR_STRDUP(def->path, path) < 0)
            return -1;
    } else {
        def->type = VIR_STORAGE_TYPE_NETWORK;

        VIR_DEBUG("parsing backing store string: '%s'", path);

        /* handle URI formatted backing stores */
        if ((json = STRSKIP(path, "json:")))
            rc = virStorageSourceParseBackingJSON(def, json);
        else if (strstr(path, "://"))
            rc = virStorageSourceParseBackingURI(def, path);
        else
            rc = virStorageSourceParseBackingColon(def, path);

        if (rc < 0)
            return -1;

        virStorageSourceNetworkAssignDefaultPorts(def);

        /* Some of the legacy parsers parse authentication data since they are
         * also used in other places. For backing store detection the
         * authentication data would be invalid anyways, so we clear it */
        if (def->auth) {
            virStorageAuthDefFree(def->auth);
            def->auth = NULL;
        }
    }

    VIR_STEAL_PTR(*src, def);
    return rc;
}


/**
 * virStorageSourceNewFromBacking:
 * @parent: storage source parent
 * @backing: returned backing store definition
 *
 * Creates a storage source which describes the backing image of @parent and
 * fills it into @backing depending on the 'backingStoreRaw' property of @parent
 * and other data. Note that for local storage this function accesses the file
 * to update the actual type of the backing store.
 *
 * Returns 0 on success, 1 if we could parse all location data but the backinig
 * store specification contained other data unrepresentable by libvirt (e.g.
 * inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
int
virStorageSourceNewFromBacking(virStorageSourcePtr parent,
                               virStorageSourcePtr *backing)
{
    struct stat st;
    VIR_AUTOUNREF(virStorageSourcePtr) def = NULL;
    int rc = 0;

    *backing = NULL;

    if (virStorageIsRelative(parent->backingStoreRaw)) {
        if (!(def = virStorageSourceNewFromBackingRelative(parent,
                                                           parent->backingStoreRaw)))
            return -1;
    } else {
        if ((rc = virStorageSourceNewFromBackingAbsolute(parent->backingStoreRaw,
                                                         &def)) < 0)
            return -1;
    }

    /* possibly update local type */
    if (def->type == VIR_STORAGE_TYPE_FILE) {
        if (stat(def->path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_DIR;
                def->format = VIR_STORAGE_FILE_DIR;
            } else if (S_ISBLK(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_BLOCK;
            }
        }
    }

    /* copy parent's labelling and other top level stuff */
    if (virStorageSourceInitChainElement(def, parent, true) < 0)
        return -1;

    def->readonly = true;
    def->detected = true;

    VIR_STEAL_PTR(*backing, def);
    return rc;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Updates src->physical depending on the actual type of storage being used.
 * To be called for domain storage source reporting as the volume code does
 * not set/use the 'type' field for the voldef->source.target
 *
 * Returns 0 on success, -1 on error. No libvirt errors are reported.
 */
int
virStorageSourceUpdatePhysicalSize(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb)
{
    off_t end;
    virStorageType actual_type = virStorageSourceGetActualType(src);

    switch (actual_type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_NETWORK:
        src->physical = sb->st_size;
        break;

    case VIR_STORAGE_TYPE_BLOCK:
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1)
            return -1;

        src->physical = end;
        break;

    case VIR_STORAGE_TYPE_DIR:
        src->physical = 0;
        break;

    /* We shouldn't get VOLUME, but the switch requires all cases */
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return -1;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Update the capacity, allocation, physical values for the storage @src
 * Shared between the domain storage source for an inactive domain and the
 * voldef source target as the result is not affected by the 'type' field.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateBackingSizes(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb)
{
    /* Get info for normal formats */
    if (S_ISREG(sb->st_mode) || fd == -1) {
#ifndef WIN32
        src->allocation = (unsigned long long)sb->st_blocks *
            (unsigned long long)DEV_BSIZE;
#else
        src->allocation = sb->st_size;
#endif
        /* Regular files may be sparse, so logical size (capacity) is not same
         * as actual allocation above
         */
        src->capacity = sb->st_size;

        /* Allocation tracks when the file is sparse, physical is the
         * last offset of the file. */
        src->physical = sb->st_size;
    } else if (S_ISDIR(sb->st_mode)) {
        src->allocation = 0;
        src->capacity = 0;
        src->physical = 0;
    } else if (fd >= 0) {
        off_t end;

        /* XXX this is POSIX compliant, but doesn't work for CHAR files,
         * only BLOCK. There is a Linux specific ioctl() for getting
         * size of both CHAR / BLOCK devices we should check for in
         * configure
         *
         * NB. Because we configure with AC_SYS_LARGEFILE, off_t
         * should be 64 bits on all platforms.  For block devices, we
         * have to seek (safe even if someone else is writing) to
         * determine physical size, and assume that allocation is the
         * same as physical (but can refine that assumption later if
         * qemu is still running).
         */
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t)-1) {
            virReportSystemError(errno,
                                 _("failed to seek to end of %s"), src->path);
            return -1;
        }
        src->physical = end;
        src->allocation = end;
        src->capacity = end;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @buf: buffer to the storage file header
 * @len: length of the storage file header
 * @probe: allow probe
 *
 * Update the storage @src capacity. This may involve probing the storage
 * @src in order to "see" if we can recognize what exists.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateCapacity(virStorageSourcePtr src,
                               char *buf,
                               ssize_t len,
                               bool probe)
{
    int format = src->format;
    VIR_AUTOUNREF(virStorageSourcePtr) meta = NULL;

    /* Raw files: capacity is physical size.  For all other files: if
     * the metadata has a capacity, use that, otherwise fall back to
     * physical size.  */
    if (format == VIR_STORAGE_FILE_NONE) {
        if (!probe) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no disk format for %s and probing is disabled"),
                           src->path);
            return -1;
        }

        if ((format = virStorageFileProbeFormatFromBuf(src->path,
                                                       buf, len)) < 0)
            return -1;

        src->format = format;
    }

    if (format == VIR_STORAGE_FILE_RAW && !src->encryption) {
        src->capacity = src->physical;
    } else if ((meta = virStorageFileGetMetadataFromBuf(src->path, buf,
                                                        len, format, NULL))) {
        src->capacity = meta->capacity ? meta->capacity : src->physical;
        if (src->encryption && meta->encryption)
            src->encryption->payload_offset = meta->encryption->payload_offset;
    } else {
        return -1;
    }

    if (src->encryption && src->encryption->payload_offset != -1)
        src->capacity -= src->encryption->payload_offset * 512;

    return 0;
}


static char *
virStorageFileCanonicalizeFormatPath(char **components,
                                     size_t ncomponents,
                                     bool beginSlash,
                                     bool beginDoubleSlash)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    char *ret = NULL;

    if (beginSlash)
        virBufferAddLit(&buf, "/");

    if (beginDoubleSlash)
        virBufferAddLit(&buf, "/");

    for (i = 0; i < ncomponents; i++) {
        if (i != 0)
            virBufferAddLit(&buf, "/");

        virBufferAdd(&buf, components[i], -1);
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    /* if the output string is empty just return an empty string */
    if (!(ret = virBufferContentAndReset(&buf)))
        ignore_value(VIR_STRDUP(ret, ""));

    return ret;
}


static int
virStorageFileCanonicalizeInjectSymlink(const char *path,
                                        size_t at,
                                        char ***components,
                                        size_t *ncomponents)
{
    char **tmp = NULL;
    char **next;
    size_t ntmp = 0;
    int ret = -1;

    if (!(tmp = virStringSplitCount(path, "/", 0, &ntmp)))
        goto cleanup;

    /* prepend */
    for (next = tmp; *next; next++) {
        if (VIR_INSERT_ELEMENT(*components, at, *ncomponents, *next) < 0)
            goto cleanup;

        at++;
    }

    ret = 0;

 cleanup:
    virStringListFreeCount(tmp, ntmp);
    return ret;
}


char *
virStorageFileCanonicalizePath(const char *path,
                               virStorageFileSimplifyPathReadlinkCallback cb,
                               void *cbdata)
{
    virHashTablePtr cycle = NULL;
    bool beginSlash = false;
    bool beginDoubleSlash = false;
    char **components = NULL;
    size_t ncomponents = 0;
    size_t i = 0;
    size_t j = 0;
    int rc;
    char *ret = NULL;
    VIR_AUTOFREE(char *) linkpath = NULL;
    VIR_AUTOFREE(char *) currentpath = NULL;

    if (path[0] == '/') {
        beginSlash = true;

        if (path[1] == '/' && path[2] != '/')
            beginDoubleSlash = true;
    }

    if (!(cycle = virHashCreate(10, NULL)))
        goto cleanup;

    if (!(components = virStringSplitCount(path, "/", 0, &ncomponents)))
        goto cleanup;

    j = 0;
    while (j < ncomponents) {
        /* skip slashes */
        if (STREQ(components[j], "")) {
            VIR_FREE(components[j]);
            VIR_DELETE_ELEMENT(components, j, ncomponents);
            continue;
        }
        j++;
    }

    while (i < ncomponents) {
        /* skip '.'s unless it's the last one remaining */
        if (STREQ(components[i], ".") &&
            (beginSlash || ncomponents  > 1)) {
            VIR_FREE(components[i]);
            VIR_DELETE_ELEMENT(components, i, ncomponents);
            continue;
        }

        /* resolve changes to parent directory */
        if (STREQ(components[i], "..")) {
            if (!beginSlash &&
                (i == 0 || STREQ(components[i - 1], ".."))) {
                i++;
                continue;
            }

            VIR_FREE(components[i]);
            VIR_DELETE_ELEMENT(components, i, ncomponents);

            if (i != 0) {
                VIR_FREE(components[i - 1]);
                VIR_DELETE_ELEMENT(components, i - 1, ncomponents);
                i--;
            }

            continue;
        }

        /* check if the actual path isn't resulting into a symlink */
        if (!(currentpath = virStorageFileCanonicalizeFormatPath(components,
                                                                 i + 1,
                                                                 beginSlash,
                                                                 beginDoubleSlash)))
            goto cleanup;

        if ((rc = cb(currentpath, &linkpath, cbdata)) < 0)
            goto cleanup;

        if (rc == 0) {
            if (virHashLookup(cycle, currentpath)) {
                virReportSystemError(ELOOP,
                                     _("Failed to canonicalize path '%s'"), path);
                goto cleanup;
            }

            if (virHashAddEntry(cycle, currentpath, (void *) 1) < 0)
                goto cleanup;

            if (linkpath[0] == '/') {
                /* kill everything from the beginning including the actual component */
                i++;
                while (i--) {
                    VIR_FREE(components[0]);
                    VIR_DELETE_ELEMENT(components, 0, ncomponents);
                }
                beginSlash = true;

                if (linkpath[1] == '/' && linkpath[2] != '/')
                    beginDoubleSlash = true;
                else
                    beginDoubleSlash = false;

                i = 0;
            } else {
                VIR_FREE(components[i]);
                VIR_DELETE_ELEMENT(components, i, ncomponents);
            }

            if (virStorageFileCanonicalizeInjectSymlink(linkpath,
                                                        i,
                                                        &components,
                                                        &ncomponents) < 0)
                goto cleanup;

            j = 0;
            while (j < ncomponents) {
                /* skip slashes */
                if (STREQ(components[j], "")) {
                    VIR_FREE(components[j]);
                    VIR_DELETE_ELEMENT(components, j, ncomponents);
                    continue;
                }
                j++;
            }

            VIR_FREE(linkpath);
            VIR_FREE(currentpath);

            continue;
        }

        VIR_FREE(currentpath);

        i++;
    }

    ret = virStorageFileCanonicalizeFormatPath(components, ncomponents,
                                               beginSlash, beginDoubleSlash);

 cleanup:
    virHashFree(cycle);
    virStringListFreeCount(components, ncomponents);

    return ret;
}


/**
 * virStorageFileRemoveLastPathComponent:
 *
 * @path: Path string to remove the last component from
 *
 * Removes the last path component of a path. This function is designed to be
 * called on file paths only (no trailing slashes in @path). Caller is
 * responsible to free the returned string.
 */
static char *
virStorageFileRemoveLastPathComponent(const char *path)
{
    char *ret;

    if (VIR_STRDUP(ret, NULLSTR_EMPTY(path)) < 0)
        return NULL;

    virFileRemoveLastComponent(ret);

    return ret;
}


/*
 * virStorageFileGetRelativeBackingPath:
 *
 * Resolve relative path to be written to the overlay of @top image when
 * collapsing the backing chain between @top and @base.
 *
 * Returns 0 on success; 1 if backing chain isn't relative and -1 on error.
 */
int
virStorageFileGetRelativeBackingPath(virStorageSourcePtr top,
                                     virStorageSourcePtr base,
                                     char **relpath)
{
    virStorageSourcePtr next;
    VIR_AUTOFREE(char *) tmp = NULL;
    VIR_AUTOFREE(char *) path = NULL;

    *relpath = NULL;

    for (next = top; virStorageSourceIsBacking(next); next = next->backingStore) {
        if (!next->relPath)
            return 1;

        if (!(tmp = virStorageFileRemoveLastPathComponent(path)))
            return -1;

        VIR_FREE(path);

        if (virAsprintf(&path, "%s%s", tmp, next->relPath) < 0)
            return -1;

        VIR_FREE(tmp);

        if (next == base)
            break;
    }

    if (next != base) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to resolve relative backing name: "
                         "base image is not in backing chain"));
        return -1;
    }

    VIR_STEAL_PTR(*relpath, path);
    return 0;
}


/*
 * virStorageFileCheckCompat
 */
int
virStorageFileCheckCompat(const char *compat)
{
    unsigned int result;
    VIR_AUTOSTRINGLIST version = NULL;

    if (!compat)
        return 0;

    version = virStringSplit(compat, ".", 2);
    if (!version || !version[1] ||
        virStrToLong_ui(version[0], NULL, 10, &result) < 0 ||
        virStrToLong_ui(version[1], NULL, 10, &result) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("forbidden characters in 'compat' attribute"));
        return -1;
    }
    return 0;
}


/**
 * virStorageSourceIsRelative:
 * @src: storage source to check
 *
 * Returns true if given storage source definition is a relative path.
 */
bool
virStorageSourceIsRelative(virStorageSourcePtr src)
{
    virStorageType actual_type = virStorageSourceGetActualType(src);

    if (!src->path)
        return false;

    switch (actual_type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
        return src->path[0] != '/';

    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return false;
    }

    return false;
}


/**
 * virStorageSourceFindByNodeName:
 * @top: backing chain top
 * @nodeName: node name to find in backing chain
 * @index: if provided the index in the backing chain
 *
 * Looks up the given storage source in the backing chain and returns the
 * pointer to it. If @index is passed then it's filled by the index in the
 * backing chain. On failure NULL is returned and no error is reported.
 */
virStorageSourcePtr
virStorageSourceFindByNodeName(virStorageSourcePtr top,
                               const char *nodeName,
                               unsigned int *idx)
{
    virStorageSourcePtr tmp;

    if (idx)
        *idx = 0;

    for (tmp = top; virStorageSourceIsBacking(tmp); tmp = tmp->backingStore) {
        if ((tmp->nodeformat && STREQ(tmp->nodeformat, nodeName)) ||
            (tmp->nodestorage && STREQ(tmp->nodestorage, nodeName)))
            return tmp;

        if (idx)
            (*idx)++;
    }

    if (idx)
        *idx = 0;
    return NULL;
}


static unsigned int
virStorageSourceNetworkDefaultPort(virStorageNetProtocol protocol)
{
    switch (protocol) {
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
            return 80;

        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
            return 443;

        case VIR_STORAGE_NET_PROTOCOL_FTP:
            return 21;

        case VIR_STORAGE_NET_PROTOCOL_FTPS:
            return 990;

        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            return 69;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            return 7000;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
            return 10809;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            return 22;

        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
            return 3260;

        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            return 24007;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            /* we don't provide a default for RBD */
            return 0;

        case VIR_STORAGE_NET_PROTOCOL_VXHS:
            return 9999;

        case VIR_STORAGE_NET_PROTOCOL_LAST:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
            return 0;
    }

    return 0;
}


void
virStorageSourceNetworkAssignDefaultPorts(virStorageSourcePtr src)
{
    size_t i;

    for (i = 0; i < src->nhosts; i++) {
        if (src->hosts[i].transport == VIR_STORAGE_NET_HOST_TRANS_TCP &&
            src->hosts[i].port == 0)
            src->hosts[i].port = virStorageSourceNetworkDefaultPort(src->protocol);
    }
}


int
virStorageSourcePrivateDataParseRelPath(xmlXPathContextPtr ctxt,
                                        virStorageSourcePtr src)
{
    src->relPath = virXPathString("string(./relPath)", ctxt);
    return 0;
}


int
virStorageSourcePrivateDataFormatRelPath(virStorageSourcePtr src,
                                         virBufferPtr buf)
{
    if (src->relPath)
        virBufferEscapeString(buf, "<relPath>%s</relPath>\n", src->relPath);

    return 0;
}

void
virStorageSourceInitiatorParseXML(xmlXPathContextPtr ctxt,
                                  virStorageSourceInitiatorDefPtr initiator)
{
    initiator->iqn = virXPathString("string(./initiator/iqn/@name)", ctxt);
}

void
virStorageSourceInitiatorFormatXML(virStorageSourceInitiatorDefPtr initiator,
                                   virBufferPtr buf)
{
    if (!initiator->iqn)
        return;

    virBufferAddLit(buf, "<initiator>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<iqn name='%s'/>\n", initiator->iqn);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</initiator>\n");
}

int
virStorageSourceInitiatorCopy(virStorageSourceInitiatorDefPtr dest,
                              const virStorageSourceInitiatorDef *src)
{
    return VIR_STRDUP(dest->iqn, src->iqn);
}

void
virStorageSourceInitiatorClear(virStorageSourceInitiatorDefPtr initiator)
{
    VIR_FREE(initiator->iqn);
}

static bool
virStorageFileIsInitialized(const virStorageSource *src)
{
    return src && src->drv;
}


/**
 * virStorageFileGetBackendForSupportCheck:
 * @src: storage source to check support for
 * @backend: pointer to the storage backend for @src if it's supported
 *
 * Returns 0 if @src is not supported by any storage backend currently linked
 * 1 if it is supported and -1 on error with an error reported.
 */
static int
virStorageFileGetBackendForSupportCheck(const virStorageSource *src,
                                        virStorageFileBackendPtr *backend)
{
    int actualType;


    if (!src) {
        *backend = NULL;
        return 0;
    }

    if (src->drv) {
        *backend = src->drv->backend;
        return 1;
    }

    actualType = virStorageSourceGetActualType(src);

    if (virStorageFileBackendForType(actualType, src->protocol, false, backend) < 0)
        return -1;

    if (!*backend)
        return 0;

    return 1;
}


int
virStorageFileSupportsBackingChainTraversal(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileGetUniqueIdentifier &&
           backend->storageFileRead &&
           backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageFileSupportsSecurityDriver:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports operations needed by the security
 * driver to perform labelling
 */
int
virStorageFileSupportsSecurityDriver(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileChown ? 1 : 0;
}


/**
 * virStorageFileSupportsAccess:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports checking if the storage source is accessible
 * for the given vm.
 */
int
virStorageFileSupportsAccess(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageFileSupportsCreate:
 * @src: a storage file structure
 *
 * Check if the storage driver supports creating storage described by @src
 * via virStorageFileCreate.
 */
int
virStorageFileSupportsCreate(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileCreate ? 1 : 0;
}


void
virStorageFileDeinit(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src))
        return;

    if (src->drv->backend &&
        src->drv->backend->backendDeinit)
        src->drv->backend->backendDeinit(src);

    VIR_FREE(src->drv);
}


/**
 * virStorageFileInitAs:
 *
 * @src: storage source definition
 * @uid: uid used to access the file, or -1 for current uid
 * @gid: gid used to access the file, or -1 for current gid
 *
 * Initialize a storage source to be used with storage driver. Use the provided
 * uid and gid if possible for the operations.
 *
 * Returns 0 if the storage file was successfully initialized, -1 if the
 * initialization failed. Libvirt error is reported.
 */
int
virStorageFileInitAs(virStorageSourcePtr src,
                     uid_t uid, gid_t gid)
{
    int actualType = virStorageSourceGetActualType(src);
    if (VIR_ALLOC(src->drv) < 0)
        return -1;

    if (uid == (uid_t) -1)
        src->drv->uid = geteuid();
    else
        src->drv->uid = uid;

    if (gid == (gid_t) -1)
        src->drv->gid = getegid();
    else
        src->drv->gid = gid;

    if (virStorageFileBackendForType(actualType,
                                     src->protocol,
                                     true,
                                     &src->drv->backend) < 0)
        goto error;

    if (src->drv->backend->backendInit &&
        src->drv->backend->backendInit(src) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(src->drv);
    return -1;
}


/**
 * virStorageFileInit:
 *
 * See virStorageFileInitAs. The file is initialized to be accessed by the
 * current user.
 */
int
virStorageFileInit(virStorageSourcePtr src)
{
    return virStorageFileInitAs(src, -1, -1);
}


/**
 * virStorageFileCreate: Creates an empty storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileCreate(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileCreate(src);

    VIR_DEBUG("created storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileUnlink: Unlink storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileUnlink(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileUnlink(src);

    VIR_DEBUG("unlinked storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileStat: returns stat struct of a file via storage driver
 *
 * @src: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageFileStat(virStorageSourcePtr src,
                   struct stat *st)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileStat) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileStat(src, st);

    VIR_DEBUG("stat of storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileRead: read bytes from a file into a buffer
 *
 * @src: file structure pointing to the file
 * @offset: number of bytes to skip in the storage file
 * @len: maximum number of bytes read from the storage file
 * @buf: buffer to read the data into. (buffer shall be freed by caller)
 *
 * Returns the count of bytes read on success and -1 on failure, -2 if the
 * function isn't supported by the backend.
 * Libvirt error is reported on failure.
 */
ssize_t
virStorageFileRead(virStorageSourcePtr src,
                   size_t offset,
                   size_t len,
                   char **buf)
{
    ssize_t ret;

    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return -1;
    }

    if (!src->drv->backend->storageFileRead)
        return -2;

    ret = src->drv->backend->storageFileRead(src, offset, len, buf);

    VIR_DEBUG("read '%zd' bytes from storage '%p' starting at offset '%zu'",
              ret, src, offset);

    return ret;
}


/*
 * virStorageFileGetUniqueIdentifier: Get a unique string describing the volume
 *
 * @src: file structure pointing to the file
 *
 * Returns a string uniquely describing a single volume (canonical path).
 * The string shall not be freed and is valid until the storage file is
 * deinitialized. Returns NULL on error and sets a libvirt error code */
const char *
virStorageFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return NULL;
    }

    if (!src->drv->backend->storageFileGetUniqueIdentifier) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unique storage file identifier not implemented for "
                         "storage type %s (protocol: %s)'"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    return src->drv->backend->storageFileGetUniqueIdentifier(src);
}


/**
 * virStorageFileAccess: Check accessibility of a storage file
 *
 * @src: storage file to check access permissions
 * @mode: accessibility check options (see man 2 access)
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileAccess(virStorageSourcePtr src,
                     int mode)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileAccess) {
        errno = ENOSYS;
        return -2;
    }

    return src->drv->backend->storageFileAccess(src, mode);
}


/**
 * virStorageFileChown: Change owner of a storage file
 *
 * @src: storage file to change owner of
 * @uid: new owner id
 * @gid: new group id
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileChown(const virStorageSource *src,
                    uid_t uid,
                    gid_t gid)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileChown) {
        errno = ENOSYS;
        return -2;
    }

    VIR_DEBUG("chown of storage file %p to %u:%u",
              src, (unsigned int)uid, (unsigned int)gid);

    return src->drv->backend->storageFileChown(src, uid, gid);
}


/**
 * virStorageFileReportBrokenChain:
 *
 * @errcode: errno when accessing @src
 * @src: inaccessible file in the backing chain of @parent
 * @parent: root virStorageSource being checked
 *
 * Reports the correct error message if @src is missing in the backing chain
 * for @parent.
 */
void
virStorageFileReportBrokenChain(int errcode,
                                virStorageSourcePtr src,
                                virStorageSourcePtr parent)
{
    if (src->drv) {
        unsigned int access_user = src->drv->uid;
        unsigned int access_group = src->drv->gid;

        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%s' "
                                   "(as uid:%u, gid:%u)"),
                                 src->path, access_user, access_group);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s' (as uid:%u, gid:%u)"),
                                 src->path, parent->path, access_user, access_group);
        }
    } else {
        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%s'"),
                                 src->path);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s'"),
                                 src->path, parent->path);
        }
    }
}


/* Recursive workhorse for virStorageFileGetMetadata.  */
static int
virStorageFileGetMetadataRecurse(virStorageSourcePtr src,
                                 virStorageSourcePtr parent,
                                 uid_t uid, gid_t gid,
                                 bool report_broken,
                                 virHashTablePtr cycle,
                                 unsigned int depth)
{
    int ret = -1;
    const char *uniqueName;
    ssize_t headerLen;
    int backingFormat;
    int rv;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) backingStore = NULL;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u",
              src->path, src->format,
              (unsigned int)uid, (unsigned int)gid);

    /* exit if we can't load information about the current image */
    rv = virStorageFileSupportsBackingChainTraversal(src);
    if (rv <= 0)
        return rv;

    if (virStorageFileInitAs(src, uid, gid) < 0)
        return -1;

    if (virStorageFileAccess(src, F_OK) < 0) {
        virStorageFileReportBrokenChain(errno, src, parent);
        goto cleanup;
    }

    if (!(uniqueName = virStorageFileGetUniqueIdentifier(src)))
        goto cleanup;

    if (virHashLookup(cycle, uniqueName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %s (%s) is self-referential"),
                       src->path, uniqueName);
        goto cleanup;
    }

    if (virHashAddEntry(cycle, uniqueName, (void *)1) < 0)
        goto cleanup;

    if ((headerLen = virStorageFileRead(src, 0, VIR_STORAGE_MAX_HEADER,
                                        &buf)) < 0) {
        if (headerLen == -2)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("storage file reading is not supported for "
                             "storage type %s (protocol: %s)"),
                           virStorageTypeToString(src->type),
                           virStorageNetProtocolTypeToString(src->protocol));
        goto cleanup;
    }

    if (virStorageFileGetMetadataInternal(src, buf, headerLen,
                                          &backingFormat) < 0)
        goto cleanup;

    if (src->backingStoreRaw) {
        if ((rv = virStorageSourceNewFromBacking(src, &backingStore)) < 0)
            goto cleanup;

        if (rv == 1) {
            /* the backing file would not be usable for VM usage */
            ret = 0;
            goto cleanup;
        }

        if (backingFormat == VIR_STORAGE_FILE_AUTO)
            backingStore->format = VIR_STORAGE_FILE_RAW;
        else if (backingFormat == VIR_STORAGE_FILE_AUTO_SAFE)
            backingStore->format = VIR_STORAGE_FILE_AUTO;
        else
            backingStore->format = backingFormat;

        if ((ret = virStorageFileGetMetadataRecurse(backingStore, parent,
                                                    uid, gid,
                                                    report_broken,
                                                    cycle, depth + 1)) < 0) {
            if (report_broken)
                goto cleanup;

            /* if we fail somewhere midway, just accept and return a
             * broken chain */
            ret = 0;
            goto cleanup;
        }
    } else {
        /* add terminator */
        if (!(backingStore = virStorageSourceNew()))
            goto cleanup;
    }

    VIR_STEAL_PTR(src->backingStore, backingStore);
    ret = 0;

 cleanup:
    if (virStorageSourceHasBacking(src))
        src->backingStore->id = depth;
    virStorageFileDeinit(src);
    return ret;
}


/**
 * virStorageFileGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Recurses through
 * the entire chain.
 *
 * Open files using UID and GID (or pass -1 for the current user/group).
 * Treat any backing files without explicit type as raw, unless ALLOW_PROBE.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If @report_broken is true, the whole function fails with a possibly sane
 * error instead of just returning a broken chain. Note that the inability for
 * libvirt to traverse a given source is not considered an error.
 *
 * Caller MUST free result after use via virObjectUnref.
 */
int
virStorageFileGetMetadata(virStorageSourcePtr src,
                          uid_t uid, gid_t gid,
                          bool report_broken)
{
    VIR_DEBUG("path=%s format=%d uid=%u gid=%u report_broken=%d",
              src->path, src->format, (unsigned int)uid, (unsigned int)gid,
              report_broken);

    virHashTablePtr cycle = NULL;
    virStorageType actualType = virStorageSourceGetActualType(src);
    int ret = -1;

    if (!(cycle = virHashCreate(5, NULL)))
        return -1;

    if (src->format <= VIR_STORAGE_FILE_NONE) {
        if (actualType == VIR_STORAGE_TYPE_DIR)
            src->format = VIR_STORAGE_FILE_DIR;
        else
            src->format = VIR_STORAGE_FILE_RAW;
    }

    ret = virStorageFileGetMetadataRecurse(src, src, uid, gid,
                                           report_broken, cycle, 1);

    virHashFree(cycle);
    return ret;
}


/**
 * virStorageFileGetBackingStoreStr:
 * @src: storage object
 *
 * Extracts the backing store string as stored in the storage volume described
 * by @src and returns it to the user. Caller is responsible for freeing it.
 * In case when the string can't be retrieved or does not exist NULL is
 * returned.
 */
int
virStorageFileGetBackingStoreStr(virStorageSourcePtr src,
                                 char **backing)
{
    ssize_t headerLen;
    int rv;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) tmp = NULL;

    *backing = NULL;

    /* exit if we can't load information about the current image */
    if (!virStorageFileSupportsBackingChainTraversal(src))
        return 0;

    rv = virStorageFileAccess(src, F_OK);
    if (rv == -2)
        return 0;
    if (rv < 0) {
        virStorageFileReportBrokenChain(errno, src, src);
        return -1;
    }

    if ((headerLen = virStorageFileRead(src, 0, VIR_STORAGE_MAX_HEADER,
                                        &buf)) < 0) {
        if (headerLen == -2)
            return 0;
        return -1;
    }

    if (!(tmp = virStorageSourceCopy(src, false)))
        return -1;

    if (virStorageFileGetMetadataInternal(tmp, buf, headerLen, NULL) < 0)
        return -1;

    VIR_STEAL_PTR(*backing, tmp->backingStoreRaw);
    return 0;
}
