/*
 * storage_file_probe.c: file utility functions for FS storage backend
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

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "internal.h"
#include "storage_file_probe.h"
#include "storage_source_conf.h"
#include "viralloc.h"
#include "virbitmap.h"
#include "virendian.h"
#include "virfile.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage_file.storagefileprobe");

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

struct FileTypeInfo {
    int magicOffset;    /* Byte offset of the magic */
    const char *magic;  /* Optional string of file magic
                         * to check at head of file */
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
    unsigned long long (*getClusterSize)(const char *buf,
                                         size_t buf_size);
    int (*getBackingStore)(char **res, int *format,
                           const char *buf, size_t buf_size);
    int (*getFeatures)(virBitmap **features, int format,
                       char *buf, ssize_t len);
};


static int cowGetBackingStore(char **, int *,
                              const char *, size_t);
static unsigned long long
qcow2GetClusterSize(const char *buf,
                    size_t buf_size);
static int qcowXGetBackingStore(char **, int *,
                                const char *, size_t);
static int qcow2GetFeatures(virBitmap **features, int format,
                            char *buf, ssize_t len);
static int vmdk4GetBackingStore(char **, int *,
                                const char *, size_t);
static int
qedGetBackingStore(char **, int *, const char *, size_t);

#define QCOWX_HDR_VERSION (4)
#define QCOWX_HDR_BACKING_FILE_OFFSET (QCOWX_HDR_VERSION+4)
#define QCOWX_HDR_BACKING_FILE_SIZE (QCOWX_HDR_BACKING_FILE_OFFSET+8)
#define QCOWX_HDR_CLUSTER_BITS_OFFSET (QCOWX_HDR_BACKING_FILE_SIZE+4)
#define QCOWX_HDR_IMAGE_SIZE (QCOWX_HDR_CLUSTER_BITS_OFFSET+4)

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
    {
        .format = VIR_STORAGE_ENCRYPTION_FORMAT_LUKS,

        .magicOffset = 0,
        .magic = NULL,
        .endian = LV_BIG_ENDIAN,

        .versionOffset  = -1,
        .versionSize = 0,
        .versionNumbers = {},

        .modeOffset = QCOW2_HDR_CRYPT,
        .modeValue = 2,

        .payloadOffset = -1,
    },
    { 0 }
};

static struct FileTypeInfo const fileTypeInfo[] = {
    [VIR_STORAGE_FILE_NONE] = { 0, NULL, LV_LITTLE_ENDIAN,
                                -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_RAW] = { 0, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0,
                               luksEncryptionInfo,
                               NULL, NULL, NULL },
    [VIR_STORAGE_FILE_DIR] = { 0, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_BOCHS] = {
        /*"Bochs Virtual HD Image", */ /* Untested */
        0, NULL,
        LV_LITTLE_ENDIAN, 64, 4, {0x20000},
        32+16+16+4+4+4+4+4, 8, 1, NULL, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_CLOOP] = {
        /* #!/bin/sh
           #V2.0 Format
           modprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1
        */ /* Untested */
        0, NULL,
        LV_LITTLE_ENDIAN, -1, 0, {0},
        -1, 0, 0, NULL, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_DMG] = {
        /* XXX QEMU says there's no magic for dmg,
         * /usr/share/misc/magic lists double magic (both offsets
         * would have to match) but then disables that check. */
        0, NULL,
        0, -1, 0, {0},
        -1, 0, 0, NULL, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_ISO] = {
        32769, "CD001",
        LV_LITTLE_ENDIAN, -2, 0, {0},
        -1, 0, 0, NULL, NULL, NULL, NULL
    },
    [VIR_STORAGE_FILE_VPC] = {
        0, "conectix",
        LV_BIG_ENDIAN, 12, 4, {0x10000},
        8 + 4 + 4 + 8 + 4 + 4 + 2 + 2 + 4, 8, 1, NULL, NULL, NULL, NULL
    },
    /* TODO: add getBackingStore function */
    [VIR_STORAGE_FILE_VDI] = {
        64, "\x7f\x10\xda\xbe",
        LV_LITTLE_ENDIAN, 68, 4, {0x00010001},
        64 + 5 * 4 + 256 + 7 * 4, 8, 1, NULL, NULL, NULL, NULL},

    /* Not direct file formats, but used for various drivers */
    [VIR_STORAGE_FILE_FAT] = { 0, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_VHD] = { 0, NULL, LV_LITTLE_ENDIAN,
                               -1, 0, {0}, 0, 0, 0, NULL, NULL, NULL, NULL },
    [VIR_STORAGE_FILE_PLOOP] = { 0, "WithouFreSpacExt", LV_LITTLE_ENDIAN,
                                 -2, 0, {0}, PLOOP_IMAGE_SIZE_OFFSET, 8,
                                 PLOOP_SIZE_MULTIPLIER, NULL, NULL, NULL, NULL },

    /* All formats with a backing store probe below here */
    [VIR_STORAGE_FILE_COW] = {
        0, "OOOM",
        LV_BIG_ENDIAN, 4, 4, {2},
        4+4+1024+4, 8, 1, NULL, NULL, cowGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW] = {
        0, "QFI",
        LV_BIG_ENDIAN, 4, 4, {1},
        QCOWX_HDR_IMAGE_SIZE, 8, 1,
        qcow1EncryptionInfo,
        NULL, qcowXGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW2] = {
        0, "QFI",
        LV_BIG_ENDIAN, 4, 4, {2, 3},
        QCOWX_HDR_IMAGE_SIZE, 8, 1,
        qcow2EncryptionInfo,
        qcow2GetClusterSize,
        qcowXGetBackingStore,
        qcow2GetFeatures
    },
    [VIR_STORAGE_FILE_QED] = {
        /* https://wiki.qemu.org/Features/QED */
        0, "QED",
        LV_LITTLE_ENDIAN, -2, 0, {0},
        QED_HDR_IMAGE_SIZE, 8, 1, NULL, NULL, qedGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_VMDK] = {
        0, "KDMV",
        LV_LITTLE_ENDIAN, 4, 4, {1, 2, 3},
        4+4+4, 8, 512, NULL, NULL, vmdk4GetBackingStore, NULL
    },
};
G_STATIC_ASSERT(G_N_ELEMENTS(fileTypeInfo) == VIR_STORAGE_FILE_LAST);


/* qcow2 compatible features in the order they appear on-disk */
enum qcow2CompatibleFeature {
    QCOW2_COMPATIBLE_FEATURE_LAZY_REFCOUNTS = 0,

    QCOW2_COMPATIBLE_FEATURE_LAST
};

/* conversion to virStorageFileFeature */
static const virStorageFileFeature qcow2CompatibleFeatureArray[] = {
    VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS,
};
G_STATIC_ASSERT(G_N_ELEMENTS(qcow2CompatibleFeatureArray) ==
       QCOW2_COMPATIBLE_FEATURE_LAST);

/* qcow2 incompatible features in the order they appear on-disk */
enum qcow2IncompatibleFeature {
    QCOW2_INCOMPATIBLE_FEATURE_DIRTY = 0,
    QCOW2_INCOMPATIBLE_FEATURE_CORRUPT,
    QCOW2_INCOMPATIBLE_FEATURE_DATA_FILE,
    QCOW2_INCOMPATIBLE_FEATURE_COMPRESSION,
    QCOW2_INCOMPATIBLE_FEATURE_EXTL2,

    QCOW2_INCOMPATIBLE_FEATURE_LAST
};

/* conversion to virStorageFileFeature */
static const virStorageFileFeature qcow2IncompatibleFeatureArray[] = {
    VIR_STORAGE_FILE_FEATURE_LAST, /* QCOW2_INCOMPATIBLE_FEATURE_DIRTY */
    VIR_STORAGE_FILE_FEATURE_LAST, /* QCOW2_INCOMPATIBLE_FEATURE_CORRUPT */
    VIR_STORAGE_FILE_FEATURE_LAST, /* QCOW2_INCOMPATIBLE_FEATURE_DATA_FILE */
    VIR_STORAGE_FILE_FEATURE_LAST, /* QCOW2_INCOMPATIBLE_FEATURE_COMPRESSION */
    VIR_STORAGE_FILE_FEATURE_EXTENDED_L2, /* QCOW2_INCOMPATIBLE_FEATURE_EXTL2 */
};
G_STATIC_ASSERT(G_N_ELEMENTS(qcow2IncompatibleFeatureArray) == QCOW2_INCOMPATIBLE_FEATURE_LAST);


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

    *res = g_strndup((const char *)buf + 4 + 4, COW_FILENAME_MAXLEN);
    return BACKING_STORE_OK;
}


static int
qcow2GetExtensions(const char *buf,
                   size_t buf_size,
                   int *backingFormat)
{
    size_t offset;
    size_t extension_start;
    size_t extension_end;
    int version = virReadBufInt32BE(buf + QCOWX_HDR_VERSION);

    if (version < 2) {
        /* QCow1 doesn't have the extensions capability
         * used to store backing format */
        return 0;
    }

    if (version == 2)
        extension_start = QCOW2_HDR_TOTAL_SIZE;
    else
        extension_start = virReadBufInt32BE(buf + QCOW2v3_HDR_SIZE);

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
    extension_end = virReadBufInt64BE(buf + QCOWX_HDR_BACKING_FILE_OFFSET);
    if (extension_end > buf_size)
        return -1;

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
    offset = extension_start;
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
        case QCOW2_HDR_EXTENSION_BACKING_FORMAT: {
            g_autofree char *tmp = NULL;
            if (!backingFormat)
                break;

            tmp = g_new0(char, len + 1);
            memcpy(tmp, buf + offset, len);
            tmp[len] = '\0';

            *backingFormat = virStorageFileFormatTypeFromString(tmp);
            if (*backingFormat <= VIR_STORAGE_FILE_NONE)
                return -1;
            break;
        }

        case QCOW2_HDR_EXTENSION_END:
            return 0;
        }

        offset += len;
    }

    return 0;
}


static unsigned long long
qcow2GetClusterSize(const char *buf,
                    size_t buf_size)
{
    int clusterBits = 0;

    if ((QCOWX_HDR_CLUSTER_BITS_OFFSET + 4) > buf_size)
        return 0;

    clusterBits = virReadBufInt32BE(buf + QCOWX_HDR_CLUSTER_BITS_OFFSET);

    if (clusterBits > 0)
        return 1ULL << clusterBits;

    return 0;
}


static int
qcowXGetBackingStore(char **res,
                     int *format,
                     const char *buf,
                     size_t buf_size)
{
    unsigned long long offset;
    unsigned int size;

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
    *res = g_new0(char, size + 1);
    memcpy(*res, buf + offset, size);
    (*res)[size] = '\0';

    if (qcow2GetExtensions(buf, buf_size, format) < 0)
        return BACKING_STORE_INVALID;

    return BACKING_STORE_OK;
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
    g_autofree char *desc = NULL;

    desc = g_new0(char, VIR_STORAGE_MAX_HEADER);

    *res = NULL;
    /*
     * Technically this should have been VMDK, since
     * VMDK spec / VMware impl only support VMDK backed
     * by VMDK. QEMU isn't following this though and
     * does probing on VMDK backing files, hence we set
     * AUTO
     */
    *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size <= 0x200)
        return BACKING_STORE_INVALID;

    len = buf_size - 0x200;
    if (len >= VIR_STORAGE_MAX_HEADER)
        len = VIR_STORAGE_MAX_HEADER - 1;
    memcpy(desc, buf + 0x200, len);
    desc[len] = '\0';
    start = strstr(desc, prefix);
    if (start == NULL) {
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }
    start += strlen(prefix);
    end = strchr(start, '"');
    if (end == NULL)
        return BACKING_STORE_INVALID;

    if (end == start) {
        *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }
    *end = '\0';
    *res = g_strdup(start);

    return BACKING_STORE_OK;
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
    *res = g_new0(char, size + 1);
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
                 "Please report new version to devel@lists.libvirt.org",
                 path, virStorageFileFormatTypeToString(possibleFormat));

 cleanup:
    VIR_DEBUG("format=%d", format);
    return format;
}


static void
qcow2GetFeaturesProcessGroup(uint64_t bits,
                             const virStorageFileFeature *featuremap,
                             size_t nfeatures,
                             virBitmap *features)
{
    size_t i;

    for (i = 0; i < nfeatures; i++) {
        if ((bits & ((uint64_t) 1 << i)) &&
            featuremap[i] != VIR_STORAGE_FILE_FEATURE_LAST)
            ignore_value(virBitmapSetBit(features, featuremap[i]));
    }
}


static int
qcow2GetFeatures(virBitmap **features,
                 int format,
                 char *buf,
                 ssize_t len)
{
    int version = -1;

    version = virReadBufInt32BE(buf + fileTypeInfo[format].versionOffset);

    if (version == 2)
        return 0;

    if (len < QCOW2v3_HDR_SIZE)
        return -1;

    *features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST);

    qcow2GetFeaturesProcessGroup(virReadBufInt64BE(buf + QCOW2v3_HDR_FEATURES_COMPATIBLE),
                                 qcow2CompatibleFeatureArray,
                                 G_N_ELEMENTS(qcow2CompatibleFeatureArray),
                                 *features);

    qcow2GetFeaturesProcessGroup(virReadBufInt64BE(buf + QCOW2v3_HDR_FEATURES_INCOMPATIBLE),
                                 qcow2IncompatibleFeatureArray,
                                 G_N_ELEMENTS(qcow2IncompatibleFeatureArray),
                                 *features);

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
int
virStorageFileProbeGetMetadata(virStorageSource *meta,
                               char *buf,
                               size_t len)
{
    int format;
    size_t i;

    VIR_DEBUG("path=%s, buf=%p, len=%zu, meta->format=%d",
              meta->path, buf, len, meta->format);

    if (meta->format == VIR_STORAGE_FILE_AUTO)
        meta->format = virStorageFileProbeFormatFromBuf(meta->path, buf, len);

    if (meta->format <= VIR_STORAGE_FILE_NONE ||
        meta->format >= VIR_STORAGE_FILE_LAST) {
        virReportSystemError(EINVAL, _("unknown storage file meta->format %1$d"),
                             meta->format);
        return -1;
    }

    if (fileTypeInfo[meta->format].cryptInfo != NULL) {
        for (i = 0; fileTypeInfo[meta->format].cryptInfo[i].format != 0; i++) {
            if (virStorageFileHasEncryptionFormat(&fileTypeInfo[meta->format].cryptInfo[i],
                                                  buf, len)) {
                int expt_fmt = fileTypeInfo[meta->format].cryptInfo[i].format;
                if (!meta->encryption) {
                    meta->encryption = g_new0(virStorageEncryption, 1);
                    meta->encryption->format = expt_fmt;
                } else {
                    if (meta->encryption->format != expt_fmt) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("encryption format %1$d doesn't match expected format %2$d"),
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

    if (fileTypeInfo[meta->format].getClusterSize != NULL)
        meta->clusterSize = fileTypeInfo[meta->format].getClusterSize(buf, len);

    VIR_FREE(meta->backingStoreRaw);
    if (fileTypeInfo[meta->format].getBackingStore != NULL) {
        int store = fileTypeInfo[meta->format].getBackingStore(&meta->backingStoreRaw,
                                                               &format,
                                                               buf, len);
        meta->backingStoreRawFormat = format;

        if (store == BACKING_STORE_INVALID)
            return 0;

        if (store == BACKING_STORE_ERROR)
            return -1;
    }

    g_clear_pointer(&meta->features, virBitmapFree);
    if (fileTypeInfo[meta->format].getFeatures != NULL &&
        fileTypeInfo[meta->format].getFeatures(&meta->features, meta->format, buf, len) < 0)
        return -1;

    VIR_FREE(meta->compat);
    if (meta->format == VIR_STORAGE_FILE_QCOW2 && meta->features)
        meta->compat = g_strdup("1.1");

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
    g_autofree char *header = NULL;

    if ((fd = virFileOpenAs(path, O_RDONLY, 0, uid, gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%1$s'"), path);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno, _("cannot stat file '%1$s'"), path);
        return -1;
    }

    /* No header to probe for directories */
    if (S_ISDIR(sb.st_mode))
        return VIR_STORAGE_FILE_DIR;

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot set to start of '%1$s'"), path);
        return -1;
    }

    if ((len = virFileReadHeaderFD(fd, len, &header)) < 0) {
        virReportSystemError(errno, _("cannot read header '%1$s'"), path);
        return -1;
    }

    return virStorageFileProbeFormatFromBuf(path, header, len);
}
