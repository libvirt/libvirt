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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "virstoragefile.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
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

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("util.storagefile");

VIR_ENUM_IMPL(virStorage, VIR_STORAGE_TYPE_LAST,
              "none",
              "file",
              "block",
              "dir",
              "network",
              "volume")

VIR_ENUM_IMPL(virStorageFileFormat,
              VIR_STORAGE_FILE_LAST,
              "none",
              "raw", "dir", "bochs",
              "cloop", "dmg", "iso",
              "vpc", "vdi",
              /* Not direct file formats, but used for various drivers */
              "fat", "vhd", "ploop",
              /* Formats with backing file below here */
              "cow", "qcow", "qcow2", "qed", "vmdk")

VIR_ENUM_IMPL(virStorageFileFeature,
              VIR_STORAGE_FILE_FEATURE_LAST,
              "lazy_refcounts",
              )

VIR_ENUM_IMPL(virStorageNetProtocol, VIR_STORAGE_NET_PROTOCOL_LAST,
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
              "ssh")

VIR_ENUM_IMPL(virStorageNetHostTransport, VIR_STORAGE_NET_HOST_TRANS_LAST,
              "tcp",
              "unix",
              "rdma")

VIR_ENUM_IMPL(virStorageSourcePoolMode,
              VIR_STORAGE_SOURCE_POOL_MODE_LAST,
              "default",
              "host",
              "direct")

VIR_ENUM_IMPL(virStorageAuth,
              VIR_STORAGE_AUTH_TYPE_LAST,
              "none", "chap", "ceph")

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
        /* http://wiki.qemu.org/Features/QED */
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
            *format = virStorageFileFormatTypeFromString(
                ((const char *)buf)+offset);
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
                     bool isQCow2)
{
    unsigned long long offset;
    unsigned int size;
    unsigned long long start;
    int version;

    *res = NULL;
    if (format)
        *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size < QCOWX_HDR_BACKING_FILE_OFFSET+8+4)
        return BACKING_STORE_INVALID;
    offset = virReadBufInt64BE(buf + QCOWX_HDR_BACKING_FILE_OFFSET);
    if (offset > buf_size)
        return BACKING_STORE_INVALID;

    if (offset == 0) {
        if (format)
            *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }

    size = virReadBufInt32BE(buf + QCOWX_HDR_BACKING_FILE_SIZE);
    if (size == 0) {
        if (format)
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
    if (isQCow2 && format) {
        version = virReadBufInt32BE(buf + QCOWX_HDR_VERSION);
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
    int ret;

    /* QCow1 doesn't have the extensions capability
     * used to store backing format */
    *format = VIR_STORAGE_FILE_AUTO;
    ret = qcowXGetBackingStore(res, NULL, buf, buf_size, false);
    if (ret == 0 && *buf == '\0')
        *format = VIR_STORAGE_FILE_NONE;
    return ret;
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
    char *desc, *start, *end;
    size_t len;
    int ret = BACKING_STORE_ERROR;

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
    VIR_FREE(desc);
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

    if (virFileHasSuffix(path, extension))
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
        if (virStorageFileMatchesMagic(
                fileTypeInfo[i].magicOffset,
                fileTypeInfo[i].magic,
                buf, buflen)) {
            if (!virStorageFileMatchesVersion(
                    fileTypeInfo[i].versionOffset,
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
        if (virStorageFileMatchesExtension(
                fileTypeInfo[i].extension, path)) {
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
 * pre-populated in META */
int
virStorageFileGetMetadataInternal(virStorageSourcePtr meta,
                                  char *buf,
                                  size_t len,
                                  int *backingFormat)
{
    int dummy;
    int ret = -1;
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
        goto cleanup;
    }

    if (fileTypeInfo[meta->format].cryptInfo != NULL) {
        for (i = 0; fileTypeInfo[meta->format].cryptInfo[i].format != 0; i++) {
            if (virStorageFileHasEncryptionFormat(&fileTypeInfo[meta->format].cryptInfo[i],
                                                  buf, len)) {
                int expt_fmt = fileTypeInfo[meta->format].cryptInfo[i].format;
                if (!meta->encryption) {
                    if (VIR_ALLOC(meta->encryption) < 0)
                        goto cleanup;

                    meta->encryption->format = expt_fmt;
                } else {
                    if (meta->encryption->format != expt_fmt) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("encryption format %d doesn't match "
                                         "expected format %d"),
                                       meta->encryption->format, expt_fmt);
                        goto cleanup;
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
        goto done;

    /* Optionally extract capacity from file */
    if (fileTypeInfo[meta->format].sizeOffset != -1) {
        if ((fileTypeInfo[meta->format].sizeOffset + 8) > len)
            goto done;

        if (fileTypeInfo[meta->format].endian == LV_LITTLE_ENDIAN)
            meta->capacity = virReadBufInt64LE(buf +
                                               fileTypeInfo[meta->format].sizeOffset);
        else
            meta->capacity = virReadBufInt64BE(buf +
                                               fileTypeInfo[meta->format].sizeOffset);
        /* Avoid unlikely, but theoretically possible overflow */
        if (meta->capacity > (ULLONG_MAX /
                              fileTypeInfo[meta->format].sizeMultiplier))
            goto done;
        meta->capacity *= fileTypeInfo[meta->format].sizeMultiplier;
    }

    VIR_FREE(meta->backingStoreRaw);
    if (fileTypeInfo[meta->format].getBackingStore != NULL) {
        int store = fileTypeInfo[meta->format].getBackingStore(&meta->backingStoreRaw,
                                                         backingFormat,
                                                         buf, len);
        if (store == BACKING_STORE_INVALID)
            goto done;

        if (store == BACKING_STORE_ERROR)
            goto cleanup;
    }

    if (fileTypeInfo[meta->format].getFeatures != NULL &&
        fileTypeInfo[meta->format].getFeatures(&meta->features, meta->format, buf, len) < 0)
        goto cleanup;

    if (meta->format == VIR_STORAGE_FILE_QCOW2 && meta->features &&
        VIR_STRDUP(meta->compat, "1.1") < 0)
        goto cleanup;

 done:
    ret = 0;

 cleanup:
    return ret;
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
    int fd;
    int ret = -1;
    struct stat sb;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    char *header = NULL;

    if ((fd = virFileOpenAs(path, O_RDONLY, 0, uid, gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%s'"), path);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno, _("cannot stat file '%s'"), path);
        goto cleanup;
    }

    /* No header to probe for directories */
    if (S_ISDIR(sb.st_mode)) {
        ret = VIR_STORAGE_FILE_DIR;
        goto cleanup;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot set to start of '%s'"), path);
        goto cleanup;
    }

    if ((len = virFileReadHeaderFD(fd, len, &header)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), path);
        goto cleanup;
    }

    ret = virStorageFileProbeFormatFromBuf(path, header, len);

 cleanup:
    VIR_FREE(header);
    VIR_FORCE_CLOSE(fd);

    return ret;
}


static virStorageSourcePtr
virStorageFileMetadataNew(const char *path,
                          int format)
{
    virStorageSourcePtr ret = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->format = format;
    ret->type = VIR_STORAGE_TYPE_FILE;

    if (VIR_STRDUP(ret->path, path) < 0)
        goto error;

    return ret;

 error:
    virStorageSourceFree(ret);
    return NULL;
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
 * Caller MUST free the result after use via virStorageSourceFree.
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
        virStorageSourceFree(ret);
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
 * Caller MUST free the result after use via virStorageSourceFree.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromFD(const char *path,
                                int fd,
                                int format,
                                int *backingFormat)

{
    virStorageSourcePtr ret = NULL;
    virStorageSourcePtr meta = NULL;
    char *buf = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    struct stat sb;
    int dummy;

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
        ret = meta;
        meta = NULL;
        goto cleanup;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%s'"), meta->path);
        goto cleanup;
    }

    if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), meta->path);
        goto cleanup;
    }

    if (virStorageFileGetMetadataInternal(meta, buf, len, backingFormat) < 0)
        goto cleanup;

    if (S_ISREG(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_FILE;
    else if (S_ISBLK(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_BLOCK;

    ret = meta;
    meta = NULL;

 cleanup:
    virStorageSourceFree(meta);
    VIR_FREE(buf);
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

    for (tmp = chain; tmp; tmp = tmp->backingStore) {
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
                     unsigned long long orig_capacity,
                     bool pre_allocate)
{
    int fd = -1;
    int ret = -1;
    int rc ATTRIBUTE_UNUSED;
    off_t offset ATTRIBUTE_UNUSED;
    off_t len ATTRIBUTE_UNUSED;

    offset = orig_capacity;
    len = capacity - orig_capacity;

    if ((fd = open(path, O_RDWR)) < 0) {
        virReportSystemError(errno, _("Unable to open '%s'"), path);
        goto cleanup;
    }

    if (pre_allocate) {
        if (safezero(fd, offset, len) != 0) {
            virReportSystemError(errno,
                                 _("Failed to pre-allocate space for "
                                   "file '%s'"), path);
            goto cleanup;
        }
    } else {
        if (ftruncate(fd, capacity) < 0) {
            virReportSystemError(errno,
                                 _("Failed to truncate file '%s'"), path);
            goto cleanup;
        }
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Unable to save '%s'"), path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


int virStorageFileIsClusterFS(const char *path)
{
    /* These are coherent cluster filesystems known to be safe for
     * migration with cache != none
     */
    return virFileIsSharedFSType(path,
                                 VIR_FILE_SHFS_GFS2 |
                                 VIR_FILE_SHFS_OCFS);
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
    virCommandPtr cmd = virCommandNewArgList(
        LVS,
        "--noheadings", "--unbuffered", "--nosuffix",
        "--options", "uuid", path,
        NULL
        );
    int ret = -1;

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

    virCommandFree(cmd);

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
int virStorageFileGetSCSIKey(const char *path,
                             char **key)
{
    int status;
    virCommandPtr cmd = virCommandNewArgList(
        "/lib/udev/scsi_id",
        "--replace-whitespace",
        "--whitelisted",
        "--device", path,
        NULL
        );
    int ret = -1;

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
        char *nl = strchr(*key, '\n');
        if (nl)
            *nl = '\0';
    }

    ret = 0;

 cleanup:
    if (*key && STREQ(*key, ""))
        VIR_FREE(*key);

    virCommandFree(cmd);

    return ret;
}
#else
int virStorageFileGetSCSIKey(const char *path,
                             char **key ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, _("Unable to get SCSI key for %s"), path);
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
    char **strings = NULL;
    size_t nstrings;
    unsigned int idx = 0;
    char *suffix;
    int ret = -1;

    *chainIndex = 0;

    if (!(strings = virStringSplitCount(str, "[", 2, &nstrings)))
        return -1;

    if (nstrings == 2) {
        if (virStrToLong_uip(strings[1], &suffix, 10, &idx) < 0 ||
            STRNEQ(suffix, "]"))
            goto cleanup;
    }

    if (target &&
        VIR_STRDUP(*target, strings[0]) < 0)
        goto cleanup;

    *chainIndex = idx;
    ret = 0;

 cleanup:
    virStringListFreeCount(strings, nstrings);
    return ret;
}


int
virStorageFileParseChainIndex(const char *diskTarget,
                              const char *name,
                              unsigned int *chainIndex)
{
    unsigned int idx = 0;
    char *target = NULL;
    int ret = 0;

    *chainIndex = 0;

    if (!name || !diskTarget)
        return 0;

    if (virStorageFileParseBackingStoreStr(name, &target, &idx) < 0)
        return 0;

    if (idx == 0)
        goto cleanup;

    if (STRNEQ(diskTarget, target)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested target '%s' does not match target '%s'"),
                       target, diskTarget);
        ret = -1;
        goto cleanup;
    }

    *chainIndex = idx;

 cleanup:
    VIR_FREE(target);
    return ret;
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
    size_t i = 0;

    if (!parent)
        parent = &prev;
    *parent = NULL;

    if (startFrom) {
        while (chain && chain != startFrom->backingStore) {
            chain = chain->backingStore;
            i++;
        }

        if (idx && idx < i) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("requested backing store index %u is above '%s' "
                             "in chain for '%s'"),
                           idx, NULLSTR(startFrom->path), NULLSTR(start));
            return NULL;
        }

        *parent = startFrom;
    }

    while (chain) {
        if (!name && !idx) {
            if (!chain->backingStore)
                break;
        } else if (idx) {
            VIR_DEBUG("%zu: %s", i, chain->path);
            if (idx == i)
                break;
        } else {
            if (STREQ_NULLABLE(name, chain->relPath) ||
                STREQ(name, chain->path))
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
        i++;
    }

    if (!chain)
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
    virStorageAuthDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_STRDUP(ret->username, src->username) < 0)
        goto error;
    /* Not present for storage pool, but used for disk source */
    if (VIR_STRDUP(ret->secrettype, src->secrettype) < 0)
        goto error;
    ret->authType = src->authType;

    if (virSecretLookupDefCopy(&ret->seclookupdef, &src->seclookupdef) < 0)
        goto error;

    return ret;

 error:
    virStorageAuthDefFree(ret);
    return NULL;
}


static virStorageAuthDefPtr
virStorageAuthDefParseXML(xmlXPathContextPtr ctxt)
{
    virStorageAuthDefPtr authdef = NULL;
    xmlNodePtr secretnode = NULL;
    char *username = NULL;
    char *authtype = NULL;

    if (VIR_ALLOC(authdef) < 0)
        return NULL;

    if (!(username = virXPathString("string(./@username)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing username for auth"));
        goto error;
    }
    authdef->username = username;
    username = NULL;

    authdef->authType = VIR_STORAGE_AUTH_TYPE_NONE;
    authtype = virXPathString("string(./@type)", ctxt);
    if (authtype) {
        /* Used by the storage pool instead of the secret type field
         * to define whether chap or ceph being used
         */
        if ((authdef->authType = virStorageAuthTypeFromString(authtype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown auth type '%s'"), authtype);
            goto error;
        }
        VIR_FREE(authtype);
    }

    if (!(secretnode = virXPathNode("./secret ", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <secret> element in auth"));
        goto error;
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
        goto error;

    return authdef;

 error:
    VIR_FREE(authtype);
    VIR_FREE(username);
    virStorageAuthDefFree(authdef);
    return NULL;
}


virStorageAuthDefPtr
virStorageAuthDefParse(xmlDocPtr xml, xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virStorageAuthDefPtr authdef = NULL;

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    authdef = virStorageAuthDefParseXML(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return authdef;
}


int
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

    return 0;
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

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->type = src->type;
    ret->protocol = src->protocol;
    ret->format = src->format;
    ret->capacity = src->capacity;
    ret->allocation = src->allocation;
    ret->has_allocation = src->has_allocation;
    ret->physical = src->physical;
    ret->readonly = src->readonly;
    ret->shared = src->shared;

    /* storage driver metadata are not copied */
    ret->drv = NULL;

    if (VIR_STRDUP(ret->path, src->path) < 0 ||
        VIR_STRDUP(ret->volume, src->volume) < 0 ||
        VIR_STRDUP(ret->driverName, src->driverName) < 0 ||
        VIR_STRDUP(ret->relPath, src->relPath) < 0 ||
        VIR_STRDUP(ret->backingStoreRaw, src->backingStoreRaw) < 0 ||
        VIR_STRDUP(ret->snapshot, src->snapshot) < 0 ||
        VIR_STRDUP(ret->configFile, src->configFile) < 0 ||
        VIR_STRDUP(ret->nodeformat, src->nodeformat) < 0 ||
        VIR_STRDUP(ret->nodestorage, src->nodestorage) < 0 ||
        VIR_STRDUP(ret->compat, src->compat) < 0)
        goto error;

    if (src->nhosts) {
        if (!(ret->hosts = virStorageNetHostDefCopy(src->nhosts, src->hosts)))
            goto error;

        ret->nhosts = src->nhosts;
    }

    if (src->srcpool &&
        !(ret->srcpool = virStorageSourcePoolDefCopy(src->srcpool)))
        goto error;

    if (src->features &&
        !(ret->features = virBitmapNewCopy(src->features)))
        goto error;

    if (src->encryption &&
        !(ret->encryption = virStorageEncryptionCopy(src->encryption)))
        goto error;

    if (src->perms &&
        !(ret->perms = virStoragePermsCopy(src->perms)))
        goto error;

    if (src->timestamps &&
        !(ret->timestamps = virStorageTimestampsCopy(src->timestamps)))
        goto error;

    if (virStorageSourceSeclabelsCopy(ret, src) < 0)
        goto error;

    if (src->auth &&
        !(ret->auth = virStorageAuthDefCopy(src->auth)))
        goto error;

    if (backingChain && src->backingStore) {
        if (!(ret->backingStore = virStorageSourceCopy(src->backingStore,
                                                       true)))
            goto error;
    }

    return ret;

 error:
    virStorageSourceFree(ret);
    return NULL;
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

    if (!newelem->driverName &&
        VIR_STRDUP(newelem->driverName, old->driverName) < 0)
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


int
virStorageSourceGetActualType(const virStorageSource *def)
{
    if (def->type == VIR_STORAGE_TYPE_VOLUME && def->srcpool)
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
    virStorageSourceFree(def->backingStore);
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
    VIR_FREE(def->driverName);
    virBitmapFree(def->features);
    VIR_FREE(def->compat);
    virStorageEncryptionFree(def->encryption);
    virStorageSourceSeclabelsClear(def);
    virStoragePermsFree(def->perms);
    VIR_FREE(def->timestamps);

    virStorageNetHostDefFree(def->nhosts, def->hosts);
    virStorageAuthDefFree(def->auth);

    VIR_FREE(def->nodestorage);
    VIR_FREE(def->nodeformat);

    virStorageSourceBackingStoreClear(def);

    memset(def, 0, sizeof(*def));
}


void
virStorageSourceFree(virStorageSourcePtr def)
{
    if (!def)
        return;

    virStorageSourceClear(def);
    VIR_FREE(def);
}


static virStorageSourcePtr
virStorageSourceNewFromBackingRelative(virStorageSourcePtr parent,
                                       const char *rel)
{
    char *dirname = NULL;
    virStorageSourcePtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    /* store relative name */
    if (VIR_STRDUP(ret->relPath, parent->backingStoreRaw) < 0)
        goto error;

    if (!(dirname = mdir_name(parent->path))) {
        virReportOOMError();
        goto error;
    }

    if (STRNEQ(dirname, "/")) {
        if (virAsprintf(&ret->path, "%s/%s", dirname, rel) < 0)
            goto error;
    } else {
        if (virAsprintf(&ret->path, "/%s", rel) < 0)
            goto error;
    }

    if (virStorageSourceGetActualType(parent) == VIR_STORAGE_TYPE_NETWORK) {
        ret->type = VIR_STORAGE_TYPE_NETWORK;

        /* copy the host network part */
        ret->protocol = parent->protocol;
        if (parent->nhosts) {
            if (!(ret->hosts = virStorageNetHostDefCopy(parent->nhosts,
                                                        parent->hosts)))
                goto error;

            ret->nhosts = parent->nhosts;
        }

        if (VIR_STRDUP(ret->volume, parent->volume) < 0)
            goto error;
    } else {
        /* set the type to _FILE, the caller shall update it to the actual type */
        ret->type = VIR_STORAGE_TYPE_FILE;
    }

 cleanup:
    VIR_FREE(dirname);
    return ret;

 error:
    virStorageSourceFree(ret);
    ret = NULL;
    goto cleanup;
}


static int
virStorageSourceParseBackingURI(virStorageSourcePtr src,
                                const char *path)
{
    virURIPtr uri = NULL;
    char **scheme = NULL;
    int ret = -1;

    if (!(uri = virURIParse(path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse backing file location '%s'"),
                       path);
        goto cleanup;
    }

    if (VIR_ALLOC(src->hosts) < 0)
        goto cleanup;

    src->nhosts = 1;

    if (!(scheme = virStringSplit(uri->scheme, "+", 2)))
        goto cleanup;

    if (!scheme[0] ||
        (src->protocol = virStorageNetProtocolTypeFromString(scheme[0])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
                       NULLSTR(scheme[0]));
        goto cleanup;
    }

    if (scheme[1] &&
        (src->hosts->transport = virStorageNetHostTransportTypeFromString(scheme[1])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid protocol transport type '%s'"),
                       scheme[1]);
        goto cleanup;
    }

    /* handle socket stored as a query */
    if (uri->query) {
        if (VIR_STRDUP(src->hosts->socket, STRSKIP(uri->query, "socket=")) < 0)
            goto cleanup;
    }

    /* XXX We currently don't support auth, so don't bother parsing it */

    /* possibly skip the leading slash */
    if (uri->path &&
        VIR_STRDUP(src->path,
                   *uri->path == '/' ? uri->path + 1 : uri->path) < 0)
        goto cleanup;

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_GLUSTER) {
        char *tmp;

        if (!src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("missing volume name and path for gluster volume"));
            goto cleanup;
        }

        if (!(tmp = strchr(src->path, '/')) ||
            tmp == src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("missing volume name or file name in "
                             "gluster source path '%s'"), src->path);
            goto cleanup;
        }

        src->volume = src->path;

        if (VIR_STRDUP(src->path, tmp) < 0)
            goto cleanup;

        tmp[0] = '\0';
    }

    src->hosts->port = uri->port;

    if (VIR_STRDUP(src->hosts->name, uri->server) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virURIFree(uri);
    virStringListFree(scheme);
    return ret;
}


static int
virStorageSourceRBDAddHost(virStorageSourcePtr src,
                           char *hostport)
{
    char *port;
    size_t skip;
    char **parts;

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
    virStringListFree(parts);
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
    char *options = NULL;
    char *p, *e, *next;
    virStorageAuthDefPtr authdef = NULL;

    /* optionally skip the "rbd:" prefix if provided */
    if (STRPREFIX(rbdstr, "rbd:"))
        rbdstr += strlen("rbd:");

    if (VIR_STRDUP(src->path, rbdstr) < 0)
        goto error;

    p = strchr(src->path, ':');
    if (p) {
        if (VIR_STRDUP(options, p + 1) < 0)
            goto error;
        *p = '\0';
    }

    /* snapshot name */
    if ((p = strchr(src->path, '@'))) {
        if (VIR_STRDUP(src->snapshot, p + 1) < 0)
            goto error;
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
            if (VIR_ALLOC(authdef) < 0)
                goto error;

            if (VIR_STRDUP(authdef->username, p + strlen("id=")) < 0)
                goto error;

            if (VIR_STRDUP(authdef->secrettype,
                           virStorageAuthTypeToString(VIR_STORAGE_AUTH_TYPE_CEPHX)) < 0)
                goto error;
            src->auth = authdef;
            authdef = NULL;

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
                    goto error;

                h = sep;
            }
        }

        if (STRPREFIX(p, "conf=") &&
            VIR_STRDUP(src->configFile, p + strlen("conf=")) < 0)
            goto error;

        p = next;
    }
    VIR_FREE(options);
    return 0;

 error:
    VIR_FREE(options);
    virStorageAuthDefFree(authdef);
    return -1;
}


static int
virStorageSourceParseNBDColonString(const char *nbdstr,
                                    virStorageSourcePtr src)
{
    char **backing = NULL;
    int ret = -1;

    if (!(backing = virStringSplit(nbdstr, ":", 0)))
        goto cleanup;

    /* we know that backing[0] now equals to "nbd" */

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        goto cleanup;

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
        goto cleanup;
    } else if (STREQ(backing[1], "unix")) {
        if (!backing[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing unix socket path in nbd backing string %s"),
                           nbdstr);
            goto cleanup;
        }

        if (VIR_STRDUP(src->hosts->socket, backing[2]) < 0)
            goto cleanup;

   } else {
        if (VIR_STRDUP(src->hosts->name, backing[1]) < 0)
            goto cleanup;

        if (!backing[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing port in nbd string '%s'"),
                           nbdstr);
            goto cleanup;
        }

        if (virStringParsePort(backing[2], &src->hosts->port) < 0)
            goto cleanup;
    }

    if (backing[3] && STRPREFIX(backing[3], "exportname=")) {
        if (VIR_STRDUP(src->path, backing[3] + strlen("exportname=")) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virStringListFree(backing);

    return ret;
}


static int
virStorageSourceParseBackingColon(virStorageSourcePtr src,
                                  const char *path)
{
    char *protocol = NULL;
    const char *p;
    int ret = -1;

    if (!(p = strchr(path, ':'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol string '%s'"),
                       path);
        goto cleanup;
    }

    if (VIR_STRNDUP(protocol, path, p - path) < 0)
        goto cleanup;

    if ((src->protocol = virStorageNetProtocolTypeFromString(protocol)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
                       protocol);
        goto cleanup;
    }

    switch ((virStorageNetProtocol) src->protocol) {
    case VIR_STORAGE_NET_PROTOCOL_NBD:
        if (virStorageSourceParseNBDColonString(path, src) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_NET_PROTOCOL_RBD:
        if (virStorageSourceParseRBDColonString(path, src) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
    case VIR_STORAGE_NET_PROTOCOL_LAST:
    case VIR_STORAGE_NET_PROTOCOL_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store parser is not implemented for protocol %s"),
                       protocol);
        goto cleanup;

    case VIR_STORAGE_NET_PROTOCOL_HTTP:
    case VIR_STORAGE_NET_PROTOCOL_HTTPS:
    case VIR_STORAGE_NET_PROTOCOL_FTP:
    case VIR_STORAGE_NET_PROTOCOL_FTPS:
    case VIR_STORAGE_NET_PROTOCOL_TFTP:
    case VIR_STORAGE_NET_PROTOCOL_ISCSI:
    case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
    case VIR_STORAGE_NET_PROTOCOL_SSH:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed backing store path for protocol %s"),
                       protocol);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(protocol);
    return ret;
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
    if (virStorageSourceParseBackingURI(src, uri) < 0)
        return -1;

    if (src->protocol != protocol) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("expected protocol '%s' but got '%s' in URI JSON volume "
                         "definition"),
                       virStorageNetProtocolTypeToString(protocol),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -1;
    }

    return 0;
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

        if (!(socket = virJSONValueObjectGetString(json, "socket"))) {
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
        virAsprintf(&src->path, "/%s", path) < 0)
        return -1;

    nservers = virJSONValueArraySize(server);

    if (nservers < 1) {
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
    const char *uri;
    char *port;
    unsigned int lun = 0;
    char *fulltarget = NULL;
    int ret = -1;

    /* legacy URI based syntax passed via 'filename' option */
    if ((uri = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_ISCSI);

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    if (VIR_ALLOC(src->hosts) < 0)
        goto cleanup;

    src->nhosts = 1;

    if (STRNEQ_NULLABLE(transport, "tcp")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("only TCP transport is supported for iSCSI volumes"));
        goto cleanup;
    }

    src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

    if (!portal) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'portal' address in iSCSI backing definition"));
        goto cleanup;
    }

    if (!target) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'target' in iSCSI backing definition"));
        goto cleanup;
    }

    if (VIR_STRDUP(src->hosts->name, portal) < 0)
        goto cleanup;

    if ((port = strchr(src->hosts->name, ':'))) {
        if (virStringParsePort(port + 1, &src->hosts->port) < 0)
            goto cleanup;

        *port = '\0';
    }

    ignore_value(virJSONValueObjectGetNumberUint(json, "lun", &lun));

    if (virAsprintf(&fulltarget, "%s/%u", target, lun) < 0)
        goto cleanup;

    VIR_STEAL_PTR(src->path, fulltarget);

    ret = 0;

 cleanup:
    VIR_FREE(fulltarget);
    return ret;
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
    char *fullname = NULL;
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

    /* currently we need to store the pool name and image name together, since
     * the rest of the code is not prepared for it */
    if (virAsprintf(&fullname, "%s/%s", pool, image) < 0)
        return -1;

    if (VIR_STRDUP(src->snapshot, snapshot) < 0 ||
        VIR_STRDUP(src->configFile, conf) < 0)
        goto cleanup;

    VIR_STEAL_PTR(src->path, fullname);

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
    VIR_FREE(fullname);

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

struct virStorageSourceJSONDriverParser {
    const char *drvname;
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
};



static int
virStorageSourceParseBackingJSONInternal(virStorageSourcePtr src,
                                         virJSONValuePtr json)
{
    virJSONValuePtr deflattened = NULL;
    virJSONValuePtr file;
    const char *drvname;
    char *str = NULL;
    size_t i;
    int ret = -1;

    if (!(deflattened = virJSONValueObjectDeflatten(json)))
        goto cleanup;

    if (!(file = virJSONValueObjectGetObject(deflattened, "file"))) {
        str = virJSONValueToString(json, false);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume defintion '%s' lacks 'file' object"),
                       NULLSTR(str));
        goto cleanup;
    }

    if (!(drvname = virJSONValueObjectGetString(file, "driver"))) {
        str = virJSONValueToString(json, false);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume defintion '%s' lacks driver name"),
                       NULLSTR(str));
        goto cleanup;
    }

    for (i = 0; i < ARRAY_CARDINALITY(jsonParsers); i++) {
        if (STREQ(drvname, jsonParsers[i].drvname)) {
            ret = jsonParsers[i].func(src, file, jsonParsers[i].opaque);
            goto cleanup;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing parser implementation for JSON backing volume "
                     "driver '%s'"), drvname);

 cleanup:
    VIR_FREE(str);
    virJSONValueFree(deflattened);
    return ret;
}


static int
virStorageSourceParseBackingJSON(virStorageSourcePtr src,
                                 const char *json)
{
    virJSONValuePtr root = NULL;
    int ret = -1;

    if (!(root = virJSONValueFromString(json)))
        return -1;

    ret = virStorageSourceParseBackingJSONInternal(src, root);

    virJSONValueFree(root);
    return ret;
}


virStorageSourcePtr
virStorageSourceNewFromBackingAbsolute(const char *path)
{
    const char *json;
    virStorageSourcePtr ret;
    int rc;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virStorageIsFile(path)) {
        ret->type = VIR_STORAGE_TYPE_FILE;

        if (VIR_STRDUP(ret->path, path) < 0)
            goto error;
    } else {
        ret->type = VIR_STORAGE_TYPE_NETWORK;

        VIR_DEBUG("parsing backing store string: '%s'", path);

        /* handle URI formatted backing stores */
        if ((json = STRSKIP(path, "json:")))
            rc = virStorageSourceParseBackingJSON(ret, json);
        else if (strstr(path, "://"))
            rc = virStorageSourceParseBackingURI(ret, path);
        else
            rc = virStorageSourceParseBackingColon(ret, path);

        if (rc < 0)
            goto error;

        virStorageSourceNetworkAssignDefaultPorts(ret);
    }

    return ret;

 error:
    virStorageSourceFree(ret);
    return NULL;
}


virStorageSourcePtr
virStorageSourceNewFromBacking(virStorageSourcePtr parent)
{
    struct stat st;
    virStorageSourcePtr ret;

    if (virStorageIsRelative(parent->backingStoreRaw))
        ret = virStorageSourceNewFromBackingRelative(parent,
                                                     parent->backingStoreRaw);
    else
        ret = virStorageSourceNewFromBackingAbsolute(parent->backingStoreRaw);

    if (ret) {
        /* possibly update local type */
        if (ret->type == VIR_STORAGE_TYPE_FILE) {
            if (stat(ret->path, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    ret->type = VIR_STORAGE_TYPE_DIR;
                    ret->format = VIR_STORAGE_FILE_DIR;
                } else if (S_ISBLK(st.st_mode)) {
                    ret->type = VIR_STORAGE_TYPE_BLOCK;
                }
            }
        }

        /* copy parent's labelling and other top level stuff */
        if (virStorageSourceInitChainElement(ret, parent, true) < 0)
            goto error;
    }

    return ret;

 error:
    virStorageSourceFree(ret);
    return NULL;
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
 * Returns 0 on success, -1 on error.
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
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1) {
            virReportSystemError(errno, _("failed to seek to end of '%s'"),
                                 src->path);
            return -1;
        }

        src->physical = end;
        break;

    case VIR_STORAGE_TYPE_DIR:
        src->physical = 0;
        break;

    /* We shouldn't get VOLUME, but the switch requires all cases */
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("cannot retrieve physical for path '%s' type '%s'"),
                      NULLSTR(src->path),
                      virStorageTypeToString(actual_type));
        return -1;
        break;
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
    int ret = -1;
    virStorageSourcePtr meta = NULL;
    int format = src->format;

    /* Raw files: capacity is physical size.  For all other files: if
     * the metadata has a capacity, use that, otherwise fall back to
     * physical size.  */
    if (format == VIR_STORAGE_FILE_NONE) {
        if (!probe) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no disk format for %s and probing is disabled"),
                           src->path);
            goto cleanup;
        }

        if ((format = virStorageFileProbeFormatFromBuf(src->path,
                                                       buf, len)) < 0)
            goto cleanup;

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
        goto cleanup;
    }

    if (src->encryption && src->encryption->payload_offset != -1)
        src->capacity -= src->encryption->payload_offset * 512;

    ret = 0;

 cleanup:
    virStorageSourceFree(meta);
    return ret;
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
    char *linkpath = NULL;
    char *currentpath = NULL;
    size_t i = 0;
    size_t j = 0;
    int rc;
    char *ret = NULL;

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
    VIR_FREE(linkpath);
    VIR_FREE(currentpath);

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

    if (VIR_STRDUP(ret, path ? path : "") < 0)
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
    char *tmp = NULL;
    char *path = NULL;
    char ret = -1;

    *relpath = NULL;

    for (next = top; next; next = next->backingStore) {
        if (!next->relPath) {
            ret = 1;
            goto cleanup;
        }

        if (!(tmp = virStorageFileRemoveLastPathComponent(path)))
            goto cleanup;

        VIR_FREE(path);

        if (virAsprintf(&path, "%s%s", tmp, next->relPath) < 0)
            goto cleanup;

        VIR_FREE(tmp);

        if (next == base)
            break;
    }

    if (next != base) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to resolve relative backing name: "
                         "base image is not in backing chain"));
        goto cleanup;
    }

    *relpath = path;
    path = NULL;

    ret = 0;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(tmp);
    return ret;
}


/*
 * virStorageFileCheckCompat
 */
int
virStorageFileCheckCompat(const char *compat)
{
    char **version;
    unsigned int result;
    int ret = -1;

    if (!compat)
        return 0;

    version = virStringSplit(compat, ".", 2);
    if (!version || !version[1] ||
        virStrToLong_ui(version[0], NULL, 10, &result) < 0 ||
        virStrToLong_ui(version[1], NULL, 10, &result) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("forbidden characters in 'compat' attribute"));
        goto cleanup;
    }
    ret = 0;

 cleanup:
    virStringListFree(version);
    return ret;
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

    for (tmp = top; tmp; tmp = tmp->backingStore) {
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
