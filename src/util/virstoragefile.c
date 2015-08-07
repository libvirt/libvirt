/*
 * virstoragefile.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

#include <sys/stat.h>
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
              "tftp")

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

#define FILE_TYPE_VERSIONS_LAST 2

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
    int qcowCryptOffset;  /* Byte offset from start of file
                           * where to find encryption mode,
                           * -1 if encryption is not used */
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


static struct FileTypeInfo const fileTypeInfo[] = {
    [VIR_STORAGE_FILE_NONE] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                                -1, {0}, 0, 0, 0, 0, NULL, NULL },
    [VIR_STORAGE_FILE_RAW] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, {0}, 0, 0, 0, 0, NULL, NULL },
    [VIR_STORAGE_FILE_DIR] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, {0}, 0, 0, 0, 0, NULL, NULL },
    [VIR_STORAGE_FILE_BOCHS] = {
        /*"Bochs Virtual HD Image", */ /* Untested */
        0, NULL, NULL,
        LV_LITTLE_ENDIAN, 64, {0x20000},
        32+16+16+4+4+4+4+4, 8, 1, -1, NULL, NULL
    },
    [VIR_STORAGE_FILE_CLOOP] = {
        /* #!/bin/sh
           #V2.0 Format
           modprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1
        */ /* Untested */
        0, NULL, NULL,
        LV_LITTLE_ENDIAN, -1, {0},
        -1, 0, 0, -1, NULL, NULL
    },
    [VIR_STORAGE_FILE_DMG] = {
        /* XXX QEMU says there's no magic for dmg,
         * /usr/share/misc/magic lists double magic (both offsets
         * would have to match) but then disables that check. */
        0, NULL, ".dmg",
        0, -1, {0},
        -1, 0, 0, -1, NULL, NULL
    },
    [VIR_STORAGE_FILE_ISO] = {
        32769, "CD001", ".iso",
        LV_LITTLE_ENDIAN, -2, {0},
        -1, 0, 0, -1, NULL, NULL
    },
    [VIR_STORAGE_FILE_VPC] = {
        0, "conectix", NULL,
        LV_BIG_ENDIAN, 12, {0x10000},
        8 + 4 + 4 + 8 + 4 + 4 + 2 + 2 + 4, 8, 1, -1, NULL, NULL
    },
    /* TODO: add getBackingStore function */
    [VIR_STORAGE_FILE_VDI] = {
        64, "\x7f\x10\xda\xbe", ".vdi",
        LV_LITTLE_ENDIAN, 68, {0x00010001},
        64 + 5 * 4 + 256 + 7 * 4, 8, 1, -1, NULL, NULL},

    /* Not direct file formats, but used for various drivers */
    [VIR_STORAGE_FILE_FAT] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, {0}, 0, 0, 0, 0, NULL, NULL },
    [VIR_STORAGE_FILE_VHD] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, {0}, 0, 0, 0, 0, NULL, NULL },
    [VIR_STORAGE_FILE_PLOOP] = { 0, NULL, NULL, LV_LITTLE_ENDIAN,
                               -1, {0}, 0, 0, 0, 0, NULL, NULL },

    /* All formats with a backing store probe below here */
    [VIR_STORAGE_FILE_COW] = {
        0, "OOOM", NULL,
        LV_BIG_ENDIAN, 4, {2},
        4+4+1024+4, 8, 1, -1, cowGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW] = {
        0, "QFI", NULL,
        LV_BIG_ENDIAN, 4, {1},
        QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW1_HDR_CRYPT, qcow1GetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_QCOW2] = {
        0, "QFI", NULL,
        LV_BIG_ENDIAN, 4, {2, 3},
        QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW2_HDR_CRYPT, qcow2GetBackingStore,
        qcow2GetFeatures
    },
    [VIR_STORAGE_FILE_QED] = {
        /* http://wiki.qemu.org/Features/QED */
        0, "QED", NULL,
        LV_LITTLE_ENDIAN, -2, {0},
        QED_HDR_IMAGE_SIZE, 8, 1, -1, qedGetBackingStore, NULL
    },
    [VIR_STORAGE_FILE_VMDK] = {
        0, "KDMV", NULL,
        LV_LITTLE_ENDIAN, 4, {1, 2},
        4+4+4, 8, 512, -1, vmdk4GetBackingStore, NULL
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
     * VMDK spec / VMWare impl only support VMDK backed
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
virStorageFileMatchesMagic(int format,
                           char *buf,
                           size_t buflen)
{
    int mlen;
    int magicOffset = fileTypeInfo[format].magicOffset;
    const char *magic = fileTypeInfo[format].magic;

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
virStorageFileMatchesExtension(int format,
                               const char *path)
{
    if (fileTypeInfo[format].extension == NULL)
        return false;

    if (virFileHasSuffix(path, fileTypeInfo[format].extension))
        return true;

    return false;
}


static bool
virStorageFileMatchesVersion(int format,
                             char *buf,
                             size_t buflen)
{
    int version;
    size_t i;

    /* Validate version number info */
    if (fileTypeInfo[format].versionOffset == -1)
        return false;

    /* -2 == non-versioned file format, so trivially match */
    if (fileTypeInfo[format].versionOffset == -2)
        return true;

    if ((fileTypeInfo[format].versionOffset + 4) > buflen)
        return false;

    if (fileTypeInfo[format].endian == LV_LITTLE_ENDIAN)
        version = virReadBufInt32LE(buf + fileTypeInfo[format].versionOffset);
    else
        version = virReadBufInt32BE(buf + fileTypeInfo[format].versionOffset);

    for (i = 0;
         i < FILE_TYPE_VERSIONS_LAST && fileTypeInfo[format].versionNumbers[i];
         i++) {
        VIR_DEBUG("Compare detected version %d vs one of the expected versions %d",
                  version, fileTypeInfo[format].versionNumbers[i]);
        if (version == fileTypeInfo[format].versionNumbers[i])
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


static bool
virStorageIsRelative(const char *backing)
{
    if (backing[0] == '/')
        return false;

    if (!virStorageIsFile(backing))
        return false;

    return true;
}


int
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
        if (virStorageFileMatchesMagic(i, buf, buflen)) {
            if (!virStorageFileMatchesVersion(i, buf, buflen)) {
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
        if (virStorageFileMatchesExtension(i, path)) {
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
    int ret = -1;

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

    if (fileTypeInfo[meta->format].qcowCryptOffset != -1) {
        int crypt_format;

        crypt_format = virReadBufInt32BE(buf +
                                         fileTypeInfo[meta->format].qcowCryptOffset);
        if (crypt_format && !meta->encryption &&
            VIR_ALLOC(meta->encryption) < 0)
            goto cleanup;
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

int
virStorageFileParseChainIndex(const char *diskTarget,
                              const char *name,
                              unsigned int *chainIndex)
{
    char **strings = NULL;
    unsigned int idx = 0;
    char *suffix;
    int ret = 0;

    *chainIndex = 0;

    if (name && diskTarget)
        strings = virStringSplit(name, "[", 2);

    if (virStringListLength(strings) != 2)
        goto cleanup;

    if (virStrToLong_uip(strings[1], &suffix, 10, &idx) < 0 ||
        STRNEQ(suffix, "]"))
        goto cleanup;

    if (STRNEQ(diskTarget, strings[0])) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested target '%s' does not match target '%s'"),
                       strings[0], diskTarget);
        ret = -1;
        goto cleanup;
    }

    *chainIndex = idx;

 cleanup:
    virStringFreeList(strings);
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
    VIR_FREE(def->port);
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

        if (VIR_STRDUP(dst->name, src->name) < 0)
            goto error;

        if (VIR_STRDUP(dst->port, src->port) < 0)
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
    if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_USAGE)
        VIR_FREE(authdef->secret.usage);
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
    ret->secretType = src->secretType;
    if (ret->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
        memcpy(ret->secret.uuid, src->secret.uuid, sizeof(ret->secret.uuid));
    } else if (ret->secretType == VIR_STORAGE_SECRET_TYPE_USAGE) {
        if (VIR_STRDUP(ret->secret.usage, src->secret.usage) < 0)
            goto error;
    }
    return ret;

 error:
    virStorageAuthDefFree(ret);
    return NULL;
}


static int
virStorageAuthDefParseSecret(xmlXPathContextPtr ctxt,
                             virStorageAuthDefPtr authdef)
{
    char *uuid;
    char *usage;
    int ret = -1;

    /* Used by the domain disk xml parsing in order to ensure the
     * <secret type='%s' value matches the expected secret type for
     * the style of disk (iscsi is chap, nbd is ceph). For some reason
     * the virSecretUsageType{From|To}String() cannot be linked here
     * and because only the domain parsing code cares - just keep
     * it as a string.
     */
    authdef->secrettype = virXPathString("string(./secret/@type)", ctxt);

    uuid = virXPathString("string(./secret/@uuid)", ctxt);
    usage = virXPathString("string(./secret/@usage)", ctxt);
    if (uuid == NULL && usage == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing auth secret uuid or usage attribute"));
        goto cleanup;
    }

    if (uuid && usage) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("either auth secret uuid or usage expected"));
        goto cleanup;
    }

    if (uuid) {
        if (virUUIDParse(uuid, authdef->secret.uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                            _("invalid auth secret uuid"));
            goto cleanup;
        }
        authdef->secretType = VIR_STORAGE_SECRET_TYPE_UUID;
    } else {
        authdef->secret.usage = usage;
        usage = NULL;
        authdef->secretType = VIR_STORAGE_SECRET_TYPE_USAGE;
    }
    ret = 0;

 cleanup:
    VIR_FREE(uuid);
    VIR_FREE(usage);
    return ret;
}


static virStorageAuthDefPtr
virStorageAuthDefParseXML(xmlXPathContextPtr ctxt)
{
    virStorageAuthDefPtr authdef = NULL;
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

    authdef->secretType = VIR_STORAGE_SECRET_TYPE_NONE;
    if (virStorageAuthDefParseSecret(ctxt, authdef) < 0)
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
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE) {
        virBufferEscapeString(buf, "<auth username='%s'>\n", authdef->username);
    } else {
        virBufferAsprintf(buf, "<auth type='%s' ",
                          virStorageAuthTypeToString(authdef->authType));
        virBufferEscapeString(buf, "username='%s'>\n", authdef->username);
    }

    virBufferAdjustIndent(buf, 2);
    if (authdef->secrettype)
        virBufferAsprintf(buf, "<secret type='%s'", authdef->secrettype);
    else
        virBufferAddLit(buf, "<secret");

    if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
        virUUIDFormat(authdef->secret.uuid, uuidstr);
        virBufferAsprintf(buf, " uuid='%s'/>\n", uuidstr);
    } else if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_USAGE) {
        virBufferEscapeString(buf, " usage='%s'/>\n",
                              authdef->secret.usage);
    } else {
        virBufferAddLit(buf, "/>\n");
    }
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

    if (VIR_STRDUP(ret->label, src->label))
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
 * @transferLabels: Transfer security lables.
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
virStorageSourceGetActualType(virStorageSourcePtr def)
{
    if (def->type == VIR_STORAGE_TYPE_VOLUME && def->srcpool)
        return def->srcpool->actualtype;

    return def->type;
}


bool
virStorageSourceIsLocalStorage(virStorageSourcePtr src)
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

    virStorageSourceBackingStoreClear(def);
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

    if (uri->port > 0) {
        if (virAsprintf(&src->hosts->port, "%d", uri->port) < 0)
            goto cleanup;
    }

    if (VIR_STRDUP(src->hosts->name, uri->server) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virURIFree(uri);
    virStringFreeList(scheme);
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
        if (VIR_STRDUP(src->hosts[src->nhosts - 1].port, port) < 0)
            goto error;
    } else {
        if (VIR_STRDUP(src->hosts[src->nhosts - 1].port, "6789") < 0)
            goto error;
    }

    parts = virStringSplit(hostport, "\\:", 0);
    if (!parts)
        goto error;
    src->hosts[src->nhosts-1].name = virStringJoin((const char **)parts, ":");
    virStringFreeList(parts);
    if (!src->hosts[src->nhosts-1].name)
        goto error;

    src->hosts[src->nhosts-1].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    src->hosts[src->nhosts-1].socket = NULL;

    return 0;

 error:
    VIR_FREE(src->hosts[src->nhosts-1].port);
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
        if (!backing[1]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing host name in nbd string '%s'"),
                           nbdstr);
            goto cleanup;
        }

        if (VIR_STRDUP(src->hosts->name, backing[1]) < 0)
            goto cleanup;

        if (!backing[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing port in nbd string '%s'"),
                           nbdstr);
            goto cleanup;
        }

        if (VIR_STRDUP(src->hosts->port, backing[2]) < 0)
            goto cleanup;
    }

    if (backing[3] && STRPREFIX(backing[3], "exportname=")) {
        if (VIR_STRDUP(src->path, backing[3] + strlen("exportname=")) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virStringFreeList(backing);

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


static virStorageSourcePtr
virStorageSourceNewFromBackingAbsolute(const char *path)
{
    virStorageSourcePtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virStorageIsFile(path)) {
        ret->type = VIR_STORAGE_TYPE_FILE;

        if (VIR_STRDUP(ret->path, path) < 0)
            goto error;
    } else {
        ret->type = VIR_STORAGE_TYPE_NETWORK;

        /* handle URI formatted backing stores */
        if (strstr(path, "://")) {
            if (virStorageSourceParseBackingURI(ret, path) < 0)
                goto error;
        } else {
            if (virStorageSourceParseBackingColon(ret, path) < 0)
                goto error;
        }
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
 * @src: disk source definiton structure
 * @report: report libvirt errors if set to true
 *
 * Updates src->physical for block devices since qemu doesn't report the current
 * size correctly for them. Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateBlockPhysicalSize(virStorageSourcePtr src,
                                        bool report)
{
    int fd = -1;
    off_t end;
    int ret = -1;

    if (virStorageSourceGetActualType(src) != VIR_STORAGE_TYPE_BLOCK)
        return 0;

    if ((fd = open(src->path, O_RDONLY)) < 0) {
        if (report)
            virReportSystemError(errno, _("failed to open block device '%s'"),
                                 src->path);
        return -1;
    }

    if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1) {
        if (report)
            virReportSystemError(errno,
                                 _("failed to seek to end of '%s'"), src->path);
    } else {
        src->physical = end;
        ret = 0;
    }

    VIR_FORCE_CLOSE(fd);
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
    virStringFreeListCount(tmp, ntmp);
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
    virStringFreeListCount(components, ncomponents);
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
    char *tmp;
    char *ret;

    if (VIR_STRDUP(ret, path ? path : "") < 0)
        return NULL;

    if ((tmp = strrchr(ret, '/')))
        tmp[1] = '\0';
    else
        ret[0] = '\0';

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
    virStringFreeList(version);
    return ret;
}
