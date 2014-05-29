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
#include "dirname.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "c-ctype.h"
#include "vircommand.h"
#include "virhash.h"
#include "virendian.h"
#include "virstring.h"
#include "virutil.h"
#if HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif

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

#define QCOW1_HDR_CRYPT (QCOWX_HDR_IMAGE_SIZE+8+1+1)
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
    size = virReadBufInt32BE(buf + QCOWX_HDR_BACKING_FILE_SIZE);
    if (size == 0) {
        if (format)
            *format = VIR_STORAGE_FILE_NONE;
        return BACKING_STORE_OK;
    }
    if (offset + size > buf_size || offset + size < offset)
        return BACKING_STORE_INVALID;
    if (size + 1 == 0)
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

/**
 * Given a starting point START (a directory containing the original
 * file, if the original file was opened via a relative path; ignored
 * if NAME is absolute), determine the location of the backing file
 * NAME (possibly relative), and compute the relative DIRECTORY
 * (optional) and CANONICAL (mandatory) location of the backing file.
 * Return 0 on success, negative on error.
 */
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
virFindBackingFile(const char *start, const char *path,
                   char **directory, char **canonical)
{
    /* FIXME - when we eventually allow non-raw network devices, we
     * must ensure that we handle backing files the same way as qemu.
     * For a qcow2 top file of gluster://server/vol/img, qemu treats
     * the relative backing file 'rel' as meaning
     * 'gluster://server/vol/rel', while the backing file '/abs' is
     * used as a local file.  But we cannot canonicalize network
     * devices via canonicalize_file_name(), because they are not part
     * of the local file system.  */
    char *combined = NULL;
    int ret = -1;

    if (*path == '/') {
        /* Safe to cast away const */
        combined = (char *)path;
    } else if (virAsprintf(&combined, "%s/%s", start, path) < 0) {
        goto cleanup;
    }

    if (directory && !(*directory = mdir_name(combined))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileAccessibleAs(combined, F_OK, geteuid(), getegid()) < 0) {
        virReportSystemError(errno,
                             _("Cannot access backing file '%s'"),
                             combined);
        goto cleanup;
    }

    if (!(*canonical = canonicalize_file_name(combined))) {
        virReportSystemError(errno,
                             _("Can't canonicalize path '%s'"), path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (combined != path)
        VIR_FREE(combined);
    return ret;
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
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
ATTRIBUTE_NONNULL(4)
virStorageFileGetMetadataInternal(virStorageSourcePtr meta,
                                  char *buf,
                                  size_t len,
                                  int *backingFormat)
{
    int ret = -1;

    VIR_DEBUG("relPath=%s, buf=%p, len=%zu, meta->format=%d",
              meta->relPath, buf, len, meta->format);

    if (meta->format == VIR_STORAGE_FILE_AUTO)
        meta->format = virStorageFileProbeFormatFromBuf(meta->relPath, buf, len);

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
        if (crypt_format && VIR_ALLOC(meta->encryption) < 0)
            goto cleanup;
    }

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

    if (VIR_STRDUP(ret->relPath, path) < 0)
        goto error;

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
 * @backing: output malloc'd name of backing image, if any
 * @backingFormat: format of @backing
 *
 * Extract metadata about the storage volume, including probing its
 * format.  Does not recurse.  Callers are advised not to trust the
 * learned format if a guest has ever used the volume when it was
 * raw, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If the returned @backingFormat is VIR_STORAGE_FILE_AUTO
 * it indicates the image didn't specify an explicit format for its
 * backing store. Callers are advised against probing for the
 * backing store format in this case.
 *
 * Caller MUST free the result after use via virStorageSourceFree.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromBuf(const char *path,
                                 char *buf,
                                 size_t len,
                                 char **backing,
                                 int *backingFormat)
{
    virStorageSourcePtr ret = NULL;
    virStorageSourcePtr meta = NULL;

    if (!(meta = virStorageFileMetadataNew(path, VIR_STORAGE_FILE_AUTO)))
        return NULL;

    if (virStorageFileGetMetadataInternal(meta, buf, len,
                                          backingFormat) < 0)
        goto cleanup;
    if (VIR_STRDUP(*backing, meta->backingStoreRaw) < 0)
        goto cleanup;

    ret = meta;
    meta = NULL;
 cleanup:
    virStorageSourceFree(meta);
    return ret;
}


/* Internal version that also supports a containing directory name.  */
static int
virStorageFileGetMetadataFromFDInternal(virStorageSourcePtr meta,
                                        int fd,
                                        int *backingFormat)
{
    char *buf = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    struct stat sb;
    int ret = -1;
    int dummy;

    if (!backingFormat)
        backingFormat = &dummy;

    *backingFormat = VIR_STORAGE_FILE_NONE;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             meta->relPath);
        return -1;
    }

    if (S_ISDIR(sb.st_mode)) {
        /* No header to probe for directories, but also no backing file. Just
         * update the metadata.*/
        meta->type = VIR_STORAGE_TYPE_DIR;
        meta->format = VIR_STORAGE_FILE_DIR;
        ret = 0;
        goto cleanup;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%s'"), meta->relPath);
        goto cleanup;
    }

    if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), meta->relPath);
        goto cleanup;
    }

    ret = virStorageFileGetMetadataInternal(meta, buf, len, backingFormat);

    if (ret == 0) {
        if (S_ISREG(sb.st_mode))
            meta->type = VIR_STORAGE_TYPE_FILE;
        else if (S_ISBLK(sb.st_mode))
            meta->type = VIR_STORAGE_TYPE_BLOCK;
    }
 cleanup:
    VIR_FREE(buf);
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
    char *canonPath = NULL;

    if (!(canonPath = canonicalize_file_name(path))) {
        virReportSystemError(errno, _("unable to resolve '%s'"), path);
        goto cleanup;
    }

    if (!(ret = virStorageFileMetadataNew(canonPath, format)))
        goto cleanup;


    if (virStorageFileGetMetadataFromFDInternal(ret, fd, backingFormat) < 0) {
        virStorageSourceFree(ret);
        ret = NULL;
    }

 cleanup:
    VIR_FREE(canonPath);
    return ret;
}


/* Recursive workhorse for virStorageFileGetMetadata.  */
static int
virStorageFileGetMetadataRecurse(virStorageSourcePtr src,
                                 const char *canonPath,
                                 uid_t uid, gid_t gid,
                                 bool allow_probe,
                                 virHashTablePtr cycle)
{
    int fd;
    int ret = -1;
    virStorageSourcePtr backingStore = NULL;
    int backingFormat;

    VIR_DEBUG("path=%s canonPath=%s dir=%s format=%d uid=%d gid=%d probe=%d",
              src->path, canonPath, NULLSTR(src->relDir), src->format,
              (int)uid, (int)gid, allow_probe);

    if (virHashLookup(cycle, canonPath)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %s is self-referential"),
                       src->path);
        return -1;
    }

    if (virHashAddEntry(cycle, canonPath, (void *)1) < 0)
        return -1;

    if (virStorageSourceGetActualType(src) != VIR_STORAGE_TYPE_NETWORK) {
        if ((fd = virFileOpenAs(src->path, O_RDONLY, 0, uid, gid, 0)) < 0) {
            virReportSystemError(-fd, _("Failed to open file '%s'"),
                                 src->path);
            return -1;
        }

        if (virStorageFileGetMetadataFromFDInternal(src, fd,
                                                    &backingFormat) < 0) {
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        if (VIR_CLOSE(fd) < 0)
            VIR_WARN("could not close file %s", src->path);
    } else {
        /* TODO: currently we call this only for local storage */
        return 0;
    }

    /* check whether we need to go deeper */
    if (!src->backingStoreRaw)
        return 0;

    if (VIR_ALLOC(backingStore) < 0)
        return -1;

    if (VIR_STRDUP(backingStore->relPath, src->backingStoreRaw) < 0)
        goto cleanup;

    if (virStorageIsFile(src->backingStoreRaw)) {
        backingStore->type = VIR_STORAGE_TYPE_FILE;

        if (virFindBackingFile(src->relDir,
                               src->backingStoreRaw,
                               &backingStore->relDir,
                               &backingStore->path) < 0) {
            /* the backing file is (currently) unavailable, treat this
             * file as standalone:
             * backingStoreRaw is kept to mark broken image chains */
            VIR_WARN("Backing file '%s' of image '%s' is missing.",
                     src->backingStoreRaw, src->path);
            ret = 0;
            goto cleanup;
        }
    } else {
        /* TODO: To satisfy the test case, copy the network URI as path. This
         * will be removed later. */
        backingStore->type = VIR_STORAGE_TYPE_NETWORK;

        if (VIR_STRDUP(backingStore->path, src->backingStoreRaw) < 0)
            goto cleanup;
    }

    if (backingFormat == VIR_STORAGE_FILE_AUTO && !allow_probe)
        backingStore->format = VIR_STORAGE_FILE_RAW;
    else if (backingFormat == VIR_STORAGE_FILE_AUTO_SAFE)
        backingStore->format = VIR_STORAGE_FILE_AUTO;
    else
        backingStore->format = backingFormat;

    if (virStorageFileGetMetadataRecurse(backingStore,
                                         backingStore->path,
                                         uid, gid, allow_probe,
                                         cycle) < 0) {
        /* if we fail somewhere midway, just accept and return a
         * broken chain */
        ret = 0;
        goto cleanup;
    }

    src->backingStore = backingStore;
    backingStore = NULL;
    ret = 0;

 cleanup:
    virStorageSourceFree(backingStore);
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
 * Caller MUST free result after use via virStorageSourceFree.
 */
int
virStorageFileGetMetadata(virStorageSourcePtr src,
                          uid_t uid, gid_t gid,
                          bool allow_probe)
{
    VIR_DEBUG("path=%s format=%d uid=%d gid=%d probe=%d",
              src->path, src->format, (int)uid, (int)gid, allow_probe);

    virHashTablePtr cycle = NULL;
    char *canonPath = NULL;
    int ret = -1;

    if (!(cycle = virHashCreate(5, NULL)))
        return -1;

    if (virStorageSourceGetActualType(src) != VIR_STORAGE_TYPE_NETWORK) {
        if (!(canonPath = canonicalize_file_name(src->path))) {
            virReportSystemError(errno, _("unable to resolve '%s'"),
                                 src->path);
            goto cleanup;
        }

        if (!src->relPath &&
            VIR_STRDUP(src->relPath, src->path) < 0)
            goto cleanup;

        if (!src->relDir &&
            !(src->relDir = mdir_name(src->path))) {
            virReportOOMError();
            goto cleanup;
        }
    } else {
        /* TODO: currently unimplemented for non-local storage */
        ret = 0;
        goto cleanup;
    }

    if (src->format <= VIR_STORAGE_FILE_NONE)
        src->format = allow_probe ? VIR_STORAGE_FILE_AUTO : VIR_STORAGE_FILE_RAW;

    ret = virStorageFileGetMetadataRecurse(src, canonPath, uid, gid,
                                           allow_probe, cycle);

 cleanup:
    VIR_FREE(canonPath);
    virHashFree(cycle);
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
#if HAVE_POSIX_FALLOCATE
        if ((rc = posix_fallocate(fd, offset, len)) != 0) {
            virReportSystemError(rc,
                                 _("Failed to pre-allocate space for "
                                   "file '%s'"), path);
            goto cleanup;
        }
#elif HAVE_SYS_SYSCALL_H && defined(SYS_fallocate)
        if (syscall(SYS_fallocate, fd, 0, offset, len) != 0) {
            virReportSystemError(errno,
                                 _("Failed to pre-allocate space for "
                                   "file '%s'"), path);
            goto cleanup;
        }
#else
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("preallocate is not supported on this platform"));
        goto cleanup;
#endif
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
        while (*tmp && c_isspace(*tmp)) {
            tmp++;
        }
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

/* Given a @chain, look for the backing store @name within the chain starting
 * from @startFrom or @chain if @startFrom is NULL and return that location
 * within the chain.  @chain must always point to the top of the chain.  Pass
 * NULL for @name and 0 for @idx to find the base of the chain.  Pass nonzero
 * @idx to find the backing source according to its position in the backing
 * chain.  If @parent is not NULL, set *@parent to the preferred name of the
 * parent (or to NULL if @name matches the start of the chain).  Since the
 * results point within @chain, they must not be independently freed.
 * Reports an error and returns NULL if @name is not found.
 */
virStorageSourcePtr
virStorageFileChainLookup(virStorageSourcePtr chain,
                          virStorageSourcePtr startFrom,
                          const char *name,
                          unsigned int idx,
                          const char **parent)
{
    const char *start = chain->path;
    const char *tmp;
    const char *parentDir = ".";
    bool nameIsFile = virStorageIsFile(name);
    size_t i;

    if (!parent)
        parent = &tmp;
    *parent = NULL;

    i = 0;
    if (startFrom) {
        while (chain && chain != startFrom) {
            chain = chain->backingStore;
            i++;
        }
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
            if (STREQ_NULLABLE(name, chain->relPath))
                break;
            if (nameIsFile && (chain->type == VIR_STORAGE_TYPE_FILE ||
                               chain->type == VIR_STORAGE_TYPE_BLOCK)) {
                int result = virFileRelLinkPointsTo(parentDir, name,
                                                    chain->path);
                if (result < 0)
                    goto error;
                if (result > 0)
                    break;
            }
        }
        *parent = chain->path;
        parentDir = chain->relDir;
        chain = chain->backingStore;
        i++;
    }

    if (!chain)
        goto error;
    return chain;

 error:
    if (idx) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find backing store %u in chain for '%s'"),
                       idx, start);
    } else if (name) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find image '%s' in chain for '%s'"),
                       name, start);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find base image in chain for '%s'"),
                       start);
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
virStorageSourcePoolDefFree(virStorageSourcePoolDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->pool);
    VIR_FREE(def->volume);

    VIR_FREE(def);
}


void
virStorageSourceAuthClear(virStorageSourcePtr def)
{
    VIR_FREE(def->auth.username);

    if (def->auth.secretType == VIR_STORAGE_SECRET_TYPE_USAGE)
        VIR_FREE(def->auth.secret.usage);

    def->auth.secretType = VIR_STORAGE_SECRET_TYPE_NONE;
}


int
virStorageSourceGetActualType(virStorageSourcePtr def)
{
    if (def->type == VIR_STORAGE_TYPE_VOLUME && def->srcpool)
        return def->srcpool->actualtype;

    return def->type;
}


/**
 * virStorageSourceClearBackingStore:
 *
 * @src: disk source to clear
 *
 * Clears information about backing store of the current storage file.
 */
void
virStorageSourceClearBackingStore(virStorageSourcePtr def)
{
    if (!def)
        return;

    VIR_FREE(def->relPath);
    VIR_FREE(def->relDir);
    VIR_FREE(def->backingStoreRaw);

    /* recursively free backing chain */
    virStorageSourceFree(def->backingStore);
    def->backingStore = NULL;
}


void
virStorageSourceClear(virStorageSourcePtr def)
{
    size_t i;

    if (!def)
        return;

    VIR_FREE(def->path);
    VIR_FREE(def->volume);
    virStorageSourcePoolDefFree(def->srcpool);
    VIR_FREE(def->driverName);
    virBitmapFree(def->features);
    VIR_FREE(def->compat);
    virStorageEncryptionFree(def->encryption);

    if (def->seclabels) {
        for (i = 0; i < def->nseclabels; i++)
            virSecurityDeviceLabelDefFree(def->seclabels[i]);
        VIR_FREE(def->seclabels);
    }
    if (def->perms) {
        VIR_FREE(def->perms->label);
        VIR_FREE(def->perms);
    }
    VIR_FREE(def->timestamps);

    virStorageNetHostDefFree(def->nhosts, def->hosts);
    virStorageSourceAuthClear(def);

    virStorageSourceClearBackingStore(def);
}


void
virStorageSourceFree(virStorageSourcePtr def)
{
    if (!def)
        return;

    virStorageSourceClear(def);
    VIR_FREE(def);
}
