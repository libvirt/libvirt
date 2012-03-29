/*
 * storage_file.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "storage_file.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef __linux__
# if HAVE_LINUX_MAGIC_H
#  include <linux/magic.h>
# endif
# include <sys/statfs.h>
#endif
#include "dirname.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_ENUM_IMPL(virStorageFileFormat,
              VIR_STORAGE_FILE_LAST,
              "raw", "dir", "bochs",
              "cloop", "cow", "dmg", "iso",
              "qcow", "qcow2", "qed", "vmdk", "vpc")

enum lv_endian {
    LV_LITTLE_ENDIAN = 1, /* 1234 */
    LV_BIG_ENDIAN         /* 4321 */
};

enum {
    BACKING_STORE_OK,
    BACKING_STORE_INVALID,
    BACKING_STORE_ERROR,
};

/* Either 'magic' or 'extension' *must* be provided */
struct FileTypeInfo {
    const char *magic;  /* Optional string of file magic
                         * to check at head of file */
    const char *extension; /* Optional file extension to check */
    enum lv_endian endian; /* Endianness of file format */
    int versionOffset;    /* Byte offset from start of file
                           * where we find version number,
                           * -1 to skip version test */
    int versionNumber;    /* Version number to validate */
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
                           const unsigned char *buf, size_t buf_size);
};

static int cowGetBackingStore(char **, int *,
                              const unsigned char *, size_t);
static int qcow1GetBackingStore(char **, int *,
                                const unsigned char *, size_t);
static int qcow2GetBackingStore(char **, int *,
                                const unsigned char *, size_t);
static int vmdk4GetBackingStore(char **, int *,
                                const unsigned char *, size_t);
static int
qedGetBackingStore(char **, int *, const unsigned char *, size_t);

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

#define QED_HDR_FEATURES_OFFSET (4+4+4+4)
#define QED_HDR_IMAGE_SIZE (QED_HDR_FEATURES_OFFSET+8+8+8+8)
#define QED_HDR_BACKING_FILE_OFFSET (QED_HDR_IMAGE_SIZE+8)
#define QED_HDR_BACKING_FILE_SIZE (QED_HDR_BACKING_FILE_OFFSET+4)
#define QED_F_BACKING_FILE 0x01
#define QED_F_BACKING_FORMAT_NO_PROBE 0x04

/* VMDK needs at least this to find backing store,
 * other formats need less */
#define STORAGE_MAX_HEAD (20*512)


static struct FileTypeInfo const fileTypeInfo[] = {
    [VIR_STORAGE_FILE_RAW] = { NULL, NULL, LV_LITTLE_ENDIAN, -1, 0, 0, 0, 0, 0, NULL },
    [VIR_STORAGE_FILE_DIR] = { NULL, NULL, LV_LITTLE_ENDIAN, -1, 0, 0, 0, 0, 0, NULL },
    [VIR_STORAGE_FILE_BOCHS] = {
        /*"Bochs Virtual HD Image", */ /* Untested */ NULL,
        NULL,
        LV_LITTLE_ENDIAN, 64, 0x20000,
        32+16+16+4+4+4+4+4, 8, 1, -1, NULL
    },
    [VIR_STORAGE_FILE_CLOOP] = {
        /*"#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n", */ /* Untested */ NULL,
        NULL,
        LV_LITTLE_ENDIAN, -1, 0,
        -1, 0, 0, -1, NULL
    },
    [VIR_STORAGE_FILE_COW] = {
        "OOOM", NULL,
        LV_BIG_ENDIAN, 4, 2,
        4+4+1024+4, 8, 1, -1, cowGetBackingStore
    },
    [VIR_STORAGE_FILE_DMG] = {
        NULL, /* XXX QEMU says there's no magic for dmg, but we should check... */
        ".dmg",
        0, -1, 0,
        -1, 0, 0, -1, NULL
    },
    [VIR_STORAGE_FILE_ISO] = {
        NULL, /* XXX there's probably some magic for iso we can validate too... */
        ".iso",
        0, -1, 0,
        -1, 0, 0, -1, NULL
    },
    [VIR_STORAGE_FILE_QCOW] = {
        "QFI", NULL,
        LV_BIG_ENDIAN, 4, 1,
        QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW1_HDR_CRYPT, qcow1GetBackingStore,
    },
    [VIR_STORAGE_FILE_QCOW2] = {
        "QFI", NULL,
        LV_BIG_ENDIAN, 4, 2,
        QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW2_HDR_CRYPT, qcow2GetBackingStore,
    },
    [VIR_STORAGE_FILE_QED] = {
        /* http://wiki.qemu.org/Features/QED */
        "QED\0", NULL,
        LV_LITTLE_ENDIAN, -1, -1,
        QED_HDR_IMAGE_SIZE, 8, 1, -1, qedGetBackingStore,
    },
    [VIR_STORAGE_FILE_VMDK] = {
        "KDMV", NULL,
        LV_LITTLE_ENDIAN, 4, 1,
        4+4+4, 8, 512, -1, vmdk4GetBackingStore
    },
    [VIR_STORAGE_FILE_VPC] = {
        "conectix", NULL,
        LV_BIG_ENDIAN, 12, 0x10000,
        8 + 4 + 4 + 8 + 4 + 4 + 2 + 2 + 4, 8, 1, -1, NULL
    },
};
verify(ARRAY_CARDINALITY(fileTypeInfo) == VIR_STORAGE_FILE_LAST);

static int
cowGetBackingStore(char **res,
                   int *format,
                   const unsigned char *buf,
                   size_t buf_size)
{
#define COW_FILENAME_MAXLEN 1024
    *res = NULL;
    *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size < 4+4+ COW_FILENAME_MAXLEN)
        return BACKING_STORE_INVALID;
    if (buf[4+4] == '\0') /* cow_header_v2.backing_file[0] */
        return BACKING_STORE_OK;

    *res = strndup ((const char*)buf + 4+4, COW_FILENAME_MAXLEN);
    if (*res == NULL) {
        virReportOOMError();
        return BACKING_STORE_ERROR;
    }
    return BACKING_STORE_OK;
}


static int
qcow2GetBackingStoreFormat(int *format,
                           const unsigned char *buf,
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
        unsigned int magic =
            (buf[offset] << 24) +
            (buf[offset+1] << 16) +
            (buf[offset+2] << 8) +
            (buf[offset+3]);
        unsigned int len =
            (buf[offset+4] << 24) +
            (buf[offset+5] << 16) +
            (buf[offset+6] << 8) +
            (buf[offset+7]);

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
            break;
        }

        offset += len;
    }

done:

    return 0;
}


static int
qcowXGetBackingStore(char **res,
                     int *format,
                     const unsigned char *buf,
                     size_t buf_size,
                     bool isQCow2)
{
    unsigned long long offset;
    unsigned int size;

    *res = NULL;
    if (format)
        *format = VIR_STORAGE_FILE_AUTO;

    if (buf_size < QCOWX_HDR_BACKING_FILE_OFFSET+8+4)
        return BACKING_STORE_INVALID;
    offset = (((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET] << 56)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+1] << 48)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+2] << 40)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+3] << 32)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+4] << 24)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+5] << 16)
              | ((unsigned long long)buf[QCOWX_HDR_BACKING_FILE_OFFSET+6] << 8)
              | buf[QCOWX_HDR_BACKING_FILE_OFFSET+7]); /* QCowHeader.backing_file_offset */
    if (offset > buf_size)
        return BACKING_STORE_INVALID;
    size = ((buf[QCOWX_HDR_BACKING_FILE_SIZE] << 24)
            | (buf[QCOWX_HDR_BACKING_FILE_SIZE+1] << 16)
            | (buf[QCOWX_HDR_BACKING_FILE_SIZE+2] << 8)
            | buf[QCOWX_HDR_BACKING_FILE_SIZE+3]); /* QCowHeader.backing_file_size */
    if (size == 0)
        return BACKING_STORE_OK;
    if (offset + size > buf_size || offset + size < offset)
        return BACKING_STORE_INVALID;
    if (size + 1 == 0)
        return BACKING_STORE_INVALID;
    if (VIR_ALLOC_N(*res, size + 1) < 0) {
        virReportOOMError();
        return BACKING_STORE_ERROR;
    }
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
     */
    if (isQCow2 && format)
        qcow2GetBackingStoreFormat(format, buf, buf_size, QCOW2_HDR_TOTAL_SIZE, offset);

    return BACKING_STORE_OK;
}


static int
qcow1GetBackingStore(char **res,
                     int *format,
                     const unsigned char *buf,
                     size_t buf_size)
{
    /* QCow1 doesn't have the extensions capability
     * used to store backing format */
    *format = VIR_STORAGE_FILE_AUTO;
    return qcowXGetBackingStore(res, NULL, buf, buf_size, false);
}

static int
qcow2GetBackingStore(char **res,
                     int *format,
                     const unsigned char *buf,
                     size_t buf_size)
{
    return qcowXGetBackingStore(res, format, buf, buf_size, true);
}


static int
vmdk4GetBackingStore(char **res,
                     int *format,
                     const unsigned char *buf,
                     size_t buf_size)
{
    static const char prefix[] = "parentFileNameHint=\"";
    char *desc, *start, *end;
    size_t len;
    int ret = BACKING_STORE_ERROR;

    if (VIR_ALLOC_N(desc, STORAGE_MAX_HEAD + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

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
    if (len > STORAGE_MAX_HEAD)
        len = STORAGE_MAX_HEAD;
    memcpy(desc, buf + 0x200, len);
    desc[len] = '\0';
    start = strstr(desc, prefix);
    if (start == NULL) {
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
        ret = BACKING_STORE_OK;
        goto cleanup;
    }
    *end = '\0';
    *res = strdup(start);
    if (*res == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ret = BACKING_STORE_OK;

cleanup:
    VIR_FREE(desc);
    return ret;
}

static unsigned long
qedGetHeaderUL(const unsigned char *loc)
{
    return ( ((unsigned long)loc[3] << 24)
           | ((unsigned long)loc[2] << 16)
           | ((unsigned long)loc[1] << 8)
           | ((unsigned long)loc[0] << 0));
}

static unsigned long long
qedGetHeaderULL(const unsigned char *loc)
{
    return ( ((unsigned long long)loc[7] << 56)
           | ((unsigned long long)loc[6] << 48)
           | ((unsigned long long)loc[5] << 40)
           | ((unsigned long long)loc[4] << 32)
           | ((unsigned long long)loc[3] << 24)
           | ((unsigned long long)loc[2] << 16)
           | ((unsigned long long)loc[1] << 8)
           | ((unsigned long long)loc[0] << 0));
}

static int
qedGetBackingStore(char **res,
                   int *format,
                   const unsigned char *buf,
                   size_t buf_size)
{
    unsigned long long flags;
    unsigned long offset, size;

    *res = NULL;
    /* Check if this image has a backing file */
    if (buf_size < QED_HDR_FEATURES_OFFSET+8)
        return BACKING_STORE_INVALID;
    flags = qedGetHeaderULL(buf + QED_HDR_FEATURES_OFFSET);
    if (!(flags & QED_F_BACKING_FILE))
        return BACKING_STORE_OK;

    /* Parse the backing file */
    if (buf_size < QED_HDR_BACKING_FILE_OFFSET+8)
        return BACKING_STORE_INVALID;
    offset = qedGetHeaderUL(buf + QED_HDR_BACKING_FILE_OFFSET);
    if (offset > buf_size)
        return BACKING_STORE_INVALID;
    size = qedGetHeaderUL(buf + QED_HDR_BACKING_FILE_SIZE);
    if (size == 0)
        return BACKING_STORE_OK;
    if (offset + size > buf_size || offset + size < offset)
        return BACKING_STORE_INVALID;
    if (VIR_ALLOC_N(*res, size + 1) < 0) {
        virReportOOMError();
        return BACKING_STORE_ERROR;
    }
    memcpy(*res, buf + offset, size);
    (*res)[size] = '\0';

    if (format) {
        if (flags & QED_F_BACKING_FORMAT_NO_PROBE)
            *format = virStorageFileFormatTypeFromString("raw");
        else
            *format = VIR_STORAGE_FILE_AUTO_SAFE;
    }

    return BACKING_STORE_OK;
}

/**
 * Return an absolute path corresponding to PATH, which is absolute or relative
 * to the directory containing BASE_FILE, or NULL on error
 */
static char *
absolutePathFromBaseFile(const char *base_file, const char *path)
{
    char *res;
    size_t d_len = dir_len (base_file);

    /* If path is already absolute, or if dirname(base_file) is ".",
       just return a copy of path.  */
    if (*path == '/' || d_len == 0)
        return strdup(path);

    /* Ensure that the following cast-to-int is valid.  */
    if (d_len > INT_MAX)
        return NULL;

    ignore_value(virAsprintf(&res, "%.*s/%s", (int) d_len, base_file, path));
    return res;
}


static bool
virStorageFileMatchesMagic(int format,
                           unsigned char *buf,
                           size_t buflen)
{
    int mlen;

    if (fileTypeInfo[format].magic == NULL)
        return false;

    /* Validate magic data */
    mlen = strlen(fileTypeInfo[format].magic);
    if (mlen > buflen)
        return false;

    if (memcmp(buf, fileTypeInfo[format].magic, mlen) != 0)
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
                             unsigned char *buf,
                             size_t buflen)
{
    int version;

    /* Validate version number info */
    if (fileTypeInfo[format].versionOffset == -1)
        return true;

    if ((fileTypeInfo[format].versionOffset + 4) > buflen)
        return false;

    if (fileTypeInfo[format].endian == LV_LITTLE_ENDIAN) {
        version =
            (buf[fileTypeInfo[format].versionOffset+3] << 24) |
            (buf[fileTypeInfo[format].versionOffset+2] << 16) |
            (buf[fileTypeInfo[format].versionOffset+1] << 8) |
            (buf[fileTypeInfo[format].versionOffset]);
    } else {
        version =
            (buf[fileTypeInfo[format].versionOffset] << 24) |
            (buf[fileTypeInfo[format].versionOffset+1] << 16) |
            (buf[fileTypeInfo[format].versionOffset+2] << 8) |
            (buf[fileTypeInfo[format].versionOffset+3]);
    }
    if (version != fileTypeInfo[format].versionNumber)
        return false;

    return true;
}

static bool
virBackingStoreIsFile(const char *backing)
{
    /* Backing store is a network block device */
    if (STRPREFIX(backing, "nbd:"))
        return false;
    return true;
}

static int
virStorageFileGetMetadataFromBuf(int format,
                                 const char *path,
                                 unsigned char *buf,
                                 size_t buflen,
                                 virStorageFileMetadata *meta)
{
    /* XXX we should consider moving virStorageBackendUpdateVolInfo
     * code into this method, for non-magic files
     */
    if (!fileTypeInfo[format].magic) {
        return 0;
    }

    /* Optionally extract capacity from file */
    if (fileTypeInfo[format].sizeOffset != -1) {
        if ((fileTypeInfo[format].sizeOffset + 8) > buflen)
            return 1;

        if (fileTypeInfo[format].endian == LV_LITTLE_ENDIAN) {
            meta->capacity =
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+7] << 56) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+6] << 48) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+5] << 40) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+4] << 32) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+3] << 24) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+2] << 16) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+1] << 8) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset]);
        } else {
            meta->capacity =
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset] << 56) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+1] << 48) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+2] << 40) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+3] << 32) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+4] << 24) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+5] << 16) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+6] << 8) |
                ((unsigned long long)buf[fileTypeInfo[format].sizeOffset+7]);
        }
        /* Avoid unlikely, but theoretically possible overflow */
        if (meta->capacity > (ULLONG_MAX / fileTypeInfo[format].sizeMultiplier))
            return 1;
        meta->capacity *= fileTypeInfo[format].sizeMultiplier;
    }

    if (fileTypeInfo[format].qcowCryptOffset != -1) {
        int crypt_format;

        crypt_format =
            (buf[fileTypeInfo[format].qcowCryptOffset] << 24) |
            (buf[fileTypeInfo[format].qcowCryptOffset+1] << 16) |
            (buf[fileTypeInfo[format].qcowCryptOffset+2] << 8) |
            (buf[fileTypeInfo[format].qcowCryptOffset+3]);
        meta->encrypted = crypt_format != 0;
    }

    if (fileTypeInfo[format].getBackingStore != NULL) {
        char *backing;
        int backingFormat;
        int ret = fileTypeInfo[format].getBackingStore(&backing,
                                                       &backingFormat,
                                                       buf, buflen);
        if (ret == BACKING_STORE_INVALID)
            return 1;

        if (ret == BACKING_STORE_ERROR)
            return -1;

        meta->backingStoreIsFile = false;
        if (backing != NULL) {
            if (virBackingStoreIsFile(backing)) {
                meta->backingStoreIsFile = true;
                meta->backingStore = absolutePathFromBaseFile(path, backing);
            } else {
                meta->backingStore = strdup(backing);
            }
            VIR_FREE(backing);
            if (meta->backingStore == NULL) {
                virReportOOMError();
                return -1;
            }
            meta->backingStoreFormat = backingFormat;
        } else {
            meta->backingStore = NULL;
            meta->backingStoreFormat = VIR_STORAGE_FILE_AUTO;
        }
    }

    return 0;
}


static int
virStorageFileProbeFormatFromBuf(const char *path,
                                 unsigned char *buf,
                                 size_t buflen)
{
    int format = VIR_STORAGE_FILE_RAW;
    int i;

    /* First check file magic */
    for (i = 0 ; i < VIR_STORAGE_FILE_LAST ; i++) {
        if (virStorageFileMatchesMagic(i, buf, buflen) &&
            virStorageFileMatchesVersion(i, buf, buflen)) {
            format = i;
            goto cleanup;
        }
    }

    /* No magic, so check file extension */
    for (i = 0 ; i < VIR_STORAGE_FILE_LAST ; i++) {
        if (virStorageFileMatchesExtension(i, path)) {
            format = i;
            goto cleanup;
        }
    }

cleanup:
    return format;
}


/**
 * virStorageFileProbeFormatFromFD:
 *
 * Probe for the format of 'fd' (which is an open file descriptor
 * pointing to 'path'), returning the detected disk format.
 *
 * Callers are advised never to trust the returned 'format'
 * unless it is listed as VIR_STORAGE_FILE_RAW, since a
 * malicious guest can turn a file into any other non-raw
 * format at will.
 *
 * Best option: Don't use this function
 */
int
virStorageFileProbeFormatFromFD(const char *path, int fd)
{
    unsigned char *head;
    ssize_t len = STORAGE_MAX_HEAD;
    int ret = -1;
    struct stat sb;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             path);
        return -1;
    }

    /* No header to probe for directories */
    if (S_ISDIR(sb.st_mode)) {
        return VIR_STORAGE_FILE_DIR;
    }

    if (VIR_ALLOC_N(head, len) < 0) {
        virReportOOMError();
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot set to start of '%s'"), path);
        goto cleanup;
    }

    if ((len = read(fd, head, len)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), path);
        goto cleanup;
    }

    ret = virStorageFileProbeFormatFromBuf(path, head, len);

cleanup:
    VIR_FREE(head);
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
virStorageFileProbeFormat(const char *path)
{
    int fd, ret;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("cannot open file '%s'"), path);
        return -1;
    }

    ret = virStorageFileProbeFormatFromFD(path, fd);

    VIR_FORCE_CLOSE(fd);

    return ret;
}

/**
 * virStorageFileGetMetadataFromFD:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If the returned meta.backingStoreFormat is VIR_STORAGE_FILE_AUTO
 * it indicates the image didn't specify an explicit format for its
 * backing store. Callers are advised against probing for the
 * backing store format in this case.
 *
 * Caller MUST free @meta after use via virStorageFileFreeMetadata.
 */
int
virStorageFileGetMetadataFromFD(const char *path,
                                int fd,
                                int format,
                                virStorageFileMetadata *meta)
{
    unsigned char *head = NULL;
    ssize_t len = STORAGE_MAX_HEAD;
    int ret = -1;
    struct stat sb;

    memset(meta, 0, sizeof(*meta));

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"),
                             path);
        return -1;
    }

    /* No header to probe for directories */
    if (S_ISDIR(sb.st_mode)) {
        return 0;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%s'"), path);
        return -1;
    }

    if (VIR_ALLOC_N(head, len) < 0) {
        virReportOOMError();
        return -1;
    }

    if ((len = read(fd, head, len)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), path);
        goto cleanup;
    }

    if (format == VIR_STORAGE_FILE_AUTO)
        format = virStorageFileProbeFormatFromBuf(path, head, len);

    if (format < 0 ||
        format >= VIR_STORAGE_FILE_LAST) {
        virReportSystemError(EINVAL, _("unknown storage file format %d"),
                             format);
        goto cleanup;
    }

    ret = virStorageFileGetMetadataFromBuf(format, path, head, len, meta);

cleanup:
    VIR_FREE(head);
    return ret;
}

/**
 * virStorageFileGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If the returned meta.backingStoreFormat is VIR_STORAGE_FILE_AUTO
 * it indicates the image didn't specify an explicit format for its
 * backing store. Callers are advised against probing for the
 * backing store format in this case.
 *
 * Caller MUST free @meta after use via virStorageFileFreeMetadata.
 */
int
virStorageFileGetMetadata(const char *path,
                          int format,
                          virStorageFileMetadata *meta)
{
    int fd, ret;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("cannot open file '%s'"), path);
        return -1;
    }

    ret = virStorageFileGetMetadataFromFD(path, fd, format, meta);

    VIR_FORCE_CLOSE(fd);

    return ret;
}

/**
 * virStorageFileFreeMetadata:
 *
 * Free pointers in passed structure and structure itself.
 */
void
virStorageFileFreeMetadata(virStorageFileMetadata *meta)
{
    if (!meta)
        return;

    VIR_FREE(meta->backingStore);
    VIR_FREE(meta);
}

/**
 * virStorageFileResize:
 *
 * Change the capacity of the raw storage file at 'path'.
 */
int
virStorageFileResize(const char *path, unsigned long long capacity)
{
    int fd = -1;
    int ret = -1;

    if ((fd = open(path, O_RDWR)) < 0) {
        virReportSystemError(errno, _("Unable to open '%s'"), path);
        goto cleanup;
    }

    if (ftruncate(fd, capacity) < 0) {
        virReportSystemError(errno, _("Failed to truncate file '%s'"), path);
        goto cleanup;
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

#ifdef __linux__

# ifndef NFS_SUPER_MAGIC
#  define NFS_SUPER_MAGIC 0x6969
# endif
# ifndef OCFS2_SUPER_MAGIC
#  define OCFS2_SUPER_MAGIC 0x7461636f
# endif
# ifndef GFS2_MAGIC
#  define GFS2_MAGIC 0x01161970
# endif
# ifndef AFS_FS_MAGIC
#  define AFS_FS_MAGIC 0x6B414653
# endif


int virStorageFileIsSharedFSType(const char *path,
                                 int fstypes)
{
    char *dirpath, *p;
    struct statfs sb;
    int statfs_ret;

    if ((dirpath = strdup(path)) == NULL) {
        virReportOOMError();
        return -1;
    }

    do {

        /* Try less and less of the path until we get to a
         * directory we can stat. Even if we don't have 'x'
         * permission on any directory in the path on the NFS
         * server (assuming it's NFS), we will be able to stat the
         * mount point, and that will properly tell us if the
         * fstype is NFS.
         */

        if ((p = strrchr(dirpath, '/')) == NULL) {
            virReportSystemError(EINVAL,
                         _("Invalid relative path '%s'"), path);
            VIR_FREE(dirpath);
            return -1;
        }

        if (p == dirpath)
            *(p+1) = '\0';
        else
            *p = '\0';

        statfs_ret = statfs(dirpath, &sb);

    } while ((statfs_ret < 0) && (p != dirpath));

    VIR_FREE(dirpath);

    if (statfs_ret < 0) {
        virReportSystemError(errno,
                             _("cannot determine filesystem for '%s'"),
                             path);
        return -1;
    }

    VIR_DEBUG("Check if path %s with FS magic %lld is shared",
              path, (long long int)sb.f_type);

    if ((fstypes & VIR_STORAGE_FILE_SHFS_NFS) &&
        (sb.f_type == NFS_SUPER_MAGIC))
        return 1;

    if ((fstypes & VIR_STORAGE_FILE_SHFS_GFS2) &&
        (sb.f_type == GFS2_MAGIC))
        return 1;
    if ((fstypes & VIR_STORAGE_FILE_SHFS_OCFS) &&
        (sb.f_type == OCFS2_SUPER_MAGIC))
        return 1;
    if ((fstypes & VIR_STORAGE_FILE_SHFS_AFS) &&
        (sb.f_type == AFS_FS_MAGIC))
        return 1;

    return 0;
}
#else
int virStorageFileIsSharedFSType(const char *path ATTRIBUTE_UNUSED,
                                 int fstypes ATTRIBUTE_UNUSED)
{
    /* XXX implement me :-) */
    return 0;
}
#endif

int virStorageFileIsSharedFS(const char *path)
{
    return virStorageFileIsSharedFSType(path,
                                        VIR_STORAGE_FILE_SHFS_NFS |
                                        VIR_STORAGE_FILE_SHFS_GFS2 |
                                        VIR_STORAGE_FILE_SHFS_OCFS |
                                        VIR_STORAGE_FILE_SHFS_AFS);
}

int virStorageFileIsClusterFS(const char *path)
{
    /* These are coherent cluster filesystems known to be safe for
     * migration with cache != none
     */
    return virStorageFileIsSharedFSType(path,
                                        VIR_STORAGE_FILE_SHFS_GFS2 |
                                        VIR_STORAGE_FILE_SHFS_OCFS);
}
