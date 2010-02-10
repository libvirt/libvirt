/*
 * storage_file.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
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

#include <unistd.h>
#include <fcntl.h>
#include "dirname.h"
#include "memory.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_ENUM_IMPL(virStorageFileFormat,
              VIR_STORAGE_FILE_LAST,
              "raw", "dir", "bochs",
              "cloop", "cow", "dmg", "iso",
              "qcow", "qcow2", "vmdk", "vpc")

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
    int type;           /* One of the constants above */
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
    int (*getBackingStore)(char **res, const unsigned char *buf, size_t buf_size);
};

static int cowGetBackingStore(char **, const unsigned char *, size_t);
static int qcowXGetBackingStore(char **, const unsigned char *, size_t);
static int vmdk4GetBackingStore(char **, const unsigned char *, size_t);


static struct FileTypeInfo const fileTypeInfo[] = {
    /* Bochs */
    /* XXX Untested
    { VIR_STORAGE_FILE_BOCHS, "Bochs Virtual HD Image", NULL,
      LV_LITTLE_ENDIAN, 64, 0x20000,
      32+16+16+4+4+4+4+4, 8, 1, -1, NULL },*/
    /* CLoop */
    /* XXX Untested
    { VIR_STORAGE_VOL_CLOOP, "#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n", NULL,
      LV_LITTLE_ENDIAN, -1, 0,
      -1, 0, 0, -1, NULL }, */
    /* Cow */
    { VIR_STORAGE_FILE_COW, "OOOM", NULL,
      LV_BIG_ENDIAN, 4, 2,
      4+4+1024+4, 8, 1, -1, cowGetBackingStore },
    /* DMG */
    /* XXX QEMU says there's no magic for dmg, but we should check... */
    { VIR_STORAGE_FILE_DMG, NULL, ".dmg",
      0, -1, 0,
      -1, 0, 0, -1, NULL },
    /* XXX there's probably some magic for iso we can validate too... */
    { VIR_STORAGE_FILE_ISO, NULL, ".iso",
      0, -1, 0,
      -1, 0, 0, -1, NULL },
    /* Parallels */
    /* XXX Untested
    { VIR_STORAGE_FILE_PARALLELS, "WithoutFreeSpace", NULL,
      LV_LITTLE_ENDIAN, 16, 2,
      16+4+4+4+4, 4, 512, -1, NULL },
    */
    /* QCow */
    { VIR_STORAGE_FILE_QCOW, "QFI", NULL,
      LV_BIG_ENDIAN, 4, 1,
      4+4+8+4+4, 8, 1, 4+4+8+4+4+8+1+1+2, qcowXGetBackingStore },
    /* QCow 2 */
    { VIR_STORAGE_FILE_QCOW2, "QFI", NULL,
      LV_BIG_ENDIAN, 4, 2,
      4+4+8+4+4, 8, 1, 4+4+8+4+4+8, qcowXGetBackingStore },
    /* VMDK 3 */
    /* XXX Untested
    { VIR_STORAGE_FILE_VMDK, "COWD", NULL,
      LV_LITTLE_ENDIAN, 4, 1,
      4+4+4, 4, 512, -1, NULL },
    */
    /* VMDK 4 */
    { VIR_STORAGE_FILE_VMDK, "KDMV", NULL,
      LV_LITTLE_ENDIAN, 4, 1,
      4+4+4, 8, 512, -1, vmdk4GetBackingStore },
    /* Connectix / VirtualPC */
    /* XXX Untested
    { VIR_STORAGE_FILE_VPC, "conectix", NULL,
      LV_BIG_ENDIAN, -1, 0,
      -1, 0, 0, -1, NULL},
    */
};

static int
cowGetBackingStore(char **res,
                   const unsigned char *buf,
                   size_t buf_size)
{
#define COW_FILENAME_MAXLEN 1024
    *res = NULL;
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
qcowXGetBackingStore(char **res,
                     const unsigned char *buf,
                     size_t buf_size)
{
    unsigned long long offset;
    unsigned long size;

    *res = NULL;
    if (buf_size < 4+4+8+4)
        return BACKING_STORE_INVALID;
    offset = (((unsigned long long)buf[4+4] << 56)
              | ((unsigned long long)buf[4+4+1] << 48)
              | ((unsigned long long)buf[4+4+2] << 40)
              | ((unsigned long long)buf[4+4+3] << 32)
              | ((unsigned long long)buf[4+4+4] << 24)
              | ((unsigned long long)buf[4+4+5] << 16)
              | ((unsigned long long)buf[4+4+6] << 8)
              | buf[4+4+7]); /* QCowHeader.backing_file_offset */
    if (offset > buf_size)
        return BACKING_STORE_INVALID;
    size = ((buf[4+4+8] << 24)
            | (buf[4+4+8+1] << 16)
            | (buf[4+4+8+2] << 8)
            | buf[4+4+8+3]); /* QCowHeader.backing_file_size */
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
    return BACKING_STORE_OK;
}


static int
vmdk4GetBackingStore(char **res,
                     const unsigned char *buf,
                     size_t buf_size)
{
    static const char prefix[] = "parentFileNameHint=\"";

    char desc[20*512 + 1], *start, *end;
    size_t len;

    *res = NULL;

    if (buf_size <= 0x200)
        return BACKING_STORE_INVALID;
    len = buf_size - 0x200;
    if (len > sizeof(desc) - 1)
        len = sizeof(desc) - 1;
    memcpy(desc, buf + 0x200, len);
    desc[len] = '\0';
    start = strstr(desc, prefix);
    if (start == NULL)
        return BACKING_STORE_OK;
    start += strlen(prefix);
    end = strchr(start, '"');
    if (end == NULL)
        return BACKING_STORE_INVALID;
    if (end == start)
        return BACKING_STORE_OK;
    *end = '\0';
    *res = strdup(start);
    if (*res == NULL) {
        virReportOOMError();
        return BACKING_STORE_ERROR;
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

    virAsprintf(&res, "%.*s/%s", (int) d_len, base_file, path);
    return res;
}

/**
 * Probe the header of a file to determine what type of disk image
 * it is, and info about its capacity if available.
 */
int
virStorageFileGetMetadataFromFD(const char *path,
                                int fd,
                                virStorageFileMetadata *meta)
{
    unsigned char head[20*512]; /* vmdk4GetBackingStore needs this much. */
    int len, i;

    /* If all else fails, call it a raw file */
    meta->format = VIR_STORAGE_FILE_RAW;

    if ((len = read(fd, head, sizeof(head))) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), path);
        return -1;
    }

    /* First check file magic */
    for (i = 0 ; i < ARRAY_CARDINALITY(fileTypeInfo) ; i++) {
        int mlen;

        if (fileTypeInfo[i].magic == NULL)
            continue;

        /* Validate magic data */
        mlen = strlen(fileTypeInfo[i].magic);
        if (mlen > len)
            continue;
        if (memcmp(head, fileTypeInfo[i].magic, mlen) != 0)
            continue;

        /* Validate version number info */
        if (fileTypeInfo[i].versionNumber != -1) {
            int version;

            if (fileTypeInfo[i].endian == LV_LITTLE_ENDIAN) {
                version = (head[fileTypeInfo[i].versionOffset+3] << 24) |
                    (head[fileTypeInfo[i].versionOffset+2] << 16) |
                    (head[fileTypeInfo[i].versionOffset+1] << 8) |
                    head[fileTypeInfo[i].versionOffset];
            } else {
                version = (head[fileTypeInfo[i].versionOffset] << 24) |
                    (head[fileTypeInfo[i].versionOffset+1] << 16) |
                    (head[fileTypeInfo[i].versionOffset+2] << 8) |
                    head[fileTypeInfo[i].versionOffset+3];
            }
            if (version != fileTypeInfo[i].versionNumber)
                continue;
        }

        /* Optionally extract capacity from file */
        if (fileTypeInfo[i].sizeOffset != -1) {
            if (fileTypeInfo[i].endian == LV_LITTLE_ENDIAN) {
                meta->capacity =
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+7] << 56) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+6] << 48) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+5] << 40) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+4] << 32) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+3] << 24) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+2] << 16) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+1] << 8) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset]);
            } else {
                meta->capacity =
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset] << 56) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+1] << 48) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+2] << 40) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+3] << 32) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+4] << 24) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+5] << 16) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+6] << 8) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+7]);
            }
            /* Avoid unlikely, but theoretically possible overflow */
            if (meta->capacity > (ULLONG_MAX / fileTypeInfo[i].sizeMultiplier))
                continue;
            meta->capacity *= fileTypeInfo[i].sizeMultiplier;
        }

        if (fileTypeInfo[i].qcowCryptOffset != -1) {
            int crypt_format;

            crypt_format = (head[fileTypeInfo[i].qcowCryptOffset] << 24) |
                (head[fileTypeInfo[i].qcowCryptOffset+1] << 16) |
                (head[fileTypeInfo[i].qcowCryptOffset+2] << 8) |
                head[fileTypeInfo[i].qcowCryptOffset+3];
            meta->encrypted = crypt_format != 0;
        }

        /* Validation passed, we know the file format now */
        meta->format = fileTypeInfo[i].type;
        if (fileTypeInfo[i].getBackingStore != NULL) {
            char *base;

            switch (fileTypeInfo[i].getBackingStore(&base, head, len)) {
            case BACKING_STORE_OK:
                break;

            case BACKING_STORE_INVALID:
                continue;

            case BACKING_STORE_ERROR:
                return -1;
            }
            if (base != NULL) {
                meta->backingStore = absolutePathFromBaseFile(path, base);
                VIR_FREE(base);
                if (meta->backingStore == NULL) {
                    virReportOOMError();
                    return -1;
                }
            }
        }
        return 0;
    }

    /* No magic, so check file extension */
    for (i = 0 ; i < ARRAY_CARDINALITY(fileTypeInfo) ; i++) {
        if (fileTypeInfo[i].extension == NULL)
            continue;

        if (!virFileHasSuffix(path, fileTypeInfo[i].extension))
            continue;

        meta->format = fileTypeInfo[i].type;
        return 0;
    }

    return 0;
}

int
virStorageFileGetMetadata(const char *path,
                          virStorageFileMetadata *meta)
{
    int fd, ret;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("cannot open file '%s'"), path);
        return -1;
    }

    ret = virStorageFileGetMetadataFromFD(path, fd, meta);

    close(fd);

    return ret;
}
