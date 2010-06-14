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
      QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW1_HDR_CRYPT, qcow1GetBackingStore },
    /* QCow 2 */
    { VIR_STORAGE_FILE_QCOW2, "QFI", NULL,
      LV_BIG_ENDIAN, 4, 2,
      QCOWX_HDR_IMAGE_SIZE, 8, 1, QCOW2_HDR_CRYPT, qcow2GetBackingStore },
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
    { VIR_STORAGE_FILE_VPC, "conectix", NULL,
      LV_BIG_ENDIAN, 12, 0x10000,
      8 + 4 + 4 + 8 + 4 + 4 + 2 + 2 + 4, 8, 1, -1, NULL},
};

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
    unsigned long size;

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
    if (isQCow2)
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

    char desc[20*512 + 1], *start, *end;
    size_t len;

    *res = NULL;
    /*
     * Technically this should have been VMDK, since
     * VMDK spec / VMWare impl only support VMDK backed
     * by VMDK. QEMU isn't following this though and
     * does probing on VMDK backing files, hence we set
     * AUTO
     */
    *format = VIR_STORAGE_FILE_AUTO;

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

    memset(meta, 0, sizeof (*meta));

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
            char *backing;
            int backingFormat;

            switch (fileTypeInfo[i].getBackingStore(&backing,
                                                    &backingFormat,
                                                    head, len)) {
            case BACKING_STORE_OK:
                break;

            case BACKING_STORE_INVALID:
                continue;

            case BACKING_STORE_ERROR:
                return -1;
            }
            if (backing != NULL) {
                meta->backingStore = absolutePathFromBaseFile(path, backing);
                VIR_FREE(backing);
                if (meta->backingStore == NULL) {
                    virReportOOMError();
                    return -1;
                }
                meta->backingStoreFormat = backingFormat;
            } else {
                meta->backingStoreFormat = VIR_STORAGE_FILE_AUTO;
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


int virStorageFileIsSharedFS(const char *path)
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

    if (sb.f_type == NFS_SUPER_MAGIC ||
        sb.f_type == GFS2_MAGIC ||
        sb.f_type == OCFS2_SUPER_MAGIC ||
        sb.f_type == AFS_FS_MAGIC) {
        return 1;
    }

    return 0;
}
#else
int virStorageFileIsSharedFS(const char *path ATTRIBUTE_UNUSED)
{
    /* XXX implement me :-) */
    return 0;
}
#endif
