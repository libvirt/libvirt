/*
 * storage_backend_fs.c: storage backend for FS and directory handling
 *
 * Copyright (C) 2007-2009 Red Hat, Inc.
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

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "virterror_internal.h"
#include "storage_backend_fs.h"
#include "storage_conf.h"
#include "util.h"
#include "memory.h"
#include "xml.h"

enum lv_endian {
    LV_LITTLE_ENDIAN = 1, /* 1234 */
    LV_BIG_ENDIAN         /* 4321 */
};

enum {
    BACKING_STORE_OK,
    BACKING_STORE_INVALID,
    BACKING_STORE_ERROR,
};

static int cowGetBackingStore(virConnectPtr, char **,
                              const unsigned char *, size_t);
static int qcowXGetBackingStore(virConnectPtr, char **,
                                const unsigned char *, size_t);
static int vmdk4GetBackingStore(virConnectPtr, char **,
                                const unsigned char *, size_t);

static int track_allocation_progress = 0;

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
    int (*getBackingStore)(virConnectPtr conn, char **res,
                           const unsigned char *buf, size_t buf_size);
};
struct FileTypeInfo const fileTypeInfo[] = {
    /* Bochs */
    /* XXX Untested
    { VIR_STORAGE_VOL_BOCHS, "Bochs Virtual HD Image", NULL,
      LV_LITTLE_ENDIAN, 64, 0x20000,
      32+16+16+4+4+4+4+4, 8, 1, NULL },*/
    /* CLoop */
    /* XXX Untested
    { VIR_STORAGE_VOL_CLOOP, "#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n", NULL,
      LV_LITTLE_ENDIAN, -1, 0,
      -1, 0, 0, NULL }, */
    /* Cow */
    { VIR_STORAGE_VOL_FILE_COW, "OOOM", NULL,
      LV_BIG_ENDIAN, 4, 2,
      4+4+1024+4, 8, 1, cowGetBackingStore },
    /* DMG */
    /* XXX QEMU says there's no magic for dmg, but we should check... */
    { VIR_STORAGE_VOL_FILE_DMG, NULL, ".dmg",
      0, -1, 0,
      -1, 0, 0, NULL },
    /* XXX there's probably some magic for iso we can validate too... */
    { VIR_STORAGE_VOL_FILE_ISO, NULL, ".iso",
      0, -1, 0,
      -1, 0, 0, NULL },
    /* Parallels */
    /* XXX Untested
    { VIR_STORAGE_VOL_FILE_PARALLELS, "WithoutFreeSpace", NULL,
      LV_LITTLE_ENDIAN, 16, 2,
      16+4+4+4+4, 4, 512, NULL },
    */
    /* QCow */
    { VIR_STORAGE_VOL_FILE_QCOW, "QFI", NULL,
      LV_BIG_ENDIAN, 4, 1,
      4+4+8+4+4, 8, 1, qcowXGetBackingStore },
    /* QCow 2 */
    { VIR_STORAGE_VOL_FILE_QCOW2, "QFI", NULL,
      LV_BIG_ENDIAN, 4, 2,
      4+4+8+4+4, 8, 1, qcowXGetBackingStore },
    /* VMDK 3 */
    /* XXX Untested
    { VIR_STORAGE_VOL_FILE_VMDK, "COWD", NULL,
      LV_LITTLE_ENDIAN, 4, 1,
      4+4+4, 4, 512, NULL },
    */
    /* VMDK 4 */
    { VIR_STORAGE_VOL_FILE_VMDK, "KDMV", NULL,
      LV_LITTLE_ENDIAN, 4, 1,
      4+4+4, 8, 512, vmdk4GetBackingStore },
    /* Connectix / VirtualPC */
    /* XXX Untested
    { VIR_STORAGE_VOL_FILE_VPC, "conectix", NULL,
      LV_BIG_ENDIAN, -1, 0,
      -1, 0, 0, NULL},
    */
};

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int
cowGetBackingStore(virConnectPtr conn,
                   char **res,
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
        virReportOOMError(conn);
        return BACKING_STORE_ERROR;
    }
    return BACKING_STORE_OK;
}

static int
qcowXGetBackingStore(virConnectPtr conn,
                     char **res,
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
        virReportOOMError(conn);
        return BACKING_STORE_ERROR;
    }
    memcpy(*res, buf + offset, size);
    (*res)[size] = '\0';
    return BACKING_STORE_OK;
}


static int
vmdk4GetBackingStore(virConnectPtr conn,
                     char **res,
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
        virReportOOMError(conn);
        return BACKING_STORE_ERROR;
    }
    return BACKING_STORE_OK;
}

/**
 * Return an absolute path corresponding to PATH, which is absolute or relative
 * to the directory containing BASE_FILE, or NULL on error
 */
static char *absolutePathFromBaseFile(const char *base_file, const char *path)
{
    size_t base_size, path_size;
    char *res, *p;

    if (*path == '/')
        return strdup(path);

    base_size = strlen(base_file) + 1;
    path_size = strlen(path) + 1;
    if (VIR_ALLOC_N(res, base_size - 1 + path_size) < 0)
        return NULL;
    memcpy(res, base_file, base_size);
    p = strrchr(res, '/');
    if (p != NULL)
        p++;
    else
        p = res;
    memcpy(p, path, path_size);
    if (VIR_REALLOC_N(res, (p + path_size) - res) < 0) {
        /* Ignore failure */
    }
    return res;
}



/**
 * Probe the header of a file to determine what type of disk image
 * it is, and info about its capacity if available.
 */
static int virStorageBackendProbeTarget(virConnectPtr conn,
                                        virStorageVolTargetPtr target,
                                        char **backingStore,
                                        unsigned long long *allocation,
                                        unsigned long long *capacity) {
    int fd;
    unsigned char head[20*512]; /* vmdk4GetBackingStore needs this much. */
    int len, i, ret;

    if (backingStore)
        *backingStore = NULL;

    if ((fd = open(target->path, O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open volume '%s'"),
                             target->path);
        return -1;
    }

    if ((ret = virStorageBackendUpdateVolTargetInfoFD(conn, target, fd,
                                                      allocation,
                                                      capacity)) < 0) {
        close(fd);
        return ret; /* Take care to propagate ret, it is not always -1 */
    }

    if ((len = read(fd, head, sizeof(head))) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot read header '%s'"),
                             target->path);
        close(fd);
        return -1;
    }

    close(fd);

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
        if (fileTypeInfo[i].sizeOffset != -1 && capacity) {
            if (fileTypeInfo[i].endian == LV_LITTLE_ENDIAN) {
                *capacity =
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+7] << 56) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+6] << 48) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+5] << 40) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+4] << 32) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+3] << 24) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+2] << 16) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset+1] << 8) |
                    ((unsigned long long)head[fileTypeInfo[i].sizeOffset]);
            } else {
                *capacity =
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
            if (*capacity > (ULLONG_MAX / fileTypeInfo[i].sizeMultiplier))
                continue;
            *capacity *= fileTypeInfo[i].sizeMultiplier;
        }

        /* Validation passed, we know the file format now */
        target->format = fileTypeInfo[i].type;
        if (fileTypeInfo[i].getBackingStore != NULL && backingStore) {
            char *base;

            switch (fileTypeInfo[i].getBackingStore(conn, &base, head, len)) {
            case BACKING_STORE_OK:
                break;

            case BACKING_STORE_INVALID:
                continue;

            case BACKING_STORE_ERROR:
                return -1;
            }
            if (base != NULL) {
                *backingStore
                    = absolutePathFromBaseFile(target->path, base);
                VIR_FREE(base);
                if (*backingStore == NULL) {
                    virReportOOMError(conn);
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

        if (!virFileHasSuffix(target->path, fileTypeInfo[i].extension))
            continue;

        target->format = fileTypeInfo[i].type;
        return 0;
    }

    /* All fails, so call it a raw file */
    target->format = VIR_STORAGE_VOL_FILE_RAW;
    return 0;
}

#if WITH_STORAGE_FS

#include <mntent.h>

struct _virNetfsDiscoverState {
    const char *host;
    virStoragePoolSourceList list;
};

typedef struct _virNetfsDiscoverState virNetfsDiscoverState;

static int
virStorageBackendFileSystemNetFindPoolSourcesFunc(virConnectPtr conn ATTRIBUTE_UNUSED,
                                                  virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                                  char **const groups,
                                                  void *data)
{
    virNetfsDiscoverState *state = data;
    const char *name, *path;
    virStoragePoolSource *src;

    path = groups[0];

    name = strrchr(path, '/');
    if (name == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("invalid netfs path (no /): %s"), path);
        return -1;
    }
    name += 1;
    if (*name == '\0') {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("invalid netfs path (ends in /): %s"), path);
        return -1;
    }

    if (VIR_REALLOC_N(state->list.sources, state->list.nsources+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }
    memset(state->list.sources + state->list.nsources, 0, sizeof(*state->list.sources));

    src = state->list.sources + state->list.nsources++;
    if (!(src->host.name = strdup(state->host)) ||
        !(src->dir = strdup(path)))
        return -1;
    src->format = VIR_STORAGE_POOL_NETFS_NFS;

    return 0;
}

static char *
virStorageBackendFileSystemNetFindPoolSources(virConnectPtr conn,
                                              const char *srcSpec,
                                              unsigned int flags ATTRIBUTE_UNUSED)
{
    /*
     *  # showmount --no-headers -e HOSTNAME
     *  /tmp   *
     *  /A dir demo1.foo.bar,demo2.foo.bar
     *
     * Extract directory name (including possible interior spaces ...).
     */

    const char *regexes[] = {
        "^(/.*\\S) +\\S+$"
    };
    int vars[] = {
        1
    };
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpath_ctxt = NULL;
    virNetfsDiscoverState state = {
        .host = NULL,
        .list = {
            .type = VIR_STORAGE_POOL_NETFS,
            .nsources = 0,
            .sources = NULL
        }
    };
    const char *prog[] = { SHOWMOUNT, "--no-headers", "--exports", NULL, NULL };
    int exitstatus;
    char *retval = NULL;
    unsigned int i;

    doc = xmlReadDoc((const xmlChar *)srcSpec, "srcSpec.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR, "%s", _("bad <source> spec"));
        goto cleanup;
    }

    xpath_ctxt = xmlXPathNewContext(doc);
    if (xpath_ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    state.host = virXPathString(conn, "string(/source/host/@name)", xpath_ctxt);
    if (!state.host || !state.host[0]) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR, "%s",
                              _("missing <host> in <source> spec"));
        goto cleanup;
    }
    prog[3] = state.host;

    if (virStorageBackendRunProgRegex(conn, NULL, prog, 1, regexes, vars,
                                      virStorageBackendFileSystemNetFindPoolSourcesFunc,
                                      &state, &exitstatus) < 0)
        goto cleanup;

    retval = virStoragePoolSourceListFormat(conn, &state.list);
    if (retval == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

 cleanup:
    for (i = 0; i < state.list.nsources; i++)
        virStoragePoolSourceFree(&state.list.sources[i]);

    VIR_FREE(state.list.sources);
    VIR_FREE(state.host);

    xmlFreeDoc(doc);
    xmlXPathFreeContext(xpath_ctxt);

    return retval;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to check for status
 *
 * Determine if a storage pool is already mounted
 *
 * Return 0 if not mounted, 1 if mounted, -1 on error
 */
static int
virStorageBackendFileSystemIsMounted(virConnectPtr conn,
                                     virStoragePoolObjPtr pool) {
    FILE *mtab;
    struct mntent ent;
    char buf[1024];

    if ((mtab = fopen(_PATH_MOUNTED, "r")) == NULL) {
        virReportSystemError(conn, errno,
                             _("cannot read mount list '%s'"),
                             _PATH_MOUNTED);
        return -1;
    }

    while ((getmntent_r(mtab, &ent, buf, sizeof(buf))) != NULL) {
        if (STREQ(ent.mnt_dir, pool->def->target.path)) {
            fclose(mtab);
            return 1;
        }
    }

    fclose(mtab);
    return 0;
}

/**
 * @conn connection to report errors against
 * @pool storage pool to mount
 *
 * Ensure that a FS storage pool is mounted on its target location.
 * If already mounted, this is a no-op
 *
 * Returns 0 if successfully mounted, -1 on error
 */
static int
virStorageBackendFileSystemMount(virConnectPtr conn,
                                 virStoragePoolObjPtr pool) {
    char *src;
    const char **mntargv;

    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    int netauto = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                   pool->def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    int source_index;

    const char *netfs_auto_argv[] = {
        MOUNT,
        NULL, /* source path */
        pool->def->target.path,
        NULL,
    };

    const char *fs_argv[] =  {
        MOUNT,
        "-t",
        pool->def->type == VIR_STORAGE_POOL_FS ?
        virStoragePoolFormatFileSystemTypeToString(pool->def->source.format) :
        virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format),
        NULL, /* Fill in shortly - careful not to add extra fields
                 before this */
        pool->def->target.path,
        NULL,
    };

    if (netauto) {
        mntargv = netfs_auto_argv;
        source_index = 1;
    } else {
        mntargv = fs_argv;
        source_index = 3;
    }

    int ret;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.host.name == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source path"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source device"));
            return -1;
        }
    }

    /* Short-circuit if already mounted */
    if ((ret = virStorageBackendFileSystemIsMounted(conn, pool)) != 0) {
        if (ret < 0)
            return -1;
        else
            return 0;
    }

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (VIR_ALLOC_N(src, strlen(pool->def->source.host.name) +
                        1 + strlen(pool->def->source.dir) + 1) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        strcpy(src, pool->def->source.host.name);
        strcat(src, ":");
        strcat(src, pool->def->source.dir);
    } else {
        if ((src = strdup(pool->def->source.devices[0].path)) == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }
    mntargv[source_index] = src;

    if (virRun(conn, mntargv, NULL) < 0) {
        VIR_FREE(src);
        return -1;
    }
    VIR_FREE(src);
    return 0;
}

/**
 * @conn connection to report errors against
 * @pool storage pool to unmount
 *
 * Ensure that a FS storage pool is not mounted on its target location.
 * If already unmounted, this is a no-op
 *
 * Returns 0 if successfully unmounted, -1 on error
 */
static int
virStorageBackendFileSystemUnmount(virConnectPtr conn,
                                   virStoragePoolObjPtr pool) {
    const char *mntargv[3];
    int ret;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.host.name == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source dir"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source device"));
            return -1;
        }
    }

    /* Short-circuit if already unmounted */
    if ((ret = virStorageBackendFileSystemIsMounted(conn, pool)) != 1) {
        if (ret < 0)
            return -1;
        else
            return 0;
    }

    mntargv[0] = UMOUNT;
    mntargv[1] = pool->def->target.path;
    mntargv[2] = NULL;

    if (virRun(conn, mntargv, NULL) < 0) {
        return -1;
    }
    return 0;
}
#endif /* WITH_STORAGE_FS */


/**
 * @conn connection to report errors against
 * @pool storage pool to start
 *
 * Starts a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
 *
 * Returns 0 on success, -1 on error
 */
#if WITH_STORAGE_FS
static int
virStorageBackendFileSystemStart(virConnectPtr conn,
                                 virStoragePoolObjPtr pool)
{
    if (pool->def->type != VIR_STORAGE_POOL_DIR &&
        virStorageBackendFileSystemMount(conn, pool) < 0)
        return -1;

    return 0;
}
#endif /* WITH_STORAGE_FS */


/**
 * @conn connection to report errors against
 * @pool storage pool to build
 *
 * Build a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemBuild(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 unsigned int flags ATTRIBUTE_UNUSED)
{
    int err;
    if ((err = virFileMakePath(pool->def->target.path)) < 0) {
        virReportSystemError(conn, err,
                             _("cannot create path '%s'"),
                             pool->def->target.path);
        return -1;
    }

    return 0;
}


/**
 * Iterate over the pool's directory and enumerate all disk images
 * within it. This is non-recursive.
 */
static int
virStorageBackendFileSystemRefresh(virConnectPtr conn,
                                   virStoragePoolObjPtr pool)
{
    DIR *dir;
    struct dirent *ent;
    struct statvfs sb;
    virStorageVolDefPtr vol = NULL;

    if (!(dir = opendir(pool->def->target.path))) {
        virReportSystemError(conn, errno,
                             _("cannot open path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    while ((ent = readdir(dir)) != NULL) {
        int ret;
        char *backingStore;

        if (VIR_ALLOC(vol) < 0)
            goto no_memory;

        if ((vol->name = strdup(ent->d_name)) == NULL)
            goto no_memory;

        vol->type = VIR_STORAGE_VOL_FILE;
        vol->target.format = VIR_STORAGE_VOL_FILE_RAW; /* Real value is filled in during probe */
        if (VIR_ALLOC_N(vol->target.path, strlen(pool->def->target.path) +
                        1 + strlen(vol->name) + 1) < 0)
            goto no_memory;

        strcpy(vol->target.path, pool->def->target.path);
        strcat(vol->target.path, "/");
        strcat(vol->target.path, vol->name);
        if ((vol->key = strdup(vol->target.path)) == NULL)
            goto no_memory;

        if ((ret = virStorageBackendProbeTarget(conn,
                                                &vol->target,
                                                &backingStore,
                                                &vol->allocation,
                                                &vol->capacity) < 0)) {
            if (ret == -1)
                goto no_memory;
            else {
                /* Silently ignore non-regular files,
                 * eg '.' '..', 'lost+found' */
                virStorageVolDefFree(vol);
                vol = NULL;
                continue;
            }
        }

        if (backingStore != NULL) {
            if (vol->target.format == VIR_STORAGE_VOL_FILE_QCOW2 &&
                STRPREFIX("fmt:", backingStore)) {
                char *fmtstr = backingStore + 4;
                char *path = strchr(fmtstr, ':');
                if (!path) {
                    VIR_FREE(backingStore);
                } else {
                    *path = '\0';
                    if ((vol->backingStore.format =
                         virStorageVolFormatFileSystemTypeFromString(fmtstr)) < 0) {
                        VIR_FREE(backingStore);
                    } else {
                        memmove(backingStore, path, strlen(path) + 1);
                        vol->backingStore.path = backingStore;

                        if (virStorageBackendUpdateVolTargetInfo(conn,
                                                                 &vol->backingStore,
                                                                 NULL,
                                                                 NULL) < 0)
                            VIR_FREE(vol->backingStore);
                    }
                }
            } else {
                vol->backingStore.path = backingStore;

                if ((ret = virStorageBackendProbeTarget(conn,
                                                        &vol->backingStore,
                                                        NULL, NULL, NULL)) < 0) {
                    if (ret == -1)
                        goto no_memory;
                    else {
                        /* Silently ignore non-regular files,
                         * eg '.' '..', 'lost+found' */
                        VIR_FREE(vol->backingStore);
                    }
                }
            }
        }



        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0)
            goto no_memory;
        pool->volumes.objs[pool->volumes.count++] = vol;
        vol = NULL;
    }
    closedir(dir);


    if (statvfs(pool->def->target.path, &sb) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot statvfs path '%s'"),
                             pool->def->target.path);
        return -1;
    }
    pool->def->capacity = ((unsigned long long)sb.f_frsize *
                           (unsigned long long)sb.f_blocks);
    pool->def->available = ((unsigned long long)sb.f_bfree *
                            (unsigned long long)sb.f_bsize);
    pool->def->allocation = pool->def->capacity - pool->def->available;

    return 0;

no_memory:
    virReportOOMError(conn);
    /* fallthrough */

 cleanup:
    closedir(dir);
    virStorageVolDefFree(vol);
    virStoragePoolObjClearVols(pool);
    return -1;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to start
 *
 * Stops a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, unmounts the unlying source device on the pool
 *  - Releases all cached data about volumes
 */
#if WITH_STORAGE_FS
static int
virStorageBackendFileSystemStop(virConnectPtr conn,
                                virStoragePoolObjPtr pool)
{
    if (pool->def->type != VIR_STORAGE_POOL_DIR &&
        virStorageBackendFileSystemUnmount(conn, pool) < 0)
        return -1;

    return 0;
}
#endif /* WITH_STORAGE_FS */


/**
 * @conn connection to report errors against
 * @pool storage pool to build
 *
 * Build a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemDelete(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  unsigned int flags ATTRIBUTE_UNUSED)
{
    /* XXX delete all vols first ? */

    if (unlink(pool->def->target.path) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot unlink path '%s'"),
                             pool->def->target.path);
        return -1;
    }

    return 0;
}


/**
 * Set up a volume definition to be added to a pool's volume list, but
 * don't do any file creation or allocation. By separating the two processes,
 * we allow allocation progress reporting (by polling the volume's 'info'
 * function), and can drop the parent pool lock during the (slow) allocation.
 */
static int
virStorageBackendFileSystemVolCreate(virConnectPtr conn,
                                     virStoragePoolObjPtr pool,
                                     virStorageVolDefPtr vol)
{

    if (VIR_ALLOC_N(vol->target.path, strlen(pool->def->target.path) +
                    1 + strlen(vol->name) + 1) < 0) {
        virReportOOMError(conn);
        return -1;
    }
    vol->type = VIR_STORAGE_VOL_FILE;
    strcpy(vol->target.path, pool->def->target.path);
    strcat(vol->target.path, "/");
    strcat(vol->target.path, vol->name);
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virReportOOMError(conn);
        return -1;
    }

    return 0;
}

/**
 * Allocate a new file as a volume. This is either done directly
 * for raw/sparse files, or by calling qemu-img/qcow-create for
 * special kinds of files
 */
static int
virStorageBackendFileSystemVolBuild(virConnectPtr conn,
                                    virStorageVolDefPtr vol)
{
    int fd;

    if (vol->target.format == VIR_STORAGE_VOL_FILE_RAW) {
        if ((fd = open(vol->target.path, O_RDWR | O_CREAT | O_EXCL,
                       vol->target.perms.mode)) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot create path '%s'"),
                                 vol->target.path);
            return -1;
        }

        /* Seek to the final size, so the capacity is available upfront
         * for progress reporting */
        if (ftruncate(fd, vol->capacity) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot extend file '%s'"),
                                 vol->target.path);
            close(fd);
            return -1;
        }

        /* Pre-allocate any data if requested */
        /* XXX slooooooooooooooooow on non-extents-based file systems */
        /* FIXME: Add in progress bars & bg thread if progress bar requested */
        if (vol->allocation) {
            if (track_allocation_progress) {
                unsigned long long remain = vol->allocation;

                while (remain) {
                    /* Allocate in chunks of 512MiB: big-enough chunk
                     * size and takes approx. 9s on ext3. A progress
                     * update every 9s is a fair-enough trade-off
                     */
                    unsigned long long bytes = 512 * 1024 * 1024;
                    int r;

                    if (bytes > remain)
                        bytes = remain;
                    if ((r = safezero(fd, 0, vol->allocation - remain,
                                      bytes)) != 0) {
                        virReportSystemError(conn, r,
                                             _("cannot fill file '%s'"),
                                             vol->target.path);
                        close(fd);
                        return -1;
                    }
                    remain -= bytes;
                }
            } else { /* No progress bars to be shown */
                int r;

                if ((r = safezero(fd, 0, 0, vol->allocation)) != 0) {
                    virReportSystemError(conn, r,
                                         _("cannot fill file '%s'"),
                                         vol->target.path);
                    close(fd);
                    return -1;
                }
            }
        }

    } else if (vol->target.format == VIR_STORAGE_VOL_FILE_DIR) {
        if (mkdir(vol->target.path, vol->target.perms.mode) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot create path '%s'"),
                                 vol->target.path);
            return -1;
        }

        if ((fd = open(vol->target.path, O_RDWR)) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot read path '%s'"),
                                 vol->target.path);
            return -1;
        }
    } else {
#if HAVE_QEMU_IMG
        const char *type = virStorageVolFormatFileSystemTypeToString(vol->target.format);
        const char *backingType = vol->backingStore.path ?
            virStorageVolFormatFileSystemTypeToString(vol->backingStore.format) : NULL;
        char size[100];
        const char **imgargv;
        const char *imgargvnormal[] = {
            QEMU_IMG, "create", "-f", type, vol->target.path, size, NULL,
        };
        /* XXX including "backingType" here too, once QEMU accepts
         * the patches to specify it. It'll probably be -F backingType */
        const char *imgargvbacking[] = {
            QEMU_IMG, "create", "-f", type, "-b", vol->backingStore.path, vol->target.path, size, NULL,
        };

        if (type == NULL) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown storage vol type %d"),
                                  vol->target.format);
            return -1;
        }
        if (vol->backingStore.path == NULL) {
            imgargv = imgargvnormal;
        } else {
            if (backingType == NULL) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("unknown storage vol backing store type %d"),
                                      vol->backingStore.format);
                return -1;
            }
            if (access(vol->backingStore.path, R_OK) != 0) {
                virReportSystemError(conn, errno,
                                     _("inaccessible backing store volume %s"),
                                     vol->backingStore.path);
                return -1;
            }

            imgargv = imgargvbacking;
        }

        /* Size in KB */
        snprintf(size, sizeof(size), "%llu", vol->capacity/1024);

        if (virRun(conn, imgargv, NULL) < 0) {
            return -1;
        }

        if ((fd = open(vol->target.path, O_RDONLY)) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot read path '%s'"),
                                 vol->target.path);
            return -1;
        }
#elif HAVE_QCOW_CREATE
        /*
         * Xen removed the fully-functional qemu-img, and replaced it
         * with a partially functional qcow-create. Go figure ??!?
         */
        char size[100];
        const char *imgargv[4];

        if (vol->target.format != VIR_STORAGE_VOL_FILE_QCOW2) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unsupported storage vol type %d"),
                                  vol->target.format);
            return -1;
        }
        if (vol->backingStore.path != NULL) {
            virStorageReportError(conn, VIR_ERR_NO_SUPPORT,
                                  _("copy-on-write image not supported with "
                                    "qcow-create"));
            return -1;
        }

        /* Size in MB - yes different units to qemu-img :-( */
        snprintf(size, sizeof(size), "%llu", vol->capacity/1024/1024);

        imgargv[0] = QCOW_CREATE;
        imgargv[1] = size;
        imgargv[2] = vol->target.path;
        imgargv[3] = NULL;

        if (virRun(conn, imgargv, NULL) < 0) {
            return -1;
        }

        if ((fd = open(vol->target.path, O_RDONLY)) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot read path '%s'"),
                                 vol->target.path);
            return -1;
        }
#else
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("creation of non-raw images "
                                      "is not supported without qemu-img"));
        return -1;
#endif
    }

    /* We can only chown/grp if root */
    if (getuid() == 0) {
        if (fchown(fd, vol->target.perms.uid, vol->target.perms.gid) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot set file owner '%s'"),
                                 vol->target.path);
            close(fd);
            return -1;
        }
    }
    if (fchmod(fd, vol->target.perms.mode) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot set file mode '%s'"),
                             vol->target.path);
        close(fd);
        return -1;
    }

    /* Refresh allocation / permissions info, but not capacity */
    if (virStorageBackendUpdateVolTargetInfoFD(conn, &vol->target, fd,
                                               &vol->allocation,
                                               NULL) < 0) {
        close(fd);
        return -1;
    }

    if (close(fd) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        return -1;
    }

    return 0;
}


/**
 * Remove a volume - just unlinks for now
 */
static int
virStorageBackendFileSystemVolDelete(virConnectPtr conn,
                                     virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                     virStorageVolDefPtr vol,
                                     unsigned int flags ATTRIBUTE_UNUSED)
{
    if (unlink(vol->target.path) < 0) {
        /* Silently ignore failures where the vol has already gone away */
        if (errno != ENOENT) {
            virReportSystemError(conn, errno,
                                 _("cannot unlink file '%s'"),
                                 vol->target.path);
            return -1;
        }
    }
    return 0;
}


/**
 * Update info about a volume's capacity/allocation
 */
static int
virStorageBackendFileSystemVolRefresh(virConnectPtr conn,
                                      virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                      virStorageVolDefPtr vol)
{
    /* Refresh allocation / permissions info in case its changed */
    return virStorageBackendUpdateVolInfo(conn, vol, 0);
}

virStorageBackend virStorageBackendDirectory = {
    .type = VIR_STORAGE_POOL_DIR,

    .buildPool = virStorageBackendFileSystemBuild,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
};

#if WITH_STORAGE_FS
virStorageBackend virStorageBackendFileSystem = {
    .type = VIR_STORAGE_POOL_FS,

    .buildPool = virStorageBackendFileSystemBuild,
    .startPool = virStorageBackendFileSystemStart,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
};
virStorageBackend virStorageBackendNetFileSystem = {
    .type = VIR_STORAGE_POOL_NETFS,

    .buildPool = virStorageBackendFileSystemBuild,
    .startPool = virStorageBackendFileSystemStart,
    .findPoolSources = virStorageBackendFileSystemNetFindPoolSources,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
};
#endif /* WITH_STORAGE_FS */
