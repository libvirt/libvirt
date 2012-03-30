/*
 * storage_conf.c: config handling for storage driver
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "storage_conf.h"
#include "storage_file.h"

#include "xml.h"
#include "uuid.h"
#include "buf.h"
#include "util.h"
#include "memory.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE


VIR_ENUM_IMPL(virStoragePool,
              VIR_STORAGE_POOL_LAST,
              "dir", "fs", "netfs",
              "logical", "disk", "iscsi",
              "scsi", "mpath")

VIR_ENUM_IMPL(virStoragePoolFormatFileSystem,
              VIR_STORAGE_POOL_FS_LAST,
              "auto", "ext2", "ext3",
              "ext4", "ufs", "iso9660", "udf",
              "gfs", "gfs2", "vfat", "hfs+", "xfs", "ocfs2")

VIR_ENUM_IMPL(virStoragePoolFormatFileSystemNet,
              VIR_STORAGE_POOL_NETFS_LAST,
              "auto", "nfs", "glusterfs", "cifs")

VIR_ENUM_IMPL(virStoragePoolFormatDisk,
              VIR_STORAGE_POOL_DISK_LAST,
              "unknown", "dos", "dvh", "gpt",
              "mac", "bsd", "pc98", "sun", "lvm2")

VIR_ENUM_IMPL(virStoragePoolFormatLogical,
              VIR_STORAGE_POOL_LOGICAL_LAST,
              "unknown", "lvm2")


VIR_ENUM_IMPL(virStorageVolFormatDisk,
              VIR_STORAGE_VOL_DISK_LAST,
              "none", "linux", "fat16",
              "fat32", "linux-swap",
              "linux-lvm", "linux-raid",
              "extended")

VIR_ENUM_IMPL(virStoragePartedFsType,
              VIR_STORAGE_PARTED_FS_TYPE_LAST,
              "ext2", "ext2", "fat16",
              "fat32", "linux-swap",
              "ext2", "ext2",
              "extended")

typedef const char *(*virStorageVolFormatToString)(int format);
typedef int (*virStorageVolFormatFromString)(const char *format);

typedef const char *(*virStoragePoolFormatToString)(int format);
typedef int (*virStoragePoolFormatFromString)(const char *format);

typedef struct _virStorageVolOptions virStorageVolOptions;
typedef virStorageVolOptions *virStorageVolOptionsPtr;
struct _virStorageVolOptions {
    int defaultFormat;
    virStorageVolFormatToString formatToString;
    virStorageVolFormatFromString formatFromString;
};

/* Flags to indicate mandatory components in the pool source */
enum {
    VIR_STORAGE_POOL_SOURCE_HOST            = (1<<0),
    VIR_STORAGE_POOL_SOURCE_DEVICE          = (1<<1),
    VIR_STORAGE_POOL_SOURCE_DIR             = (1<<2),
    VIR_STORAGE_POOL_SOURCE_ADAPTER         = (1<<3),
    VIR_STORAGE_POOL_SOURCE_NAME            = (1<<4),
    VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN   = (1<<5),
};



typedef struct _virStoragePoolOptions virStoragePoolOptions;
typedef virStoragePoolOptions *virStoragePoolOptionsPtr;
struct _virStoragePoolOptions {
    unsigned int flags;
    int defaultFormat;
    virStoragePoolFormatToString formatToString;
    virStoragePoolFormatFromString formatFromString;
};

typedef struct _virStoragePoolTypeInfo virStoragePoolTypeInfo;
typedef virStoragePoolTypeInfo *virStoragePoolTypeInfoPtr;

struct _virStoragePoolTypeInfo {
    int poolType;
    virStoragePoolOptions poolOptions;
    virStorageVolOptions volOptions;
};

static virStoragePoolTypeInfo poolTypeInfo[] = {
    { .poolType = VIR_STORAGE_POOL_LOGICAL,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_NAME |
                      VIR_STORAGE_POOL_SOURCE_DEVICE),
            .defaultFormat = VIR_STORAGE_POOL_LOGICAL_LVM2,
            .formatFromString = virStoragePoolFormatLogicalTypeFromString,
            .formatToString = virStoragePoolFormatLogicalTypeToString,
        },
    },
    { .poolType = VIR_STORAGE_POOL_DIR,
      .volOptions = {
            .defaultFormat = VIR_STORAGE_FILE_RAW,
            .formatFromString = virStorageFileFormatTypeFromString,
            .formatToString = virStorageFileFormatTypeToString,
        },
    },
    { .poolType = VIR_STORAGE_POOL_FS,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
            .defaultFormat = VIR_STORAGE_POOL_FS_AUTO,
            .formatFromString = virStoragePoolFormatFileSystemTypeFromString,
            .formatToString = virStoragePoolFormatFileSystemTypeToString,
        },
      .volOptions = {
            .defaultFormat = VIR_STORAGE_FILE_RAW,
            .formatFromString = virStorageFileFormatTypeFromString,
            .formatToString = virStorageFileFormatTypeToString,
        },
    },
    { .poolType = VIR_STORAGE_POOL_NETFS,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                      VIR_STORAGE_POOL_SOURCE_DIR),
            .defaultFormat = VIR_STORAGE_POOL_NETFS_AUTO,
            .formatFromString = virStoragePoolFormatFileSystemNetTypeFromString,
            .formatToString = virStoragePoolFormatFileSystemNetTypeToString,
        },
      .volOptions = {
            .defaultFormat = VIR_STORAGE_FILE_RAW,
            .formatFromString = virStorageFileFormatTypeFromString,
            .formatToString = virStorageFileFormatTypeToString,
        },
    },
    { .poolType = VIR_STORAGE_POOL_ISCSI,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                      VIR_STORAGE_POOL_SOURCE_DEVICE |
                      VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN),
        },
      .volOptions = {
            .formatToString = virStoragePoolFormatDiskTypeToString,
        }
    },
    { .poolType = VIR_STORAGE_POOL_SCSI,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_ADAPTER),
        },
      .volOptions = {
            .formatToString = virStoragePoolFormatDiskTypeToString,
        }
    },
    { .poolType = VIR_STORAGE_POOL_MPATH,
      .volOptions = {
            .formatToString = virStoragePoolFormatDiskTypeToString,
        }
    },
    { .poolType = VIR_STORAGE_POOL_DISK,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
            .defaultFormat = VIR_STORAGE_POOL_DISK_UNKNOWN,
            .formatFromString = virStoragePoolFormatDiskTypeFromString,
            .formatToString = virStoragePoolFormatDiskTypeToString,
        },
      .volOptions = {
            .defaultFormat = VIR_STORAGE_VOL_DISK_NONE,
            .formatFromString = virStorageVolFormatDiskTypeFromString,
            .formatToString = virStorageVolFormatDiskTypeToString,
        },
    }
};


static virStoragePoolTypeInfoPtr
virStoragePoolTypeInfoLookup(int type) {
    unsigned int i;
    for (i = 0; i < ARRAY_CARDINALITY(poolTypeInfo) ; i++)
        if (poolTypeInfo[i].poolType == type)
            return &poolTypeInfo[i];

    virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                          _("missing backend for pool type %d"), type);
    return NULL;
}

static virStoragePoolOptionsPtr
virStoragePoolOptionsForPoolType(int type) {
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->poolOptions;
}

static virStorageVolOptionsPtr
virStorageVolOptionsForPoolType(int type) {
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->volOptions;
}


void
virStorageVolDefFree(virStorageVolDefPtr def) {
    int i;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->key);

    for (i = 0 ; i < def->source.nextent ; i++) {
        VIR_FREE(def->source.extents[i].path);
    }
    VIR_FREE(def->source.extents);

    VIR_FREE(def->target.path);
    VIR_FREE(def->target.perms.label);
    virStorageEncryptionFree(def->target.encryption);
    VIR_FREE(def->backingStore.path);
    VIR_FREE(def->backingStore.perms.label);
    virStorageEncryptionFree(def->backingStore.encryption);
    VIR_FREE(def);
}

void
virStoragePoolSourceClear(virStoragePoolSourcePtr source)
{
    int i;

    if (!source)
        return;

    VIR_FREE(source->host.name);
    for (i = 0 ; i < source->ndevice ; i++) {
        VIR_FREE(source->devices[i].freeExtents);
        VIR_FREE(source->devices[i].path);
    }
    VIR_FREE(source->devices);
    VIR_FREE(source->dir);
    VIR_FREE(source->name);
    VIR_FREE(source->adapter);
    VIR_FREE(source->initiator.iqn);
    VIR_FREE(source->vendor);
    VIR_FREE(source->product);

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        VIR_FREE(source->auth.chap.login);
        VIR_FREE(source->auth.chap.passwd);
    }
}

void
virStoragePoolSourceFree(virStoragePoolSourcePtr source)
{
    virStoragePoolSourceClear(source);
    VIR_FREE(source);
}

void
virStoragePoolDefFree(virStoragePoolDefPtr def) {
    if (!def)
        return;

    VIR_FREE(def->name);

    virStoragePoolSourceClear(&def->source);

    VIR_FREE(def->target.path);
    VIR_FREE(def->target.perms.label);
    VIR_FREE(def);
}


void
virStoragePoolObjFree(virStoragePoolObjPtr obj) {
    if (!obj)
        return;

    virStoragePoolObjClearVols(obj);

    virStoragePoolDefFree(obj->def);
    virStoragePoolDefFree(obj->newDef);

    VIR_FREE(obj->configFile);
    VIR_FREE(obj->autostartLink);

    virMutexDestroy(&obj->lock);

    VIR_FREE(obj);
}

void virStoragePoolObjListFree(virStoragePoolObjListPtr pools)
{
    unsigned int i;
    for (i = 0 ; i < pools->count ; i++)
        virStoragePoolObjFree(pools->objs[i]);
    VIR_FREE(pools->objs);
    pools->count = 0;
}

void
virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                        virStoragePoolObjPtr pool)
{
    unsigned int i;

    virStoragePoolObjUnlock(pool);

    for (i = 0 ; i < pools->count ; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (pools->objs[i] == pool) {
            virStoragePoolObjUnlock(pools->objs[i]);
            virStoragePoolObjFree(pools->objs[i]);

            if (i < (pools->count - 1))
                memmove(pools->objs + i, pools->objs + i + 1,
                        sizeof(*(pools->objs)) * (pools->count - (i + 1)));

            if (VIR_REALLOC_N(pools->objs, pools->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            pools->count--;

            break;
        }
        virStoragePoolObjUnlock(pools->objs[i]);
    }
}


static int
virStoragePoolDefParseAuthChap(xmlXPathContextPtr ctxt,
                               virStoragePoolAuthChapPtr auth) {
    auth->login = virXPathString("string(./auth/@login)", ctxt);
    if (auth->login == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing auth host attribute"));
        return -1;
    }

    auth->passwd = virXPathString("string(./auth/@passwd)", ctxt);
    if (auth->passwd == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing auth passwd attribute"));
        return -1;
    }

    return 0;
}

static int
virStoragePoolDefParseSource(xmlXPathContextPtr ctxt,
                             virStoragePoolSourcePtr source,
                             int pool_type,
                             xmlNodePtr node) {
    int ret = -1;
    xmlNodePtr relnode, *nodeset = NULL;
    char *authType = NULL;
    int nsource, i;
    virStoragePoolOptionsPtr options;
    char *port = NULL;

    relnode = ctxt->node;
    ctxt->node = node;

    if ((options = virStoragePoolOptionsForPoolType(pool_type)) == NULL) {
        goto cleanup;
    }

    source->name = virXPathString("string(./name)", ctxt);

    if (options->formatFromString) {
        char *format = virXPathString("string(./format/@type)", ctxt);
        if (format == NULL)
            source->format = options->defaultFormat;
        else
            source->format = options->formatFromString(format);

        if (source->format < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  _("unknown pool format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    source->host.name = virXPathString("string(./host/@name)", ctxt);
    port = virXPathString("string(./host/@port)", ctxt);
    if (port) {
        if (virStrToLong_i(port, NULL, 10, &source->host.port) < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  _("Invalid port number: %s"),
                                  port);
            goto cleanup;
        }
    }


    source->initiator.iqn = virXPathString("string(./initiator/iqn/@name)", ctxt);

    nsource = virXPathNodeSet("./device", ctxt, &nodeset);
    if (nsource < 0)
        goto cleanup;

    if (nsource > 0) {
        if (VIR_ALLOC_N(source->devices, nsource) < 0) {
            VIR_FREE(nodeset);
            virReportOOMError();
            goto cleanup;
        }

        for (i = 0 ; i < nsource ; i++) {
            char *path = virXMLPropString(nodeset[i], "path");
            if (path == NULL) {
                VIR_FREE(nodeset);
                virStorageReportError(VIR_ERR_XML_ERROR,
                        "%s", _("missing storage pool source device path"));
                goto cleanup;
            }
            source->devices[i].path = path;
        }
        source->ndevice = nsource;
    }

    source->dir = virXPathString("string(./dir/@path)", ctxt);
    source->adapter = virXPathString("string(./adapter/@name)", ctxt);

    authType = virXPathString("string(./auth/@type)", ctxt);
    if (authType == NULL) {
        source->authType = VIR_STORAGE_POOL_AUTH_NONE;
    } else {
        if (STREQ(authType, "chap")) {
            source->authType = VIR_STORAGE_POOL_AUTH_CHAP;
        } else {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  _("unknown auth type '%s'"),
                                  (const char *)authType);
            goto cleanup;
        }
    }

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        if (virStoragePoolDefParseAuthChap(ctxt, &source->auth.chap) < 0)
            goto cleanup;
    }

    source->vendor = virXPathString("string(./vendor/@name)", ctxt);
    source->product = virXPathString("string(./product/@name)", ctxt);

    ret = 0;
cleanup:
    ctxt->node = relnode;

    VIR_FREE(port);
    VIR_FREE(authType);
    VIR_FREE(nodeset);
    return ret;
}

virStoragePoolSourcePtr
virStoragePoolDefParseSourceString(const char *srcSpec,
                                   int pool_type)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr xpath_ctxt = NULL;
    virStoragePoolSourcePtr def = NULL, ret = NULL;

    if (!(doc = virXMLParseStringCtxt(srcSpec, _("(storage_source_specification)"), &xpath_ctxt))) {
        goto cleanup;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    node = virXPathNode("/source", xpath_ctxt);
    if (!node) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("root element was not source"));
        goto cleanup;
    }

    if (virStoragePoolDefParseSource(xpath_ctxt, def, pool_type,
                                     node) < 0)
        goto cleanup;

    ret = def;
    def = NULL;
cleanup:
    virStoragePoolSourceFree(def);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(xpath_ctxt);

    return ret;
}
static int
virStorageDefParsePerms(xmlXPathContextPtr ctxt,
                        virStoragePermsPtr perms,
                        const char *permxpath,
                        int defaultmode) {
    char *mode;
    long v;
    int ret = -1;
    xmlNodePtr relnode;
    xmlNodePtr node;

    node = virXPathNode(permxpath, ctxt);
    if (node == NULL) {
        /* Set default values if there is not <permissions> element */
        perms->mode = defaultmode;
        perms->uid = -1;
        perms->gid = -1;
        perms->label = NULL;
        return 0;
    }

    relnode = ctxt->node;
    ctxt->node = node;

    mode = virXPathString("string(./mode)", ctxt);
    if (!mode) {
        perms->mode = defaultmode;
    } else {
        char *end = NULL;
        perms->mode = strtol(mode, &end, 8);
        if (*end || (perms->mode & ~0777)) {
            VIR_FREE(mode);
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("malformed octal mode"));
            goto error;
        }
        VIR_FREE(mode);
    }

    if (virXPathNode("./owner", ctxt) == NULL) {
        perms->uid = -1;
    } else {
        if (virXPathLong("number(./owner)", ctxt, &v) < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("malformed owner element"));
            goto error;
        }
        perms->uid = (int)v;
    }

    if (virXPathNode("./group", ctxt) == NULL) {
        perms->gid = -1;
    } else {
        if (virXPathLong("number(./group)", ctxt, &v) < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("malformed group element"));
            goto error;
        }
        perms->gid = (int)v;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString("string(./label)", ctxt);

    ret = 0;
error:
    ctxt->node = relnode;
    return ret;
}

static virStoragePoolDefPtr
virStoragePoolDefParseXML(xmlXPathContextPtr ctxt) {
    virStoragePoolOptionsPtr options;
    virStoragePoolDefPtr ret;
    xmlNodePtr source_node;
    char *type = NULL;
    char *uuid = NULL;
    char *tmppath;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    type = virXPathString("string(./@type)", ctxt);
    if ((ret->type = virStoragePoolTypeFromString((const char *)type)) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage pool type %s"), (const char*)type);
        goto cleanup;
    }

    xmlFree(type);
    type = NULL;

    if ((options = virStoragePoolOptionsForPoolType(ret->type)) == NULL) {
        goto cleanup;
    }

    source_node = virXPathNode("./source", ctxt);
    if (source_node) {
        if (virStoragePoolDefParseSource(ctxt, &ret->source, ret->type,
                                         source_node) < 0)
            goto cleanup;
    }

    ret->name = virXPathString("string(./name)", ctxt);
    if (ret->name == NULL &&
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        ret->name = ret->source.name;
    if (ret->name == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing pool source name element"));
        goto cleanup;
    }

    uuid = virXPathString("string(./uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("unable to generate uuid"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("malformed uuid element"));
            goto cleanup;
        }
        VIR_FREE(uuid);
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_HOST) {
        if (!ret->source.host.name) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s",
                                  _("missing storage pool source host name"));
            goto cleanup;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR) {
        if (!ret->source.dir) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("missing storage pool source path"));
            goto cleanup;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME) {
        if (ret->source.name == NULL) {
            /* source name defaults to pool name */
            ret->source.name = strdup(ret->name);
            if (ret->source.name == NULL) {
                virReportOOMError();
                goto cleanup;
            }
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) {
        if (!ret->source.adapter) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("missing storage pool source adapter name"));
            goto cleanup;
        }
    }

    /* If DEVICE is the only source type, then its required */
    if (options->flags == VIR_STORAGE_POOL_SOURCE_DEVICE) {
        if (!ret->source.ndevice) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("missing storage pool source device name"));
            goto cleanup;
        }
    }

    if ((tmppath = virXPathString("string(./target/path)", ctxt)) == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing storage pool target path"));
        goto cleanup;
    }
    ret->target.path = virFileSanitizePath(tmppath);
    VIR_FREE(tmppath);
    if (!ret->target.path)
        goto cleanup;


    if (virStorageDefParsePerms(ctxt, &ret->target.perms,
                                "./target/permissions", 0700) < 0)
        goto cleanup;

    return ret;

 cleanup:
    VIR_FREE(uuid);
    xmlFree(type);
    virStoragePoolDefFree(ret);
    return NULL;
}

virStoragePoolDefPtr
virStoragePoolDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root) {
    xmlXPathContextPtr ctxt = NULL;
    virStoragePoolDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "pool")) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("unknown root element for storage pool"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virStoragePoolDefParseXML(ctxt);
cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virStoragePoolDefPtr
virStoragePoolDefParse(const char *xmlStr,
                       const char *filename) {
    virStoragePoolDefPtr ret = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(storage_pool_definition)")))) {
        ret = virStoragePoolDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return ret;
}

virStoragePoolDefPtr
virStoragePoolDefParseString(const char *xmlStr)
{
    return virStoragePoolDefParse(xmlStr, NULL);
}

virStoragePoolDefPtr
virStoragePoolDefParseFile(const char *filename)
{
    return virStoragePoolDefParse(NULL, filename);
}

static int
virStoragePoolSourceFormat(virBufferPtr buf,
                           virStoragePoolOptionsPtr options,
                           virStoragePoolSourcePtr src)
{
    int i, j;

    virBufferAddLit(buf,"  <source>\n");
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_HOST) &&
        src->host.name) {
        virBufferAsprintf(buf, "    <host name='%s'", src->host.name);
        if (src->host.port)
            virBufferAsprintf(buf, " port='%d'", src->host.port);
        virBufferAddLit(buf, "/>\n");
    }

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_DEVICE) &&
        src->ndevice) {
        for (i = 0 ; i < src->ndevice ; i++) {
            if (src->devices[i].nfreeExtent) {
                virBufferAsprintf(buf,"    <device path='%s'>\n",
                                  src->devices[i].path);
                for (j = 0 ; j < src->devices[i].nfreeExtent ; j++) {
                    virBufferAsprintf(buf, "    <freeExtent start='%llu' end='%llu'/>\n",
                                      src->devices[i].freeExtents[j].start,
                                      src->devices[i].freeExtents[j].end);
                }
                virBufferAddLit(buf,"    </device>\n");
            }
            else
                virBufferAsprintf(buf, "    <device path='%s'/>\n",
                                  src->devices[i].path);
        }
    }
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_DIR) &&
        src->dir)
        virBufferAsprintf(buf,"    <dir path='%s'/>\n", src->dir);
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) &&
        src->adapter)
        virBufferAsprintf(buf,"    <adapter name='%s'/>\n", src->adapter);
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_NAME) &&
        src->name)
        virBufferAsprintf(buf,"    <name>%s</name>\n", src->name);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN) &&
        src->initiator.iqn) {
        virBufferAddLit(buf,"    <initiator>\n");
        virBufferEscapeString(buf,"      <iqn name='%s'/>\n", src->initiator.iqn);
        virBufferAddLit(buf,"    </initiator>\n");
    }

    if (options->formatToString) {
        const char *format = (options->formatToString)(src->format);
        if (!format) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("unknown pool format number %d"),
                                  src->format);
            return -1;
        }
        virBufferAsprintf(buf,"    <format type='%s'/>\n", format);
    }


    if (src->authType == VIR_STORAGE_POOL_AUTH_CHAP)
        virBufferAsprintf(buf,"    <auth type='chap' login='%s' passwd='%s'/>\n",
                          src->auth.chap.login,
                          src->auth.chap.passwd);

    if (src->vendor != NULL) {
        virBufferEscapeString(buf,"    <vendor name='%s'/>\n", src->vendor);
    }

    if (src->product != NULL) {
        virBufferEscapeString(buf,"    <product name='%s'/>\n", src->product);
    }

    virBufferAddLit(buf,"  </source>\n");

    return 0;
}


char *
virStoragePoolDefFormat(virStoragePoolDefPtr def) {
    virStoragePoolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    char uuid[VIR_UUID_STRING_BUFLEN];

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected pool type"));
        goto cleanup;
    }
    virBufferAsprintf(&buf, "<pool type='%s'>\n", type);
    virBufferAsprintf(&buf,"  <name>%s</name>\n", def->name);

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(&buf,"  <uuid>%s</uuid>\n", uuid);

    virBufferAsprintf(&buf,"  <capacity unit='bytes'>%llu</capacity>\n",
                      def->capacity);
    virBufferAsprintf(&buf,"  <allocation unit='bytes'>%llu</allocation>\n",
                      def->allocation);
    virBufferAsprintf(&buf,"  <available unit='bytes'>%llu</available>\n",
                      def->available);

    if (virStoragePoolSourceFormat(&buf, options, &def->source) < 0)
        goto cleanup;

    virBufferAddLit(&buf,"  <target>\n");

    if (def->target.path)
        virBufferAsprintf(&buf,"    <path>%s</path>\n", def->target.path);

    virBufferAddLit(&buf,"    <permissions>\n");
    virBufferAsprintf(&buf,"      <mode>0%o</mode>\n",
                      def->target.perms.mode);
    virBufferAsprintf(&buf,"      <owner>%u</owner>\n",
                      (unsigned int) def->target.perms.uid);
    virBufferAsprintf(&buf,"      <group>%u</group>\n",
                      (unsigned int) def->target.perms.gid);

    if (def->target.perms.label)
        virBufferAsprintf(&buf,"      <label>%s</label>\n",
                          def->target.perms.label);

    virBufferAddLit(&buf,"    </permissions>\n");
    virBufferAddLit(&buf,"  </target>\n");
    virBufferAddLit(&buf,"</pool>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
virStorageSize(const char *unit,
               const char *val,
               unsigned long long *ret)
{
    if (virStrToLong_ull(val, NULL, 10, ret) < 0) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("malformed capacity element"));
        return -1;
    }
    /* off_t is signed, so you cannot create a file larger than 2**63
     * bytes in the first place.  */
    if (virScaleInteger(ret, unit, 1, LLONG_MAX) < 0)
        return -1;

    return 0;
}

static virStorageVolDefPtr
virStorageVolDefParseXML(virStoragePoolDefPtr pool,
                         xmlXPathContextPtr ctxt) {
    virStorageVolDefPtr ret;
    virStorageVolOptionsPtr options;
    char *allocation = NULL;
    char *capacity = NULL;
    char *unit = NULL;
    xmlNodePtr node;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    ret->name = virXPathString("string(./name)", ctxt);
    if (ret->name == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing volume name element"));
        goto cleanup;
    }

    /* Auto-generated so deliberately ignore */
    /*ret->key = virXPathString("string(./key)", ctxt);*/

    capacity = virXPathString("string(./capacity)", ctxt);
    unit = virXPathString("string(./capacity/@unit)", ctxt);
    if (capacity == NULL) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              "%s", _("missing capacity element"));
        goto cleanup;
    }
    if (virStorageSize(unit, capacity, &ret->capacity) < 0)
        goto cleanup;
    VIR_FREE(capacity);
    VIR_FREE(unit);

    allocation = virXPathString("string(./allocation)", ctxt);
    if (allocation) {
        unit = virXPathString("string(./allocation/@unit)", ctxt);
        if (virStorageSize(unit, allocation, &ret->allocation) < 0)
            goto cleanup;
        VIR_FREE(allocation);
        VIR_FREE(unit);
    } else {
        ret->allocation = ret->capacity;
    }

    ret->target.path = virXPathString("string(./target/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString("string(./target/format/@type)", ctxt);
        if (format == NULL)
            ret->target.format = options->defaultFormat;
        else
            ret->target.format = (options->formatFromString)(format);

        if (ret->target.format < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if (virStorageDefParsePerms(ctxt, &ret->target.perms,
                                "./target/permissions", 0600) < 0)
        goto cleanup;

    node = virXPathNode("./target/encryption", ctxt);
    if (node != NULL) {
        ret->target.encryption = virStorageEncryptionParseNode(ctxt->doc,
                                                               node);
        if (ret->target.encryption == NULL)
            goto cleanup;
    }



    ret->backingStore.path = virXPathString("string(./backingStore/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString("string(./backingStore/format/@type)", ctxt);
        if (format == NULL)
            ret->backingStore.format = options->defaultFormat;
        else
            ret->backingStore.format = (options->formatFromString)(format);

        if (ret->backingStore.format < 0) {
            virStorageReportError(VIR_ERR_XML_ERROR,
                                  _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if (virStorageDefParsePerms(ctxt, &ret->backingStore.perms,
                                "./backingStore/permissions", 0600) < 0)
        goto cleanup;

    return ret;

 cleanup:
    VIR_FREE(allocation);
    VIR_FREE(capacity);
    VIR_FREE(unit);
    virStorageVolDefFree(ret);
    return NULL;
}

virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root) {
    xmlXPathContextPtr ctxt = NULL;
    virStorageVolDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "volume")) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                          "%s", _("unknown root element for storage vol"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virStorageVolDefParseXML(pool, ctxt);
cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virStorageVolDefPtr
virStorageVolDefParse(virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename) {
    virStorageVolDefPtr ret = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(storage_volume_definition)")))) {
        ret = virStorageVolDefParseNode(pool, xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return ret;
}

virStorageVolDefPtr
virStorageVolDefParseString(virStoragePoolDefPtr pool,
                            const char *xmlStr)
{
    return virStorageVolDefParse(pool, xmlStr, NULL);
}

virStorageVolDefPtr
virStorageVolDefParseFile(virStoragePoolDefPtr pool,
                          const char *filename)
{
    return virStorageVolDefParse(pool, NULL, filename);
}

static int
virStorageVolTargetDefFormat(virStorageVolOptionsPtr options,
                             virBufferPtr buf,
                             virStorageVolTargetPtr def,
                             const char *type) {
    virBufferAsprintf(buf, "  <%s>\n", type);

    if (def->path)
        virBufferAsprintf(buf,"    <path>%s</path>\n", def->path);

    if (options->formatToString) {
        const char *format = (options->formatToString)(def->format);
        if (!format) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("unknown volume format number %d"),
                                  def->format);
            return -1;
        }
        virBufferAsprintf(buf,"    <format type='%s'/>\n", format);
    }

    virBufferAddLit(buf,"    <permissions>\n");
    virBufferAsprintf(buf,"      <mode>0%o</mode>\n",
                      def->perms.mode);
    virBufferAsprintf(buf,"      <owner>%u</owner>\n",
                      (unsigned int) def->perms.uid);
    virBufferAsprintf(buf,"      <group>%u</group>\n",
                      (unsigned int) def->perms.gid);


    if (def->perms.label)
        virBufferAsprintf(buf,"      <label>%s</label>\n",
                          def->perms.label);

    virBufferAddLit(buf,"    </permissions>\n");

    if (def->encryption) {
        virBufferAdjustIndent(buf, 4);
        if (virStorageEncryptionFormat(buf, def->encryption) < 0)
            return -1;
        virBufferAdjustIndent(buf, -4);
    }

    virBufferAsprintf(buf, "  </%s>\n", type);

    return 0;
}

char *
virStorageVolDefFormat(virStoragePoolDefPtr pool,
                       virStorageVolDefPtr def) {
    virStorageVolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    virBufferAddLit(&buf, "<volume>\n");
    virBufferAsprintf(&buf,"  <name>%s</name>\n", def->name);
    virBufferAsprintf(&buf,"  <key>%s</key>\n", def->key);
    virBufferAddLit(&buf, "  <source>\n");

    if (def->source.nextent) {
        int i;
        const char *thispath = NULL;
        for (i = 0 ; i < def->source.nextent ; i++) {
            if (thispath == NULL ||
                STRNEQ(thispath, def->source.extents[i].path)) {
                if (thispath != NULL)
                    virBufferAddLit(&buf, "    </device>\n");

                virBufferAsprintf(&buf, "    <device path='%s'>\n",
                                  def->source.extents[i].path);
            }

            virBufferAsprintf(&buf,
                              "      <extent start='%llu' end='%llu'/>\n",
                              def->source.extents[i].start,
                              def->source.extents[i].end);
            thispath = def->source.extents[i].path;
        }
        if (thispath != NULL)
            virBufferAddLit(&buf, "    </device>\n");
    }
    virBufferAddLit(&buf, "  </source>\n");

    virBufferAsprintf(&buf,"  <capacity unit='bytes'>%llu</capacity>\n",
                      def->capacity);
    virBufferAsprintf(&buf,"  <allocation unit='bytes'>%llu</allocation>\n",
                      def->allocation);

    if (virStorageVolTargetDefFormat(options, &buf,
                                     &def->target, "target") < 0)
        goto cleanup;

    if (def->backingStore.path &&
        virStorageVolTargetDefFormat(options, &buf,
                                     &def->backingStore, "backingStore") < 0)
        goto cleanup;

    virBufferAddLit(&buf,"</volume>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                            const unsigned char *uuid) {
    unsigned int i;

    for (i = 0 ; i < pools->count ; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (!memcmp(pools->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return pools->objs[i];
        virStoragePoolObjUnlock(pools->objs[i]);
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
                            const char *name) {
    unsigned int i;

    for (i = 0 ; i < pools->count ; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (STREQ(pools->objs[i]->def->name, name))
            return pools->objs[i];
        virStoragePoolObjUnlock(pools->objs[i]);
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolSourceFindDuplicateDevices(virStoragePoolObjPtr pool,
                                         virStoragePoolDefPtr def) {
    unsigned int i, j;

    for (i = 0; i < pool->def->source.ndevice; i++) {
        for (j = 0; j < def->source.ndevice; j++) {
            if (STREQ(pool->def->source.devices[i].path, def->source.devices[j].path))
                return pool;
        }
    }

    return NULL;
}

void
virStoragePoolObjClearVols(virStoragePoolObjPtr pool)
{
    unsigned int i;
    for (i = 0 ; i < pool->volumes.count ; i++)
        virStorageVolDefFree(pool->volumes.objs[i]);

    VIR_FREE(pool->volumes.objs);
    pool->volumes.count = 0;
}

virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr pool,
                          const char *key) {
    unsigned int i;

    for (i = 0 ; i < pool->volumes.count ; i++)
        if (STREQ(pool->volumes.objs[i]->key, key))
            return pool->volumes.objs[i];

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr pool,
                           const char *path) {
    unsigned int i;

    for (i = 0 ; i < pool->volumes.count ; i++)
        if (STREQ(pool->volumes.objs[i]->target.path, path))
            return pool->volumes.objs[i];

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr pool,
                           const char *name) {
    unsigned int i;

    for (i = 0 ; i < pool->volumes.count ; i++)
        if (STREQ(pool->volumes.objs[i]->name, name))
            return pool->volumes.objs[i];

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjAssignDef(virStoragePoolObjListPtr pools,
                           virStoragePoolDefPtr def) {
    virStoragePoolObjPtr pool;

    if ((pool = virStoragePoolObjFindByName(pools, def->name))) {
        if (!virStoragePoolObjIsActive(pool)) {
            virStoragePoolDefFree(pool->def);
            pool->def = def;
        } else {
            virStoragePoolDefFree(pool->newDef);
            pool->newDef = def;
        }
        return pool;
    }

    if (VIR_ALLOC(pool) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&pool->lock) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot initialize mutex"));
        VIR_FREE(pool);
        return NULL;
    }
    virStoragePoolObjLock(pool);
    pool->active = 0;
    pool->def = def;

    if (VIR_REALLOC_N(pools->objs, pools->count+1) < 0) {
        pool->def = NULL;
        virStoragePoolObjUnlock(pool);
        virStoragePoolObjFree(pool);
        virReportOOMError();
        return NULL;
    }
    pools->objs[pools->count++] = pool;

    return pool;
}

static virStoragePoolObjPtr
virStoragePoolObjLoad(virStoragePoolObjListPtr pools,
                      const char *file,
                      const char *path,
                      const char *autostartLink) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;

    if (!(def = virStoragePoolDefParseFile(path))) {
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virStorageReportError(VIR_ERR_XML_ERROR,
                              _("Storage pool config filename '%s' does not match pool name '%s'"),
                              path, def->name);
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    VIR_FREE(pool->configFile);  /* for driver reload */
    pool->configFile = strdup(path);
    if (pool->configFile == NULL) {
        virReportOOMError();
        virStoragePoolDefFree(def);
        return NULL;
    }
    VIR_FREE(pool->autostartLink); /* for driver reload */
    pool->autostartLink = strdup(autostartLink);
    if (pool->autostartLink == NULL) {
        virReportOOMError();
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->autostart = virFileLinkPointsTo(pool->autostartLink,
                                          pool->configFile);

    return pool;
}


int
virStoragePoolLoadAllConfigs(virStoragePoolObjListPtr pools,
                             const char *configDir,
                             const char *autostartDir) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virReportSystemError(errno, _("Failed to open dir '%s'"),
                             configDir);
        return -1;
    }

    while ((entry = readdir(dir))) {
        char *path;
        char *autostartLink;
        virStoragePoolObjPtr pool;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(configDir, entry->d_name, NULL)))
            continue;

        if (!(autostartLink = virFileBuildPath(autostartDir, entry->d_name,
                                               NULL))) {
            VIR_FREE(path);
            continue;
        }

        pool = virStoragePoolObjLoad(pools, entry->d_name, path,
                                     autostartLink);
        if (pool)
            virStoragePoolObjUnlock(pool);

        VIR_FREE(path);
        VIR_FREE(autostartLink);
    }

    closedir(dir);

    return 0;
}

int
virStoragePoolObjSaveDef(virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr pool,
                         virStoragePoolDefPtr def)
{
    char *xml;
    int ret = -1;

    if (!pool->configFile) {
        if (virFileMakePath(driver->configDir) < 0) {
            virReportSystemError(errno,
                                 _("cannot create config directory %s"),
                                 driver->configDir);
            return -1;
        }

        if (!(pool->configFile = virFileBuildPath(driver->configDir,
                                                  def->name, ".xml"))) {
            return -1;
        }

        if (!(pool->autostartLink = virFileBuildPath(driver->autostartDir,
                                                     def->name, ".xml"))) {
            VIR_FREE(pool->configFile);
            return -1;
        }
    }

    if (!(xml = virStoragePoolDefFormat(def))) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("failed to generate XML"));
        return -1;
    }

    ret = virXMLSaveFile(pool->configFile, def->name, "pool-edit", xml);
    VIR_FREE(xml);

    return ret;
}

int
virStoragePoolObjDeleteDef(virStoragePoolObjPtr pool) {
    if (!pool->configFile) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("no config file for %s"), pool->def->name);
        return -1;
    }

    if (unlink(pool->configFile) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("cannot remove config for %s"),
                              pool->def->name);
        return -1;
    }

    return 0;
}

virStoragePoolSourcePtr
virStoragePoolSourceListNewSource(virStoragePoolSourceListPtr list)
{
    virStoragePoolSourcePtr source;

    if (VIR_REALLOC_N(list->sources, list->nsources+1) < 0) {
        virReportOOMError();
        return NULL;
    }

    source = &list->sources[list->nsources++];
    memset(source, 0, sizeof(*source));

    return source;
}

char *virStoragePoolSourceListFormat(virStoragePoolSourceListPtr def)
{
    virStoragePoolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    int i;

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected pool type"));
        goto cleanup;
    }

    virBufferAddLit(&buf, "<sources>\n");

    for (i = 0; i < def->nsources; i++) {
        virStoragePoolSourceFormat(&buf, options, &def->sources[i]);
    }

    virBufferAddLit(&buf, "</sources>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


/*
 * virStoragePoolObjIsDuplicate:
 * @doms : virStoragePoolObjListPtr to search
 * @def  : virStoragePoolDefPtr definition of pool to lookup
 * @check_active: If true, ensure that pool is not active
 *
 * Returns: -1 on error
 *          0 if pool is new
 *          1 if pool is a duplicate
 */
int virStoragePoolObjIsDuplicate(virStoragePoolObjListPtr pools,
                                 virStoragePoolDefPtr def,
                                 unsigned int check_active)
{
    int ret = -1;
    int dupPool = 0;
    virStoragePoolObjPtr pool = NULL;

    /* See if a Pool with matching UUID already exists */
    pool = virStoragePoolObjFindByUUID(pools, def->uuid);
    if (pool) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(pool->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(pool->def->uuid, uuidstr);
            virStorageReportError(VIR_ERR_OPERATION_FAILED,
                                  _("pool '%s' is already defined with uuid %s"),
                                  pool->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if Pool is already active, refuse it */
            if (virStoragePoolObjIsActive(pool)) {
                virStorageReportError(VIR_ERR_OPERATION_INVALID,
                                      _("pool is already active as '%s'"),
                                      pool->def->name);
                goto cleanup;
            }
        }

        dupPool = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        pool = virStoragePoolObjFindByName(pools, def->name);
        if (pool) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(pool->def->uuid, uuidstr);
            virStorageReportError(VIR_ERR_OPERATION_FAILED,
                                  _("pool '%s' already exists with uuid %s"),
                                  def->name, uuidstr);
            goto cleanup;
        }
    }

    ret = dupPool;
cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

int virStoragePoolSourceFindDuplicate(virStoragePoolObjListPtr pools,
                                      virStoragePoolDefPtr def)
{
    int i;
    int ret = 1;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolObjPtr matchpool = NULL;

    /* Check the pool list for duplicate underlying storage */
    for (i = 0; i < pools->count; i++) {
        pool = pools->objs[i];
        if (def->type != pool->def->type)
            continue;

        /* Don't mach against ourself if re-defining existing pool ! */
        if (STREQ(pool->def->name, def->name))
            continue;

        virStoragePoolObjLock(pool);

        switch (pool->def->type) {
        case VIR_STORAGE_POOL_DIR:
            if (STREQ(pool->def->target.path, def->target.path))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_NETFS:
            if ((STREQ(pool->def->source.dir, def->source.dir)) \
                && (STREQ(pool->def->source.host.name, def->source.host.name)))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_SCSI:
            if (STREQ(pool->def->source.adapter, def->source.adapter))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_ISCSI:
        {
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            if (matchpool) {
                if (STREQ(matchpool->def->source.host.name, def->source.host.name)) {
                    if ((matchpool->def->source.initiator.iqn) && (def->source.initiator.iqn)) {
                        if (STREQ(matchpool->def->source.initiator.iqn, def->source.initiator.iqn))
                            break;
                        matchpool = NULL;
                    }
                    break;
                }
                matchpool = NULL;
            }
            break;
        }
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_LOGICAL:
        case VIR_STORAGE_POOL_DISK:
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            break;
        default:
            break;
        }
        virStoragePoolObjUnlock(pool);
    }

    if (matchpool) {
        virStorageReportError(VIR_ERR_OPERATION_FAILED,
                              _("Storage source conflict with pool: '%s'"),
                              matchpool->def->name);
        ret = -1;
    }
    return ret;
}

void virStoragePoolObjLock(virStoragePoolObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virStoragePoolObjUnlock(virStoragePoolObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}
