/*
 * storage_conf.c: config handling for storage driver
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define virStorageError(conn, code, fmt...)                             \
            virReportErrorHelper(conn, VIR_FROM_STORAGE, code, __FILE__,\
                                  __FUNCTION__, __LINE__, fmt)

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
              "auto", "nfs", "glusterfs")

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
    VIR_STORAGE_POOL_SOURCE_HOST    = (1<<0),
    VIR_STORAGE_POOL_SOURCE_DEVICE  = (1<<1),
    VIR_STORAGE_POOL_SOURCE_DIR     = (1<<2),
    VIR_STORAGE_POOL_SOURCE_ADAPTER = (1<<3),
    VIR_STORAGE_POOL_SOURCE_NAME    = (1<<4),
};



typedef struct _virStoragePoolOptions virStoragePoolOptions;
typedef virStoragePoolOptions *virStoragePoolOptionsPtr;
struct _virStoragePoolOptions {
    int flags;
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
            .defaultFormat = VIR_STORAGE_POOL_FS_AUTO,
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
                      VIR_STORAGE_POOL_SOURCE_DEVICE),
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

    virStorageReportError(NULL, VIR_ERR_INTERNAL_ERROR,
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
virStoragePoolSourceFree(virStoragePoolSourcePtr source) {
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

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        VIR_FREE(source->auth.chap.login);
        VIR_FREE(source->auth.chap.passwd);
    }
}

void
virStoragePoolDefFree(virStoragePoolDefPtr def) {
    if (!def)
        return;

    VIR_FREE(def->name);

    virStoragePoolSourceFree(&def->source);

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
virStoragePoolDefParseAuthChap(virConnectPtr conn,
                               xmlXPathContextPtr ctxt,
                               virStoragePoolAuthChapPtr auth) {
    auth->login = virXPathString(conn, "string(./auth/@login)", ctxt);
    if (auth->login == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth host attribute"));
        return -1;
    }

    auth->passwd = virXPathString(conn, "string(./auth/@passwd)", ctxt);
    if (auth->passwd == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth passwd attribute"));
        return -1;
    }

    return 0;
}

static int
virStoragePoolDefParseSource(virConnectPtr conn,
                             xmlXPathContextPtr ctxt,
                             virStoragePoolSourcePtr source,
                             int pool_type,
                             xmlNodePtr node) {
    int ret = -1;
    xmlNodePtr relnode, *nodeset = NULL;
    char *authType = NULL;
    int nsource, i;
    virStoragePoolOptionsPtr options;

    relnode = ctxt->node;
    ctxt->node = node;

    if ((options = virStoragePoolOptionsForPoolType(pool_type)) == NULL) {
        goto cleanup;
    }

    source->name = virXPathString(conn, "string(./name)", ctxt);

    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(./format/@type)", ctxt);
        if (format == NULL)
            source->format = options->defaultFormat;
        else
            source->format = options->formatFromString(format);

        if (source->format < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown pool format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    source->host.name = virXPathString(conn, "string(./host/@name)", ctxt);

    nsource = virXPathNodeSet(conn, "./device", ctxt, &nodeset);
    if (nsource > 0) {
        if (VIR_ALLOC_N(source->devices, nsource) < 0) {
            VIR_FREE(nodeset);
            virReportOOMError(conn);
            goto cleanup;
        }

        for (i = 0 ; i < nsource ; i++) {
            xmlChar *path = xmlGetProp(nodeset[i], BAD_CAST "path");
            if (path == NULL) {
                VIR_FREE(nodeset);
                virStorageReportError(conn, VIR_ERR_XML_ERROR,
                        "%s", _("missing storage pool source device path"));
                goto cleanup;
            }
            source->devices[i].path = (char *)path;
        }
        source->ndevice = nsource;
    }

    source->dir = virXPathString(conn, "string(./dir/@path)", ctxt);
    source->adapter = virXPathString(conn, "string(./adapter/@name)", ctxt);

    authType = virXPathString(conn, "string(./auth/@type)", ctxt);
    if (authType == NULL) {
        source->authType = VIR_STORAGE_POOL_AUTH_NONE;
    } else {
        if (STREQ(authType, "chap")) {
            source->authType = VIR_STORAGE_POOL_AUTH_CHAP;
        } else {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown auth type '%s'"),
                                  (const char *)authType);
            goto cleanup;
        }
    }

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        if (virStoragePoolDefParseAuthChap(conn, ctxt, &source->auth.chap) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    ctxt->node = relnode;

    VIR_FREE(authType);
    VIR_FREE(nodeset);
    return ret;
}

virStoragePoolSourcePtr
virStoragePoolDefParseSourceString(virConnectPtr conn,
                                   const char *srcSpec,
                                   int pool_type)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr xpath_ctxt = NULL;
    virStoragePoolSourcePtr def = NULL, ret = NULL;

    doc = xmlReadDoc((const xmlChar *)srcSpec, "srcSpec.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

    if (doc == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("bad <source> spec"));
        goto cleanup;
    }

    xpath_ctxt = xmlXPathNewContext(doc);
    if (xpath_ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    node = virXPathNode(conn, "/source", xpath_ctxt);
    if (!node) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("root element was not source"));
        goto cleanup;
    }

    if (virStoragePoolDefParseSource(conn, xpath_ctxt, def, pool_type,
                                     node) < 0)
        goto cleanup;

    ret = def;
    def = NULL;
cleanup:
    if (def)
        virStoragePoolSourceFree(def);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(xpath_ctxt);

    return ret;
}
static int
virStorageDefParsePerms(virConnectPtr conn,
                        xmlXPathContextPtr ctxt,
                        virStoragePermsPtr perms,
                        const char *permxpath,
                        int defaultmode) {
    char *mode;
    long v;
    int ret = -1;
    xmlNodePtr relnode;
    xmlNodePtr node;

    node = virXPathNode(conn, permxpath, ctxt);
    if (node == NULL) {
        /* Set default values if there is not <permissions> element */
        perms->mode = defaultmode;
        perms->uid = getuid();
        perms->gid = getgid();
        perms->label = NULL;
        return 0;
    }

    relnode = ctxt->node;
    ctxt->node = node;

    mode = virXPathString(conn, "string(./mode)", ctxt);
    if (!mode) {
        perms->mode = defaultmode;
    } else {
        char *end = NULL;
        perms->mode = strtol(mode, &end, 8);
        if (*end || perms->mode < 0 || perms->mode > 0777) {
            VIR_FREE(mode);
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed octal mode"));
            goto error;
        }
        VIR_FREE(mode);
    }

    if (virXPathNode(conn, "./owner", ctxt) == NULL) {
        perms->uid = getuid();
    } else {
        if (virXPathLong(conn, "number(./owner)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed owner element"));
            goto error;
        }
        perms->uid = (int)v;
    }

    if (virXPathNode(conn, "./group", ctxt) == NULL) {
        perms->gid = getgid();
    } else {
        if (virXPathLong(conn, "number(./group)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed group element"));
            goto error;
        }
        perms->gid = (int)v;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString(conn, "string(./label)", ctxt);

    ret = 0;
error:
    ctxt->node = relnode;
    return ret;
}

static virStoragePoolDefPtr
virStoragePoolDefParseXML(virConnectPtr conn,
                          xmlXPathContextPtr ctxt) {
    virStoragePoolOptionsPtr options;
    virStoragePoolDefPtr ret;
    xmlNodePtr source_node;
    char *type = NULL;
    char *uuid = NULL;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXPathString(conn, "string(./@type)", ctxt);
    if ((ret->type = virStoragePoolTypeFromString((const char *)type)) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage pool type %s"), (const char*)type);
        goto cleanup;
    }

    xmlFree(type);
    type = NULL;

    if ((options = virStoragePoolOptionsForPoolType(ret->type)) == NULL) {
        goto cleanup;
    }

    source_node = virXPathNode(conn, "./source", ctxt);
    if (source_node) {
        if (virStoragePoolDefParseSource(conn, ctxt, &ret->source, ret->type,
                                         source_node) < 0)
            goto cleanup;
    }

    ret->name = virXPathString(conn, "string(./name)", ctxt);
    if (ret->name == NULL &&
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        ret->name = ret->source.name;
    if (ret->name == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing pool source name element"));
        goto cleanup;
    }

    uuid = virXPathString(conn, "string(./uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("unable to generate uuid"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed uuid element"));
            goto cleanup;
        }
        VIR_FREE(uuid);
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_HOST) {
        if (!ret->source.host.name) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s",
                                  _("missing storage pool source host name"));
            goto cleanup;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR) {
        if (!ret->source.dir) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing storage pool source path"));
            goto cleanup;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME) {
        if (ret->source.name == NULL) {
            /* source name defaults to pool name */
            ret->source.name = strdup(ret->name);
            if (ret->source.name == NULL) {
                virReportOOMError(conn);
                goto cleanup;
            }
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) {
        if (!ret->source.adapter) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing storage pool source adapter name"));
            goto cleanup;
        }
    }

    if ((ret->target.path = virXPathString(conn, "string(./target/path)", ctxt)) == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing storage pool target path"));
        goto cleanup;
    }

    if (virStorageDefParsePerms(conn, ctxt, &ret->target.perms,
                                "./target/permissions", 0700) < 0)
        goto cleanup;

    return ret;

 cleanup:
    VIR_FREE(uuid);
    xmlFree(type);
    virStoragePoolDefFree(ret);
    return NULL;
}

/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError (void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (conn &&
            conn->err.code == VIR_ERR_NONE &&
            ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            virStorageReportError (conn, VIR_ERR_XML_DETAIL,
                                   _("at line %d: %s"),
                                   ctxt->lastError.line,
                                   ctxt->lastError.message);
        }
    }
}

virStoragePoolDefPtr
virStoragePoolDefParseNode(virConnectPtr conn,
                           xmlDocPtr xml,
                           xmlNodePtr root) {
    xmlXPathContextPtr ctxt = NULL;
    virStoragePoolDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "pool")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                          "%s", _("unknown root element for storage pool"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    def = virStoragePoolDefParseXML(conn, ctxt);
cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virStoragePoolDefPtr
virStoragePoolDefParse(virConnectPtr conn,
                       const char *xmlStr,
                       const char *filename) {
    virStoragePoolDefPtr ret = NULL;
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    if (filename) {
        xml = xmlCtxtReadFile (pctxt, filename, NULL,
                               XML_PARSE_NOENT | XML_PARSE_NONET |
                               XML_PARSE_NOWARNING);
    } else {
        xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr,
                              "storage.xml", NULL,
                              XML_PARSE_NOENT | XML_PARSE_NONET |
                              XML_PARSE_NOWARNING);
    }

    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s",_("failed to parse xml document"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStoragePoolDefParseNode(conn, xml, node);

    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc(xml);
    return NULL;
}

virStoragePoolDefPtr
virStoragePoolDefParseString(virConnectPtr conn,
                             const char *xmlStr)
{
    return virStoragePoolDefParse(conn, xmlStr, NULL);
}

virStoragePoolDefPtr
virStoragePoolDefParseFile(virConnectPtr conn,
                           const char *filename)
{
    return virStoragePoolDefParse(conn, NULL, filename);
}

static int
virStoragePoolSourceFormat(virConnectPtr conn,
                           virBufferPtr buf,
                           virStoragePoolOptionsPtr options,
                           virStoragePoolSourcePtr src)
{
    int i, j;

    virBufferAddLit(buf,"  <source>\n");
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_HOST) &&
        src->host.name)
        virBufferVSprintf(buf,"    <host name='%s'/>\n", src->host.name);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_DEVICE) &&
        src->ndevice) {
        for (i = 0 ; i < src->ndevice ; i++) {
            if (src->devices[i].nfreeExtent) {
                virBufferVSprintf(buf,"    <device path='%s'>\n",
                                  src->devices[i].path);
                for (j = 0 ; j < src->devices[i].nfreeExtent ; j++) {
                    virBufferVSprintf(buf, "    <freeExtent start='%llu' end='%llu'/>\n",
                                      src->devices[i].freeExtents[j].start,
                                      src->devices[i].freeExtents[j].end);
                }
                virBufferAddLit(buf,"    </device>\n");
            }
            else
                virBufferVSprintf(buf, "    <device path='%s'/>\n",
                                  src->devices[i].path);
        }
    }
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_DIR) &&
        src->dir)
        virBufferVSprintf(buf,"    <dir path='%s'/>\n", src->dir);
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) &&
        src->adapter)
        virBufferVSprintf(buf,"    <adapter name='%s'/>\n", src->adapter);
    if ((options->flags & VIR_STORAGE_POOL_SOURCE_NAME) &&
        src->name)
        virBufferVSprintf(buf,"    <name>%s</name>\n", src->name);

    if (options->formatToString) {
        const char *format = (options->formatToString)(src->format);
        if (!format) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown pool format number %d"),
                                  src->format);
            return -1;
        }
        virBufferVSprintf(buf,"    <format type='%s'/>\n", format);
    }


    if (src->authType == VIR_STORAGE_POOL_AUTH_CHAP)
        virBufferVSprintf(buf,"    <auth type='chap' login='%s' passwd='%s'/>\n",
                          src->auth.chap.login,
                          src->auth.chap.passwd);
    virBufferAddLit(buf,"  </source>\n");

    return 0;
}


char *
virStoragePoolDefFormat(virConnectPtr conn,
                        virStoragePoolDefPtr def) {
    virStoragePoolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    char uuid[VIR_UUID_STRING_BUFLEN];

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected pool type"));
        goto cleanup;
    }
    virBufferVSprintf(&buf, "<pool type='%s'>\n", type);
    virBufferVSprintf(&buf,"  <name>%s</name>\n", def->name);

    virUUIDFormat(def->uuid, uuid);
    virBufferVSprintf(&buf,"  <uuid>%s</uuid>\n", uuid);

    virBufferVSprintf(&buf,"  <capacity>%llu</capacity>\n",
                      def->capacity);
    virBufferVSprintf(&buf,"  <allocation>%llu</allocation>\n",
                      def->allocation);
    virBufferVSprintf(&buf,"  <available>%llu</available>\n",
                      def->available);

    if (virStoragePoolSourceFormat(conn, &buf, options, &def->source) < 0)
        goto cleanup;

    virBufferAddLit(&buf,"  <target>\n");

    if (def->target.path)
        virBufferVSprintf(&buf,"    <path>%s</path>\n", def->target.path);

    virBufferAddLit(&buf,"    <permissions>\n");
    virBufferVSprintf(&buf,"      <mode>0%o</mode>\n",
                      def->target.perms.mode);
    virBufferVSprintf(&buf,"      <owner>%d</owner>\n",
                      def->target.perms.uid);
    virBufferVSprintf(&buf,"      <group>%d</group>\n",
                      def->target.perms.gid);

    if (def->target.perms.label)
        virBufferVSprintf(&buf,"      <label>%s</label>\n",
                          def->target.perms.label);

    virBufferAddLit(&buf,"    </permissions>\n");
    virBufferAddLit(&buf,"  </target>\n");
    virBufferAddLit(&buf,"</pool>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError(conn);
 cleanup:
    free(virBufferContentAndReset(&buf));
    return NULL;
}


static int
virStorageSize(virConnectPtr conn,
               const char *unit,
               const char *val,
               unsigned long long *ret) {
    unsigned long long mult;
    char *end;

    if (!unit) {
        mult = 1;
    } else {
        switch (unit[0]) {
        case 'k':
        case 'K':
            mult = 1024ull;
            break;

        case 'm':
        case 'M':
            mult = 1024ull * 1024ull;
            break;

        case 'g':
        case 'G':
            mult = 1024ull * 1024ull * 1024ull;
            break;

        case 't':
        case 'T':
            mult = 1024ull * 1024ull * 1024ull * 1024ull;
            break;

        case 'p':
        case 'P':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull;
            break;

        case 'y':
        case 'Y':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull *
                1024ull;
            break;

        default:
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown size units '%s'"), unit);
            return -1;
        }
    }

    if (virStrToLong_ull (val, &end, 10, ret) < 0) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("malformed capacity element"));
        return -1;
    }
    if (*ret > (ULLONG_MAX / mult)) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("capacity element value too large"));
            return -1;
    }

    *ret *= mult;

    return 0;
}

static virStorageVolDefPtr
virStorageVolDefParseXML(virConnectPtr conn,
                         virStoragePoolDefPtr pool,
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
        virReportOOMError(conn);
        return NULL;
    }

    ret->name = virXPathString(conn, "string(./name)", ctxt);
    if (ret->name == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing volume name element"));
        goto cleanup;
    }

    /* Auto-generated so deliberately ignore */
    /*ret->key = virXPathString(conn, "string(./key)", ctxt);*/

    capacity = virXPathString(conn, "string(./capacity)", ctxt);
    unit = virXPathString(conn, "string(./capacity/@unit)", ctxt);
    if (capacity == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing capacity element"));
        goto cleanup;
    }
    if (virStorageSize(conn, unit, capacity, &ret->capacity) < 0)
        goto cleanup;
    VIR_FREE(capacity);
    VIR_FREE(unit);

    allocation = virXPathString(conn, "string(./allocation)", ctxt);
    if (allocation) {
        unit = virXPathString(conn, "string(./allocation/@unit)", ctxt);
        if (virStorageSize(conn, unit, allocation, &ret->allocation) < 0)
            goto cleanup;
        VIR_FREE(allocation);
        VIR_FREE(unit);
    } else {
        ret->allocation = ret->capacity;
    }

    ret->target.path = virXPathString(conn, "string(./target/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(./target/format/@type)", ctxt);
        if (format == NULL)
            ret->target.format = options->defaultFormat;
        else
            ret->target.format = (options->formatFromString)(format);

        if (ret->target.format < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if (virStorageDefParsePerms(conn, ctxt, &ret->target.perms,
                                "./target/permissions", 0600) < 0)
        goto cleanup;

    node = virXPathNode(conn, "./target/encryption", ctxt);
    if (node != NULL) {
        ret->target.encryption = virStorageEncryptionParseNode(conn, ctxt->doc,
                                                               node);
        if (ret->target.encryption == NULL)
            goto cleanup;
    }



    ret->backingStore.path = virXPathString(conn, "string(./backingStore/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(./backingStore/format/@type)", ctxt);
        if (format == NULL)
            ret->backingStore.format = options->defaultFormat;
        else
            ret->backingStore.format = (options->formatFromString)(format);

        if (ret->backingStore.format < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if (virStorageDefParsePerms(conn, ctxt, &ret->backingStore.perms,
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
virStorageVolDefParseNode(virConnectPtr conn,
                          virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root) {
    xmlXPathContextPtr ctxt = NULL;
    virStorageVolDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "volume")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                          "%s", _("unknown root element for storage vol"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    def = virStorageVolDefParseXML(conn, pool, ctxt);
cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virStorageVolDefPtr
virStorageVolDefParse(virConnectPtr conn,
                      virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename) {
    virStorageVolDefPtr ret = NULL;
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);

    if (filename) {
        xml = xmlCtxtReadFile (pctxt, filename, NULL,
                               XML_PARSE_NOENT | XML_PARSE_NONET |
                               XML_PARSE_NOWARNING);
    } else {
        xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr,
                              "storage.xml", NULL,
                              XML_PARSE_NOENT | XML_PARSE_NONET |
                              XML_PARSE_NOWARNING);
    }

    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStorageVolDefParseNode(conn, pool, xml, node);

    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc(xml);
    return NULL;
}

virStorageVolDefPtr
virStorageVolDefParseString(virConnectPtr conn,
                            virStoragePoolDefPtr pool,
                            const char *xmlStr)
{
    return virStorageVolDefParse(conn, pool, xmlStr, NULL);
}

virStorageVolDefPtr
virStorageVolDefParseFile(virConnectPtr conn,
                          virStoragePoolDefPtr pool,
                          const char *filename)
{
    return virStorageVolDefParse(conn, pool, NULL, filename);
}

static int
virStorageVolTargetDefFormat(virConnectPtr conn,
                             virStorageVolOptionsPtr options,
                             virBufferPtr buf,
                             virStorageVolTargetPtr def,
                             const char *type) {
    virBufferVSprintf(buf, "  <%s>\n", type);

    if (def->path)
        virBufferVSprintf(buf,"    <path>%s</path>\n", def->path);

    if (options->formatToString) {
        const char *format = (options->formatToString)(def->format);
        if (!format) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown volume format number %d"),
                                  def->format);
            return -1;
        }
        virBufferVSprintf(buf,"    <format type='%s'/>\n", format);
    }

    virBufferAddLit(buf,"    <permissions>\n");
    virBufferVSprintf(buf,"      <mode>0%o</mode>\n",
                      def->perms.mode);
    virBufferVSprintf(buf,"      <owner>%d</owner>\n",
                      def->perms.uid);
    virBufferVSprintf(buf,"      <group>%d</group>\n",
                      def->perms.gid);


    if (def->perms.label)
        virBufferVSprintf(buf,"      <label>%s</label>\n",
                          def->perms.label);

    virBufferAddLit(buf,"    </permissions>\n");

    if (def->encryption != NULL &&
        virStorageEncryptionFormat(conn, buf, def->encryption) < 0)
        return -1;

    virBufferVSprintf(buf, "  </%s>\n", type);

    return 0;
}

char *
virStorageVolDefFormat(virConnectPtr conn,
                       virStoragePoolDefPtr pool,
                       virStorageVolDefPtr def) {
    virStorageVolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *tmp;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    virBufferAddLit(&buf, "<volume>\n");
    virBufferVSprintf(&buf,"  <name>%s</name>\n", def->name);
    virBufferVSprintf(&buf,"  <key>%s</key>\n", def->key);
    virBufferAddLit(&buf, "  <source>\n");

    if (def->source.nextent) {
        int i;
        const char *thispath = NULL;
        for (i = 0 ; i < def->source.nextent ; i++) {
            if (thispath == NULL ||
                STRNEQ(thispath, def->source.extents[i].path)) {
                if (thispath != NULL)
                    virBufferAddLit(&buf, "    </device>\n");

                virBufferVSprintf(&buf, "    <device path='%s'>\n",
                                  def->source.extents[i].path);
            }

            virBufferVSprintf(&buf,
                              "      <extent start='%llu' end='%llu'/>\n",
                              def->source.extents[i].start,
                              def->source.extents[i].end);
            thispath = def->source.extents[i].path;
        }
        if (thispath != NULL)
            virBufferAddLit(&buf, "    </device>\n");
    }
    virBufferAddLit(&buf, "  </source>\n");

    virBufferVSprintf(&buf,"  <capacity>%llu</capacity>\n",
                      def->capacity);
    virBufferVSprintf(&buf,"  <allocation>%llu</allocation>\n",
                      def->allocation);

    if (virStorageVolTargetDefFormat(conn, options, &buf,
                                     &def->target, "target") < 0)
        goto cleanup;

    if (def->backingStore.path &&
        virStorageVolTargetDefFormat(conn, options, &buf,
                                     &def->backingStore, "backingStore") < 0)
        goto cleanup;

    virBufferAddLit(&buf,"</volume>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError(conn);
 cleanup:
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
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
virStoragePoolObjAssignDef(virConnectPtr conn,
                           virStoragePoolObjListPtr pools,
                           virStoragePoolDefPtr def) {
    virStoragePoolObjPtr pool;

    if ((pool = virStoragePoolObjFindByName(pools, def->name))) {
        if (!virStoragePoolObjIsActive(pool)) {
            virStoragePoolDefFree(pool->def);
            pool->def = def;
        } else {
            if (pool->newDef)
                virStoragePoolDefFree(pool->newDef);
            pool->newDef = def;
        }
        return pool;
    }

    if (VIR_ALLOC(pool) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (virMutexInit(&pool->lock) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
        virReportOOMError(conn);
        return NULL;
    }
    pools->objs[pools->count++] = pool;

    return pool;
}

static virStoragePoolObjPtr
virStoragePoolObjLoad(virConnectPtr conn,
                      virStoragePoolObjListPtr pools,
                      const char *file,
                      const char *path,
                      const char *autostartLink) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;

    if (!(def = virStoragePoolDefParseFile(conn, path))) {
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virStorageError(conn, VIR_ERR_INVALID_STORAGE_POOL,
            "Storage pool config filename '%s' does not match pool name '%s'",
                      path, def->name);
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->configFile = strdup(path);
    if (pool->configFile == NULL) {
        virReportOOMError(conn);
        virStoragePoolDefFree(def);
        return NULL;
    }
    pool->autostartLink = strdup(autostartLink);
    if (pool->autostartLink == NULL) {
        virReportOOMError(conn);
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->autostart = virFileLinkPointsTo(pool->autostartLink,
                                          pool->configFile);

    return pool;
}


int
virStoragePoolLoadAllConfigs(virConnectPtr conn,
                             virStoragePoolObjListPtr pools,
                             const char *configDir,
                             const char *autostartDir) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virReportSystemError(conn, errno, _("Failed to open dir '%s'"),
                             configDir);
        return -1;
    }

    while ((entry = readdir(dir))) {
        char path[PATH_MAX];
        char autostartLink[PATH_MAX];
        virStoragePoolObjPtr pool;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (virFileBuildPath(configDir, entry->d_name,
                             NULL, path, PATH_MAX) < 0) {
            virStorageError(conn, VIR_ERR_INTERNAL_ERROR,
                            "Config filename '%s/%s' is too long",
                            configDir, entry->d_name);
            continue;
        }

        if (virFileBuildPath(autostartDir, entry->d_name,
                             NULL, autostartLink, PATH_MAX) < 0) {
            virStorageError(conn, VIR_ERR_INTERNAL_ERROR,
                            "Autostart link path '%s/%s' is too long",
                            autostartDir, entry->d_name);
            continue;
        }

        pool = virStoragePoolObjLoad(conn, pools, entry->d_name, path,
                                     autostartLink);
        if (pool)
            virStoragePoolObjUnlock(pool);
    }

    closedir(dir);

    return 0;
}

int
virStoragePoolObjSaveDef(virConnectPtr conn,
                         virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr pool,
                         virStoragePoolDefPtr def) {
    char *xml;
    int fd = -1, ret = -1;
    ssize_t towrite;

    if (!pool->configFile) {
        int err;
        char path[PATH_MAX];

        if ((err = virFileMakePath(driver->configDir))) {
            virReportSystemError(conn, err,
                                 _("cannot create config directory %s"),
                                 driver->configDir);
            return -1;
        }

        if (virFileBuildPath(driver->configDir, def->name, ".xml",
                             path, sizeof(path)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot construct config file path"));
            return -1;
        }
        if (!(pool->configFile = strdup(path))) {
            virReportOOMError(conn);
            return -1;
        }

        if (virFileBuildPath(driver->autostartDir, def->name, ".xml",
                             path, sizeof(path)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot construct "
                                          "autostart link path"));
            VIR_FREE(pool->configFile);
            return -1;
        }
        if (!(pool->autostartLink = strdup(path))) {
            virReportOOMError(conn);
            VIR_FREE(pool->configFile);
            return -1;
        }
    }

    if (!(xml = virStoragePoolDefFormat(conn, def))) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("failed to generate XML"));
        return -1;
    }

    if ((fd = open(pool->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create config file %s"),
                             pool->configFile);
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) != towrite) {
        virReportSystemError(conn, errno,
                             _("cannot write config file %s"),
                             pool->configFile);
        goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot save config file %s"),
                             pool->configFile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (fd != -1)
        close(fd);

    VIR_FREE(xml);

    return ret;
}

int
virStoragePoolObjDeleteDef(virConnectPtr conn,
                           virStoragePoolObjPtr pool) {
    if (!pool->configFile) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("no config file for %s"), pool->def->name);
        return -1;
    }

    if (unlink(pool->configFile) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot remove config for %s"),
                              pool->def->name);
        return -1;
    }

    return 0;
}

virStoragePoolSourcePtr
virStoragePoolSourceListNewSource(virConnectPtr conn,
                                  virStoragePoolSourceListPtr list)
{
    virStoragePoolSourcePtr source;

    if (VIR_ALLOC(source) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (VIR_REALLOC_N(list->sources, list->nsources+1) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    source = &list->sources[list->nsources++];
    memset(source, 0, sizeof(*source));

    return source;
}

char *virStoragePoolSourceListFormat(virConnectPtr conn,
                                     virStoragePoolSourceListPtr def)
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
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected pool type"));
        goto cleanup;
    }

    virBufferAddLit(&buf, "<sources>\n");

    for (i = 0; i < def->nsources; i++) {
        virStoragePoolSourceFormat(conn, &buf, options, &def->sources[i]);
    }

    virBufferAddLit(&buf, "</sources>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError(conn);
 cleanup:
    free(virBufferContentAndReset(&buf));
    return NULL;
}


void virStoragePoolObjLock(virStoragePoolObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virStoragePoolObjUnlock(virStoragePoolObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}
