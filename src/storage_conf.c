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

#include "xml.h"
#include "uuid.h"
#include "buf.h"
#include "util.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

/* Work around broken limits.h on debian etch */
#if defined __GNUC__ && defined _GCC_LIMITS_H_ && ! defined ULLONG_MAX
# define ULLONG_MAX   ULONG_LONG_MAX
#endif

#define virStorageLog(msg...) fprintf(stderr, msg)

VIR_ENUM_IMPL(virStoragePool,
              VIR_STORAGE_POOL_LAST,
              "dir", "fs", "netfs",
              "logical", "disk", "iscsi",
              "scsi")

VIR_ENUM_IMPL(virStoragePoolFormatFileSystem,
              VIR_STORAGE_POOL_FS_LAST,
              "auto", "ext2", "ext3",
              "ext4", "ufs", "iso9660", "udf",
              "gfs", "gfs2", "vfat", "hfs+", "xfs")

VIR_ENUM_IMPL(virStoragePoolFormatFileSystemNet,
              VIR_STORAGE_POOL_NETFS_LAST,
              "auto", "nfs")

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

VIR_ENUM_IMPL(virStorageVolFormatFileSystem,
              VIR_STORAGE_VOL_FILE_LAST,
              "raw", "dir", "bochs",
              "cloop", "cow", "dmg", "iso",
              "qcow", "qcow2", "vmdk", "vpc")


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
            .defaultFormat = VIR_STORAGE_VOL_FILE_RAW,
            .formatFromString = virStorageVolFormatFileSystemTypeFromString,
            .formatToString = virStorageVolFormatFileSystemTypeToString,
        },
    },
    { .poolType = VIR_STORAGE_POOL_FS,
      .poolOptions = {
            .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
            .formatFromString = virStoragePoolFormatFileSystemTypeFromString,
            .formatToString = virStoragePoolFormatFileSystemTypeToString,
        },
      .volOptions = {
            .defaultFormat = VIR_STORAGE_VOL_FILE_RAW,
            .formatFromString = virStorageVolFormatFileSystemTypeFromString,
            .formatToString = virStorageVolFormatFileSystemTypeToString,
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
            .defaultFormat = VIR_STORAGE_VOL_FILE_RAW,
            .formatFromString = virStorageVolFormatFileSystemTypeFromString,
            .formatToString = virStorageVolFormatFileSystemTypeToString,
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
    VIR_FREE(def->backingStore.path);
    VIR_FREE(def->backingStore.perms.label);
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
    auth->login = virXPathString(conn, "string(/pool/source/auth/@login)", ctxt);
    if (auth->login == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth host attribute"));
        return -1;
    }

    auth->passwd = virXPathString(conn, "string(/pool/source/auth/@passwd)", ctxt);
    if (auth->passwd == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth passwd attribute"));
        return -1;
    }

    return 0;
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
virStoragePoolDefParseDoc(virConnectPtr conn,
                          xmlXPathContextPtr ctxt,
                          xmlNodePtr root) {
    virStoragePoolOptionsPtr options;
    virStoragePoolDefPtr ret;
    xmlChar *type = NULL;
    char *uuid = NULL;
    char *authType = NULL;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (STRNEQ((const char *)root->name, "pool")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                          "%s", _("unknown root element for storage pool"));
        goto cleanup;
    }

    type = xmlGetProp(root, BAD_CAST "type");
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

    ret->name = virXPathString(conn, "string(/pool/name)", ctxt);
    if (ret->name == NULL &&
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        ret->name = virXPathString(conn, "string(/pool/source/name)", ctxt);
    if (ret->name == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing pool source name element"));
        goto cleanup;
    }

    uuid = virXPathString(conn, "string(/pool/uuid)", ctxt);
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

    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(/pool/source/format/@type)", ctxt);
        if (format == NULL)
            ret->source.format = options->defaultFormat;
        else
            ret->source.format = options->formatFromString(format);

        if (ret->source.format < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown pool format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_HOST) {
        if ((ret->source.host.name = virXPathString(conn, "string(/pool/source/host/@name)", ctxt)) == NULL) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("missing storage pool source host name"));
            goto cleanup;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_DEVICE) {
        xmlNodePtr *nodeset = NULL;
        int nsource, i;

        if ((nsource = virXPathNodeSet(conn, "/pool/source/device", ctxt, &nodeset)) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                        "%s", _("cannot extract storage pool source devices"));
            goto cleanup;
        }
        if (VIR_ALLOC_N(ret->source.devices, nsource) < 0) {
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
            ret->source.devices[i].path = (char *)path;
        }
        VIR_FREE(nodeset);
        ret->source.ndevice = nsource;
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR) {
        if ((ret->source.dir = virXPathString(conn, "string(/pool/source/dir/@path)", ctxt)) == NULL) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                "%s", _("missing storage pool source path"));
            goto cleanup;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME) {
        ret->source.name = virXPathString(conn, "string(/pool/source/name)",
                                          ctxt);
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
        if ((ret->source.adapter = virXPathString(conn,
                                                  "string(/pool/source/adapter/@name)",
                                                  ctxt)) == NULL) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("missing storage pool source adapter name"));
            goto cleanup;
        }
    }

    authType = virXPathString(conn, "string(/pool/source/auth/@type)", ctxt);
    if (authType == NULL) {
        ret->source.authType = VIR_STORAGE_POOL_AUTH_NONE;
    } else {
        if (STREQ(authType, "chap")) {
            ret->source.authType = VIR_STORAGE_POOL_AUTH_CHAP;
        } else {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown auth type '%s'"),
                                  (const char *)authType);
            VIR_FREE(authType);
            goto cleanup;
        }
        VIR_FREE(authType);
    }

    if (ret->source.authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        if (virStoragePoolDefParseAuthChap(conn, ctxt, &ret->source.auth.chap) < 0)
            goto cleanup;
    }

    if ((ret->target.path = virXPathString(conn, "string(/pool/target/path)", ctxt)) == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing storage pool target path"));
        goto cleanup;
    }

    if (virStorageDefParsePerms(conn, ctxt, &ret->target.perms,
                                "/pool/target/permissions", 0700) < 0)
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
virStoragePoolDefParse(virConnectPtr conn,
                       const char *xmlStr,
                       const char *filename) {
    virStoragePoolDefPtr ret = NULL;
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr ctxt = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr,
                          filename ? filename : "storage.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s",_("failed to parse xml document"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStoragePoolDefParseDoc(conn, ctxt, node);

    xmlFreeParserCtxt (pctxt);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return NULL;
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
        virBufferVSprintf(buf,"    <auth type='chap' login='%s' passwd='%s'>\n",
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

        case 'z':
        case 'Z':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull *
                1024ull * 1024ull;
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
virStorageVolDefParseDoc(virConnectPtr conn,
                         virStoragePoolDefPtr pool,
                         xmlXPathContextPtr ctxt,
                         xmlNodePtr root) {
    virStorageVolDefPtr ret;
    virStorageVolOptionsPtr options;
    char *allocation = NULL;
    char *capacity = NULL;
    char *unit = NULL;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (STRNEQ((const char *)root->name, "volume")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("unknown root element"));
        goto cleanup;
    }

    ret->name = virXPathString(conn, "string(/volume/name)", ctxt);
    if (ret->name == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing volume name element"));
        goto cleanup;
    }

    /* Auto-generated so deliberately ignore */
    /*ret->key = virXPathString(conn, "string(/volume/key)", ctxt);*/

    capacity = virXPathString(conn, "string(/volume/capacity)", ctxt);
    unit = virXPathString(conn, "string(/volume/capacity/@unit)", ctxt);
    if (capacity == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing capacity element"));
        goto cleanup;
    }
    if (virStorageSize(conn, unit, capacity, &ret->capacity) < 0)
        goto cleanup;
    VIR_FREE(capacity);
    VIR_FREE(unit);

    allocation = virXPathString(conn, "string(/volume/allocation)", ctxt);
    if (allocation) {
        unit = virXPathString(conn, "string(/volume/allocation/@unit)", ctxt);
        if (virStorageSize(conn, unit, allocation, &ret->allocation) < 0)
            goto cleanup;
        VIR_FREE(allocation);
        VIR_FREE(unit);
    } else {
        ret->allocation = ret->capacity;
    }

    ret->target.path = virXPathString(conn, "string(/volume/target/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(/volume/target/format/@type)", ctxt);
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
                                "/volume/target/permissions", 0600) < 0)
        goto cleanup;



    ret->backingStore.path = virXPathString(conn, "string(/volume/backingStore/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString(conn, "string(/volume/backingStore/format/@type)", ctxt);
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
                                "/volume/backingStore/permissions", 0600) < 0)
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
virStorageVolDefParse(virConnectPtr conn,
                      virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename) {
    virStorageVolDefPtr ret = NULL;
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr ctxt = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr,
                          filename ? filename : "storage.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStorageVolDefParseDoc(conn, pool, ctxt, node);

    xmlFreeParserCtxt (pctxt);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return NULL;
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
                      const char *xml,
                      const char *autostartLink) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;

    if (!(def = virStoragePoolDefParse(NULL, xml, file))) {
        virErrorPtr err = virGetLastError();
        virStorageLog("Error parsing storage pool config '%s' : %s",
                      path, err ? err->message : NULL);
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virStorageLog("Storage pool config filename '%s' does not match pool name '%s'",
                      path, def->name);
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, pools, def))) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->configFile = strdup(path);
    if (pool->configFile == NULL) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
        virStoragePoolDefFree(def);
        return NULL;
    }
    pool->autostartLink = strdup(autostartLink);
    if (pool->autostartLink == NULL) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
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
        char ebuf[1024];
        if (errno == ENOENT)
            return 0;
        virStorageLog("Failed to open dir '%s': %s",
                      configDir, virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    while ((entry = readdir(dir))) {
        char *xml = NULL;
        char path[PATH_MAX];
        char autostartLink[PATH_MAX];
        virStoragePoolObjPtr pool;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (virFileBuildPath(configDir, entry->d_name,
                             NULL, path, PATH_MAX) < 0) {
            virStorageLog("Config filename '%s/%s' is too long",
                          configDir, entry->d_name);
            continue;
        }

        if (virFileBuildPath(autostartDir, entry->d_name,
                             NULL, autostartLink, PATH_MAX) < 0) {
            virStorageLog("Autostart link path '%s/%s' is too long",
                          autostartDir, entry->d_name);
            continue;
        }

        if (virFileReadAll(path, 8192, &xml) < 0)
            continue;

        pool = virStoragePoolObjLoad(conn, pools, entry->d_name, path, xml, autostartLink);
        if (pool)
            virStoragePoolObjUnlock(pool);

        VIR_FREE(xml);
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
            virStorageReportError(conn, err,
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
