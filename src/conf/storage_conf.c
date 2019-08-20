/*
 * storage_conf.c: config handling for storage driver
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "virerror.h"
#include "datatypes.h"
#include "node_device_conf.h"
#include "storage_adapter_conf.h"
#include "storage_conf.h"
#include "virstoragefile.h"

#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virscsihost.h"
#include "virstring.h"
#include "virlog.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("conf.storage_conf");

VIR_ENUM_IMPL(virStorageVol,
              VIR_STORAGE_VOL_LAST,
              "file", "block", "dir", "network",
              "netdir", "ploop",
);

VIR_ENUM_IMPL(virStoragePool,
              VIR_STORAGE_POOL_LAST,
              "dir", "fs", "netfs",
              "logical", "disk", "iscsi",
              "iscsi-direct", "scsi", "mpath",
              "rbd", "sheepdog", "gluster",
              "zfs", "vstorage",
);

VIR_ENUM_IMPL(virStoragePoolFormatFileSystem,
              VIR_STORAGE_POOL_FS_LAST,
              "auto", "ext2", "ext3",
              "ext4", "ufs", "iso9660", "udf",
              "gfs", "gfs2", "vfat", "hfs+", "xfs", "ocfs2",
);

VIR_ENUM_IMPL(virStoragePoolFormatFileSystemNet,
              VIR_STORAGE_POOL_NETFS_LAST,
              "auto", "nfs", "glusterfs", "cifs",
);

VIR_ENUM_IMPL(virStoragePoolFormatDisk,
              VIR_STORAGE_POOL_DISK_LAST,
              "unknown", "dos", "dvh", "gpt",
              "mac", "bsd", "pc98", "sun", "lvm2",
);

VIR_ENUM_IMPL(virStoragePoolFormatLogical,
              VIR_STORAGE_POOL_LOGICAL_LAST,
              "unknown", "lvm2",
);


VIR_ENUM_IMPL(virStorageVolFormatDisk,
              VIR_STORAGE_VOL_DISK_LAST,
              "none", "linux", "fat16",
              "fat32", "linux-swap",
              "linux-lvm", "linux-raid",
              "extended",
);

VIR_ENUM_IMPL(virStorageVolDefRefreshAllocation,
              VIR_STORAGE_VOL_DEF_REFRESH_ALLOCATION_LAST,
              "default", "capacity",
);

VIR_ENUM_IMPL(virStoragePartedFs,
              VIR_STORAGE_PARTED_FS_TYPE_LAST,
              "ext2", "ext2", "fat16",
              "fat32", "linux-swap",
              "ext2", "ext2",
              "extended",
);

typedef const char *(*virStorageVolFormatToString)(int format);
typedef int (*virStorageVolFormatFromString)(const char *format);

typedef const char *(*virStoragePoolFormatToString)(int format);
typedef int (*virStoragePoolFormatFromString)(const char *format);

typedef struct _virStorageVolOptions virStorageVolOptions;
typedef virStorageVolOptions *virStorageVolOptionsPtr;
struct _virStorageVolOptions {
    int defaultFormat;
    int lastFormat;
    virStorageVolFormatToString formatToString;
    virStorageVolFormatFromString formatFromString;
};

/* Flags to indicate mandatory components in the pool source */
enum {
    VIR_STORAGE_POOL_SOURCE_HOST            = (1 << 0),
    VIR_STORAGE_POOL_SOURCE_DEVICE          = (1 << 1),
    VIR_STORAGE_POOL_SOURCE_DIR             = (1 << 2),
    VIR_STORAGE_POOL_SOURCE_ADAPTER         = (1 << 3),
    VIR_STORAGE_POOL_SOURCE_NAME            = (1 << 4),
    VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN   = (1 << 5),
    VIR_STORAGE_POOL_SOURCE_NETWORK         = (1 << 6),
};

typedef struct _virStoragePoolOptions virStoragePoolOptions;
typedef virStoragePoolOptions *virStoragePoolOptionsPtr;
struct _virStoragePoolOptions {
    unsigned int flags;
    int defaultFormat;
    int lastFormat;

    virXMLNamespace ns;

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


static int
virStorageVolumeFormatFromString(const char *format)
{
    int ret = virStorageFileFormatTypeFromString(format);
    if (ret == VIR_STORAGE_FILE_NONE)
        return -1;
    return ret;
}


static virStoragePoolTypeInfo poolTypeInfo[] = {
    {.poolType = VIR_STORAGE_POOL_LOGICAL,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_NAME |
                   VIR_STORAGE_POOL_SOURCE_DEVICE),
         .defaultFormat = VIR_STORAGE_POOL_LOGICAL_LVM2,
         .lastFormat = VIR_STORAGE_POOL_LOGICAL_LAST,
         .formatFromString = virStoragePoolFormatLogicalTypeFromString,
         .formatToString = virStoragePoolFormatLogicalTypeToString,
     },
    },
    {.poolType = VIR_STORAGE_POOL_DIR,
     .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .lastFormat = VIR_STORAGE_FILE_LAST,
         .formatFromString = virStorageVolumeFormatFromString,
         .formatToString = virStorageFileFormatTypeToString,
     },
    },
    {.poolType = VIR_STORAGE_POOL_FS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
         .defaultFormat = VIR_STORAGE_POOL_FS_AUTO,
         .lastFormat = VIR_STORAGE_POOL_FS_LAST,
         .formatFromString = virStoragePoolFormatFileSystemTypeFromString,
         .formatToString = virStoragePoolFormatFileSystemTypeToString,
      },
      .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .lastFormat = VIR_STORAGE_FILE_LAST,
         .formatFromString = virStorageVolumeFormatFromString,
         .formatToString = virStorageFileFormatTypeToString,
      },
    },
    {.poolType = VIR_STORAGE_POOL_NETFS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_DIR),
         .defaultFormat = VIR_STORAGE_POOL_NETFS_AUTO,
         .lastFormat = VIR_STORAGE_POOL_NETFS_LAST,
         .formatFromString = virStoragePoolFormatFileSystemNetTypeFromString,
         .formatToString = virStoragePoolFormatFileSystemNetTypeToString,
      },
      .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .lastFormat = VIR_STORAGE_FILE_LAST,
         .formatFromString = virStorageVolumeFormatFromString,
         .formatToString = virStorageFileFormatTypeToString,
      },
    },
    {.poolType = VIR_STORAGE_POOL_ISCSI,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_DEVICE |
                   VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN),
      },
    },
    {.poolType = VIR_STORAGE_POOL_ISCSI_DIRECT,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_DEVICE |
                   VIR_STORAGE_POOL_SOURCE_NETWORK |
                   VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN),
      },
    },
    {.poolType = VIR_STORAGE_POOL_SCSI,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_ADAPTER),
     },
    },
    {.poolType = VIR_STORAGE_POOL_RBD,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_NETWORK |
                   VIR_STORAGE_POOL_SOURCE_NAME),
      },
      .volOptions = {
          .defaultFormat = VIR_STORAGE_FILE_RAW,
          .formatFromString = virStorageVolumeFormatFromString,
          .formatToString = virStorageFileFormatTypeToString,
      }
    },
    {.poolType = VIR_STORAGE_POOL_SHEEPDOG,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_NETWORK |
                   VIR_STORAGE_POOL_SOURCE_NAME),
     },
    },
    {.poolType = VIR_STORAGE_POOL_GLUSTER,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_NETWORK |
                   VIR_STORAGE_POOL_SOURCE_NAME |
                   VIR_STORAGE_POOL_SOURCE_DIR),
     },
     .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .lastFormat = VIR_STORAGE_FILE_LAST,
         .formatToString = virStorageFileFormatTypeToString,
         .formatFromString = virStorageVolumeFormatFromString,
     }
    },
    {.poolType = VIR_STORAGE_POOL_MPATH,
    },
    {.poolType = VIR_STORAGE_POOL_DISK,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
         .defaultFormat = VIR_STORAGE_POOL_DISK_UNKNOWN,
         .lastFormat = VIR_STORAGE_POOL_DISK_LAST,
         .formatFromString = virStoragePoolFormatDiskTypeFromString,
         .formatToString = virStoragePoolFormatDiskTypeToString,
     },
     .volOptions = {
         .defaultFormat = VIR_STORAGE_VOL_DISK_NONE,
         .lastFormat = VIR_STORAGE_VOL_DISK_LAST,
         .formatFromString = virStorageVolFormatDiskTypeFromString,
         .formatToString = virStorageVolFormatDiskTypeToString,
     },
    },
    {.poolType = VIR_STORAGE_POOL_ZFS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_NAME |
                   VIR_STORAGE_POOL_SOURCE_DEVICE),
     },
    },
    {.poolType = VIR_STORAGE_POOL_VSTORAGE,
     .poolOptions = {
        .flags = VIR_STORAGE_POOL_SOURCE_NAME,
     },
     .volOptions = {
        .defaultFormat = VIR_STORAGE_FILE_RAW,
        .lastFormat = VIR_STORAGE_FILE_LAST,
        .formatFromString = virStorageVolumeFormatFromString,
        .formatToString = virStorageFileFormatTypeToString,
     },
    },
};


static virStoragePoolTypeInfoPtr
virStoragePoolTypeInfoLookup(int type)
{
    size_t i;
    for (i = 0; i < ARRAY_CARDINALITY(poolTypeInfo); i++)
        if (poolTypeInfo[i].poolType == type)
            return &poolTypeInfo[i];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing backend for pool type %d"), type);
    return NULL;
}


static virStoragePoolOptionsPtr
virStoragePoolOptionsForPoolType(int type)
{
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->poolOptions;
}


/* virStoragePoolOptionsPoolTypeSetXMLNamespace:
 * @type: virStoragePoolType
 * @ns: xmlopt namespace pointer
 *
 * Store the @ns in the pool options for the particular backend.
 * This allows the parse/format code to then directly call the Namespace
 * method space (parse, format, href, free) as needed during processing.
 *
 * Returns: 0 on success, -1 on failure.
 */
int
virStoragePoolOptionsPoolTypeSetXMLNamespace(int type,
                                             virXMLNamespacePtr ns)
{
    int ret = -1;
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);

    if (!backend)
        goto cleanup;

    backend->poolOptions.ns = *ns;
    ret = 0;

 cleanup:
    return ret;
}


static virStorageVolOptionsPtr
virStorageVolOptionsForPoolType(int type)
{
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->volOptions;
}


int
virStoragePoolOptionsFormatPool(virBufferPtr buf,
                                int type)
{
    virStoragePoolOptionsPtr poolOptions;

    if (!(poolOptions = virStoragePoolOptionsForPoolType(type)))
        return -1;

    if (!poolOptions->formatToString)
        return 0;

    virBufferAddLit(buf, "<poolOptions>\n");
    virBufferAdjustIndent(buf, 2);

    if (poolOptions->formatToString) {
        size_t i;

        virBufferAsprintf(buf, "<defaultFormat type='%s'/>\n",
                          (poolOptions->formatToString)(poolOptions->defaultFormat));

        virBufferAddLit(buf, "<enum name='sourceFormatType'>\n");
        virBufferAdjustIndent(buf, 2);

        for (i = 0; i < poolOptions->lastFormat; i++)
            virBufferAsprintf(buf, "<value>%s</value>\n",
                              (poolOptions->formatToString)(i));

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</enum>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</poolOptions>\n");
    return 0;
}


int
virStoragePoolOptionsFormatVolume(virBufferPtr buf,
                                  int type)
{
    size_t i;
    virStorageVolOptionsPtr volOptions;

    if (!(volOptions = virStorageVolOptionsForPoolType(type)))
        return -1;

    if (!volOptions->formatToString)
        return 0;

    virBufferAddLit(buf, "<volOptions>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<defaultFormat type='%s'/>\n",
                      (volOptions->formatToString)(volOptions->defaultFormat));

    virBufferAddLit(buf, "<enum name='targetFormatType'>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < volOptions->lastFormat; i++)
        virBufferAsprintf(buf, "<value>%s</value>\n",
                          (volOptions->formatToString)(i));

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</enum>\n");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</volOptions>\n");

    return 0;
}


void
virStorageVolDefFree(virStorageVolDefPtr def)
{
    size_t i;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->key);

    for (i = 0; i < def->source.nextent; i++)
        VIR_FREE(def->source.extents[i].path);
    VIR_FREE(def->source.extents);

    virStorageSourceClear(&def->target);
    VIR_FREE(def);
}


void
virStoragePoolSourceDeviceClear(virStoragePoolSourceDevicePtr dev)
{
    VIR_FREE(dev->freeExtents);
    VIR_FREE(dev->path);
}


void
virStoragePoolSourceClear(virStoragePoolSourcePtr source)
{
    size_t i;

    if (!source)
        return;

    for (i = 0; i < source->nhost; i++)
        VIR_FREE(source->hosts[i].name);
    VIR_FREE(source->hosts);

    for (i = 0; i < source->ndevice; i++)
        virStoragePoolSourceDeviceClear(&source->devices[i]);
    VIR_FREE(source->devices);
    VIR_FREE(source->dir);
    VIR_FREE(source->name);
    virStorageAdapterClear(&source->adapter);
    virStorageSourceInitiatorClear(&source->initiator);
    virStorageAuthDefFree(source->auth);
    VIR_FREE(source->vendor);
    VIR_FREE(source->product);
}


void
virStoragePoolSourceFree(virStoragePoolSourcePtr source)
{
    virStoragePoolSourceClear(source);
    VIR_FREE(source);
}


void
virStoragePoolDefFree(virStoragePoolDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->name);

    virStoragePoolSourceClear(&def->source);

    VIR_FREE(def->target.path);
    VIR_FREE(def->target.perms.label);
    VIR_FREE(def->refresh);
    if (def->namespaceData && def->ns.free)
        (def->ns.free)(def->namespaceData);
    VIR_FREE(def);
}


static int
virStoragePoolDefParseSource(xmlXPathContextPtr ctxt,
                             virStoragePoolSourcePtr source,
                             int pool_type,
                             xmlNodePtr node)
{
    int ret = -1;
    xmlNodePtr relnode, authnode;
    xmlNodePtr adapternode;
    int nsource;
    size_t i;
    virStoragePoolOptionsPtr options;
    int n;
    VIR_AUTOPTR(virStorageAuthDef) authdef = NULL;
    VIR_AUTOFREE(char *) port = NULL;
    VIR_AUTOFREE(char *) ver = NULL;
    VIR_AUTOFREE(xmlNodePtr *) nodeset = NULL;
    VIR_AUTOFREE(char *) sourcedir = NULL;

    relnode = ctxt->node;
    ctxt->node = node;

    if ((options = virStoragePoolOptionsForPoolType(pool_type)) == NULL)
        goto cleanup;

    source->name = virXPathString("string(./name)", ctxt);
    if (pool_type == VIR_STORAGE_POOL_RBD && source->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("element 'name' is mandatory for RBD pool"));
        goto cleanup;
    }

    if (options->formatFromString) {
        VIR_AUTOFREE(char *) format = NULL;

        format = virXPathString("string(./format/@type)", ctxt);
        if (format == NULL)
            source->format = options->defaultFormat;
        else
            source->format = options->formatFromString(format);

        if (source->format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown pool format type %s"), format);
            goto cleanup;
        }
    }

    if ((n = virXPathNodeSet("./host", ctxt, &nodeset)) < 0)
        goto cleanup;

    if (n) {
        if (VIR_ALLOC_N(source->hosts, n) < 0)
            goto cleanup;
        source->nhost = n;

        for (i = 0; i < source->nhost; i++) {
            source->hosts[i].name = virXMLPropString(nodeset[i], "name");
            if (!source->hosts[i].name) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool host name"));
                goto cleanup;
            }

            port = virXMLPropString(nodeset[i], "port");
            if (port) {
                if (virStrToLong_i(port, NULL, 10, &source->hosts[i].port) < 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("Invalid port number: %s"),
                                   port);
                    goto cleanup;
                }
            }
            VIR_FREE(port);
        }
    }

    VIR_FREE(nodeset);

    virStorageSourceInitiatorParseXML(ctxt, &source->initiator);

    nsource = virXPathNodeSet("./device", ctxt, &nodeset);
    if (nsource < 0)
        goto cleanup;

    for (i = 0; i < nsource; i++) {
        VIR_AUTOFREE(char *) partsep = NULL;
        virStoragePoolSourceDevice dev = { .path = NULL };
        dev.path = virXMLPropString(nodeset[i], "path");

        if (dev.path == NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source device path"));
            goto cleanup;
        }

        partsep = virXMLPropString(nodeset[i], "part_separator");
        if (partsep) {
            dev.part_separator = virTristateBoolTypeFromString(partsep);
            if (dev.part_separator <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid part_separator setting '%s'"),
                               partsep);
                virStoragePoolSourceDeviceClear(&dev);
                goto cleanup;
            }
        }

        if (VIR_APPEND_ELEMENT(source->devices, source->ndevice, dev) < 0) {
            virStoragePoolSourceDeviceClear(&dev);
            goto cleanup;
        }

    }

    sourcedir = virXPathString("string(./dir/@path)", ctxt);
    if (sourcedir)
        source->dir = virFileSanitizePath(sourcedir);
    /* In gluster, a missing dir defaults to "/" */
    if (!source->dir && pool_type == VIR_STORAGE_POOL_GLUSTER &&
        VIR_STRDUP(source->dir, "/") < 0)
        goto cleanup;

    if ((adapternode = virXPathNode("./adapter", ctxt))) {
        if (virStorageAdapterParseXML(&source->adapter, adapternode, ctxt) < 0)
            goto cleanup;
    }

    if ((authnode = virXPathNode("./auth", ctxt))) {
        if (!(authdef = virStorageAuthDefParse(authnode, ctxt)))
            goto cleanup;

        if (authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("storage pool missing auth type"));
            goto cleanup;
        }

        VIR_STEAL_PTR(source->auth, authdef);
    }

    /* Option protocol version string (NFSvN) */
    if ((ver = virXPathString("string(./protocol/@ver)", ctxt))) {
        if ((source->format != VIR_STORAGE_POOL_NETFS_NFS) &&
            (source->format != VIR_STORAGE_POOL_NETFS_AUTO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("storage pool protocol ver unsupported for "
                             "pool type '%s'"),
                           virStoragePoolFormatFileSystemNetTypeToString(source->format));
            goto cleanup;
        }
        if (virStrToLong_uip(ver, NULL, 0, &source->protocolVer) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("storage pool protocol ver '%s' is malformed"),
                           ver);
            goto cleanup;
        }
    }

    source->vendor = virXPathString("string(./vendor/@name)", ctxt);
    source->product = virXPathString("string(./product/@name)", ctxt);

    ret = 0;
 cleanup:
    ctxt->node = relnode;

    return ret;
}


virStoragePoolSourcePtr
virStoragePoolDefParseSourceString(const char *srcSpec,
                                   int pool_type)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr xpath_ctxt = NULL;
    virStoragePoolSourcePtr ret = NULL;
    VIR_AUTOPTR(virStoragePoolSource) def = NULL;

    if (!(doc = virXMLParseStringCtxt(srcSpec,
                                      _("(storage_source_specification)"),
                                      &xpath_ctxt)))
        goto cleanup;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    if (!(node = virXPathNode("/source", xpath_ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("root element was not source"));
        goto cleanup;
    }

    if (virStoragePoolDefParseSource(xpath_ctxt, def, pool_type,
                                     node) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, def);
 cleanup:
    xmlFreeDoc(doc);
    xmlXPathFreeContext(xpath_ctxt);

    return ret;
}


static int
virStorageDefParsePerms(xmlXPathContextPtr ctxt,
                        virStoragePermsPtr perms,
                        const char *permxpath)
{
    long long val;
    int ret = -1;
    xmlNodePtr relnode;
    xmlNodePtr node;
    VIR_AUTOFREE(char *) mode = NULL;

    node = virXPathNode(permxpath, ctxt);
    if (node == NULL) {
        /* Set default values if there is not <permissions> element */
        perms->mode = (mode_t) -1;
        perms->uid = (uid_t) -1;
        perms->gid = (gid_t) -1;
        perms->label = NULL;
        return 0;
    }

    relnode = ctxt->node;
    ctxt->node = node;

    if ((mode = virXPathString("string(./mode)", ctxt))) {
        int tmp;

        if (virStrToLong_i(mode, NULL, 8, &tmp) < 0 || (tmp & ~0777)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed octal mode"));
            goto error;
        }
        perms->mode = tmp;
    } else {
        perms->mode = (mode_t) -1;
    }

    if (virXPathNode("./owner", ctxt) == NULL) {
        perms->uid = (uid_t) -1;
    } else {
        /* We previously could output -1, so continue to parse it */
        if (virXPathLongLong("number(./owner)", ctxt, &val) < 0 ||
            ((uid_t)val != val &&
             val != -1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed owner element"));
            goto error;
        }

        perms->uid = val;
    }

    if (virXPathNode("./group", ctxt) == NULL) {
        perms->gid = (gid_t) -1;
    } else {
        /* We previously could output -1, so continue to parse it */
        if (virXPathLongLong("number(./group)", ctxt, &val) < 0 ||
            ((gid_t) val != val &&
             val != -1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed group element"));
            goto error;
        }
        perms->gid = val;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString("string(./label)", ctxt);

    ret = 0;
 error:
    ctxt->node = relnode;
    return ret;
}


static int
virStoragePoolDefRefreshParse(xmlXPathContextPtr ctxt,
                              virStoragePoolDefPtr def)
{
    VIR_AUTOFREE(virStoragePoolDefRefreshPtr) refresh = NULL;
    VIR_AUTOFREE(char *) allocation = NULL;
    int tmp;

    allocation = virXPathString("string(./refresh/volume/@allocation)", ctxt);

    if (!allocation)
        return 0;

    if ((tmp = virStorageVolDefRefreshAllocationTypeFromString(allocation)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown storage pool volume refresh allocation type %s"),
                       allocation);
        return -1;
    }

    if (VIR_ALLOC(refresh) < 0)
        return -1;

    refresh->volume.allocation = tmp;
    VIR_STEAL_PTR(def->refresh, refresh);
    return 0;
}


static void
virStoragePoolDefRefreshFormat(virBufferPtr buf,
                               virStoragePoolDefRefreshPtr refresh)
{
    if (!refresh)
        return;

    virBufferAddLit(buf, "<refresh>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<volume allocation='%s'/>\n",
                      virStorageVolDefRefreshAllocationTypeToString(refresh->volume.allocation));
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</refresh>\n");
}


virStoragePoolDefPtr
virStoragePoolDefParseXML(xmlXPathContextPtr ctxt)
{
    virStoragePoolOptionsPtr options;
    virStoragePoolDefPtr ret = NULL;
    xmlNodePtr source_node;
    VIR_AUTOPTR(virStoragePoolDef) def = NULL;
    VIR_AUTOFREE(char *) type = NULL;
    VIR_AUTOFREE(char *) uuid = NULL;
    VIR_AUTOFREE(char *) target_path = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    type = virXPathString("string(./@type)", ctxt);
    if (type == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("storage pool missing type attribute"));
        return NULL;
    }

    if ((def->type = virStoragePoolTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown storage pool type %s"), type);
        return NULL;
    }

    if ((options = virStoragePoolOptionsForPoolType(def->type)) == NULL)
        return NULL;

    source_node = virXPathNode("./source", ctxt);
    if (source_node) {
        if (virStoragePoolDefParseSource(ctxt, &def->source, def->type,
                                         source_node) < 0)
            return NULL;
    } else {
        if (options->formatFromString)
            def->source.format = options->defaultFormat;
    }

    def->name = virXPathString("string(./name)", ctxt);
    if (def->name == NULL &&
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME &&
        VIR_STRDUP(def->name, def->source.name) < 0)
        return NULL;

    if (def->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing pool source name element"));
        return NULL;
    }

    if (strchr(def->name, '/')) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("name %s cannot contain '/'"), def->name);
        return NULL;
    }

    uuid = virXPathString("string(./uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to generate uuid"));
            return NULL;
        }
    } else {
        if (virUUIDParse(uuid, def->uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed uuid element"));
            return NULL;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_HOST) {
        if (!def->source.nhost) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source host name"));
            return NULL;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR) {
        if (!def->source.dir) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source path"));
            return NULL;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME) {
        if (def->source.name == NULL) {
            /* source name defaults to pool name */
            if (VIR_STRDUP(def->source.name, def->name) < 0)
                return NULL;
        }
    }

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) &&
        (virStorageAdapterValidate(&def->source.adapter)) < 0)
            return NULL;

    /* If DEVICE is the only source type, then its required */
    if (options->flags == VIR_STORAGE_POOL_SOURCE_DEVICE) {
        if (!def->source.ndevice) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source device name"));
            return NULL;
        }
    }

    /* When we are working with a virtual disk we can skip the target
     * path and permissions */
    if (!(options->flags & VIR_STORAGE_POOL_SOURCE_NETWORK)) {
        if (def->type == VIR_STORAGE_POOL_LOGICAL) {
            if (virAsprintf(&target_path, "/dev/%s", def->source.name) < 0)
                return NULL;
        } else if (def->type == VIR_STORAGE_POOL_ZFS) {
            if (virAsprintf(&target_path, "/dev/zvol/%s", def->source.name) < 0)
                return NULL;
        } else {
            target_path = virXPathString("string(./target/path)", ctxt);
            if (!target_path) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool target path"));
                return NULL;
            }
        }
        def->target.path = virFileSanitizePath(target_path);
        if (!def->target.path)
            return NULL;

        if (virStorageDefParsePerms(ctxt, &def->target.perms,
                                    "./target/permissions") < 0)
            return NULL;
    }

    if (def->type == VIR_STORAGE_POOL_ISCSI_DIRECT &&
        !def->source.initiator.iqn) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing initiator IQN"));
        return NULL;
    }

    if (virStoragePoolDefRefreshParse(ctxt, def) < 0)
        return NULL;

    /* Make a copy of all the callback pointers here for easier use,
     * especially during the virStoragePoolSourceClear method */
    def->ns = options->ns;
    if (def->ns.parse) {
        if ((def->ns.parse)(ctxt, &def->namespaceData) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, def);
    return ret;
}


virStoragePoolDefPtr
virStoragePoolDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virStoragePoolDefPtr def = NULL;

    if (!virXMLNodeNameEqual(root, "pool")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <pool>"),
                       root->name);
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
                       const char *filename)
{
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
    size_t i, j;

    virBufferAddLit(buf, "<source>\n");
    virBufferAdjustIndent(buf, 2);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_HOST) && src->nhost) {
        for (i = 0; i < src->nhost; i++) {
            virBufferEscapeString(buf, "<host name='%s'",
                                  src->hosts[i].name);
            if (src->hosts[i].port)
                virBufferAsprintf(buf, " port='%d'", src->hosts[i].port);
            virBufferAddLit(buf, "/>\n");
        }
    }

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_DEVICE) &&
        src->ndevice) {
        for (i = 0; i < src->ndevice; i++) {
            virBufferEscapeString(buf, "<device path='%s'",
                                  src->devices[i].path);
            if (src->devices[i].part_separator !=
                VIR_TRISTATE_SWITCH_ABSENT) {
                virBufferAsprintf(buf, " part_separator='%s'",
                                  virTristateBoolTypeToString(src->devices[i].part_separator));
            }
            if (src->devices[i].nfreeExtent) {
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                for (j = 0; j < src->devices[i].nfreeExtent; j++) {
                    virBufferAsprintf(buf, "<freeExtent start='%llu' end='%llu'/>\n",
                                      src->devices[i].freeExtents[j].start,
                                      src->devices[i].freeExtents[j].end);
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</device>\n");
            } else {
                virBufferAddLit(buf, "/>\n");
            }
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR)
        virBufferEscapeString(buf, "<dir path='%s'/>\n", src->dir);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) &&
        (src->adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST ||
         src->adapter.type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST))
        virStorageAdapterFormat(buf, &src->adapter);

    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        virBufferEscapeString(buf, "<name>%s</name>\n", src->name);

    if (options->flags & VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN)
        virStorageSourceInitiatorFormatXML(&src->initiator, buf);

    if (options->formatToString) {
        const char *format = (options->formatToString)(src->format);
        if (!format) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown pool format number %d"),
                           src->format);
            return -1;
        }
        virBufferAsprintf(buf, "<format type='%s'/>\n", format);
    }

    if (src->auth)
        virStorageAuthDefFormat(buf, src->auth);

    if (src->protocolVer)
        virBufferAsprintf(buf, "<protocol ver='%u'/>\n", src->protocolVer);

    virBufferEscapeString(buf, "<vendor name='%s'/>\n", src->vendor);
    virBufferEscapeString(buf, "<product name='%s'/>\n", src->product);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</source>\n");
    return 0;
}


static int
virStoragePoolDefFormatBuf(virBufferPtr buf,
                           virStoragePoolDefPtr def)
{
    virStoragePoolOptionsPtr options;
    char uuid[VIR_UUID_STRING_BUFLEN];
    const char *type;

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return -1;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected pool type"));
        return -1;
    }
    virBufferAsprintf(buf, "<pool type='%s'", type);
    if (def->namespaceData && def->ns.href)
        virBufferAsprintf(buf, " %s", (def->ns.href)());
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", def->name);

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuid);

    virBufferAsprintf(buf, "<capacity unit='bytes'>%llu</capacity>\n",
                      def->capacity);
    virBufferAsprintf(buf, "<allocation unit='bytes'>%llu</allocation>\n",
                      def->allocation);
    virBufferAsprintf(buf, "<available unit='bytes'>%llu</available>\n",
                      def->available);

    if (virStoragePoolSourceFormat(buf, options, &def->source) < 0)
        return -1;

    /* RBD, Sheepdog, Gluster and Iscsi-direct devices are not local block devs nor
     * files, so they don't have a target */
    if (def->type != VIR_STORAGE_POOL_RBD &&
        def->type != VIR_STORAGE_POOL_SHEEPDOG &&
        def->type != VIR_STORAGE_POOL_GLUSTER &&
        def->type != VIR_STORAGE_POOL_ISCSI_DIRECT) {
        virBufferAddLit(buf, "<target>\n");
        virBufferAdjustIndent(buf, 2);

        virBufferEscapeString(buf, "<path>%s</path>\n", def->target.path);

        if (def->target.perms.mode != (mode_t) -1 ||
            def->target.perms.uid != (uid_t) -1 ||
            def->target.perms.gid != (gid_t) -1 ||
            def->target.perms.label) {
            virBufferAddLit(buf, "<permissions>\n");
            virBufferAdjustIndent(buf, 2);
            if (def->target.perms.mode != (mode_t) -1)
                virBufferAsprintf(buf, "<mode>0%o</mode>\n",
                                  def->target.perms.mode);
            if (def->target.perms.uid != (uid_t) -1)
                virBufferAsprintf(buf, "<owner>%d</owner>\n",
                                  (int) def->target.perms.uid);
            if (def->target.perms.gid != (gid_t) -1)
                virBufferAsprintf(buf, "<group>%d</group>\n",
                                  (int) def->target.perms.gid);
            virBufferEscapeString(buf, "<label>%s</label>\n",
                                  def->target.perms.label);

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</permissions>\n");
        }

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</target>\n");
    }

    virStoragePoolDefRefreshFormat(buf, def->refresh);

    if (def->namespaceData && def->ns.format) {
        if ((def->ns.format)(buf, def->namespaceData) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</pool>\n");

    return 0;
}


char *
virStoragePoolDefFormat(virStoragePoolDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virStoragePoolDefFormatBuf(&buf, def) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
virStorageSize(const char *unit,
               const char *val,
               unsigned long long *ret)
{
    if (virStrToLong_ullp(val, NULL, 10, ret) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("malformed capacity element"));
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
                         xmlXPathContextPtr ctxt,
                         unsigned int flags)
{
    virStorageVolDefPtr ret = NULL;
    virStorageVolOptionsPtr options;
    xmlNodePtr node;
    size_t i;
    int n;
    VIR_AUTOPTR(virStorageVolDef) def = NULL;
    VIR_AUTOFREE(char *) type = NULL;
    VIR_AUTOFREE(char *) allocation = NULL;
    VIR_AUTOFREE(char *) capacity = NULL;
    VIR_AUTOFREE(char *) unit = NULL;
    VIR_AUTOFREE(char *) backingStore = NULL;
    VIR_AUTOFREE(xmlNodePtr *) nodes = NULL;

    virCheckFlags(VIR_VOL_XML_PARSE_NO_CAPACITY |
                  VIR_VOL_XML_PARSE_OPT_CAPACITY, NULL);

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->target.type = VIR_STORAGE_TYPE_FILE;

    def->name = virXPathString("string(./name)", ctxt);
    if (def->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing volume name element"));
        return NULL;
    }

    /* Normally generated by pool refresh, but useful for unit tests */
    def->key = virXPathString("string(./key)", ctxt);

    /* Technically overridden by pool refresh, but useful for unit tests */
    type = virXPathString("string(./@type)", ctxt);
    if (type) {
        if ((def->type = virStorageVolTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume type '%s'"), type);
            return NULL;
        }
    }

    if ((backingStore = virXPathString("string(./backingStore/path)", ctxt))) {
        if (!(def->target.backingStore = virStorageSourceNew()))
            return NULL;

        def->target.backingStore->type = VIR_STORAGE_TYPE_FILE;

        def->target.backingStore->path = backingStore;
        backingStore = NULL;

        if (options->formatFromString) {
            VIR_AUTOFREE(char *) format = NULL;

            format = virXPathString("string(./backingStore/format/@type)", ctxt);
            if (format == NULL)
                def->target.backingStore->format = options->defaultFormat;
            else
                def->target.backingStore->format = (options->formatFromString)(format);

            if (def->target.backingStore->format < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown volume format type %s"), format);
                return NULL;
            }
        }

        if (VIR_ALLOC(def->target.backingStore->perms) < 0)
            return NULL;
        if (virStorageDefParsePerms(ctxt, def->target.backingStore->perms,
                                    "./backingStore/permissions") < 0)
            return NULL;
    }

    capacity = virXPathString("string(./capacity)", ctxt);
    unit = virXPathString("string(./capacity/@unit)", ctxt);
    if (capacity) {
        if (virStorageSize(unit, capacity, &def->target.capacity) < 0)
            return NULL;
    } else if (!(flags & VIR_VOL_XML_PARSE_NO_CAPACITY) &&
               !((flags & VIR_VOL_XML_PARSE_OPT_CAPACITY) &&
                 virStorageSourceHasBacking(&def->target))) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing capacity element"));
        return NULL;
    }
    VIR_FREE(unit);

    allocation = virXPathString("string(./allocation)", ctxt);
    if (allocation) {
        unit = virXPathString("string(./allocation/@unit)", ctxt);
        if (virStorageSize(unit, allocation, &def->target.allocation) < 0)
            return NULL;
        def->target.has_allocation = true;
    } else {
        def->target.allocation = def->target.capacity;
    }

    def->target.path = virXPathString("string(./target/path)", ctxt);
    if (options->formatFromString) {
        VIR_AUTOFREE(char *) format = NULL;

        format = virXPathString("string(./target/format/@type)", ctxt);
        if (format == NULL)
            def->target.format = options->defaultFormat;
        else
            def->target.format = (options->formatFromString)(format);

        if (def->target.format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume format type %s"), format);
            return NULL;
        }
    }

    if (VIR_ALLOC(def->target.perms) < 0)
        return NULL;
    if (virStorageDefParsePerms(ctxt, def->target.perms,
                                "./target/permissions") < 0)
        return NULL;

    node = virXPathNode("./target/encryption", ctxt);
    if (node != NULL) {
        def->target.encryption = virStorageEncryptionParseNode(node, ctxt);
        if (def->target.encryption == NULL)
            return NULL;
    }

    def->target.compat = virXPathString("string(./target/compat)", ctxt);
    if (virStorageFileCheckCompat(def->target.compat) < 0)
        return NULL;

    if (virXPathNode("./target/nocow", ctxt))
        def->target.nocow = true;

    if (virXPathNode("./target/features", ctxt)) {
        if ((n = virXPathNodeSet("./target/features/*", ctxt, &nodes)) < 0)
            return NULL;

        if (!def->target.compat && VIR_STRDUP(def->target.compat, "1.1") < 0)
            return NULL;

        if (!(def->target.features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST)))
            return NULL;

        for (i = 0; i < n; i++) {
            int f = virStorageFileFeatureTypeFromString((const char*)nodes[i]->name);

            if (f < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("unsupported feature %s"),
                               (const char*)nodes[i]->name);
                return NULL;
            }
            ignore_value(virBitmapSetBit(def->target.features, f));
        }
        VIR_FREE(nodes);
    }

    VIR_STEAL_PTR(ret, def);
    return ret;
}


virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root,
                          unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virStorageVolDefPtr def = NULL;

    if (!virXMLNodeNameEqual(root, "volume")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <volume>"),
                       root->name);
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virStorageVolDefParseXML(pool, ctxt, flags);
 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


static virStorageVolDefPtr
virStorageVolDefParse(virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename,
                      unsigned int flags)
{
    virStorageVolDefPtr ret = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(storage_volume_definition)")))) {
        ret = virStorageVolDefParseNode(pool, xml, xmlDocGetRootElement(xml), flags);
        xmlFreeDoc(xml);
    }

    return ret;
}


virStorageVolDefPtr
virStorageVolDefParseString(virStoragePoolDefPtr pool,
                            const char *xmlStr,
                            unsigned int flags)
{
    return virStorageVolDefParse(pool, xmlStr, NULL, flags);
}


virStorageVolDefPtr
virStorageVolDefParseFile(virStoragePoolDefPtr pool,
                          const char *filename,
                          unsigned int flags)
{
    return virStorageVolDefParse(pool, NULL, filename, flags);
}


static void
virStorageVolTimestampFormat(virBufferPtr buf, const char *name,
                             struct timespec *ts)
{
    if (ts->tv_nsec < 0)
        return;
    virBufferAsprintf(buf, "<%s>%llu", name,
                      (unsigned long long) ts->tv_sec);
    if (ts->tv_nsec)
       virBufferAsprintf(buf, ".%09ld", ts->tv_nsec);
    virBufferAsprintf(buf, "</%s>\n", name);
}


static int
virStorageVolTargetDefFormat(virStorageVolOptionsPtr options,
                             virBufferPtr buf,
                             virStorageSourcePtr def,
                             const char *type)
{
    virBufferAsprintf(buf, "<%s>\n", type);
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<path>%s</path>\n", def->path);

    if (options->formatToString) {
        const char *format = (options->formatToString)(def->format);
        if (!format) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown volume format number %d"),
                           def->format);
            return -1;
        }
        virBufferAsprintf(buf, "<format type='%s'/>\n", format);
    }

    if (def->perms &&
        (def->perms->mode != (mode_t) -1 ||
         def->perms->uid != (uid_t) -1 ||
         def->perms->gid != (gid_t) -1 ||
         def->perms->label)) {
        virBufferAddLit(buf, "<permissions>\n");
        virBufferAdjustIndent(buf, 2);

        if (def->perms->mode != (mode_t) -1)
            virBufferAsprintf(buf, "<mode>0%o</mode>\n",
                              def->perms->mode);
        if (def->perms->uid != (uid_t) -1)
            virBufferAsprintf(buf, "<owner>%d</owner>\n",
                              (int) def->perms->uid);
        if (def->perms->gid != (gid_t) -1)
            virBufferAsprintf(buf, "<group>%d</group>\n",
                              (int) def->perms->gid);

        virBufferEscapeString(buf, "<label>%s</label>\n",
                              def->perms->label);

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</permissions>\n");
    }

    if (def->timestamps) {
        virBufferAddLit(buf, "<timestamps>\n");
        virBufferAdjustIndent(buf, 2);
        virStorageVolTimestampFormat(buf, "atime", &def->timestamps->atime);
        virStorageVolTimestampFormat(buf, "mtime", &def->timestamps->mtime);
        virStorageVolTimestampFormat(buf, "ctime", &def->timestamps->ctime);
        virStorageVolTimestampFormat(buf, "btime", &def->timestamps->btime);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</timestamps>\n");
    }

    if (def->encryption &&
        virStorageEncryptionFormat(buf, def->encryption) < 0)
            return -1;

    virBufferEscapeString(buf, "<compat>%s</compat>\n", def->compat);

    if (def->features) {
        size_t i;
        bool empty = virBitmapIsAllClear(def->features);

        if (empty) {
            virBufferAddLit(buf, "<features/>\n");
        } else {
            virBufferAddLit(buf, "<features>\n");
            virBufferAdjustIndent(buf, 2);
        }

        for (i = 0; i < VIR_STORAGE_FILE_FEATURE_LAST; i++) {
            if (virBitmapIsBitSet(def->features, i))
                virBufferAsprintf(buf, "<%s/>\n",
                                  virStorageFileFeatureTypeToString(i));
        }
        if (!empty) {
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</features>\n");
        }
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAsprintf(buf, "</%s>\n", type);
    return 0;
}


char *
virStorageVolDefFormat(virStoragePoolDefPtr pool,
                       virStorageVolDefPtr def)
{
    virStorageVolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    virBufferAsprintf(&buf, "<volume type='%s'>\n",
                      virStorageVolTypeToString(def->type));
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);
    virBufferEscapeString(&buf, "<key>%s</key>\n", def->key);
    virBufferAddLit(&buf, "<source>\n");
    virBufferAdjustIndent(&buf, 2);

    if (def->source.nextent) {
        size_t i;
        const char *thispath = NULL;
        for (i = 0; i < def->source.nextent; i++) {
            if (thispath == NULL ||
                STRNEQ(thispath, def->source.extents[i].path)) {
                if (thispath != NULL)
                    virBufferAddLit(&buf, "</device>\n");

                virBufferEscapeString(&buf, "<device path='%s'>\n",
                                      def->source.extents[i].path);
            }

            virBufferAdjustIndent(&buf, 2);
            virBufferAsprintf(&buf, "<extent start='%llu' end='%llu'/>\n",
                              def->source.extents[i].start,
                              def->source.extents[i].end);
            virBufferAdjustIndent(&buf, -2);
            thispath = def->source.extents[i].path;
        }
        if (thispath != NULL)
            virBufferAddLit(&buf, "</device>\n");
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</source>\n");

    virBufferAsprintf(&buf, "<capacity unit='bytes'>%llu</capacity>\n",
                      def->target.capacity);
    virBufferAsprintf(&buf, "<allocation unit='bytes'>%llu</allocation>\n",
                      def->target.allocation);
    /* NB: Display only - since virStorageVolInfo is limited to just
     * 'capacity' and 'allocation' on output. Since we don't read this
     * in, be sure it was filled in before printing */
    if (def->target.physical)
        virBufferAsprintf(&buf, "<physical unit='bytes'>%llu</physical>\n",
                          def->target.physical);

    if (virStorageVolTargetDefFormat(options, &buf,
                                     &def->target, "target") < 0)
        goto cleanup;

    if (virStorageSourceHasBacking(&def->target) &&
        virStorageVolTargetDefFormat(options, &buf,
                                     def->target.backingStore,
                                     "backingStore") < 0)
        goto cleanup;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    return virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
virStoragePoolSaveXML(const char *path,
                      virStoragePoolDefPtr def,
                      const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ret = -1;

    virUUIDFormat(def->uuid, uuidstr);
    ret = virXMLSaveFile(path,
                         virXMLPickShellSafeComment(def->name, uuidstr),
                         "pool-edit", xml);

    return ret;
}


int
virStoragePoolSaveState(const char *stateFile,
                        virStoragePoolDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) xml = NULL;

    virBufferAddLit(&buf, "<poolstate>\n");
    virBufferAdjustIndent(&buf, 2);

    if (virStoragePoolDefFormatBuf(&buf, def) < 0)
        return -1;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</poolstate>\n");

    if (virBufferCheckError(&buf) < 0)
        return -1;

    if (!(xml = virBufferContentAndReset(&buf)))
        return -1;

    if (virStoragePoolSaveXML(stateFile, def, xml))
        return -1;

    return 0;
}


int
virStoragePoolSaveConfig(const char *configFile,
                         virStoragePoolDefPtr def)
{
    VIR_AUTOFREE(char *) xml = NULL;

    if (!(xml = virStoragePoolDefFormat(def))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate XML"));
        return -1;
    }

    return virStoragePoolSaveXML(configFile, def, xml);
}


virStoragePoolSourcePtr
virStoragePoolSourceListNewSource(virStoragePoolSourceListPtr list)
{
    virStoragePoolSourcePtr source;

    if (VIR_REALLOC_N(list->sources, list->nsources + 1) < 0)
        return NULL;

    source = &list->sources[list->nsources++];
    memset(source, 0, sizeof(*source));

    return source;
}


char *
virStoragePoolSourceListFormat(virStoragePoolSourceListPtr def)
{
    virStoragePoolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    size_t i;

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected pool type"));
        goto cleanup;
    }

    virBufferAddLit(&buf, "<sources>\n");
    virBufferAdjustIndent(&buf, 2);

    for (i = 0; i < def->nsources; i++)
        virStoragePoolSourceFormat(&buf, options, &def->sources[i]);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</sources>\n");

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    return virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}
