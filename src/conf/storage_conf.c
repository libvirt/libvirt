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
#include "storage_adapter_conf.h"
#include "storage_conf.h"
#include "storage_source_conf.h"

#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virlog.h"
#include "virutil.h"

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
              "vmfs",
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
struct _virStoragePoolOptions {
    unsigned int flags;
    int defaultFormat;
    int lastFormat;

    virXMLNamespace ns;

    virStoragePoolFormatToString formatToString;
    virStoragePoolFormatFromString formatFromString;
};

typedef struct _virStoragePoolTypeInfo virStoragePoolTypeInfo;
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


static virStoragePoolTypeInfo *
virStoragePoolTypeInfoLookup(int type)
{
    size_t i;
    for (i = 0; i < G_N_ELEMENTS(poolTypeInfo); i++)
        if (poolTypeInfo[i].poolType == type)
            return &poolTypeInfo[i];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing backend for pool type %1$d"), type);
    return NULL;
}


static virStoragePoolOptions *
virStoragePoolOptionsForPoolType(int type)
{
    virStoragePoolTypeInfo *backend = virStoragePoolTypeInfoLookup(type);
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
                                             virXMLNamespace *ns)
{
    virStoragePoolTypeInfo *backend = virStoragePoolTypeInfoLookup(type);

    if (!backend)
        return -1;

    backend->poolOptions.ns = *ns;

    return 0;
}


static virStorageVolOptions *
virStorageVolOptionsForPoolType(int type)
{
    virStoragePoolTypeInfo *backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->volOptions;
}


int
virStoragePoolOptionsFormatPool(virBuffer *buf,
                                int type)
{
    virStoragePoolOptions *poolOptions;
    size_t i;

    if (!(poolOptions = virStoragePoolOptionsForPoolType(type)))
        return -1;

    if (!poolOptions->formatToString)
        return 0;

    virBufferAddLit(buf, "<poolOptions>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<defaultFormat type='%s'/>\n",
                      (poolOptions->formatToString)(poolOptions->defaultFormat));

    virBufferAddLit(buf, "<enum name='sourceFormatType'>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < poolOptions->lastFormat; i++)
        virBufferAsprintf(buf, "<value>%s</value>\n", (poolOptions->formatToString)(i));

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</enum>\n");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</poolOptions>\n");
    return 0;
}


int
virStoragePoolOptionsFormatVolume(virBuffer *buf,
                                  int type)
{
    size_t i;
    virStorageVolOptions *volOptions;

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
virStorageVolDefFree(virStorageVolDef *def)
{
    size_t i;

    if (!def)
        return;

    g_free(def->name);
    g_free(def->key);

    for (i = 0; i < def->source.nextent; i++)
        g_free(def->source.extents[i].path);
    g_free(def->source.extents);

    virStorageSourceClear(&def->target);
    g_free(def);
}


void
virStoragePoolSourceDeviceClear(virStoragePoolSourceDevice *dev)
{
    VIR_FREE(dev->freeExtents);
    VIR_FREE(dev->path);
}


void
virStoragePoolSourceClear(virStoragePoolSource *source)
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
    VIR_FREE(source->protocolVer);
}


void
virStoragePoolSourceFree(virStoragePoolSource *source)
{
    virStoragePoolSourceClear(source);
    g_free(source);
}


void
virStoragePoolDefFree(virStoragePoolDef *def)
{
    if (!def)
        return;

    g_free(def->name);

    virStoragePoolSourceClear(&def->source);

    g_free(def->target.path);
    g_free(def->target.perms.label);
    g_free(def->refresh);
    if (def->namespaceData && def->ns.free)
        (def->ns.free)(def->namespaceData);
    g_free(def);
}


static int
virStoragePoolDefParseSource(xmlXPathContextPtr ctxt,
                             virStoragePoolSource *source,
                             int pool_type,
                             xmlNodePtr node)
{
    xmlNodePtr authnode;
    xmlNodePtr adapternode;
    int nsource;
    size_t i;
    virStoragePoolOptions *options;
    int n;
    g_autoptr(virStorageAuthDef) authdef = NULL;
    g_autofree xmlNodePtr *nodeset = NULL;
    g_autofree char *sourcedir = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if ((options = virStoragePoolOptionsForPoolType(pool_type)) == NULL)
        return -1;

    source->name = virXPathString("string(./name)", ctxt);
    if (pool_type == VIR_STORAGE_POOL_RBD && source->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("element 'name' is mandatory for RBD pool"));
        return -1;
    }

    if (options->formatFromString) {
        g_autofree char *format = NULL;

        format = virXPathString("string(./format/@type)", ctxt);
        if (format == NULL)
            source->format = options->defaultFormat;
        else
            source->format = options->formatFromString(format);

        if (source->format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown pool format type %1$s"), format);
            return -1;
        }
    }

    if ((n = virXPathNodeSet("./host", ctxt, &nodeset)) < 0)
        return -1;

    if (n) {
        source->hosts = g_new0(virStoragePoolSourceHost, n);
        source->nhost = n;

        for (i = 0; i < source->nhost; i++) {
            source->hosts[i].name = virXMLPropString(nodeset[i], "name");
            if (!source->hosts[i].name) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool host name"));
                return -1;
            }

            if (virXMLPropInt(nodeset[i], "port", 10, VIR_XML_PROP_NONE,
                              &source->hosts[i].port, 0) < 0)
                return -1;
        }
    }

    VIR_FREE(nodeset);

    virStorageSourceInitiatorParseXML(ctxt, &source->initiator);

    nsource = virXPathNodeSet("./device", ctxt, &nodeset);
    if (nsource < 0)
        return -1;

    for (i = 0; i < nsource; i++) {
        virStoragePoolSourceDevice dev = { .path = NULL };
        dev.path = virXMLPropString(nodeset[i], "path");

        if (dev.path == NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source device path"));
            return -1;
        }

        if (virXMLPropTristateBool(nodeset[i], "part_separator",
                                   VIR_XML_PROP_NONE,
                                   &dev.part_separator) < 0) {
            virStoragePoolSourceDeviceClear(&dev);
            return -1;
        }

        VIR_APPEND_ELEMENT(source->devices, source->ndevice, dev);
    }

    sourcedir = virXPathString("string(./dir/@path)", ctxt);
    if (sourcedir)
        source->dir = virFileSanitizePath(sourcedir);
    /* In gluster, a missing dir defaults to "/" */
    if (!source->dir && pool_type == VIR_STORAGE_POOL_GLUSTER)
        source->dir = g_strdup("/");

    if ((adapternode = virXPathNode("./adapter", ctxt))) {
        if (virStorageAdapterParseXML(&source->adapter, adapternode, ctxt) < 0)
            return -1;
    }

    if ((authnode = virXPathNode("./auth", ctxt))) {
        if (!(authdef = virStorageAuthDefParse(authnode, ctxt)))
            return -1;

        if (authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("storage pool missing auth type"));
            return -1;
        }

        source->auth = g_steal_pointer(&authdef);
    }

    /* Option protocol version string (NFSvN) */
    if ((source->protocolVer = virXPathString("string(./protocol/@ver)", ctxt))) {
        if ((source->format != VIR_STORAGE_POOL_NETFS_NFS) &&
            (source->format != VIR_STORAGE_POOL_NETFS_AUTO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("storage pool protocol ver unsupported for pool type '%1$s'"),
                           virStoragePoolFormatFileSystemNetTypeToString(source->format));
            return -1;
        }

        if (strchr(source->protocolVer, ',')) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("storage pool protocol ver '%1$s' must not contain ','"),
                           source->protocolVer);
            return -1;
        }
    }

    source->vendor = virXPathString("string(./vendor/@name)", ctxt);
    source->product = virXPathString("string(./product/@name)", ctxt);

    return 0;
}


virStoragePoolSource *
virStoragePoolDefParseSourceString(const char *srcSpec,
                                   int pool_type)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) xpath_ctxt = NULL;
    g_autoptr(virStoragePoolSource) def = NULL;

    if (!(doc = virXMLParse(NULL, srcSpec, _("(storage_source_specification)"),
                            "source", &xpath_ctxt, NULL, false)))
        return NULL;

    def = g_new0(virStoragePoolSource, 1);

    if (virStoragePoolDefParseSource(xpath_ctxt, def, pool_type,
                                     xpath_ctxt->node) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static int
virStorageDefParsePerms(xmlXPathContextPtr ctxt,
                        virStoragePerms *perms,
                        const char *permxpath)
{
    long long val;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr node;
    g_autofree char *mode = NULL;

    node = virXPathNode(permxpath, ctxt);
    if (node == NULL) {
        /* Set default values if there is not <permissions> element */
        perms->mode = (mode_t) -1;
        perms->uid = (uid_t) -1;
        perms->gid = (gid_t) -1;
        perms->label = NULL;
        return 0;
    }

    ctxt->node = node;

    if ((mode = virXPathString("string(./mode)", ctxt))) {
        int tmp;

        if (virStrToLong_i(mode, NULL, 8, &tmp) < 0 || (tmp & ~0777)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed octal mode"));
            return -1;
        }
        perms->mode = tmp;
    } else {
        perms->mode = (mode_t) -1;
    }

    if (virXPathNode("./owner", ctxt) == NULL) {
        perms->uid = (uid_t) -1;
    } else {
        /* We previously could output -1, so continue to parse it */
        if (virXPathLongLong("string(./owner)", ctxt, &val) < 0 ||
            ((uid_t)val != val &&
             val != -1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed owner element"));
            return -1;
        }

        perms->uid = val;
    }

    if (virXPathNode("./group", ctxt) == NULL) {
        perms->gid = (gid_t) -1;
    } else {
        /* We previously could output -1, so continue to parse it */
        if (virXPathLongLong("string(./group)", ctxt, &val) < 0 ||
            ((gid_t) val != val &&
             val != -1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed group element"));
            return -1;
        }
        perms->gid = val;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString("string(./label)", ctxt);
    return 0;
}


static int
virStoragePoolDefRefreshParse(xmlXPathContextPtr ctxt,
                              virStoragePoolDef *def)
{
    g_autofree virStoragePoolDefRefresh *refresh = NULL;
    g_autofree char *allocation = NULL;
    int tmp;

    allocation = virXPathString("string(./refresh/volume/@allocation)", ctxt);

    if (!allocation)
        return 0;

    if ((tmp = virStorageVolDefRefreshAllocationTypeFromString(allocation)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown storage pool volume refresh allocation type %1$s"),
                       allocation);
        return -1;
    }

    refresh = g_new0(virStoragePoolDefRefresh, 1);

    refresh->volume.allocation = tmp;
    def->refresh = g_steal_pointer(&refresh);
    return 0;
}


static void
virStoragePoolDefRefreshFormat(virBuffer *buf,
                               virStoragePoolDefRefresh *refresh)
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


static int
virStoragePoolDefParseFeatures(virStoragePoolDef *def,
                               xmlXPathContextPtr ctxt)
{
    xmlNodePtr node = virXPathNode("./features/cow", ctxt);
    virTristateBool val;
    int rv;

    if ((rv = virXMLPropTristateBool(node, "state",
                                     VIR_XML_PROP_NONE,
                                     &val)) < 0) {
        return -1;
    } else if (rv > 0) {
        if (def->type != VIR_STORAGE_POOL_FS &&
            def->type != VIR_STORAGE_POOL_DIR) {
            virReportError(VIR_ERR_NO_SUPPORT, "%s",
                           _("cow feature may only be used for 'fs' and 'dir' pools"));
            return -1;
        }
        def->features.cow = val;
    }

    return 0;
}


virStoragePoolDef *
virStoragePoolDefParseXML(xmlXPathContextPtr ctxt)
{
    virStoragePoolOptions *options;
    xmlNodePtr source_node;
    g_autoptr(virStoragePoolDef) def = NULL;
    virStoragePoolType type;
    g_autofree char *uuid = NULL;
    g_autofree char *target_path = NULL;

    def = g_new0(virStoragePoolDef, 1);

    if (virXMLPropEnum(ctxt->node, "type", virStoragePoolTypeFromString,
                       VIR_XML_PROP_REQUIRED, &type) < 0)
        return NULL;

    def->type = type;

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
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        def->name = g_strdup(def->source.name);

    if (def->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing pool source name element"));
        return NULL;
    }

    if (strchr(def->name, '/')) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("name %1$s cannot contain '/'"), def->name);
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

    if (virStoragePoolDefParseFeatures(def, ctxt) < 0)
        return NULL;

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
            def->source.name = g_strdup(def->name);
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
            target_path = g_strdup_printf("/dev/%s", def->source.name);
        } else if (def->type == VIR_STORAGE_POOL_ZFS) {
            target_path = g_strdup_printf("/dev/zvol/%s", def->source.name);
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
        if (virXMLNamespaceRegister(ctxt, &def->ns) < 0)
            return NULL;
        if ((def->ns.parse)(ctxt, &def->namespaceData) < 0)
            return NULL;
    }

    return g_steal_pointer(&def);
}


virStoragePoolDef *
virStoragePoolDefParse(const char *xmlStr,
                       const char *filename,
                       unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    bool validate = flags & VIR_STORAGE_POOL_DEFINE_VALIDATE;


    if (!(xml = virXMLParse(filename, xmlStr, _("(storage_pool_definition)"),
                            "pool", &ctxt, "storagepool.rng", validate)))
        return NULL;

    return virStoragePoolDefParseXML(ctxt);
}


static int
virStoragePoolSourceFormat(virBuffer *buf,
                           virStoragePoolOptions *options,
                           virStoragePoolSource *src)
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
                VIR_TRISTATE_BOOL_ABSENT) {
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
                           _("unknown pool format number %1$d"),
                           src->format);
            return -1;
        }
        virBufferAsprintf(buf, "<format type='%s'/>\n", format);
    }

    if (src->auth)
        virStorageAuthDefFormat(buf, src->auth);

    virBufferEscapeString(buf, "<protocol ver='%s'/>\n", src->protocolVer);
    virBufferEscapeString(buf, "<vendor name='%s'/>\n", src->vendor);
    virBufferEscapeString(buf, "<product name='%s'/>\n", src->product);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</source>\n");
    return 0;
}


static void
virStoragePoolDefFormatFeatures(virBuffer *buf,
                                virStoragePoolDef *def)
{
    if (def->features.cow == VIR_TRISTATE_BOOL_ABSENT)
        return;

    virBufferAddLit(buf, "<features>\n");
    virBufferAdjustIndent(buf, 2);
    if (def->features.cow != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(buf, "<cow state='%s'/>\n",
                          virTristateBoolTypeToString(def->features.cow));
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</features>\n");
}


static int
virStoragePoolDefFormatBuf(virBuffer *buf,
                           virStoragePoolDef *def)
{
    virStoragePoolOptions *options;
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
    if (def->namespaceData && def->ns.format)
        virXMLNamespaceFormatNS(buf, &def->ns);
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

    virStoragePoolDefFormatFeatures(buf, def);

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
virStoragePoolDefFormat(virStoragePoolDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virStoragePoolDefFormatBuf(&buf, def) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
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


static int
virStorageCheckCompat(const char *compat)
{
    unsigned int result;
    g_auto(GStrv) version = NULL;

    if (!compat)
        return 0;

    version = g_strsplit(compat, ".", 2);
    if (!version || !version[1] ||
        virStrToLong_ui(version[0], NULL, 10, &result) < 0 ||
        virStrToLong_ui(version[1], NULL, 10, &result) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("forbidden characters in 'compat' attribute"));
        return -1;
    }
    return 0;
}


virStorageVolDef *
virStorageVolDefParseXML(virStoragePoolDef *pool,
                         xmlXPathContextPtr ctxt,
                         unsigned int flags)
{
    virStorageVolOptions *options;
    xmlNodePtr node;
    size_t i;
    int n;
    g_autoptr(virStorageVolDef) def = NULL;
    g_autofree char *type = NULL;
    g_autofree char *allocation = NULL;
    g_autofree char *capacity = NULL;
    g_autofree char *unit = NULL;
    g_autofree char *backingStore = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    virCheckFlags(VIR_VOL_XML_PARSE_NO_CAPACITY |
                  VIR_VOL_XML_PARSE_OPT_CAPACITY, NULL);

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    def = g_new0(virStorageVolDef, 1);

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
                           _("unknown volume type '%1$s'"), type);
            return NULL;
        }
    }

    if ((backingStore = virXPathString("string(./backingStore/path)", ctxt))) {
        def->target.backingStore = virStorageSourceNew();
        def->target.backingStore->type = VIR_STORAGE_TYPE_FILE;
        def->target.backingStore->path = g_steal_pointer(&backingStore);

        if (options->formatFromString) {
            g_autofree char *format = NULL;

            format = virXPathString("string(./backingStore/format/@type)", ctxt);
            if (format == NULL)
                def->target.backingStore->format = options->defaultFormat;
            else
                def->target.backingStore->format = (options->formatFromString)(format);

            if (def->target.backingStore->format < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown volume format type %1$s"), format);
                return NULL;
            }
        }

        def->target.backingStore->perms = g_new0(virStoragePerms, 1);
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
        g_autofree char *format = NULL;

        format = virXPathString("string(./target/format/@type)", ctxt);
        if (format == NULL)
            def->target.format = options->defaultFormat;
        else
            def->target.format = (options->formatFromString)(format);

        if (def->target.format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume format type %1$s"), format);
            return NULL;
        }
    }

    def->target.perms = g_new0(virStoragePerms, 1);
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
    if (virStorageCheckCompat(def->target.compat) < 0)
        return NULL;

    if (virXPathNode("./target/nocow", ctxt))
        def->target.nocow = true;

    if (virParseScaledValue("./target/clusterSize",
                            "./target/clusterSize/@unit",
                            ctxt, &def->target.clusterSize,
                            1, ULLONG_MAX, false) < 0) {
        return NULL;
    }

    if (virXPathNode("./target/features", ctxt)) {
        if ((n = virXPathNodeSet("./target/features/*", ctxt, &nodes)) < 0)
            return NULL;

        if (!def->target.compat)
            def->target.compat = g_strdup("1.1");

        def->target.features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST);

        for (i = 0; i < n; i++) {
            int f = virStorageFileFeatureTypeFromString((const char*)nodes[i]->name);

            if (f < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported feature %1$s"),
                               (const char*)nodes[i]->name);
                return NULL;
            }
            ignore_value(virBitmapSetBit(def->target.features, f));
        }
        VIR_FREE(nodes);
    }

    return g_steal_pointer(&def);
}


virStorageVolDef *
virStorageVolDefParse(virStoragePoolDef *pool,
                      const char *xmlStr,
                      const char *filename,
                      unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    bool validate = flags & VIR_VOL_XML_PARSE_VALIDATE;

    if (!(xml = virXMLParse(filename, xmlStr, _("(storage_volume_definition)"),
                            "volume", &ctxt, "storagevol.rng", validate)))
        return NULL;

    return virStorageVolDefParseXML(pool, ctxt, flags);
}


static void
virStorageVolTimestampFormat(virBuffer *buf, const char *name,
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
virStorageVolTargetDefFormat(virStorageVolOptions *options,
                             virBuffer *buf,
                             virStorageSource *def,
                             const char *type)
{
    virBufferAsprintf(buf, "<%s>\n", type);
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<path>%s</path>\n", def->path);

    if (options->formatToString) {
        const char *format = (options->formatToString)(def->format);
        if (!format) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown volume format number %1$d"),
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

    if (def->clusterSize > 0) {
        virBufferAsprintf(buf, "<clusterSize unit='B'>%llu</clusterSize>\n",
                          def->clusterSize);
    }

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


static void
virStorageVolDefFormatSourceExtents(virBuffer *buf,
                                    virStorageVolDef *def)
{
    size_t i;
    const char *thispath = NULL;

    for (i = 0; i < def->source.nextent; i++) {
        if (thispath == NULL ||
            STRNEQ(thispath, def->source.extents[i].path)) {
            if (thispath != NULL)
                virBufferAddLit(buf, "</device>\n");

            virBufferEscapeString(buf, "<device path='%s'>\n",
                                  def->source.extents[i].path);
        }

        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<extent start='%llu' end='%llu'/>\n",
                          def->source.extents[i].start,
                          def->source.extents[i].end);
        virBufferAdjustIndent(buf, -2);
        thispath = def->source.extents[i].path;
    }
    if (thispath != NULL)
        virBufferAddLit(buf, "</device>\n");
}


char *
virStorageVolDefFormat(virStoragePoolDef *pool,
                       virStorageVolDef *def)
{
    virStorageVolOptions *options;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INITIALIZER;

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    virBufferAsprintf(&buf, "<volume type='%s'>\n",
                      virStorageVolTypeToString(def->type));
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);
    virBufferEscapeString(&buf, "<key>%s</key>\n", def->key);

    virBufferSetIndent(&sourceChildBuf, virBufferGetIndent(&buf) + 2);

    if (def->source.nextent)
        virStorageVolDefFormatSourceExtents(&sourceChildBuf, def);

    virXMLFormatElement(&buf, "source", NULL, &sourceChildBuf);

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
        return NULL;

    if (virStorageSourceHasBacking(&def->target) &&
        virStorageVolTargetDefFormat(options, &buf,
                                     def->target.backingStore,
                                     "backingStore") < 0)
        return NULL;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    return virBufferContentAndReset(&buf);
}


static int
virStoragePoolSaveXML(const char *path,
                      virStoragePoolDef *def,
                      const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(def->uuid, uuidstr);
    return virXMLSaveFile(path,
                          virXMLPickShellSafeComment(def->name, uuidstr),
                          "pool-edit", xml);
}


int
virStoragePoolSaveState(const char *stateFile,
                        virStoragePoolDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xml = NULL;

    virBufferAddLit(&buf, "<poolstate>\n");
    virBufferAdjustIndent(&buf, 2);

    if (virStoragePoolDefFormatBuf(&buf, def) < 0)
        return -1;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</poolstate>\n");

    if (!(xml = virBufferContentAndReset(&buf)))
        return -1;

    if (virStoragePoolSaveXML(stateFile, def, xml))
        return -1;

    return 0;
}


int
virStoragePoolSaveConfig(const char *configFile,
                         virStoragePoolDef *def)
{
    g_autofree char *xml = NULL;

    if (!(xml = virStoragePoolDefFormat(def))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate XML"));
        return -1;
    }

    return virStoragePoolSaveXML(configFile, def, xml);
}


virStoragePoolSource *
virStoragePoolSourceListNewSource(virStoragePoolSourceList *list)
{
    virStoragePoolSource *source;

    VIR_REALLOC_N(list->sources, list->nsources + 1);

    source = &list->sources[list->nsources++];
    memset(source, 0, sizeof(*source));

    return source;
}


char *
virStoragePoolSourceListFormat(virStoragePoolSourceList *def)
{
    virStoragePoolOptions *options;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    size_t i;

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected pool type"));
        return NULL;
    }

    virBufferAddLit(&buf, "<sources>\n");
    virBufferAdjustIndent(&buf, 2);

    for (i = 0; i < def->nsources; i++)
        virStoragePoolSourceFormat(&buf, options, &def->sources[i]);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</sources>\n");

    return virBufferContentAndReset(&buf);
}


void
virStoragePoolSourceListFree(virStoragePoolSourceList *list)
{
    size_t i;

    if (!list)
        return;

    for (i = 0; i < list->nsources; i++)
        virStoragePoolSourceClear(&list->sources[i]);

    g_free(list->sources);
    g_free(list);
}
