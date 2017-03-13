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

#include "virerror.h"
#include "datatypes.h"
#include "node_device_conf.h"
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
              "netdir", "ploop")

VIR_ENUM_IMPL(virStoragePool,
              VIR_STORAGE_POOL_LAST,
              "dir", "fs", "netfs",
              "logical", "disk", "iscsi",
              "scsi", "mpath", "rbd",
              "sheepdog", "gluster", "zfs",
              "vstorage")

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

VIR_ENUM_IMPL(virStoragePartedFs,
              VIR_STORAGE_PARTED_FS_TYPE_LAST,
              "ext2", "ext2", "fat16",
              "fat32", "linux-swap",
              "ext2", "ext2",
              "extended")

VIR_ENUM_IMPL(virStoragePoolSourceAdapter,
              VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_LAST,
              "default", "scsi_host", "fc_host")

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
         .formatFromString = virStoragePoolFormatLogicalTypeFromString,
         .formatToString = virStoragePoolFormatLogicalTypeToString,
     },
    },
    {.poolType = VIR_STORAGE_POOL_DIR,
     .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .formatFromString = virStorageVolumeFormatFromString,
         .formatToString = virStorageFileFormatTypeToString,
     },
    },
    {.poolType = VIR_STORAGE_POOL_FS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_DEVICE),
         .defaultFormat = VIR_STORAGE_POOL_FS_AUTO,
         .formatFromString = virStoragePoolFormatFileSystemTypeFromString,
         .formatToString = virStoragePoolFormatFileSystemTypeToString,
      },
      .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .formatFromString = virStorageVolumeFormatFromString,
         .formatToString = virStorageFileFormatTypeToString,
      },
    },
    {.poolType = VIR_STORAGE_POOL_NETFS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_HOST |
                   VIR_STORAGE_POOL_SOURCE_DIR),
         .defaultFormat = VIR_STORAGE_POOL_NETFS_AUTO,
         .formatFromString = virStoragePoolFormatFileSystemNetTypeFromString,
         .formatToString = virStoragePoolFormatFileSystemNetTypeToString,
      },
      .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
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
      .volOptions = {
         .formatToString = virStoragePoolFormatDiskTypeToString,
      }
    },
    {.poolType = VIR_STORAGE_POOL_SCSI,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_ADAPTER),
     },
     .volOptions = {
         .formatToString = virStoragePoolFormatDiskTypeToString,
     }
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
     .volOptions = {
         .defaultFormat = VIR_STORAGE_FILE_RAW,
         .formatToString = virStoragePoolFormatDiskTypeToString,
     }
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
         .formatToString = virStorageFileFormatTypeToString,
         .formatFromString = virStorageVolumeFormatFromString,
     }
    },
    {.poolType = VIR_STORAGE_POOL_MPATH,
     .volOptions = {
         .formatToString = virStoragePoolFormatDiskTypeToString,
     }
    },
    {.poolType = VIR_STORAGE_POOL_DISK,
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
    },
    {.poolType = VIR_STORAGE_POOL_ZFS,
     .poolOptions = {
         .flags = (VIR_STORAGE_POOL_SOURCE_NAME |
                   VIR_STORAGE_POOL_SOURCE_DEVICE),
         .defaultFormat = VIR_STORAGE_FILE_RAW,
     },
    },
    {.poolType = VIR_STORAGE_POOL_VSTORAGE,
     .poolOptions = {
        .flags = VIR_STORAGE_POOL_SOURCE_NAME,
     },
     .volOptions = {
        .defaultFormat = VIR_STORAGE_FILE_RAW,
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

static virStorageVolOptionsPtr
virStorageVolOptionsForPoolType(int type)
{
    virStoragePoolTypeInfoPtr backend = virStoragePoolTypeInfoLookup(type);
    if (backend == NULL)
        return NULL;
    return &backend->volOptions;
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

static void
virStoragePoolSourceAdapterClear(virStoragePoolSourceAdapterPtr adapter)
{
    if (adapter->type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
        VIR_FREE(adapter->data.fchost.wwnn);
        VIR_FREE(adapter->data.fchost.wwpn);
        VIR_FREE(adapter->data.fchost.parent);
        VIR_FREE(adapter->data.fchost.parent_wwnn);
        VIR_FREE(adapter->data.fchost.parent_wwpn);
        VIR_FREE(adapter->data.fchost.parent_fabric_wwn);
    } else if (adapter->type ==
               VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
        VIR_FREE(adapter->data.scsi_host.name);
    }
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
    virStoragePoolSourceAdapterClear(&source->adapter);
    VIR_FREE(source->initiator.iqn);
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
    VIR_FREE(def);
}


void
virStoragePoolObjFree(virStoragePoolObjPtr obj)
{
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

void
virStoragePoolObjListFree(virStoragePoolObjListPtr pools)
{
    size_t i;
    for (i = 0; i < pools->count; i++)
        virStoragePoolObjFree(pools->objs[i]);
    VIR_FREE(pools->objs);
    pools->count = 0;
}

void
virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                        virStoragePoolObjPtr pool)
{
    size_t i;

    virStoragePoolObjUnlock(pool);

    for (i = 0; i < pools->count; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (pools->objs[i] == pool) {
            virStoragePoolObjUnlock(pools->objs[i]);
            virStoragePoolObjFree(pools->objs[i]);

            VIR_DELETE_ELEMENT(pools->objs, i, pools->count);
            break;
        }
        virStoragePoolObjUnlock(pools->objs[i]);
    }
}

static int
virStoragePoolDefParseSource(xmlXPathContextPtr ctxt,
                             virStoragePoolSourcePtr source,
                             int pool_type,
                             xmlNodePtr node)
{
    int ret = -1;
    xmlNodePtr relnode, authnode, *nodeset = NULL;
    int nsource;
    size_t i;
    virStoragePoolOptionsPtr options;
    virStorageAuthDefPtr authdef = NULL;
    char *name = NULL;
    char *port = NULL;
    char *adapter_type = NULL;
    char *managed = NULL;
    int n;

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
        char *format = virXPathString("string(./format/@type)", ctxt);
        if (format == NULL)
            source->format = options->defaultFormat;
        else
            source->format = options->formatFromString(format);

        if (source->format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown pool format type %s"), format);
            VIR_FREE(format);
            goto cleanup;
        }
        VIR_FREE(format);
    }

    if ((n = virXPathNodeSet("./host", ctxt, &nodeset)) < 0)
        goto cleanup;

    if (n) {
        if (VIR_ALLOC_N(source->hosts, n) < 0)
            goto cleanup;
        source->nhost = n;

        for (i = 0; i < source->nhost; i++) {
            name = virXMLPropString(nodeset[i], "name");
            if (name == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool host name"));
                goto cleanup;
            }
            source->hosts[i].name = name;

            port = virXMLPropString(nodeset[i], "port");
            if (port) {
                if (virStrToLong_i(port, NULL, 10, &source->hosts[i].port) < 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("Invalid port number: %s"),
                                   port);
                    goto cleanup;
                }
            }
        }
    }

    VIR_FREE(nodeset);
    source->initiator.iqn = virXPathString("string(./initiator/iqn/@name)", ctxt);

    nsource = virXPathNodeSet("./device", ctxt, &nodeset);
    if (nsource < 0)
        goto cleanup;

    for (i = 0; i < nsource; i++) {
        char *partsep;
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
                VIR_FREE(partsep);
                goto cleanup;
            }
            VIR_FREE(partsep);
        }

        if (VIR_APPEND_ELEMENT(source->devices, source->ndevice, dev) < 0) {
            virStoragePoolSourceDeviceClear(&dev);
            goto cleanup;
        }

    }

    source->dir = virXPathString("string(./dir/@path)", ctxt);
    /* In gluster, a missing dir defaults to "/" */
    if (!source->dir && pool_type == VIR_STORAGE_POOL_GLUSTER &&
        VIR_STRDUP(source->dir, "/") < 0)
        goto cleanup;

    if ((adapter_type = virXPathString("string(./adapter/@type)", ctxt))) {
        if ((source->adapter.type =
             virStoragePoolSourceAdapterTypeFromString(adapter_type)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown pool adapter type '%s'"),
                           adapter_type);
            goto cleanup;
        }

        if (source->adapter.type ==
            VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            source->adapter.data.fchost.parent =
                virXPathString("string(./adapter/@parent)", ctxt);
            managed = virXPathString("string(./adapter/@managed)", ctxt);
            if (managed) {
                source->adapter.data.fchost.managed =
                    virTristateBoolTypeFromString(managed);
                if (source->adapter.data.fchost.managed < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown fc_host managed setting '%s'"),
                                   managed);
                    goto cleanup;
                }
            }

            source->adapter.data.fchost.parent_wwnn =
                virXPathString("string(./adapter/@parent_wwnn)", ctxt);
            source->adapter.data.fchost.parent_wwpn =
                virXPathString("string(./adapter/@parent_wwpn)", ctxt);
            source->adapter.data.fchost.parent_fabric_wwn =
                virXPathString("string(./adapter/@parent_fabric_wwn)", ctxt);

            source->adapter.data.fchost.wwpn =
                virXPathString("string(./adapter/@wwpn)", ctxt);
            source->adapter.data.fchost.wwnn =
                virXPathString("string(./adapter/@wwnn)", ctxt);
        } else if (source->adapter.type ==
                   VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {

            source->adapter.data.scsi_host.name =
                virXPathString("string(./adapter/@name)", ctxt);
            if (virXPathNode("./adapter/parentaddr", ctxt)) {
                xmlNodePtr addrnode = virXPathNode("./adapter/parentaddr/address",
                                                   ctxt);
                virPCIDeviceAddressPtr addr =
                    &source->adapter.data.scsi_host.parentaddr;

                if (!addrnode) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("Missing scsi_host PCI address element"));
                    goto cleanup;
                }
                source->adapter.data.scsi_host.has_parent = true;
                if (virPCIDeviceAddressParseXML(addrnode, addr) < 0)
                    goto cleanup;
                if ((virXPathInt("string(./adapter/parentaddr/@unique_id)",
                                 ctxt,
                                 &source->adapter.data.scsi_host.unique_id) < 0) ||
                    (source->adapter.data.scsi_host.unique_id < 0)) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("Missing or invalid scsi adapter "
                                     "'unique_id' value"));
                    goto cleanup;
                }
            }
        }
    } else {
        char *wwnn = NULL;
        char *wwpn = NULL;
        char *parent = NULL;

        /* "type" was not specified in the XML, so we must verify that
         * "wwnn", "wwpn", "parent", or "parentaddr" are also not in the
         * XML. If any are found, then we cannot just use "name" alone".
         */
        wwnn = virXPathString("string(./adapter/@wwnn)", ctxt);
        wwpn = virXPathString("string(./adapter/@wwpn)", ctxt);
        parent = virXPathString("string(./adapter/@parent)", ctxt);

        if (wwnn || wwpn || parent) {
            VIR_FREE(wwnn);
            VIR_FREE(wwpn);
            VIR_FREE(parent);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Use of 'wwnn', 'wwpn', and 'parent' attributes "
                             "requires use of the adapter 'type'"));
            goto cleanup;
        }

        if (virXPathNode("./adapter/parentaddr", ctxt)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Use of 'parent' element requires use "
                             "of the adapter 'type'"));
            goto cleanup;
        }

        /* To keep back-compat, 'type' is not required to specify
         * for scsi_host adapter.
         */
        if ((source->adapter.data.scsi_host.name =
             virXPathString("string(./adapter/@name)", ctxt)))
            source->adapter.type =
                VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST;
    }

    if ((authnode = virXPathNode("./auth", ctxt))) {
        if (!(authdef = virStorageAuthDefParse(node->doc, authnode)))
            goto cleanup;

        if (authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("storage pool missing auth type"));
            goto cleanup;
        }

        source->auth = authdef;
        authdef = NULL;
    }

    source->vendor = virXPathString("string(./vendor/@name)", ctxt);
    source->product = virXPathString("string(./product/@name)", ctxt);

    ret = 0;
 cleanup:
    ctxt->node = relnode;

    VIR_FREE(port);
    VIR_FREE(nodeset);
    VIR_FREE(adapter_type);
    VIR_FREE(managed);
    virStorageAuthDefFree(authdef);
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
                        const char *permxpath)
{
    char *mode;
    long long val;
    int ret = -1;
    xmlNodePtr relnode;
    xmlNodePtr node;

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
            VIR_FREE(mode);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed octal mode"));
            goto error;
        }
        perms->mode = tmp;
        VIR_FREE(mode);
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

static virStoragePoolDefPtr
virStoragePoolDefParseXML(xmlXPathContextPtr ctxt)
{
    virStoragePoolOptionsPtr options;
    virStoragePoolDefPtr ret;
    xmlNodePtr source_node;
    char *type = NULL;
    char *uuid = NULL;
    char *target_path = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    type = virXPathString("string(./@type)", ctxt);
    if (type == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("storage pool missing type attribute"));
        goto error;
    }

    if ((ret->type = virStoragePoolTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown storage pool type %s"), type);
        goto error;
    }

    if ((options = virStoragePoolOptionsForPoolType(ret->type)) == NULL)
        goto error;

    source_node = virXPathNode("./source", ctxt);
    if (source_node) {
        if (virStoragePoolDefParseSource(ctxt, &ret->source, ret->type,
                                         source_node) < 0)
            goto error;
    }

    ret->name = virXPathString("string(./name)", ctxt);
    if (ret->name == NULL &&
        options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        ret->name = ret->source.name;
    if (ret->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing pool source name element"));
        goto error;
    }

    if (strchr(ret->name, '/')) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("name %s cannot contain '/'"), ret->name);
        goto error;
    }

    uuid = virXPathString("string(./uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to generate uuid"));
            goto error;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed uuid element"));
            goto error;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_HOST) {
        if (!ret->source.nhost) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source host name"));
            goto error;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR) {
        if (!ret->source.dir) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source path"));
            goto error;
        }
    }
    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME) {
        if (ret->source.name == NULL) {
            /* source name defaults to pool name */
            if (VIR_STRDUP(ret->source.name, ret->name) < 0)
                goto error;
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER) {
        if (!ret->source.adapter.type) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source adapter"));
            goto error;
        }

        if (ret->source.adapter.type ==
            VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            if (!ret->source.adapter.data.fchost.wwnn ||
                !ret->source.adapter.data.fchost.wwpn) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'wwnn' and 'wwpn' must be specified for adapter "
                                 "type 'fchost'"));
                goto error;
            }

            if (!virValidateWWN(ret->source.adapter.data.fchost.wwnn) ||
                !virValidateWWN(ret->source.adapter.data.fchost.wwpn))
                goto error;
        } else if (ret->source.adapter.type ==
                   VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
            if (!ret->source.adapter.data.scsi_host.name &&
                !ret->source.adapter.data.scsi_host.has_parent) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Either 'name' or 'parent' must be specified "
                                 "for the 'scsi_host' adapter"));
                goto error;
            }

            if (ret->source.adapter.data.scsi_host.name &&
                ret->source.adapter.data.scsi_host.has_parent) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Both 'name' and 'parent' cannot be specified "
                                 "for the 'scsi_host' adapter"));
                goto error;
            }
        }
    }

    /* If DEVICE is the only source type, then its required */
    if (options->flags == VIR_STORAGE_POOL_SOURCE_DEVICE) {
        if (!ret->source.ndevice) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source device name"));
            goto error;
        }
    }

    /* When we are working with a virtual disk we can skip the target
     * path and permissions */
    if (!(options->flags & VIR_STORAGE_POOL_SOURCE_NETWORK)) {
        if (ret->type == VIR_STORAGE_POOL_LOGICAL) {
            if (virAsprintf(&target_path, "/dev/%s", ret->source.name) < 0)
                goto error;
        } else if (ret->type == VIR_STORAGE_POOL_ZFS) {
            if (virAsprintf(&target_path, "/dev/zvol/%s", ret->source.name) < 0)
                goto error;
        } else {
            target_path = virXPathString("string(./target/path)", ctxt);
            if (!target_path) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool target path"));
                goto error;
            }
        }
        ret->target.path = virFileSanitizePath(target_path);
        if (!ret->target.path)
            goto error;

        if (virStorageDefParsePerms(ctxt, &ret->target.perms,
                                    "./target/permissions") < 0)
            goto error;
    }

 cleanup:
    VIR_FREE(uuid);
    VIR_FREE(type);
    VIR_FREE(target_path);
    return ret;

 error:
    virStoragePoolDefFree(ret);
    ret = NULL;
    goto cleanup;
}

virStoragePoolDefPtr
virStoragePoolDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virStoragePoolDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "pool")) {
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

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER)) {
        if (src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST ||
            src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST)
            virBufferAsprintf(buf, "<adapter type='%s'",
                              virStoragePoolSourceAdapterTypeToString(src->adapter.type));

        if (src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            virBufferEscapeString(buf, " parent='%s'",
                                  src->adapter.data.fchost.parent);
            if (src->adapter.data.fchost.managed)
                virBufferAsprintf(buf, " managed='%s'",
                                  virTristateBoolTypeToString(src->adapter.data.fchost.managed));
            virBufferEscapeString(buf, " parent_wwnn='%s'",
                                  src->adapter.data.fchost.parent_wwnn);
            virBufferEscapeString(buf, " parent_wwpn='%s'",
                                  src->adapter.data.fchost.parent_wwpn);
            virBufferEscapeString(buf, " parent_fabric_wwn='%s'",
                                  src->adapter.data.fchost.parent_fabric_wwn);

            virBufferAsprintf(buf, " wwnn='%s' wwpn='%s'/>\n",
                              src->adapter.data.fchost.wwnn,
                              src->adapter.data.fchost.wwpn);
        } else if (src->adapter.type ==
                   VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
            if (src->adapter.data.scsi_host.name) {
                virBufferAsprintf(buf, " name='%s'/>\n",
                                  src->adapter.data.scsi_host.name);
            } else {
                virPCIDeviceAddress addr;
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                virBufferAsprintf(buf, "<parentaddr unique_id='%d'>\n",
                                  src->adapter.data.scsi_host.unique_id);
                virBufferAdjustIndent(buf, 2);
                addr = src->adapter.data.scsi_host.parentaddr;
                ignore_value(virPCIDeviceAddressFormat(buf, addr, false));
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</parentaddr>\n");
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</adapter>\n");
            }
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_NAME)
        virBufferEscapeString(buf, "<name>%s</name>\n", src->name);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_INITIATOR_IQN) &&
        src->initiator.iqn) {
        virBufferAddLit(buf, "<initiator>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<iqn name='%s'/>\n",
                              src->initiator.iqn);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</initiator>\n");
    }

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

    if (src->auth) {
        if (virStorageAuthDefFormat(buf, src->auth) < 0)
            return -1;
    }

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
    virBufferAsprintf(buf, "<pool type='%s'>\n", type);
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

    /* RBD, Sheepdog, and Gluster devices are not local block devs nor
     * files, so they don't have a target */
    if (def->type != VIR_STORAGE_POOL_RBD &&
        def->type != VIR_STORAGE_POOL_SHEEPDOG &&
        def->type != VIR_STORAGE_POOL_GLUSTER) {
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
    if (virStrToLong_ull(val, NULL, 10, ret) < 0) {
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
    virStorageVolDefPtr ret;
    virStorageVolOptionsPtr options;
    char *type = NULL;
    char *allocation = NULL;
    char *capacity = NULL;
    char *unit = NULL;
    char *backingStore = NULL;
    xmlNodePtr node;
    xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    virCheckFlags(VIR_VOL_XML_PARSE_NO_CAPACITY |
                  VIR_VOL_XML_PARSE_OPT_CAPACITY, NULL);

    options = virStorageVolOptionsForPoolType(pool->type);
    if (options == NULL)
        return NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->name = virXPathString("string(./name)", ctxt);
    if (ret->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing volume name element"));
        goto error;
    }

    /* Normally generated by pool refresh, but useful for unit tests */
    ret->key = virXPathString("string(./key)", ctxt);

    /* Technically overridden by pool refresh, but useful for unit tests */
    type = virXPathString("string(./@type)", ctxt);
    if (type) {
        if ((ret->type = virStorageVolTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume type '%s'"), type);
            goto error;
        }
    }

    if ((backingStore = virXPathString("string(./backingStore/path)", ctxt))) {
        if (VIR_ALLOC(ret->target.backingStore) < 0)
            goto error;

        ret->target.backingStore->path = backingStore;
        backingStore = NULL;

        if (options->formatFromString) {
            char *format = virXPathString("string(./backingStore/format/@type)", ctxt);
            if (format == NULL)
                ret->target.backingStore->format = options->defaultFormat;
            else
                ret->target.backingStore->format = (options->formatFromString)(format);

            if (ret->target.backingStore->format < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown volume format type %s"), format);
                VIR_FREE(format);
                goto error;
            }
            VIR_FREE(format);
        }

        if (VIR_ALLOC(ret->target.backingStore->perms) < 0)
            goto error;
        if (virStorageDefParsePerms(ctxt, ret->target.backingStore->perms,
                                    "./backingStore/permissions") < 0)
            goto error;
    }

    capacity = virXPathString("string(./capacity)", ctxt);
    unit = virXPathString("string(./capacity/@unit)", ctxt);
    if (capacity) {
        if (virStorageSize(unit, capacity, &ret->target.capacity) < 0)
            goto error;
    } else if (!(flags & VIR_VOL_XML_PARSE_NO_CAPACITY) &&
               !((flags & VIR_VOL_XML_PARSE_OPT_CAPACITY) && ret->target.backingStore)) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing capacity element"));
        goto error;
    }
    VIR_FREE(unit);

    allocation = virXPathString("string(./allocation)", ctxt);
    if (allocation) {
        unit = virXPathString("string(./allocation/@unit)", ctxt);
        if (virStorageSize(unit, allocation, &ret->target.allocation) < 0)
            goto error;
        ret->target.has_allocation = true;
    } else {
        ret->target.allocation = ret->target.capacity;
    }

    ret->target.path = virXPathString("string(./target/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString("string(./target/format/@type)", ctxt);
        if (format == NULL)
            ret->target.format = options->defaultFormat;
        else
            ret->target.format = (options->formatFromString)(format);

        if (ret->target.format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto error;
        }
        VIR_FREE(format);
    }

    if (VIR_ALLOC(ret->target.perms) < 0)
        goto error;
    if (virStorageDefParsePerms(ctxt, ret->target.perms,
                                "./target/permissions") < 0)
        goto error;

    node = virXPathNode("./target/encryption", ctxt);
    if (node != NULL) {
        ret->target.encryption = virStorageEncryptionParseNode(ctxt->doc,
                                                               node);
        if (ret->target.encryption == NULL)
            goto error;
    }

    ret->target.compat = virXPathString("string(./target/compat)", ctxt);
    if (virStorageFileCheckCompat(ret->target.compat) < 0)
        goto error;

    if (virXPathNode("./target/nocow", ctxt))
        ret->target.nocow = true;

    if (virXPathNode("./target/features", ctxt)) {
        if ((n = virXPathNodeSet("./target/features/*", ctxt, &nodes)) < 0)
            goto error;

        if (!ret->target.compat && VIR_STRDUP(ret->target.compat, "1.1") < 0)
            goto error;

        if (!(ret->target.features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST)))
            goto error;

        for (i = 0; i < n; i++) {
            int f = virStorageFileFeatureTypeFromString((const char*)nodes[i]->name);

            if (f < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("unsupported feature %s"),
                               (const char*)nodes[i]->name);
                goto error;
            }
            ignore_value(virBitmapSetBit(ret->target.features, f));
        }
        VIR_FREE(nodes);
    }

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(allocation);
    VIR_FREE(capacity);
    VIR_FREE(unit);
    VIR_FREE(type);
    VIR_FREE(backingStore);
    return ret;

 error:
    virStorageVolDefFree(ret);
    ret = NULL;
    goto cleanup;
}

virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root,
                          unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virStorageVolDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "volume")) {
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

    if (def->target.backingStore &&
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


virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                            const unsigned char *uuid)
{
    size_t i;

    for (i = 0; i < pools->count; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (!memcmp(pools->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return pools->objs[i];
        virStoragePoolObjUnlock(pools->objs[i]);
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
                            const char *name)
{
    size_t i;

    for (i = 0; i < pools->count; i++) {
        virStoragePoolObjLock(pools->objs[i]);
        if (STREQ(pools->objs[i]->def->name, name))
            return pools->objs[i];
        virStoragePoolObjUnlock(pools->objs[i]);
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolSourceFindDuplicateDevices(virStoragePoolObjPtr pool,
                                         virStoragePoolDefPtr def)
{
    size_t i, j;

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
    size_t i;
    for (i = 0; i < pool->volumes.count; i++)
        virStorageVolDefFree(pool->volumes.objs[i]);

    VIR_FREE(pool->volumes.objs);
    pool->volumes.count = 0;
}

virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr pool,
                          const char *key)
{
    size_t i;

    for (i = 0; i < pool->volumes.count; i++)
        if (STREQ(pool->volumes.objs[i]->key, key))
            return pool->volumes.objs[i];

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr pool,
                           const char *path)
{
    size_t i;

    for (i = 0; i < pool->volumes.count; i++)
        if (STREQ(pool->volumes.objs[i]->target.path, path))
            return pool->volumes.objs[i];

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr pool,
                           const char *name)
{
    size_t i;

    for (i = 0; i < pool->volumes.count; i++)
        if (STREQ(pool->volumes.objs[i]->name, name))
            return pool->volumes.objs[i];

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjAssignDef(virStoragePoolObjListPtr pools,
                           virStoragePoolDefPtr def)
{
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

    if (VIR_ALLOC(pool) < 0)
        return NULL;

    if (virMutexInit(&pool->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        VIR_FREE(pool);
        return NULL;
    }
    virStoragePoolObjLock(pool);
    pool->active = 0;

    if (VIR_APPEND_ELEMENT_COPY(pools->objs, pools->count, pool) < 0) {
        virStoragePoolObjUnlock(pool);
        virStoragePoolObjFree(pool);
        return NULL;
    }
    pool->def = def;

    return pool;
}

static virStoragePoolObjPtr
virStoragePoolObjLoad(virStoragePoolObjListPtr pools,
                      const char *file,
                      const char *path,
                      const char *autostartLink)
{
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;

    if (!(def = virStoragePoolDefParseFile(path)))
        return NULL;

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Storage pool config filename '%s' does "
                         "not match pool name '%s'"),
                       path, def->name);
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    VIR_FREE(pool->configFile);  /* for driver reload */
    if (VIR_STRDUP(pool->configFile, path) < 0) {
        virStoragePoolObjRemove(pools, pool);
        return NULL;
    }
    VIR_FREE(pool->autostartLink); /* for driver reload */
    if (VIR_STRDUP(pool->autostartLink, autostartLink) < 0) {
        virStoragePoolObjRemove(pools, pool);
        return NULL;
    }

    pool->autostart = virFileLinkPointsTo(pool->autostartLink,
                                          pool->configFile);

    return pool;
}


virStoragePoolObjPtr
virStoragePoolLoadState(virStoragePoolObjListPtr pools,
                        const char *stateDir,
                        const char *name)
{
    char *stateFile = NULL;
    virStoragePoolDefPtr def = NULL;
    virStoragePoolObjPtr pool = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr node = NULL;

    if (!(stateFile = virFileBuildPath(stateDir, name, ".xml")))
        goto error;

    if (!(xml = virXMLParseCtxt(stateFile, NULL, _("(pool state)"), &ctxt)))
        goto error;

    if (!(node = virXPathNode("//pool", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any 'pool' element in state file"));
        goto error;
    }

    ctxt->node = node;
    if (!(def = virStoragePoolDefParseXML(ctxt)))
        goto error;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Storage pool state file '%s' does not match "
                         "pool name '%s'"),
                       stateFile, def->name);
        goto error;
    }

    /* create the object */
    if (!(pool = virStoragePoolObjAssignDef(pools, def)))
        goto error;

    /* XXX: future handling of some additional useful status data,
     * for now, if a status file for a pool exists, the pool will be marked
     * as active
     */

    pool->active = 1;

 cleanup:
    VIR_FREE(stateFile);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return pool;

 error:
    virStoragePoolDefFree(def);
    goto cleanup;
}


int
virStoragePoolLoadAllState(virStoragePoolObjListPtr pools,
                           const char *stateDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virStoragePoolObjPtr pool;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        if (!(pool = virStoragePoolLoadState(pools, stateDir, entry->d_name)))
            continue;
        virStoragePoolObjUnlock(pool);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virStoragePoolLoadAllConfigs(virStoragePoolObjListPtr pools,
                             const char *configDir,
                             const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        char *path;
        char *autostartLink;
        virStoragePoolObjPtr pool;

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

    VIR_DIR_CLOSE(dir);
    return ret;
}


static int virStoragePoolSaveXML(const char *path,
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
    int ret = -1;
    char *xml;

    virBufferAddLit(&buf, "<poolstate>\n");
    virBufferAdjustIndent(&buf, 2);

    if (virStoragePoolDefFormatBuf(&buf, def) < 0)
        goto error;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</poolstate>\n");

    if (virBufferCheckError(&buf) < 0)
        goto error;

    if (!(xml = virBufferContentAndReset(&buf)))
        goto error;

    if (virStoragePoolSaveXML(stateFile, def, xml))
        goto error;

    ret = 0;

 error:
    VIR_FREE(xml);
    return ret;
}


int
virStoragePoolSaveConfig(const char *configFile,
                         virStoragePoolDefPtr def)
{
    char *xml;
    int ret = -1;

    if (!(xml = virStoragePoolDefFormat(def))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate XML"));
        return -1;
    }

    if (virStoragePoolSaveXML(configFile, def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}

int
virStoragePoolObjSaveDef(virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr pool,
                         virStoragePoolDefPtr def)
{
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

    return virStoragePoolSaveConfig(pool->configFile, def);
}

int
virStoragePoolObjDeleteDef(virStoragePoolObjPtr pool)
{
    if (!pool->configFile) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no config file for %s"), pool->def->name);
        return -1;
    }

    if (unlink(pool->configFile) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
int
virStoragePoolObjIsDuplicate(virStoragePoolObjListPtr pools,
                             virStoragePoolDefPtr def,
                             unsigned int check_active)
{
    int ret = -1;
    virStoragePoolObjPtr pool = NULL;

    /* See if a Pool with matching UUID already exists */
    pool = virStoragePoolObjFindByUUID(pools, def->uuid);
    if (pool) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(pool->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(pool->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%s' is already defined with uuid %s"),
                           pool->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if Pool is already active, refuse it */
            if (virStoragePoolObjIsActive(pool)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("pool is already active as '%s'"),
                               pool->def->name);
                goto cleanup;
            }
        }

        ret = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        pool = virStoragePoolObjFindByName(pools, def->name);
        if (pool) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(pool->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto cleanup;
        }
        ret = 0;
    }

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static int
getSCSIHostNumber(virStoragePoolSourceAdapter adapter,
                  unsigned int *hostnum)
{
    int ret = -1;
    unsigned int num;
    char *name = NULL;

    if (adapter.data.scsi_host.has_parent) {
        virPCIDeviceAddress addr = adapter.data.scsi_host.parentaddr;
        unsigned int unique_id = adapter.data.scsi_host.unique_id;

        if (!(name = virSCSIHostGetNameByParentaddr(addr.domain,
                                                    addr.bus,
                                                    addr.slot,
                                                    addr.function,
                                                    unique_id)))
            goto cleanup;
        if (virSCSIHostGetNumber(name, &num) < 0)
            goto cleanup;
    } else {
        if (virSCSIHostGetNumber(adapter.data.scsi_host.name, &num) < 0)
            goto cleanup;
    }

    *hostnum = num;
    ret = 0;

 cleanup:
    VIR_FREE(name);
    return ret;
}


static bool
virStorageIsSameHostnum(const char *name,
                        unsigned int scsi_hostnum)
{
    unsigned int fc_hostnum;

    if (virSCSIHostGetNumber(name, &fc_hostnum) == 0 &&
        scsi_hostnum == fc_hostnum)
        return true;

    return false;
}


/*
 * matchFCHostToSCSIHost:
 *
 * @conn: Connection pointer
 * @fc_adapter: fc_host adapter (either def or pool->def)
 * @scsi_hostnum: Already determined "scsi_pool" hostnum
 *
 * Returns true/false whether there is a match between the incoming
 *         fc_adapter host# and the scsi_host host#
 */
static bool
matchFCHostToSCSIHost(virConnectPtr conn,
                      virStoragePoolSourceAdapter fc_adapter,
                      unsigned int scsi_hostnum)
{
    bool ret = false;
    char *name = NULL;
    char *scsi_host_name = NULL;
    char *parent_name = NULL;

    /* If we have a parent defined, get its hostnum, and compare to the
     * scsi_hostnum. If they are the same, then we have a match
     */
    if (fc_adapter.data.fchost.parent &&
        virStorageIsSameHostnum(fc_adapter.data.fchost.parent, scsi_hostnum))
        return true;

    /* If we find an fc_adapter name, then either libvirt created a vHBA
     * for this fc_host or a 'virsh nodedev-create' generated a vHBA.
     */
    if ((name = virVHBAGetHostByWWN(NULL, fc_adapter.data.fchost.wwnn,
                                    fc_adapter.data.fchost.wwpn))) {

        /* Get the scsi_hostN for the vHBA in order to see if it
         * matches our scsi_hostnum
         */
        if (virStorageIsSameHostnum(name, scsi_hostnum)) {
            ret = true;
            goto cleanup;
        }

        /* We weren't provided a parent, so we have to query the node
         * device driver in order to ascertain the parent of the vHBA.
         * If the parent fc_hostnum is the same as the scsi_hostnum, we
         * have a match.
         */
        if (conn && !fc_adapter.data.fchost.parent) {
            if (virAsprintf(&scsi_host_name, "scsi_%s", name) < 0)
                goto cleanup;
            if ((parent_name = virNodeDeviceGetParentName(conn,
                                                          scsi_host_name))) {
                if (virStorageIsSameHostnum(parent_name, scsi_hostnum)) {
                    ret = true;
                    goto cleanup;
                }
            } else {
                /* Throw away the error and fall through */
                virResetLastError();
                VIR_DEBUG("Could not determine parent vHBA");
            }
        }
    }

    /* NB: Lack of a name means that this vHBA hasn't yet been created,
     *     which means our scsi_host cannot be using the vHBA. Furthermore,
     *     lack of a provided parent means libvirt is going to choose the
     *     "best" fc_host capable adapter based on availabilty. That could
     *     conflict with an existing scsi_host definition, but there's no
     *     way to know that now.
     */

 cleanup:
    VIR_FREE(name);
    VIR_FREE(parent_name);
    VIR_FREE(scsi_host_name);
    return ret;
}

static bool
matchSCSIAdapterParent(virStoragePoolObjPtr pool,
                       virStoragePoolDefPtr def)
{
    virPCIDeviceAddressPtr pooladdr =
        &pool->def->source.adapter.data.scsi_host.parentaddr;
    virPCIDeviceAddressPtr defaddr =
        &def->source.adapter.data.scsi_host.parentaddr;
    int pool_unique_id =
        pool->def->source.adapter.data.scsi_host.unique_id;
    int def_unique_id =
        def->source.adapter.data.scsi_host.unique_id;
    if (pooladdr->domain == defaddr->domain &&
        pooladdr->bus == defaddr->bus &&
        pooladdr->slot == defaddr->slot &&
        pooladdr->function == defaddr->function &&
        pool_unique_id == def_unique_id) {
        return true;
    }
    return false;
}

static bool
virStoragePoolSourceMatchSingleHost(virStoragePoolSourcePtr poolsrc,
                                    virStoragePoolSourcePtr defsrc)
{
    if (poolsrc->nhost != 1 && defsrc->nhost != 1)
        return false;

    if (defsrc->hosts[0].port &&
        poolsrc->hosts[0].port != defsrc->hosts[0].port)
        return false;

    return STREQ(poolsrc->hosts[0].name, defsrc->hosts[0].name);
}


static bool
virStoragePoolSourceISCSIMatch(virStoragePoolObjPtr matchpool,
                               virStoragePoolDefPtr def)
{
    virStoragePoolSourcePtr poolsrc = &matchpool->def->source;
    virStoragePoolSourcePtr defsrc = &def->source;

    /* NB: Do not check the source host name */
    if (STRNEQ_NULLABLE(poolsrc->initiator.iqn, defsrc->initiator.iqn))
        return false;

    return true;
}


int
virStoragePoolSourceFindDuplicate(virConnectPtr conn,
                                  virStoragePoolObjListPtr pools,
                                  virStoragePoolDefPtr def)
{
    size_t i;
    int ret = 1;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolObjPtr matchpool = NULL;

    /* Check the pool list for duplicate underlying storage */
    for (i = 0; i < pools->count; i++) {
        pool = pools->objs[i];
        if (def->type != pool->def->type)
            continue;

        /* Don't match against ourself if re-defining existing pool ! */
        if (STREQ(pool->def->name, def->name))
            continue;

        virStoragePoolObjLock(pool);

        switch ((virStoragePoolType)pool->def->type) {
        case VIR_STORAGE_POOL_DIR:
            if (STREQ(pool->def->target.path, def->target.path))
                matchpool = pool;
            break;

        case VIR_STORAGE_POOL_GLUSTER:
            if (STREQ(pool->def->source.name, def->source.name) &&
                STREQ_NULLABLE(pool->def->source.dir, def->source.dir) &&
                virStoragePoolSourceMatchSingleHost(&pool->def->source,
                                                    &def->source))
                matchpool = pool;
            break;

        case VIR_STORAGE_POOL_NETFS:
            if (STREQ(pool->def->source.dir, def->source.dir) &&
                virStoragePoolSourceMatchSingleHost(&pool->def->source,
                                                    &def->source))
                matchpool = pool;
            break;

        case VIR_STORAGE_POOL_SCSI:
            if (pool->def->source.adapter.type ==
                VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST &&
                def->source.adapter.type ==
                VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
                if (STREQ(pool->def->source.adapter.data.fchost.wwnn,
                          def->source.adapter.data.fchost.wwnn) &&
                    STREQ(pool->def->source.adapter.data.fchost.wwpn,
                          def->source.adapter.data.fchost.wwpn))
                    matchpool = pool;
            } else if (pool->def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST &&
                       def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
                unsigned int pool_hostnum, def_hostnum;

                if (pool->def->source.adapter.data.scsi_host.has_parent &&
                    def->source.adapter.data.scsi_host.has_parent &&
                    matchSCSIAdapterParent(pool, def)) {
                    matchpool = pool;
                    break;
                }

                if (getSCSIHostNumber(pool->def->source.adapter,
                                      &pool_hostnum) < 0 ||
                    getSCSIHostNumber(def->source.adapter, &def_hostnum) < 0)
                    break;
                if (pool_hostnum == def_hostnum)
                    matchpool = pool;
            } else if (pool->def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST &&
                       def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
                unsigned int scsi_hostnum;

                /* Get the scsi_hostN for the scsi_host source adapter def */
                if (getSCSIHostNumber(def->source.adapter,
                                      &scsi_hostnum) < 0)
                    break;

                if (matchFCHostToSCSIHost(conn, pool->def->source.adapter,
                                          scsi_hostnum)) {
                    matchpool = pool;
                    break;
                }

            } else if (pool->def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST &&
                       def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
                unsigned int scsi_hostnum;

                if (getSCSIHostNumber(pool->def->source.adapter,
                                      &scsi_hostnum) < 0)
                    break;

                if (matchFCHostToSCSIHost(conn, def->source.adapter,
                                          scsi_hostnum)) {
                    matchpool = pool;
                    break;
                }
            }
            break;
        case VIR_STORAGE_POOL_ISCSI:
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            if (matchpool) {
                if (!virStoragePoolSourceISCSIMatch(matchpool, def))
                    matchpool = NULL;
            }
            break;
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_LOGICAL:
        case VIR_STORAGE_POOL_DISK:
        case VIR_STORAGE_POOL_ZFS:
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            break;
        case VIR_STORAGE_POOL_SHEEPDOG:
            if (virStoragePoolSourceMatchSingleHost(&pool->def->source,
                                                    &def->source))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_MPATH:
            /* Only one mpath pool is valid per host */
            matchpool = pool;
            break;
        case VIR_STORAGE_POOL_VSTORAGE:
            if (STREQ(pool->def->source.name, def->source.name))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_RBD:
        case VIR_STORAGE_POOL_LAST:
            break;
        }
        virStoragePoolObjUnlock(pool);

        if (matchpool)
            break;
    }

    if (matchpool) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Storage source conflict with pool: '%s'"),
                       matchpool->def->name);
        ret = -1;
    }
    return ret;
}

void
virStoragePoolObjLock(virStoragePoolObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void
virStoragePoolObjUnlock(virStoragePoolObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}

#define MATCH(FLAG) (flags & (FLAG))
static bool
virStoragePoolMatch(virStoragePoolObjPtr poolobj,
                    unsigned int flags)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE) &&
           virStoragePoolObjIsActive(poolobj)) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE) &&
           !virStoragePoolObjIsActive(poolobj))))
        return false;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT) &&
           poolobj->configFile) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT) &&
           !poolobj->configFile)))
        return false;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART) &&
           poolobj->autostart) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART) &&
           !poolobj->autostart)))
        return false;

    /* filter by pool type */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE)) {
        if (!((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_DIR) &&
               (poolobj->def->type == VIR_STORAGE_POOL_DIR))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FS) &&
               (poolobj->def->type == VIR_STORAGE_POOL_FS))      ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_NETFS) &&
               (poolobj->def->type == VIR_STORAGE_POOL_NETFS))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL) &&
               (poolobj->def->type == VIR_STORAGE_POOL_LOGICAL)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_DISK) &&
               (poolobj->def->type == VIR_STORAGE_POOL_DISK))    ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI) &&
               (poolobj->def->type == VIR_STORAGE_POOL_ISCSI))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_SCSI) &&
               (poolobj->def->type == VIR_STORAGE_POOL_SCSI))    ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_MPATH) &&
               (poolobj->def->type == VIR_STORAGE_POOL_MPATH))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_RBD) &&
               (poolobj->def->type == VIR_STORAGE_POOL_RBD))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG) &&
               (poolobj->def->type == VIR_STORAGE_POOL_SHEEPDOG)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER) &&
               (poolobj->def->type == VIR_STORAGE_POOL_GLUSTER)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ZFS) &&
               poolobj->def->type == VIR_STORAGE_POOL_ZFS)       ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE) &&
               poolobj->def->type == VIR_STORAGE_POOL_VSTORAGE)))
            return false;
    }

    return true;
}
#undef MATCH

int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjList poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags)
{
    virStoragePoolPtr *tmp_pools = NULL;
    virStoragePoolPtr pool = NULL;
    int npools = 0;
    int ret = -1;
    size_t i;

    if (pools && VIR_ALLOC_N(tmp_pools, poolobjs.count + 1) < 0)
        goto cleanup;

    for (i = 0; i < poolobjs.count; i++) {
        virStoragePoolObjPtr poolobj = poolobjs.objs[i];
        virStoragePoolObjLock(poolobj);
        if ((!filter || filter(conn, poolobj->def)) &&
            virStoragePoolMatch(poolobj, flags)) {
            if (pools) {
                if (!(pool = virGetStoragePool(conn,
                                               poolobj->def->name,
                                               poolobj->def->uuid,
                                               NULL, NULL))) {
                    virStoragePoolObjUnlock(poolobj);
                    goto cleanup;
                }
                tmp_pools[npools] = pool;
            }
            npools++;
        }
        virStoragePoolObjUnlock(poolobj);
    }

    if (tmp_pools) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(tmp_pools, npools + 1));
        *pools = tmp_pools;
        tmp_pools = NULL;
    }

    ret = npools;

 cleanup:
    if (tmp_pools) {
        for (i = 0; i < npools; i++)
            virObjectUnref(tmp_pools[i]);
    }

    VIR_FREE(tmp_pools);
    return ret;
}
