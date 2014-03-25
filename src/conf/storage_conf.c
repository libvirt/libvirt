/*
 * storage_conf.c: config handling for storage driver
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
#include "storage_conf.h"
#include "virstoragefile.h"

#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define DEFAULT_POOL_PERM_MODE 0755
#define DEFAULT_VOL_PERM_MODE  0600

VIR_ENUM_IMPL(virStorageVol,
              VIR_STORAGE_VOL_LAST,
              "file", "block", "dir", "network", "netdir")

VIR_ENUM_IMPL(virStoragePool,
              VIR_STORAGE_POOL_LAST,
              "dir", "fs", "netfs",
              "logical", "disk", "iscsi",
              "scsi", "mpath", "rbd", "sheepdog", "gluster")

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

VIR_ENUM_IMPL(virStoragePoolSourceAdapterType,
              VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_LAST,
              "default", "scsi_host", "fc_host")

VIR_ENUM_IMPL(virStoragePoolAuthType,
              VIR_STORAGE_POOL_AUTH_LAST,
              "none", "chap", "ceph")

typedef const char *(*virStorageVolFormatToString)(int format);
typedef int (*virStorageVolFormatFromString)(const char *format);
typedef const char *(*virStorageVolFeatureToString)(int feature);
typedef int (*virStorageVolFeatureFromString)(const char *feature);

typedef const char *(*virStoragePoolFormatToString)(int format);
typedef int (*virStoragePoolFormatFromString)(const char *format);

typedef struct _virStorageVolOptions virStorageVolOptions;
typedef virStorageVolOptions *virStorageVolOptionsPtr;
struct _virStorageVolOptions {
    int defaultFormat;
    virStorageVolFormatToString formatToString;
    virStorageVolFormatFromString formatFromString;
    virStorageVolFeatureToString featureToString;
    virStorageVolFeatureFromString featureFromString;
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
         .featureFromString = virStorageFileFeatureTypeFromString,
         .featureToString = virStorageFileFeatureTypeToString,
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
         .featureFromString = virStorageFileFeatureTypeFromString,
         .featureToString = virStorageFileFeatureTypeToString,
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
         .featureFromString = virStorageFileFeatureTypeFromString,
         .featureToString = virStorageFileFeatureTypeToString,
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
          .formatToString = virStoragePoolFormatDiskTypeToString,
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
    }
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

    for (i = 0; i < def->source.nextent; i++) {
        VIR_FREE(def->source.extents[i].path);
    }
    VIR_FREE(def->source.extents);

    VIR_FREE(def->target.compat);
    virBitmapFree(def->target.features);
    VIR_FREE(def->target.path);
    VIR_FREE(def->target.perms.label);
    VIR_FREE(def->target.timestamps);
    virStorageEncryptionFree(def->target.encryption);
    VIR_FREE(def->backingStore.path);
    VIR_FREE(def->backingStore.perms.label);
    VIR_FREE(def->backingStore.timestamps);
    virStorageEncryptionFree(def->backingStore.encryption);
    VIR_FREE(def);
}

static void
virStoragePoolSourceAdapterClear(virStoragePoolSourceAdapter adapter)
{
    if (adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
        VIR_FREE(adapter.data.fchost.wwnn);
        VIR_FREE(adapter.data.fchost.wwpn);
        VIR_FREE(adapter.data.fchost.parent);
    } else if (adapter.type ==
               VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
        VIR_FREE(adapter.data.name);
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

    for (i = 0; i < source->nhost; i++) {
        VIR_FREE(source->hosts[i].name);
    }
    VIR_FREE(source->hosts);

    for (i = 0; i < source->ndevice; i++)
        virStoragePoolSourceDeviceClear(&source->devices[i]);
    VIR_FREE(source->devices);
    VIR_FREE(source->dir);
    VIR_FREE(source->name);
    virStoragePoolSourceAdapterClear(source->adapter);
    VIR_FREE(source->initiator.iqn);
    VIR_FREE(source->vendor);
    VIR_FREE(source->product);

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        VIR_FREE(source->auth.chap.username);
        VIR_FREE(source->auth.chap.secret.usage);
    }

    if (source->authType == VIR_STORAGE_POOL_AUTH_CEPHX) {
        VIR_FREE(source->auth.cephx.username);
        VIR_FREE(source->auth.cephx.secret.usage);
    }
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
virStoragePoolDefParseAuthSecret(xmlXPathContextPtr ctxt,
                                 virStoragePoolAuthSecretPtr secret)
{
    char *uuid = NULL;
    int ret = -1;

    uuid = virXPathString("string(./auth/secret/@uuid)", ctxt);
    secret->usage = virXPathString("string(./auth/secret/@usage)", ctxt);
    if (uuid == NULL && secret->usage == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing auth secret uuid or usage attribute"));
        return -1;
    }

    if (uuid != NULL) {
        if (secret->usage != NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("either auth secret uuid or usage expected"));
            goto cleanup;
        }
        if (virUUIDParse(uuid, secret->uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid auth secret uuid"));
            goto cleanup;
        }
        secret->uuidUsable = true;
    } else {
        secret->uuidUsable = false;
    }

    ret = 0;
 cleanup:
    VIR_FREE(uuid);
    return ret;
}

static int
virStoragePoolDefParseAuth(xmlXPathContextPtr ctxt,
                           virStoragePoolSourcePtr source)
{
    int ret = -1;
    char *authType = NULL;
    char *username = NULL;

    authType = virXPathString("string(./auth/@type)", ctxt);
    if (authType == NULL) {
        source->authType = VIR_STORAGE_POOL_AUTH_NONE;
        ret = 0;
        goto cleanup;
    }

    if ((source->authType =
         virStoragePoolAuthTypeTypeFromString(authType)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown auth type '%s'"),
                       authType);
        goto cleanup;
    }

    username = virXPathString("string(./auth/@username)", ctxt);
    if (username == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing auth username attribute"));
        goto cleanup;
    }

    if (source->authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        source->auth.chap.username = username;
        username = NULL;
        if (virStoragePoolDefParseAuthSecret(ctxt,
                                             &source->auth.chap.secret) < 0)
            goto cleanup;
    }
    else if (source->authType == VIR_STORAGE_POOL_AUTH_CEPHX) {
        source->auth.cephx.username = username;
        username = NULL;
        if (virStoragePoolDefParseAuthSecret(ctxt,
                                             &source->auth.cephx.secret) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(authType);
    VIR_FREE(username);
    return ret;
}

static int
virStoragePoolDefParseSource(xmlXPathContextPtr ctxt,
                             virStoragePoolSourcePtr source,
                             int pool_type,
                             xmlNodePtr node)
{
    int ret = -1;
    xmlNodePtr relnode, *nodeset = NULL;
    int nsource;
    size_t i;
    virStoragePoolOptionsPtr options;
    char *name = NULL;
    char *port = NULL;
    char *adapter_type = NULL;
    int n;

    relnode = ctxt->node;
    ctxt->node = node;

    if ((options = virStoragePoolOptionsForPoolType(pool_type)) == NULL) {
        goto cleanup;
    }

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
        virStoragePoolSourceDevice dev = { .path = NULL };
        dev.path = virXMLPropString(nodeset[i], "path");

        if (dev.path == NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing storage pool source device path"));
            goto cleanup;
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
             virStoragePoolSourceAdapterTypeTypeFromString(adapter_type)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown pool adapter type '%s'"),
                           adapter_type);
            goto cleanup;
        }

        if (source->adapter.type ==
            VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            source->adapter.data.fchost.parent =
                virXPathString("string(./adapter/@parent)", ctxt);
            source->adapter.data.fchost.wwnn =
                virXPathString("string(./adapter/@wwnn)", ctxt);
            source->adapter.data.fchost.wwpn =
                virXPathString("string(./adapter/@wwpn)", ctxt);
        } else if (source->adapter.type ==
                   VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
            source->adapter.data.name =
                virXPathString("string(./adapter/@name)", ctxt);
        }
    } else {
        char *wwnn = NULL;
        char *wwpn = NULL;
        char *parent = NULL;

        wwnn = virXPathString("string(./adapter/@wwnn)", ctxt);
        wwpn = virXPathString("string(./adapter/@wwpn)", ctxt);
        parent = virXPathString("string(./adapter/@parent)", ctxt);

        if (wwnn || wwpn || parent) {
            VIR_FREE(wwnn);
            VIR_FREE(wwpn);
            VIR_FREE(parent);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Use of 'wwnn', 'wwpn', and 'parent' attributes "
                             "requires the 'fc_host' adapter 'type'"));
            goto cleanup;
        }

        /* To keep back-compat, 'type' is not required to specify
         * for scsi_host adapter.
         */
        if ((source->adapter.data.name =
             virXPathString("string(./adapter/@name)", ctxt)))
            source->adapter.type =
                VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST;
    }

    if (virStoragePoolDefParseAuth(ctxt, source) < 0)
        goto cleanup;

    source->vendor = virXPathString("string(./vendor/@name)", ctxt);
    source->product = virXPathString("string(./product/@name)", ctxt);

    ret = 0;
 cleanup:
    ctxt->node = relnode;

    VIR_FREE(port);
    VIR_FREE(nodeset);
    VIR_FREE(adapter_type);
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
                        const char *permxpath,
                        int defaultmode)
{
    char *mode;
    long val;
    int ret = -1;
    xmlNodePtr relnode;
    xmlNodePtr node;

    node = virXPathNode(permxpath, ctxt);
    if (node == NULL) {
        /* Set default values if there is not <permissions> element */
        perms->mode = defaultmode;
        perms->uid = (uid_t) -1;
        perms->gid = (gid_t) -1;
        perms->label = NULL;
        return 0;
    }

    relnode = ctxt->node;
    ctxt->node = node;

    mode = virXPathString("string(./mode)", ctxt);
    if (!mode) {
        perms->mode = defaultmode;
    } else {
        int tmp;

        if (virStrToLong_i(mode, NULL, 8, &tmp) < 0 || (tmp & ~0777)) {
            VIR_FREE(mode);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("malformed octal mode"));
            goto error;
        }
        perms->mode = tmp;
        VIR_FREE(mode);
    }

    if (virXPathNode("./owner", ctxt) == NULL) {
        perms->uid = (uid_t) -1;
    } else {
        if (virXPathLong("number(./owner)", ctxt, &val) < 0 ||
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
        if (virXPathLong("number(./group)", ctxt, &val) < 0 ||
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

    if ((options = virStoragePoolOptionsForPoolType(ret->type)) == NULL) {
        goto error;
    }

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
            if (!ret->source.adapter.data.name) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing storage pool source adapter name"));
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
            if (virAsprintf(&target_path, "/dev/%s", ret->source.name) < 0) {
                goto error;
            }
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
                                    "./target/permissions",
                                    DEFAULT_POOL_PERM_MODE) < 0)
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
    char uuid[VIR_UUID_STRING_BUFLEN];

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
            if (src->devices[i].nfreeExtent) {
                virBufferEscapeString(buf, "<device path='%s'>\n",
                                      src->devices[i].path);
                virBufferAdjustIndent(buf, 2);
                for (j = 0; j < src->devices[i].nfreeExtent; j++) {
                    virBufferAsprintf(buf, "<freeExtent start='%llu' end='%llu'/>\n",
                                      src->devices[i].freeExtents[j].start,
                                      src->devices[i].freeExtents[j].end);
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</device>\n");
            } else {
                virBufferEscapeString(buf, "<device path='%s'/>\n",
                                      src->devices[i].path);
            }
        }
    }

    if (options->flags & VIR_STORAGE_POOL_SOURCE_DIR)
        virBufferEscapeString(buf, "<dir path='%s'/>\n", src->dir);

    if ((options->flags & VIR_STORAGE_POOL_SOURCE_ADAPTER)) {
        if (src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST ||
            src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST)
            virBufferAsprintf(buf, "<adapter type='%s'",
                              virStoragePoolSourceAdapterTypeTypeToString(src->adapter.type));

        if (src->adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            virBufferEscapeString(buf, " parent='%s'",
                                  src->adapter.data.fchost.parent);
            virBufferAsprintf(buf, " wwnn='%s' wwpn='%s'/>\n",
                              src->adapter.data.fchost.wwnn,
                              src->adapter.data.fchost.wwpn);
        } else if (src->adapter.type ==
                 VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
            virBufferAsprintf(buf, " name='%s'/>\n", src->adapter.data.name);
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

    if (src->authType == VIR_STORAGE_POOL_AUTH_CHAP ||
        src->authType == VIR_STORAGE_POOL_AUTH_CEPHX) {
        virBufferAsprintf(buf, "<auth type='%s' ",
                          virStoragePoolAuthTypeTypeToString(src->authType));
        virBufferEscapeString(buf, "username='%s'>\n",
                              (src->authType == VIR_STORAGE_POOL_AUTH_CHAP ?
                               src->auth.chap.username :
                               src->auth.cephx.username));
        virBufferAdjustIndent(buf, 2);

        virBufferAddLit(buf, "<secret");
        if (src->auth.cephx.secret.uuidUsable) {
            virUUIDFormat(src->auth.cephx.secret.uuid, uuid);
            virBufferAsprintf(buf, " uuid='%s'", uuid);
        }

        if (src->auth.cephx.secret.usage != NULL) {
            virBufferAsprintf(buf, " usage='%s'", src->auth.cephx.secret.usage);
        }
        virBufferAddLit(buf, "/>\n");

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</auth>\n");
    }

    virBufferEscapeString(buf, "<vendor name='%s'/>\n", src->vendor);
    virBufferEscapeString(buf, "<product name='%s'/>\n", src->product);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</source>\n");
    return 0;
}


char *
virStoragePoolDefFormat(virStoragePoolDefPtr def)
{
    virStoragePoolOptionsPtr options;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type;
    char uuid[VIR_UUID_STRING_BUFLEN];

    options = virStoragePoolOptionsForPoolType(def->type);
    if (options == NULL)
        return NULL;

    type = virStoragePoolTypeToString(def->type);
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected pool type"));
        goto cleanup;
    }
    virBufferAsprintf(&buf, "<pool type='%s'>\n", type);
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", uuid);

    virBufferAsprintf(&buf, "<capacity unit='bytes'>%llu</capacity>\n",
                      def->capacity);
    virBufferAsprintf(&buf, "<allocation unit='bytes'>%llu</allocation>\n",
                      def->allocation);
    virBufferAsprintf(&buf, "<available unit='bytes'>%llu</available>\n",
                      def->available);

    if (virStoragePoolSourceFormat(&buf, options, &def->source) < 0)
        goto cleanup;

    /* RBD, Sheepdog, and Gluster devices are not local block devs nor
     * files, so they don't have a target */
    if (def->type != VIR_STORAGE_POOL_RBD &&
        def->type != VIR_STORAGE_POOL_SHEEPDOG &&
        def->type != VIR_STORAGE_POOL_GLUSTER) {
        virBufferAddLit(&buf, "<target>\n");
        virBufferAdjustIndent(&buf, 2);

        virBufferEscapeString(&buf, "<path>%s</path>\n", def->target.path);

        virBufferAddLit(&buf, "<permissions>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<mode>0%o</mode>\n",
                          def->target.perms.mode);
        virBufferAsprintf(&buf, "<owner>%d</owner>\n",
                          (int) def->target.perms.uid);
        virBufferAsprintf(&buf, "<group>%d</group>\n",
                          (int) def->target.perms.gid);

        virBufferEscapeString(&buf, "<label>%s</label>\n",
                              def->target.perms.label);

        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</permissions>\n");
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</target>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</pool>\n");

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
                         xmlXPathContextPtr ctxt)
{
    virStorageVolDefPtr ret;
    virStorageVolOptionsPtr options;
    char *type = NULL;
    char *allocation = NULL;
    char *capacity = NULL;
    char *unit = NULL;
    xmlNodePtr node;
    xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

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

    capacity = virXPathString("string(./capacity)", ctxt);
    unit = virXPathString("string(./capacity/@unit)", ctxt);
    if (capacity == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing capacity element"));
        goto error;
    }
    if (virStorageSize(unit, capacity, &ret->capacity) < 0)
        goto error;
    VIR_FREE(unit);

    allocation = virXPathString("string(./allocation)", ctxt);
    if (allocation) {
        unit = virXPathString("string(./allocation/@unit)", ctxt);
        if (virStorageSize(unit, allocation, &ret->allocation) < 0)
            goto error;
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
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto error;
        }
        VIR_FREE(format);
    }

    if (virStorageDefParsePerms(ctxt, &ret->target.perms,
                                "./target/permissions",
                                DEFAULT_VOL_PERM_MODE) < 0)
        goto error;

    node = virXPathNode("./target/encryption", ctxt);
    if (node != NULL) {
        ret->target.encryption = virStorageEncryptionParseNode(ctxt->doc,
                                                               node);
        if (ret->target.encryption == NULL)
            goto error;
    }

    ret->backingStore.path = virXPathString("string(./backingStore/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString("string(./backingStore/format/@type)", ctxt);
        if (format == NULL)
            ret->backingStore.format = options->defaultFormat;
        else
            ret->backingStore.format = (options->formatFromString)(format);

        if (ret->backingStore.format < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown volume format type %s"), format);
            VIR_FREE(format);
            goto error;
        }
        VIR_FREE(format);
    }

    ret->target.compat = virXPathString("string(./target/compat)", ctxt);
    if (ret->target.compat) {
        char **version = virStringSplit(ret->target.compat, ".", 2);
        unsigned int result;

        if (!version || !version[1] ||
            virStrToLong_ui(version[0], NULL, 10, &result) < 0 ||
            virStrToLong_ui(version[1], NULL, 10, &result) < 0) {
            virStringFreeList(version);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("forbidden characters in 'compat' attribute"));
            goto error;
        }
        virStringFreeList(version);
    }

    if (options->featureFromString && virXPathNode("./target/features", ctxt)) {
        if ((n = virXPathNodeSet("./target/features/*", ctxt, &nodes)) < 0)
            goto error;

        if (!ret->target.compat && VIR_STRDUP(ret->target.compat, "1.1") < 0)
            goto error;

        if (!(ret->target.features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST)))
            goto error;

        for (i = 0; i < n; i++) {
            int f = options->featureFromString((const char*)nodes[i]->name);

            if (f < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("unsupported feature %s"),
                               (const char*)nodes[i]->name);
                goto error;
            }
            ignore_value(virBitmapSetBit(ret->target.features, f));
        }
        VIR_FREE(nodes);
    }

    if (virStorageDefParsePerms(ctxt, &ret->backingStore.perms,
                                "./backingStore/permissions",
                                DEFAULT_VOL_PERM_MODE) < 0)
        goto error;

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(allocation);
    VIR_FREE(capacity);
    VIR_FREE(unit);
    VIR_FREE(type);
    return ret;

 error:
    virStorageVolDefFree(ret);
    ret = NULL;
    goto cleanup;
}

virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root)
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
    def = virStorageVolDefParseXML(pool, ctxt);
 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virStorageVolDefPtr
virStorageVolDefParse(virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename)
{
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
                             virStorageVolTargetPtr def,
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

    virBufferAddLit(buf, "<permissions>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<mode>0%o</mode>\n",
                      def->perms.mode);
    virBufferAsprintf(buf, "<owner>%u</owner>\n",
                      (unsigned int) def->perms.uid);
    virBufferAsprintf(buf, "<group>%u</group>\n",
                      (unsigned int) def->perms.gid);


    virBufferEscapeString(buf, "<label>%s</label>\n",
                          def->perms.label);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</permissions>\n");

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

    if (options->featureToString && def->features) {
        size_t i;
        bool b;
        bool empty = virBitmapIsAllClear(def->features);

        if (empty) {
            virBufferAddLit(buf, "<features/>\n");
        } else {
            virBufferAddLit(buf, "<features>\n");
            virBufferAdjustIndent(buf, 2);
        }

        for (i = 0; i < VIR_STORAGE_FILE_FEATURE_LAST; i++) {
            ignore_value(virBitmapGetBit(def->features, i, &b));
            if (b)
                virBufferAsprintf(buf, "<%s/>\n",
                                  options->featureToString(i));
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
                      def->capacity);
    virBufferAsprintf(&buf, "<allocation unit='bytes'>%llu</allocation>\n",
                      def->allocation);

    if (virStorageVolTargetDefFormat(options, &buf,
                                     &def->target, "target") < 0)
        goto cleanup;

    if (def->backingStore.path &&
        virStorageVolTargetDefFormat(options, &buf,
                                     &def->backingStore, "backingStore") < 0)
        goto cleanup;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

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

    if (!(def = virStoragePoolDefParseFile(path))) {
        return NULL;
    }

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
        virStoragePoolDefFree(def);
        return NULL;
    }
    VIR_FREE(pool->autostartLink); /* for driver reload */
    if (VIR_STRDUP(pool->autostartLink, autostartLink) < 0) {
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
                             const char *autostartDir)
{
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
    char uuidstr[VIR_UUID_STRING_BUFLEN];
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate XML"));
        return -1;
    }

    virUUIDFormat(def->uuid, uuidstr);
    ret = virXMLSaveFile(pool->configFile,
                         virXMLPickShellSafeComment(def->name, uuidstr),
                         "pool-edit", xml);
    VIR_FREE(xml);

    return ret;
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

int
virStoragePoolSourceFindDuplicate(virStoragePoolObjListPtr pools,
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
                && (pool->def->source.nhost == 1 && def->source.nhost == 1) \
                && (STREQ(pool->def->source.hosts[0].name, def->source.hosts[0].name)))
                matchpool = pool;
            break;
        case VIR_STORAGE_POOL_SCSI:
            if (pool->def->source.adapter.type ==
                VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
                if (STREQ(pool->def->source.adapter.data.fchost.wwnn,
                          def->source.adapter.data.fchost.wwnn) &&
                    STREQ(pool->def->source.adapter.data.fchost.wwpn,
                          def->source.adapter.data.fchost.wwpn))
                    matchpool = pool;
            } else if (pool->def->source.adapter.type ==
                       VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST){
                if (STREQ(pool->def->source.adapter.data.name,
                          def->source.adapter.data.name))
                    matchpool = pool;
            }
            break;
        case VIR_STORAGE_POOL_ISCSI:
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            if (matchpool) {
                if (matchpool->def->source.nhost == 1 && def->source.nhost == 1) {
                    if (STREQ(matchpool->def->source.hosts[0].name, def->source.hosts[0].name)) {
                        if ((matchpool->def->source.initiator.iqn) && (def->source.initiator.iqn)) {
                            if (STREQ(matchpool->def->source.initiator.iqn, def->source.initiator.iqn))
                                break;
                            matchpool = NULL;
                        }
                        break;
                    }
                }
                matchpool = NULL;
            }
            break;
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_LOGICAL:
        case VIR_STORAGE_POOL_DISK:
            matchpool = virStoragePoolSourceFindDuplicateDevices(pool, def);
            break;
        default:
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
               (poolobj->def->type == VIR_STORAGE_POOL_GLUSTER))))
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
        for (i = 0; i < npools; i++) {
            if (tmp_pools[i])
                virStoragePoolFree(tmp_pools[i]);
        }
    }

    VIR_FREE(tmp_pools);
    return ret;
}
