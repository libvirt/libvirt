/*
 * virstorageobj.c: internal storage pool and volume objects handling
 *                  (derived from storage_conf.c)
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
#include <dirent.h>

#include "datatypes.h"
#include "node_device_conf.h"
#include "virstorageobj.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virscsihost.h"
#include "virstring.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("conf.virstorageobj");


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
getSCSIHostNumber(virStorageAdapterSCSIHostPtr scsi_host,
                  unsigned int *hostnum)
{
    int ret = -1;
    unsigned int num;
    char *name = NULL;

    if (scsi_host->has_parent) {
        virPCIDeviceAddressPtr addr = &scsi_host->parentaddr;
        unsigned int unique_id = scsi_host->unique_id;

        if (!(name = virSCSIHostGetNameByParentaddr(addr->domain,
                                                    addr->bus,
                                                    addr->slot,
                                                    addr->function,
                                                    unique_id)))
            goto cleanup;
        if (virSCSIHostGetNumber(name, &num) < 0)
            goto cleanup;
    } else {
        if (virSCSIHostGetNumber(scsi_host->name, &num) < 0)
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
 * @fchost: fc_host adapter ptr (either def or pool->def)
 * @scsi_hostnum: Already determined "scsi_pool" hostnum
 *
 * Returns true/false whether there is a match between the incoming
 *         fc_adapter host# and the scsi_host host#
 */
static bool
matchFCHostToSCSIHost(virConnectPtr conn,
                      virStorageAdapterFCHostPtr fchost,
                      unsigned int scsi_hostnum)
{
    bool ret = false;
    char *name = NULL;
    char *scsi_host_name = NULL;
    char *parent_name = NULL;

    /* If we have a parent defined, get its hostnum, and compare to the
     * scsi_hostnum. If they are the same, then we have a match
     */
    if (fchost->parent &&
        virStorageIsSameHostnum(fchost->parent, scsi_hostnum))
        return true;

    /* If we find an fc adapter name, then either libvirt created a vHBA
     * for this fc_host or a 'virsh nodedev-create' generated a vHBA.
     */
    if ((name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {

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
        if (conn && !fchost->parent) {
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
matchSCSIAdapterParent(virStorageAdapterSCSIHostPtr pool_scsi_host,
                       virStorageAdapterSCSIHostPtr def_scsi_host)
{
    virPCIDeviceAddressPtr pooladdr = &pool_scsi_host->parentaddr;
    virPCIDeviceAddressPtr defaddr = &def_scsi_host->parentaddr;

    if (pooladdr->domain == defaddr->domain &&
        pooladdr->bus == defaddr->bus &&
        pooladdr->slot == defaddr->slot &&
        pooladdr->function == defaddr->function &&
        pool_scsi_host->unique_id == def_scsi_host->unique_id)
        return true;

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
    virStorageAdapterPtr pool_adapter;
    virStorageAdapterPtr def_adapter;

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
            pool_adapter = &pool->def->source.adapter;
            def_adapter = &def->source.adapter;

            if (pool_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST &&
                def_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
                virStorageAdapterFCHostPtr pool_fchost =
                    &pool_adapter->data.fchost;
                virStorageAdapterFCHostPtr def_fchost =
                    &def_adapter->data.fchost;

                if (STREQ(pool_fchost->wwnn, def_fchost->wwnn) &&
                    STREQ(pool_fchost->wwpn, def_fchost->wwpn))
                    matchpool = pool;
            } else if (pool_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST &&
                       def_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) {
                virStorageAdapterSCSIHostPtr pool_scsi_host =
                    &pool_adapter->data.scsi_host;
                virStorageAdapterSCSIHostPtr def_scsi_host =
                    &def_adapter->data.scsi_host;
                unsigned int pool_hostnum, def_hostnum;

                if (pool_scsi_host->has_parent &&
                    def_scsi_host->has_parent &&
                    matchSCSIAdapterParent(pool_scsi_host, def_scsi_host)) {
                    matchpool = pool;
                    break;
                }

                if (getSCSIHostNumber(pool_scsi_host, &pool_hostnum) < 0 ||
                    getSCSIHostNumber(def_scsi_host, &def_hostnum) < 0)
                    break;
                if (pool_hostnum == def_hostnum)
                    matchpool = pool;
            } else if (pool_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_FC_HOST &&
                       def_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) {
                virStorageAdapterFCHostPtr pool_fchost =
                    &pool_adapter->data.fchost;
                virStorageAdapterSCSIHostPtr def_scsi_host =
                    &def_adapter->data.scsi_host;
                unsigned int scsi_hostnum;

                /* Get the scsi_hostN for the scsi_host source adapter def */
                if (getSCSIHostNumber(def_scsi_host, &scsi_hostnum) < 0)
                    break;

                if (matchFCHostToSCSIHost(conn, pool_fchost, scsi_hostnum)) {
                    matchpool = pool;
                    break;
                }

            } else if (pool_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST &&
                       def_adapter->type ==
                       VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
                virStorageAdapterSCSIHostPtr pool_scsi_host =
                    &pool_adapter->data.scsi_host;
                virStorageAdapterFCHostPtr def_fchost =
                    &def_adapter->data.fchost;
                unsigned int scsi_hostnum;

                if (getSCSIHostNumber(pool_scsi_host, &scsi_hostnum) < 0)
                    break;

                if (matchFCHostToSCSIHost(conn, def_fchost, scsi_hostnum)) {
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
               (poolobj->def->type == VIR_STORAGE_POOL_ZFS))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE) &&
               (poolobj->def->type == VIR_STORAGE_POOL_VSTORAGE))))
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
