/*
 * storage_backend_logical.c: storage backend for logical volume handling
 *
 * Copyright (C) 2007-2016 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "virerror.h"
#include "storage_backend_logical.h"
#include "storage_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"
#include "virutil.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_logical");


static int
virStorageBackendLogicalSetActive(virStoragePoolObj *pool,
                                  bool on)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virCommand) cmd = NULL;
    int ret;

    cmd = virStorageBackendLogicalChangeCmd(VGCHANGE, def, on);

    virObjectUnlock(pool);
    ret = virCommandRun(cmd, NULL);
    virObjectLock(pool);

    return ret;
}


/*
 * @path: Path to the device
 *
 * Remove the pv device since we're done with it. This ensures a subsequent
 * create won't require special arguments in order for force recreation.
 */
static void
virStorageBackendLogicalRemoveDevice(const char *path)
{
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(PVREMOVE, path, NULL);
    if (virCommandRun(cmd, NULL) < 0)
        VIR_INFO("Failed to pvremove logical device '%s'", path);
}


/*
 * @path: Path to the device
 *
 * Initialize and pvcreate the device.
 *
 * Returns 0 on success, -1 on failure with error message set
 */
static int
virStorageBackendLogicalInitializeDevice(const char *path)
{
    g_autoptr(virCommand) pvcmd = NULL;

    /*
     * LVM requires that the first sector is blanked if using
     * a whole disk as a PV. So we just blank them out regardless
     * rather than trying to figure out if we're a disk or partition
     */
    if (virStorageBackendZeroPartitionTable(path, 1024 * 1024) < 0)
        return -1;

    /*
     * Initialize the physical volume because vgcreate is not
     * clever enough todo this for us :-(
     */
    pvcmd = virCommandNewArgList(PVCREATE, path, NULL);
    return virCommandRun(pvcmd, NULL);
}


#define VIR_STORAGE_VOL_LOGICAL_SEGTYPE_STRIPED "striped"
#define VIR_STORAGE_VOL_LOGICAL_SEGTYPE_MIRROR  "mirror"
#define VIR_STORAGE_VOL_LOGICAL_SEGTYPE_RAID    "raid"

struct virStorageBackendLogicalPoolVolData {
    virStoragePoolObj *pool;
    virStorageVolDef *vol;
};

static int
virStorageBackendLogicalParseVolExtents(virStorageVolDef *vol,
                                        char **const groups)
{
    g_autoptr(GRegex) re = NULL;
    g_autoptr(GError) err = NULL;
    g_autoptr(GMatchInfo) info = NULL;
    int nextents;
    const char *regex_unit = "(\\S+)\\((\\S+)\\)";
    size_t i;
    unsigned long long offset;
    unsigned long long size;
    unsigned long long length;
    g_autofree char *regex = NULL;

    /* Assume 1 extent (the regex for 'devices' is "(\\S+)") and only
     * check the 'stripes' field if we have a striped, mirror, or one of
     * the raid (raid1, raid4, raid5*, raid6*, or raid10) segtypes in which
     * case the stripes field will denote the number of lv's within the
     * 'devices' field in order to generate the proper regex to decode
     * the field
     */
    nextents = 1;
    if (STREQ(groups[4], VIR_STORAGE_VOL_LOGICAL_SEGTYPE_STRIPED) ||
        STREQ(groups[4], VIR_STORAGE_VOL_LOGICAL_SEGTYPE_MIRROR) ||
        STRPREFIX(groups[4], VIR_STORAGE_VOL_LOGICAL_SEGTYPE_RAID)) {
        if (virStrToLong_i(groups[5], NULL, 10, &nextents) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("malformed volume extent stripes value"));
            return -1;
        }
    }

    if (virStrToLong_ull(groups[6], NULL, 10, &length) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume extent length value"));
        return -1;
    }

    if (virStrToLong_ull(groups[7], NULL, 10, &size) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume extent size value"));
        return -1;
    }

    /* Allocate space for 'nextents' regex_unit strings plus a comma for each */
    regex = g_new0(char, nextents * (strlen(regex_unit) + 1) + 1);
    strcat(regex, regex_unit);
    for (i = 1; i < nextents; i++) {
        /* "," is the separator of "devices" field */
        strcat(regex, ",");
        strcat(regex, regex_unit);
    }

    re = g_regex_new(regex, 0, 0, &err);
    if (!re) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %1$s"), err->message);
        return -1;
    }

    if (!g_regex_match(re, groups[3], 0, &info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed volume extent devices value"));
        return -1;
    }

    /* Each extent has a "path:offset" pair, and match #0
     * is the whole matched string.
     */
    for (i = 0; i < nextents; i++) {
        g_autofree char *offset_str = NULL;
        virStorageVolSourceExtent extent = { 0 };
        size_t j = (i * 2) + 1;

        offset_str = g_match_info_fetch(info, j + 1);

        if (virStrToLong_ull(offset_str, NULL, 10, &offset) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("malformed volume extent offset value"));
            return -1;
        }

        extent.path = g_match_info_fetch(info, j);
        extent.start = offset * size;
        extent.end = (offset * size) + length;

        VIR_APPEND_ELEMENT(vol->source.extents, vol->source.nextent, extent);
    }

    return 0;
}


static int
virStorageBackendLogicalMakeVol(char **const groups,
                                void *opaque)
{
    struct virStorageBackendLogicalPoolVolData *data = opaque;
    virStoragePoolObj *pool = data->pool;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageVolDef *vol = NULL;
    bool is_new_vol = false;
    int ret = -1;
    const char *attrs = groups[9];

    /* Skip inactive volume */
    if (attrs[4] != 'a')
        return 0;

    /*
     * Skip thin pools(t). These show up in normal lvs output
     * but do not have a corresponding /dev/$vg/$lv device that
     * is created by udev. This breaks assumptions in later code.
     */
    if (attrs[0] == 't')
        return 0;

    /* See if we're only looking for a specific volume */
    if (data->vol != NULL) {
        vol = data->vol;
        if (STRNEQ(vol->name, groups[0]))
            return 0;
    }

    /* Or filling in more data on an existing volume */
    if (vol == NULL)
        vol = virStorageVolDefFindByName(pool, groups[0]);

    /* Or a completely new volume */
    if (vol == NULL) {
        vol = g_new0(virStorageVolDef, 1);

        is_new_vol = true;
        vol->type = VIR_STORAGE_VOL_BLOCK;

        vol->name = g_strdup(groups[0]);

    }

    if (vol->target.path == NULL)
        vol->target.path = g_strdup_printf("%s/%s", def->target.path, vol->name);

    /* Mark the (s) sparse/snapshot lv, e.g. the lv created using
     * the --virtualsize/-V option. We've already ignored the (t)hin
     * pool definition. In the manner libvirt defines these, the
     * thin pool is hidden to the lvs output, except as the name
     * in brackets [] described for the groups[1] (backingStore).
     */
    if (attrs[0] == 's')
        vol->target.sparse = true;

    /* Skips the backingStore of lv created with "--virtualsize",
     * its original device "/dev/$vgname/$lvname_vorigin" is
     * just for lvm internal use, one should never use it.
     *
     * (lvs outputs "[$lvname_vorigin] for field "origin" if the
     *  lv is created with "--virtualsize").
     */
    if (groups[1] && STRNEQ(groups[1], "") && (groups[1][0] != '[')) {
        vol->target.backingStore = virStorageSourceNew();
        vol->target.backingStore->path = g_strdup_printf("%s/%s",
                                                         def->target.path, groups[1]);

        vol->target.backingStore->format = VIR_STORAGE_POOL_LOGICAL_LVM2;
        vol->target.backingStore->type = VIR_STORAGE_TYPE_BLOCK;
    }

    if (!vol->key)
        vol->key = g_strdup(groups[2]);

    if (virStorageBackendUpdateVolInfo(vol, false,
                                       VIR_STORAGE_VOL_OPEN_DEFAULT, 0) < 0)
        goto cleanup;

    if (virStrToLong_ull(groups[8], NULL, 10, &vol->target.allocation) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume allocation value"));
        goto cleanup;
    }

    if (virStorageBackendLogicalParseVolExtents(vol, groups) < 0)
        goto cleanup;

    if (is_new_vol && virStoragePoolObjAddVol(pool, vol) < 0)
        goto cleanup;
    vol = NULL;

    ret = 0;

 cleanup:
    if (is_new_vol)
        virStorageVolDefFree(vol);
    return ret;
}

#define VIR_STORAGE_VOL_LOGICAL_PREFIX_REGEX "^\\s*"
#define VIR_STORAGE_VOL_LOGICAL_LV_NAME_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_ORIGIN_REGEX "(\\S*)#"
#define VIR_STORAGE_VOL_LOGICAL_UUID_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_DEVICES_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_SEGTYPE_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_STRIPES_REGEX "([0-9]+)#"
#define VIR_STORAGE_VOL_LOGICAL_SEG_SIZE_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_VG_EXTENT_SIZE_REGEX "([0-9]+)#"
#define VIR_STORAGE_VOL_LOGICAL_SIZE_REGEX "([0-9]+)#"
#define VIR_STORAGE_VOL_LOGICAL_LV_ATTR_REGEX "(\\S+)#"
#define VIR_STORAGE_VOL_LOGICAL_SUFFIX_REGEX "?\\s*$"

#define VIR_STORAGE_VOL_LOGICAL_REGEX_COUNT 10
#define VIR_STORAGE_VOL_LOGICAL_REGEX \
           VIR_STORAGE_VOL_LOGICAL_PREFIX_REGEX \
           VIR_STORAGE_VOL_LOGICAL_LV_NAME_REGEX \
           VIR_STORAGE_VOL_LOGICAL_ORIGIN_REGEX \
           VIR_STORAGE_VOL_LOGICAL_UUID_REGEX \
           VIR_STORAGE_VOL_LOGICAL_DEVICES_REGEX \
           VIR_STORAGE_VOL_LOGICAL_SEGTYPE_REGEX \
           VIR_STORAGE_VOL_LOGICAL_STRIPES_REGEX \
           VIR_STORAGE_VOL_LOGICAL_SEG_SIZE_REGEX \
           VIR_STORAGE_VOL_LOGICAL_VG_EXTENT_SIZE_REGEX \
           VIR_STORAGE_VOL_LOGICAL_SIZE_REGEX \
           VIR_STORAGE_VOL_LOGICAL_LV_ATTR_REGEX \
           VIR_STORAGE_VOL_LOGICAL_SUFFIX_REGEX

static int
virStorageBackendLogicalFindLVs(virStoragePoolObj *pool,
                                virStorageVolDef *vol)
{
    /*
     * # lvs --separator # --noheadings --units b --unbuffered --nosuffix --options \
     * "lv_name,origin,uuid,devices,segtype,stripes,seg_size,vg_extent_size,size,lv_attr" VGNAME
     *
     * RootLV##06UgP5-2rhb-w3Bo-3mdR-WeoL-pytO-SAa2ky#/dev/hda2(0)#linear#1#5234491392#33554432#5234491392#-wi-ao
     * SwapLV##oHviCK-8Ik0-paqS-V20c-nkhY-Bm1e-zgzU0M#/dev/hda2(156)#linear#1#1040187392#33554432#1040187392#-wi-ao
     * Test2##3pg3he-mQsA-5Sui-h0i6-HNmc-Cz7W-QSndcR#/dev/hda2(219)#linear#1#1073741824#33554432#1073741824#owi-a-
     * Test3##UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht#/dev/hda2(251)#linear#1#2181038080#33554432#2181038080#-wi-a-
     * Test3#Test2#UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht#/dev/hda2(187)#linear#1#1040187392#33554432#1040187392#swi-a-
     * test_stripes##fSLSZH-zAS2-yAIb-n4mV-Al9u-HA3V-oo9K1B#/dev/sdc1(10240),/dev/sdd1(0)#striped#2#42949672960#4194304#-wi-a-
     *
     * Pull out name, origin, & uuid, device, device extent start #,
     * segment size, extent size, size, attrs
     *
     * NB can be multiple rows per volume if they have many extents
     *
     * NB lvs from some distros (e.g. SLES10 SP2) outputs trailing ","
     * on each line
     *
     * NB Encrypted logical volumes can print ':' in their name, so it is
     *    not a suitable separator (rhbz 470693).
     *
     * NB "devices" field has multiple device paths and "," if the volume is
     *    striped, so "," is not a suitable separator either (rhbz 727474).
     */
    const char *regexes[] = {
        VIR_STORAGE_VOL_LOGICAL_REGEX
    };
    int vars[] = {
        VIR_STORAGE_VOL_LOGICAL_REGEX_COUNT
    };
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    struct virStorageBackendLogicalPoolVolData cbdata = {
        .pool = pool,
        .vol = vol,
    };
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(LVS,
                               "--separator", "#",
                               "--noheadings",
                               "--units", "b",
                               "--unbuffered",
                               "--nosuffix",
                               "--options",
                               "lv_name,origin,uuid,devices,segtype,stripes,seg_size,vg_extent_size,size,lv_attr",
                               def->source.name,
                               NULL);
    return virCommandRunRegex(cmd, 1, regexes, vars,
                              virStorageBackendLogicalMakeVol,
                              &cbdata, "lvs", NULL);
}

static int
virStorageBackendLogicalRefreshPoolFunc(char **const groups,
                                        void *data)
{
    virStoragePoolObj *pool = data;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    if (virStrToLong_ull(groups[0], NULL, 10, &def->capacity) < 0)
        return -1;
    if (virStrToLong_ull(groups[1], NULL, 10, &def->available) < 0)
        return -1;
    def->allocation = def->capacity - def->available;

    return 0;
}


static int
virStorageBackendLogicalFindPoolSourcesFunc(char **const groups,
                                            void *data)
{
    virStoragePoolSourceList *sourceList = data;
    size_t i;
    virStoragePoolSourceDevice *dev;
    virStoragePoolSource *thisSource;
    g_autofree char *pvname = NULL;
    g_autofree char *vgname = NULL;

    pvname = g_strdup(groups[0]);
    vgname = g_strdup(groups[1]);

    thisSource = NULL;
    for (i = 0; i < sourceList->nsources; i++) {
        if (STREQ(sourceList->sources[i].name, vgname)) {
            thisSource = &sourceList->sources[i];
            break;
        }
    }

    if (thisSource == NULL) {
        if (!(thisSource = virStoragePoolSourceListNewSource(sourceList)))
            return -1;

        thisSource->name = g_steal_pointer(&vgname);
    }

    VIR_REALLOC_N(thisSource->devices, thisSource->ndevice + 1);

    dev = &thisSource->devices[thisSource->ndevice];
    thisSource->ndevice++;
    thisSource->format = VIR_STORAGE_POOL_LOGICAL_LVM2;

    memset(dev, 0, sizeof(*dev));
    dev->path = g_steal_pointer(&pvname);

    return 0;
}

/*
 * @sourceList: Pointer to a storage pool source list
 *
 * Use the pvs command to fill the list of pv_name and vg_name associated
 * into the passed sourceList.
 *
 * Returns 0 if successful, -1 and sets error on failure
 */
static int
virStorageBackendLogicalGetPoolSources(virStoragePoolSourceList *sourceList)
{
    /*
     * # pvs --noheadings -o pv_name,vg_name
     *   /dev/sdb
     *   /dev/sdc VolGroup00
     */
    const char *regexes[] = {
        "^\\s*(\\S+)\\s+(\\S+)\\s*$"
    };
    int vars[] = {
        2
    };
    g_autoptr(virCommand) vgcmd = NULL;
    g_autoptr(virCommand) pvcmd = NULL;

    /*
     * NOTE: ignoring errors here; this is just to "touch" any logical volumes
     * that might be hanging around, so if this fails for some reason, the
     * worst that happens is that scanning doesn't pick everything up
     */
    vgcmd = virCommandNew(VGSCAN);
    if (virCommandRun(vgcmd, NULL) < 0)
        VIR_WARN("Failure when running vgscan to refresh physical volumes");

    pvcmd = virCommandNewArgList(PVS,
                                 "--noheadings",
                                 "-o", "pv_name,vg_name",
                                 NULL, NULL);
    return virCommandRunRegex(pvcmd, 1, regexes, vars,
                              virStorageBackendLogicalFindPoolSourcesFunc,
                              sourceList, "pvs", NULL);
}


static char *
virStorageBackendLogicalFindPoolSources(const char *srcSpec G_GNUC_UNUSED,
                                        unsigned int flags)
{
    virStoragePoolSourceList sourceList = { 0 };
    size_t i;
    char *retval = NULL;

    virCheckFlags(0, NULL);

    sourceList.type = VIR_STORAGE_POOL_LOGICAL;

    if (virStorageBackendLogicalGetPoolSources(&sourceList) < 0)
        goto cleanup;

    retval = virStoragePoolSourceListFormat(&sourceList);
    if (retval == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to get source from sourceList"));
        goto cleanup;
    }

 cleanup:
    for (i = 0; i < sourceList.nsources; i++)
        virStoragePoolSourceClear(&sourceList.sources[i]);
    VIR_FREE(sourceList.sources);

    return retval;
}


/*
 * virStorageBackendLogicalMatchPoolSource
 * @pool: Pointer to the source pool object
 *
 * Search the output generated by a 'pvs --noheadings -o pv_name,vg_name'
 * to match the 'vg_name' with the pool def->source.name and for the list
 * of pool def->source.devices[].
 *
 * Returns true if the volume group name matches the pool's source.name
 * and at least one of the pool's def->source.devices[] matches the
 * list of physical device names listed for the pool. Return false if
 * we cannot find a matching volume group name and if we cannot match
 * the any device list members.
 */
static bool
virStorageBackendLogicalMatchPoolSource(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStoragePoolSourceList sourceList = { 0 };
    virStoragePoolSource *thisSource = NULL;
    size_t i, j;
    int matchcount = 0;
    bool ret = false;

    sourceList.type = VIR_STORAGE_POOL_LOGICAL;

    if (virStorageBackendLogicalGetPoolSources(&sourceList) < 0)
        goto cleanup;

    /* Search the pvs output for this pool's source.name */
    for (i = 0; i < sourceList.nsources; i++) {
        thisSource = &sourceList.sources[i];
        if (STREQ(thisSource->name, def->source.name))
            break;
    }

    if (i == sourceList.nsources) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot find logical volume group name '%1$s'"),
                       def->source.name);
        goto cleanup;
    }

    /* If the pool has defined source device(s), then let's make sure
     * they match as well; otherwise, matching can only occur on the
     * pool's name.
     */
   if (!def->source.ndevice) {
        ret = true;
        goto cleanup;
    }

    /* Let's make sure the pool's device(s) match what the pvs output has
     * for volume group devices.
     */
    for (i = 0; i < def->source.ndevice; i++) {
        for (j = 0; j < thisSource->ndevice; j++) {
            if (STREQ(def->source.devices[i].path,
                      thisSource->devices[j].path))
                matchcount++;
        }
    }

    /* If we didn't find any matches, then this pool has listed (a) source
     * device path(s) that don't/doesn't match what was created for the pool
     */
    if (matchcount == 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot find any matching source devices for logical volume group '%1$s'"),
                       def->source.name);
        goto cleanup;
    }

    /* Either there's more devices in the pool source device list or there's
     * more devices in the pvs output. Could easily happen if someone decides
     * to 'add' to or 'remove' from the volume group outside of libvirt's
     * knowledge. Rather than fail on that, provide a warning and move on.
     */
    if (matchcount != def->source.ndevice)
        VIR_WARN("pool device list count doesn't match pvs device list count");

    ret = true;

 cleanup:
    for (i = 0; i < sourceList.nsources; i++)
        virStoragePoolSourceClear(&sourceList.sources[i]);
    VIR_FREE(sourceList.sources);

    return ret;
}


static int
virStorageBackendLogicalCheckPool(virStoragePoolObj *pool,
                                  bool *isActive)
{
    *isActive = virStorageBackendLogicalMatchPoolSource(pool);
    return 0;
}

static int
virStorageBackendLogicalStartPool(virStoragePoolObj *pool)
{
    /* Let's make sure that the pool's name matches the pvs output and
     * that the pool's source devices match the pvs output.
     */
    if (!virStorageBackendLogicalMatchPoolSource(pool) ||
        virStorageBackendLogicalSetActive(pool, true) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendLogicalBuildPool(virStoragePoolObj *pool,
                                  unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    int ret = -1;
    size_t i = 0;
    g_autoptr(virCommand) vgcmd = NULL;

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, ret);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                             VIR_STORAGE_POOL_BUILD_NO_OVERWRITE,
                             cleanup);

    vgcmd = virCommandNewArgList(VGCREATE, def->source.name, NULL);

    for (i = 0; i < def->source.ndevice; i++) {
        const char *path = def->source.devices[i].path;

        /* The blkid FS and Part probing code doesn't know "lvm2" (this
         * pool's only format type), but it does know "LVM2_member", so
         * we'll pass that here */
        if (!(flags & VIR_STORAGE_POOL_BUILD_OVERWRITE) &&
            !virStorageBackendDeviceIsEmpty(path, "LVM2_member", true))
            goto cleanup;

        if (virStorageBackendLogicalInitializeDevice(path) < 0)
            goto cleanup;

        virCommandAddArg(vgcmd, path);
    }

    virObjectUnlock(pool);
    /* Now create the volume group itself */
    ret = virCommandRun(vgcmd, NULL);
    virObjectLock(pool);

 cleanup:
    /* On any failure, run through the devices that had pvcreate run in
     * in order to run pvremove on the device; otherwise, subsequent build
     * will fail if a pvcreate had been run already. */
    if (ret < 0) {
        size_t j;
        for (j = 0; j < i; j++)
            virStorageBackendLogicalRemoveDevice(def->source.devices[j].path);
    }
    return ret;
}


static int
virStorageBackendLogicalRefreshPool(virStoragePoolObj *pool)
{
    /*
     *  # vgs --separator : --noheadings --units b --unbuffered --nosuffix --options "vg_size,vg_free" VGNAME
     *    10603200512:4328521728
     *
     * Pull out size & free
     *
     * NB vgs from some distros (e.g. SLES10 SP2) outputs trailing ":" on each line
     */
    const char *regexes[] = {
        "^\\s*(\\S+):([0-9]+):?\\s*$"
    };
    int vars[] = {
        2
    };
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virCommand) cmd = NULL;

    virWaitForDevices();

    /* Get list of all logical volumes */
    if (virStorageBackendLogicalFindLVs(pool, NULL) < 0)
        return -1;

    cmd = virCommandNewArgList(VGS,
                               "--separator", ":",
                               "--noheadings",
                               "--units", "b",
                               "--unbuffered",
                               "--nosuffix",
                               "--options", "vg_size,vg_free",
                               def->source.name,
                               NULL);

    /* Now get basic volgrp metadata */
    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virStorageBackendLogicalRefreshPoolFunc,
                           pool,
                           "vgs",
                           NULL) < 0)
        return -1;

    return 0;
}

/*
 * This is actually relatively safe; if you happen to try to "stop" the
 * pool that your / is on, for instance, you will get failure like:
 * "Can't deactivate volume group "VolGroup00" with 3 open logical volume(s)"
 */
static int
virStorageBackendLogicalStopPool(virStoragePoolObj *pool)
{
    if (virStorageBackendLogicalSetActive(pool, false) < 0)
        return -1;

    return 0;
}

static int
virStorageBackendLogicalDeletePool(virStoragePoolObj *pool,
                                   unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    size_t i;
    g_autoptr(virCommand) cmd = NULL;

    virCheckFlags(0, -1);

    /* first remove the volume group */
    cmd = virCommandNewArgList(VGREMOVE,
                               "-f", def->source.name,
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    /* now remove the pv devices and clear them out */
    for (i = 0; i < def->source.ndevice; i++)
        virStorageBackendLogicalRemoveDevice(def->source.devices[i].path);

    return 0;
}


static int
virStorageBackendLogicalDeleteVol(virStoragePoolObj *pool G_GNUC_UNUSED,
                                  virStorageVolDef *vol,
                                  unsigned int flags)
{
    g_autoptr(virCommand) lvchange_cmd = NULL;
    g_autoptr(virCommand) lvremove_cmd = NULL;

    virCheckFlags(0, -1);

    virWaitForDevices();

    lvchange_cmd = virCommandNewArgList(LVCHANGE, "-aln", vol->target.path, NULL);
    lvremove_cmd = virCommandNewArgList(LVREMOVE, "-f", vol->target.path, NULL);

    if (virCommandRun(lvremove_cmd, NULL) < 0) {
        if (virCommandRun(lvchange_cmd, NULL) < 0) {
            return -1;
        } else {
            if (virCommandRun(lvremove_cmd, NULL) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virStorageBackendLogicalLVCreate(virStorageVolDef *vol,
                                 virStoragePoolDef *def)
{
    unsigned long long capacity = vol->target.capacity;
    g_autoptr(virCommand) cmd = NULL;

    if (vol->target.encryption &&
        vol->target.encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool only supports LUKS encrypted volumes"));
        return -1;
    }

    cmd = virCommandNewArgList(LVCREATE,
                               "--name", vol->name,
                               NULL);
    virCommandAddArg(cmd, "-L");
    if (capacity != vol->target.allocation) {
        virCommandAddArgFormat(cmd, "%lluK",
                               VIR_DIV_UP(vol->target.allocation
                                          ? vol->target.allocation : 1, 1024));
        virCommandAddArgList(cmd, "--type", "snapshot", NULL);
        virCommandAddArg(cmd, "--virtualsize");
        vol->target.sparse = true;
    }

    /* If we're going to encrypt using LUKS, then we could need up to
     * an extra 2MB for the LUKS header - so account for that now */
    if (vol->target.encryption)
        capacity += 2 * 1024 * 1024;
    virCommandAddArgFormat(cmd, "%lluK", VIR_DIV_UP(capacity, 1024));

    if (virStorageSourceHasBacking(&vol->target))
        virCommandAddArgList(cmd, "-s", vol->target.backingStore->path, NULL);
    else
        virCommandAddArg(cmd, def->source.name);

    virCommandAddArg(cmd, "--yes");

    return virCommandRun(cmd, NULL);
}


static int
virStorageBackendLogicalCreateVol(virStoragePoolObj *pool,
                                  virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virErrorPtr err;
    struct stat sb;
    VIR_AUTOCLOSE fd = -1;

    vol->type = VIR_STORAGE_VOL_BLOCK;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->target.path, vol->name);

    if (virStorageBackendLogicalLVCreate(vol, def) < 0)
        return -1;

    if (vol->target.encryption &&
        virStorageBackendCreateVolUsingQemuImg(pool, vol, NULL, 0) < 0)
        goto error;

    if ((fd = virStorageBackendVolOpen(vol->target.path, &sb,
                                       VIR_STORAGE_VOL_OPEN_DEFAULT)) < 0)
        goto error;

    /* We can only chown/grp if root */
    if (geteuid() == 0) {
        if (fchown(fd, vol->target.perms->uid, vol->target.perms->gid) < 0) {
            virReportSystemError(errno,
                                 _("cannot set file owner '%1$s'"),
                                 vol->target.path);
            goto error;
        }
    }
    if (fchmod(fd, (vol->target.perms->mode == (mode_t)-1 ?
                    VIR_STORAGE_DEFAULT_VOL_PERM_MODE :
                    vol->target.perms->mode)) < 0) {
        virReportSystemError(errno,
                             _("cannot set file mode '%1$s'"),
                             vol->target.path);
        goto error;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%1$s'"),
                             vol->target.path);
        goto error;
    }

    /* Fill in data about this new vol */
    if (virStorageBackendLogicalFindLVs(pool, vol) < 0) {
        virReportSystemError(errno,
                             _("cannot find newly created volume '%1$s'"),
                             vol->target.path);
        goto error;
    }

    return 0;

 error:
    virErrorPreserveLast(&err);
    virStorageBackendLogicalDeleteVol(pool, vol, 0);
    virErrorRestore(&err);
    return -1;
}

static int
virStorageBackendLogicalBuildVolFrom(virStoragePoolObj *pool,
                                     virStorageVolDef *vol,
                                     virStorageVolDef *inputvol,
                                     unsigned int flags)
{
    virStorageBackendBuildVolFrom build_func;

    build_func = virStorageBackendGetBuildVolFromFunction(vol, inputvol);
    if (!build_func)
        return -1;

    return build_func(pool, vol, inputvol, flags);
}

static int
virStorageBackendLogicalVolWipe(virStoragePoolObj *pool,
                                virStorageVolDef *vol,
                                unsigned int algorithm,
                                unsigned int flags)
{
    if (!vol->target.sparse)
        return virStorageBackendVolWipeLocal(pool, vol, algorithm, flags);

    /* The wiping algorithms will write something to the logical volume.
     * Writing to a sparse logical volume causes it to be filled resulting
     * in the volume becoming INACTIVE because there is some amount of
     * metadata contained within the sparse lv. Choosing to only write
     * a wipe pattern to the already written portion lv based on what
     * 'lvs' shows in the "Data%" column/field for the sparse lv was
     * considered. However, there is no guarantee that sparse lv could
     * grow or shrink outside of libvirt's knowledge and thus still render
     * the volume INACTIVE. Until there is some sort of wipe function
     * implemented by lvm for one of these sparse lv, we'll just return
     * unsupported.
     */
    virReportError(VIR_ERR_NO_SUPPORT,
                   _("logical volume '%1$s' is sparse, volume wipe not supported"),
                   vol->target.path);
    return -1;
}

virStorageBackend virStorageBackendLogical = {
    .type = VIR_STORAGE_POOL_LOGICAL,

    .findPoolSources = virStorageBackendLogicalFindPoolSources,
    .checkPool = virStorageBackendLogicalCheckPool,
    .startPool = virStorageBackendLogicalStartPool,
    .buildPool = virStorageBackendLogicalBuildPool,
    .refreshPool = virStorageBackendLogicalRefreshPool,
    .stopPool = virStorageBackendLogicalStopPool,
    .deletePool = virStorageBackendLogicalDeletePool,
    .buildVol = NULL,
    .buildVolFrom = virStorageBackendLogicalBuildVolFrom,
    .createVol = virStorageBackendLogicalCreateVol,
    .deleteVol = virStorageBackendLogicalDeleteVol,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendLogicalVolWipe,
};


int
virStorageBackendLogicalRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendLogical);
}
