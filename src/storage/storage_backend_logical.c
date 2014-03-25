/*
 * storage_backend_logical.c: storage backend for logical volume handling
 *
 * Copyright (C) 2007-2009, 2011, 2013 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <regex.h>
#include <string.h>
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

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_logical");

#define PV_BLANK_SECTOR_SIZE 512


static int
virStorageBackendLogicalSetActive(virStoragePoolObjPtr pool,
                                  int on)
{
    int ret;
    virCommandPtr cmd =
        virCommandNewArgList(VGCHANGE,
                             on ? "-aly" : "-aln",
                             pool->def->source.name,
                             NULL);

    ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    return ret;
}


#define VIR_STORAGE_VOL_LOGICAL_SEGTYPE_STRIPED "striped"

struct virStorageBackendLogicalPoolVolData {
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
};

static int
virStorageBackendLogicalMakeVol(char **const groups,
                                void *opaque)
{
    struct virStorageBackendLogicalPoolVolData *data = opaque;
    virStoragePoolObjPtr pool = data->pool;
    virStorageVolDefPtr vol = NULL;
    bool is_new_vol = false;
    unsigned long long offset, size, length;
    const char *regex_unit = "(\\S+)\\((\\S+)\\)";
    char *regex = NULL;
    regex_t *reg = NULL;
    regmatch_t *vars = NULL;
    char *p = NULL;
    size_t i;
    int err, nextents, nvars, ret = -1;
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
        if (VIR_ALLOC(vol) < 0)
            return -1;

        is_new_vol = true;
        vol->type = VIR_STORAGE_VOL_BLOCK;

        if (VIR_STRDUP(vol->name, groups[0]) < 0)
            goto cleanup;

    }

    if (vol->target.path == NULL) {
        if (virAsprintf(&vol->target.path, "%s/%s",
                        pool->def->target.path, vol->name) < 0)
            goto cleanup;
    }

    /* Skips the backingStore of lv created with "--virtualsize",
     * its original device "/dev/$vgname/$lvname_vorigin" is
     * just for lvm internal use, one should never use it.
     *
     * (lvs outputs "[$lvname_vorigin] for field "origin" if the
     *  lv is created with "--virtualsize").
     */
    if (groups[1] && !STREQ(groups[1], "") && (groups[1][0] != '[')) {
        if (virAsprintf(&vol->backingStore.path, "%s/%s",
                        pool->def->target.path, groups[1]) < 0)
            goto cleanup;

        vol->backingStore.format = VIR_STORAGE_POOL_LOGICAL_LVM2;
    }

    if (!vol->key && VIR_STRDUP(vol->key, groups[2]) < 0)
        goto cleanup;

    if (virStorageBackendUpdateVolInfo(vol, 1) < 0)
        goto cleanup;

    nextents = 1;
    if (STREQ(groups[4], VIR_STORAGE_VOL_LOGICAL_SEGTYPE_STRIPED)) {
        if (virStrToLong_i(groups[5], NULL, 10, &nextents) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("malformed volume extent stripes value"));
            goto cleanup;
        }
    }

    /* Finally fill in extents information */
    if (VIR_REALLOC_N(vol->source.extents,
                      vol->source.nextent + nextents) < 0)
        goto cleanup;

    if (virStrToLong_ull(groups[6], NULL, 10, &length) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume extent length value"));
        goto cleanup;
    }
    if (virStrToLong_ull(groups[7], NULL, 10, &size) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume extent size value"));
        goto cleanup;
    }
    if (virStrToLong_ull(groups[8], NULL, 10, &vol->allocation) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volume allocation value"));
        goto cleanup;
    }

    /* Now parse the "devices" field separately */
    if (VIR_STRDUP(regex, regex_unit) < 0)
        goto cleanup;

    for (i = 1; i < nextents; i++) {
        if (VIR_REALLOC_N(regex, strlen(regex) + strlen(regex_unit) + 2) < 0)
            goto cleanup;
        /* "," is the separator of "devices" field */
        strcat(regex, ",");
        strncat(regex, regex_unit, strlen(regex_unit));
    }

    if (VIR_ALLOC(reg) < 0)
        goto cleanup;

    /* Each extent has a "path:offset" pair, and vars[0] will
     * be the whole matched string.
     */
    nvars = (nextents * 2) + 1;
    if (VIR_ALLOC_N(vars, nvars) < 0)
        goto cleanup;

    err = regcomp(reg, regex, REG_EXTENDED);
    if (err != 0) {
        char error[100];
        regerror(err, reg, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %s"),
                       error);
        goto cleanup;
    }

    err = regexec(reg, groups[3], nvars, vars, 0);
    regfree(reg);
    if (err != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed volume extent devices value"));
        goto cleanup;
    }

    p = groups[3];

    /* vars[0] is skipped */
    for (i = 0; i < nextents; i++) {
        size_t j;
        int len;
        char *offset_str = NULL;

        j = (i * 2) + 1;
        len = vars[j].rm_eo - vars[j].rm_so;
        p[vars[j].rm_eo] = '\0';

        if (VIR_STRNDUP(vol->source.extents[vol->source.nextent].path,
                        p + vars[j].rm_so, len) < 0)
            goto cleanup;

        len = vars[j + 1].rm_eo - vars[j + 1].rm_so;
        if (VIR_STRNDUP(offset_str, p + vars[j + 1].rm_so, len) < 0)
            goto cleanup;

        if (virStrToLong_ull(offset_str, NULL, 10, &offset) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("malformed volume extent offset value"));
            VIR_FREE(offset_str);
            goto cleanup;
        }

        VIR_FREE(offset_str);

        vol->source.extents[vol->source.nextent].start = offset * size;
        vol->source.extents[vol->source.nextent].end = (offset * size) + length;
        vol->source.nextent++;
    }

    if (is_new_vol &&
        VIR_APPEND_ELEMENT(pool->volumes.objs, pool->volumes.count, vol) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(regex);
    VIR_FREE(reg);
    VIR_FREE(vars);
    if (is_new_vol && (ret == -1))
        virStorageVolDefFree(vol);
    return ret;
}

static int
virStorageBackendLogicalFindLVs(virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol)
{
    /*
     * # lvs --separator , --noheadings --units b --unbuffered --nosuffix --options \
     * "lv_name,origin,uuid,devices,seg_size,vg_extent_size,size,lv_attr" VGNAME
     *
     * RootLV,,06UgP5-2rhb-w3Bo-3mdR-WeoL-pytO-SAa2ky,/dev/hda2(0),5234491392,33554432,5234491392,-wi-ao
     * SwapLV,,oHviCK-8Ik0-paqS-V20c-nkhY-Bm1e-zgzU0M,/dev/hda2(156),1040187392,33554432,1040187392,-wi-ao
     * Test2,,3pg3he-mQsA-5Sui-h0i6-HNmc-Cz7W-QSndcR,/dev/hda2(219),1073741824,33554432,1073741824,owi-a-
     * Test3,,UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht,/dev/hda2(251),2181038080,33554432,2181038080,-wi-a-
     * Test3,Test2,UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht,/dev/hda2(187),1040187392,33554432,1040187392,swi-a-
     *
     * Pull out name, origin, & uuid, device, device extent start #,
     * segment size, extent size, size, attrs
     *
     * NB can be multiple rows per volume if they have many extents
     *
     * NB lvs from some distros (e.g. SLES10 SP2) outputs trailing "," on each line
     *
     * NB Encrypted logical volumes can print ':' in their name, so it is
     *    not a suitable separator (rhbz 470693).
     * NB "devices" field has multiple device paths and "," if the volume is
     *    striped, so "," is not a suitable separator either (rhbz 727474).
     */
    const char *regexes[] = {
       "^\\s*(\\S+)#(\\S*)#(\\S+)#(\\S+)#(\\S+)#([0-9]+)#(\\S+)#([0-9]+)#([0-9]+)#(\\S+)#?\\s*$"
    };
    int vars[] = {
        10
    };
    int ret = -1;
    virCommandPtr cmd;
    struct virStorageBackendLogicalPoolVolData cbdata = {
        .pool = pool,
        .vol = vol,
    };

    cmd = virCommandNewArgList(LVS,
                               "--separator", "#",
                               "--noheadings",
                               "--units", "b",
                               "--unbuffered",
                               "--nosuffix",
                               "--options",
                               "lv_name,origin,uuid,devices,segtype,stripes,seg_size,vg_extent_size,size,lv_attr",
                               pool->def->source.name,
                               NULL);
    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virStorageBackendLogicalMakeVol,
                           &cbdata,
                           "lvs") < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}

static int
virStorageBackendLogicalRefreshPoolFunc(char **const groups,
                                        void *data)
{
    virStoragePoolObjPtr pool = data;
    if (virStrToLong_ull(groups[0], NULL, 10, &pool->def->capacity) < 0)
        return -1;
    if (virStrToLong_ull(groups[1], NULL, 10, &pool->def->available) < 0)
        return -1;
    pool->def->allocation = pool->def->capacity - pool->def->available;

    return 0;
}


static int
virStorageBackendLogicalFindPoolSourcesFunc(char **const groups,
                                            void *data)
{
    virStoragePoolSourceListPtr sourceList = data;
    char *pvname = NULL;
    char *vgname = NULL;
    size_t i;
    virStoragePoolSourceDevicePtr dev;
    virStoragePoolSource *thisSource;

    if (VIR_STRDUP(pvname, groups[0]) < 0 ||
        VIR_STRDUP(vgname, groups[1]) < 0)
        goto error;

    thisSource = NULL;
    for (i = 0; i < sourceList->nsources; i++) {
        if (STREQ(sourceList->sources[i].name, vgname)) {
            thisSource = &sourceList->sources[i];
            break;
        }
    }

    if (thisSource == NULL) {
        if (!(thisSource = virStoragePoolSourceListNewSource(sourceList)))
            goto error;

        thisSource->name = vgname;
    }
    else
        VIR_FREE(vgname);

    if (VIR_REALLOC_N(thisSource->devices, thisSource->ndevice + 1) != 0)
        goto error;

    dev = &thisSource->devices[thisSource->ndevice];
    thisSource->ndevice++;
    thisSource->format = VIR_STORAGE_POOL_LOGICAL_LVM2;

    memset(dev, 0, sizeof(*dev));
    dev->path = pvname;

    return 0;

 error:
    VIR_FREE(pvname);
    VIR_FREE(vgname);

    return -1;
}

static char *
virStorageBackendLogicalFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        const char *srcSpec ATTRIBUTE_UNUSED,
                                        unsigned int flags)
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
    virCommandPtr cmd;
    char *retval = NULL;
    virStoragePoolSourceList sourceList;
    size_t i;

    virCheckFlags(0, NULL);

    /*
     * NOTE: ignoring errors here; this is just to "touch" any logical volumes
     * that might be hanging around, so if this fails for some reason, the
     * worst that happens is that scanning doesn't pick everything up
     */
    cmd = virCommandNew(VGSCAN);
    if (virCommandRun(cmd, NULL) < 0)
        VIR_WARN("Failure when running vgscan to refresh physical volumes");
    virCommandFree(cmd);

    memset(&sourceList, 0, sizeof(sourceList));
    sourceList.type = VIR_STORAGE_POOL_LOGICAL;

    cmd = virCommandNewArgList(PVS,
                               "--noheadings",
                               "-o", "pv_name,vg_name",
                               NULL);
    if (virCommandRunRegex(cmd, 1, regexes, vars,
                           virStorageBackendLogicalFindPoolSourcesFunc,
                           &sourceList, "pvs") < 0) {
        virCommandFree(cmd);
        return NULL;
    }
    virCommandFree(cmd);

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


static int
virStorageBackendLogicalCheckPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  bool *isActive)
{
    *isActive = virFileExists(pool->def->target.path);
    return 0;
}

static int
virStorageBackendLogicalStartPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool)
{
    if (virStorageBackendLogicalSetActive(pool, 1) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendLogicalBuildPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  unsigned int flags)
{
    virCommandPtr vgcmd;
    int fd;
    char zeros[PV_BLANK_SECTOR_SIZE];
    int ret = -1;
    size_t i;

    virCheckFlags(0, -1);

    memset(zeros, 0, sizeof(zeros));

    vgcmd = virCommandNewArgList(VGCREATE, pool->def->source.name, NULL);

    for (i = 0; i < pool->def->source.ndevice; i++) {
        virCommandPtr pvcmd;
        /*
         * LVM requires that the first sector is blanked if using
         * a whole disk as a PV. So we just blank them out regardless
         * rather than trying to figure out if we're a disk or partition
         */
        if ((fd = open(pool->def->source.devices[i].path, O_WRONLY)) < 0) {
            virReportSystemError(errno,
                                 _("cannot open device '%s'"),
                                 pool->def->source.devices[i].path);
            goto cleanup;
        }
        if (safewrite(fd, zeros, sizeof(zeros)) < 0) {
            virReportSystemError(errno,
                                 _("cannot clear device header of '%s'"),
                                 pool->def->source.devices[i].path);
            VIR_FORCE_CLOSE(fd);
            goto cleanup;
        }
        if (fsync(fd) < 0) {
            virReportSystemError(errno,
                                 _("cannot flush header of device'%s'"),
                                 pool->def->source.devices[i].path);
            VIR_FORCE_CLOSE(fd);
            goto cleanup;
        }
        if (VIR_CLOSE(fd) < 0) {
            virReportSystemError(errno,
                                 _("cannot close device '%s'"),
                                 pool->def->source.devices[i].path);
            goto cleanup;
        }

        /*
         * Initialize the physical volume because vgcreate is not
         * clever enough todo this for us :-(
         */
        pvcmd = virCommandNewArgList(PVCREATE,
                                     pool->def->source.devices[i].path,
                                     NULL);
        if (virCommandRun(pvcmd, NULL) < 0) {
            virCommandFree(pvcmd);
            goto cleanup;
        }
        virCommandFree(pvcmd);

        virCommandAddArg(vgcmd, pool->def->source.devices[i].path);
    }

    /* Now create the volume group itself */
    if (virCommandRun(vgcmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(vgcmd);
    return ret;
}


static int
virStorageBackendLogicalRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virStoragePoolObjPtr pool)
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
    virCommandPtr cmd = NULL;
    int ret = -1;

    virFileWaitForDevices();

    /* Get list of all logical volumes */
    if (virStorageBackendLogicalFindLVs(pool, NULL) < 0)
        goto cleanup;

    cmd = virCommandNewArgList(VGS,
                               "--separator", ":",
                               "--noheadings",
                               "--units", "b",
                               "--unbuffered",
                               "--nosuffix",
                               "--options", "vg_size,vg_free",
                               pool->def->source.name,
                               NULL);

    /* Now get basic volgrp metadata */
    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virStorageBackendLogicalRefreshPoolFunc,
                           pool,
                           "vgs") < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (ret < 0)
        virStoragePoolObjClearVols(pool);
    return ret;
}

/*
 * This is actually relatively safe; if you happen to try to "stop" the
 * pool that your / is on, for instance, you will get failure like:
 * "Can't deactivate volume group "VolGroup00" with 3 open logical volume(s)"
 */
static int
virStorageBackendLogicalStopPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    if (virStorageBackendLogicalSetActive(pool, 0) < 0)
        return -1;

    return 0;
}

static int
virStorageBackendLogicalDeletePool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virStoragePoolObjPtr pool,
                                   unsigned int flags)
{
    virCommandPtr cmd = NULL;
    size_t i;
    int ret = -1;

    virCheckFlags(0, -1);

    /* first remove the volume group */
    cmd = virCommandNewArgList(VGREMOVE,
                               "-f", pool->def->source.name,
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;
    virCommandFree(cmd);
    cmd = NULL;

    /* now remove the pv devices and clear them out */
    ret = 0;
    for (i = 0; i < pool->def->source.ndevice; i++) {
        cmd = virCommandNewArgList(PVREMOVE,
                                   pool->def->source.devices[i].path,
                                   NULL);
        if (virCommandRun(cmd, NULL) < 0) {
            ret = -1;
            break;
        }
        virCommandFree(cmd);
        cmd = NULL;
    }

 cleanup:
    virCommandFree(cmd);
    return ret;
}


static int
virStorageBackendLogicalDeleteVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                  virStorageVolDefPtr vol,
                                  unsigned int flags)
{
    int ret = -1;

    virCommandPtr lvchange_cmd = NULL;
    virCommandPtr lvremove_cmd = NULL;

    virCheckFlags(0, -1);

    virFileWaitForDevices();

    lvchange_cmd = virCommandNewArgList(LVCHANGE, "-aln", vol->target.path, NULL);
    lvremove_cmd = virCommandNewArgList(LVREMOVE, "-f", vol->target.path, NULL);

    if (virCommandRun(lvremove_cmd, NULL) < 0) {
        if (virCommandRun(lvchange_cmd, NULL) < 0) {
            goto cleanup;
        } else {
            if (virCommandRun(lvremove_cmd, NULL) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virCommandFree(lvchange_cmd);
    virCommandFree(lvremove_cmd);
    return ret;
}


static int
virStorageBackendLogicalCreateVol(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol)
{
    int fd = -1;
    virCommandPtr cmd = NULL;
    virErrorPtr err;

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("storage pool does not support encrypted "
                               "volumes"));
        return -1;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    if (vol->target.path != NULL) {
        /* A target path passed to CreateVol has no meaning */
        VIR_FREE(vol->target.path);
    }

    if (virAsprintf(&vol->target.path, "%s/%s",
                    pool->def->target.path,
                    vol->name) == -1)
        return -1;

    cmd = virCommandNewArgList(LVCREATE,
                               "--name", vol->name,
                               NULL);
    virCommandAddArg(cmd, "-L");
    if (vol->capacity != vol->allocation) {
        virCommandAddArgFormat(cmd, "%lluK",
                VIR_DIV_UP(vol->allocation ? vol->allocation : 1, 1024));
        virCommandAddArg(cmd, "--virtualsize");
    }
    virCommandAddArgFormat(cmd, "%lluK", VIR_DIV_UP(vol->capacity, 1024));
    if (vol->backingStore.path)
        virCommandAddArgList(cmd, "-s", vol->backingStore.path, NULL);
    else
        virCommandAddArg(cmd, pool->def->source.name);

    if (virCommandRun(cmd, NULL) < 0)
        goto error;

    virCommandFree(cmd);
    cmd = NULL;

    if ((fd = virStorageBackendVolOpen(vol->target.path)) < 0)
        goto error;

    /* We can only chown/grp if root */
    if (geteuid() == 0) {
        if (fchown(fd, vol->target.perms.uid, vol->target.perms.gid) < 0) {
            virReportSystemError(errno,
                                 _("cannot set file owner '%s'"),
                                 vol->target.path);
            goto error;
        }
    }
    if (fchmod(fd, vol->target.perms.mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set file mode '%s'"),
                             vol->target.path);
        goto error;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot close file '%s'"),
                             vol->target.path);
        goto error;
    }

    /* Fill in data about this new vol */
    if (virStorageBackendLogicalFindLVs(pool, vol) < 0) {
        virReportSystemError(errno,
                             _("cannot find newly created volume '%s'"),
                             vol->target.path);
        goto error;
    }

    return 0;

 error:
    err = virSaveLastError();
    VIR_FORCE_CLOSE(fd);
    virStorageBackendLogicalDeleteVol(conn, pool, vol, 0);
    virCommandFree(cmd);
    virSetError(err);
    virFreeError(err);
    return -1;
}

static int
virStorageBackendLogicalBuildVolFrom(virConnectPtr conn,
                                     virStoragePoolObjPtr pool,
                                     virStorageVolDefPtr vol,
                                     virStorageVolDefPtr inputvol,
                                     unsigned int flags)
{
    virStorageBackendBuildVolFrom build_func;

    build_func = virStorageBackendGetBuildVolFromFunction(vol, inputvol);
    if (!build_func)
        return -1;

    return build_func(conn, pool, vol, inputvol, flags);
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
};
