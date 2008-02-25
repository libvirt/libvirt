/*
 * storage_backend_logvol.c: storage backend for logical volume handling
 *
 * Copyright (C) 2007-2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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

#include "storage_backend_logical.h"
#include "storage_conf.h"
#include "util.h"


#define PV_BLANK_SECTOR_SIZE 512

enum {
    VIR_STORAGE_POOL_LOGICAL_LVM2 = 0,
};


static int
virStorageBackendLogicalPoolFormatFromString(virConnectPtr conn,
                                             const char *format) {
    if (format == NULL)
        return VIR_STORAGE_POOL_LOGICAL_LVM2;

    if (STREQ(format, "lvm2"))
        return VIR_STORAGE_POOL_LOGICAL_LVM2;

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported pool format %s"), format);
    return -1;
}

static const char *
virStorageBackendLogicalPoolFormatToString(virConnectPtr conn,
                                           int format) {
    switch (format) {
    case VIR_STORAGE_POOL_LOGICAL_LVM2:
        return "lvm2";
    }

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported pool format %d"), format);
    return NULL;
}

static int
virStorageBackendLogicalSetActive(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  int on)
{
    const char *cmdargv[4];

    cmdargv[0] = VGCHANGE;
    cmdargv[1] = on ? "-ay" : "-an";
    cmdargv[2] = pool->def->name;
    cmdargv[3] = NULL;

    if (virRun(conn, (char**)cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendLogicalMakeVol(virConnectPtr conn,
                                virStoragePoolObjPtr pool,
                                char **const groups,
                                void *data)
{
    virStorageVolDefPtr vol = NULL;
    virStorageVolSourceExtentPtr tmp;
    unsigned long long offset, size, length;

    /* See if we're only looking for a specific volume */
    if (data != NULL) {
        vol = data;
        if (STRNEQ(vol->name, groups[0]))
            return 0;
    }

    /* Or filling in more data on an existing volume */
    if (vol == NULL)
        vol = virStorageVolDefFindByName(pool, groups[0]);

    /* Or a completely new volume */
    if (vol == NULL) {
        if ((vol = calloc(1, sizeof(*vol))) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
            return -1;
        }

        if ((vol->name = strdup(groups[0])) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
            return -1;
        }

        vol->next = pool->volumes;
        pool->volumes = vol;
        pool->nvolumes++;
    }

    if (vol->target.path == NULL) {
        if ((vol->target.path = malloc(strlen(pool->def->target.path) +
                                       1 + strlen(vol->name) + 1)) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
            return -1;
        }
        strcpy(vol->target.path, pool->def->target.path);
        strcat(vol->target.path, "/");
        strcat(vol->target.path, vol->name);
    }

    if (vol->key == NULL &&
        (vol->key = strdup(groups[1])) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
        return -1;
    }

    if (virStorageBackendUpdateVolInfo(conn, vol, 1) < 0)
        return -1;


    /* Finally fill in extents information */
    if ((tmp = realloc(vol->source.extents, sizeof(*tmp)
                       * (vol->source.nextent + 1))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("extents"));
        return -1;
    }
    vol->source.extents = tmp;

    if ((vol->source.extents[vol->source.nextent].path =
         strdup(groups[2])) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("extents"));
        return -1;
    }

    if (virStrToLong_ull(groups[3], NULL, 10, &offset) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("malformed volume extent offset value"));
        return -1;
    }
    if (virStrToLong_ull(groups[4], NULL, 10, &length) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("malformed volume extent length value"));
        return -1;
    }
    if (virStrToLong_ull(groups[5], NULL, 10, &size) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("malformed volume extent size value"));
        return -1;
    }

    vol->source.extents[vol->source.nextent].start = offset * size;
    vol->source.extents[vol->source.nextent].end = (offset * size) + length;
    vol->source.nextent++;

    return 0;
}

static int
virStorageBackendLogicalFindLVs(virConnectPtr conn,
                                virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol)
{
    /*
     *  # lvs --separator : --noheadings --units b --unbuffered --nosuffix --options "lv_name,uuid,devices,seg_size,vg_extent_size" VGNAME
     *  RootLV:06UgP5-2rhb-w3Bo-3mdR-WeoL-pytO-SAa2ky:/dev/hda2(0):5234491392:33554432
     *  SwapLV:oHviCK-8Ik0-paqS-V20c-nkhY-Bm1e-zgzU0M:/dev/hda2(156):1040187392:33554432
     *  Test2:3pg3he-mQsA-5Sui-h0i6-HNmc-Cz7W-QSndcR:/dev/hda2(219):1073741824:33554432
     *  Test3:UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht:/dev/hda2(251):2181038080:33554432
     *  Test3:UB5hFw-kmlm-LSoX-EI1t-ioVd-h7GL-M0W8Ht:/dev/hda2(187):1040187392:33554432
     *
     * Pull out name & uuid, device, device extent start #, segment size, extent size.
     *
     * NB can be multiple rows per volume if they have many extents
     */
    const char *regexes[] = {
        "^\\s*(\\S+):(\\S+):(\\S+)\\((\\S+)\\):(\\S+):(\\S+)\\s*$"
    };
    int vars[] = {
        6
    };
    const char *prog[] = {
        LVS, "--separator", ":", "--noheadings", "--units", "b",
        "--unbuffered", "--nosuffix", "--options",
        "lv_name,uuid,devices,seg_size,vg_extent_size",
        pool->def->name, NULL
    };

    return virStorageBackendRunProgRegex(conn,
                                         pool,
                                         prog,
                                         1,
                                         regexes,
                                         vars,
                                         virStorageBackendLogicalMakeVol,
                                         vol);
}

static int
virStorageBackendLogicalRefreshPoolFunc(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                        char **const groups,
                                        void *data ATTRIBUTE_UNUSED)
{
    if (virStrToLong_ull(groups[0], NULL, 10, &pool->def->capacity) < 0)
        return -1;
    if (virStrToLong_ull(groups[1], NULL, 10, &pool->def->available) < 0)
        return -1;
    pool->def->allocation = pool->def->capacity - pool->def->available;

    return 0;
}


static int
virStorageBackendLogicalStartPool(virConnectPtr conn,
                                  virStoragePoolObjPtr pool)
{
    if (virStorageBackendLogicalSetActive(conn, pool, 1) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendLogicalBuildPool(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  unsigned int flags ATTRIBUTE_UNUSED)
{
    const char **vgargv;
    const char *pvargv[3];
    int n = 0, i, fd;
    char zeros[PV_BLANK_SECTOR_SIZE];

    memset(zeros, 0, sizeof(zeros));

    /* XXX multiple pvs */
    if ((vgargv = malloc(sizeof(char*) * (1))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("command line"));
        return -1;
    }

    vgargv[n++] = VGCREATE;
    vgargv[n++] = pool->def->name;

    pvargv[0] = PVCREATE;
    pvargv[2] = NULL;
    for (i = 0 ; i < pool->def->source.ndevice ; i++) {
        /*
         * LVM requires that the first sector is blanked if using
         * a whole disk as a PV. So we just blank them out regardless
         * rather than trying to figure out if we're a disk or partition
         */
        if ((fd = open(pool->def->source.devices[i].path, O_WRONLY)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot open device %s"),
                                  strerror(errno));
            goto cleanup;
        }
        if (safewrite(fd, zeros, sizeof(zeros)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot clear device header %s"),
                                  strerror(errno));
            close(fd);
            goto cleanup;
        }
        if (close(fd) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot close device %s"),
                                  strerror(errno));
            goto cleanup;
        }

        /*
         * Initialize the physical volume because vgcreate is not
         * clever enough todo this for us :-(
         */
        vgargv[n++] = pool->def->source.devices[i].path;
        pvargv[1] = pool->def->source.devices[i].path;
        if (virRun(conn, (char**)pvargv, NULL) < 0)
            goto cleanup;
    }

    vgargv[n++] = NULL;

    /* Now create the volume group itself */
    if (virRun(conn, (char**)vgargv, NULL) < 0)
        goto cleanup;

    free(vgargv);

    return 0;

 cleanup:
    free(vgargv);
    return -1;
}


static int
virStorageBackendLogicalRefreshPool(virConnectPtr conn,
                                    virStoragePoolObjPtr pool)
{
    /*
     *  # vgs --separator : --noheadings --units b --unbuffered --nosuffix --options "vg_size,vg_free" VGNAME
     *    10603200512:4328521728
     *
     * Pull out size & free
     */
    const char *regexes[] = {
        "^\\s*(\\S+):(\\S+)\\s*$"
    };
    int vars[] = {
        2
    };
    const char *prog[] = {
        VGS, "--separator", ":", "--noheadings", "--units", "b", "--unbuffered",
        "--nosuffix", "--options", "vg_size,vg_free",
        pool->def->name, NULL
    };

    /* Get list of all logical volumes */
    if (virStorageBackendLogicalFindLVs(conn, pool, NULL) < 0) {
        virStoragePoolObjClearVols(pool);
        return -1;
    }

    /* Now get basic volgrp metadata */
    if (virStorageBackendRunProgRegex(conn,
                                      pool,
                                      prog,
                                      1,
                                      regexes,
                                      vars,
                                      virStorageBackendLogicalRefreshPoolFunc,
                                      NULL) < 0) {
        virStoragePoolObjClearVols(pool);
        return -1;
    }

    return 0;
}


/* XXX should we set LVM to inactive ? Probably not - it would
 * suck if this were your LVM root fs :-)
 */
#if 0
static int
virStorageBackendLogicalStopPool(virConnectPtr conn,
                                 virStoragePoolObjPtr pool)
{
    if (virStorageBackendLogicalSetActive(conn, pool, 0) < 0)
        return -1;

    return 0;
}
#endif

static int
virStorageBackendLogicalDeletePool(virConnectPtr conn,
                                   virStoragePoolObjPtr pool,
                                   unsigned int flags ATTRIBUTE_UNUSED)
{
    const char *cmdargv[] = {
        VGREMOVE, "-f", pool->def->name, NULL
    };

    if (virRun(conn, (char**)cmdargv, NULL) < 0)
        return -1;

    /* XXX clear the PVs too ? ie pvremove ? probably ought to */

    return 0;
}


static int
virStorageBackendLogicalDeleteVol(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  unsigned int flags);


static int
virStorageBackendLogicalCreateVol(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol)
{
    int fd = -1;
    char size[100];
    const char *cmdargv[] = {
        LVCREATE, "--name", vol->name, "-L", size,
        pool->def->target.path, NULL
    };

    snprintf(size, sizeof(size)-1, "%lluK", vol->capacity/1024);
    size[sizeof(size)-1] = '\0';

    if (virRun(conn, (char**)cmdargv, NULL) < 0)
        return -1;

    if ((fd = open(vol->target.path, O_RDONLY)) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot read path '%s': %s"),
                              vol->target.path, strerror(errno));
        goto cleanup;
    }

    /* We can only chown/grp if root */
    if (getuid() == 0) {
        if (fchown(fd, vol->target.perms.uid, vol->target.perms.gid) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot set file owner '%s': %s"),
                                  vol->target.path, strerror(errno));
            goto cleanup;
        }
    }
    if (fchmod(fd, vol->target.perms.mode) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot set file mode '%s': %s"),
                              vol->target.path, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot close file '%s': %s"),
                              vol->target.path, strerror(errno));
        goto cleanup;
    }
    fd = -1;

    /* Fill in data about this new vol */
    if (virStorageBackendLogicalFindLVs(conn, pool, vol) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot find newly created volume '%s': %s"),
                              vol->target.path, strerror(errno));
        goto cleanup;
    }

    return 0;

 cleanup:
    if (fd != -1)
        close(fd);
    virStorageBackendLogicalDeleteVol(conn, pool, vol, 0);
    return -1;
}

static int
virStorageBackendLogicalDeleteVol(virConnectPtr conn,
                                  virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                  virStorageVolDefPtr vol,
                                  unsigned int flags ATTRIBUTE_UNUSED)
{
    const char *cmdargv[] = {
        LVREMOVE, "-f", vol->target.path, NULL
    };

    if (virRun(conn, (char**)cmdargv, NULL) < 0)
        return -1;

    return 0;
}


virStorageBackend virStorageBackendLogical = {
    .type = VIR_STORAGE_POOL_LOGICAL,

    .startPool = virStorageBackendLogicalStartPool,
    .buildPool = virStorageBackendLogicalBuildPool,
    .refreshPool = virStorageBackendLogicalRefreshPool,
#if 0
    .stopPool = virStorageBackendLogicalStopPool,
#endif
    .deletePool = virStorageBackendLogicalDeletePool,
    .createVol = virStorageBackendLogicalCreateVol,
    .deleteVol = virStorageBackendLogicalDeleteVol,

    .poolOptions = {
        .formatFromString = virStorageBackendLogicalPoolFormatFromString,
        .formatToString = virStorageBackendLogicalPoolFormatToString,
    },

    .volType = VIR_STORAGE_VOL_BLOCK,
};

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
