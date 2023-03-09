/*
 * parthelper.c: Helper program to talk to parted with.
 *
 * This helper exists because parted is GPLv3+, while libvirt is LGPLv2+.
 * Thus we can't link to parted in libvirt.so without the combined work
 * being GPLv3+. Thus we separate via an external command. NB, this source
 * code is still LGPLv2+, but the binary helper is effectively GPLv3+
 *
 * The existing 'parted' command line tool is also incredibly hard to parse
 * in a reliable fashion if merely after a list of partitions & sizes,
 * though it is fine for creating partitions.
 *
 * Copyright (C) 2007-2008, 2010, 2013, 2016 Red Hat, Inc.
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

#include <parted/parted.h>
#include <libdevmapper.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virfile.h"
#include "virgettext.h"
#include "virdevmapper.h"
#include "virerror.h"

/* we don't need to include the full internal.h just for this */
#define STREQ(a, b) (strcmp(a, b) == 0)

/* Make the comparisons below fail if your parted headers
   are so old that they lack the definition.  */
#ifndef PED_PARTITION_PROTECTED
# define PED_PARTITION_PROTECTED 0
#endif

enum diskCommand {
    DISK_LAYOUT = 0,
    DISK_GEOMETRY
};

int main(int argc, char **argv)
{
    PedDevice *dev;
    PedDisk *disk;
    PedPartition *part;
    int cmd = DISK_LAYOUT;
    const char *path;
    g_autofree char *canonical_path = NULL;
    const char *partsep;
    bool devmap_partsep = false;

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0)
        exit(EXIT_FAILURE);

    if (argc == 3 && STREQ(argv[2], "-g")) {
        cmd = DISK_GEOMETRY;
    } else if (argc == 3 && STREQ(argv[2], "-p")) {
        devmap_partsep = true;
    } else if (argc != 2) {
        fprintf(stderr, _("syntax: %1$s DEVICE [-g]|[-p]\n"), argv[0]);
        return 1;
    }

    /* NB: Changes to the following algorithm will need corresponding
     * changes to virStorageBackendDiskDeleteVol */
    path = argv[1];
    if (virIsDevMapperDevice(path)) {
        /* If the path ends with a number or we explicitly request it for
         * path, then append the "p" partition separator. Otherwise, if
         * the path ends with a letter already, then no need for a separator.
         */
        if (g_ascii_isdigit(path[strlen(path)-1]) || devmap_partsep)
            partsep = "p";
        else
            partsep = "";
        canonical_path = g_strdup(path);
    } else {
        if (virFileResolveLink(path, &canonical_path) != 0)
            return 2;

        partsep = *canonical_path &&
            g_ascii_isdigit(canonical_path[strlen(canonical_path)-1]) ? "p" : "";
    }

    if ((dev = ped_device_get(path)) == NULL) {
        fprintf(stderr, _("unable to access device %1$s\n"), path);
        return 2;
    }

    /* return the geometry of the disk and then exit */
    if (cmd == DISK_GEOMETRY) {
        printf("%d%c%d%c%d%c",
               dev->hw_geom.cylinders, '\0',
               dev->hw_geom.heads, '\0',
               dev->hw_geom.sectors, '\0');
        return 0;
    }

    if ((disk = ped_disk_new(dev)) == NULL) {
        fprintf(stderr, _("unable to access disk %1$s\n"), argv[1]);
        return 2;
    }

    /* Get the first partition, and then iterate over all */
    part = ped_disk_next_partition(disk, NULL);
    while (part) {
        const char *type;
        const char *content;
        if (part->type & PED_PARTITION_LOGICAL) {
            type = "logical";
            if (part->type & PED_PARTITION_FREESPACE)
                content = "free";
            else if (part->type & PED_PARTITION_METADATA)
                content = "metadata";
            else if (part->type & PED_PARTITION_PROTECTED)
                content = "protected";
            else
                content = "data";
        } else if (part->type == PED_PARTITION_EXTENDED) {
            type = "extended";
            content = "metadata";
        } else {
            type = "normal";
            if (part->type & PED_PARTITION_FREESPACE)
                content = "free";
            else if (part->type & PED_PARTITION_METADATA)
                content = "metadata";
            else if (part->type & PED_PARTITION_PROTECTED)
                content = "protected";
            else
                content = "data";
        }

        /* We do +1 on geom.end, because we want end of the last sector
         * in bytes, not the last sector number
         */
        if (part->num != -1) {
            printf("%s%s%d%c%s%c%s%c%llu%c%llu%c%llu%c",
                   canonical_path, partsep,
                   part->num, '\0',
                   type, '\0',
                   content, '\0',
                   part->geom.start * dev->sector_size, '\0',
                   (part->geom.end + 1) * dev->sector_size, '\0',
                   part->geom.length * dev->sector_size, '\0');
        } else {
            printf("%s%c%s%c%s%c%llu%c%llu%c%llu%c",
                   "-", '\0',
                   type, '\0',
                   content, '\0',
                   part->geom.start * dev->sector_size, '\0',
                   (part->geom.end + 1) * dev->sector_size, '\0',
                   part->geom.length * dev->sector_size, '\0');
        }
        part = ped_disk_next_partition(disk, part);
    }

    return 0;
}
