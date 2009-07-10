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

#include <parted/parted.h>
#include <stdio.h>

/* we don't need to include the full internal.h just for this */
#define STREQ(a,b) (strcmp((a),(b)) == 0)

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

    if (argc == 3 && STREQ(argv[2], "-g")) {
        cmd = DISK_GEOMETRY;
    } else if (argc != 2) {
        fprintf(stderr, "syntax: %s DEVICE [-g]\n", argv[0]);
        return 1;
    }

    if ((dev = ped_device_get(argv[1])) == NULL) {
        fprintf(stderr, "unable to access device %s\n", argv[1]);
        return 2;
    }

    /* return the geometry of the disk and then exit */
    if(cmd == DISK_GEOMETRY) {
        printf("%d%c%d%c%d%c",
               dev->hw_geom.cylinders, '\0',
               dev->hw_geom.heads, '\0',
               dev->hw_geom.sectors, '\0');
        return 0;
    }

    if ((disk = ped_disk_new(dev)) == NULL) {
        fprintf(stderr, "unable to access disk %s\n", argv[1]);
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
            printf("%s%d%c%s%c%s%c%llu%c%llu%c%llu%c",
                   part->geom.dev->path,
                   part->num, '\0',
                   type, '\0',
                   content, '\0',
                   part->geom.start * 512llu, '\0',
                   (part->geom.end + 1 ) * 512llu, '\0',
                   part->geom.length * 512llu, '\0');
        } else {
            printf("%s%c%s%c%s%c%llu%c%llu%c%llu%c",
                   "-", '\0',
                   type, '\0',
                   content, '\0',
                   part->geom.start * 512llu, '\0',
                   (part->geom.end + 1 ) * 512llu, '\0',
                   part->geom.length * 512llu, '\0');
        }
        part = ped_disk_next_partition(disk, part);
    }

    return 0;
}
