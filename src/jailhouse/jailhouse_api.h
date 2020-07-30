/*
 * jailhouse_api.h: Jailhouse hypervisor API implementation
 *
 * Copyright (C) 2020 Prakhar Bansal
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

#pragma once

#define JAILHOUSE_CELL_ID_NAMELEN       31

typedef struct _virJailhouseCellId virJailhouseCellId;

struct _virJailhouseCellId {
    __s32 id;
    __u32 padding;
    char name[JAILHOUSE_CELL_ID_NAMELEN + 1];
};

typedef struct _virJailhouseCellInfo virJailhouseCellInfo;
typedef virJailhouseCellInfo *virJailhouseCellInfoPtr;

struct _virJailhouseCellInfo {
    struct _virJailhouseCellId id;
    char *state;
    char *cpus_assigned_list;
    char *cpus_failed_list;
};

typedef struct _virJailhouseCellCreate virJailhouseCellCreate;

struct _virJailhouseCellCreate {
    __u64 config_address;
    __u32 config_size;
    __u32 padding;
};

typedef struct _virJailhousePreloadImage virJailhousePreloadImage;
typedef virJailhousePreloadImage *virJailhousePreloadImagePtr;

struct _virJailhousePreloadImage {
    __u64 source_address;
    __u64 size;
    __u64 target_address;
    __u64 padding;
};

typedef struct _virJailhouseCellLoad virJailhouseCellLoad;
typedef virJailhouseCellLoad *virJailhouseCellLoadPtr;

struct _virJailhouseCellLoad {
    struct _virJailhouseCellId id;
    __u32 num_preload_images;
    __u32 padding;
    struct _virJailhousePreloadImage image[];
};


// Enables the Jailhouse hypervisor by reading the hypervisor system
// configuration from the given file and calls the ioctl API to
// enable the hypervisor.
int jailhouseEnable(const char *sys_conf_file_path);

// Disables the Jailhouse hypervisor.
int jailhouseDisable(void);

/* Cell API methods */

// Creates Jailhouse cells using the cells configurations
// provided in the dir_name.
int createJailhouseCells(const char *dir_path);

int loadImagesInCell(virJailhouseCellId cell_id, char **images, int num_images);

int startCell(virJailhouseCellId cell_id);

int shutdownCell(virJailhouseCellId cell_id);

int destroyCell(virJailhouseCellId cell_id);

// Destroys Jailhouse cells using the cell IDs provided in
// the cell_info_list.
int destroyJailhouseCells(virJailhouseCellInfoPtr *cell_info_list);

// Returns cell's information in a null-terminated array of
// virJailhouseCellInfoPtr for all the Jailhouse cells.
virJailhouseCellInfoPtr *getJailhouseCellsInfo(void);

// Free the cell info object.
void cellInfoFree(virJailhouseCellInfoPtr cell_info);
