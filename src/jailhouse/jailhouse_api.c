/*
 * jailhouse_api.c: Jailhouse API
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
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "jailhouse_api.h"

#define JAILHOUSE_DEVICE                        "/dev/jailhouse"
#define JAILHOUSE_CELLS                         "/sys/devices/jailhouse/cells"
#define MAX_JAILHOUSE_SYS_CONFIG_FILE_SIZE      1024*1024
#define MAX_JAILHOUSE_CELL_CONFIG_FILE_SIZE     1024
#define MAX_JAILHOUSE_CELL_IMAGE_FILE_SIZE      64*1024*1024


#define JAILHOUSE_ENABLE               _IOW(0, 0, void *)
#define JAILHOUSE_DISABLE              _IO(0, 1)
#define JAILHOUSE_CELL_CREATE          _IOW(0, 2, virJailhouseCellCreate)
#define JAILHOUSE_CELL_LOAD            _IOW(0, 3, virJailhouseCellLoad)
#define JAILHOUSE_CELL_START           _IOW(0, 4, virJailhouseCellId)
#define JAILHOUSE_CELL_DESTROY         _IOW(0, 5, virJailhouseCellId)

#define VIR_FROM_THIS VIR_FROM_JAILHOUSE

VIR_LOG_INIT("jailhouse.jailhouse_api");

#define JAILHOUSE_CELL_FILE_EXTENSION ".cell"

/* Forward declarations */

/* Open the Jailhouse device for ioctl APIs */
int openDev(void);

/* Reads cell's property given by 'entry' using sysfs API */
char *readSysfsCellString(const unsigned int id, const char *entry);

int cell_match(const struct dirent *dirent);

int createCell(const char *conf_file);

int loadImagesInCell(virJailhouseCellId cell_id, char *images, int num_images);

int shutdownCell(virJailhouseCellId cell_id);

int startCell(virJailhouseCellId cell_id);

int destroyCell(virJailhouseCellId cell_id);

int getCellInfo(const unsigned int id,
                virJailhouseCellInfoPtr * cell_info);

int
jailhouseEnable(const char *sys_conf_file_path)
{
    int err = -1, len;
    g_autofree char *buffer = NULL;
    VIR_AUTOCLOSE fd = -1;

    if (!virFileExists(sys_conf_file_path))
        return 0;

    len = virFileReadAll(sys_conf_file_path, MAX_JAILHOUSE_SYS_CONFIG_FILE_SIZE, &buffer);
    if (len < 0 || !buffer) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                      "%s", _("Failed to read the system configuration file"));
        return -1;
    }

    fd = openDev();

    err = ioctl(fd, JAILHOUSE_ENABLE, buffer);
    if (err) {
        virReportSystemError(errno, "%s", _("Failed to enable jailhouse"));
        return err;
    }

    VIR_DEBUG("Jailhouse hypervisor is enabled");

    return 1;
}

int
jailhouseDisable(void)
{
    int err = -1;
    VIR_AUTOCLOSE fd = -1;

    fd = openDev();

    err = ioctl(fd, JAILHOUSE_DISABLE);
    if (err)
        virReportSystemError(errno,
                             "%s",
                             _("Failed to disable jailhouse: %s"));

    VIR_DEBUG("Jailhouse hypervisor is disabled");

    return err;
}

int
cell_match(const struct dirent *dirent)
{
    char *ext = strrchr(dirent->d_name, '.');

    return dirent->d_name[0] != '.'
        && (STREQ(ext, JAILHOUSE_CELL_FILE_EXTENSION) == 0);
}

int
createJailhouseCells(const char *dir_path)
{

    struct dirent **namelist;
    int num_entries, ret = -1;
    size_t i;

    if (strlen(dir_path) == 0)
        return ret;

    num_entries = scandir(dir_path, &namelist, cell_match, alphasort);
    if (num_entries == -1) {
        if (errno == ENOENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("No cells found in %s, scandir failed."),
                           dir_path);
            goto fail;
        }

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Error reading cell configurations in %s."),
                       dir_path);
        goto fail;
    }


    for (i = 0; i < num_entries; i++) {
        g_autofree char *file_path = g_strdup_printf("%s/%s", dir_path, namelist[i]->d_name);

        if (createCell(file_path) != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cell creation failed with conf found in  %s."),
                           namelist[i]->d_name);
            goto fail;
        }
    }

    ret = 0;

 fail:
    VIR_FREE(namelist);
    return ret;
}

int
openDev(void)
{
    int fd;

    fd = open(JAILHOUSE_DEVICE, O_RDWR);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("Error opening jailhouse device %s"),
                             JAILHOUSE_DEVICE);
    }
    return fd;
}

int
createCell(const char *conf_file)
{
    virJailhouseCellCreate cell_create;
    int err = -1, len;
    g_autofree char *buffer = NULL;
    VIR_AUTOCLOSE fd = -1;

    if (strlen(conf_file) == 0)
        return err;

    len = virFileReadAll(conf_file, MAX_JAILHOUSE_CELL_CONFIG_FILE_SIZE, &buffer);
    if (len < 0 || !buffer) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                      "%s", _("Failed to read the system configuration file"));
        return err;
    }

    cell_create.config_address = (unsigned long) buffer;
    cell_create.config_size = len;

    fd = openDev();

    err = ioctl(fd, JAILHOUSE_CELL_CREATE, &cell_create);
    if (err)
        virReportSystemError(errno,
                             "%s",
                             _("Cell creation failed: %s"));

    return err;
}

void
cellInfoFree(virJailhouseCellInfoPtr cell_info)
{
    VIR_FREE(cell_info->state);
    VIR_FREE(cell_info->cpus_assigned_list);
    VIR_FREE(cell_info->cpus_failed_list);
    VIR_FREE(cell_info);
}

char *
readSysfsCellString(const unsigned int id, const char *entry)
{
    g_autofree char *buffer = NULL;
    g_autofree char *file_path = NULL;
    int len = -1;

    file_path = g_strdup_printf(JAILHOUSE_CELLS "%u/%s", id, entry);

    len = virFileReadAll(file_path, 1024, &buffer);
    if (len < 0 || !buffer) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error reading cell(%u) %s from %s failed"),
                       id, entry, file_path);
        return NULL;
    }

    virTrimSpaces(buffer, NULL);

    return buffer;
}

int
getCellInfo(const unsigned int id, virJailhouseCellInfoPtr *cell_info_ptr)
{
    char *tmp;

    if (VIR_ALLOC(*cell_info_ptr) < 0)
        return -1;

    virJailhouseCellInfoPtr cell_info = *cell_info_ptr;

    /* set cell id */
    cell_info->id.id = id;

    /* get cell name */
    tmp = readSysfsCellString(id, "name");
    if (virStrncpy(cell_info->id.name, tmp, JAILHOUSE_CELL_ID_NAMELEN, JAILHOUSE_CELL_ID_NAMELEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cell ID %s too long to be copied to the cell info"),
                       tmp);
        return -1;
    }

    cell_info->id.name[JAILHOUSE_CELL_ID_NAMELEN] = 0;
    VIR_FREE(tmp);

    /* get cell state */
    cell_info->state = readSysfsCellString(id, "state");

    /* get assigned cpu list */
    cell_info->cpus_assigned_list =
        readSysfsCellString(id, "cpus_assigned_list");

    /* get failed cpu list */
    cell_info->cpus_failed_list =
        readSysfsCellString(id, "cpus_failed_list");

    return 0;
}

virJailhouseCellInfoPtr *
getJailhouseCellsInfo(void)
{
    struct dirent **namelist;
    virJailhouseCellInfoPtr *cell_info_list;
    unsigned int id;
    int num_entries;
    size_t i;

    num_entries =
        scandir(JAILHOUSE_CELLS, &namelist, cell_match, alphasort);
    if (num_entries == -1) {
        if (errno == ENOENT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No cells found in %s, scandir failed."),
                           JAILHOUSE_CELLS);
            return NULL;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error reading cell IDs in %s."),
                       JAILHOUSE_CELLS);
        return NULL;
    }

    /* Allocate memory for 1 more than num_entries and make the last entry NULL. */
    if (VIR_ALLOC_N(cell_info_list, num_entries + 1) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Insufficient memory for cells info list"));
    }

    /* Set the last entry to NULL. */
    cell_info_list[num_entries] = NULL;

    for (i = 0; i < num_entries; i++) {
        if (virStrToLong_ui(namelist[i]->d_name, NULL, 10, &id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cell ID %s could not be converted to a long"),
                           namelist[i]->d_name);
            continue;
        }

        /* get the cell's information(name, state etc.) using sysfs */
        getCellInfo(id, &cell_info_list[i]);
        VIR_FREE(namelist[i]);
    }

    VIR_FREE(namelist);
    return cell_info_list;
}

int
loadImagesInCell(virJailhouseCellId cell_id, char **images, int num_images)
{
   virJailhousePreloadImagePtr image;
   virJailhouseCellLoadPtr cell_load;
   g_autofree char *buffer = NULL;
   unsigned int n;
   int len = -1, err = -1;
   VIR_AUTOCLOSE fd = -1;


   if (VIR_ALLOC(cell_load) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Insufficient memory for cell load"));
        return -1;
   }


   if (VIR_ALLOC_N(cell_load->image, num_images) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Insufficient memory for cell load images"));
        return -1;
   }

   cell_load->id = cell_id;
   cell_load->num_preload_images = num_images;

   for (n = 0, image = cell_load->image; n < num_images; n++, image++) {
        len = virFileReadAll(images[n], MAX_JAILHOUSE_CELL_IMAGE_FILE_SIZE, &buffer);
        if (len < 0 || !buffer) {
             virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Failed to read the image file %s"),
                            images[n]);
             return -1;
        }

        image->source_address = (unsigned long)buffer;
        image->size = len;

        // TODO(Prakhar): Add support for target address.
        image->target_address = 0;
   }

   fd = openDev();

   err = ioctl(fd, JAILHOUSE_CELL_LOAD, cell_load);
   if (err) {
       virReportSystemError(errno,
                            _("Loading cell images for %d failed"),
                            cell_id.id);
       return -1;
   }

   return 0;
}

int
shutdownCell(virJailhouseCellId cell_id)
{
    // Loading 0 images in the cell causes cell to shutdown.
    return loadImagesInCell(cell_id, NULL, 0);
}

int
startCell(virJailhouseCellId cell_id)
{
    int err = -1;
    VIR_AUTOCLOSE fd = -1;

    fd = openDev();

    err = ioctl(fd, JAILHOUSE_CELL_START, &cell_id);
    if (err) {
        virReportSystemError(errno,
                             _("Start cell %d failed"),
                             cell_id.id);
        return -1;
    }

    return 0;
}

int
destroyCell(virJailhouseCellId cell_id)
{
    int err = -1;
    VIR_AUTOCLOSE fd = -1;

    fd = openDev();

    err = ioctl(fd, JAILHOUSE_CELL_DESTROY, &cell_id);
    if (err) {
        virReportSystemError(errno,
                             _("Destroying cell %d failed"),
                             cell_id.id);

        return -1;
    }

    return 0;
}
