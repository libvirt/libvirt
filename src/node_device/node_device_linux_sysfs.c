/*
 * node_device_hal_linuc.c: Linux specific code to gather device data
 * not available through HAL.
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "node_device_driver.h"
#include "node_device_hal.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include <dirent.h>

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

static int open_wwn_file(const char *prefix,
                         int host,
                         const char *file,
                         int *fd)
{
    int retval = 0;
    char *wwn_path = NULL;

    if (virAsprintf(&wwn_path, "%s/host%d/%s", prefix, host, file) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    /* fd will be closed by caller */
    if ((*fd = open(wwn_path, O_RDONLY)) != -1) {
        VIR_DEBUG("Opened WWN path '%s' for reading",
                  wwn_path);
    } else {
        VIR_ERROR(_("Failed to open WWN path '%s' for reading"),
                  wwn_path);
    }

out:
    VIR_FREE(wwn_path);
    return retval;
}


int read_wwn_linux(int host, const char *file, char **wwn)
{
    char *p = NULL;
    int fd = -1, retval = 0;
    char buf[64];

    if (open_wwn_file(LINUX_SYSFS_FC_HOST_PREFIX, host, file, &fd) < 0) {
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    if (saferead(fd, buf, sizeof(buf)) < 0) {
        retval = -1;
        VIR_DEBUG("Failed to read WWN for host%d '%s'",
                  host, file);
        goto out;
    }

    p = strstr(buf, "0x");
    if (p != NULL) {
        p += strlen("0x");
    } else {
        p = buf;
    }

    *wwn = strndup(p, sizeof(buf));
    if (*wwn == NULL) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    p = strchr(*wwn, '\n');
    if (p != NULL) {
        *p = '\0';
    }

out:
    if (fd != -1) {
        close(fd);
    }
    return retval;
}


int check_fc_host_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    int retval = 0;
    struct stat st;

    VIR_DEBUG("Checking if host%d is an FC HBA", d->scsi_host.host);

    if (virAsprintf(&sysfs_path, "%shost%d",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) != 0) {
        /* Not an FC HBA; not an error, either. */
        goto out;
    }

    d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

    if (read_wwn(d->scsi_host.host,
                 "port_name",
                 &d->scsi_host.wwpn) == -1) {
        VIR_ERROR(_("Failed to read WWPN for host%d"),
                  d->scsi_host.host);
        retval = -1;
        goto out;
    }

    if (read_wwn(d->scsi_host.host,
                 "node_name",
                 &d->scsi_host.wwnn) == -1) {
        VIR_ERROR(_("Failed to read WWNN for host%d"),
                  d->scsi_host.host);
        retval = -1;
    }

out:
    if (retval == -1) {
        VIR_FREE(d->scsi_host.wwnn);
        VIR_FREE(d->scsi_host.wwpn);
    }
    VIR_FREE(sysfs_path);
    return 0;
}


int check_vport_capable_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    struct stat st;
    int retval = 0;

    if (virAsprintf(&sysfs_path,
                    "%shost%d%s",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host,
                    LINUX_SYSFS_VPORT_CREATE_POSTFIX) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) == 0) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;
        goto out;
    }

    VIR_FREE(sysfs_path);
    if (virAsprintf(&sysfs_path,
                    "%shost%d%s",
                    LINUX_SYSFS_SCSI_HOST_PREFIX,
                    d->scsi_host.host,
                    LINUX_SYSFS_VPORT_CREATE_POSTFIX) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) == 0) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;
    } else {
        /* Not a vport capable HBA; not an error, either. */
        VIR_DEBUG("No vport operation path found for host%d",
                  d->scsi_host.host);
    }

out:
    VIR_FREE(sysfs_path);
    return retval;
}


static int logStrToLong_ui(char const *s,
                           char **end_ptr,
                           int base,
                           unsigned int *result)
{
    int ret = 0;

    ret = virStrToLong_ui(s, end_ptr, base, result);
    if (ret != 0) {
        VIR_ERROR(_("Failed to convert '%s' to unsigned int"), s);
    } else {
        VIR_DEBUG("Converted '%s' to unsigned int %u", s, *result);
    }

    return ret;
}


static int parse_pci_config_address(char *address, struct pci_config_address *bdf)
{
    char *p = NULL;
    int ret = -1;

    if ((address == NULL) || (logStrToLong_ui(address, &p, 16,
                                              &bdf->domain) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->bus) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->slot) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->function) == -1)) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}




static int get_sriov_function(const char *device_link,
                              struct pci_config_address **bdf)
{
    char *config_address = NULL;
    char *device_path = NULL;
    char errbuf[64];
    int ret = SRIOV_ERROR;

    VIR_DEBUG("Attempting to resolve device path from device link '%s'",
              device_link);

    if (!virFileExists(device_link)) {

        VIR_DEBUG("SR IOV function link '%s' does not exist", device_link);
        /* Not an SR IOV device, not an error, either. */
        ret = SRIOV_NOT_FOUND;

        goto out;

    }

    device_path = canonicalize_file_name (device_link);
    if (device_path == NULL) {
        memset(errbuf, '\0', sizeof(errbuf));
        VIR_ERROR(_("Failed to resolve device link '%s': '%s'"), device_link,
                  virStrerror(errno, errbuf, sizeof(errbuf)));
        goto out;
    }

    VIR_DEBUG("SR IOV device path is '%s'", device_path);
    config_address = basename(device_path);
    if (VIR_ALLOC(*bdf) != 0) {
        VIR_ERROR0(_("Failed to allocate memory for PCI device name"));
        goto out;
    }

    if (parse_pci_config_address(config_address, *bdf) != 0) {
        VIR_ERROR(_("Failed to parse PCI config address '%s'"), config_address);
        goto out;
    }

    VIR_DEBUG("SR IOV function %.4x:%.2x:%.2x.%.1x",
              (*bdf)->domain,
              (*bdf)->bus,
              (*bdf)->slot,
              (*bdf)->function);

    ret = SRIOV_FOUND;

out:
    VIR_FREE(device_path);
    return ret;
}


int get_physical_function_linux(const char *sysfs_path,
                                union _virNodeDevCapData *d ATTRIBUTE_UNUSED)
{
    int ret = -1;
    char *device_link = NULL;

    VIR_DEBUG("Attempting to get SR IOV physical function for device "
              "with sysfs path '%s'", sysfs_path);

    if (virBuildPath(&device_link, sysfs_path, "physfn") == -1) {
        virReportOOMError();
    } else {
        ret = get_sriov_function(device_link, &d->pci_dev.physical_function);
        if (ret == SRIOV_FOUND) {
            d->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;
        }
    }

    VIR_FREE(device_link);
    return ret;
}


int get_virtual_functions_linux(const char *sysfs_path,
                                union _virNodeDevCapData *d)
{
    int ret = -1;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char *device_link = NULL;

    VIR_DEBUG("Attempting to get SR IOV virtual functions for device"
              "with sysfs path '%s'", sysfs_path);

    dir = opendir(sysfs_path);
    if (dir == NULL) {
        goto out;
    }

    while ((entry = readdir(dir))) {
        if (STRPREFIX(entry->d_name, "virtfn")) {
            /* This local is just to avoid lines of code much > 80 col. */
            unsigned int *num_funcs = &d->pci_dev.num_virtual_functions;

            if (virBuildPath(&device_link, sysfs_path, entry->d_name) == -1) {
                virReportOOMError();
                goto out;
            }

            VIR_DEBUG("Number of virtual functions: %d", *num_funcs);
            if (VIR_REALLOC_N(d->pci_dev.virtual_functions,
                              (*num_funcs) + 1) != 0) {
                virReportOOMError();
                goto out;
            }

            if (get_sriov_function(device_link,
                                   &d->pci_dev.virtual_functions[*num_funcs])
                                   != SRIOV_FOUND) {

                /* We should not get back SRIOV_NOT_FOUND in this
                 * case, so if we do, it's an error. */
                VIR_ERROR(_("Failed to get SR IOV function from device link '%s'"),
                          device_link);
                goto out;
            } else {
                (*num_funcs)++;
                d->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;
            }

            VIR_FREE(device_link);
        }
    }

    ret = 0;

out:
    if (dir)
        closedir(dir);
    VIR_FREE(device_link);
    return ret;
}

#endif /* __linux__ */
