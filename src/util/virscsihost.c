/*
 * virscsihost.c: Generic scsi_host management utility functions
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

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virscsihost.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.scsi_host");

#ifdef __linux__

# define SYSFS_SCSI_HOST_PATH "/sys/class/scsi_host"

/* virSCSIHostGetUniqueId:
 * @sysfs_prefix: "scsi_host" sysfs path, defaults to SYSFS_SCSI_HOST_PATH
 * @host: Host number, E.g. 5 of "scsi_host/host5"
 *
 * Read the value of the "scsi_host" unique_id file.
 *
 * Returns the value on success or -1 on failure.
 */
int
virSCSIHostGetUniqueId(const char *sysfs_prefix,
                       int host)
{
    char *sysfs_path = NULL;
    char *p = NULL;
    int ret = -1;
    char *buf = NULL;
    int unique_id;

    if (virAsprintf(&sysfs_path, "%s/host%d/unique_id",
                    sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_HOST_PATH,
                    host) < 0)
        return -1;

    if (virFileReadAll(sysfs_path, 1024, &buf) < 0)
        goto cleanup;

    if ((p = strchr(buf, '\n')))
        *p = '\0';

    if (virStrToLong_i(buf, NULL, 10, &unique_id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse unique_id: %s"), buf);

        goto cleanup;
    }

    ret = unique_id;

 cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(buf);
    return ret;
}


/* virSCSIHostFindByPCI:
 * @sysfs_prefix: "scsi_host" sysfs path, defaults to SYSFS_SCSI_HOST_PATH
 * @parentaddr: string of the PCI address "scsi_host" device to be found
 * @unique_id: unique_id value of the to be found "scsi_host" device
 * @result: Return the host# of the matching "scsi_host" device
 *
 * Iterate over the SYSFS_SCSI_HOST_PATH entries looking for a matching
 * PCI Address in the expected format (dddd:bb:ss.f, where 'dddd' is the
 * 'domain' value, 'bb' is the 'bus' value, 'ss' is the 'slot' value, and
 * 'f' is the 'function' value from the PCI address) with a unique_id file
 * entry having the value expected. Unlike virReadSCSIUniqueId() we don't
 * have a host number yet and that's what we're looking for.
 *
 * Returns the host name of the "scsi_host" which must be freed by the caller,
 * or NULL on failure
 */
char *
virSCSIHostFindByPCI(const char *sysfs_prefix,
                     const char *parentaddr,
                     unsigned int unique_id)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_HOST_PATH;
    struct dirent *entry = NULL;
    DIR *dir = NULL;
    char *host_link = NULL;
    char *host_path = NULL;
    char *p = NULL;
    char *ret = NULL;
    char *buf = NULL;
    char *unique_path = NULL;
    unsigned int read_unique_id;

    if (virDirOpen(&dir, prefix) < 0)
        return NULL;

    while (virDirRead(dir, &entry, prefix) > 0) {
        if (!virFileIsLink(entry->d_name))
            continue;

        if (virAsprintf(&host_link, "%s/%s", prefix, entry->d_name) < 0)
            goto cleanup;

        if (virFileResolveLink(host_link, &host_path) < 0)
            goto cleanup;

        if (!strstr(host_path, parentaddr)) {
            VIR_FREE(host_link);
            VIR_FREE(host_path);
            continue;
        }
        VIR_FREE(host_link);
        VIR_FREE(host_path);

        if (virAsprintf(&unique_path, "%s/%s/unique_id", prefix,
                        entry->d_name) < 0)
            goto cleanup;

        if (!virFileExists(unique_path)) {
            VIR_FREE(unique_path);
            continue;
        }

        if (virFileReadAll(unique_path, 1024, &buf) < 0)
            goto cleanup;

        if ((p = strchr(buf, '\n')))
            *p = '\0';

        if (virStrToLong_ui(buf, NULL, 10, &read_unique_id) < 0)
            goto cleanup;

        VIR_FREE(buf);

        if (read_unique_id != unique_id) {
            VIR_FREE(unique_path);
            continue;
        }

        ignore_value(VIR_STRDUP(ret, entry->d_name));
        break;
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(unique_path);
    VIR_FREE(host_link);
    VIR_FREE(host_path);
    VIR_FREE(buf);
    return ret;
}


/* virSCSIHostGetNumber:
 * @adapter_name: Name of the host adapter
 * @result: Return the entry value as unsigned int
 *
 * Convert the various forms of scsi_host names into the numeric
 * host# value that can be used in order to scan sysfs looking for
 * the specific host.
 *
 * Names can be either "scsi_host#" or just "host#", where
 * "host#" is the back-compat format, but both equate to
 * the same source adapter.  First check if both pool and def
 * are using same format (easier) - if so, then compare
 *
 * Returns 0 on success, and @result has the host number.
 * Otherwise returns -1.
 */
int
virSCSIHostGetNumber(const char *adapter_name,
                     unsigned int *result)
{
    /* Specifying adapter like 'host5' is still supported for
     * back-compat reason.
     */
    if (STRPREFIX(adapter_name, "scsi_host")) {
        adapter_name += strlen("scsi_host");
    } else if (STRPREFIX(adapter_name, "fc_host")) {
        adapter_name += strlen("fc_host");
    } else if (STRPREFIX(adapter_name, "host")) {
        adapter_name += strlen("host");
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid adapter name '%s' for SCSI pool"),
                       adapter_name);
        return -1;
    }

    if (virStrToLong_ui(adapter_name, NULL, 10, result) == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid adapter name '%s' for SCSI pool"),
                       adapter_name);
        return -1;
    }

    return 0;
}

/* virSCSIHostGetNameByParentaddr:
 * @domain: The domain from the scsi_host parentaddr
 * @bus: The bus from the scsi_host parentaddr
 * @slot: The slot from the scsi_host parentaddr
 * @function: The function from the scsi_host parentaddr
 * @unique_id: The unique id value for parentaddr
 *
 * Generate a parentaddr and find the scsi_host host# for
 * the provided parentaddr PCI address fields.
 *
 * Returns the "host#" string which must be free'd by
 * the caller or NULL on error
 */
char *
virSCSIHostGetNameByParentaddr(unsigned int domain,
                               unsigned int bus,
                               unsigned int slot,
                               unsigned int function,
                               unsigned int unique_id)
{
    char *name = NULL;
    char *parentaddr = NULL;

    if (virAsprintf(&parentaddr, "%04x:%02x:%02x.%01x",
                    domain, bus, slot, function) < 0)
        goto cleanup;
    if (!(name = virSCSIHostFindByPCI(NULL, parentaddr, unique_id))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Failed to find scsi_host using PCI '%s' "
                         "and unique_id='%u'"),
                       parentaddr, unique_id);
        goto cleanup;
    }

 cleanup:
    VIR_FREE(parentaddr);
    return name;
}

#else

int
virSCSIHostGetUniqueId(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                       int host ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

char *
virSCSIHostFindByPCI(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                     const char *parentaddr ATTRIBUTE_UNUSED,
                     unsigned int unique_id ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}

int
virSCSIHostGetNumber(const char *adapter_name ATTRIBUTE_UNUSED,
                     unsigned int *result ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

char *
virSCSIHostGetNameByParentaddr(unsigned int domain ATTRIBUTE_UNUSED,
                               unsigned int bus ATTRIBUTE_UNUSED,
                               unsigned int slot ATTRIBUTE_UNUSED,
                               unsigned int function ATTRIBUTE_UNUSED,
                               unsigned int unique_id ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}

#endif /* __linux__ */
