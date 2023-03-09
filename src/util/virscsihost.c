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
 *
 * No errors are reported.
 */
int
virSCSIHostGetUniqueId(const char *sysfs_prefix,
                       int host)
{
    g_autofree char *sysfs_path = NULL;
    char *p = NULL;
    g_autofree char *buf = NULL;
    int unique_id;

    sysfs_path = g_strdup_printf("%s/host%d/unique_id",
                                 sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_HOST_PATH, host);

    if (virFileReadAllQuiet(sysfs_path, 1024, &buf) < 0)
        return -1;

    if ((p = strchr(buf, '\n')))
        *p = '\0';

    if (virStrToLong_i(buf, NULL, 10, &unique_id) < 0) {
        VIR_DEBUG("unable to parse unique_id: '%s'", buf);
        return -1;
    }

    return unique_id;
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
    g_autoptr(DIR) dir = NULL;

    if (virDirOpen(&dir, prefix) < 0)
        return NULL;

    while (virDirRead(dir, &entry, prefix) > 0) {
        g_autofree char *host_link = NULL;
        g_autofree char *host_path = NULL;
        g_autofree char *unique_path = NULL;
        g_autofree char *buf = NULL;
        char *p = NULL;
        unsigned int read_unique_id;

        host_link = g_strdup_printf("%s/%s", prefix, entry->d_name);

        if (!virFileIsLink(host_link))
            continue;

        if (virFileResolveLink(host_link, &host_path) < 0)
            return NULL;

        if (!strstr(host_path, parentaddr)) {
            continue;
        }

        unique_path = g_strdup_printf("%s/%s/unique_id", prefix, entry->d_name);

        if (!virFileExists(unique_path)) {
            continue;
        }

        if (virFileReadAll(unique_path, 1024, &buf) < 0)
            return NULL;

        if ((p = strchr(buf, '\n')))
            *p = '\0';

        if (virStrToLong_ui(buf, NULL, 10, &read_unique_id) < 0)
            return NULL;

        if (read_unique_id != unique_id) {
            continue;
        }

        return g_strdup(entry->d_name);
    }

    return NULL;
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
                       _("Invalid adapter name '%1$s' for SCSI pool"),
                       adapter_name);
        return -1;
    }

    if (virStrToLong_ui(adapter_name, NULL, 10, result) == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid adapter name '%1$s' for SCSI pool"),
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
    g_autofree char *parentaddr = NULL;

    parentaddr = g_strdup_printf("%04x:%02x:%02x.%01x", domain, bus, slot,
                                 function);
    if (!(name = virSCSIHostFindByPCI(NULL, parentaddr, unique_id))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Failed to find scsi_host using PCI '%1$s' and unique_id='%2$u'"),
                       parentaddr, unique_id);
        return NULL;
    }

    return name;
}

#else

int
virSCSIHostGetUniqueId(const char *sysfs_prefix G_GNUC_UNUSED,
                       int host G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

char *
virSCSIHostFindByPCI(const char *sysfs_prefix G_GNUC_UNUSED,
                     const char *parentaddr G_GNUC_UNUSED,
                     unsigned int unique_id G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}

int
virSCSIHostGetNumber(const char *adapter_name G_GNUC_UNUSED,
                     unsigned int *result G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

char *
virSCSIHostGetNameByParentaddr(unsigned int domain G_GNUC_UNUSED,
                               unsigned int bus G_GNUC_UNUSED,
                               unsigned int slot G_GNUC_UNUSED,
                               unsigned int function G_GNUC_UNUSED,
                               unsigned int unique_id G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}

#endif /* __linux__ */
