/*
 * virvhba.c: Generic vHBA management utility functions
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

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.vhba");

#ifdef __linux__

# define SYSFS_SCSI_HOST_PATH "/sys/class/scsi_host"
# define SYSFS_FC_HOST_PATH "/sys/class/fc_host"
# define PORT_STATE_ONLINE "Online"


/* virVHBAPathExists:
 * @sysfs_prefix: "fc_host" sysfs path, defaults to SYSFS_FC_HOST_PATH
 * @host: Host number, E.g. 5 of "fc_host/host5"
 *
 * Check if the "fc_host" to provided host# exists. This path may be either
 * a vHBA capable path or a vHBA itself.
 *
 * Returns true if it does, false if not
 */
bool
virVHBAPathExists(const char *sysfs_prefix,
                  int host)
{
    char *sysfs_path = NULL;
    bool ret = false;

    if (virAsprintf(&sysfs_path, "%s/host%d",
                    sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH,
                    host) < 0)
        return false;

    if (virFileExists(sysfs_path))
        ret = true;

    VIR_FREE(sysfs_path);
    return ret;
}


/* virVHBAIsVportCapable:
 * @sysfs_prefix: "fc_host" sysfs path, defaults to SYSFS_FC_HOST_PATH
 * @host: Host number, E.g. 5 of "fc_host/host5"
 *
 * Not all vHBA paths can create/delete a vport - only the parent NPIV
 * capable HBA has the "vport_create" and "vport_delete" functions.
 * A vHBA created path does not have the function files.
 *
 * NB: Checks both the "fc_host" and "scsi_host" paths.
 *
 * Returns true if capable, false if not
 */
bool
virVHBAIsVportCapable(const char *sysfs_prefix,
                      int host)
{
    char *scsi_host_path = NULL;
    char *fc_host_path = NULL;
    bool ret = false;

    if (virAsprintf(&fc_host_path,
                    "%s/host%d/%s",
                    sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH,
                    host,
                    "vport_create") < 0)
        return false;

    if (virAsprintf(&scsi_host_path,
                    "%s/host%d/%s",
                    sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_HOST_PATH,
                    host,
                    "vport_create") < 0)
        goto cleanup;

    if (virFileExists(fc_host_path) || virFileExists(scsi_host_path))
        ret = true;

 cleanup:
    VIR_FREE(fc_host_path);
    VIR_FREE(scsi_host_path);
    return ret;
}


/* virVHBAGetConfig:
 * @sysfs_prefix: "fc_host" sysfs path, defaults to SYSFS_FC_HOST_PATH
 * @host: Host number, E.g. 5 of "fc_host/host5"
 * @entry: Name of the FC sysfs entry to read
 *
 * Read the value of a vHBA sysfs "fc_host" entry (if it exists).
 *
 * Returns result as a string on success, caller is responsible for
 * freeing the @result; otherwise returns NULL on failure.
 */
char *
virVHBAGetConfig(const char *sysfs_prefix,
                 int host,
                 const char *entry)
{
    char *sysfs_path = NULL;
    char *p = NULL;
    char *buf = NULL;
    char *result = NULL;

    if (virAsprintf(&sysfs_path, "%s/host%d/%s",
                    sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH,
                    host, entry) < 0)
        goto cleanup;

    if (!virFileExists(sysfs_path))
        goto cleanup;

    if (virFileReadAll(sysfs_path, 1024, &buf) < 0)
        goto cleanup;

    if ((p = strchr(buf, '\n')))
        *p = '\0';

    if ((p = strstr(buf, "0x")))
        p += strlen("0x");
    else
        p = buf;

    ignore_value(VIR_STRDUP(result, p));

 cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(buf);
    return result;
}


/* virVHBAFindVportHost:
 *
 * Iterate over the sysfs and find out the first online HBA which
 * supports vport, and is not saturated. Returns the host name (e.g.
 * host5) on success, or NULL on failure.
 *
 * It's up to the caller to free the returned string.
 */
char *
virVHBAFindVportHost(const char *sysfs_prefix)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char *max_vports = NULL;
    char *vports = NULL;
    char *state = NULL;
    char *ret = NULL;

    if (virDirOpen(&dir, prefix) < 0)
        return NULL;

    while (virDirRead(dir, &entry, prefix) > 0) {
        unsigned int host;
        char *p = NULL;

        p = entry->d_name + strlen("host");
        if (virStrToLong_ui(p, NULL, 10, &host) == -1) {
            VIR_DEBUG("Failed to parse host number from '%s'",
                      entry->d_name);
            continue;
        }

        if (!virVHBAPathExists(prefix, host))
            continue;

        if (!(state = virVHBAGetConfig(prefix, host, "port_state"))) {
             VIR_DEBUG("Failed to read port_state for host%d", host);
             continue;
        }

        /* Skip the not online FC host */
        if (STRNEQ(state, PORT_STATE_ONLINE)) {
            VIR_FREE(state);
            continue;
        }
        VIR_FREE(state);

        if (!(max_vports = virVHBAGetConfig(prefix, host, "max_npiv_vports"))) {
             VIR_DEBUG("Failed to read max_npiv_vports for host%d", host);
             continue;
        }

        if (!(vports = virVHBAGetConfig(prefix, host, "npiv_vports_inuse"))) {
             VIR_DEBUG("Failed to read npiv_vports_inuse for host%d", host);
             VIR_FREE(max_vports);
             continue;
        }

        /* Compare from the strings directly, instead of converting
         * the strings to integers first
         */
        if ((strlen(max_vports) >= strlen(vports)) ||
            ((strlen(max_vports) == strlen(vports)) &&
             strcmp(max_vports, vports) > 0)) {
            ignore_value(VIR_STRDUP(ret, entry->d_name));
            goto cleanup;
        }

        VIR_FREE(max_vports);
        VIR_FREE(vports);
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(max_vports);
    VIR_FREE(vports);
    return ret;
}

/* virVHBAManageVport:
 * @sysfs_prefix: "fc_host" sysfs path, defaults to SYSFS_FC_HOST_PATH
 * @wwnn: world wide node name used to create/delete the vport
 * @wwpn: world wide port name used to create/delete the vport
 * @operation: create or delete
 *
 * NB: Checks both the "fc_host" and "scsi_host" paths.
 * Returns true if capable, false if not
 */
int
virVHBAManageVport(const int parent_host,
                   const char *wwpn,
                   const char *wwnn,
                   int operation)
{
    int ret = -1;
    char *operation_path = NULL, *vport_name = NULL;
    const char *operation_file = NULL;

    switch (operation) {
    case VPORT_CREATE:
        operation_file = "vport_create";
        break;
    case VPORT_DELETE:
        operation_file = "vport_delete";
        break;
    default:
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Invalid vport operation (%d)"), operation);
        goto cleanup;
    }

    if (virAsprintf(&operation_path, "%s/host%d/%s",
                    SYSFS_FC_HOST_PATH, parent_host, operation_file) < 0)
        goto cleanup;

    if (!virFileExists(operation_path)) {
        VIR_FREE(operation_path);
        if (virAsprintf(&operation_path, "%s/host%d/%s",
                        SYSFS_SCSI_HOST_PATH, parent_host, operation_file) < 0)
            goto cleanup;

        if (!virFileExists(operation_path)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("vport operation '%s' is not supported "
                             "for host%d"),
                           operation_file, parent_host);
            goto cleanup;
        }
    }

    /* Create/Delete is handled through the file passing the wwpn:wwnn as
     * a parameter. This results in the kernel managing the port. For udev,
     * an event is posted and handled in udevEventHandleCallback resulting
     * in calling either the Add or Remove device functions. This translates
     * into either adding or removing a node device object and a node device
     * lifecycle event for applications to consume. */
    if (virAsprintf(&vport_name, "%s:%s", wwpn, wwnn) < 0)
        goto cleanup;

    if (virFileWriteStr(operation_path, vport_name, 0) == 0)
        ret = 0;
    else
        virReportSystemError(errno,
                             _("Write of '%s' to '%s' during "
                               "vport create/delete failed"),
                             vport_name, operation_path);

 cleanup:
    VIR_FREE(vport_name);
    VIR_FREE(operation_path);
    return ret;
}


/* vhbaReadCompareWWN
 * @prefix: path to the wwn file
 * @d_name: name of the current directory
 * @f_name: file name to read
 *
 * Read/compare the on-disk file with the passed wwn value.
 *
 * Returns:
 *   -1 : Error
 *    0 : No match
 *    1 : Match
 */
static int
vhbaReadCompareWWN(const char *prefix,
                   const char *d_name,
                   const char *f_name,
                   const char *wwn)
{
    char *path;
    char *buf = NULL;
    char *p;
    int ret = -1;

    if (virAsprintf(&path, "%s/%s/%s", prefix, d_name, f_name) < 0)
        return -1;

    if (!virFileExists(path)) {
        ret = 0;
        goto cleanup;
    }

    if (virFileReadAll(path, 1024, &buf) < 0)
        goto cleanup;

    if ((p = strchr(buf, '\n')))
        *p = '\0';
    if (STRPREFIX(buf, "0x"))
        p = buf + strlen("0x");
    else
        p = buf;

    if (STRNEQ(wwn, p))
        ret = 0;
    else
        ret = 1;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(buf);

    return ret;
}

/* virVHBAGetHostByWWN:
 *
 * Iterate over the sysfs tree to get FC host name (e.g. host5)
 * by the provided "wwnn,wwpn" pair.
 *
 * Returns the FC host name which must be freed by the caller,
 * or NULL on failure.
 */
char *
virVHBAGetHostByWWN(const char *sysfs_prefix,
                    const char *wwnn,
                    const char *wwpn)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH;
    struct dirent *entry = NULL;
    DIR *dir = NULL;
    char *ret = NULL;

    if (virDirOpen(&dir, prefix) < 0)
        return NULL;

    while (virDirRead(dir, &entry, prefix) > 0) {
        int rc;

        if ((rc = vhbaReadCompareWWN(prefix, entry->d_name,
                                     "node_name", wwnn)) < 0)
            goto cleanup;

        if (rc == 0)
            continue;

        if ((rc = vhbaReadCompareWWN(prefix, entry->d_name,
                                     "port_name", wwpn)) < 0)
            goto cleanup;

        if (rc == 0)
            continue;

        ignore_value(VIR_STRDUP(ret, entry->d_name));
        break;
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    return ret;
}

/* virVHBAGetHostByFabricWWN:
 *
 * Iterate over the sysfs tree to get FC host name (e.g. host5)
 * by the provided "fabric_wwn". This would find a host on a SAN.
 *
 * Returns the FC host name which must be freed by the caller,
 * or NULL on failure.
 */
char *
virVHBAGetHostByFabricWWN(const char *sysfs_prefix,
                          const char *fabric_wwn)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_FC_HOST_PATH;
    struct dirent *entry = NULL;
    DIR *dir = NULL;
    char *vport_create_path = NULL;
    char *ret = NULL;

    if (virDirOpen(&dir, prefix) < 0)
        return NULL;

    while (virDirRead(dir, &entry, prefix) > 0) {
        int rc;

        VIR_FREE(vport_create_path);

        /* Existing vHBA's will have the same fabric_name, but won't
         * have the vport_create file - so we check for both */
        if (virAsprintf(&vport_create_path, "%s/%s/vport_create", prefix,
                        entry->d_name) < 0)
            goto cleanup;

        if (!virFileExists(vport_create_path))
            continue;

        if ((rc = vhbaReadCompareWWN(prefix, entry->d_name,
                                     "fabric_name", fabric_wwn)) < 0)
            goto cleanup;

        if (rc == 0)
            continue;

        ignore_value(VIR_STRDUP(ret, entry->d_name));
        break;
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(vport_create_path);
    return ret;
}

#else

bool
virVHBAPathExists(const char *sysfs_prefix G_GNUC_UNUSED,
                  int host G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return false;
}


bool
virVHBAIsVportCapable(const char *sysfs_prefix G_GNUC_UNUSED,
                      int host G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return false;
}


char *
virVHBAGetConfig(const char *sysfs_prefix G_GNUC_UNUSED,
                 int host G_GNUC_UNUSED,
                 const char *entry G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}


char *
virVHBAFindVportHost(const char *sysfs_prefix G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}


int
virVHBAManageVport(const int parent_host G_GNUC_UNUSED,
                   const char *wwpn G_GNUC_UNUSED,
                   const char *wwnn G_GNUC_UNUSED,
                   int operation G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}


char *
virVHBAGetHostByWWN(const char *sysfs_prefix G_GNUC_UNUSED,
                    const char *wwnn G_GNUC_UNUSED,
                    const char *wwpn G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}


char *
virVHBAGetHostByFabricWWN(const char *sysfs_prefix G_GNUC_UNUSED,
                          const char *fabric_wwn G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return NULL;
}

#endif /* __linux__ */
