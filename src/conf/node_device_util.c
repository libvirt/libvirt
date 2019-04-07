/*
 * node_device_util.c: helper functions for the node device driver
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

#include "internal.h"

#include "node_device_util.h"
#include "virlog.h"
#include "virscsihost.h"
#include "virstring.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("node_device.node_device_util");

/* virNodeDeviceGetParentName
 * @conn: Connection pointer
 * @nodedev_name: Node device to lookup
 *
 * Lookup the node device by name and return the parent name
 *
 * Returns parent name on success, caller is responsible for freeing;
 * otherwise, returns NULL on failure
 */
char *
virNodeDeviceGetParentName(virConnectPtr conn,
                           const char *nodedev_name)
{
    virNodeDevicePtr device = NULL;
    char *parent;

    if (!(device = virNodeDeviceLookupByName(conn, nodedev_name))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Cannot find '%s' in node device database"),
                       nodedev_name);
        return NULL;
    }

    ignore_value(VIR_STRDUP(parent, virNodeDeviceGetParent(device)));
    virObjectUnref(device);

    return parent;
}


/**
 * @fchost: Pointer to vHBA adapter
 *
 * Create a vHBA for Storage. This code accomplishes this via searching
 * through the sysfs for scsi_host/fc_host in order to first ensure some
 * vHBA doesn't already exist for the requested wwnn/wwpn (e.g. an unmanaged
 * vHBA) and to search for the parent vport capable scsi_host by name,
 * wwnn/wwpn, or fabric_wwn (if provided). If no parent is provided, then
 * a vport capable scsi_host will be selected.
 *
 * Returns vHBA name on success, NULL on failure with an error message set
 */
char *
virNodeDeviceCreateVport(virStorageAdapterFCHostPtr fchost)
{
    unsigned int parent_host;
    char *name = NULL;
    char *parent_hoststr = NULL;
    bool skip_capable_check = false;

    VIR_DEBUG("parent='%s', wwnn='%s' wwpn='%s'",
              NULLSTR(fchost->parent), fchost->wwnn, fchost->wwpn);

    if (fchost->parent) {
        if (VIR_STRDUP(parent_hoststr, fchost->parent) < 0)
            goto cleanup;
    } else if (fchost->parent_wwnn && fchost->parent_wwpn) {
        if (!(parent_hoststr = virVHBAGetHostByWWN(NULL, fchost->parent_wwnn,
                                                   fchost->parent_wwpn))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot find parent using provided wwnn/wwpn"));
            goto cleanup;
        }
    } else if (fchost->parent_fabric_wwn) {
        if (!(parent_hoststr =
              virVHBAGetHostByFabricWWN(NULL, fchost->parent_fabric_wwn))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot find parent using provided fabric_wwn"));
            goto cleanup;
        }
    } else {
        if (!(parent_hoststr = virVHBAFindVportHost(NULL))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'parent' for vHBA not specified, and "
                             "cannot find one on this host"));
            goto cleanup;
        }
        skip_capable_check = true;
    }

    if (virSCSIHostGetNumber(parent_hoststr, &parent_host) < 0)
        goto cleanup;

    /* NOTE:
     * We do not save the parent_hoststr in fchost->parent since
     * we could be writing out the 'def' to the saved XML config.
     * If we wrote out the name in the XML, then future starts would
     * always use the same parent rather than finding the "best available"
     * parent. Besides we have a way to determine the parent based on
     * the 'name' field.
     */
    if (!skip_capable_check && !virVHBAPathExists(NULL, parent_host)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("parent '%s' specified for vHBA does not exist"),
                       parent_hoststr);
        goto cleanup;
    }

    if (virVHBAManageVport(parent_host, fchost->wwpn, fchost->wwnn,
                           VPORT_CREATE) < 0)
        goto cleanup;

    /* Let's ensure the device was created */
    virWaitForDevices();
    if (!(name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {
        ignore_value(virVHBAManageVport(parent_host, fchost->wwpn, fchost->wwnn,
                                        VPORT_DELETE));
        goto cleanup;
    }

 cleanup:
    VIR_FREE(parent_hoststr);
    return name;
}


/**
 * @conn: Connection pointer
 * @fchost: Pointer to vHBA adapter
 *
 * As long as the vHBA is being managed, search for the scsi_host via the
 * provided wwnn/wwpn and then find the corresponding parent scsi_host in
 * order to send the delete request.
 *
 * Returns 0 on success, -1 on failure
 */
int
virNodeDeviceDeleteVport(virConnectPtr conn,
                         virStorageAdapterFCHostPtr fchost)
{
    char *name = NULL;
    char *scsi_host_name = NULL;
    unsigned int parent_host;
    char *vhba_parent = NULL;
    int ret = -1;

    VIR_DEBUG("conn=%p parent='%s', managed='%d' wwnn='%s' wwpn='%s'",
              conn, NULLSTR(fchost->parent), fchost->managed,
              fchost->wwnn, fchost->wwpn);

    /* If we're not managing the deletion of the vHBA, then just return */
    if (fchost->managed != VIR_TRISTATE_BOOL_YES)
        return 0;

    /* Find our vHBA by searching the fc_host sysfs tree for our wwnn/wwpn */
    if (!(name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find fc_host for wwnn='%s' and wwpn='%s'"),
                       fchost->wwnn, fchost->wwpn);
        goto cleanup;
    }

    if (virAsprintf(&scsi_host_name, "scsi_%s", name) < 0)
        goto cleanup;

    /* If at startup time we provided a parent, then use that to
     * get the parent_host value; otherwise, we have to determine
     * the parent scsi_host which we did not save at startup time
     */
    if (fchost->parent) {
        /* Someone provided a parent string at startup time that
         * was the same as the scsi_host - meaning we have a pool
         * backed to an HBA, so there won't be a vHBA to delete */
        if (STREQ(scsi_host_name, fchost->parent)) {
            ret = 0;
            goto cleanup;
        }

        if (virSCSIHostGetNumber(fchost->parent, &parent_host) < 0)
            goto cleanup;
    } else {
        if (!(vhba_parent = virNodeDeviceGetParentName(conn, scsi_host_name)))
            goto cleanup;

        /* If the parent is not a scsi_host, then this is a pool backed
         * directly to an HBA and there's no vHBA to remove - so we're done */
        if (!STRPREFIX(vhba_parent, "scsi_host")) {
            ret = 0;
            goto cleanup;
        }

        if (virSCSIHostGetNumber(vhba_parent, &parent_host) < 0)
            goto cleanup;
    }

    if (virVHBAManageVport(parent_host, fchost->wwpn, fchost->wwnn,
                           VPORT_DELETE) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(name);
    VIR_FREE(vhba_parent);
    VIR_FREE(scsi_host_name);
    return ret;
}
