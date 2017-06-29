/*
 * node_device_driver.c: node device enumeration
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
 * Copyright (C) 2008 Virtual Iron Software, Inc.
 * Copyright (C) 2008 David F. Lively
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
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#include <config.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "node_device_conf.h"
#include "node_device_event.h"
#include "node_device_driver.h"
#include "node_device_hal.h"
#include "node_device_linux_sysfs.h"
#include "virvhba.h"
#include "viraccessapicheck.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

virNodeDeviceDriverStatePtr driver;


static int
nodeDeviceUpdateCaps(virNodeDeviceDefPtr def)
{
    virNodeDevCapsDefPtr cap = def->caps;

    while (cap) {
        switch (cap->data.type) {
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            nodeDeviceSysfsGetSCSIHostCaps(&cap->data.scsi_host);
            break;
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            nodeDeviceSysfsGetSCSITargetCaps(def->sysfs_path,
                                             &cap->data.scsi_target);
            break;
        case VIR_NODE_DEV_CAP_NET:
            if (virNetDevGetLinkInfo(cap->data.net.ifname, &cap->data.net.lnk) < 0)
                return -1;
            virBitmapFree(cap->data.net.features);
            if (virNetDevGetFeatures(cap->data.net.ifname, &cap->data.net.features) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
           if (nodeDeviceSysfsGetPCIRelatedDevCaps(def->sysfs_path,
                                                   &cap->data.pci_dev) < 0)
              return -1;
           break;

        /* all types that (supposedly) don't require any updates
         * relative to what's in the cache.
         */
        case VIR_NODE_DEV_CAP_DRM:
        case VIR_NODE_DEV_CAP_SYSTEM:
        case VIR_NODE_DEV_CAP_USB_DEV:
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
        case VIR_NODE_DEV_CAP_SCSI:
        case VIR_NODE_DEV_CAP_STORAGE:
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        case VIR_NODE_DEV_CAP_MDEV_TYPES:
        case VIR_NODE_DEV_CAP_MDEV:
        case VIR_NODE_DEV_CAP_CCW_DEV:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }
        cap = cap->next;
    }

    return 0;
}


#if defined (__linux__) && ( defined (WITH_HAL) || defined(WITH_UDEV))
/* NB: It was previously believed that changes in driver name were
 * relayed to libvirt as "change" events by udev, and the udev event
 * notification is setup to recognize such events and effectively
 * recreate the device entry in the cache. However, neither the kernel
 * nor udev sends such an event, so it is necessary to manually update
 * the driver name for a device each time its entry is used, both for
 * udev *and* HAL backends.
 */
static int
nodeDeviceUpdateDriverName(virNodeDeviceDefPtr def)
{
    char *driver_link = NULL;
    char *devpath = NULL;
    char *p;
    int ret = -1;

    VIR_FREE(def->driver);

    if (virAsprintf(&driver_link, "%s/driver", def->sysfs_path) < 0)
        goto cleanup;

    /* Some devices don't have an explicit driver, so just return
       without a name */
    if (access(driver_link, R_OK) < 0) {
        ret = 0;
        goto cleanup;
    }

    if (virFileResolveLink(driver_link, &devpath) < 0) {
        virReportSystemError(errno,
                             _("cannot resolve driver link %s"), driver_link);
        goto cleanup;
    }

    p = strrchr(devpath, '/');
    if (p && VIR_STRDUP(def->driver, p + 1) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    VIR_FREE(driver_link);
    VIR_FREE(devpath);
    return ret;
}
#else
/* XXX: Implement me for non-linux */
static int
nodeDeviceUpdateDriverName(virNodeDeviceDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}
#endif


void
nodeDeviceLock(void)
{
    virMutexLock(&driver->lock);
}


void
nodeDeviceUnlock(void)
{
    virMutexUnlock(&driver->lock);
}


int
nodeNumOfDevices(virConnectPtr conn,
                 const char *cap,
                 unsigned int flags)
{
    if (virNodeNumOfDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    return virNodeDeviceObjListNumOfDevices(driver->devs, conn, cap,
                                            virNodeNumOfDevicesCheckACL);
}


int
nodeListDevices(virConnectPtr conn,
                const char *cap,
                char **const names,
                int maxnames,
                unsigned int flags)
{
    if (virNodeListDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    return virNodeDeviceObjListGetNames(driver->devs, conn,
                                        virNodeListDevicesCheckACL,
                                        cap, names, maxnames);
}


int
nodeConnectListAllNodeDevices(virConnectPtr conn,
                              virNodeDevicePtr **devices,
                              unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP, -1);

    if (virConnectListAllNodeDevicesEnsureACL(conn) < 0)
        return -1;

    return virNodeDeviceObjListExport(conn, driver->devs, devices,
                                      virConnectListAllNodeDevicesCheckACL,
                                      flags);
}


static virNodeDeviceObjPtr
nodeDeviceObjFindByName(const char *name)
{
    virNodeDeviceObjPtr obj;

    if (!(obj = virNodeDeviceObjListFindByName(driver->devs, name))) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       name);
    }

    return obj;
}


virNodeDevicePtr
nodeDeviceLookupByName(virConnectPtr conn,
                       const char *name)
{
    virNodeDeviceObjPtr obj;
    virNodeDeviceDefPtr def;
    virNodeDevicePtr device = NULL;

    if (!(obj = nodeDeviceObjFindByName(name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    if ((device = virGetNodeDevice(conn, name))) {
        if (VIR_STRDUP(device->parent, def->parent) < 0) {
            virObjectUnref(device);
            device = NULL;
        }
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return device;
}


virNodeDevicePtr
nodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                              const char *wwnn,
                              const char *wwpn,
                              unsigned int flags)
{
    virNodeDeviceObjPtr obj = NULL;
    virNodeDeviceDefPtr def;
    virNodeDevicePtr device = NULL;

    virCheckFlags(0, NULL);

    if (!(obj = virNodeDeviceObjListFindSCSIHostByWWNs(driver->devs,
                                                       wwnn, wwpn)))
        return NULL;

    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceLookupSCSIHostByWWNEnsureACL(conn, def) < 0)
        goto cleanup;

    if ((device = virGetNodeDevice(conn, def->name))) {
        if (VIR_STRDUP(device->parent, def->parent) < 0) {
            virObjectUnref(device);
            device = NULL;
        }
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return device;
}


char *
nodeDeviceGetXMLDesc(virNodeDevicePtr device,
                     unsigned int flags)
{
    virNodeDeviceObjPtr obj;
    virNodeDeviceDefPtr def;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceGetXMLDescEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (nodeDeviceUpdateDriverName(def) < 0)
        goto cleanup;

    if (nodeDeviceUpdateCaps(def) < 0)
        goto cleanup;

    ret = virNodeDeviceDefFormat(def);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


char *
nodeDeviceGetParent(virNodeDevicePtr device)
{
    virNodeDeviceObjPtr obj;
    virNodeDeviceDefPtr def;
    char *ret = NULL;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceGetParentEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (def->parent) {
        if (VIR_STRDUP(ret, def->parent) < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no parent for this device"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeDeviceNumOfCaps(virNodeDevicePtr device)
{
    virNodeDeviceObjPtr obj;
    virNodeDeviceDefPtr def;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceNumOfCapsEnsureACL(device->conn, def) < 0)
        goto cleanup;

    for (caps = def->caps; caps; caps = caps->next) {
        ++ncaps;

        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            if (caps->data.scsi_host.flags &
                VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST)
                ncaps++;

            if (caps->data.scsi_host.flags &
                VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS)
                ncaps++;
        }
    }

    ret = ncaps;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}



int
nodeDeviceListCaps(virNodeDevicePtr device,
                   char **const names,
                   int maxnames)
{
    virNodeDeviceObjPtr obj;
    virNodeDeviceDefPtr def;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceListCapsEnsureACL(device->conn, def) < 0)
        goto cleanup;

    for (caps = def->caps; caps && ncaps < maxnames; caps = caps->next) {
        if (VIR_STRDUP(names[ncaps++], virNodeDevCapTypeToString(caps->data.type)) < 0)
            goto cleanup;

        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            if (ncaps < maxnames &&
                caps->data.scsi_host.flags &
                VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                if (VIR_STRDUP(names[ncaps++],
                               virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_FC_HOST)) < 0)
                    goto cleanup;
            }

            if (ncaps < maxnames &&
                caps->data.scsi_host.flags &
                VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS) {
                if (VIR_STRDUP(names[ncaps++],
                               virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_VPORTS)) < 0)
                    goto cleanup;
            }
        }
    }
    ret = ncaps;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    if (ret == -1) {
        --ncaps;
        while (--ncaps >= 0)
            VIR_FREE(names[ncaps]);
    }
    return ret;
}


static int
nodeDeviceGetTime(time_t *t)
{
    int ret = 0;

    *t = time(NULL);
    if (*t == (time_t)-1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Could not get current time"));

        *t = 0;
        ret = -1;
    }

    return ret;
}


/* When large numbers of devices are present on the host, it's
 * possible for udev not to realize that it has work to do before we
 * get here.  We thus keep trying to find the new device we just
 * created for up to LINUX_NEW_DEVICE_WAIT_TIME.  Note that udev's
 * default settle time is 180 seconds, so once udev realizes that it
 * has work to do, it might take that long for the udev wait to
 * return.  Thus the total maximum time for this function to return is
 * the udev settle time plus LINUX_NEW_DEVICE_WAIT_TIME.
 *
 * This whole area is a race, but if we retry the udev wait for
 * LINUX_NEW_DEVICE_WAIT_TIME seconds and there's still no device,
 * it's probably safe to assume it's not going to appear.
 */
static virNodeDevicePtr
nodeDeviceFindNewDevice(virConnectPtr conn,
                        const char *wwnn,
                        const char *wwpn)
{
    virNodeDevicePtr device = NULL;
    time_t start = 0, now = 0;

    nodeDeviceGetTime(&start);

    while ((now - start) < LINUX_NEW_DEVICE_WAIT_TIME) {

        virWaitForDevices();

        device = nodeDeviceLookupSCSIHostByWWN(conn, wwnn, wwpn, 0);

        if (device != NULL)
            break;

        sleep(5);
        if (nodeDeviceGetTime(&now) == -1)
            break;
    }

    return device;
}


virNodeDevicePtr
nodeDeviceCreateXML(virConnectPtr conn,
                    const char *xmlDesc,
                    unsigned int flags)
{
    virNodeDeviceDefPtr def = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;
    virNodeDevicePtr device = NULL;
    const char *virt_type = NULL;

    virCheckFlags(0, NULL);
    virt_type  = virConnectGetType(conn);

    if (!(def = virNodeDeviceDefParseString(xmlDesc, CREATE_DEVICE, virt_type)))
        goto cleanup;

    if (virNodeDeviceCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) == -1)
        goto cleanup;

    if ((parent_host = virNodeDeviceObjListGetParentHost(driver->devs, def)) < 0)
        goto cleanup;

    if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_CREATE) < 0)
        goto cleanup;

    device = nodeDeviceFindNewDevice(conn, wwnn, wwpn);
    /* We don't check the return value, because one way or another,
     * we're returning what we get... */

    if (device == NULL)
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device for '%s' with matching "
                         "wwnn '%s' and wwpn '%s'"),
                       def->name, wwnn, wwpn);
 cleanup:
    virNodeDeviceDefFree(def);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return device;
}


int
nodeDeviceDestroy(virNodeDevicePtr device)
{
    int ret = -1;
    virNodeDeviceObjPtr obj = NULL;
    virNodeDeviceDefPtr def;
    char *parent = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    unsigned int parent_host;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceDestroyEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) < 0)
        goto cleanup;

    /* Because we're about to release the lock and thus run into a race
     * possibility (however improbable) with a udevAddOneDevice change
     * event which would essentially free the existing @def (obj->def) and
     * replace it with something new, we need to grab the parent field
     * and then find the parent obj in order to manage the vport */
    if (VIR_STRDUP(parent, def->parent) < 0)
        goto cleanup;

    virNodeDeviceObjEndAPI(&obj);

    if (!(obj = virNodeDeviceObjListFindByName(driver->devs, parent))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find parent '%s' definition"), parent);
        goto cleanup;
    }

    if (virSCSIHostGetNumber(parent, &parent_host) < 0)
        goto cleanup;

    if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_DELETE) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    VIR_FREE(parent);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}


int
nodeConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                      virNodeDevicePtr device,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    int callbackID = -1;

    if (virConnectNodeDeviceEventRegisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virNodeDeviceEventStateRegisterID(conn, driver->nodeDeviceEventState,
                                          device, eventID, callback,
                                          opaque, freecb, &callbackID) < 0)
        callbackID = -1;
 cleanup:
    return callbackID;
}


int
nodeConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                        int callbackID)
{
    int ret = -1;

    if (virConnectNodeDeviceEventDeregisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->nodeDeviceEventState,
                                        callbackID, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


int
nodedevRegister(void)
{
#ifdef WITH_UDEV
    return udevNodeRegister();
#else
# ifdef WITH_HAL
    return halNodeRegister();
# endif
#endif
}
