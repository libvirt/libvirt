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

static int update_caps(virNodeDeviceObjPtr dev)
{
    virNodeDevCapsDefPtr cap = dev->def->caps;

    while (cap) {
        switch (cap->data.type) {
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            nodeDeviceSysfsGetSCSIHostCaps(&dev->def->caps->data.scsi_host);
            break;
        case VIR_NODE_DEV_CAP_NET:
            if (virNetDevGetLinkInfo(cap->data.net.ifname, &cap->data.net.lnk) < 0)
                return -1;
            virBitmapFree(cap->data.net.features);
            if (virNetDevGetFeatures(cap->data.net.ifname, &cap->data.net.features) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
           if (nodeDeviceSysfsGetPCIRelatedDevCaps(dev->def->sysfs_path,
                                                   &dev->def->caps->data.pci_dev) < 0)
              return -1;
           break;

        /* all types that (supposedly) don't require any updates
         * relative to what's in the cache.
         */
        case VIR_NODE_DEV_CAP_DRM:
        case VIR_NODE_DEV_CAP_SYSTEM:
        case VIR_NODE_DEV_CAP_USB_DEV:
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
        case VIR_NODE_DEV_CAP_SCSI:
        case VIR_NODE_DEV_CAP_STORAGE:
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
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
static int update_driver_name(virNodeDeviceObjPtr dev)
{
    char *driver_link = NULL;
    char *devpath = NULL;
    char *p;
    int ret = -1;

    VIR_FREE(dev->def->driver);

    if (virAsprintf(&driver_link, "%s/driver", dev->def->sysfs_path) < 0)
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
    if (p && VIR_STRDUP(dev->def->driver, p + 1) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    VIR_FREE(driver_link);
    VIR_FREE(devpath);
    return ret;
}
#else
/* XXX: Implement me for non-linux */
static int update_driver_name(virNodeDeviceObjPtr dev ATTRIBUTE_UNUSED)
{
    return 0;
}
#endif


void nodeDeviceLock(void)
{
    virMutexLock(&driver->lock);
}
void nodeDeviceUnlock(void)
{
    virMutexUnlock(&driver->lock);
}

int
nodeNumOfDevices(virConnectPtr conn,
                 const char *cap,
                 unsigned int flags)
{
    int ndevs = 0;

    if (virNodeNumOfDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    nodeDeviceLock();
    ndevs = virNodeDeviceObjNumOfDevices(&driver->devs, conn, cap,
                                         virNodeNumOfDevicesCheckACL);
    nodeDeviceUnlock();

    return ndevs;
}

int
nodeListDevices(virConnectPtr conn,
                const char *cap,
                char **const names, int maxnames,
                unsigned int flags)
{
    int ndevs = 0;
    size_t i;

    if (virNodeListDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    nodeDeviceLock();
    for (i = 0; i < driver->devs.count && ndevs < maxnames; i++) {
        virNodeDeviceObjPtr obj = driver->devs.objs[i];
        virNodeDeviceObjLock(obj);
        if (virNodeListDevicesCheckACL(conn, obj->def) &&
            (cap == NULL ||
             virNodeDeviceObjHasCap(obj, cap))) {
            if (VIR_STRDUP(names[ndevs++], obj->def->name) < 0) {
                virNodeDeviceObjUnlock(obj);
                goto failure;
            }
        }
        virNodeDeviceObjUnlock(obj);
    }
    nodeDeviceUnlock();

    return ndevs;

 failure:
    nodeDeviceUnlock();
    --ndevs;
    while (--ndevs >= 0)
        VIR_FREE(names[ndevs]);
    return -1;
}

int
nodeConnectListAllNodeDevices(virConnectPtr conn,
                              virNodeDevicePtr **devices,
                              unsigned int flags)
{
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP, -1);

    if (virConnectListAllNodeDevicesEnsureACL(conn) < 0)
        return -1;

    nodeDeviceLock();
    ret = virNodeDeviceObjListExport(conn, driver->devs, devices,
                                     virConnectListAllNodeDevicesCheckACL,
                                     flags);
    nodeDeviceUnlock();
    return ret;
}

virNodeDevicePtr
nodeDeviceLookupByName(virConnectPtr conn, const char *name)
{
    virNodeDeviceObjPtr obj;
    virNodeDevicePtr ret = NULL;

    nodeDeviceLock();
    obj = virNodeDeviceObjFindByName(&driver->devs, name);
    nodeDeviceUnlock();

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       name);
        goto cleanup;
    }

    if (virNodeDeviceLookupByNameEnsureACL(conn, obj->def) < 0)
        goto cleanup;

    if ((ret = virGetNodeDevice(conn, name))) {
        if (VIR_STRDUP(ret->parent, obj->def->parent) < 0)
            virObjectUnref(ret);
    }

 cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


virNodeDevicePtr
nodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                              const char *wwnn,
                              const char *wwpn,
                              unsigned int flags)
{
    size_t i;
    virNodeDeviceObjListPtr devs = &driver->devs;
    virNodeDevCapsDefPtr cap = NULL;
    virNodeDeviceObjPtr obj = NULL;
    virNodeDevicePtr dev = NULL;

    virCheckFlags(0, NULL);

    nodeDeviceLock();

    for (i = 0; i < devs->count; i++) {
        obj = devs->objs[i];
        virNodeDeviceObjLock(obj);
        cap = obj->def->caps;

        while (cap) {
            if (cap->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
                nodeDeviceSysfsGetSCSIHostCaps(&cap->data.scsi_host);
                if (cap->data.scsi_host.flags &
                    VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                    if (STREQ(cap->data.scsi_host.wwnn, wwnn) &&
                        STREQ(cap->data.scsi_host.wwpn, wwpn)) {

                        if (virNodeDeviceLookupSCSIHostByWWNEnsureACL(conn, obj->def) < 0)
                            goto out;

                        if ((dev = virGetNodeDevice(conn, obj->def->name))) {
                            if (VIR_STRDUP(dev->parent, obj->def->parent) < 0)
                                virObjectUnref(dev);
                        }
                        virNodeDeviceObjUnlock(obj);
                        goto out;
                    }
                }
            }
            cap = cap->next;
        }

        virNodeDeviceObjUnlock(obj);
    }

 out:
    nodeDeviceUnlock();
    return dev;
}


char *
nodeDeviceGetXMLDesc(virNodeDevicePtr dev,
                     unsigned int flags)
{
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    nodeDeviceLock();
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock();

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (virNodeDeviceGetXMLDescEnsureACL(dev->conn, obj->def) < 0)
        goto cleanup;

    update_driver_name(obj);
    if (update_caps(obj) < 0)
        goto cleanup;

    ret = virNodeDeviceDefFormat(obj->def);

 cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


char *
nodeDeviceGetParent(virNodeDevicePtr dev)
{
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    nodeDeviceLock();
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock();

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (virNodeDeviceGetParentEnsureACL(dev->conn, obj->def) < 0)
        goto cleanup;

    if (obj->def->parent) {
        if (VIR_STRDUP(ret, obj->def->parent) < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no parent for this device"));
    }

 cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


int
nodeDeviceNumOfCaps(virNodeDevicePtr dev)
{
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    nodeDeviceLock();
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock();

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (virNodeDeviceNumOfCapsEnsureACL(dev->conn, obj->def) < 0)
        goto cleanup;

    for (caps = obj->def->caps; caps; caps = caps->next) {
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
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


int
nodeDeviceListCaps(virNodeDevicePtr dev, char **const names, int maxnames)
{
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    nodeDeviceLock();
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock();

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (virNodeDeviceListCapsEnsureACL(dev->conn, obj->def) < 0)
        goto cleanup;

    for (caps = obj->def->caps; caps && ncaps < maxnames; caps = caps->next) {
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
    if (obj)
        virNodeDeviceObjUnlock(obj);
    if (ret == -1) {
        --ncaps;
        while (--ncaps >= 0)
            VIR_FREE(names[ncaps]);
    }
    return ret;
}

static int
get_time(time_t *t)
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
find_new_device(virConnectPtr conn, const char *wwnn, const char *wwpn)
{
    virNodeDevicePtr dev = NULL;
    time_t start = 0, now = 0;

    /* The thread that creates the device takes the driver lock, so we
     * must release it in order to allow the device to be created.
     * We're not doing anything with the driver pointer at this point,
     * so it's safe to release it, assuming that the pointer itself
     * doesn't become invalid.  */
    nodeDeviceUnlock();

    get_time(&start);

    while ((now - start) < LINUX_NEW_DEVICE_WAIT_TIME) {

        virWaitForDevices();

        dev = nodeDeviceLookupSCSIHostByWWN(conn, wwnn, wwpn, 0);

        if (dev != NULL)
            break;

        sleep(5);
        if (get_time(&now) == -1)
            break;
    }

    nodeDeviceLock();

    return dev;
}

virNodeDevicePtr
nodeDeviceCreateXML(virConnectPtr conn,
                    const char *xmlDesc,
                    unsigned int flags)
{
    virNodeDeviceDefPtr def = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;
    virNodeDevicePtr dev = NULL;
    const char *virt_type = NULL;

    virCheckFlags(0, NULL);
    virt_type  = virConnectGetType(conn);

    nodeDeviceLock();

    if (!(def = virNodeDeviceDefParseString(xmlDesc, CREATE_DEVICE, virt_type)))
        goto cleanup;

    if (virNodeDeviceCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) == -1)
        goto cleanup;

    if ((parent_host = virNodeDeviceObjGetParentHost(&driver->devs, def,
                                                     CREATE_DEVICE)) < 0)
        goto cleanup;

    if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_CREATE) < 0)
        goto cleanup;

    dev = find_new_device(conn, wwnn, wwpn);
    /* We don't check the return value, because one way or another,
     * we're returning what we get... */

    if (dev == NULL)
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device for '%s' with matching "
                         "wwnn '%s' and wwpn '%s'"),
                       def->name, wwnn, wwpn);
 cleanup:
    nodeDeviceUnlock();
    virNodeDeviceDefFree(def);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return dev;
}


int
nodeDeviceDestroy(virNodeDevicePtr dev)
{
    int ret = -1;
    virNodeDeviceObjPtr obj = NULL;
    virNodeDeviceDefPtr def;
    char *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;

    nodeDeviceLock();
    if (!(obj = virNodeDeviceObjFindByName(&driver->devs, dev->name))) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (virNodeDeviceDestroyEnsureACL(dev->conn, obj->def) < 0)
        goto cleanup;

    if (virNodeDeviceGetWWNs(obj->def, &wwnn, &wwpn) < 0)
        goto cleanup;

    /* virNodeDeviceGetParentHost will cause the device object's lock
     * to be taken, so grab the object def which will have the various
     * fields used to search (name, parent, parent_wwnn, parent_wwpn,
     * or parent_fabric_wwn) and drop the object lock. */
    def = obj->def;
    virNodeDeviceObjUnlock(obj);
    obj = NULL;
    if ((parent_host = virNodeDeviceObjGetParentHost(&driver->devs, def,
                                                     EXISTING_DEVICE)) < 0)
        goto cleanup;

    if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_DELETE) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    nodeDeviceUnlock();
    if (obj)
        virNodeDeviceObjUnlock(obj);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}

int
nodeConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                      virNodeDevicePtr dev,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    int callbackID = -1;

    if (virConnectNodeDeviceEventRegisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virNodeDeviceEventStateRegisterID(conn, driver->nodeDeviceEventState,
                                          dev, eventID, callback,
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
                                        callbackID) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}

int nodedevRegister(void)
{
#ifdef WITH_UDEV
    return udevNodeRegister();
#else
# ifdef WITH_HAL
    return halNodeRegister();
# endif
#endif
}
