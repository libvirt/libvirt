/*
 * node_device.c: node device enumeration
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#include <config.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "logging.h"
#include "node_device_conf.h"
#include "node_device_hal.h"
#include "node_device_driver.h"
#include "util.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV


static int update_caps(virNodeDeviceObjPtr dev)
{
    virNodeDevCapsDefPtr cap = dev->def->caps;

    while (cap) {
        /* The only caps that currently need updating are FC related. */
        if (cap->type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            check_fc_host(&dev->def->caps->data);
        }
        cap = cap->next;
    }

    return 0;
}


#if defined (__linux__) && defined (HAVE_HAL)
/* Under libudev changes to the driver name should be picked up as
 * "change" events, so we don't call update driver name unless we're
 * using the HAL backend. */
static int update_driver_name(virNodeDeviceObjPtr dev)
{
    char *driver_link = NULL;
    char *devpath = NULL;
    char *p;
    int ret = -1;

    VIR_FREE(dev->def->driver);

    if (virAsprintf(&driver_link, "%s/driver", dev->def->sysfs_path) < 0) {
        virReportOOMError();
        goto cleanup;
    }

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
    if (p) {
        dev->def->driver = strdup(p+1);
        if (!dev->def->driver) {
            virReportOOMError();
            goto cleanup;
        }
    }
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


void nodeDeviceLock(virDeviceMonitorStatePtr driver)
{
    virMutexLock(&driver->lock);
}
void nodeDeviceUnlock(virDeviceMonitorStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

int
nodeNumOfDevices(virConnectPtr conn,
                 const char *cap,
                 unsigned int flags)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    int ndevs = 0;
    unsigned int i;

    virCheckFlags(0, -1);

    nodeDeviceLock(driver);
    for (i = 0; i < driver->devs.count; i++) {
        virNodeDeviceObjLock(driver->devs.objs[i]);
        if ((cap == NULL) ||
            virNodeDeviceHasCap(driver->devs.objs[i], cap))
            ++ndevs;
        virNodeDeviceObjUnlock(driver->devs.objs[i]);
    }
    nodeDeviceUnlock(driver);

    return ndevs;
}

int
nodeListDevices(virConnectPtr conn,
                const char *cap,
                char **const names, int maxnames,
                unsigned int flags)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    int ndevs = 0;
    unsigned int i;

    virCheckFlags(0, -1);

    nodeDeviceLock(driver);
    for (i = 0; i < driver->devs.count && ndevs < maxnames; i++) {
        virNodeDeviceObjLock(driver->devs.objs[i]);
        if (cap == NULL ||
            virNodeDeviceHasCap(driver->devs.objs[i], cap)) {
            if ((names[ndevs++] = strdup(driver->devs.objs[i]->def->name)) == NULL) {
                virNodeDeviceObjUnlock(driver->devs.objs[i]);
                virReportOOMError();
                goto failure;
            }
        }
        virNodeDeviceObjUnlock(driver->devs.objs[i]);
    }
    nodeDeviceUnlock(driver);

    return ndevs;

 failure:
    nodeDeviceUnlock(driver);
    --ndevs;
    while (--ndevs >= 0)
        VIR_FREE(names[ndevs]);
    return -1;
}


virNodeDevicePtr
nodeDeviceLookupByName(virConnectPtr conn, const char *name)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    virNodeDevicePtr ret = NULL;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE, NULL);
        goto cleanup;
    }

    ret = virGetNodeDevice(conn, name);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


static virNodeDevicePtr
nodeDeviceLookupByWWN(virConnectPtr conn,
                      const char *wwnn,
                      const char *wwpn)
{
    unsigned int i;
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    virNodeDeviceObjListPtr devs = &driver->devs;
    virNodeDevCapsDefPtr cap = NULL;
    virNodeDeviceObjPtr obj = NULL;
    virNodeDevicePtr dev = NULL;

    nodeDeviceLock(driver);

    for (i = 0; i < devs->count; i++) {

        obj = devs->objs[i];
        virNodeDeviceObjLock(obj);
        cap = obj->def->caps;

        while (cap) {

            if (cap->type == VIR_NODE_DEV_CAP_SCSI_HOST) {
                check_fc_host(&cap->data);
                if (cap->data.scsi_host.flags &
                    VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {

                    if (STREQ(cap->data.scsi_host.wwnn, wwnn) &&
                        STREQ(cap->data.scsi_host.wwpn, wwpn)) {
                        dev = virGetNodeDevice(conn, obj->def->name);
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
    nodeDeviceUnlock(driver);
    return dev;
}


char *
nodeDeviceGetXMLDesc(virNodeDevicePtr dev,
                     unsigned int flags)
{
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    update_driver_name(obj);
    update_caps(obj);

    ret = virNodeDeviceDefFormat(obj->def);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


char *
nodeDeviceGetParent(virNodeDevicePtr dev)
{
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    if (obj->def->parent) {
        ret = strdup(obj->def->parent);
        if (!ret)
            virReportOOMError();
    } else {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
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
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    for (caps = obj->def->caps; caps; caps = caps->next)
        ++ncaps;
    ret = ncaps;

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


int
nodeDeviceListCaps(virNodeDevicePtr dev, char **const names, int maxnames)
{
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    for (caps = obj->def->caps; caps && ncaps < maxnames; caps = caps->next) {
        names[ncaps] = strdup(virNodeDevCapTypeToString(caps->type));
        if (names[ncaps++] == NULL) {
            virReportOOMError();
            goto cleanup;
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
nodeDeviceVportCreateDelete(const int parent_host,
                            const char *wwpn,
                            const char *wwnn,
                            int operation)
{
    int retval = 0;
    char *operation_path = NULL, *vport_name = NULL;
    const char *operation_file = NULL;
    struct stat st;

    switch (operation) {
    case VPORT_CREATE:
        operation_file = LINUX_SYSFS_VPORT_CREATE_POSTFIX;
        break;
    case VPORT_DELETE:
        operation_file = LINUX_SYSFS_VPORT_DELETE_POSTFIX;
        break;
    default:
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("Invalid vport operation (%d)"), operation);
        retval = -1;
        goto cleanup;
        break;
    }

    if (virAsprintf(&operation_path,
                    "%shost%d%s",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    parent_host,
                    operation_file) < 0) {

        virReportOOMError();
        retval = -1;
        goto cleanup;
    }

    if (stat(operation_path, &st) != 0) {
        VIR_FREE(operation_path);
        if (virAsprintf(&operation_path,
                        "%shost%d%s",
                        LINUX_SYSFS_SCSI_HOST_PREFIX,
                        parent_host,
                        operation_file) < 0) {
            virReportOOMError();
            retval = -1;
            goto cleanup;
        }

        if (stat(operation_path, &st) != 0) {
            VIR_ERROR(_("No vport operation path found for host%d"),
                      parent_host);
            retval = -1;
            goto cleanup;
        }
    }

    VIR_DEBUG("Vport operation path is '%s'", operation_path);

    if (virAsprintf(&vport_name,
                    "%s:%s",
                    wwpn,
                    wwnn) < 0) {

        virReportOOMError();
        retval = -1;
        goto cleanup;
    }

    if (virFileWriteStr(operation_path, vport_name, 0) == -1) {
        virReportSystemError(errno,
                             _("Write of '%s' to '%s' during "
                               "vport create/delete failed"),
                             vport_name, operation_path);
        retval = -1;
    }

cleanup:
    VIR_FREE(vport_name);
    VIR_FREE(operation_path);
    VIR_DEBUG("%s", _("Vport operation complete"));
    return retval;
}


static int
get_time(time_t *t)
{
    int ret = 0;

    *t = time(NULL);
    if (*t == (time_t)-1) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
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
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    virNodeDevicePtr dev = NULL;
    time_t start = 0, now = 0;

    /* The thread that creates the device takes the driver lock, so we
     * must release it in order to allow the device to be created.
     * We're not doing anything with the driver pointer at this point,
     * so it's safe to release it, assuming that the pointer itself
     * doesn't become invalid.  */
    nodeDeviceUnlock(driver);

    get_time(&start);

    while ((now - start) < LINUX_NEW_DEVICE_WAIT_TIME) {

        virFileWaitForDevices();

        dev = nodeDeviceLookupByWWN(conn, wwnn, wwpn);

        if (dev != NULL) {
            break;
        }

        sleep(5);
        if (get_time(&now) == -1) {
            break;
        }
    }

    nodeDeviceLock(driver);

    return dev;
}

virNodeDevicePtr
nodeDeviceCreateXML(virConnectPtr conn,
                    const char *xmlDesc,
                    unsigned int flags)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    virNodeDeviceDefPtr def = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;
    virNodeDevicePtr dev = NULL;
    const char *virt_type = NULL;

    virCheckFlags(0, NULL);
    virt_type  = virConnectGetType(conn);

    nodeDeviceLock(driver);

    def = virNodeDeviceDefParseString(xmlDesc, CREATE_DEVICE, virt_type);
    if (def == NULL) {
        goto cleanup;
    }

    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) == -1) {
        goto cleanup;
    }

    if (virNodeDeviceGetParentHost(&driver->devs,
                                   def->name,
                                   def->parent,
                                   &parent_host) == -1) {
        goto cleanup;
    }

    if (nodeDeviceVportCreateDelete(parent_host,
                                    wwpn,
                                    wwnn,
                                    VPORT_CREATE) == -1) {
        goto cleanup;
    }

    dev = find_new_device(conn, wwnn, wwpn);
    /* We don't check the return value, because one way or another,
     * we're returning what we get... */

    if (dev == NULL) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE, NULL);
    }

cleanup:
    nodeDeviceUnlock(driver);
    virNodeDeviceDefFree(def);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return dev;
}


int
nodeDeviceDestroy(virNodeDevicePtr dev)
{
    int ret = -1;
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj = NULL;
    char *parent_name = NULL, *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE, NULL);
        goto out;
    }

    if (virNodeDeviceGetWWNs(obj->def, &wwnn, &wwpn) == -1) {
        goto out;
    }

    parent_name = strdup(obj->def->parent);

    /* virNodeDeviceGetParentHost will cause the device object's lock to be
     * taken, so we have to dup the parent's name and drop the lock
     * before calling it.  We don't need the reference to the object
     * any more once we have the parent's name.  */
    virNodeDeviceObjUnlock(obj);
    obj = NULL;

    if (parent_name == NULL) {
        virReportOOMError();
        goto out;
    }

    if (virNodeDeviceGetParentHost(&driver->devs,
                                   dev->name,
                                   parent_name,
                                   &parent_host) == -1) {
        goto out;
    }

    if (nodeDeviceVportCreateDelete(parent_host,
                                    wwpn,
                                    wwnn,
                                    VPORT_DELETE) == -1) {
        goto out;
    }

    ret = 0;
out:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    VIR_FREE(parent_name);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}

int nodedevRegister(void) {
#if defined(HAVE_HAL) && defined(HAVE_UDEV)
    /* Register only one of these two - they conflict */
    if (udevNodeRegister() == -1)
        return halNodeRegister();
    return 0;
#else
# ifdef HAVE_HAL
    return halNodeRegister();
# endif
# ifdef HAVE_UDEV
    return udevNodeRegister();
# endif
#endif
}
