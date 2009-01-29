/*
 * node_device.c: node device enumeration
 *
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

#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "logging.h"
#include "node_device_conf.h"
#include "node_device.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

static int dev_has_cap(const virNodeDeviceObjPtr dev, const char *cap)
{
    virNodeDevCapsDefPtr caps = dev->def->caps;
    while (caps) {
        if (STREQ(cap, virNodeDevCapTypeToString(caps->type)))
            return 1;
        caps = caps->next;
    }
    return 0;
}


void nodeDeviceLock(virDeviceMonitorStatePtr driver)
{
    DEBUG("LOCK node %p", driver);
    virMutexLock(&driver->lock);
}
void nodeDeviceUnlock(virDeviceMonitorStatePtr driver)
{
    DEBUG("UNLOCK node %p", driver);
    virMutexUnlock(&driver->lock);
}

static int nodeNumOfDevices(virConnectPtr conn,
                            const char *cap,
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    int ndevs = 0;
    unsigned int i;

    for (i = 0; i < driver->devs.count; i++)
        if ((cap == NULL) ||
            dev_has_cap(driver->devs.objs[i], cap))
            ++ndevs;

    return ndevs;
}

static int
nodeListDevices(virConnectPtr conn,
                const char *cap,
                char **const names, int maxnames,
                unsigned int flags ATTRIBUTE_UNUSED)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    int ndevs = 0;
    unsigned int i;

    nodeDeviceLock(driver);
    for (i = 0; i < driver->devs.count && ndevs < maxnames; i++) {
        virNodeDeviceObjLock(driver->devs.objs[i]);
        if (cap == NULL ||
            dev_has_cap(driver->devs.objs[i], cap)) {
            if ((names[ndevs++] = strdup(driver->devs.objs[i]->def->name)) == NULL) {
                virNodeDeviceObjUnlock(driver->devs.objs[i]);
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


static virNodeDevicePtr nodeDeviceLookupByName(virConnectPtr conn,
                                               const char *name)
{
    virDeviceMonitorStatePtr driver = conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    virNodeDevicePtr ret = NULL;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(conn, VIR_ERR_INVALID_NODE_DEVICE,
                                 "%s", _("no node device with matching name"));
        goto cleanup;
    }

    ret = virGetNodeDevice(conn, name);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}

static char *nodeDeviceDumpXML(virNodeDevicePtr dev,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(dev->conn, VIR_ERR_INVALID_NODE_DEVICE,
                              "%s", _("no node device with matching name"));
        goto cleanup;
    }

    ret = virNodeDeviceDefFormat(dev->conn, obj->def);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


static char *nodeDeviceGetParent(virNodeDevicePtr dev)
{
    virDeviceMonitorStatePtr driver = dev->conn->devMonPrivateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    nodeDeviceLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    nodeDeviceUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(dev->conn, VIR_ERR_INVALID_NODE_DEVICE,
                              "%s", _("no node device with matching name"));
        goto cleanup;
    }

    ret = strdup(obj->def->parent);
    if (!ret)
        virReportOOMError(dev->conn);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


static int nodeDeviceNumOfCaps(virNodeDevicePtr dev)
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
        virNodeDeviceReportError(dev->conn, VIR_ERR_INVALID_NODE_DEVICE,
                              "%s", _("no node device with matching name"));
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


static int
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
        virNodeDeviceReportError(dev->conn, VIR_ERR_INVALID_NODE_DEVICE,
                              "%s", _("no node device with matching name"));
        goto cleanup;
    }

    for (caps = obj->def->caps; caps && ncaps < maxnames; caps = caps->next) {
        names[ncaps] = strdup(virNodeDevCapTypeToString(caps->type));
        if (names[ncaps++] == NULL)
            goto cleanup;
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


void registerCommonNodeFuncs(virDeviceMonitorPtr driver)
{
    driver->numOfDevices = nodeNumOfDevices;
    driver->listDevices = nodeListDevices;
    driver->deviceLookupByName = nodeDeviceLookupByName;
    driver->deviceDumpXML = nodeDeviceDumpXML;
    driver->deviceGetParent = nodeDeviceGetParent;
    driver->deviceNumOfCaps = nodeDeviceNumOfCaps;
    driver->deviceListCaps = nodeDeviceListCaps;
}


int nodedevRegister(void) {
#if defined(HAVE_HAL) && defined(HAVE_DEVKIT)
    /* Register only one of these two - they conflict */
    if (halNodeRegister() == -1)
        return devkitNodeRegister();
    return 0;
#else
#ifdef HAVE_HAL
    return halNodeRegister();
#endif
#ifdef HAVE_DEVKIT
    return devkitNodeRegister();
#endif
#endif
}
