/*
 * interface_backend_udev.c: udev backend for virInterface
 *
 * Copyright (C) 2012 Doug Goldstein <cardoe@cardoe.com>
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */
#include <config.h>

#include <libudev.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "interface_driver.h"
#include "interface_conf.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

struct udev_iface_driver {
    struct udev *udev;
};

typedef enum {
    VIR_UDEV_IFACE_ACTIVE,
    VIR_UDEV_IFACE_INACTIVE,
    VIR_UDEV_IFACE_ALL
} virUdevStatus ;

static const char *
virUdevStatusString(virUdevStatus status)
{
    switch (status) {
        case VIR_UDEV_IFACE_ACTIVE:
            return "active";
        case VIR_UDEV_IFACE_INACTIVE:
            return "inactive";
        case VIR_UDEV_IFACE_ALL:
            return "all";
    }

    return "";
}

static struct udev_enumerate * ATTRIBUTE_NONNULL(1)
udevIfaceGetDevices(struct udev *udev, virUdevStatus status)
{
    struct udev_enumerate *enumerate;

    /* Create a new enumeration to create a list */
    enumerate = udev_enumerate_new(udev);

    if (!enumerate)
        return NULL;

    /* Enumerate all network subsystem devices */
    udev_enumerate_add_match_subsystem(enumerate, "net");

    /* Ignore devices that are part of a bridge */
    udev_enumerate_add_nomatch_sysattr(enumerate, "brport/state", NULL);

    /* State of the device */
    switch (status) {
        case VIR_UDEV_IFACE_ACTIVE:
            udev_enumerate_add_match_sysattr(enumerate, "operstate", "up");
            break;

        case VIR_UDEV_IFACE_INACTIVE:
            udev_enumerate_add_match_sysattr(enumerate, "operstate", "down");
            break;

        case VIR_UDEV_IFACE_ALL:
            break;
    }

    /* We don't want to see the TUN devices that QEMU creates for other guests
     * running on this machine. By saying nomatch NULL, we just are getting
     * devices without the tun_flags sysattr.
     */
    udev_enumerate_add_nomatch_sysattr(enumerate, "tun_flags", NULL);

    return enumerate;
}

static virDrvOpenStatus
udevIfaceOpenInterface(virConnectPtr conn,
                       virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                       unsigned int flags)
{
    struct udev_iface_driver *driverState = NULL;

    virCheckFlags(0, VIR_DRV_OPEN_ERROR);

    if (VIR_ALLOC(driverState) < 0) {
        virReportOOMError();
        goto err;
    }

    driverState->udev = udev_new();
    if (!driverState->udev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create udev context"));
        goto err;
    }

    conn->interfacePrivateData = driverState;

    return VIR_DRV_OPEN_SUCCESS;

err:
    VIR_FREE(driverState);

    return VIR_DRV_OPEN_ERROR;
}

static int
udevIfaceCloseInterface(virConnectPtr conn)
{
    struct udev_iface_driver *driverState;

    if (conn->interfacePrivateData != NULL) {
        driverState = conn->interfacePrivateData;

        udev_unref(driverState->udev);

        VIR_FREE(driverState);
    }

    conn->interfacePrivateData = NULL;
    return 0;
}

static int
udevIfaceNumOfInterfacesByStatus(virConnectPtr conn, virUdevStatus status)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevIfaceGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get number of %s interfaces on host"),
                       virUdevStatusString(status));
        count = -1;
        goto err;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        count++;
    }

err:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return count;
}

static int
udevIfaceListInterfacesByStatus(virConnectPtr conn,
                                char **const names,
                                int names_len,
                                virUdevStatus status)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevIfaceGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get list of %s interfaces on host"),
                       virUdevStatusString(status));
        goto err;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        struct udev_device *dev;
        const char *path;

        /* Ensure we won't exceed the size of our array */
        if (count > names_len)
            break;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);
        names[count] = strdup(udev_device_get_sysname(dev));
        udev_device_unref(dev);

        /* If strdup() failed, we are out of memory */
        if (!names[count]) {
            virReportOOMError();
            goto err;
        }

        count++;
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return count;

err:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    for (names_len = 0; names_len < count; names_len++)
        VIR_FREE(names[names_len]);

    return -1;
}

static int
udevIfaceNumOfInterfaces(virConnectPtr conn)
{
    return udevIfaceNumOfInterfacesByStatus(conn, VIR_UDEV_IFACE_ACTIVE);
}

static int
udevIfaceListInterfaces(virConnectPtr conn,
                        char **const names,
                        int names_len)
{
    return udevIfaceListInterfacesByStatus(conn, names, names_len,
                                           VIR_UDEV_IFACE_ACTIVE);
}

static int
udevIfaceNumOfDefinedInterfaces(virConnectPtr conn)
{
    return udevIfaceNumOfInterfacesByStatus(conn, VIR_UDEV_IFACE_INACTIVE);
}

static int
udevIfaceListDefinedInterfaces(virConnectPtr conn,
                               char **const names,
                               int names_len)
{
    return udevIfaceListInterfacesByStatus(conn, names, names_len,
                                           VIR_UDEV_IFACE_INACTIVE);
}

static int
udevIfaceListAllInterfaces(virConnectPtr conn,
                           virInterfacePtr **ifaces,
                           unsigned int flags)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev;
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    virInterfacePtr *ifaces_list;
    virInterfacePtr iface_obj;
    int tmp_count;
    int count = 0;
    int status = 0;
    int ret;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_ACTIVE |
                  VIR_CONNECT_LIST_INTERFACES_INACTIVE, -1);

    /* Grab a udev reference */
    udev = udev_ref(driverState->udev);

    /* List all interfaces in case we support more filter flags in the future */
    enumerate = udevIfaceGetDevices(udev, VIR_UDEV_IFACE_ALL);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get list of %s interfaces on host"),
                       virUdevStatusString(status));
        ret = -1;
        goto cleanup;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        count++;
    }

    /* If we've got nothing, exit out */
    if (count == 0) {
        ret = 0;
        goto cleanup;
    }

    /* If we're asked for the ifaces then alloc up memory */
    if (ifaces) {
        if (VIR_ALLOC_N(ifaces_list, count + 1) < 0) {
            virReportOOMError();
            ret = -1;
            goto cleanup;
        }
    }

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* reset our iterator */
    count = 0;

    /* Walk through each device */
    udev_list_entry_foreach(dev_entry, devices) {
        struct udev_device *dev;
        const char *path;
        const char *name;
        const char *macaddr;
        int add_to_list;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);
        name = udev_device_get_sysname(dev);
        macaddr = udev_device_get_sysattr_value(dev, "address");
        status = STREQ(udev_device_get_sysattr_value(dev, "operstate"), "up");
        udev_device_unref(dev);

        /* Filter the results */
        if (status && (flags & VIR_CONNECT_LIST_INTERFACES_ACTIVE))
            add_to_list = 1;
        else if (!status && (flags & VIR_CONNECT_LIST_INTERFACES_INACTIVE))
            add_to_list = 1;

        /* If we matched a filter, then add it */
        if (add_to_list) {
            if (ifaces) {
                iface_obj = virGetInterface(conn, name, macaddr);
                ifaces_list[count] = iface_obj;
            }
            count++;
        }
    }

    /* Drop our refcounts */
    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    /* Trim the array to its final size */
    if (ifaces) {
        ignore_value(VIR_REALLOC_N(ifaces_list, count + 1));
        *ifaces = ifaces_list;
    }

    return count;

cleanup:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    if (ifaces) {
        for (tmp_count = 0; tmp_count < count; tmp_count++)
            virInterfaceFree(ifaces_list[tmp_count]);
    }

    VIR_FREE(ifaces_list);

    return ret;

}

static virInterfacePtr
udevIfaceLookupByName(virConnectPtr conn, const char *name)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_device *dev;
    const char *macaddr;
    virInterfacePtr ret = NULL;

    /* get a device reference based on the device name */
    dev = udev_device_new_from_subsystem_sysname(udev, "net", name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%s'"),
                       name);
        goto err;
    }

    macaddr = udev_device_get_sysattr_value(dev, "address");
    ret = virGetInterface(conn, name, macaddr);
    udev_device_unref(dev);

err:
    udev_unref(udev);

    return ret;
}

static virInterfacePtr
udevIfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *dev_entry;
    struct udev_device *dev;
    const char *name;
    virInterfacePtr ret = NULL;

    enumerate = udevIfaceGetDevices(udev, VIR_UDEV_IFACE_ALL);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to lookup interface with MAC address '%s'"),
                       macstr);
        goto err;
    }

    /* Match on MAC */
    udev_enumerate_add_match_sysattr(enumerate, "address", macstr);

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    dev_entry = udev_enumerate_get_list_entry(enumerate);

    /* Check that we got something back */
    if (!dev_entry) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface with MAC address '%s'"),
                       macstr);
        goto err;
    }

    /* Check that we didn't get multiple items back */
    if (udev_list_entry_get_next(dev_entry)) {
        virReportError(VIR_ERR_MULTIPLE_INTERFACES,
                       _("the MAC address '%s' matches multiple interfaces"),
                       macstr);
        goto err;
    }

    dev = udev_device_new_from_syspath(udev, udev_list_entry_get_name(dev_entry));
    name = udev_device_get_sysname(dev);
    ret = virGetInterface(conn, name, macstr);
    udev_device_unref(dev);

err:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return ret;
}

static int
udevIfaceIsActive(virInterfacePtr ifinfo)
{
    struct udev_iface_driver *driverState = ifinfo->conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_device *dev;
    int status;

    dev = udev_device_new_from_subsystem_sysname(udev, "net",
                                                 ifinfo->name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%s'"),
                       ifinfo->name);
        status = -1;
        goto cleanup;
    }

    /* Check if it's active or not */
    status = STREQ(udev_device_get_sysattr_value(dev, "operstate"), "up");

    udev_device_unref(dev);

cleanup:
    udev_unref(udev);

    return status;
}

static virInterfaceDriver udevIfaceDriver = {
    "udev",
    .open = udevIfaceOpenInterface, /* 0.10.3 */
    .close = udevIfaceCloseInterface, /* 0.10.3 */
    .numOfInterfaces = udevIfaceNumOfInterfaces, /* 0.10.3 */
    .listInterfaces = udevIfaceListInterfaces, /* 0.10.3 */
    .numOfDefinedInterfaces = udevIfaceNumOfDefinedInterfaces, /* 0.10.3 */
    .listDefinedInterfaces = udevIfaceListDefinedInterfaces, /* 0.10.3 */
    .listAllInterfaces = udevIfaceListAllInterfaces, /* 0.10.3 */
    .interfaceLookupByName = udevIfaceLookupByName, /* 0.10.3 */
    .interfaceLookupByMACString = udevIfaceLookupByMACString, /* 0.10.3 */
    .interfaceIsActive = udevIfaceIsActive, /* 0.10.3 */
};

int
udevIfaceRegister(void) {
    if (virRegisterInterfaceDriver(&udevIfaceDriver) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to register udev interface driver"));
        return -1;
    }
    return 0;
}
