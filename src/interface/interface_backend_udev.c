/*
 * interface_backend_udev.c: udev backend for virInterface
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include <errno.h>
#include <dirent.h>
#include <libudev.h>

#include "virerror.h"
#include "c-ctype.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "interface_driver.h"
#include "interface_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

struct udev_iface_driver {
    struct udev *udev;
};

typedef enum {
    VIR_UDEV_IFACE_ACTIVE,
    VIR_UDEV_IFACE_INACTIVE,
    VIR_UDEV_IFACE_ALL
} virUdevStatus;

static virInterfaceDef *udevGetIfaceDef(struct udev *udev, const char *name);

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

/*
 * Get a minimal virInterfaceDef containing enough metadata
 * for access control checks to be performed. Currently
 * this implies existance of name and mac address attributes
 */
static virInterfaceDef * ATTRIBUTE_NONNULL(1)
udevGetMinimalDefForDevice(struct udev_device *dev)
{
    virInterfaceDef *def;

    /* Allocate our interface definition structure */
    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (VIR_STRDUP(def->name, udev_device_get_sysname(dev)) < 0)
        goto cleanup;

    if (VIR_STRDUP(def->mac, udev_device_get_sysattr_value(dev, "address")) < 0)
        goto cleanup;

    return def;

 cleanup:
    virInterfaceDefFree(def);
    return NULL;
}


static struct udev_enumerate * ATTRIBUTE_NONNULL(1)
udevGetDevices(struct udev *udev, virUdevStatus status)
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
udevInterfaceOpen(virConnectPtr conn,
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    struct udev_iface_driver *driverState = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (VIR_ALLOC(driverState) < 0)
        goto cleanup;

    driverState->udev = udev_new();
    if (!driverState->udev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create udev context"));
        goto cleanup;
    }

    conn->interfacePrivateData = driverState;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    VIR_FREE(driverState);

    return VIR_DRV_OPEN_ERROR;
}

static int
udevInterfaceClose(virConnectPtr conn)
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
udevNumOfInterfacesByStatus(virConnectPtr conn, virUdevStatus status,
                            virInterfaceObjListFilter filter)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get number of %s interfaces on host"),
                       virUdevStatusString(status));
        count = -1;
        goto cleanup;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        struct udev_device *dev;
        const char *path;
        virInterfaceDefPtr def;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);

        def = udevGetMinimalDefForDevice(dev);
        if (filter(conn, def))
            count++;
        udev_device_unref(dev);
        virInterfaceDefFree(def);
    }

 cleanup:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return count;
}

static int
udevListInterfacesByStatus(virConnectPtr conn,
                           char **const names,
                           int names_len,
                           virUdevStatus status,
                           virInterfaceObjListFilter filter)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get list of %s interfaces on host"),
                       virUdevStatusString(status));
        goto error;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        struct udev_device *dev;
        const char *path;
        virInterfaceDefPtr def;

        /* Ensure we won't exceed the size of our array */
        if (count > names_len)
            break;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);

        def = udevGetMinimalDefForDevice(dev);
        if (filter(conn, def)) {
            if (VIR_STRDUP(names[count], udev_device_get_sysname(dev)) < 0) {
                udev_device_unref(dev);
                virInterfaceDefFree(def);
                goto error;
            }
            count++;
        }
        udev_device_unref(dev);
        virInterfaceDefFree(def);
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return count;

 error:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);

    for (names_len = 0; names_len < count; names_len++)
        VIR_FREE(names[names_len]);

    return -1;
}

static int
udevConnectNumOfInterfaces(virConnectPtr conn)
{
    if (virConnectNumOfInterfacesEnsureACL(conn) < 0)
        return -1;

    return udevNumOfInterfacesByStatus(conn, VIR_UDEV_IFACE_ACTIVE,
                                       virConnectNumOfInterfacesCheckACL);
}

static int
udevConnectListInterfaces(virConnectPtr conn,
                          char **const names,
                          int names_len)
{
    if (virConnectListInterfacesEnsureACL(conn) < 0)
        return -1;

    return udevListInterfacesByStatus(conn, names, names_len,
                                      VIR_UDEV_IFACE_ACTIVE,
                                      virConnectListInterfacesCheckACL);
}

static int
udevConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    if (virConnectNumOfDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    return udevNumOfInterfacesByStatus(conn, VIR_UDEV_IFACE_INACTIVE,
                                       virConnectNumOfDefinedInterfacesCheckACL);
}

static int
udevConnectListDefinedInterfaces(virConnectPtr conn,
                                 char **const names,
                                 int names_len)
{
    if (virConnectListDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    return udevListInterfacesByStatus(conn, names, names_len,
                                      VIR_UDEV_IFACE_INACTIVE,
                                      virConnectListDefinedInterfacesCheckACL);
}

#define MATCH(FLAG) (flags & (FLAG))
static int
udevConnectListAllInterfaces(virConnectPtr conn,
                             virInterfacePtr **ifaces,
                             unsigned int flags)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev;
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    virInterfacePtr *ifaces_list = NULL;
    virInterfacePtr iface_obj;
    int tmp_count;
    int count = 0;
    int status = 0;
    int ret;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE, -1);

    if (virConnectListAllInterfacesEnsureACL(conn) < 0)
        return -1;

    /* Grab a udev reference */
    udev = udev_ref(driverState->udev);

    /* List all interfaces in case we support more filter flags in the future */
    enumerate = udevGetDevices(udev, VIR_UDEV_IFACE_ALL);

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
    if (ifaces && VIR_ALLOC_N(ifaces_list, count + 1) < 0) {
        ret = -1;
        goto cleanup;
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
        virInterfaceDefPtr def;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);
        name = udev_device_get_sysname(dev);
        macaddr = udev_device_get_sysattr_value(dev, "address");
        status = STREQ(udev_device_get_sysattr_value(dev, "operstate"), "up");

        def = udevGetMinimalDefForDevice(dev);
        if (!virConnectListAllInterfacesCheckACL(conn, def)) {
            udev_device_unref(dev);
            virInterfaceDefFree(def);
            continue;
        }
        virInterfaceDefFree(def);

        /* Filter the results */
        if (MATCH(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE) &&
            !((MATCH(VIR_CONNECT_LIST_INTERFACES_ACTIVE) && status) ||
              (MATCH(VIR_CONNECT_LIST_INTERFACES_INACTIVE) && !status))) {
            udev_device_unref(dev);
            continue;
        }

        /* If we matched a filter, then add it */
        if (ifaces) {
            iface_obj = virGetInterface(conn, name, macaddr);
            ifaces_list[count++] = iface_obj;
        }
        udev_device_unref(dev);
    }

    /* Drop our refcounts */
    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    /* Trim the array to its final size */
    if (ifaces) {
        ignore_value(VIR_REALLOC_N(ifaces_list, count + 1));
        *ifaces = ifaces_list;
        ifaces_list = NULL;
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
udevInterfaceLookupByName(virConnectPtr conn, const char *name)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_device *dev;
    virInterfacePtr ret = NULL;
    virInterfaceDefPtr def = NULL;

    /* get a device reference based on the device name */
    dev = udev_device_new_from_subsystem_sysname(udev, "net", name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%s'"),
                       name);
        goto cleanup;
    }

    if (!(def = udevGetMinimalDefForDevice(dev)))
        goto cleanup;

    if (virInterfaceLookupByNameEnsureACL(conn, def) < 0)
       goto cleanup;

    ret = virGetInterface(conn, def->name, def->mac);
    udev_device_unref(dev);

 cleanup:
    udev_unref(udev);
    virInterfaceDefFree(def);

    return ret;
}

static virInterfacePtr
udevInterfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    struct udev_iface_driver *driverState = conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *dev_entry;
    struct udev_device *dev;
    virInterfaceDefPtr def = NULL;
    virInterfacePtr ret = NULL;

    enumerate = udevGetDevices(udev, VIR_UDEV_IFACE_ALL);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to lookup interface with MAC address '%s'"),
                       macstr);
        goto cleanup;
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
        goto cleanup;
    }

    /* Check that we didn't get multiple items back */
    if (udev_list_entry_get_next(dev_entry)) {
        virReportError(VIR_ERR_MULTIPLE_INTERFACES,
                       _("the MAC address '%s' matches multiple interfaces"),
                       macstr);
        goto cleanup;
    }

    dev = udev_device_new_from_syspath(udev, udev_list_entry_get_name(dev_entry));

    if (!(def = udevGetMinimalDefForDevice(dev)))
        goto cleanup;

    if (virInterfaceLookupByMACStringEnsureACL(conn, def) < 0)
       goto cleanup;

    ret = virGetInterface(conn, def->name, def->mac);
    udev_device_unref(dev);

 cleanup:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);
    virInterfaceDefFree(def);

    return ret;
}

/**
 * Helper function for finding bond slaves using scandir()
 *
 * @param entry - directory entry passed by scandir()
 *
 * @return 1 if we want to add it to scandir's list, 0 if not.
 */
static int
udevBondScanDirFilter(const struct dirent *entry)
{
    /* This is ugly so if anyone has a better suggestion, please improve
     * this. Unfortunately the kernel stores everything in the top level
     * interface sysfs entry and references the slaves as slave_eth0 for
     * example.
     */
    if (STRPREFIX(entry->d_name, "slave_"))
        return 1;

    return 0;
}

/**
 * Helper function for finding bridge members using scandir()
 *
 * @param entry - directory entry passed by scandir()
 *
 * @return 1 if we want to add it to scandir's list, 0 if not.
 */
static int
udevBridgeScanDirFilter(const struct dirent *entry)
{
    if (STREQ(entry->d_name, ".") || STREQ(entry->d_name, ".."))
        return 0;

    /* Omit the domain interfaces from the list of bridge attached
     * devices. All we can do is check for the device name matching
     * vnet%d. Improvements to this check are welcome.
     */
    if (strlen(entry->d_name) >= 5) {
        if (STRPREFIX(entry->d_name, VIR_NET_GENERATED_PREFIX) &&
            c_isdigit(entry->d_name[4]))
            return 0;
    }

    return 1;
}


static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK
udevGetIfaceDefBond(struct udev *udev,
                    struct udev_device *dev,
                    const char *name,
                    virInterfaceDef *ifacedef)
{
    struct dirent **slave_list = NULL;
    int slave_count = 0;
    size_t i;
    const char *tmp_str;
    int tmp_int;

    /* Initial defaults */
    ifacedef->data.bond.target = NULL;
    ifacedef->data.bond.nbItf = 0;
    ifacedef->data.bond.itf = NULL;

    /* Set the bond specifics */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/downdelay");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/downdelay' for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/downdelay' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.downdelay = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/updelay");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/updelay' for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/updelay' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.updelay = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/miimon");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/miimon' for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/miimon' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.frequency = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/arp_interval");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/arp_interval' for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/arp_interval' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.interval = tmp_int;

    /* bonding/mode is in the format: "balance-rr 0" so we find the
     * space and increment the pointer to get the number and convert
     * it to an interger. libvirt uses 1 through 7 while the raw
     * number is 0 through 6 so increment it by 1.
     */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/mode");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/mode' for '%s'"), name);
        goto error;
    }
    tmp_str = strchr(tmp_str, ' ');
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Invalid format for 'bonding/mode' for '%s'"), name);
        goto error;
    }
    if (strlen(tmp_str) < 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Unable to find correct value in 'bonding/mode' for '%s'"),
                name);
        goto error;
    }
    if (virStrToLong_i(tmp_str + 1, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/mode' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.mode = tmp_int + 1;

    /* bonding/arp_validate is in the format: "none 0" so we find the
     * space and increment the pointer to get the number and convert
     * it to an interger.
     */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/arp_validate");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/arp_validate' for '%s'"), name);
        goto error;
    }
    tmp_str = strchr(tmp_str, ' ');
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Invalid format for 'bonding/arp_validate' for '%s'"), name);
        goto error;
    }
    if (strlen(tmp_str) < 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Unable to find correct value in 'bonding/arp_validate' "
                "for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str + 1, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/arp_validate' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.validate = tmp_int;

    /* bonding/use_carrier is 0 or 1 and libvirt stores it as 1 or 2. */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/use_carrier");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/use_carrier' for '%s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/use_carrier' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.carrier = tmp_int + 1;

    /* MII or ARP Monitoring is based on arp_interval and miimon.
     * if arp_interval > 0 then ARP monitoring is in play, if
     * miimon > 0 then MII monitoring is in play.
     */
    if (ifacedef->data.bond.interval > 0)
        ifacedef->data.bond.monit = VIR_INTERFACE_BOND_MONIT_ARP;
    else if (ifacedef->data.bond.frequency > 0)
        ifacedef->data.bond.monit = VIR_INTERFACE_BOND_MONIT_MII;
    else
        ifacedef->data.bond.monit = VIR_INTERFACE_BOND_MONIT_NONE;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/arp_ip_target");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/arp_ip_target' for '%s'"), name);
        goto error;
    }
    if (VIR_STRDUP(ifacedef->data.bond.target, tmp_str) < 0)
        goto error;

    /* Slaves of the bond */
    /* Get each slave in the bond */
    slave_count = scandir(udev_device_get_syspath(dev), &slave_list,
            udevBondScanDirFilter, alphasort);

    if (slave_count < 0) {
        virReportSystemError(errno,
                _("Could not get slaves of bond '%s'"), name);
        goto error;
    }

    /* Allocate our list of slave devices */
    if (VIR_ALLOC_N(ifacedef->data.bond.itf, slave_count) < 0)
        goto error;
    ifacedef->data.bond.nbItf = slave_count;

    for (i = 0; i < slave_count; i++) {
        /* Names are slave_interface. e.g. slave_eth0
         * so we use the part after the _
         */
        tmp_str = strchr(slave_list[i]->d_name, '_');
        if (!tmp_str || strlen(tmp_str) < 2) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid enslaved interface name '%s' seen for "
                             "bond '%s'"), slave_list[i]->d_name, name);
            goto error;
        }
        /* go past the _ */
        tmp_str++;

        ifacedef->data.bond.itf[i] =
            udevGetIfaceDef(udev, tmp_str);
        if (!ifacedef->data.bond.itf[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not get interface information for '%s', which is "
                  "a enslaved in bond '%s'"), slave_list[i]->d_name, name);
            goto error;
        }
        VIR_FREE(slave_list[i]);
    }

    VIR_FREE(slave_list);

    return 0;

 error:
    for (i = 0; slave_count != -1 && i < slave_count; i++) {
        VIR_FREE(slave_list[i]);
    }
    VIR_FREE(slave_list);

    return -1;
}

static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK
udevGetIfaceDefBridge(struct udev *udev,
                      struct udev_device *dev,
                      const char *name,
                      virInterfaceDef *ifacedef)
{
    struct dirent **member_list = NULL;
    int member_count = 0;
    char *member_path;
    const char *tmp_str;
    int stp;
    size_t i;

    /* Set our type to Bridge  */
    ifacedef->type = VIR_INTERFACE_TYPE_BRIDGE;

    /* Retrieve the forward delay */
    tmp_str = udev_device_get_sysattr_value(dev, "bridge/forward_delay");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bridge/forward_delay' for '%s'"), name);
        goto error;
    }

    if (VIR_STRDUP(ifacedef->data.bridge.delay, tmp_str) < 0)
        goto error;

    /* Retrieve Spanning Tree State. Valid values = -1, 0, 1 */
    tmp_str = udev_device_get_sysattr_value(dev, "bridge/stp_state");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            _("Could not retrieve 'bridge/stp_state' for '%s'"), name);
        goto error;
    }

    if (virStrToLong_i(tmp_str, NULL, 10, &stp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bridge/stp_state' '%s' for '%s'"),
                tmp_str, name);
        goto error;
    }

    switch (stp) {
    case -1:
    case 0:
    case 1:
        ifacedef->data.bridge.stp = stp;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
            _("Invalid STP state value %d received for '%s'. Must be "
              "-1, 0, or 1."), stp, name);
        goto error;
    }

    /* Members of the bridge */
    if (virAsprintf(&member_path, "%s/%s",
                udev_device_get_syspath(dev), "brif") < 0)
        goto error;

    /* Get each member of the bridge */
    member_count = scandir(member_path, &member_list,
            udevBridgeScanDirFilter, alphasort);

    /* Don't need the path anymore */
    VIR_FREE(member_path);

    if (member_count < 0) {
        virReportSystemError(errno,
                _("Could not get members of bridge '%s'"),
                name);
        goto error;
    }

    /* Allocate our list of member devices */
    if (VIR_ALLOC_N(ifacedef->data.bridge.itf, member_count) < 0)
        goto error;
    ifacedef->data.bridge.nbItf = member_count;

    /* Get the interface defintions for each member of the bridge */
    for (i = 0; i < member_count; i++) {
        ifacedef->data.bridge.itf[i] =
            udevGetIfaceDef(udev, member_list[i]->d_name);
        if (!ifacedef->data.bridge.itf[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not get interface information for '%s', which is "
                  "a member of bridge '%s'"), member_list[i]->d_name, name);
            goto error;
        }
        VIR_FREE(member_list[i]);
    }

    VIR_FREE(member_list);

    return 0;

 error:
    for (i = 0; member_count != -1 && i < member_count; i++) {
        VIR_FREE(member_list[i]);
    }
    VIR_FREE(member_list);

    return -1;
}

static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK
udevGetIfaceDefVlan(struct udev *udev ATTRIBUTE_UNUSED,
                    struct udev_device *dev ATTRIBUTE_UNUSED,
                    const char *name,
                    virInterfaceDef *ifacedef)
{
    const char *vid;

    /* Find the DEVICE.VID again */
    vid = strrchr(name, '.');
    if (!vid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find the VID for the VLAN device '%s'"),
                       name);
        return -1;
    }

    /* Set the VLAN specifics */
    if (VIR_STRDUP(ifacedef->data.vlan.tag, vid + 1) < 0)
        goto error;
    if (VIR_STRNDUP(ifacedef->data.vlan.devname,
                    name, (vid - name)) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(ifacedef->data.vlan.tag);
    VIR_FREE(ifacedef->data.vlan.devname);

    return -1;
}

static virInterfaceDef * ATTRIBUTE_NONNULL(1)
udevGetIfaceDef(struct udev *udev, const char *name)
{
    struct udev_device *dev = NULL;
    virInterfaceDef *ifacedef;
    unsigned int mtu;
    const char *mtu_str;
    char *vlan_parent_dev = NULL;
    const char *devtype;

    /* Allocate our interface definition structure */
    if (VIR_ALLOC(ifacedef) < 0)
        return NULL;

    /* Clear our structure and set safe defaults */
    ifacedef->startmode = VIR_INTERFACE_START_UNSPECIFIED;
    if (VIR_STRDUP(ifacedef->name, name) < 0)
        goto error;

    /* Lookup the device we've been asked about */
    dev = udev_device_new_from_subsystem_sysname(udev, "net", name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%s'"), name);
        goto error;
    }

    /* MAC address */
    if (VIR_STRDUP(ifacedef->mac,
                   udev_device_get_sysattr_value(dev, "address")) < 0)
        goto error;

    /* MTU */
    mtu_str = udev_device_get_sysattr_value(dev, "mtu");
    if (virStrToLong_ui(mtu_str, NULL, 10, &mtu) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse MTU value '%s'"), mtu_str);
        goto error;
    }
    ifacedef->mtu = mtu;

    /* Number of IP protocols this interface has assigned */
    /* XXX: Do we want a netlink query or a call out to ip or leave it? */
    ifacedef->nprotos = 0;
    ifacedef->protos = NULL;

    /* Check the type of device we are working with based on the devtype */
    devtype = udev_device_get_devtype(dev);

    /* Set our type to ethernet as the default case */
    ifacedef->type = VIR_INTERFACE_TYPE_ETHERNET;

    if (STREQ_NULLABLE(devtype, "vlan")) {
        /* This only works on modern kernels (3.7 and newer)
         * e949b09b71d975a82f13ac88ce4ad338fed213da
         */
        ifacedef->type = VIR_INTERFACE_TYPE_VLAN;
    } else if (STREQ_NULLABLE(devtype, "bridge")) {
        ifacedef->type = VIR_INTERFACE_TYPE_BRIDGE;
    } else if (STREQ_NULLABLE(devtype, "bond")) {
        /* This only works on modern kernels (3.9 and newer) */
        ifacedef->type = VIR_INTERFACE_TYPE_BOND;
    }

    /* Fallback checks if the devtype check didn't work. */
    if (ifacedef->type == VIR_INTERFACE_TYPE_ETHERNET) {
        /* First check if its a VLAN based on the name containing a dot,
         * to prevent false positives
         */
        vlan_parent_dev = strrchr(name, '.');
        if (vlan_parent_dev) {
            ifacedef->type = VIR_INTERFACE_TYPE_VLAN;
        }

        /* Fallback check to see if this is a bond device */
        if (udev_device_get_sysattr_value(dev, "bonding/mode")) {
            ifacedef->type = VIR_INTERFACE_TYPE_BOND;
        }
    }

    switch (ifacedef->type) {
    case VIR_INTERFACE_TYPE_VLAN:
        if (udevGetIfaceDefVlan(udev, dev, name, ifacedef) < 0)
            goto error;
        break;
    case VIR_INTERFACE_TYPE_BRIDGE:
        if (udevGetIfaceDefBridge(udev, dev, name, ifacedef) < 0)
            goto error;
        break;
    case VIR_INTERFACE_TYPE_BOND:
        if (udevGetIfaceDefBond(udev, dev, name, ifacedef) < 0)
            goto error;
        break;
    case VIR_INTERFACE_TYPE_ETHERNET:
        break;
    }

    udev_device_unref(dev);

    return ifacedef;

 error:
    udev_device_unref(dev);

    virInterfaceDefFree(ifacedef);

    return NULL;
}

static char *
udevInterfaceGetXMLDesc(virInterfacePtr ifinfo,
                        unsigned int flags)
{
    struct udev_iface_driver *driverState = ifinfo->conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    virInterfaceDef *ifacedef;
    char *xmlstr = NULL;

    virCheckFlags(VIR_INTERFACE_XML_INACTIVE, NULL);

    /* Recursively build up the interface XML based on the requested
     * interface name
     */
    ifacedef = udevGetIfaceDef(udev, ifinfo->name);

    if (!ifacedef)
        goto cleanup;

    if (virInterfaceGetXMLDescEnsureACL(ifinfo->conn, ifacedef) < 0)
        goto cleanup;

    xmlstr = virInterfaceDefFormat(ifacedef);

    virInterfaceDefFree(ifacedef);

 cleanup:
    /* decrement our udev ptr */
    udev_unref(udev);

    return xmlstr;
}

static int
udevInterfaceIsActive(virInterfacePtr ifinfo)
{
    struct udev_iface_driver *driverState = ifinfo->conn->interfacePrivateData;
    struct udev *udev = udev_ref(driverState->udev);
    struct udev_device *dev;
    virInterfaceDefPtr def = NULL;
    int status = -1;

    dev = udev_device_new_from_subsystem_sysname(udev, "net",
                                                 ifinfo->name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%s'"),
                       ifinfo->name);
        goto cleanup;
    }

    if (!(def = udevGetMinimalDefForDevice(dev)))
        goto cleanup;

    if (virInterfaceIsActiveEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    /* Check if it's active or not */
    status = STREQ(udev_device_get_sysattr_value(dev, "operstate"), "up");

    udev_device_unref(dev);

 cleanup:
    udev_unref(udev);
    virInterfaceDefFree(def);

    return status;
}

static virInterfaceDriver udevIfaceDriver = {
    "udev",
    .interfaceOpen = udevInterfaceOpen, /* 1.0.0 */
    .interfaceClose = udevInterfaceClose, /* 1.0.0 */
    .connectNumOfInterfaces = udevConnectNumOfInterfaces, /* 1.0.0 */
    .connectListInterfaces = udevConnectListInterfaces, /* 1.0.0 */
    .connectNumOfDefinedInterfaces = udevConnectNumOfDefinedInterfaces, /* 1.0.0 */
    .connectListDefinedInterfaces = udevConnectListDefinedInterfaces, /* 1.0.0 */
    .connectListAllInterfaces = udevConnectListAllInterfaces, /* 1.0.0 */
    .interfaceLookupByName = udevInterfaceLookupByName, /* 1.0.0 */
    .interfaceLookupByMACString = udevInterfaceLookupByMACString, /* 1.0.0 */
    .interfaceIsActive = udevInterfaceIsActive, /* 1.0.0 */
    .interfaceGetXMLDesc = udevInterfaceGetXMLDesc, /* 1.0.0 */
};

int
udevIfaceRegister(void)
{
    if (virRegisterInterfaceDriver(&udevIfaceDriver) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to register udev interface driver"));
        return -1;
    }
    return 0;
}
