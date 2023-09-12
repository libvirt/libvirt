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

#include <dirent.h>
#include <libudev.h>

#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "datatypes.h"
#include "interface_driver.h"
#include "interface_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "virpidfile.h"
#include "viraccessapicheck.h"
#include "virinterfaceobj.h"
#include "virnetdev.h"
#include "virutil.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_LOG_INIT("interface.interface_backend_udev");

struct udev_iface_driver {
    struct udev *udev;
    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    char *stateDir;
    bool privileged;
};

typedef enum {
    VIR_UDEV_IFACE_ACTIVE,
    VIR_UDEV_IFACE_INACTIVE,
    VIR_UDEV_IFACE_ALL
} virUdevStatus;

static struct udev_iface_driver *driver;

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
 * this implies existence of name and mac address attributes
 */
static virInterfaceDef * ATTRIBUTE_NONNULL(1)
udevGetMinimalDefForDevice(struct udev_device *dev)
{
    virInterfaceDef *def;

    /* Allocate our interface definition structure */
    def = g_new0(virInterfaceDef, 1);

    def->name = g_strdup(udev_device_get_sysname(dev));
    def->mac = g_strdup(udev_device_get_sysattr_value(dev, "address"));

    return def;
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

static int
udevNumOfInterfacesByStatus(virConnectPtr conn, virUdevStatus status,
                            virInterfaceObjListFilter filter)
{
    struct udev *udev = udev_ref(driver->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get number of %1$s interfaces on host"),
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
        g_autoptr(virInterfaceDef) def = NULL;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);

        def = udevGetMinimalDefForDevice(dev);
        if (filter(conn, def))
            count++;
        udev_device_unref(dev);
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
    struct udev *udev = udev_ref(driver->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    int count = 0;

    enumerate = udevGetDevices(udev, status);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get list of %1$s interfaces on host"),
                       virUdevStatusString(status));
        udev_unref(udev);
        return -1;
    }

    /* Do the scan to load up the enumeration */
    udev_enumerate_scan_devices(enumerate);

    /* Get a list we can walk */
    devices = udev_enumerate_get_list_entry(enumerate);

    /* For each item so we can count */
    udev_list_entry_foreach(dev_entry, devices) {
        struct udev_device *dev;
        const char *path;
        g_autoptr(virInterfaceDef) def = NULL;

        /* Ensure we won't exceed the size of our array */
        if (count > names_len)
            break;

        path = udev_list_entry_get_name(dev_entry);
        dev = udev_device_new_from_syspath(udev, path);

        def = udevGetMinimalDefForDevice(dev);
        if (filter(conn, def)) {
            names[count] = g_strdup(udev_device_get_sysname(dev));
            count++;
        }
        udev_device_unref(dev);
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return count;
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
    struct udev *udev;
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_entry;
    virInterfacePtr *ifaces_list = NULL;
    virInterfacePtr iface_obj;
    int count = 0;
    int status = 0;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE, -1);

    if (virConnectListAllInterfacesEnsureACL(conn) < 0)
        return -1;

    /* Grab a udev reference */
    udev = udev_ref(driver->udev);

    /* List all interfaces in case we support more filter flags in the future */
    enumerate = udevGetDevices(udev, VIR_UDEV_IFACE_ALL);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get list of %1$s interfaces on host"),
                       virUdevStatusString(status));
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
    if (ifaces)
        ifaces_list = g_new0(virInterfacePtr, count + 1);

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
        g_autoptr(virInterfaceDef) def = NULL;

        if (!(path = udev_list_entry_get_name(dev_entry))) {
            VIR_DEBUG("Skipping interface, path == NULL");
            continue;
        }
        if (!(dev = udev_device_new_from_syspath(udev, path))) {
            VIR_DEBUG("Skipping interface '%s', dev == NULL", path);
            continue;
        }
        if (!(name = udev_device_get_sysname(dev))) {
            VIR_DEBUG("Skipping interface '%s', name == NULL", path);
            continue;
        }
        macaddr = udev_device_get_sysattr_value(dev, "address");
        status = STREQ_NULLABLE(udev_device_get_sysattr_value(dev, "operstate"), "up");

        def = udevGetMinimalDefForDevice(dev);
        if (!virConnectListAllInterfacesCheckACL(conn, def)) {
            udev_device_unref(dev);
            continue;
        }

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
        VIR_REALLOC_N(ifaces_list, count + 1);
        *ifaces = g_steal_pointer(&ifaces_list);
    }

    return count;

 cleanup:
    if (enumerate)
        udev_enumerate_unref(enumerate);
    udev_unref(udev);
    return ret;

}

static virInterfacePtr
udevInterfaceLookupByName(virConnectPtr conn, const char *name)
{
    struct udev *udev = udev_ref(driver->udev);
    struct udev_device *dev;
    virInterfacePtr ret = NULL;
    g_autoptr(virInterfaceDef) def = NULL;

    /* get a device reference based on the device name */
    dev = udev_device_new_from_subsystem_sysname(udev, "net", name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"),
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

    return ret;
}

static virInterfacePtr
udevInterfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    struct udev *udev = udev_ref(driver->udev);
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *dev_entry;
    struct udev_device *dev;
    g_autoptr(virInterfaceDef) def = NULL;
    virInterfacePtr ret = NULL;

    enumerate = udevGetDevices(udev, VIR_UDEV_IFACE_ALL);

    if (!enumerate) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to lookup interface with MAC address '%1$s'"),
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
                       _("couldn't find interface with MAC address '%1$s'"),
                       macstr);
        goto cleanup;
    }

    /* Check that we didn't get multiple items back */
    if (udev_list_entry_get_next(dev_entry)) {
        virReportError(VIR_ERR_MULTIPLE_INTERFACES,
                       _("the MAC address '%1$s' matches multiple interfaces"),
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
        if (STRPREFIX(entry->d_name, VIR_NET_GENERATED_VNET_PREFIX) &&
            g_ascii_isdigit(entry->d_name[4]))
            return 0;
    }

    return 1;
}


static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT
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
                _("Could not retrieve 'bonding/downdelay' for '%1$s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/downdelay' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.downdelay = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/updelay");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/updelay' for '%1$s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/updelay' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.updelay = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/miimon");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/miimon' for '%1$s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/miimon' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.frequency = tmp_int;

    tmp_str = udev_device_get_sysattr_value(dev, "bonding/arp_interval");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/arp_interval' for '%1$s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/arp_interval' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.interval = tmp_int;

    /* bonding/mode is in the format: "balance-rr 0" so we find the
     * space and increment the pointer to get the number and convert
     * it to an integer. libvirt uses 1 through 7 while the raw
     * number is 0 through 6 so increment it by 1.
     */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/mode");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/mode' for '%1$s'"), name);
        goto error;
    }
    tmp_str = strchr(tmp_str, ' ');
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Invalid format for 'bonding/mode' for '%1$s'"), name);
        goto error;
    }
    if (strlen(tmp_str) < 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Unable to find correct value in 'bonding/mode' for '%1$s'"),
                name);
        goto error;
    }
    if (virStrToLong_i(tmp_str + 1, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/mode' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.mode = tmp_int + 1;

    /* bonding/arp_validate is in the format: "none 0" so we find the
     * space and increment the pointer to get the number and convert
     * it to an integer.
     */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/arp_validate");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/arp_validate' for '%1$s'"), name);
        goto error;
    }
    tmp_str = strchr(tmp_str, ' ');
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Invalid format for 'bonding/arp_validate' for '%1$s'"), name);
        goto error;
    }
    if (strlen(tmp_str) < 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Unable to find correct value in 'bonding/arp_validate' for '%1$s'"),
                name);
        goto error;
    }
    if (virStrToLong_i(tmp_str + 1, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/arp_validate' '%1$s' for '%2$s'"),
                tmp_str, name);
        goto error;
    }
    ifacedef->data.bond.validate = tmp_int;

    /* bonding/use_carrier is 0 or 1 and libvirt stores it as 1 or 2. */
    tmp_str = udev_device_get_sysattr_value(dev, "bonding/use_carrier");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not retrieve 'bonding/use_carrier' for '%1$s'"), name);
        goto error;
    }
    if (virStrToLong_i(tmp_str, NULL, 10, &tmp_int) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse 'bonding/use_carrier' '%1$s' for '%2$s'"),
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
                _("Could not retrieve 'bonding/arp_ip_target' for '%1$s'"), name);
        goto error;
    }
    ifacedef->data.bond.target = g_strdup(tmp_str);

    /* Slaves of the bond */
    /* Get each slave in the bond */
    slave_count = scandir(udev_device_get_syspath(dev), &slave_list,
            udevBondScanDirFilter, alphasort);

    if (slave_count < 0) {
        virReportSystemError(errno,
                             _("Could not get slaves of bond '%1$s'"), name);
        goto error;
    }

    /* Allocate our list of slave devices */
    ifacedef->data.bond.itf = g_new0(struct _virInterfaceDef *,
                                     slave_count);
    ifacedef->data.bond.nbItf = slave_count;

    for (i = 0; i < slave_count; i++) {
        /* Names are slave_interface. e.g. slave_eth0
         * so we use the part after the _
         */
        tmp_str = strchr(slave_list[i]->d_name, '_');
        if (!tmp_str || strlen(tmp_str) < 2) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid enslaved interface name '%1$s' seen for bond '%2$s'"),
                           slave_list[i]->d_name, name);
            goto error;
        }
        /* go past the _ */
        tmp_str++;

        ifacedef->data.bond.itf[i] =
            udevGetIfaceDef(udev, tmp_str);
        if (!ifacedef->data.bond.itf[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get interface information for '%1$s', which is a enslaved in bond '%2$s'"),
                           slave_list[i]->d_name, name);
            goto error;
        }
        VIR_FREE(slave_list[i]);
    }

    VIR_FREE(slave_list);

    return 0;

 error:
    for (i = 0; slave_count != -1 && i < slave_count; i++)
        VIR_FREE(slave_list[i]);
    VIR_FREE(slave_list);

    return -1;
}

static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT
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
                       _("Could not retrieve 'bridge/forward_delay' for '%1$s'"),
                       name);
        goto error;
    }

    ifacedef->data.bridge.delay = g_strdup(tmp_str);

    /* Retrieve Spanning Tree State. Valid values = -1, 0, 1 */
    tmp_str = udev_device_get_sysattr_value(dev, "bridge/stp_state");
    if (!tmp_str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not retrieve 'bridge/stp_state' for '%1$s'"),
                       name);
        goto error;
    }

    if (virStrToLong_i(tmp_str, NULL, 10, &stp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse 'bridge/stp_state' '%1$s' for '%2$s'"),
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
                       _("Invalid STP state value %1$d received for '%2$s'. Must be -1, 0, or 1."),
                       stp, name);
        goto error;
    }

    /* Members of the bridge */
    member_path = g_strdup_printf("%s/%s", udev_device_get_syspath(dev), "brif");

    /* Get each member of the bridge */
    member_count = scandir(member_path, &member_list,
            udevBridgeScanDirFilter, alphasort);

    /* Don't need the path anymore */
    VIR_FREE(member_path);

    if (member_count < 0) {
        virReportSystemError(errno,
                _("Could not get members of bridge '%1$s'"),
                name);
        goto error;
    }

    /* Allocate our list of member devices */
    ifacedef->data.bridge.itf = g_new0(struct _virInterfaceDef *, member_count);
    ifacedef->data.bridge.nbItf = member_count;

    /* Get the interface definitions for each member of the bridge */
    for (i = 0; i < member_count; i++) {
        ifacedef->data.bridge.itf[i] =
            udevGetIfaceDef(udev, member_list[i]->d_name);
        if (!ifacedef->data.bridge.itf[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not get interface information for '%1$s', which is a member of bridge '%2$s'"),
                member_list[i]->d_name, name);
            goto error;
        }
        VIR_FREE(member_list[i]);
    }

    VIR_FREE(member_list);

    return 0;

 error:
    for (i = 0; member_count != -1 && i < member_count; i++)
        VIR_FREE(member_list[i]);
    VIR_FREE(member_list);

    return -1;
}

static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT
udevGetIfaceDefVlan(struct udev *udev G_GNUC_UNUSED,
                    struct udev_device *dev G_GNUC_UNUSED,
                    const char *name,
                    virInterfaceDef *ifacedef)
{
    g_autofree char *procpath = NULL;
    g_autofree char *buf = NULL;
    char *vid_pos, *dev_pos;
    size_t vid_len, dev_len;
    const char *vid_prefix = "VID: ";
    const char *dev_prefix = "\nDevice: ";

    procpath = g_strdup_printf("/proc/net/vlan/%s", name);

    if (virFileReadAll(procpath, BUFSIZ, &buf) < 0)
        return -1;

    if ((vid_pos = strstr(buf, vid_prefix)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find the VID for the VLAN device '%1$s'"),
                       name);
        return -1;
    }
    vid_pos += strlen(vid_prefix);

    if ((vid_len = strspn(vid_pos, "0123456789")) == 0 ||
        !g_ascii_isspace(vid_pos[vid_len])) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find the VID for the VLAN device '%1$s'"),
                       name);
        return -1;
    }

    if ((dev_pos = strstr(vid_pos + vid_len, dev_prefix)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find the real device for the VLAN device '%1$s'"),
                       name);
        return -1;
    }
    dev_pos += strlen(dev_prefix);

    if ((dev_len = strcspn(dev_pos, "\n")) == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find the real device for the VLAN device '%1$s'"),
                       name);
        return -1;
    }

    ifacedef->data.vlan.tag = g_strndup(vid_pos, vid_len);
    ifacedef->data.vlan.dev_name = g_strndup(dev_pos, dev_len);

    return 0;
}

static virInterfaceDef * ATTRIBUTE_NONNULL(1)
udevGetIfaceDef(struct udev *udev, const char *name)
{
    struct udev_device *dev = NULL;
    g_autoptr(virInterfaceDef) ifacedef = NULL;
    unsigned int mtu;
    const char *mtu_str;
    char *vlan_parent_dev = NULL;
    const char *devtype;

    /* Allocate our interface definition structure */
    ifacedef = g_new0(virInterfaceDef, 1);

    /* Clear our structure and set safe defaults */
    ifacedef->startmode = VIR_INTERFACE_START_UNSPECIFIED;
    ifacedef->name = g_strdup(name);

    /* Lookup the device we've been asked about */
    dev = udev_device_new_from_subsystem_sysname(udev, "net", name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"), name);
        goto error;
    }

    /* MAC address */
    ifacedef->mac = g_strdup(udev_device_get_sysattr_value(dev, "address"));

    /* Link state and speed */
    if (virNetDevGetLinkInfo(ifacedef->name, &ifacedef->lnk) < 0)
        goto error;

    /* MTU */
    mtu_str = udev_device_get_sysattr_value(dev, "mtu");
    if (!mtu_str || virStrToLong_ui(mtu_str, NULL, 10, &mtu) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                _("Could not parse MTU value '%1$s'"), NULLSTR(mtu_str));
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
        if (vlan_parent_dev)
            ifacedef->type = VIR_INTERFACE_TYPE_VLAN;

        /* Fallback check to see if this is a bond device */
        if (udev_device_get_sysattr_value(dev, "bonding/mode"))
            ifacedef->type = VIR_INTERFACE_TYPE_BOND;
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

    return g_steal_pointer(&ifacedef);

 error:
    udev_device_unref(dev);

    return NULL;
}

static char *
udevInterfaceGetXMLDesc(virInterfacePtr ifinfo,
                        unsigned int flags)
{
    struct udev *udev = udev_ref(driver->udev);
    g_autoptr(virInterfaceDef) ifacedef = NULL;
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

 cleanup:
    /* decrement our udev ptr */
    udev_unref(udev);

    return xmlstr;
}

static int
udevInterfaceIsActive(virInterfacePtr ifinfo)
{
    struct udev *udev = udev_ref(driver->udev);
    struct udev_device *dev;
    g_autoptr(virInterfaceDef) def = NULL;
    int status = -1;

    dev = udev_device_new_from_subsystem_sysname(udev, "net",
                                                 ifinfo->name);
    if (!dev) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"),
                       ifinfo->name);
        goto cleanup;
    }

    if (!(def = udevGetMinimalDefForDevice(dev)))
        goto cleanup;

    if (virInterfaceIsActiveEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    /* Check if it's active or not */
    status = STREQ_NULLABLE(udev_device_get_sysattr_value(dev, "operstate"), "up");

    udev_device_unref(dev);

 cleanup:
    udev_unref(udev);

    return status;
}


static int
udevStateCleanup(void);

static int
udevStateInitialize(bool privileged,
                    const char *root,
                    bool monolithic G_GNUC_UNUSED,
                    virStateInhibitCallback callback G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    int ret = VIR_DRV_STATE_INIT_ERROR;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    driver = g_new0(struct udev_iface_driver, 1);

    driver->lockFD = -1;

    if (privileged) {
        driver->stateDir = g_strdup_printf("%s/libvirt/interface", RUNSTATEDIR);
    } else {
        g_autofree char *rundir = NULL;

        rundir = virGetUserRuntimeDirectory();
        driver->stateDir = g_strdup_printf("%s/interface/run", rundir);
    }

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto cleanup;
    }

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto cleanup;

    driver->udev = udev_new();
    if (!driver->udev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create udev context"));
        goto cleanup;
    }
    driver->privileged = privileged;

    ret = VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    if (ret < 0)
        udevStateCleanup();
    return ret;
}

static int
udevStateCleanup(void)
{
    if (!driver)
        return -1;

    if (driver->udev)
        udev_unref(driver->udev);

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

    VIR_FREE(driver->stateDir);
    VIR_FREE(driver);
    return 0;
}


static virDrvOpenStatus
udevConnectOpen(virConnectPtr conn,
                virConnectAuthPtr auth G_GNUC_UNUSED,
                virConf *conf G_GNUC_UNUSED,
                unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("interface state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!virConnectValidateURIPath(conn->uri->path,
                                   "interface",
                                   driver->privileged))
        return VIR_DRV_OPEN_ERROR;

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int udevConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}


static int udevConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int udevConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int udevConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static virInterfaceDriver udevIfaceDriver = {
    .name = "udev",
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


static virHypervisorDriver udevHypervisorDriver = {
    .name = "interface",
    .connectOpen = udevConnectOpen, /* 4.1.0 */
    .connectClose = udevConnectClose, /* 4.1.0 */
    .connectIsEncrypted = udevConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = udevConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = udevConnectIsAlive, /* 4.1.0 */
};


static virConnectDriver udevConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "interface", NULL },
    .hypervisorDriver = &udevHypervisorDriver,
    .interfaceDriver = &udevIfaceDriver,
};


static virStateDriver interfaceStateDriver = {
    .name = "udev",
    .stateInitialize = udevStateInitialize,
    .stateCleanup = udevStateCleanup,
};

int
udevIfaceRegister(void)
{
    if (virRegisterConnectDriver(&udevConnectDriver, false) < 0)
        return -1;
    if (virSetSharedInterfaceDriver(&udevIfaceDriver) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to register udev interface driver"));
        return -1;
    }
    if (virRegisterStateDriver(&interfaceStateDriver) < 0)
        return -1;
    return 0;
}
