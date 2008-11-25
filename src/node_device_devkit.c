/*
 * node_device_devkit.c: node device enumeration - DeviceKit-based implementation
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
#include <devkit-gobject.h>

#include "node_device_conf.h"
#include "virterror_internal.h"
#include "driver.h"
#include "datatypes.h"
#include "event.h"
#include "memory.h"
#include "uuid.h"
#include "logging.h"

#include "node_device.h"

/*
 * Host device enumeration (DeviceKit implementation)
 */

static virDeviceMonitorStatePtr driverState;

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

#define CONN_DRV_STATE(conn) \
        ((virDeviceMonitorStatePtr)((conn)->devMonPrivateData))
#define DRV_STATE_DKCLIENT(ds) ((DevkitClient *)((ds)->privateData))
#define CONN_DKCLIENT(conn) DRV_STATE_DKCLIENT(CONN_DRV_STATE(conn))

#define NODE_DEV_DKDEV(obj) ((DevkitDevice *)((obj)->privateData)

static int get_str_prop(DevkitDevice *dkdev, const char *prop, char **val_p)
{
    char *val = devkit_device_dup_property_as_str(dkdev, prop);

    if (val) {
        if (*val) {
            *val_p = val;
            return 0;
        } else {
            /* Treat empty strings as NULL values */
            VIR_FREE(val);
        }
    }

    return -1;
}

#if 0
static int get_int_prop(DevkitDevice *dkdev, const char *prop, int *val_p)
{
    if (! devkit_device_has_property(dkdev, prop))
        return -1;
    *val_p = devkit_device_get_property_as_int(dkdev, prop);
    return 0;
}

static int get_uint64_prop(DevkitDevice *dkdev, const char *prop,
                           unsigned long long *val_p)
{
    if (! devkit_device_has_property(dkdev, prop))
        return -1;
    *val_p = devkit_device_get_property_as_uint64(dkdev, prop);
    return 0;
}
#endif

static int gather_pci_cap(DevkitDevice *dkdev,
                          union _virNodeDevCapData *d)
{
    const char *sysfs_path = devkit_device_get_native_path(dkdev);

    if (sysfs_path != NULL) {
        char *p = strrchr(sysfs_path, '/');
        if (p) {
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.domain);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.bus);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.slot);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.function);
        }
    }
    return 0;
}


static int gather_usb_cap(DevkitDevice *dkdev,
                          union _virNodeDevCapData *d)
{
    (void)get_str_prop(dkdev, "ID_VENDOR", &d->usb_dev.vendor_name);
    (void)get_str_prop(dkdev, "ID_MODEL", &d->usb_dev.product_name);
    return 0;
}


static int gather_net_cap(DevkitDevice *dkdev,
                          union _virNodeDevCapData *d)
{
    const char *sysfs_path = devkit_device_get_native_path(dkdev);
    const char *ifname;

    if (sysfs_path == NULL)
        return -1;
    ifname = strrchr(sysfs_path, '/');
    if (!ifname || !*ifname || !*(++ifname))
        return -1;
    if ((d->net.ifname = strdup(ifname)) == NULL)
        return -1;

    d->net.subtype = VIR_NODE_DEV_CAP_NET_LAST;

    return 0;
}


static int gather_storage_cap(DevkitDevice *dkdev,
                              union _virNodeDevCapData *d)
{
    const char *device = devkit_device_get_device_file(dkdev);

    if (device && ((d->storage.block = strdup(device)) == NULL))
        return -1;

    return 0;
}


struct _caps_tbl_entry {
    const char *cap_name;
    enum virNodeDevCapType type;
    int (*gather_fn)(DevkitDevice *dkdev,
                     union _virNodeDevCapData *data);
};

typedef struct _caps_tbl_entry caps_tbl_entry;

static caps_tbl_entry caps_tbl[] = {
    { "pci",        VIR_NODE_DEV_CAP_PCI_DEV,   gather_pci_cap },
    { "usb",        VIR_NODE_DEV_CAP_USB_DEV,   gather_usb_cap },
    { "net",        VIR_NODE_DEV_CAP_NET,       gather_net_cap },
    { "block",      VIR_NODE_DEV_CAP_STORAGE,   gather_storage_cap },
    // TODO: more caps!
};


/* qsort/bsearch string comparator */
static int cmpstringp(const void *p1, const void *p2)
{
    /* from man 3 qsort */
    return strcmp(* (char * const *) p1, * (char * const *) p2);
}


static int gather_capability(DevkitDevice *dkdev,
                             const char *cap_name,
                             virNodeDevCapsDefPtr *caps_p)
{
    size_t caps_tbl_len = sizeof(caps_tbl) / sizeof(caps_tbl[0]);
    caps_tbl_entry *entry;

    entry = bsearch(&cap_name, caps_tbl, caps_tbl_len,
                    sizeof(caps_tbl[0]), cmpstringp);

    if (entry) {
        virNodeDevCapsDefPtr caps;
        if (VIR_ALLOC(caps) < 0)
            return ENOMEM;
        caps->type = entry->type;
        if (entry->gather_fn) {
            int rv = (*entry->gather_fn)(dkdev, &caps->data);
            if (rv != 0) {
                virNodeDevCapsDefFree(caps);
                return rv;
            }
        }
        caps->next = *caps_p;
        *caps_p = caps;
    }

    return 0;
}


static int gather_capabilities(DevkitDevice *dkdev,
                               virNodeDevCapsDefPtr *caps_p)
{
    const char *subsys = devkit_device_get_subsystem(dkdev);
    const char *bus_name = devkit_device_get_property(dkdev, "ID_BUS");
    virNodeDevCapsDefPtr caps = NULL;
    int rv;

    if (subsys) {
        rv = gather_capability(dkdev, subsys, &caps);
        if (rv != 0) goto failure;
    }

    if (bus_name && (subsys == NULL || !STREQ(bus_name, subsys))) {
        rv = gather_capability(dkdev, bus_name, &caps);
        if (rv != 0) goto failure;
    }

    *caps_p = caps;
    return 0;

 failure:
    while (caps) {
        virNodeDevCapsDefPtr next = caps->next;
        virNodeDevCapsDefFree(caps);
        caps = next;
    }
    return rv;
}

static void dev_create(void *_dkdev, void *_dkclient ATTRIBUTE_UNUSED)
{
    DevkitDevice *dkdev = _dkdev;
    const char *sysfs_path = devkit_device_get_native_path(dkdev);
    virNodeDeviceObjPtr dev = NULL;
    const char *name;
    int rv;

    if (sysfs_path == NULL)
        /* Currently using basename(sysfs_path) as device name (key) */
        return;

    name = strrchr(sysfs_path, '/');
    if (name == NULL)
        name = sysfs_path;
    else
        ++name;

    if (VIR_ALLOC(dev) < 0 || VIR_ALLOC(dev->def) < 0)
        goto failure;

    dev->privateData = dkdev;

    if ((dev->def->name = strdup(name)) == NULL)
        goto failure;

    // TODO: Find device parent, if any

    rv = gather_capabilities(dkdev, &dev->def->caps);
    if (rv != 0) goto failure;

    if (VIR_REALLOC_N(driverState->devs.objs, driverState->devs.count + 1) < 0)
        goto failure;

    driverState->devs.objs[driverState->devs.count++] = dev;

    return;

 failure:
    DEBUG("FAILED TO ADD dev %s", name);
    if (dev)
        virNodeDeviceDefFree(dev->def);
    VIR_FREE(dev);
}


static int devkitDeviceMonitorStartup(void)
{
    size_t caps_tbl_len = sizeof(caps_tbl) / sizeof(caps_tbl[0]);
    DevkitClient *devkit_client = NULL;
    GError *err = NULL;
    GList *devs;
    int i;

    /* Ensure caps_tbl is sorted by capability name */
    qsort(caps_tbl, caps_tbl_len, sizeof(caps_tbl[0]), cmpstringp);

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    // TODO: Is it really ok to call this multiple times??
    //       Is there something analogous to call on close?
    g_type_init();

    /* Get new devkit_client and connect to daemon */
    devkit_client = devkit_client_new(NULL);
    if (devkit_client == NULL) {
        DEBUG0("devkit_client_new returned NULL");
        goto failure;
    }
    if (!devkit_client_connect(devkit_client, &err)) {
        DEBUG0("devkit_client_connect failed");
        goto failure;
    }

    /* Populate with known devices.
     *
     * This really should be:
        devs = devkit_client_enumerate_by_subsystem(devkit_client, NULL, &err);
        if (err) {
            DEBUG0("devkit_client_enumerate_by_subsystem failed");
            devs = NULL;
            goto failure;
        }
        g_list_foreach(devs, dev_create, devkit_client);
    * but devkit_client_enumerate_by_subsystem currently fails when the second
    * arg is null (contrary to the API documentation).  So the following code
    * (from Dan B) works around this by listing devices per handled subsystem.
    */

    for (i = 0 ; i < ARRAY_CARDINALITY(caps_tbl) ; i++) {
        const char *caps[] = { caps_tbl[i].cap_name, NULL };
        devs = devkit_client_enumerate_by_subsystem(devkit_client,
                                                    caps,
                                                    &err);
        if (err) {
            DEBUG0("devkit_client_enumerate_by_subsystem failed");
            devs = NULL;
            goto failure;
        }
        g_list_foreach(devs, dev_create, devkit_client);
    }

    driverState->privateData = devkit_client;

    // TODO: Register to get DeviceKit events on device changes and
    //       coordinate updates with queries and other operations.

    return 0;

 failure:
    if (err) {
        DEBUG("\terror[%d]: %s", err->code, err->message);
        g_error_free(err);
    }
    if (devs) {
        g_list_foreach(devs, (GFunc)g_object_unref, NULL);
        g_list_free(devs);
    }
    if (devkit_client)
        g_object_unref(devkit_client);
    VIR_FREE(driverState);

    return -1;
}


static int devkitDeviceMonitorShutdown(void)
{
    if (driverState) {
        DevkitClient *devkit_client = DRV_STATE_DKCLIENT(driverState);
        virNodeDeviceObjListFree(&driverState->devs);
        if (devkit_client)
            g_object_unref(devkit_client);
        VIR_FREE(driverState);
        return 0;
    }
    return -1;
}


static int devkitDeviceMonitorReload(void)
{
    (void)devkitDeviceMonitorShutdown();
    return devkitDeviceMonitorStartup();
}


static int devkitDeviceMonitorActive(void)
{
    /* Always ready to deal with a shutdown */
    return 0;
}


static virDrvOpenStatus
devkitNodeDrvOpen(virConnectPtr conn,
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                  int flags ATTRIBUTE_UNUSED)
{
    if (driverState == NULL)
        return VIR_DRV_OPEN_DECLINED;

    conn->devMonPrivateData = driverState;

    return VIR_DRV_OPEN_SUCCESS;
}

static int devkitNodeDrvClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    conn->devMonPrivateData = NULL;
    return 0;
}


static virDeviceMonitor devkitDeviceMonitor = {
    .name = "devkitDeviceMonitor",
    .open = devkitNodeDrvOpen,
    .close = devkitNodeDrvClose,
};


static virStateDriver devkitStateDriver = {
    .initialize = devkitDeviceMonitorStartup,
    .cleanup = devkitDeviceMonitorShutdown,
    .reload = devkitDeviceMonitorReload,
    .active = devkitDeviceMonitorActive,
};

int devkitNodeRegister(void)
{
    registerCommonNodeFuncs(&devkitDeviceMonitor);
    if (virRegisterDeviceMonitor(&devkitDeviceMonitor) < 0)
        return -1;
    return virRegisterStateDriver(&devkitStateDriver);
}
