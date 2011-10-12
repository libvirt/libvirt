/*
 * node_device_hal.c: node device enumeration - HAL-based implementation
 *
 * Copyright (C) 2011 Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <libhal.h>

#include "node_device_conf.h"
#include "node_device_hal.h"
#include "virterror_internal.h"
#include "driver.h"
#include "datatypes.h"
#include "memory.h"
#include "uuid.h"
#include "pci.h"
#include "logging.h"
#include "node_device_driver.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

/*
 * Host device enumeration (HAL implementation)
 */

static virDeviceMonitorStatePtr driverState;

#define CONN_DRV_STATE(conn) \
        ((virDeviceMonitorStatePtr)((conn)->devMonPrivateData))
#define DRV_STATE_HAL_CTX(ds) ((LibHalContext *)((ds)->privateData))
#define CONN_HAL_CTX(conn) DRV_STATE_HAL_CTX(CONN_DRV_STATE(conn))

#define NODE_DEV_UDI(obj) ((const char *)((obj)->privateData)


static const char *hal_name(const char *udi)
{
    const char *name = strrchr(udi, '/');
    if (name)
        return name+1;
    return udi;
}


static int get_str_prop(LibHalContext *ctxt, const char *udi,
                        const char *prop, char **val_p)
{
    char *val = libhal_device_get_property_string(ctxt, udi, prop, NULL);

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

static int get_int_prop(LibHalContext *ctxt, const char *udi,
                        const char *prop, int *val_p)
{
    DBusError err;
    int val;
    int rv;

    dbus_error_init(&err);
    val = libhal_device_get_property_int(ctxt, udi, prop, &err);
    rv = dbus_error_is_set(&err);
    dbus_error_free(&err);
    if (rv == 0)
        *val_p = val;

    return rv;
}

static int get_bool_prop(LibHalContext *ctxt, const char *udi,
                         const char *prop, int *val_p)
{
    DBusError err;
    int val;
    int rv;

    dbus_error_init(&err);
    val = libhal_device_get_property_bool(ctxt, udi, prop, &err);
    rv = dbus_error_is_set(&err);
    dbus_error_free(&err);
    if (rv == 0)
        *val_p = val;

    return rv;
}

static int get_uint64_prop(LibHalContext *ctxt, const char *udi,
                           const char *prop, unsigned long long *val_p)
{
    DBusError err;
    unsigned long long val;
    int rv;

    dbus_error_init(&err);
    val = libhal_device_get_property_uint64(ctxt, udi, prop, &err);
    rv = dbus_error_is_set(&err);
    dbus_error_free(&err);
    if (rv == 0)
        *val_p = val;

    return rv;
}

static int gather_pci_cap(LibHalContext *ctx, const char *udi,
                          union _virNodeDevCapData *d)
{
    char *sysfs_path;

    if (get_str_prop(ctx, udi, "pci.linux.sysfs_path", &sysfs_path) == 0) {
        char *p = strrchr(sysfs_path, '/');
        if (p) {
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.domain);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.bus);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.slot);
            (void)virStrToLong_ui(p+1, &p, 16, &d->pci_dev.function);
        }

        if (!pciGetPhysicalFunction(sysfs_path, &d->pci_dev.physical_function))
            d->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

        if (!pciGetVirtualFunctions(sysfs_path, &d->pci_dev.virtual_functions,
            &d->pci_dev.num_virtual_functions) ||
            d->pci_dev.num_virtual_functions > 0)
            d->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;

        VIR_FREE(sysfs_path);
    }

    (void)get_int_prop(ctx, udi, "pci.vendor_id", (int *)&d->pci_dev.vendor);
    if (get_str_prop(ctx, udi, "pci.vendor", &d->pci_dev.vendor_name) != 0)
        (void)get_str_prop(ctx, udi, "info.vendor", &d->pci_dev.vendor_name);
    (void)get_int_prop(ctx, udi, "pci.product_id", (int *)&d->pci_dev.product);
    if (get_str_prop(ctx, udi, "pci.product", &d->pci_dev.product_name) != 0)
        (void)get_str_prop(ctx, udi, "info.product", &d->pci_dev.product_name);

    return 0;
}


static int gather_usb_cap(LibHalContext *ctx, const char *udi,
                          union _virNodeDevCapData *d)
{
    (void)get_int_prop(ctx, udi, "usb.interface.number",
                       (int *)&d->usb_if.number);
    (void)get_int_prop(ctx, udi, "usb.interface.class",
                       (int *)&d->usb_if._class);
    (void)get_int_prop(ctx, udi, "usb.interface.subclass",
                       (int *)&d->usb_if.subclass);
    (void)get_int_prop(ctx, udi, "usb.interface.protocol",
                       (int *)&d->usb_if.protocol);
    (void)get_str_prop(ctx, udi, "usb.interface.description",
                       &d->usb_if.description);
    return 0;
}


static int gather_usb_device_cap(LibHalContext *ctx, const char *udi,
                          union _virNodeDevCapData *d)
{
    (void)get_int_prop(ctx, udi, "usb_device.bus_number",
                       (int *)&d->usb_dev.bus);
    (void)get_int_prop(ctx, udi, "usb_device.linux.device_number",
                       (int *)&d->usb_dev.device);
    (void)get_int_prop(ctx, udi, "usb_device.vendor_id",
                       (int *)&d->usb_dev.vendor);
    if (get_str_prop(ctx, udi, "usb_device.vendor",
                     &d->usb_dev.vendor_name) != 0)
        (void)get_str_prop(ctx, udi, "info.vendor", &d->usb_dev.vendor_name);
    (void)get_int_prop(ctx, udi, "usb_device.product_id",
                       (int *)&d->usb_dev.product);
    if (get_str_prop(ctx, udi, "usb_device.product",
                     &d->usb_dev.product_name) != 0)
        (void)get_str_prop(ctx, udi, "info.product", &d->usb_dev.product_name);
    return 0;
}


static int gather_net_cap(LibHalContext *ctx, const char *udi,
                          union _virNodeDevCapData *d)
{
    unsigned long long dummy;
    (void)get_str_prop(ctx, udi, "net.interface", &d->net.ifname);
    (void)get_str_prop(ctx, udi, "net.address", &d->net.address);
    if (get_uint64_prop(ctx, udi, "net.80203.mac_address",
                        &dummy) == 0)
        d->net.subtype = VIR_NODE_DEV_CAP_NET_80203;
    else if (get_uint64_prop(ctx, udi, "net.80211.mac_address",
                             &dummy) == 0)
        d->net.subtype = VIR_NODE_DEV_CAP_NET_80211;
    else
        d->net.subtype = VIR_NODE_DEV_CAP_NET_LAST;

    return 0;
}


static int gather_scsi_host_cap(LibHalContext *ctx, const char *udi,
                                union _virNodeDevCapData *d)
{
    int retval = 0;

    (void)get_int_prop(ctx, udi, "scsi_host.host", (int *)&d->scsi_host.host);

    retval = check_fc_host(d);

    if (retval == -1) {
        goto out;
    }

    retval = check_vport_capable(d);

out:
    return retval;
}


static int gather_scsi_cap(LibHalContext *ctx, const char *udi,
                           union _virNodeDevCapData *d)
{
    (void)get_int_prop(ctx, udi, "scsi.host", (int *)&d->scsi.host);
    (void)get_int_prop(ctx, udi, "scsi.bus", (int *)&d->scsi.bus);
    (void)get_int_prop(ctx, udi, "scsi.target", (int *)&d->scsi.target);
    (void)get_int_prop(ctx, udi, "scsi.lun", (int *)&d->scsi.lun);
    (void)get_str_prop(ctx, udi, "scsi.type", &d->scsi.type);
    return 0;
}


static int gather_storage_cap(LibHalContext *ctx, const char *udi,
                              union _virNodeDevCapData *d)
{
    int val;
    (void)get_str_prop(ctx, udi, "block.device", &d->storage.block);
    (void)get_str_prop(ctx, udi, "storage.bus", &d->storage.bus);
    (void)get_str_prop(ctx, udi, "storage.drive_type", &d->storage.drive_type);
    (void)get_str_prop(ctx, udi, "storage.model", &d->storage.model);
    (void)get_str_prop(ctx, udi, "storage.vendor", &d->storage.vendor);
    (void)get_str_prop(ctx, udi, "storage.serial", &d->storage.serial);
    if (get_bool_prop(ctx, udi, "storage.removable", &val) == 0 && val) {
        d->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;
        if (get_bool_prop(ctx, udi, "storage.removable.media_available",
                          &val) == 0 && val) {
            d->storage.flags |=
                VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;
            (void)get_uint64_prop(ctx, udi, "storage.removable.media_size",
                                  &d->storage.removable_media_size);
        }
    } else {
        (void)get_uint64_prop(ctx, udi, "storage.size", &d->storage.size);
    }
    if (get_bool_prop(ctx, udi, "storage.hotpluggable", &val) == 0 && val)
        d->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE;
    return 0;
}


static int gather_system_cap(LibHalContext *ctx, const char *udi,
                             union _virNodeDevCapData *d)
{
    char *uuidstr;

    (void)get_str_prop(ctx, udi, "system.product", &d->system.product_name);
    (void)get_str_prop(ctx, udi, "system.hardware.vendor",
                       &d->system.hardware.vendor_name);
    (void)get_str_prop(ctx, udi, "system.hardware.version",
                       &d->system.hardware.version);
    (void)get_str_prop(ctx, udi, "system.hardware.serial",
                       &d->system.hardware.serial);
    if (get_str_prop(ctx, udi, "system.hardware.uuid", &uuidstr) == 0) {
        ignore_value(virUUIDParse(uuidstr, d->system.hardware.uuid));
        VIR_FREE(uuidstr);
    }
    (void)get_str_prop(ctx, udi, "system.firmware.vendor",
                       &d->system.firmware.vendor_name);
    (void)get_str_prop(ctx, udi, "system.firmware.version",
                       &d->system.firmware.version);
    (void)get_str_prop(ctx, udi, "system.firmware.release_date",
                       &d->system.firmware.release_date);
    return 0;
}


struct _caps_tbl_entry {
    const char *cap_name;
    enum virNodeDevCapType type;
    int (*gather_fn)(LibHalContext *ctx,
                     const char *udi,
                     union _virNodeDevCapData *data);
};

typedef struct _caps_tbl_entry caps_tbl_entry;

static caps_tbl_entry caps_tbl[] = {
    { "system",     VIR_NODE_DEV_CAP_SYSTEM,        gather_system_cap },
    { "pci",        VIR_NODE_DEV_CAP_PCI_DEV,       gather_pci_cap },
    { "usb",        VIR_NODE_DEV_CAP_USB_INTERFACE, gather_usb_cap },
    { "usb_device", VIR_NODE_DEV_CAP_USB_DEV,       gather_usb_device_cap },
    { "net",        VIR_NODE_DEV_CAP_NET,           gather_net_cap },
    { "scsi_host",  VIR_NODE_DEV_CAP_SCSI_HOST,     gather_scsi_host_cap },
    { "scsi",       VIR_NODE_DEV_CAP_SCSI,          gather_scsi_cap },
    { "storage",    VIR_NODE_DEV_CAP_STORAGE,       gather_storage_cap },
};


/* qsort/bsearch string comparator */
static int cmpstringp(const void *p1, const void *p2)
{
    /* from man 3 qsort */
    return strcmp(* (char * const *) p1, * (char * const *) p2);
}


static int gather_capability(LibHalContext *ctx, const char *udi,
                             const char *cap_name,
                             virNodeDevCapsDefPtr *caps_p)
{
    caps_tbl_entry *entry;

    entry = bsearch(&cap_name, caps_tbl, ARRAY_CARDINALITY(caps_tbl),
                    sizeof(caps_tbl[0]), cmpstringp);

    if (entry) {
        virNodeDevCapsDefPtr caps;
        if (VIR_ALLOC(caps) < 0)
            return ENOMEM;
        caps->type = entry->type;
        if (entry->gather_fn) {
            int rv = (*entry->gather_fn)(ctx, udi, &caps->data);
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


static int gather_capabilities(LibHalContext *ctx, const char *udi,
                               virNodeDevCapsDefPtr *caps_p)
{
    char *bus_name = NULL;
    virNodeDevCapsDefPtr caps = NULL;
    char **hal_cap_names = NULL;
    int rv, i;

    if (STREQ(udi, "/org/freedesktop/Hal/devices/computer")) {
        rv = gather_capability(ctx, udi, "system", &caps);
        if (rv != 0)
            goto failure;
    }

    if (get_str_prop(ctx, udi, "info.subsystem", &bus_name) == 0 ||
        get_str_prop(ctx, udi, "linux.subsystem", &bus_name) == 0) {
        rv = gather_capability(ctx, udi, bus_name, &caps);
        if (rv != 0)
            goto failure;
    }

    hal_cap_names = libhal_device_get_property_strlist(ctx, udi,
                                                       "info.capabilities",
                                                       NULL);
    if (hal_cap_names) {
        for (i = 0; hal_cap_names[i]; i++) {
            if (! (bus_name && STREQ(hal_cap_names[i], bus_name))) {
                rv = gather_capability(ctx, udi, hal_cap_names[i], &caps);
                if (rv != 0)
                    goto failure;
            }
        }
        for (i = 0; hal_cap_names[i]; i++)
            VIR_FREE(hal_cap_names[i]);
        VIR_FREE(hal_cap_names);
    }
    VIR_FREE(bus_name);

    *caps_p = caps;
    return 0;

 failure:
    VIR_FREE(bus_name);
    if (hal_cap_names) {
        for (i = 0; hal_cap_names[i]; i++)
            VIR_FREE(hal_cap_names[i]);
        VIR_FREE(hal_cap_names);
    }
    while (caps) {
        virNodeDevCapsDefPtr next = caps->next;
        virNodeDevCapsDefFree(caps);
        caps = next;
    }
    return rv;
}

static void free_udi(void *udi)
{
    VIR_FREE(udi);
}

static void dev_create(const char *udi)
{
    LibHalContext *ctx;
    char *parent_key = NULL;
    virNodeDeviceObjPtr dev = NULL;
    virNodeDeviceDefPtr def = NULL;
    const char *name = hal_name(udi);
    int rv;
    char *privData = strdup(udi);
    char *devicePath = NULL;

    if (!privData)
        return;

    nodeDeviceLock(driverState);
    ctx = DRV_STATE_HAL_CTX(driverState);

    if (VIR_ALLOC(def) < 0)
        goto failure;

    if ((def->name = strdup(name)) == NULL)
        goto failure;

    if (get_str_prop(ctx, udi, "info.parent", &parent_key) == 0) {
        def->parent = strdup(hal_name(parent_key));
        VIR_FREE(parent_key);
        if (def->parent == NULL)
            goto failure;
    }

    rv = gather_capabilities(ctx, udi, &def->caps);
    if (rv != 0) goto failure;

    if (def->caps == NULL)
        goto cleanup;

    /* Some devices don't have a path in sysfs, so ignore failure */
    (void)get_str_prop(ctx, udi, "linux.sysfs_path", &devicePath);

    dev = virNodeDeviceAssignDef(&driverState->devs,
                                 def);

    if (!dev) {
        VIR_FREE(devicePath);
        goto failure;
    }

    dev->privateData = privData;
    dev->privateFree = free_udi;
    dev->def->sysfs_path = devicePath;

    virNodeDeviceObjUnlock(dev);

    nodeDeviceUnlock(driverState);
    return;

 failure:
    VIR_DEBUG("FAILED TO ADD dev %s", name);
cleanup:
    VIR_FREE(privData);
    virNodeDeviceDefFree(def);
    nodeDeviceUnlock(driverState);
}

static void dev_refresh(const char *udi)
{
    const char *name = hal_name(udi);
    virNodeDeviceObjPtr dev;

    nodeDeviceLock(driverState);
    dev = virNodeDeviceFindByName(&driverState->devs, name);
    if (dev) {
        /* Simply "rediscover" device -- incrementally handling changes
         * to sub-capabilities (like net.80203) is nasty ... so avoid it.
         */
        virNodeDeviceObjRemove(&driverState->devs, dev);
    } else
        VIR_DEBUG("no device named %s", name);
    nodeDeviceUnlock(driverState);

    if (dev) {
        dev_create(udi);
    }
}

static void device_added(LibHalContext *ctx ATTRIBUTE_UNUSED,
                         const char *udi)
{
    VIR_DEBUG("%s", hal_name(udi));
    dev_create(udi);
}


static void device_removed(LibHalContext *ctx ATTRIBUTE_UNUSED,
                           const char *udi)
{
    const char *name = hal_name(udi);
    virNodeDeviceObjPtr dev;

    nodeDeviceLock(driverState);
    dev = virNodeDeviceFindByName(&driverState->devs,name);
    VIR_DEBUG("%s", name);
    if (dev)
        virNodeDeviceObjRemove(&driverState->devs, dev);
    else
        VIR_DEBUG("no device named %s", name);
    nodeDeviceUnlock(driverState);
}


static void device_cap_added(LibHalContext *ctx,
                             const char *udi, const char *cap)
{
    const char *name = hal_name(udi);
    virNodeDeviceObjPtr dev;

    nodeDeviceLock(driverState);
    dev = virNodeDeviceFindByName(&driverState->devs,name);
    nodeDeviceUnlock(driverState);
    VIR_DEBUG("%s %s", cap, name);
    if (dev) {
        (void)gather_capability(ctx, udi, cap, &dev->def->caps);
        virNodeDeviceObjUnlock(dev);
    } else {
        VIR_DEBUG("no device named %s", name);
    }
}


static void device_cap_lost(LibHalContext *ctx ATTRIBUTE_UNUSED,
                            const char *udi,
                            const char *cap)
{
    const char *name = hal_name(udi);
    VIR_DEBUG("%s %s", cap, name);

    dev_refresh(udi);
}


static void device_prop_modified(LibHalContext *ctx ATTRIBUTE_UNUSED,
                                 const char *udi,
                                 const char *key,
                                 dbus_bool_t is_removed ATTRIBUTE_UNUSED,
                                 dbus_bool_t is_added ATTRIBUTE_UNUSED)
{
    const char *name = hal_name(udi);
    VIR_DEBUG("%s %s", name, key);

    dev_refresh(udi);
}


static void dbus_watch_callback(int fdatch ATTRIBUTE_UNUSED,
                                int fd ATTRIBUTE_UNUSED,
                                int events, void *opaque)
{
    DBusWatch *watch = opaque;
    LibHalContext *hal_ctx;
    DBusConnection *dbus_conn;
    int dbus_flags = 0;

    if (events & VIR_EVENT_HANDLE_READABLE)
        dbus_flags |= DBUS_WATCH_READABLE;
    if (events & VIR_EVENT_HANDLE_WRITABLE)
        dbus_flags |= DBUS_WATCH_WRITABLE;
    if (events & VIR_EVENT_HANDLE_ERROR)
        dbus_flags |= DBUS_WATCH_ERROR;
    if (events & VIR_EVENT_HANDLE_HANGUP)
        dbus_flags |= DBUS_WATCH_HANGUP;

    (void)dbus_watch_handle(watch, dbus_flags);

    nodeDeviceLock(driverState);
    hal_ctx = DRV_STATE_HAL_CTX(driverState);
    dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
    nodeDeviceUnlock(driverState);
    while (dbus_connection_dispatch(dbus_conn) == DBUS_DISPATCH_DATA_REMAINS)
        /* keep dispatching while data remains */;
}


static int xlate_dbus_watch_flags(int dbus_flags)
{
    unsigned int flags = 0;
    if (dbus_flags & DBUS_WATCH_READABLE)
        flags |= VIR_EVENT_HANDLE_READABLE;
    if (dbus_flags & DBUS_WATCH_WRITABLE)
        flags |= VIR_EVENT_HANDLE_WRITABLE;
    if (dbus_flags & DBUS_WATCH_ERROR)
        flags |= VIR_EVENT_HANDLE_ERROR;
    if (dbus_flags & DBUS_WATCH_HANGUP)
        flags |= VIR_EVENT_HANDLE_HANGUP;
    return flags;
}


struct nodeDeviceWatchInfo
{
    int watch;
};

static void nodeDeviceWatchFree(void *data) {
    struct nodeDeviceWatchInfo *info = data;
    VIR_FREE(info);
}

static dbus_bool_t add_dbus_watch(DBusWatch *watch,
                                  void *data ATTRIBUTE_UNUSED)
{
    int flags = 0;
    int fd;
    struct nodeDeviceWatchInfo *info;

    if (VIR_ALLOC(info) < 0)
        return 0;

    if (dbus_watch_get_enabled(watch))
        flags = xlate_dbus_watch_flags(dbus_watch_get_flags(watch));

#if HAVE_DBUS_WATCH_GET_UNIX_FD
    fd = dbus_watch_get_unix_fd(watch);
#else
    fd = dbus_watch_get_fd(watch);
#endif
    info->watch = virEventAddHandle(fd, flags, dbus_watch_callback,
                                    watch, NULL);
    if (info->watch < 0) {
        VIR_FREE(info);
        return 0;
    }
    dbus_watch_set_data(watch, info, nodeDeviceWatchFree);

    return 1;
}


static void remove_dbus_watch(DBusWatch *watch,
                              void *data ATTRIBUTE_UNUSED)
{
    struct nodeDeviceWatchInfo *info;

    info = dbus_watch_get_data(watch);

    (void)virEventRemoveHandle(info->watch);
}


static void toggle_dbus_watch(DBusWatch *watch,
                              void *data ATTRIBUTE_UNUSED)
{
    int flags = 0;
    struct nodeDeviceWatchInfo *info;

    if (dbus_watch_get_enabled(watch))
        flags = xlate_dbus_watch_flags(dbus_watch_get_flags(watch));

    info = dbus_watch_get_data(watch);

    (void)virEventUpdateHandle(info->watch, flags);
}


static int halDeviceMonitorStartup(int privileged ATTRIBUTE_UNUSED)
{
    LibHalContext *hal_ctx = NULL;
    DBusConnection *dbus_conn = NULL;
    DBusError err;
    char **udi = NULL;
    int num_devs, i;
    int ret = -1;

    /* Ensure caps_tbl is sorted by capability name */
    qsort(caps_tbl, ARRAY_CARDINALITY(caps_tbl), sizeof(caps_tbl[0]),
          cmpstringp);

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        return -1;
    }
    nodeDeviceLock(driverState);

    /* Allocate and initialize a new HAL context */
    dbus_connection_set_change_sigpipe(FALSE);
    dbus_threads_init_default();

    dbus_error_init(&err);
    hal_ctx = libhal_ctx_new();
    if (hal_ctx == NULL) {
        VIR_ERROR(_("libhal_ctx_new returned NULL"));
        goto failure;
    }
    dbus_conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_conn == NULL) {
        VIR_ERROR(_("dbus_bus_get failed"));
        /* We don't want to show a fatal error here,
           otherwise entire libvirtd shuts down when
           D-Bus isn't running */
        ret = 0;
        goto failure;
    }
    dbus_connection_set_exit_on_disconnect(dbus_conn, FALSE);

    if (!libhal_ctx_set_dbus_connection(hal_ctx, dbus_conn)) {
        VIR_ERROR(_("libhal_ctx_set_dbus_connection failed"));
        goto failure;
    }
    if (!libhal_ctx_init(hal_ctx, &err)) {
        VIR_ERROR(_("libhal_ctx_init failed, haldaemon is probably not running"));
        /* We don't want to show a fatal error here,
           otherwise entire libvirtd shuts down when
           hald isn't running */
        ret = 0;
        goto failure;
    }

    /* Register dbus watch callbacks */
    if (!dbus_connection_set_watch_functions(dbus_conn,
                                             add_dbus_watch,
                                             remove_dbus_watch,
                                             toggle_dbus_watch,
                                             NULL, NULL)) {
        VIR_ERROR(_("dbus_connection_set_watch_functions failed"));
        goto failure;
    }

    /* Populate with known devices */
    driverState->privateData = hal_ctx;

    /* We need to unlock state now, since setting these callbacks cause
     * a dbus RPC call, and while this call is waiting for the reply,
     * a signal may already arrive, triggering the callback and thus
     * requiring the lock !
     */
    nodeDeviceUnlock(driverState);

    /* Register HAL event callbacks */
    if (!libhal_ctx_set_device_added(hal_ctx, device_added) ||
        !libhal_ctx_set_device_removed(hal_ctx, device_removed) ||
        !libhal_ctx_set_device_new_capability(hal_ctx, device_cap_added) ||
        !libhal_ctx_set_device_lost_capability(hal_ctx, device_cap_lost) ||
        !libhal_ctx_set_device_property_modified(hal_ctx, device_prop_modified) ||
        !libhal_device_property_watch_all(hal_ctx, &err)) {
        VIR_ERROR(_("setting up HAL callbacks failed"));
        goto failure;
    }

    udi = libhal_get_all_devices(hal_ctx, &num_devs, &err);
    if (udi == NULL) {
        VIR_ERROR(_("libhal_get_all_devices failed"));
        goto failure;
    }
    for (i = 0; i < num_devs; i++) {
        dev_create(udi[i]);
        VIR_FREE(udi[i]);
    }
    VIR_FREE(udi);

    return 0;

 failure:
    if (dbus_error_is_set(&err)) {
        VIR_ERROR(_("%s: %s"), err.name, err.message);
        dbus_error_free(&err);
    }
    virNodeDeviceObjListFree(&driverState->devs);
    if (hal_ctx)
        (void)libhal_ctx_free(hal_ctx);
    nodeDeviceUnlock(driverState);
    VIR_FREE(driverState);

    return ret;
}


static int halDeviceMonitorShutdown(void)
{
    if (driverState) {
        nodeDeviceLock(driverState);
        LibHalContext *hal_ctx = DRV_STATE_HAL_CTX(driverState);
        virNodeDeviceObjListFree(&driverState->devs);
        (void)libhal_ctx_shutdown(hal_ctx, NULL);
        (void)libhal_ctx_free(hal_ctx);
        nodeDeviceUnlock(driverState);
        virMutexDestroy(&driverState->lock);
        VIR_FREE(driverState);
        return 0;
    }
    return -1;
}


static int halDeviceMonitorReload(void)
{
    DBusError err;
    char **udi = NULL;
    int num_devs, i;
    LibHalContext *hal_ctx;

    VIR_INFO("Reloading HAL device state");
    nodeDeviceLock(driverState);
    VIR_INFO("Removing existing objects");
    virNodeDeviceObjListFree(&driverState->devs);
    nodeDeviceUnlock(driverState);

    hal_ctx = DRV_STATE_HAL_CTX(driverState);
    VIR_INFO("Creating new objects");
    dbus_error_init(&err);
    udi = libhal_get_all_devices(hal_ctx, &num_devs, &err);
    if (udi == NULL) {
        VIR_ERROR(_("libhal_get_all_devices failed"));
        return -1;
    }
    for (i = 0; i < num_devs; i++) {
        dev_create(udi[i]);
        VIR_FREE(udi[i]);
    }
    VIR_FREE(udi);
    VIR_INFO("HAL device reload complete");

    return 0;
}


static int halDeviceMonitorActive(void)
{
    /* Always ready to deal with a shutdown */
    return 0;
}


static virDrvOpenStatus halNodeDrvOpen(virConnectPtr conn,
                                       virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                       unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driverState == NULL)
        return VIR_DRV_OPEN_DECLINED;

    conn->devMonPrivateData = driverState;

    return VIR_DRV_OPEN_SUCCESS;
}

static int halNodeDrvClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    conn->devMonPrivateData = NULL;
    return 0;
}


static virDeviceMonitor halDeviceMonitor = {
    .name = "halDeviceMonitor",
    .open = halNodeDrvOpen, /* 0.5.0 */
    .close = halNodeDrvClose, /* 0.5.0 */
    .numOfDevices = nodeNumOfDevices, /* 0.5.0 */
    .listDevices = nodeListDevices, /* 0.5.0 */
    .deviceLookupByName = nodeDeviceLookupByName, /* 0.5.0 */
    .deviceGetXMLDesc = nodeDeviceGetXMLDesc, /* 0.5.0 */
    .deviceGetParent = nodeDeviceGetParent, /* 0.5.0 */
    .deviceNumOfCaps = nodeDeviceNumOfCaps, /* 0.5.0 */
    .deviceListCaps = nodeDeviceListCaps, /* 0.5.0 */
    .deviceCreateXML = nodeDeviceCreateXML, /* 0.6.5 */
    .deviceDestroy = nodeDeviceDestroy, /* 0.6.5 */
};


static virStateDriver halStateDriver = {
    .name = "HAL",
    .initialize = halDeviceMonitorStartup, /* 0.5.0 */
    .cleanup = halDeviceMonitorShutdown, /* 0.5.0 */
    .reload = halDeviceMonitorReload, /* 0.5.0 */
    .active = halDeviceMonitorActive, /* 0.5.0 */
};

int halNodeRegister(void)
{
    if (virRegisterDeviceMonitor(&halDeviceMonitor) < 0)
        return -1;
    return virRegisterStateDriver(&halStateDriver);
}
