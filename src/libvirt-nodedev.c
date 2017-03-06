/*
 * libvirt-nodedev.c: entry points for virNodeDevPtr APIs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("libvirt.nodedev");

#define VIR_FROM_THIS VIR_FROM_NODEDEV


/**
 * virNodeNumOfDevices:
 * @conn: pointer to the hypervisor connection
 * @cap: capability name
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Provides the number of node devices.
 *
 * If the optional 'cap'  argument is non-NULL, then the count
 * will be restricted to devices with the specified capability
 *
 * Returns the number of node devices or -1 in case of error
 */
int
virNodeNumOfDevices(virConnectPtr conn, const char *cap, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cap=%s, flags=%x", conn, NULLSTR(cap), flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeNumOfDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->nodeNumOfDevices(conn, cap, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectListAllNodeDevices:
 * @conn: Pointer to the hypervisor connection.
 * @devices: Pointer to a variable to store the array containing the node
 *           device objects or NULL if the list is not required (just returns
 *           number of node devices).
 * @flags: bitwise-OR of virConnectListAllNodeDevices.
 *
 * Collect the list of node devices, and allocate an array to store those
 * objects.
 *
 * Normally, all node devices are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted node devices.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a node device, and where all bits
 * within a group describe all possible node devices.
 *
 * Only one group of the @flags is provided to filter the node devices by
 * capability type, flags include:
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPORTS
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_DRM
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV_TYPES
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV
 *
 * Returns the number of node devices found or -1 and sets @devices to NULL in
 * case of error.  On success, the array stored into @devices is guaranteed to
 * have an extra allocated element set to NULL but not included in the return
 * count, to make iteration easier.  The caller is responsible for calling
 * virNodeDeviceFree() on each array element, then calling free() on
 * @devices.
 */
int
virConnectListAllNodeDevices(virConnectPtr conn,
                             virNodeDevicePtr **devices,
                             unsigned int flags)
{
    VIR_DEBUG("conn=%p, devices=%p, flags=%x", conn, devices, flags);

    virResetLastError();

    if (devices)
        *devices = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->connectListAllNodeDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->connectListAllNodeDevices(conn, devices, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeListDevices:
 * @conn: pointer to the hypervisor connection
 * @cap: capability name
 * @names: array to collect the list of node device names
 * @maxnames: size of @names
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of node devices, and store their names in @names
 *
 * For more control over the results, see virConnectListAllNodeDevices().
 *
 * If the optional 'cap'  argument is non-NULL, then the count
 * will be restricted to devices with the specified capability
 *
 * Returns the number of node devices found or -1 in case of error
 */
int
virNodeListDevices(virConnectPtr conn,
                   const char *cap,
                   char **const names, int maxnames,
                   unsigned int flags)
{
    VIR_DEBUG("conn=%p, cap=%s, names=%p, maxnames=%d, flags=%x",
              conn, NULLSTR(cap), names, maxnames, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeListDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->nodeListDevices(conn, cap, names, maxnames, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeDeviceLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: unique device name
 *
 * Lookup a node device by its name.
 *
 * virNodeDeviceFree should be used to free the resources after the
 * node device object is no longer needed.
 *
 * Returns a virNodeDevicePtr if found, NULL otherwise.
 */
virNodeDevicePtr
virNodeDeviceLookupByName(virConnectPtr conn, const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeDeviceLookupByName) {
        virNodeDevicePtr ret;
        ret = conn->nodeDeviceDriver->nodeDeviceLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNodeDeviceLookupSCSIHostByWWN:
 * @conn: pointer to the hypervisor connection
 * @wwnn: WWNN of the SCSI Host.
 * @wwpn: WWPN of the SCSI Host.
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Lookup SCSI Host which is capable with 'fc_host' by its WWNN and WWPN.
 *
 * virNodeDeviceFree should be used to free the resources after the
 * node device object is no longer needed.
 *
 * Returns a virNodeDevicePtr if found, NULL otherwise.
 */
virNodeDevicePtr
virNodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                                 const char *wwnn,
                                 const char *wwpn,
                                 unsigned int flags)
{
    VIR_DEBUG("conn=%p, wwnn=%s, wwpn=%s, flags=%x", conn, NULLSTR(wwnn), NULLSTR(wwpn), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(wwnn, error);
    virCheckNonNullArgGoto(wwpn, error);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->nodeDeviceLookupSCSIHostByWWN) {
        virNodeDevicePtr ret;
        ret = conn->nodeDeviceDriver->nodeDeviceLookupSCSIHostByWWN(conn, wwnn,
                                                             wwpn, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNodeDeviceGetXMLDesc:
 * @dev: pointer to the node device
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Fetch an XML document describing all aspects of
 * the device.
 *
 * Returns the XML document, or NULL on error
 */
char *
virNodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags)
{
    VIR_DEBUG("dev=%p, conn=%p, flags=%x", dev, dev ? dev->conn : NULL, flags);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, NULL);

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceGetXMLDesc) {
        char *ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceGetXMLDesc(dev, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return NULL;
}


/**
 * virNodeDeviceGetName:
 * @dev: the device
 *
 * Just return the device name
 *
 * Returns the device name or NULL in case of error
 */
const char *
virNodeDeviceGetName(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, NULL);

    return dev->name;
}


/**
 * virNodeDeviceGetParent:
 * @dev: the device
 *
 * Accessor for the parent of the device
 *
 * Returns the name of the device's parent, or NULL if an
 * error occurred or when the device has no parent.
 */
const char *
virNodeDeviceGetParent(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, NULL);

    if (!dev->parent) {
        if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceGetParent) {
            dev->parent = dev->conn->nodeDeviceDriver->nodeDeviceGetParent(dev);
        } else {
            virReportUnsupportedError();
            virDispatchError(dev->conn);
            return NULL;
        }
    }
    return dev->parent;
}


/**
 * virNodeDeviceNumOfCaps:
 * @dev: the device
 *
 * Accessor for the number of capabilities supported by the device.
 *
 * Returns the number of capabilities supported by the device or -1
 * in case of error.
 */
int
virNodeDeviceNumOfCaps(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceNumOfCaps) {
        int ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceNumOfCaps(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceListCaps:
 * @dev: the device
 * @names: array to collect the list of capability names
 * @maxnames: size of @names
 *
 * Lists the names of the capabilities supported by the device.
 *
 * Returns the number of capability names listed in @names or -1
 * in case of error.
 */
int
virNodeDeviceListCaps(virNodeDevicePtr dev,
                      char **const names,
                      int maxnames)
{
    VIR_DEBUG("dev=%p, conn=%p, names=%p, maxnames=%d",
          dev, dev ? dev->conn : NULL, names, maxnames);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceListCaps) {
        int ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceListCaps(dev, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceFree:
 * @dev: pointer to the node device
 *
 * Drops a reference to the node device, freeing it if
 * this was the last reference.
 *
 * Returns the 0 for success, -1 for error.
 */
int
virNodeDeviceFree(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);

    virObjectUnref(dev);
    return 0;
}


/**
 * virNodeDeviceRef:
 * @dev: the dev to hold a reference on
 *
 * Increment the reference count on the dev. For each
 * additional call to this method, there shall be a corresponding
 * call to virNodeDeviceFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a dev would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceRef(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p refs=%d", dev, dev ? dev->object.u.s.refs : 0);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);

    virObjectRef(dev);
    return 0;
}


/**
 * virNodeDeviceDettach:
 * @dev: pointer to the node device
 *
 * Dettach the node device from the node itself so that it may be
 * assigned to a guest domain.
 *
 * Depending on the hypervisor, this may involve operations such
 * as unbinding any device drivers from the device, binding the
 * device to a dummy device driver and resetting the device.
 *
 * If the device is currently in use by the node, this method may
 * fail.
 *
 * Once the device is not assigned to any guest, it may be re-attached
 * to the node using the virNodeDeviceReattach() method.
 *
 * If the caller needs control over which backend driver will be used
 * during PCI device assignment (to use something other than the
 * default, for example VFIO), the newer virNodeDeviceDetachFlags()
 * API should be used instead.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceDettach(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckReadOnlyGoto(dev->conn->flags, error);

    if (dev->conn->driver->nodeDeviceDettach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceDettach(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceDetachFlags:
 * @dev: pointer to the node device
 * @driverName: name of backend driver that will be used
 *              for later device assignment to a domain. NULL
 *              means "use the hypervisor default driver"
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Detach the node device from the node itself so that it may be
 * assigned to a guest domain.
 *
 * Depending on the hypervisor, this may involve operations such as
 * unbinding any device drivers from the device, binding the device to
 * a dummy device driver and resetting the device. Different backend
 * drivers expect the device to be bound to different dummy
 * devices. For example, QEMU's "kvm" backend driver (the default)
 * expects the device to be bound to "pci-stub", but its "vfio"
 * backend driver expects the device to be bound to "vfio-pci".
 *
 * If the device is currently in use by the node, this method may
 * fail.
 *
 * Once the device is not assigned to any guest, it may be re-attached
 * to the node using the virNodeDeviceReAttach() method.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceDetachFlags(virNodeDevicePtr dev,
                         const char *driverName,
                         unsigned int flags)
{
    VIR_DEBUG("dev=%p, conn=%p driverName=%s flags=%x",
              dev, dev ? dev->conn : NULL,
              driverName ? driverName : "(default)", flags);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckReadOnlyGoto(dev->conn->flags, error);

    if (dev->conn->driver->nodeDeviceDetachFlags) {
        int ret;
        ret = dev->conn->driver->nodeDeviceDetachFlags(dev, driverName, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceReAttach:
 * @dev: pointer to the node device
 *
 * Re-attach a previously detached node device to the node so that it
 * may be used by the node again.
 *
 * Depending on the hypervisor, this may involve operations such
 * as resetting the device, unbinding it from a dummy device driver
 * and binding it to its appropriate driver.
 *
 * If the device is currently in use by a guest, this method may fail.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceReAttach(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckReadOnlyGoto(dev->conn->flags, error);

    if (dev->conn->driver->nodeDeviceReAttach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReAttach(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceReset:
 * @dev: pointer to the node device
 *
 * Reset a previously detached node device to the node before or
 * after assigning it to a guest.
 *
 * The exact reset semantics depends on the hypervisor and device
 * type but, for example, KVM will attempt to reset PCI devices with
 * a Function Level Reset, Secondary Bus Reset or a Power Management
 * D-State reset.
 *
 * If the reset will affect other devices which are currently in use,
 * this function may fail.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceReset(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckReadOnlyGoto(dev->conn->flags, error);

    if (dev->conn->driver->nodeDeviceReset) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReset(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the device to be created
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Create a new device on the VM host machine, for example, virtual
 * HBAs created using vport_create.
 *
 * virNodeDeviceFree should be used to free the resources after the
 * node device object is no longer needed.
 *
 * Returns a node device object if successful, NULL in case of failure
 */
virNodeDevicePtr
virNodeDeviceCreateXML(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->nodeDeviceCreateXML) {
        virNodeDevicePtr dev = conn->nodeDeviceDriver->nodeDeviceCreateXML(conn, xmlDesc, flags);
        if (dev == NULL)
            goto error;
        return dev;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNodeDeviceDestroy:
 * @dev: a device object
 *
 * Destroy the device object. The virtual device (only works for vHBA
 * currently) is removed from the host operating system.  This function
 * may require privileged access.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNodeDeviceDestroy(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p", dev);

    virResetLastError();

    virCheckNodeDeviceReturn(dev, -1);
    virCheckReadOnlyGoto(dev->conn->flags, error);

    if (dev->conn->nodeDeviceDriver &&
        dev->conn->nodeDeviceDriver->nodeDeviceDestroy) {
        int retval = dev->conn->nodeDeviceDriver->nodeDeviceDestroy(dev);
        if (retval < 0)
            goto error;

        return 0;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virConnectNodeDeviceEventRegisterAny:
 * @conn: pointer to the connection
 * @dev: pointer to the node device
 * @eventID: the event type to receive
 * @cb: callback to the function handling node device events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary node device events
 * occurring on a node device. This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * If @dev is NULL, then events will be monitored for any node device.
 * If @dev is non-NULL, then only the specific node device will be monitored.
 *
 * Most types of events have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_NODE_DEVICE_EVENT_CALLBACK() macro to cast the
 * supplied function pointer to match the signature of this method.
 *
 * The virNodeDevicePtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the node device object after the callback
 * returns, it shall take a reference to it, by calling virNodeDeviceRef().
 * The reference can be released once the object is no longer required
 * by calling virNodeDeviceFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectNodeDeviceEventDeregisterAny() method.
 *
 * Returns a callback identifier on success, -1 on failure.
 */
int
virConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                     virNodeDevicePtr dev,
                                     int eventID,
                                     virConnectNodeDeviceEventGenericCallback cb,
                                     void *opaque,
                                     virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p, nodeDevice=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
              conn, dev, eventID, cb, opaque, freecb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (dev) {
        virCheckNodeDeviceGoto(dev, error);
        if (dev->conn != conn) {
            virReportInvalidArg(dev,
                                _("node device '%s' in %s must match connection"),
                                dev->name, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);

    if (eventID >= VIR_NODE_DEVICE_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %s must be less than %d"),
                            __FUNCTION__, VIR_NODE_DEVICE_EVENT_ID_LAST);
        goto error;
    }

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->connectNodeDeviceEventRegisterAny) {
        int ret;
        ret = conn->nodeDeviceDriver->connectNodeDeviceEventRegisterAny(conn,
                                                                        dev,
                                                                        eventID,
                                                                        cb,
                                                                        opaque,
                                                                        freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectNodeDeviceEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectNodeDeviceEventRegisterAny() method.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                       int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->connectNodeDeviceEventDeregisterAny) {
        int ret;
        ret = conn->nodeDeviceDriver->connectNodeDeviceEventDeregisterAny(conn,
                                                                          callbackID);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}
