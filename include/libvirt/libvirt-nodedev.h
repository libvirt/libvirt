/*
 * libvirt-nodedev.h
 * Summary: APIs for management of nodedevs
 * Description: Provides APIs for the management of nodedevs
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef LIBVIRT_NODEDEV_H
# define LIBVIRT_NODEDEV_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


/**
 * virNodeDevice:
 *
 * A virNodeDevice contains a node (host) device details.
 *
 * Since: 0.5.0
 */
typedef struct _virNodeDevice virNodeDevice;

/**
 * virNodeDevicePtr:
 *
 * A virNodeDevicePtr is a pointer to a virNodeDevice structure.  Get
 * one via virNodeDeviceLookupByName, or virNodeDeviceCreate.  Be sure
 * to call virNodeDeviceFree when done using a virNodeDevicePtr obtained
 * from any of the above functions to avoid leaking memory.
 *
 * Since: 0.5.0
 */
typedef virNodeDevice *virNodeDevicePtr;


int                     virNodeNumOfDevices     (virConnectPtr conn,
                                                 const char *cap,
                                                 unsigned int flags);

int                     virNodeListDevices      (virConnectPtr conn,
                                                 const char *cap,
                                                 char **const names,
                                                 int maxnames,
                                                 unsigned int flags);
/**
 * virConnectListAllNodeDeviceFlags:
 *
 * Flags used to filter either by capability or active state, the
 * returned node devices.
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM        = 1 << 0,  /* System capability (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV       = 1 << 1,  /* PCI device (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV       = 1 << 2,  /* USB device (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE = 1 << 3,  /* USB interface (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET           = 1 << 4,  /* Network device (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST     = 1 << 5,  /* SCSI Host Bus Adapter (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET   = 1 << 6,  /* SCSI Target (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI          = 1 << 7,  /* SCSI device (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE       = 1 << 8,  /* Storage device (Since: 0.10.2) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST       = 1 << 9,  /* FC Host Bus Adapter (Since: 1.0.4) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPORTS        = 1 << 10, /* Capable of vport (Since: 1.0.4) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC  = 1 << 11, /* Capable of scsi_generic (Since: 1.1.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_DRM           = 1 << 12, /* DRM device (Since: 3.1.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV_TYPES    = 1 << 13, /* Capable of mediated devices (Since: 3.4.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV          = 1 << 14, /* Mediated device (Since: 3.4.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_CCW_DEV       = 1 << 15, /* CCW device (Since: 3.4.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_CSS_DEV       = 1 << 16, /* CSS device (Since: 6.8.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_VDPA          = 1 << 17, /* vDPA device (Since: 6.9.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_CARD       = 1 << 18, /* s390 AP Card device (Since: 7.0.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_QUEUE      = 1 << 19, /* s390 AP Queue (Since: 7.0.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_MATRIX     = 1 << 20, /* s390 AP Matrix (Since: 7.0.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPD           = 1 << 21, /* Device with VPD (Since: 7.9.0) */

    VIR_CONNECT_LIST_NODE_DEVICES_INACTIVE          = 1 << 30, /* Inactive devices (Since: 7.3.0) */
    VIR_CONNECT_LIST_NODE_DEVICES_ACTIVE            = 1U << 31, /* Active devices (Since: 7.3.0) */
} virConnectListAllNodeDeviceFlags;

int                     virConnectListAllNodeDevices (virConnectPtr conn,
                                                      virNodeDevicePtr **devices,
                                                      unsigned int flags);

virNodeDevicePtr        virNodeDeviceLookupByName (virConnectPtr conn,
                                                   const char *name);

virNodeDevicePtr        virNodeDeviceLookupSCSIHostByWWN (virConnectPtr conn,
                                                          const char *wwnn,
                                                          const char *wwpn,
                                                          unsigned int flags);

const char *            virNodeDeviceGetName     (virNodeDevicePtr dev);

const char *            virNodeDeviceGetParent   (virNodeDevicePtr dev);

int                     virNodeDeviceNumOfCaps   (virNodeDevicePtr dev);

int                     virNodeDeviceListCaps    (virNodeDevicePtr dev,
                                                  char **const names,
                                                  int maxnames);

char *                  virNodeDeviceGetXMLDesc (virNodeDevicePtr dev,
                                                 unsigned int flags);

int                     virNodeDeviceRef        (virNodeDevicePtr dev);
int                     virNodeDeviceFree       (virNodeDevicePtr dev);

int                     virNodeDeviceDettach    (virNodeDevicePtr dev);
int                     virNodeDeviceDetachFlags(virNodeDevicePtr dev,
                                                 const char *driverName,
                                                 unsigned int flags);
int                     virNodeDeviceReAttach   (virNodeDevicePtr dev);
int                     virNodeDeviceReset      (virNodeDevicePtr dev);

/**
 * virNodeDeviceCreateXMLFlags:
 *
 * Since: 8.10.0
 */
typedef enum {
    VIR_NODE_DEVICE_CREATE_XML_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 8.10.0) */
} virNodeDeviceCreateXMLFlags;

virNodeDevicePtr        virNodeDeviceCreateXML  (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);

int                     virNodeDeviceDestroy    (virNodeDevicePtr dev);


/**
 * virNodeDeviceDefineXMLFlags:
 *
 * Since: 8.10.0
 */
typedef enum {
    VIR_NODE_DEVICE_DEFINE_XML_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 8.10.0) */
} virNodeDeviceDefineXMLFlags;

virNodeDevicePtr virNodeDeviceDefineXML(virConnectPtr conn,
                                        const char *xmlDesc,
                                        unsigned int flags);

int virNodeDeviceUndefine(virNodeDevicePtr dev,
                          unsigned int flags);

int virNodeDeviceCreate(virNodeDevicePtr dev,
                        unsigned int flags);

int virNodeDeviceSetAutostart(virNodeDevicePtr dev,
                              int autostart);

int virNodeDeviceGetAutostart(virNodeDevicePtr dev,
                              int *autostart);

int virNodeDeviceIsPersistent(virNodeDevicePtr dev);

int virNodeDeviceIsActive(virNodeDevicePtr dev);

/**
 * VIR_NODE_DEVICE_EVENT_CALLBACK:
 *
 * Used to cast the event specific callback into the generic one
 * for use for virConnectNodeDeviceEventRegisterAny()
 *
 * Since: 2.2.0
 */
# define VIR_NODE_DEVICE_EVENT_CALLBACK(cb)((virConnectNodeDeviceEventGenericCallback)(cb))

/**
 * virNodeDeviceEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectNodeDeviceEventRegisterAny(). Each event id determines which
 * signature of callback function will be used.
 *
 * Since: 2.2.0
 */
typedef enum {
    VIR_NODE_DEVICE_EVENT_ID_LIFECYCLE = 0, /* virConnectNodeDeviceEventLifecycleCallback (Since: 2.2.0) */
    VIR_NODE_DEVICE_EVENT_ID_UPDATE = 1, /* virConnectNodeDeviceEventGenericCallback (Since: 2.2.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_NODE_DEVICE_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     *
     * Since: 2.2.0
     */
# endif
} virNodeDeviceEventID;

/**
 * virConnectNodeDeviceEventGenericCallback:
 * @conn: the connection pointer
 * @dev: the node device pointer
 * @opaque: application specified data
 *
 * A generic node device event callback handler, for use with
 * virConnectNodeDeviceEventRegisterAny(). Specific events usually
 * have a customization with extra parameters, often with @opaque being
 * passed in a different parameter position; use
 * VIR_NODE_DEVICE_EVENT_CALLBACK() when registering an appropriate handler.
 *
 * Since: 2.2.0
 */
typedef void (*virConnectNodeDeviceEventGenericCallback)(virConnectPtr conn,
                                                         virNodeDevicePtr dev,
                                                         void *opaque);

/* Use VIR_NODE_DEVICE_EVENT_CALLBACK() to cast the 'cb' parameter  */
int virConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                         virNodeDevicePtr dev, /* optional, to filter */
                                         int eventID,
                                         virConnectNodeDeviceEventGenericCallback cb,
                                         void *opaque,
                                         virFreeCallback freecb);

int virConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                           int callbackID);

/**
 * virNodeDeviceEventLifecycleType:
 *
 * a virNodeDeviceEventLifecycleType is emitted during node device
 * lifecycle events
 *
 * Since: 2.2.0
 */
typedef enum {
    VIR_NODE_DEVICE_EVENT_CREATED = 0, /* (Since: 2.2.0) */
    VIR_NODE_DEVICE_EVENT_DELETED = 1, /* (Since: 2.2.0) */
    VIR_NODE_DEVICE_EVENT_DEFINED = 2, /* (Since: 7.3.0) */
    VIR_NODE_DEVICE_EVENT_UNDEFINED = 3, /* (Since: 7.3.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_NODE_DEVICE_EVENT_LAST /* (Since: 2.2.0) */
# endif
} virNodeDeviceEventLifecycleType;

/**
 * virConnectNodeDeviceEventLifecycleCallback:
 * @conn: connection object
 * @dev: node device on which the event occurred
 * @event: The specific virNodeDeviceEventLifecycleType which occurred
 * @detail: contains some details on the reason of the event.
 * @opaque: application specified data
 *
 * This callback is called when a node device lifecycle action is performed,
 * like added or removed.
 *
 * The callback signature to use when registering for an event of type
 * VIR_NODE_DEVICE_EVENT_ID_LIFECYCLE with
 * virConnectNodeDeviceEventRegisterAny()
 *
 * Since: 2.2.0
 */
typedef void (*virConnectNodeDeviceEventLifecycleCallback)(virConnectPtr conn,
                                                           virNodeDevicePtr dev,
                                                           int event,
                                                           int detail,
                                                           void *opaque);

#endif /* LIBVIRT_NODEDEV_H */
