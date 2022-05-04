/*
 * libvirt-secret.h
 * Summary: APIs for management of secrets
 * Description: Provides APIs for the management of secrets
 *
 * Copyright (C) 2006-2014, 2016 Red Hat, Inc.
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

#ifndef LIBVIRT_SECRET_H
# define LIBVIRT_SECRET_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


/**
 * virSecret:
 *
 * A virSecret stores a secret value (e.g. a passphrase or encryption key)
 * and associated metadata.
 *
 * Since: 0.7.1
 */
typedef struct _virSecret virSecret;

/**
 * virSecretPtr:
 *
 * Since: 0.7.1
 */
typedef virSecret *virSecretPtr;

/**
 * virSecretUsageType:
 *
 * Since: 0.7.1
 */
typedef enum {
    VIR_SECRET_USAGE_TYPE_NONE = 0, /* (Since: 0.7.1) */
    VIR_SECRET_USAGE_TYPE_VOLUME = 1, /* (Since: 0.7.1) */
    VIR_SECRET_USAGE_TYPE_CEPH = 2, /* (Since: 0.9.7) */
    VIR_SECRET_USAGE_TYPE_ISCSI = 3, /* (Since: 1.0.4) */
    VIR_SECRET_USAGE_TYPE_TLS = 4, /* (Since: 2.3.0) */
    VIR_SECRET_USAGE_TYPE_VTPM = 5, /* (Since: 5.6.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_SECRET_USAGE_TYPE_LAST
    /*
     * NB: this enum value will increase over time as new usage types are
     * added to the libvirt API. It reflects the last usage type supported
     * by this version of the libvirt API.
     *
     * Since: 0.9.7
     */
# endif
} virSecretUsageType;

virConnectPtr           virSecretGetConnect     (virSecretPtr secret);
int                     virConnectNumOfSecrets  (virConnectPtr conn);
int                     virConnectListSecrets   (virConnectPtr conn,
                                                 char **uuids,
                                                 int maxuuids);

/**
 * virConnectListAllSecretsFlags:
 *
 * Flags used to filter the returned secrets. Flags in each group
 * are exclusive attributes of a secret.
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_CONNECT_LIST_SECRETS_EPHEMERAL    = 1 << 0, /* kept in memory, never
                                                       stored persistently (Since: 0.10.2) */
    VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL = 1 << 1, /* (Since: 0.10.2) */

    VIR_CONNECT_LIST_SECRETS_PRIVATE      = 1 << 2, /* not revealed to any caller
                                                       of libvirt, nor to any other
                                                       node (Since: 0.10.2) */
    VIR_CONNECT_LIST_SECRETS_NO_PRIVATE   = 1 << 3, /* (Since: 0.10.2) */
} virConnectListAllSecretsFlags;

int                     virConnectListAllSecrets(virConnectPtr conn,
                                                 virSecretPtr **secrets,
                                                 unsigned int flags);
virSecretPtr            virSecretLookupByUUID(virConnectPtr conn,
                                              const unsigned char *uuid);
virSecretPtr            virSecretLookupByUUIDString(virConnectPtr conn,
                                                    const char *uuid);
virSecretPtr            virSecretLookupByUsage(virConnectPtr conn,
                                               int usageType,
                                               const char *usageID);
/**
 * virSecretDefineFlags:
 *
 * Since: 7.7.0
 */
typedef enum {
    VIR_SECRET_DEFINE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.7.0) */
} virSecretDefineFlags;

virSecretPtr            virSecretDefineXML      (virConnectPtr conn,
                                                 const char *xml,
                                                 unsigned int flags);
int                     virSecretGetUUID        (virSecretPtr secret,
                                                 unsigned char *buf);
int                     virSecretGetUUIDString  (virSecretPtr secret,
                                                 char *buf);
int                     virSecretGetUsageType   (virSecretPtr secret);
const char *            virSecretGetUsageID     (virSecretPtr secret);
char *                  virSecretGetXMLDesc     (virSecretPtr secret,
                                                 unsigned int flags);
int                     virSecretSetValue       (virSecretPtr secret,
                                                 const unsigned char *value,
                                                 size_t value_size,
                                                 unsigned int flags);
unsigned char *         virSecretGetValue       (virSecretPtr secret,
                                                 size_t *value_size,
                                                 unsigned int flags);
int                     virSecretUndefine       (virSecretPtr secret);
int                     virSecretRef            (virSecretPtr secret);
int                     virSecretFree           (virSecretPtr secret);

/**
 * VIR_SECRET_EVENT_CALLBACK:
 *
 * Used to cast the event specific callback into the generic one
 * for use for virConnectSecretEventRegisterAny()
 *
 * Since: 3.0.0
 */
# define VIR_SECRET_EVENT_CALLBACK(cb)((virConnectSecretEventGenericCallback)(cb))

/**
 * virSecretEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectSecretEventRegisterAny(). Each event id determines which
 * signature of callback function will be used.
 *
 * Since: 3.0.0
 */
typedef enum {
    VIR_SECRET_EVENT_ID_LIFECYCLE = 0, /* virConnectSecretEventLifecycleCallback (Since: 3.0.0) */
    VIR_SECRET_EVENT_ID_VALUE_CHANGED = 1, /* virConnectSecretEventGenericCallback (Since: 3.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_SECRET_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     *
     * Since: 3.0.0
     */
# endif
} virSecretEventID;

/**
 * virConnectSecretEventGenericCallback:
 * @conn: the connection pointer
 * @secret: the secret pointer
 * @opaque: application specified data
 *
 * A generic secret event callback handler, for use with
 * virConnectSecretEventRegisterAny(). Specific events usually
 * have a customization with extra parameters, often with @opaque being
 * passed in a different parameter position; use
 * VIR_SECRET_EVENT_CALLBACK() when registering an appropriate handler.
 *
 * Since: 3.0.0
 */
typedef void (*virConnectSecretEventGenericCallback)(virConnectPtr conn,
                                                     virSecretPtr secret,
                                                     void *opaque);

/* Use VIR_SECRET_EVENT_CALLBACK() to cast the 'cb' parameter  */
int virConnectSecretEventRegisterAny(virConnectPtr conn,
                                     virSecretPtr secret, /* optional, to filter */
                                     int eventID,
                                     virConnectSecretEventGenericCallback cb,
                                     void *opaque,
                                     virFreeCallback freecb);

int virConnectSecretEventDeregisterAny(virConnectPtr conn,
                                       int callbackID);

/**
 * virSecretEventLifecycleType:
 *
 * a virSecretEventLifecycleType is emitted during secret
 * lifecycle events
 *
 * Since: 3.0.0
 */
typedef enum {
    VIR_SECRET_EVENT_DEFINED = 0, /* (Since: 3.0.0) */
    VIR_SECRET_EVENT_UNDEFINED = 1, /* (Since: 3.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_SECRET_EVENT_LAST /* (Since: 3.0.0) */
# endif
} virSecretEventLifecycleType;

/**
 * virConnectSecretEventLifecycleCallback:
 * @conn: connection object
 * @secret: secret on which the event occurred
 * @event: The specific virSecretEventLifecycleType which occurred
 * @detail: contains some details on the reason of the event (currently unused)
 * @opaque: application specified data
 *
 * This callback is called when a secret lifecycle action is performed,
 * like added or removed.
 *
 * The callback signature to use when registering for an event of type
 * VIR_SECRET_EVENT_ID_LIFECYCLE with
 * virConnectSecretEventRegisterAny()
 *
 * Since: 3.0.0
 */
typedef void (*virConnectSecretEventLifecycleCallback)(virConnectPtr conn,
                                                       virSecretPtr secret,
                                                       int event,
                                                       int detail,
                                                       void *opaque);


#endif /* LIBVIRT_SECRET_H */
