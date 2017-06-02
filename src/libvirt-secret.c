/*
 * libvirt-secret.c: entry points for virSecretPtr APIs
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

VIR_LOG_INIT("libvirt.secret");

#define VIR_FROM_THIS VIR_FROM_SECRET

/**
 * virSecretGetConnect:
 * @secret: A virSecret secret
 *
 * Provides the connection pointer associated with a secret.  The reference
 * counter on the connection is not increased by this call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virSecretGetConnect(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, NULL);

    return secret->conn;
}


/**
 * virConnectNumOfSecrets:
 * @conn: virConnect connection
 *
 * Fetch number of currently defined secrets.
 *
 * Returns the number currently defined secrets.
 */
int
virConnectNumOfSecrets(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->secretDriver != NULL &&
        conn->secretDriver->connectNumOfSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->connectNumOfSecrets(conn);
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
 * virConnectListAllSecrets:
 * @conn: Pointer to the hypervisor connection.
 * @secrets: Pointer to a variable to store the array containing the secret
 *           objects or NULL if the list is not required (just returns the
 *           number of secrets).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of secrets, and allocate an array to store those
 * objects.
 *
 * Normally, all secrets are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted secrets. The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a secret, and where all bits
 * within a group describe all possible secrets.
 *
 * The first group of @flags is used to filter secrets by its storage
 * location. Flag VIR_CONNECT_LIST_SECRETS_EPHEMERAL selects secrets that
 * are kept only in memory. Flag VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL
 * selects secrets that are kept in persistent storage.
 *
 * The second group of @flags is used to filter secrets by privacy. Flag
 * VIR_CONNECT_LIST_SECRETS_PRIVATE selects secrets that are never revealed
 * to any caller of libvirt nor to any other node. Flag
 * VIR_CONNECT_LIST_SECRETS_NO_PRIVATE selects non-private secrets.
 *
 * Returns the number of secrets found or -1 and sets @secrets to NULL in case
 * of error.  On success, the array stored into @secrets is guaranteed to
 * have an extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virSecretFree() on each array element, then calling free() on @secrets.
 */
int
virConnectListAllSecrets(virConnectPtr conn,
                         virSecretPtr **secrets,
                         unsigned int flags)
{
    VIR_DEBUG("conn=%p, secrets=%p, flags=%x", conn, secrets, flags);

    virResetLastError();

    if (secrets)
        *secrets = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->secretDriver &&
        conn->secretDriver->connectListAllSecrets) {
        int ret;
        ret = conn->secretDriver->connectListAllSecrets(conn, secrets, flags);
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
 * virConnectListSecrets:
 * @conn: virConnect connection
 * @uuids: Pointer to an array to store the UUIDs
 * @maxuuids: size of the array.
 *
 * List UUIDs of defined secrets, store pointers to names in uuids.
 *
 * Returns the number of UUIDs provided in the array, or -1 on failure.
 */
int
virConnectListSecrets(virConnectPtr conn, char **uuids, int maxuuids)
{
    VIR_DEBUG("conn=%p, uuids=%p, maxuuids=%d", conn, uuids, maxuuids);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(uuids, error);
    virCheckNonNegativeArgGoto(maxuuids, error);

    if (conn->secretDriver != NULL && conn->secretDriver->connectListSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->connectListSecrets(conn, uuids, maxuuids);
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
 * virSecretLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the secret
 *
 * Try to lookup a secret on the given hypervisor based on its UUID.
 * Uses the 16 bytes of raw data to describe the UUID
 *
 * virSecretFree should be used to free the resources after the
 * secret object is no longer needed.
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (conn->secretDriver &&
        conn->secretDriver->secretLookupByUUID) {
        virSecretPtr ret;
        ret = conn->secretDriver->secretLookupByUUID(conn, uuid);
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
 * virSecretLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the secret
 *
 * Try to lookup a secret on the given hypervisor based on its UUID.
 * Uses the printable string value to describe the UUID
 *
 * virSecretFree should be used to free the resources after the
 * secret object is no longer needed.
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
        goto error;
    }

    return virSecretLookupByUUID(conn, &uuid[0]);

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretLookupByUsage:
 * @conn: pointer to the hypervisor connection
 * @usageType: the type of secret usage
 * @usageID: identifier of the object using the secret
 *
 * Try to lookup a secret on the given hypervisor based on its usage
 * The usageID is unique within the set of secrets sharing the
 * same usageType value.
 *
 * virSecretFree should be used to free the resources after the
 * secret object is no longer needed.
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUsage(virConnectPtr conn,
                       int usageType,
                       const char *usageID)
{
    VIR_DEBUG("conn=%p, usageType=%d usageID=%s", conn, usageType, NULLSTR(usageID));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(usageID, error);

    if (conn->secretDriver &&
        conn->secretDriver->secretLookupByUsage) {
        virSecretPtr ret;
        ret = conn->secretDriver->secretLookupByUsage(conn, usageType, usageID);
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
 * virSecretDefineXML:
 * @conn: virConnect connection
 * @xml: XML describing the secret.
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * If XML specifies a UUID, locates the specified secret and replaces all
 * attributes of the secret specified by UUID by attributes specified in xml
 * (any attributes not specified in xml are discarded).
 *
 * Otherwise, creates a new secret with an automatically chosen UUID, and
 * initializes its attributes from xml.
 *
 * virSecretFree should be used to free the resources after the
 * secret object is no longer needed.
 *
 * Returns a secret on success, NULL on failure.
 */
virSecretPtr
virSecretDefineXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=%x", conn, NULLSTR(xml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretDefineXML != NULL) {
        virSecretPtr ret;

        ret = conn->secretDriver->secretDefineXML(conn, xml, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretGetUUID:
 * @secret: A virSecret secret
 * @uuid: buffer of VIR_UUID_BUFLEN bytes in size
 *
 * Fetches the UUID of the secret.
 *
 * Returns 0 on success with the uuid buffer being filled, or
 * -1 upon failure.
 */
int
virSecretGetUUID(virSecretPtr secret, unsigned char *uuid)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &secret->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(secret->conn);
    return -1;
}


/**
 * virSecretGetUUIDString:
 * @secret: a secret object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a secret as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virSecretGetUUIDString(virSecretPtr secret, char *buf)
{
    VIR_DEBUG("secret=%p, buf=%p", secret, buf);

    virResetLastError();

    virCheckSecretReturn(secret, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(secret->uuid, buf);
    return 0;

 error:
    virDispatchError(secret->conn);
    return -1;
}


/**
 * virSecretGetUsageType:
 * @secret: a secret object
 *
 * Get the type of object which uses this secret. The returned
 * value is one of the constants defined in the virSecretUsageType
 * enumeration. More values may be added to this enumeration in
 * the future, so callers should expect to see usage types they
 * do not explicitly know about.
 *
 * Returns a positive integer identifying the type of object,
 * or -1 upon error.
 */
int
virSecretGetUsageType(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, -1);

    return secret->usageType;
}


/**
 * virSecretGetUsageID:
 * @secret: a secret object
 *
 * Get the unique identifier of the object with which this
 * secret is to be used. The format of the identifier is
 * dependent on the usage type of the secret. For a secret
 * with a usage type of VIR_SECRET_USAGE_TYPE_VOLUME the
 * identifier will be a fully qualified path name. The
 * identifiers are intended to be unique within the set of
 * all secrets sharing the same usage type. ie, there shall
 * only ever be one secret for each volume path.
 *
 * Returns a string identifying the object using the secret,
 * or NULL upon error
 */
const char *
virSecretGetUsageID(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, NULL);

    return secret->usageID;
}


/**
 * virSecretGetXMLDesc:
 * @secret: A virSecret secret
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Fetches an XML document describing attributes of the secret.
 *
 * Returns the XML document on success, NULL on failure.  The caller must
 * free() the XML.
 */
char *
virSecretGetXMLDesc(virSecretPtr secret, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, flags=%x", secret, flags);

    virResetLastError();

    virCheckSecretReturn(secret, NULL);
    conn = secret->conn;

    if (conn->secretDriver != NULL && conn->secretDriver->secretGetXMLDesc != NULL) {
        char *ret;

        ret = conn->secretDriver->secretGetXMLDesc(secret, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretSetValue:
 * @secret: A virSecret secret
 * @value: Value of the secret
 * @value_size: Size of the value
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Sets the value of a secret.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virSecretSetValue(virSecretPtr secret, const unsigned char *value,
                  size_t value_size, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, value=%p, value_size=%zu, flags=%x", secret, value,
              value_size, flags);

    virResetLastError();

    virCheckSecretReturn(secret, -1);
    conn = secret->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(value, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretSetValue != NULL) {
        int ret;

        ret = conn->secretDriver->secretSetValue(secret, value, value_size, flags);
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
 * virSecretGetValue:
 * @secret: A virSecret connection
 * @value_size: Place for storing size of the secret value
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Fetches the value of a secret.
 *
 * Returns the secret value on success, NULL on failure.  The caller must
 * free() the secret value.
 */
unsigned char *
virSecretGetValue(virSecretPtr secret, size_t *value_size, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, value_size=%p, flags=%x", secret, value_size, flags);

    virResetLastError();

    virCheckSecretReturn(secret, NULL);
    conn = secret->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(value_size, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretGetValue != NULL) {
        unsigned char *ret;

        ret = conn->secretDriver->secretGetValue(secret, value_size, flags, 0);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretUndefine:
 * @secret: A virSecret secret
 *
 * Deletes the specified secret.  This does not free the associated
 * virSecretPtr object.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virSecretUndefine(virSecretPtr secret)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, -1);
    conn = secret->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretUndefine != NULL) {
        int ret;

        ret = conn->secretDriver->secretUndefine(secret);
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
 * virSecretRef:
 * @secret: the secret to hold a reference on
 *
 * Increment the reference count on the secret. For each additional call to
 * this method, there shall be a corresponding call to virSecretFree to release
 * the reference count, once the caller no longer needs the reference to this
 * object.
 *
 * This method is typically useful for applications where multiple threads are
 * using a connection, and it is required that the connection remain open until
 * all threads have finished using it. ie, each new thread using a secret would
 * increment the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virSecretRef(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p refs=%d", secret,
              secret ? secret->object.u.s.refs : 0);

    virResetLastError();

    virCheckSecretReturn(secret, -1);

    virObjectRef(secret);
    return 0;
}


/**
 * virSecretFree:
 * @secret: pointer to a secret
 *
 * Release the secret handle. The underlying secret continues to exist.
 *
 * Returns 0 on success, or -1 on error
 */
int
virSecretFree(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    virCheckSecretReturn(secret, -1);

    virObjectUnref(secret);
    return 0;
}


/**
 * virConnectSecretEventRegisterAny:
 * @conn: pointer to the connection
 * @secret: pointer to the secret
 * @eventID: the event type to receive
 * @cb: callback to the function handling secret events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary secret events
 * occurring on a secret. This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * If @secret is NULL, then events will be monitored for any secret.
 * If @secret is non-NULL, then only the specific secret will be monitored.
 *
 * Most types of events have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_SECRET_EVENT_CALLBACK() macro to cast the
 * supplied function pointer to match the signature of this method.
 *
 * The virSecretPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the secret object after the callback
 * returns, it shall take a reference to it, by calling virSecretRef().
 * The reference can be released once the object is no longer required
 * by calling virSecretFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectSecretEventDeregisterAny() method.
 *
 * Returns a callback identifier on success, -1 on failure.
 */
int
virConnectSecretEventRegisterAny(virConnectPtr conn,
                                 virSecretPtr secret,
                                 int eventID,
                                 virConnectSecretEventGenericCallback cb,
                                 void *opaque,
                                 virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p, secret=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
              conn, secret, eventID, cb, opaque, freecb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (secret) {
        virCheckSecretGoto(secret, error);
        if (secret->conn != conn) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(secret->uuid, uuidstr);
            virReportInvalidArg(secret,
                                _("secret '%s' in %s must match connection"),
                                uuidstr, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);

    if (eventID >= VIR_SECRET_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %s must be less than %d"),
                            __FUNCTION__, VIR_SECRET_EVENT_ID_LAST);
        goto error;
    }

    if (conn->secretDriver &&
        conn->secretDriver->connectSecretEventRegisterAny) {
        int ret;
        ret = conn->secretDriver->connectSecretEventRegisterAny(conn,
                                                                secret,
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
 * virConnectSecretEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectSecretEventRegisterAny() method.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virConnectSecretEventDeregisterAny(virConnectPtr conn,
                                   int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);

    if (conn->secretDriver &&
        conn->secretDriver->connectSecretEventDeregisterAny) {
        int ret;
        ret = conn->secretDriver->connectSecretEventDeregisterAny(conn,
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
