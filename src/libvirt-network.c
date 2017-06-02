/*
 * libvirt-network.c: entry points for virNetworkPtr APIs
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
#include "viralloc.h"
#include "virlog.h"

VIR_LOG_INIT("libvirt.network");

#define VIR_FROM_THIS VIR_FROM_NETWORK

/**
 * virNetworkGetConnect:
 * @net: pointer to a network
 *
 * Provides the connection pointer associated with a network.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virNetworkGetConnect(virNetworkPtr net)
{
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    virCheckNetworkReturn(net, NULL);

    return net->conn;
}


/**
 * virConnectListAllNetworks:
 * @conn: Pointer to the hypervisor connection.
 * @nets: Pointer to a variable to store the array containing the network
 *        objects or NULL if the list is not required (just returns number
 *        of networks).
 * @flags: bitwise-OR of virConnectListAllNetworksFlags.
 *
 * Collect the list of networks, and allocate an array to store those
 * objects. This API solves the race inherent between virConnectListNetworks
 * and virConnectListDefinedNetworks.
 *
 * Normally, all networks are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted networks.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a network, and where all bits
 * within a group describe all possible networks.
 *
 * The first group of @flags is VIR_CONNECT_LIST_NETWORKS_ACTIVE (up) and
 * VIR_CONNECT_LIST_NETWORKS_INACTIVE (down) to filter the networks by state.
 *
 * The second group of @flags is VIR_CONNECT_LIST_NETWORKS_PERSISTENT (defined)
 * and VIR_CONNECT_LIST_NETWORKS_TRANSIENT (running but not defined), to filter
 * the networks by whether they have persistent config or not.
 *
 * The third group of @flags is VIR_CONNECT_LIST_NETWORKS_AUTOSTART
 * and VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART, to filter the networks by
 * whether they are marked as autostart or not.
 *
 * Returns the number of networks found or -1 and sets @nets to  NULL in case
 * of error.  On success, the array stored into @nets is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virNetworkFree() on each array element, then calling free() on @nets.
 */
int
virConnectListAllNetworks(virConnectPtr conn,
                          virNetworkPtr **nets,
                          unsigned int flags)
{
    VIR_DEBUG("conn=%p, nets=%p, flags=%x", conn, nets, flags);

    virResetLastError();

    if (nets)
        *nets = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->networkDriver &&
        conn->networkDriver->connectListAllNetworks) {
        int ret;
        ret = conn->networkDriver->connectListAllNetworks(conn, nets, flags);
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
 * virConnectNumOfNetworks:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active networks.
 *
 * Returns the number of network found or -1 in case of error
 */
int
virConnectNumOfNetworks(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->networkDriver && conn->networkDriver->connectNumOfNetworks) {
        int ret;
        ret = conn->networkDriver->connectNumOfNetworks(conn);
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
 * virConnectListNetworks:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of active networks
 * @maxnames: size of @names
 *
 * Collect the list of active networks, and store their names in @names
 *
 * For more control over the results, see virConnectListAllNetworks().
 *
 * Returns the number of networks found or -1 in case of error.  Note that
 * this command is inherently racy; a network can be started between a call
 * to virConnectNumOfNetworks() and this call; you are only guaranteed that
 * all currently active networks were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 */
int
virConnectListNetworks(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->networkDriver && conn->networkDriver->connectListNetworks) {
        int ret;
        ret = conn->networkDriver->connectListNetworks(conn, names, maxnames);
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
 * virConnectNumOfDefinedNetworks:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of inactive networks.
 *
 * Returns the number of networks found or -1 in case of error
 */
int
virConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->networkDriver && conn->networkDriver->connectNumOfDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->connectNumOfDefinedNetworks(conn);
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
 * virConnectListDefinedNetworks:
 * @conn: pointer to the hypervisor connection
 * @names: pointer to an array to store the names
 * @maxnames: size of the array
 *
 * list the inactive networks, stores the pointers to the names in @names
 *
 * For more control over the results, see virConnectListAllNetworks().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a network can be defined between
 * a call to virConnectNumOfDefinedNetworks() and this call; you are only
 * guaranteed that all currently defined networks were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 */
int
virConnectListDefinedNetworks(virConnectPtr conn, char **const names,
                              int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->networkDriver && conn->networkDriver->connectListDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->connectListDefinedNetworks(conn, names, maxnames);
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
 * virNetworkLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the network
 *
 * Try to lookup a network on the given hypervisor based on its name.
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByName(virConnectPtr conn, const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->networkDriver && conn->networkDriver->networkLookupByName) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByName(conn, name);
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
 * virNetworkLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (conn->networkDriver && conn->networkDriver->networkLookupByUUID) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByUUID(conn, uuid);
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
 * virNetworkLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
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

    return virNetworkLookupByUUID(conn, &uuid[0]);

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNetworkCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the network
 *
 * Create and start a new virtual network, based on an XML description
 * similar to the one returned by virNetworkGetXMLDesc()
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns a new network object or NULL in case of failure
 */
virNetworkPtr
virNetworkCreateXML(virConnectPtr conn, const char *xmlDesc)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s", conn, NULLSTR(xmlDesc));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkCreateXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkCreateXML(conn, xmlDesc);
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
 * virNetworkDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the network, preferably in UTF-8
 *
 * Define an inactive persistent virtual network or modify an existing
 * persistent one from the XML description.
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns NULL in case of error, a pointer to the network otherwise
 */
virNetworkPtr
virNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    VIR_DEBUG("conn=%p, xml=%s", conn, NULLSTR(xml));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkDefineXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkDefineXML(conn, xml);
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
 * virNetworkUndefine:
 * @network: pointer to a defined network
 *
 * Undefine a network but does not stop it if it is running
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkUndefine(virNetworkPtr network)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkUndefine) {
        int ret;
        ret = conn->networkDriver->networkUndefine(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkUpdate:
 * @network: pointer to a defined network
 * @section: which section of the network to update
 *           (see virNetworkUpdateSection for descriptions)
 * @command: what action to perform (add/delete/modify)
 *           (see virNetworkUpdateCommand for descriptions)
 * @parentIndex: which parent element, if there are multiple parents
 *           of the same type (e.g. which <ip> element when modifying
 *           a <dhcp>/<host> element), or "-1" for "don't care" or
 *           "automatically find appropriate one".
 * @xml: the XML description for the network, preferably in UTF-8
 * @flags: bitwise OR of virNetworkUpdateFlags.
 *
 * Update the definition of an existing network, either its live
 * running state, its persistent configuration, or both.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkUpdate(virNetworkPtr network,
                 unsigned int command, /* virNetworkUpdateCommand */
                 unsigned int section, /* virNetworkUpdateSection */
                 int parentIndex,
                 const char *xml,
                 unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, section=%d, parentIndex=%d, xml=%s, flags=0x%x",
              network, section, parentIndex, xml, flags);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkUpdate) {
        int ret;
        ret = conn->networkDriver->networkUpdate(network, section, command,
                                                 parentIndex, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkCreate:
 * @network: pointer to a defined network
 *
 * Create and start a defined network. If the call succeed the network
 * moves from the defined to the running networks pools.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkCreate(virNetworkPtr network)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkCreate) {
        int ret;
        ret = conn->networkDriver->networkCreate(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkDestroy:
 * @network: a network object
 *
 * Destroy the network object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor. This
 * does not free the associated virNetworkPtr object.
 * This function may require privileged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNetworkDestroy(virNetworkPtr network)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkDestroy) {
        int ret;
        ret = conn->networkDriver->networkDestroy(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkFree:
 * @network: a network object
 *
 * Free the network object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNetworkFree(virNetworkPtr network)
{
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, -1);

    virObjectUnref(network);
    return 0;
}


/**
 * virNetworkRef:
 * @network: the network to hold a reference on
 *
 * Increment the reference count on the network. For each
 * additional call to this method, there shall be a corresponding
 * call to virNetworkFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a network would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNetworkRef(virNetworkPtr network)
{
    VIR_DEBUG("network=%p refs=%d", network,
              network ? network->object.u.s.refs : 0);

    virResetLastError();

    virCheckNetworkReturn(network, -1);

    virObjectRef(network);
    return 0;
}


/**
 * virNetworkGetName:
 * @network: a network object
 *
 * Get the public name for that network
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the network object.
 */
const char *
virNetworkGetName(virNetworkPtr network)
{
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, NULL);

    return network->name;
}


/**
 * virNetworkGetUUID:
 * @network: a network object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a network
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetUUID(virNetworkPtr network, unsigned char *uuid)
{
    VIR_DEBUG("network=%p, uuid=%p", network, uuid);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &network->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkGetUUIDString:
 * @network: a network object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a network as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetUUIDString(virNetworkPtr network, char *buf)
{
    VIR_DEBUG("network=%p, buf=%p", network, buf);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(network->uuid, buf);
    return 0;

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkGetXMLDesc:
 * @network: a network object
 * @flags: bitwise-OR of virNetworkXMLFlags
 *
 * Provide an XML description of the network. The description may be reused
 * later to relaunch the network with virNetworkCreateXML().
 *
 * Normally, if a network included a physical function, the output includes
 * all virtual functions tied to that physical interface.  If @flags includes
 * VIR_NETWORK_XML_INACTIVE, then the expansion of virtual interfaces is
 * not performed.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetXMLDesc(virNetworkPtr network, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, flags=%x", network, flags);

    virResetLastError();

    virCheckNetworkReturn(network, NULL);
    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetXMLDesc) {
        char *ret;
        ret = conn->networkDriver->networkGetXMLDesc(network, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return NULL;
}


/**
 * virNetworkGetBridgeName:
 * @network: a network object
 *
 * Provides a bridge interface name to which a domain may connect
 * a network interface in order to join the network.
 *
 * Returns a 0 terminated interface name, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetBridgeName(virNetworkPtr network)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    virCheckNetworkReturn(network, NULL);
    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetBridgeName) {
        char *ret;
        ret = conn->networkDriver->networkGetBridgeName(network);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return NULL;
}


/**
 * virNetworkGetAutostart:
 * @network: a network object
 * @autostart: the value returned
 *
 * Provides a boolean value indicating whether the network
 * configured to be automatically started when the host
 * machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetAutostart(virNetworkPtr network,
                       int *autostart)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, autostart=%p", network, autostart);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    virCheckNonNullArgGoto(autostart, error);

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetAutostart) {
        int ret;
        ret = conn->networkDriver->networkGetAutostart(network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkSetAutostart:
 * @network: a network object
 * @autostart: whether the network should be automatically started 0 or 1
 *
 * Configure the network to be automatically started
 * when the host machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkSetAutostart(virNetworkPtr network,
                       int autostart)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, autostart=%d", network, autostart);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkSetAutostart) {
        int ret;
        ret = conn->networkDriver->networkSetAutostart(network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkIsActive:
 * @net: pointer to the network object
 *
 * Determine if the network is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int
virNetworkIsActive(virNetworkPtr net)
{
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    virCheckNetworkReturn(net, -1);

    if (net->conn->networkDriver->networkIsActive) {
        int ret;
        ret = net->conn->networkDriver->networkIsActive(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(net->conn);
    return -1;
}


/**
 * virNetworkIsPersistent:
 * @net: pointer to the network object
 *
 * Determine if the network has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 */
int
virNetworkIsPersistent(virNetworkPtr net)
{
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    virCheckNetworkReturn(net, -1);

    if (net->conn->networkDriver->networkIsPersistent) {
        int ret;
        ret = net->conn->networkDriver->networkIsPersistent(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(net->conn);
    return -1;
}


/**
 * virConnectNetworkEventRegisterAny:
 * @conn: pointer to the connection
 * @net: pointer to the network
 * @eventID: the event type to receive
 * @cb: callback to the function handling network events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary network events
 * occurring on a network.  This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * If @net is NULL, then events will be monitored for any network. If @net
 * is non-NULL, then only the specific network will be monitored.
 *
 * Most types of event have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_NETWORK_EVENT_CALLBACK() macro to cast the supplied function pointer
 * to match the signature of this method.
 *
 * The virNetworkPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the network object after the callback
 * returns, it shall take a reference to it, by calling virNetworkRef().
 * The reference can be released once the object is no longer required
 * by calling virNetworkFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectNetworkEventDeregisterAny() method.
 *
 * Returns a callback identifier on success, -1 on failure.
 */
int
virConnectNetworkEventRegisterAny(virConnectPtr conn,
                                  virNetworkPtr net,
                                  int eventID,
                                  virConnectNetworkEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
              conn, eventID, cb, opaque, freecb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (net) {
        virCheckNetworkGoto(net, error);
        if (net->conn != conn) {
            virReportInvalidArg(net,
                                _("network '%s' in %s must match connection"),
                                net->name, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);

    if (eventID >= VIR_NETWORK_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %s must be less than %d"),
                            __FUNCTION__, VIR_NETWORK_EVENT_ID_LAST);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->connectNetworkEventRegisterAny) {
        int ret;
        ret = conn->networkDriver->connectNetworkEventRegisterAny(conn, net,
                                                                  eventID,
                                                                  cb, opaque,
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
 * virConnectNetworkEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectNetworkEventRegisterAny() method.
 *
 * Returns 0 on success, -1 on failure
 */
int
virConnectNetworkEventDeregisterAny(virConnectPtr conn,
                                    int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);

    if (conn->networkDriver &&
        conn->networkDriver->connectNetworkEventDeregisterAny) {
        int ret;
        ret = conn->networkDriver->connectNetworkEventDeregisterAny(conn,
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


/**
 * virNetworkGetDHCPLeases:
 * @network: Pointer to network object
 * @mac: Optional ASCII formatted MAC address of an interface
 * @leases: Pointer to a variable to store the array containing details on
 *          obtained leases, or NULL if the list is not required (just returns
 *          number of leases).
 * @flags: Extra flags, not used yet, so callers should always pass 0
 *
 * For DHCPv4, the information returned:
 * - Network Interface Name
 * - Expiry Time
 * - MAC address
 * - IAID (NULL)
 * - IPv4 address (with type and prefix)
 * - Hostname (can be NULL)
 * - Client ID (can be NULL)
 *
 * For DHCPv6, the information returned:
 * - Network Interface Name
 * - Expiry Time
 * - MAC address
 * - IAID (can be NULL, only in rare cases)
 * - IPv6 address (with type and prefix)
 * - Hostname (can be NULL)
 * - Client DUID
 *
 * Note: @mac, @iaid, @ipaddr, @clientid are in ASCII form, not raw bytes.
 * Note: @expirytime can 0, in case the lease is for infinite time.
 *
 * The API fetches leases info of guests in the specified network. If the
 * optional parameter @mac is specified, the returned list will contain only
 * lease info about a specific guest interface with @mac. There can be
 * multiple leases for a single @mac because this API supports DHCPv6 too.
 *
 * Returns the number of leases found or -1 and sets @leases to NULL in
 * case of error. On success, the array stored into @leases is guaranteed to
 * have an extra allocated element set to NULL but not included in the return
 * count, to make iteration easier. The caller is responsible for calling
 * virNetworkDHCPLeaseFree() on each array element, then calling free() on @leases.
 *
 * See also virNetworkGetDHCPLeasesForMAC() as a convenience for filtering
 * the list to a single MAC address.
 *
 * Example of usage:
 *
 * virNetworkDHCPLeasePtr *leases = NULL;
 * virNetworkPtr network = ... obtain a network pointer here ...;
 * size_t i;
 * int nleases;
 * unsigned int flags = 0;
 *
 * nleases = virNetworkGetDHCPLeases(network, NULL, &leases, flags);
 * if (nleases < 0)
 *     error();
 *
 * ... do something with returned values, for example:
 *
 * for (i = 0; i < nleases; i++) {
 *     virNetworkDHCPLeasePtr lease = leases[i];
 *
 *     printf("Time(epoch): %lu, MAC address: %s, "
 *            "IP address: %s, Hostname: %s, ClientID: %s\n",
 *            lease->expirytime, lease->mac, lease->ipaddr,
 *            lease->hostname, lease->clientid);
 *
 *            virNetworkDHCPLeaseFree(leases[i]);
 * }
 *
 * free(leases);
 *
 */
int
virNetworkGetDHCPLeases(virNetworkPtr network,
                        const char *mac,
                        virNetworkDHCPLeasePtr **leases,
                        unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, mac='%s' leases=%p, flags=%x",
               network, NULLSTR(mac), leases, flags);

    virResetLastError();

    if (leases)
        *leases = NULL;

    virCheckNetworkReturn(network, -1);

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetDHCPLeases) {
        int ret;
        ret = conn->networkDriver->networkGetDHCPLeases(network, mac, leases, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return -1;
}


/**
 * virNetworkDHCPLeaseFree:
 * @lease: pointer to a leases object
 *
 * Frees all the memory occupied by @lease.
 */
void
virNetworkDHCPLeaseFree(virNetworkDHCPLeasePtr lease)
{
    if (!lease)
        return;
    VIR_FREE(lease->iface);
    VIR_FREE(lease->mac);
    VIR_FREE(lease->iaid);
    VIR_FREE(lease->ipaddr);
    VIR_FREE(lease->hostname);
    VIR_FREE(lease->clientid);
    VIR_FREE(lease);
}
