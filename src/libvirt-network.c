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
#include "virtypedparam.h"

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
 *
 * Since: 0.3.0
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
 *
 * Since: 0.10.2
 */
int
virConnectListAllNetworks(virConnectPtr conn,
                          virNetworkPtr **nets,
                          unsigned int flags)
{
    VIR_DEBUG("conn=%p, nets=%p, flags=0x%x", conn, nets, flags);

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
 *
 * Since: 0.2.0
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
 * The use of this function is discouraged. Instead, use
 * virConnectListAllNetworks().
 *
 * Returns the number of networks found or -1 in case of error.  Note that
 * this command is inherently racy; a network can be started between a call
 * to virConnectNumOfNetworks() and this call; you are only guaranteed that
 * all currently active networks were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 *
 * Since: 0.2.0
 */
int
virConnectListNetworks(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
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
 *
 * Since: 0.2.0
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
 * The use of this function is discouraged. Instead, use
 * virConnectListAllNetworks().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a network can be defined between
 * a call to virConnectNumOfDefinedNetworks() and this call; you are only
 * guaranteed that all currently defined networks were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 *
 * Since: 0.2.0
 */
int
virConnectListDefinedNetworks(virConnectPtr conn, char **const names,
                              int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
                            _("uuidstr in %1$s must be a valid UUID"),
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
 *
 * Since: 0.2.0
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
 * virNetworkCreateXMLFlags:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the network
 * @flags: bitwise-OR of virNetworkCreateFlags
 *
 * Create and start a new virtual network, based on an XML description
 * similar to the one returned by virNetworkGetXMLDesc()
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns a new network object or NULL in case of failure
 *
 * Since: 7.8.0
 */
virNetworkPtr
virNetworkCreateXMLFlags(virConnectPtr conn, const char *xmlDesc, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=0x%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkCreateXMLFlags) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkCreateXMLFlags(conn, xmlDesc, flags);
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
 *
 * Since: 0.2.0
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
 * virNetworkDefineXMLFlags:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the network, preferably in UTF-8
 * @flags: bitwise-OR of virNetworkDefineFlags
 *
 * Define an inactive persistent virtual network or modify an existing
 * persistent one from the XML description.
 *
 * virNetworkFree should be used to free the resources after the
 * network object is no longer needed.
 *
 * Returns NULL in case of error, a pointer to the network otherwise
 *
 * Since: 7.7.0
 */
virNetworkPtr
virNetworkDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=0x%x", conn, NULLSTR(xml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkDefineXMLFlags) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkDefineXMLFlags(conn, xml, flags);
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.10.2
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
    VIR_DEBUG("network=%p, command=%d, section=%d, parentIndex=%d, xml=%s, flags=0x%x",
              network, command, section, parentIndex, xml, flags);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkUpdate) {
        int ret;
        int rc;

        /* Since its introduction in v0.10.2-rc1~9 the @section and @command
         * arguments were mistakenly swapped when passed to driver's callback.
         * Detect if the other side is fixed already or not. */
        rc = VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                      VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER);

        VIR_DEBUG("Argument order feature detection returned: %d", rc);
        if (rc < 0)
            goto error;

        if (rc == 0) {
            /* Feature not supported, preserve swapped order */
            ret = conn->networkDriver->networkUpdate(network, section, command,
                                                     parentIndex, xml, flags);
        } else {
            /* Feature supported, correct order can be used */
            ret = conn->networkDriver->networkUpdate(network, command, section,
                                                     parentIndex, xml, flags);
        }

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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.6.0
 */
int
virNetworkRef(virNetworkPtr network)
{
    VIR_DEBUG("network=%p", network);

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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.0
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
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case
 * of error. The caller must free() the returned value.
 *
 * Since: 0.2.0
 */
char *
virNetworkGetXMLDesc(virNetworkPtr network, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, flags=0x%x", network, flags);

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
 * Returns a 0 terminated interface name, or NULL in case of
 * error. The caller must free() the returned value.
 *
 * Since: 0.2.0
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
 *
 * Since: 0.2.1
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
 *
 * Since: 0.2.1
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
 *
 * Since: 0.7.3
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
 *
 * Since: 0.7.3
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
 *
 * Since: 1.2.1
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
                                _("network '%1$s' in %2$s must match connection"),
                                net->name, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);

    if (eventID >= VIR_NETWORK_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %1$s must be less than %2$d"),
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
 *
 * Since: 1.2.1
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
 * On success, the array stored into @leases is guaranteed to
 * have an extra allocated element set to NULL but not included in the return
 * count, to make iteration easier. The caller is responsible for calling
 * virNetworkDHCPLeaseFree() on each array element, then calling free() on @leases.
 *
 * See also virNetworkGetDHCPLeasesForMAC() as a convenience for filtering
 * the list to a single MAC address.
 *
 * Example of usage:
 *
 *   virNetworkDHCPLeasePtr *leases = NULL;
 *   virNetworkPtr network = ... obtain a network pointer here ...;
 *   size_t i;
 *   int nleases;
 *   unsigned int flags = 0;
 *
 *   nleases = virNetworkGetDHCPLeases(network, NULL, &leases, flags);
 *   if (nleases < 0)
 *       error();
 *
 *   ... do something with returned values, for example:
 *
 *   for (i = 0; i < nleases; i++) {
 *       virNetworkDHCPLeasePtr lease = leases[i];
 *
 *       printf("Time(epoch): %lu, MAC address: %s, "
 *              "IP address: %s, Hostname: %s, ClientID: %s\n",
 *              lease->expirytime, lease->mac, lease->ipaddr,
 *              lease->hostname, lease->clientid);
 *
 *              virNetworkDHCPLeaseFree(leases[i]);
 *   }
 *
 *   free(leases);
 *
 * Returns the number of leases found or -1 and sets @leases to NULL in
 * case of error.
 *
 * Since: 1.2.6
 */
int
virNetworkGetDHCPLeases(virNetworkPtr network,
                        const char *mac,
                        virNetworkDHCPLeasePtr **leases,
                        unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, mac='%s' leases=%p, flags=0x%x",
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
 *
 * Since: 1.2.6
 */
void
virNetworkDHCPLeaseFree(virNetworkDHCPLeasePtr lease)
{
    if (!lease)
        return;
    g_free(lease->iface);
    g_free(lease->mac);
    g_free(lease->iaid);
    g_free(lease->ipaddr);
    g_free(lease->hostname);
    g_free(lease->clientid);
    g_free(lease);
}


/**
 * virNetworkPortLookupByUUID:
 * @net: pointer to the network object
 * @uuid: the raw UUID for the network port
 *
 * Try to lookup a port on the given network based on its UUID.
 *
 * virNetworkPortFree should be used to free the resources after the
 * network port object is no longer needed.
 *
 * Returns a new network port object or NULL in case of failure.  If the
 * network port cannot be found, then VIR_ERR_NO_NETWORK_PORT error is raised.
 *
 * Since: 5.5.0
 */
virNetworkPortPtr
virNetworkPortLookupByUUID(virNetworkPtr net,
                           const unsigned char *uuid)
{
    VIR_UUID_DEBUG(net, uuid);

    virResetLastError();

    virCheckNetworkReturn(net, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (net->conn->networkDriver && net->conn->networkDriver->networkPortLookupByUUID) {
        virNetworkPortPtr ret;
        ret = net->conn->networkDriver->networkPortLookupByUUID(net, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(net->conn);
    return NULL;
}


/**
 * virNetworkPortLookupByUUIDString:
 * @net: pointer to the network object
 * @uuidstr: the string UUID for the port
 *
 * Try to lookup a port on the given network based on its UUID.
 *
 * Returns a new network port object or NULL in case of failure.  If the
 * network port cannot be found, then VIR_ERR_NO_NETWORK_PORT error is raised.
 *
 * Since: 5.5.0
 */
virNetworkPortPtr
virNetworkPortLookupByUUIDString(virNetworkPtr net,
                                 const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    VIR_DEBUG("net=%p, uuidstr=%s", net, NULLSTR(uuidstr));

    virResetLastError();

    virCheckNetworkReturn(net, NULL);
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %1$s must be a valid UUID"),
                            __FUNCTION__);
        goto error;
    }

    return virNetworkPortLookupByUUID(net, &uuid[0]);

 error:
    virDispatchError(net->conn);
    return NULL;
}


/**
 * virNetworkPortSetParameters:
 * @port: a network port object
 * @params: pointer to interface parameter objects
 * @nparams: number of interface parameter (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: currently unused, pass 0
 *
 * Change a subset or all parameters of the network port; currently this
 * includes bandwidth parameters.
 *
 * Returns -1 in case of error, 0 in case of success.
 *
 * Since: 5.5.0
 */
int
virNetworkPortSetParameters(virNetworkPortPtr port,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("port=%p, params=%p, nparams=%d, flags=0x%x", port, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);
    conn = port->net->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkPortSetParameters) {
        int ret;
        ret = conn->networkDriver->networkPortSetParameters(port, params, nparams, flags);
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
 * virNetworkPortGetParameters:
 * @port: a network port object
 * @params: pointer to pointer of interface parameter objects
 * @nparams: pointer to received number of interface parameter
 * @flags: currently unused, pass 0
 *
 * Get all interface parameters. On input, @params should be initialized
 * to NULL. On return @params will be allocated with the size large
 * enough to hold all parameters, and @nparams will be updated to say
 * how many parameters are present. @params should be freed by the caller
 * on success.
 *
 * Returns -1 in case of error, 0 in case of success.
 *
 * Since: 5.5.0
 */
int
virNetworkPortGetParameters(virNetworkPortPtr port,
                            virTypedParameterPtr *params,
                            int *nparams,
                            unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("port=%p, params=%p, nparams=%p, flags=0x%x", port, params, nparams, flags);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);
    conn = port->net->conn;

    if (conn->networkDriver && conn->networkDriver->networkPortGetParameters) {
        int ret;
        ret = conn->networkDriver->networkPortGetParameters(port, params, nparams, flags);
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
 * virNetworkPortCreateXML:
 * @net: pointer to the network object
 * @xmldesc: an XML description of the port
 * @flags: bitwise-OR of virNetworkPortCreateFlags
 *
 * Create a new network port, based on an XML description
 * similar to the one returned by virNetworkPortGetXMLDesc()
 *
 * virNetworkPortFree should be used to free the resources after the
 * network port object is no longer needed.
 *
 * Returns a new network port object or NULL in case of failure
 *
 * Since: 5.5.0
 */
virNetworkPortPtr
virNetworkPortCreateXML(virNetworkPtr net,
                        const char *xmldesc,
                        unsigned int flags)
{
    VIR_DEBUG("net=%p, xmldesc=%s, flags=0x%x", net, NULLSTR(xmldesc), flags);

    virResetLastError();

    virCheckNetworkReturn(net, NULL);
    virCheckNonNullArgGoto(xmldesc, error);
    virCheckReadOnlyGoto(net->conn->flags, error);

    if (net->conn->networkDriver && net->conn->networkDriver->networkPortCreateXML) {
        virNetworkPortPtr ret;
        ret = net->conn->networkDriver->networkPortCreateXML(net, xmldesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(net->conn);
    return NULL;
}

/**
 * virNetworkPortGetNetwork:
 * @port: pointer to a network port
 *
 * Provides the network pointer associated with a port.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virNetworkPtr or NULL in case of failure.
 *
 * Since: 5.5.0
 */
virNetworkPtr
virNetworkPortGetNetwork(virNetworkPortPtr port)
{
    VIR_DEBUG("port=%p", port);

    virResetLastError();

    virCheckNetworkPortReturn(port, NULL);

    return port->net;
}


/**
 * virNetworkPortGetXMLDesc:
 * @port: a network port object
 * @flags: currently unused, pass 0
 *
 * Provide an XML description of the network port. The description may be reused
 * later to recreate the port with virNetworkPortCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 *
 * Since: 5.5.0
 */
char *
virNetworkPortGetXMLDesc(virNetworkPortPtr port,
                         unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("port=%p, flags=0x%x", port, flags);

    virResetLastError();

    virCheckNetworkPortReturn(port, NULL);
    conn = port->net->conn;

    if (conn->networkDriver && conn->networkDriver->networkPortGetXMLDesc) {
        char *ret;
        ret = conn->networkDriver->networkPortGetXMLDesc(port, flags);
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
 * virNetworkPortGetUUID:
 * @port: a network port object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a network port
 *
 * Returns -1 in case of error, 0 in case of success
 *
 * Since: 5.5.0
 */
int
virNetworkPortGetUUID(virNetworkPortPtr port,
                      unsigned char *uuid)
{
    VIR_DEBUG("port=%p, uuid=%p", port, uuid);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &port->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(port->net->conn);
    return -1;
}


/**
 * virNetworkPortGetUUIDString:
 * @port: a network port object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a network as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 *
 * Since: 5.5.0
 */
int
virNetworkPortGetUUIDString(virNetworkPortPtr port,
                            char *buf)
{
    VIR_DEBUG("port=%p, buf=%p", port, buf);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(port->uuid, buf);
    return 0;

 error:
    virDispatchError(port->net->conn);
    return -1;
}

/**
 * virNetworkPortDelete:
 * @port: a port object
 * @flags: currently unused, pass 0
 *
 * Delete the network port. This does not free the
 * associated virNetworkPortPtr object. It is the
 * caller's responsibility to ensure the port is not
 * still in use by a virtual machine before deleting
 * port.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 5.5.0
 */
int
virNetworkPortDelete(virNetworkPortPtr port,
                     unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("port=%p, flags=0x%x", port, flags);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);
    conn = port->net->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->networkDriver && conn->networkDriver->networkPortDelete) {
        int ret;
        ret = conn->networkDriver->networkPortDelete(port, flags);
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
 * virNetworkListAllPorts:
 * @network: pointer to a network object
 * @ports: Pointer to a variable to store the array containing network port
 *        objects or NULL if the list is not required (just returns number
 *        of ports).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of network ports, and allocate an array to store those
 * objects.
 *
 * Returns the number of network ports found or -1 and sets @ports to
 * NULL in case of error.  On success, the array stored into @ports is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virNetworkPortFree() on each array element, then calling
 * free() on @ports.
 *
 * Since: 5.5.0
 */
int
virNetworkListAllPorts(virNetworkPtr network,
                       virNetworkPortPtr **ports,
                       unsigned int flags)
{
    VIR_DEBUG("network=%p, ports=%p, flags=0x%x", network, ports, flags);

    virResetLastError();

    virCheckNetworkReturn(network, -1);

    if (network->conn->networkDriver &&
        network->conn->networkDriver->networkListAllPorts) {
        int ret;
        ret = network->conn->networkDriver->networkListAllPorts(network, ports, flags);
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
 * virNetworkPortFree:
 * @port: a network port object
 *
 * Free the network port object.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 5.5.0
 */
int
virNetworkPortFree(virNetworkPortPtr port)
{
    VIR_DEBUG("port=%p", port);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);

    virObjectUnref(port);
    return 0;
}


/**
 * virNetworkPortRef:
 * @port: a network port object
 *
 * Increment the reference count on the network port. For each
 * additional call to this method, there shall be a corresponding
 * call to virNetworkPortFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a network port, and it is required that the
 * port remain resident until all threads have finished using
 * it. ie, each new thread using a network port would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 5.5.0
 */
int
virNetworkPortRef(virNetworkPortPtr port)
{
    VIR_DEBUG("port=%p", port);

    virResetLastError();

    virCheckNetworkPortReturn(port, -1);

    virObjectRef(port);
    return 0;
}


/**
 * virNetworkSetMetadata:
 * @network: a network object
 * @type: type of metadata, from virNetworkMetadataType
 * @metadata: new metadata text
 * @key: XML namespace key, or NULL
 * @uri: XML namespace URI, or NULL
 * @flags: bitwise-OR of virNetworkUpdateFlags
 *
 * Sets the appropriate network element given by @type to the
 * value of @metadata.  A @type of VIR_NETWORK_METADATA_DESCRIPTION
 * is free-form text; VIR_NETWORK_METADATA_TITLE is free-form, but no
 * newlines are permitted, and should be short (although the length is
 * not enforced). For these two options @key and @uri are irrelevant and
 * must be set to NULL.
 *
 * For type VIR_NETWORK_METADATA_ELEMENT @metadata must be well-formed
 * XML belonging to namespace defined by @uri with local name @key.
 *
 * Passing NULL for @metadata says to remove that element from the
 * network XML (passing the empty string leaves the element present).
 *
 * The resulting metadata will be present in virNetworkGetXMLDesc(),
 * as well as quick access through virNetworkGetMetadata().
 *
 * @flags controls whether the live network state, persistent configuration,
 * or both will be modified.
 *
 * Returns 0 on success, -1 in case of failure.
 *
 * Since: 9.7.0
 */
int
virNetworkSetMetadata(virNetworkPtr network,
                      int type,
                      const char *metadata,
                      const char *key,
                      const char *uri,
                      unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("network=%p, type=%d, metadata='%s', key='%s', uri='%s', flags=0x%x",
              network, type, NULLSTR(metadata), NULLSTR(key), NULLSTR(uri),
              flags);

    virResetLastError();

    virCheckNetworkReturn(network, -1);
    conn = network->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    switch (type) {
    case VIR_NETWORK_METADATA_TITLE:
        if (metadata && strchr(metadata, '\n')) {
            virReportInvalidArg(metadata, "%s",
                                _("metadata title can't contain newlines"));
            goto error;
        }
        G_GNUC_FALLTHROUGH;
    case VIR_NETWORK_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        virCheckNullArgGoto(key, error);
        break;
    case VIR_NETWORK_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        if (metadata)
            virCheckNonNullArgGoto(key, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    if (conn->networkDriver->networkSetMetadata) {
        int ret;
        ret = conn->networkDriver->networkSetMetadata(network, type, metadata, key, uri,
                                                      flags);
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
 * virNetworkGetMetadata:
 * @network: a network object
 * @type: type of metadata, from virNetworkMetadataType
 * @uri: XML namespace identifier
 * @flags: bitwise-OR of virNetworkUpdateFlags
 *
 * Retrieves the appropriate network element given by @type.
 * If VIR_NETWORK_METADATA_ELEMENT is requested parameter @uri
 * must be set to the name of the namespace the requested elements
 * belong to, otherwise must be NULL.
 *
 * If an element of the network XML is not present, the resulting
 * error will be VIR_ERR_NO_NETWORK_METADATA.  This method forms
 * a shortcut for seeing information from virNetworkSetMetadata()
 * without having to go through virNetworkGetXMLDesc().
 *
 * @flags controls whether the live network state or persistent
 * configuration will be queried.
 *
 * Returns the metadata string on success (caller must free),
 * or NULL in case of failure.
 *
 * Since: 9.7.0
 */
char *
virNetworkGetMetadata(virNetworkPtr network,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("network=%p, type=%d, uri='%s', flags=0x%x",
               network, type, NULLSTR(uri), flags);

    virResetLastError();

    virCheckNetworkReturn(network, NULL);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_NETWORK_UPDATE_AFFECT_LIVE,
                             VIR_NETWORK_UPDATE_AFFECT_CONFIG,
                             error);

    switch (type) {
    case VIR_NETWORK_METADATA_TITLE:
    case VIR_NETWORK_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        break;
    case VIR_NETWORK_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    conn = network->conn;

    if (conn->networkDriver->networkGetMetadata) {
        char *ret;
        if (!(ret = conn->networkDriver->networkGetMetadata(network, type, uri, flags)))
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(network->conn);
    return NULL;
}
