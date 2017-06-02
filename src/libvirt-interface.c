/*
 * libvirt-interface.c: entry points for virInterfacePtr APIs
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

VIR_LOG_INIT("libvirt.interface");

#define VIR_FROM_THIS VIR_FROM_INTERFACE

/**
 * virInterfaceGetConnect:
 * @iface: pointer to an interface
 *
 * Provides the connection pointer associated with an interface.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virInterfaceGetConnect(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, NULL);

    return iface->conn;
}


/**
 * virConnectListAllInterfaces:
 * @conn: Pointer to the hypervisor connection.
 * @ifaces: Pointer to a variable to store the array containing the interface
 *          objects or NULL if the list is not required (just returns number
 *          of interfaces).
 * @flags: bitwise-OR of virConnectListAllInterfacesFlags.
 *
 * Collect the list of interfaces, and allocate an array to store those
 * objects. This API solves the race inherent between virConnectListInterfaces
 * and virConnectListDefinedInterfaces.
 *
 * Normally, all interfaces are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted interfaces.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a interface, and where all bits
 * within a group describe all possible interfaces.
 *
 * The only group of @flags is VIR_CONNECT_LIST_INTERFACES_ACTIVE (up) and
 * VIR_CONNECT_LIST_INTERFACES_INACTIVE (down) to filter the interfaces by state.
 *
 * Returns the number of interfaces found or -1 and sets @ifaces to  NULL in case
 * of error.  On success, the array stored into @ifaces is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virStorageInterfaceFree() on each array element, then calling free() on @ifaces.
 */
int
virConnectListAllInterfaces(virConnectPtr conn,
                            virInterfacePtr **ifaces,
                            unsigned int flags)
{
    VIR_DEBUG("conn=%p, ifaces=%p, flags=%x", conn, ifaces, flags);

    virResetLastError();

    if (ifaces)
        *ifaces = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->interfaceDriver &&
        conn->interfaceDriver->connectListAllInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListAllInterfaces(conn, ifaces, flags);
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
 * virConnectNumOfInterfaces:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active interfaces on the physical host.
 *
 * Returns the number of active interfaces found or -1 in case of error
 */
int
virConnectNumOfInterfaces(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->interfaceDriver && conn->interfaceDriver->connectNumOfInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectNumOfInterfaces(conn);
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
 * virConnectListInterfaces:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of interfaces
 * @maxnames: size of @names
 *
 * Collect the list of active physical host interfaces,
 * and store their names in @names
 *
 * For more control over the results, see virConnectListAllInterfaces().
 *
 * Returns the number of interfaces found or -1 in case of error.  Note that
 * this command is inherently racy; a interface can be started between a call
 * to virConnectNumOfInterfaces() and this call; you are only guaranteed that
 * all currently active interfaces were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 */
int
virConnectListInterfaces(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->interfaceDriver && conn->interfaceDriver->connectListInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListInterfaces(conn, names, maxnames);
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
 * virConnectNumOfDefinedInterfaces:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of defined (inactive) interfaces on the physical host.
 *
 * Returns the number of defined interface found or -1 in case of error
 */
int
virConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->interfaceDriver && conn->interfaceDriver->connectNumOfDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectNumOfDefinedInterfaces(conn);
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
 * virConnectListDefinedInterfaces:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of interfaces
 * @maxnames: size of @names
 *
 * Collect the list of defined (inactive) physical host interfaces,
 * and store their names in @names.
 *
 * For more control over the results, see virConnectListAllInterfaces().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a interface can be defined between
 * a call to virConnectNumOfDefinedInterfaces() and this call; you are only
 * guaranteed that all currently defined interfaces were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 */
int
virConnectListDefinedInterfaces(virConnectPtr conn,
                                char **const names,
                                int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->interfaceDriver && conn->interfaceDriver->connectListDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListDefinedInterfaces(conn, names, maxnames);
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
 * virInterfaceLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the interface
 *
 * Try to lookup an interface on the given hypervisor based on its name.
 *
 * virInterfaceFree should be used to free the resources after the
 * interface object is no longer needed.
 *
 * Returns a new interface object or NULL in case of failure.  If the
 * interface cannot be found, then VIR_ERR_NO_INTERFACE error is raised.
 */
virInterfacePtr
virInterfaceLookupByName(virConnectPtr conn, const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByName) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByName(conn, name);
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
 * virInterfaceLookupByMACString:
 * @conn: pointer to the hypervisor connection
 * @macstr: the MAC for the interface (null-terminated ASCII format)
 *
 * Try to lookup an interface on the given hypervisor based on its MAC.
 *
 * virInterfaceFree should be used to free the resources after the
 * interface object is no longer needed.
 *
 * Returns a new interface object or NULL in case of failure.  If the
 * interface cannot be found, then VIR_ERR_NO_INTERFACE error is raised.
 */
virInterfacePtr
virInterfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    VIR_DEBUG("conn=%p, macstr=%s", conn, NULLSTR(macstr));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(macstr, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByMACString) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByMACString(conn, macstr);
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
 * virInterfaceGetName:
 * @iface: an interface object
 *
 * Get the public name for that interface
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the interface object.
 */
const char *
virInterfaceGetName(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, NULL);

    return iface->name;
}


/**
 * virInterfaceGetMACString:
 * @iface: an interface object
 *
 * Get the MAC for an interface as string. For more information about
 * MAC see RFC4122.
 *
 * Returns a pointer to the MAC address (in null-terminated ASCII
 * format) or NULL, the string need not be deallocated its lifetime
 * will be the same as the interface object.
 */
const char *
virInterfaceGetMACString(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, NULL);

    return iface->mac;
}


/**
 * virInterfaceGetXMLDesc:
 * @iface: an interface object
 * @flags: bitwise-OR of extraction flags. Current valid bits:
 *
 *      VIR_INTERFACE_XML_INACTIVE - return the static configuration,
 *                                   suitable for use redefining the
 *                                   interface via virInterfaceDefineXML()
 *
 * Provide an XML description of the interface. If
 * VIR_INTERFACE_XML_INACTIVE is set, the description may be reused
 * later to redefine the interface with virInterfaceDefineXML(). If it
 * is not set, the ip address and netmask will be the current live
 * setting of the interface, not the settings from the config files.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virInterfaceGetXMLDesc(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    virCheckInterfaceReturn(iface, NULL);
    conn = iface->conn;

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceGetXMLDesc) {
        char *ret;
        ret = conn->interfaceDriver->interfaceGetXMLDesc(iface, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(iface->conn);
    return NULL;
}


/**
 * virInterfaceDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the interface, preferably in UTF-8
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Define an inactive persistent physical host interface or modify an existing
 * persistent one from the XML description.
 *
 * Normally this change in the interface configuration is immediately
 * permanent/persistent, but if virInterfaceChangeBegin() has been
 * previously called (i.e. if an interface config transaction is
 * open), the new interface definition will only become permanent if
 * virInterfaceChangeCommit() is called prior to the next reboot of
 * the system running libvirtd. Prior to that time, it can be
 * explicitly removed using virInterfaceChangeRollback(), or will be
 * automatically removed during the next reboot of the system running
 * libvirtd.
 *
 * virInterfaceFree should be used to free the resources after the
 * interface object is no longer needed.
 *
 * Returns NULL in case of error, a pointer to the interface otherwise
 */
virInterfacePtr
virInterfaceDefineXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=%x", conn, NULLSTR(xml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDefineXML) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceDefineXML(conn, xml, flags);
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
 * virInterfaceUndefine:
 * @iface: pointer to a defined interface
 *
 * Undefine an interface, ie remove it from the config.
 * This does not free the associated virInterfacePtr object.
 *
 * Normally this change in the interface configuration is
 * permanent/persistent, but if virInterfaceChangeBegin() has been
 * previously called (i.e. if an interface config transaction is
 * open), the removal of the interface definition will only become
 * permanent if virInterfaceChangeCommit() is called prior to the next
 * reboot of the system running libvirtd. Prior to that time, the
 * definition can be explicitly restored using
 * virInterfaceChangeRollback(), or will be automatically restored
 * during the next reboot of the system running libvirtd.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceUndefine(virInterfacePtr iface)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);
    conn = iface->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceUndefine) {
        int ret;
        ret = conn->interfaceDriver->interfaceUndefine(iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(iface->conn);
    return -1;
}


/**
 * virInterfaceCreate:
 * @iface: pointer to a defined interface
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Activate an interface (i.e. call "ifup").
 *
 * If there was an open network config transaction at the time this
 * interface was defined (that is, if virInterfaceChangeBegin() had
 * been called), the interface will be brought back down (and then
 * undefined) if virInterfaceChangeRollback() is called.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceCreate(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);
    conn = iface->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceCreate) {
        int ret;
        ret = conn->interfaceDriver->interfaceCreate(iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(iface->conn);
    return -1;
}


/**
 * virInterfaceDestroy:
 * @iface: an interface object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * deactivate an interface (ie call "ifdown")
 * This does not remove the interface from the config, and
 * does not free the associated virInterfacePtr object.
 *

 * If there is an open network config transaction at the time this
 * interface is destroyed (that is, if virInterfaceChangeBegin() had
 * been called), and if the interface is later undefined and then
 * virInterfaceChangeRollback() is called, the restoral of the
 * interface definition will also bring the interface back up.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceDestroy(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);
    conn = iface->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDestroy) {
        int ret;
        ret = conn->interfaceDriver->interfaceDestroy(iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(iface->conn);
    return -1;
}


/**
 * virInterfaceRef:
 * @iface: the interface to hold a reference on
 *
 * Increment the reference count on the interface. For each
 * additional call to this method, there shall be a corresponding
 * call to virInterfaceFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using an interface would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virInterfaceRef(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p refs=%d", iface, iface ? iface->object.u.s.refs : 0);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);

    virObjectRef(iface);
    return 0;
}


/**
 * virInterfaceFree:
 * @iface: an interface object
 *
 * Free the interface object. The interface itself is unaltered.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceFree(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);

    virObjectUnref(iface);
    return 0;
}


/**
 * virInterfaceChangeBegin:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function creates a restore point to which one can return
 * later by calling virInterfaceChangeRollback(). This function should
 * be called before any transaction with interface configuration.
 * Once it is known that a new configuration works, it can be committed via
 * virInterfaceChangeCommit(), which frees the restore point.
 *
 * If virInterfaceChangeBegin() is called when a transaction is
 * already opened, this function will fail, and a
 * VIR_ERR_INVALID_OPERATION will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeBegin(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceChangeBegin) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeBegin(conn, flags);
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
 * virInterfaceChangeCommit:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This commits the changes made to interfaces and frees the restore point
 * created by virInterfaceChangeBegin().
 *
 * If virInterfaceChangeCommit() is called when a transaction is not
 * opened, this function will fail, and a VIR_ERR_INVALID_OPERATION
 * will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeCommit(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceChangeCommit) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeCommit(conn, flags);
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
 * virInterfaceChangeRollback:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This cancels changes made to interfaces settings by restoring previous
 * state created by virInterfaceChangeBegin().
 *
 * If virInterfaceChangeRollback() is called when a transaction is not
 * opened, this function will fail, and a VIR_ERR_INVALID_OPERATION
 * will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeRollback(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->interfaceDriver &&
        conn->interfaceDriver->interfaceChangeRollback) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeRollback(conn, flags);
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
 * virInterfaceIsActive:
 * @iface: pointer to the interface object
 *
 * Determine if the interface is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int
virInterfaceIsActive(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    virCheckInterfaceReturn(iface, -1);

    if (iface->conn->interfaceDriver->interfaceIsActive) {
        int ret;
        ret = iface->conn->interfaceDriver->interfaceIsActive(iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(iface->conn);
    return -1;
}
