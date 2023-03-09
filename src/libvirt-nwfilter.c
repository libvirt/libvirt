/*
 * libvirt-nwfilter.c: entry points for virNwfilterPtr APIs
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

VIR_LOG_INIT("libvirt.nwfilter");

#define VIR_FROM_THIS VIR_FROM_NWFILTER


/**
 * virConnectNumOfNWFilters:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of nwfilters.
 *
 * Returns the number of nwfilters found or -1 in case of error
 *
 * Since: 0.8.0
 */
int
virConnectNumOfNWFilters(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->nwfilterDriver && conn->nwfilterDriver->connectNumOfNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectNumOfNWFilters(conn);
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
 * virConnectListAllNWFilters:
 * @conn: Pointer to the hypervisor connection.
 * @filters: Pointer to a variable to store the array containing the network
 *           filter objects or NULL if the list is not required (just returns
 *           number of network filters).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of network filters, and allocate an array to store those
 * objects.
 *
 * Returns the number of network filters found or -1 and sets @filters to  NULL
 * in case of error.  On success, the array stored into @filters is guaranteed to
 * have an extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virNWFilterFree() on each array element, then calling free() on @filters.
 *
 * Since: 0.10.2
 */
int
virConnectListAllNWFilters(virConnectPtr conn,
                           virNWFilterPtr **filters,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, filters=%p, flags=0x%x", conn, filters, flags);

    virResetLastError();

    if (filters)
        *filters = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->nwfilterDriver &&
        conn->nwfilterDriver->connectListAllNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectListAllNWFilters(conn, filters, flags);
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
 * virConnectListNWFilters:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of network filters
 * @maxnames: size of @names
 *
 * Collect the list of network filters, and store their names in @names
 *
 * The use of this function is discouraged. Instead, use
 * virConnectListAllNWFilters().
 *
 * Returns the number of network filters found or -1 in case of error
 *
 * Since: 0.8.0
 */
int
virConnectListNWFilters(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->connectListNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectListNWFilters(conn, names, maxnames);
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
 * virNWFilterLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the network filter
 *
 * Try to lookup a network filter on the given hypervisor based on its name.
 *
 * virNWFilterFree should be used to free the resources after the
 * nwfilter object is no longer needed.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * network filter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 *
 * Since: 0.8.0
 */
virNWFilterPtr
virNWFilterLookupByName(virConnectPtr conn, const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByName) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByName(conn, name);
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
 * virNWFilterLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the network filter
 *
 * Try to lookup a network filter on the given hypervisor based on its UUID.
 *
 * virNWFilterFree should be used to free the resources after the
 * nwfilter object is no longer needed.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * nwfdilter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 *
 * Since: 0.8.0
 */
virNWFilterPtr
virNWFilterLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByUUID) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByUUID(conn, uuid);
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
 * virNWFilterLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the nwfilter
 *
 * Try to lookup an nwfilter on the given hypervisor based on its UUID.
 *
 * virNWFilterFree should be used to free the resources after the
 * nwfilter object is no longer needed.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * nwfilter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 *
 * Since: 0.8.0
 */
virNWFilterPtr
virNWFilterLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
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

    return virNWFilterLookupByUUID(conn, &uuid[0]);

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNWFilterFree:
 * @nwfilter: a nwfilter object
 *
 * Free the nwfilter object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 0.8.0
 */
int
virNWFilterFree(virNWFilterPtr nwfilter)
{
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, -1);

    virObjectUnref(nwfilter);
    return 0;
}


/**
 * virNWFilterGetName:
 * @nwfilter: a nwfilter object
 *
 * Get the public name for the network filter
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the nwfilter object.
 *
 * Since: 0.8.0
 */
const char *
virNWFilterGetName(virNWFilterPtr nwfilter)
{
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, NULL);

    return nwfilter->name;
}


/**
 * virNWFilterGetUUID:
 * @nwfilter: a nwfilter object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a network filter
 *
 * Returns -1 in case of error, 0 in case of success
 *
 * Since: 0.8.0
 */
int
virNWFilterGetUUID(virNWFilterPtr nwfilter, unsigned char *uuid)
{
    VIR_DEBUG("nwfilter=%p, uuid=%p", nwfilter, uuid);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &nwfilter->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterGetUUIDString:
 * @nwfilter: a nwfilter object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a network filter as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 *
 * Since: 0.8.0
 */
int
virNWFilterGetUUIDString(virNWFilterPtr nwfilter, char *buf)
{
    VIR_DEBUG("nwfilter=%p, buf=%p", nwfilter, buf);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(nwfilter->uuid, buf);
    return 0;

 error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the nwfilter
 *
 * Define a new network filter, based on an XML description
 * similar to the one returned by virNWFilterGetXMLDesc()
 *
 * virNWFilterFree should be used to free the resources after the
 * nwfilter object is no longer needed.
 *
 * Returns a new nwfilter object or NULL in case of failure
 *
 * Since: 0.8.0
 */
virNWFilterPtr
virNWFilterDefineXML(virConnectPtr conn, const char *xmlDesc)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s", conn, NULLSTR(xmlDesc));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterDefineXML) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterDefineXML(conn, xmlDesc);
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
 * virNWFilterDefineXMLFlags:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the nwfilter
 * @flags: bitwise-OR of virNWFilterDefineFlags
 *
 * Define a new network filter, based on an XML description
 * similar to the one returned by virNWFilterGetXMLDesc()
 *
 * virNWFilterFree should be used to free the resources after the
 * nwfilter object is no longer needed.
 *
 * Returns a new nwfilter object or NULL in case of failure
 *
 * Since: 7.7.0
 */
virNWFilterPtr
virNWFilterDefineXMLFlags(virConnectPtr conn, const char *xmlDesc, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s flags=0x%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterDefineXMLFlags) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterDefineXMLFlags(conn, xmlDesc, flags);
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
 * virNWFilterUndefine:
 * @nwfilter: a nwfilter object
 *
 * Undefine the nwfilter object. This call will not succeed if
 * a running VM is referencing the filter. This does not free the
 * associated virNWFilterPtr object.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 0.8.0
 */
int
virNWFilterUndefine(virNWFilterPtr nwfilter)
{
    virConnectPtr conn;
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, -1);
    conn = nwfilter->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterUndefine) {
        int ret;
        ret = conn->nwfilterDriver->nwfilterUndefine(nwfilter);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterGetXMLDesc:
 * @nwfilter: a nwfilter object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Provide an XML description of the network filter. The description may be
 * reused later to redefine the network filter with virNWFilterCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case
 * of error. The caller must free() the returned value.
 *
 * Since: 0.8.0
 */
char *
virNWFilterGetXMLDesc(virNWFilterPtr nwfilter, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("nwfilter=%p, flags=0x%x", nwfilter, flags);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, NULL);
    conn = nwfilter->conn;

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterGetXMLDesc) {
        char *ret;
        ret = conn->nwfilterDriver->nwfilterGetXMLDesc(nwfilter, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(nwfilter->conn);
    return NULL;
}


/**
 * virNWFilterRef:
 * @nwfilter: the nwfilter to hold a reference on
 *
 * Increment the reference count on the nwfilter. For each
 * additional call to this method, there shall be a corresponding
 * call to virNWFilterFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using an nwfilter would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 0.8.0
 */
int
virNWFilterRef(virNWFilterPtr nwfilter)
{
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    virCheckNWFilterReturn(nwfilter, -1);

    virObjectRef(nwfilter);
    return 0;
}


/**
 * virConnectListAllNWFilterBindings:
 * @conn: Pointer to the hypervisor connection.
 * @bindings: Pointer to a variable to store the array containing the network
 *            filter objects or NULL if the list is not required (just returns
 *            number of network filters).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of network filters, and allocate an array to store those
 * objects.
 *
 * Returns the number of network filters found or -1 and sets @filters to  NULL
 * in case of error.  On success, the array stored into @filters is guaranteed to
 * have an extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virNWFilterFree() on each array element, then calling free() on @filters.
 *
 * Since: 4.5.0
 */
int
virConnectListAllNWFilterBindings(virConnectPtr conn,
                                  virNWFilterBindingPtr **bindings,
                                  unsigned int flags)
{
    VIR_DEBUG("conn=%p, bindings=%p, flags=0x%x", conn, bindings, flags);

    virResetLastError();

    if (bindings)
        *bindings = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->nwfilterDriver &&
        conn->nwfilterDriver->connectListAllNWFilterBindings) {
        int ret;
        ret = conn->nwfilterDriver->connectListAllNWFilterBindings(conn, bindings, flags);
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
 * virNWFilterBindingLookupByPortDev:
 * @conn: pointer to the hypervisor connection
 * @portdev: name for the network port device
 *
 * Try to lookup a network filter binding on the given hypervisor based
 * on network port device name.
 *
 * virNWFilterBindingFree should be used to free the resources after the
 * binding object is no longer needed.
 *
 * Returns a new binding object or NULL in case of failure.  If the
 * network filter cannot be found, then VIR_ERR_NO_NWFILTER_BINDING
 * error is raised.
 *
 * Since: 4.5.0
 */
virNWFilterBindingPtr
virNWFilterBindingLookupByPortDev(virConnectPtr conn, const char *portdev)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(portdev));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(portdev, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterBindingLookupByPortDev) {
        virNWFilterBindingPtr ret;
        ret = conn->nwfilterDriver->nwfilterBindingLookupByPortDev(conn, portdev);
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
 * virNWFilterBindingFree:
 * @binding: a binding object
 *
 * Free the binding object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 4.5.0
 */
int
virNWFilterBindingFree(virNWFilterBindingPtr binding)
{
    VIR_DEBUG("binding=%p", binding);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, -1);

    virObjectUnref(binding);
    return 0;
}


/**
 * virNWFilterBindingGetPortDev:
 * @binding: a binding object
 *
 * Get the port dev name for the network filter binding
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the binding object.
 *
 * Since: 4.5.0
 */
const char *
virNWFilterBindingGetPortDev(virNWFilterBindingPtr binding)
{
    VIR_DEBUG("binding=%p", binding);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, NULL);

    return binding->portdev;
}


/**
 * virNWFilterBindingGetFilterName:
 * @binding: a binding object
 *
 * Get the filter name for the network filter binding
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the binding object.
 *
 * Since: 4.5.0
 */
const char *
virNWFilterBindingGetFilterName(virNWFilterBindingPtr binding)
{
    VIR_DEBUG("binding=%p", binding);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, NULL);

    return binding->filtername;
}


/**
 * virNWFilterBindingCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xml: an XML description of the binding
 * @flags: bitwise-OR of virNWFilterBindingCreateFlags
 *
 * Define a new network filter, based on an XML description
 * similar to the one returned by virNWFilterGetXMLDesc(). This
 * API may be used to associate a filter with a currently running
 * guest that does not have a filter defined for a specific network
 * port. Since the bindings are generally automatically managed by
 * the hypervisor, using this command to define a filter for a network
 * port and then starting the guest afterwards may prevent the guest
 * from starting if it attempts to use the network port and finds a
 * filter already defined.
 *
 * virNWFilterFree should be used to free the resources after the
 * binding object is no longer needed.
 *
 * Returns a new binding object or NULL in case of failure
 *
 * Since: 4.5.0
 */
virNWFilterBindingPtr
virNWFilterBindingCreateXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s", conn, NULLSTR(xml));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterBindingCreateXML) {
        virNWFilterBindingPtr ret;
        ret = conn->nwfilterDriver->nwfilterBindingCreateXML(conn, xml, flags);
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
 * virNWFilterBindingDelete:
 * @binding: a binding object
 *
 * Delete the binding object. This does not free the
 * associated virNWFilterBindingPtr object. This API
 * may be used to remove the network port binding filter
 * currently in use for the guest while the guest is
 * running without needing to restart the guest. Restoring
 * the network port binding filter for the running guest
 * would be accomplished by using virNWFilterBindingCreateXML.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 4.5.0
 */
int
virNWFilterBindingDelete(virNWFilterBindingPtr binding)
{
    virConnectPtr conn;
    VIR_DEBUG("binding=%p", binding);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, -1);
    conn = binding->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterBindingDelete) {
        int ret;
        ret = conn->nwfilterDriver->nwfilterBindingDelete(binding);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(binding->conn);
    return -1;
}


/**
 * virNWFilterBindingGetXMLDesc:
 * @binding: a binding object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Provide an XML description of the network filter. The description may be
 * reused later to redefine the network filter with virNWFilterCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case
 * of error. The caller must free() the returned value.
 *
 * Since: 4.5.0
 */
char *
virNWFilterBindingGetXMLDesc(virNWFilterBindingPtr binding, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("binding=%p, flags=0x%x", binding, flags);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, NULL);
    conn = binding->conn;

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterBindingGetXMLDesc) {
        char *ret;
        ret = conn->nwfilterDriver->nwfilterBindingGetXMLDesc(binding, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(binding->conn);
    return NULL;
}


/**
 * virNWFilterBindingRef:
 * @binding: the binding to hold a reference on
 *
 * Increment the reference count on the binding. For each
 * additional call to this method, there shall be a corresponding
 * call to virNWFilterFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using an binding would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 4.5.0
 */
int
virNWFilterBindingRef(virNWFilterBindingPtr binding)
{
    VIR_DEBUG("binding=%p", binding);

    virResetLastError();

    virCheckNWFilterBindingReturn(binding, -1);

    virObjectRef(binding);
    return 0;
}
