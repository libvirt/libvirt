/*
 * libvirt-domain.c: entry points for virDomainPtr APIs
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
#include <sys/stat.h>

#include "intprops.h"

#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virtypedparam.h"

VIR_LOG_INIT("libvirt.domain");

#define VIR_FROM_THIS VIR_FROM_DOMAIN


/**
 * virConnectListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their IDs in array @ids
 *
 * For inactive domains, see virConnectListDefinedDomains().  For more
 * control over the results, see virConnectListAllDomains().
 *
 * Returns the number of domains found or -1 in case of error.  Note that
 * this command is inherently racy; a domain can be started between a
 * call to virConnectNumOfDomains() and this call; you are only guaranteed
 * that all currently active domains were listed if the return is less
 * than @maxids.
 */
int
virConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    VIR_DEBUG("conn=%p, ids=%p, maxids=%d", conn, ids, maxids);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(ids, error);
    virCheckNonNegativeArgGoto(maxids, error);

    if (conn->driver->connectListDomains) {
        int ret = conn->driver->connectListDomains(conn, ids, maxids);
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
 * virConnectNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDomains(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectNumOfDomains) {
        int ret = conn->driver->connectNumOfDomains(conn);
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
 * virDomainGetConnect:
 * @dom: pointer to a domain
 *
 * Provides the connection pointer associated with a domain.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the domain object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virDomainGetConnect(virDomainPtr dom)
{
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    virCheckDomainReturn(dom, NULL);

    return dom->conn;
}


/**
 * virDomainCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a new guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may require privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, the guest domain
 * will be started, but its CPUs will remain paused. The CPUs
 * can later be manually started using virDomainResume.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateXML(virConnectPtr conn, const char *xmlDesc,
                   unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreateXML) {
        virDomainPtr ret;
        ret = conn->driver->domainCreateXML(conn, xmlDesc, flags);
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
 * virDomainCreateXMLWithFiles:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @nfiles: number of file descriptors passed
 * @files: list of file descriptors passed
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a new guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may require privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * @files provides an array of file descriptors which will be
 * made available to the 'init' process of the guest. The file
 * handles exposed to the guest will be renumbered to start
 * from 3 (ie immediately following stderr). This is only
 * supported for guests which use container based virtualization
 * technology.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, the guest domain
 * will be started, but its CPUs will remain paused. The CPUs
 * can later be manually started using virDomainResume.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateXMLWithFiles(virConnectPtr conn, const char *xmlDesc,
                            unsigned int nfiles,
                            int *files,
                            unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, nfiles=%u, files=%p, flags=%x",
              conn, NULLSTR(xmlDesc), nfiles, files, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreateXMLWithFiles) {
        virDomainPtr ret;
        ret = conn->driver->domainCreateXMLWithFiles(conn, xmlDesc,
                                                     nfiles, files,
                                                     flags);
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
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Deprecated after 0.4.6.
 * Renamed to virDomainCreateXML() providing identical functionality.
 * This existing name will be left indefinitely for API compatibility.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags)
{
    return virDomainCreateXML(conn, xmlDesc, flags);
}


/**
 * virDomainLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 * Note that this won't work for inactive domains which have an ID of -1,
 * in that case a lookup based on the Name or UUId need to be done instead.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByID(virConnectPtr conn, int id)
{
    VIR_DEBUG("conn=%p, id=%d", conn, id);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNegativeArgGoto(id, error);

    if (conn->driver->domainLookupByID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByID(conn, id);
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
 * virDomainLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (conn->driver->domainLookupByUUID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByUUID(conn, uuid);
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
 * virDomainLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr, "%s", _("Invalid UUID"));
        goto error;
    }

    return virDomainLookupByUUID(conn, &uuid[0]);

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its name.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByName(virConnectPtr conn, const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->driver->domainLookupByName) {
        virDomainPtr dom;
        dom = conn->driver->domainLookupByName(conn, name);
        if (!dom)
            goto error;
        return dom;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainDestroy:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor. This
 * does not free the associated virDomainPtr object.
 * This function may require privileged access.
 *
 * virDomainDestroy first requests that a guest terminate
 * (e.g. SIGTERM), then waits for it to comply. After a reasonable
 * timeout, if the guest still exists, virDomainDestroy will
 * forcefully terminate the guest (e.g. SIGKILL) if necessary (which
 * may produce undesirable results, for example unflushed disk cache
 * in the guest). To avoid this possibility, it's recommended to
 * instead call virDomainDestroyFlags, sending the
 * VIR_DOMAIN_DESTROY_GRACEFUL flag.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainDestroy) {
        int ret;
        ret = conn->driver->domainDestroy(domain);
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
 * virDomainDestroyFlags:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainDestroyFlagsValues
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 * This does not free the associated virDomainPtr object.
 * This function may require privileged access.
 *
 * Calling this function with no @flags set (equal to zero) is
 * equivalent to calling virDomainDestroy, and after a reasonable
 * timeout will forcefully terminate the guest (e.g. SIGKILL) if
 * necessary (which may produce undesirable results, for example
 * unflushed disk cache in the guest). Including
 * VIR_DOMAIN_DESTROY_GRACEFUL in the flags will prevent the forceful
 * termination of the guest, and virDomainDestroyFlags will instead
 * return an error if the guest doesn't terminate by the end of the
 * timeout; at that time, the management application can decide if
 * calling again without VIR_DOMAIN_DESTROY_GRACEFUL is appropriate.
 *
 * Another alternative which may produce cleaner results for the
 * guest's disks is to use virDomainShutdown() instead, but that
 * depends on guest support (some hypervisor/guest combinations may
 * ignore the shutdown request).
 *
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroyFlags(virDomainPtr domain,
                      unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainDestroyFlags) {
        int ret;
        ret = conn->driver->domainDestroyFlags(domain, flags);
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
 * virDomainFree:
 * @domain: a domain object
 *
 * Free the domain object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainFree(virDomainPtr domain)
{
    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virObjectUnref(domain);
    return 0;
}


/**
 * virDomainRef:
 * @domain: the domain to hold a reference on
 *
 * Increment the reference count on the domain. For each
 * additional call to this method, there shall be a corresponding
 * call to virDomainFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a domain would increment
 * the reference count.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRef(virDomainPtr domain)
{
    VIR_DOMAIN_DEBUG(domain, "refs=%d", domain ? domain->object.u.s.refs : 0);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virObjectRef(domain);
    return 0;
}


/**
 * virDomainSuspend:
 * @domain: a domain object
 *
 * Suspends an active domain, the process is frozen without further access
 * to CPU resources and I/O but the memory used by the domain at the
 * hypervisor level will stay allocated. Use virDomainResume() to reactivate
 * the domain.
 * This function may require privileged access.
 * Moreover, suspend may not be supported if domain is in some
 * special state like VIR_DOMAIN_PMSUSPENDED.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainSuspend) {
        int ret;
        ret = conn->driver->domainSuspend(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume a suspended domain, the process is restarted from the state where
 * it was frozen by calling virDomainSuspend().
 * This function may require privileged access
 * Moreover, resume may not be supported if domain is in some
 * special state like VIR_DOMAIN_PMSUSPENDED.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainResume) {
        int ret;
        ret = conn->driver->domainResume(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainPMSuspendForDuration:
 * @dom: a domain object
 * @target: a value from virNodeSuspendTarget
 * @duration: duration in seconds to suspend, or 0 for indefinite
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Attempt to have the guest enter the given @target power management
 * suspension level.  If @duration is non-zero, also schedule the guest to
 * resume normal operation after that many seconds, if nothing else has
 * resumed it earlier.  Some hypervisors require that @duration be 0, for
 * an indefinite suspension.
 *
 * Dependent on hypervisor used, this may require a
 * guest agent to be available, e.g. QEMU.
 *
 * Beware that at least for QEMU, the domain's process will be terminated
 * when VIR_NODE_SUSPEND_TARGET_DISK is used and a new process will be
 * launched when libvirt is asked to wake up the domain. As a result of
 * this, any runtime changes, such as device hotplug or memory settings,
 * are lost unless such changes were made with VIR_DOMAIN_AFFECT_CONFIG
 * flag.
 *
 * Returns: 0 on success,
 *          -1 on failure.
 */
int
virDomainPMSuspendForDuration(virDomainPtr dom,
                              unsigned int target,
                              unsigned long long duration,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "target=%u duration=%llu flags=%x",
                     target, duration, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainPMSuspendForDuration) {
        int ret;
        ret = conn->driver->domainPMSuspendForDuration(dom, target,
                                                       duration, flags);
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
 * virDomainPMWakeup:
 * @dom: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Inject a wakeup into the guest that previously used
 * virDomainPMSuspendForDuration, rather than waiting for the
 * previously requested duration (if any) to elapse.
 *
 * Returns: 0 on success,
 *          -1 on failure.
 */
int
virDomainPMWakeup(virDomainPtr dom,
                  unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainPMWakeup) {
        int ret;
        ret = conn->driver->domainPMWakeup(dom, flags);
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
 * virDomainSave:
 * @domain: a domain object
 * @to: path for the output file
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this ends the life of a transient domain).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * See virDomainSaveFlags() for more control.  Also, a save file can
 * be inspected or modified slightly with virDomainSaveImageGetXMLDesc()
 * and virDomainSaveImageDefineXML().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSave(virDomainPtr domain, const char *to)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s", to);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(to, error);

    if (conn->driver->domainSave) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute output file path"));
            goto error;
        }

        ret = conn->driver->domainSave(domain, absolute_to);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSaveFlags:
 * @domain: a domain object
 * @to: path for the output file
 * @dxml: (optional) XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this ends the life of a transient domain).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * If the hypervisor supports it, @dxml can be used to alter
 * host-specific portions of the domain XML that will be used when
 * restoring an image.  For example, it is possible to alter the
 * backing filename that is associated with a disk device, in order to
 * prepare for file renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while creating the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override what state gets saved into the file.  These
 * two flags are mutually exclusive.
 *
 * A save file can be inspected or modified slightly with
 * virDomainSaveImageGetXMLDesc() and virDomainSaveImageDefineXML().
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation; in that case, use virDomainBlockJobAbort()
 * to stop the block copy first.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSaveFlags(virDomainPtr domain, const char *to,
                   const char *dxml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s, dxml=%s, flags=%x",
                     to, NULLSTR(dxml), flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(to, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SAVE_RUNNING,
                             VIR_DOMAIN_SAVE_PAUSED,
                             error);

    if (conn->driver->domainSaveFlags) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute output file path"));
            goto error;
        }

        ret = conn->driver->domainSaveFlags(domain, absolute_to, dxml, flags);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainRestore:
 * @conn: pointer to the hypervisor connection
 * @from: path to the input file
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * See virDomainRestoreFlags() for more control.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestore(virConnectPtr conn, const char *from)
{
    VIR_DEBUG("conn=%p, from=%s", conn, NULLSTR(from));

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(from, error);

    if (conn->driver->domainRestore) {
        int ret;
        char *absolute_from;

        /* We must absolutize the file path as the restore is done out of process */
        if (virFileAbsPath(from, &absolute_from) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainRestore(conn, absolute_from);

        VIR_FREE(absolute_from);

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
 * virDomainRestoreFlags:
 * @conn: pointer to the hypervisor connection
 * @from: path to the input file
 * @dxml: (optional) XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * If the hypervisor supports it, @dxml can be used to alter
 * host-specific portions of the domain XML that will be used when
 * restoring an image.  For example, it is possible to alter the
 * backing filename that is associated with a disk device, in order to
 * prepare for file renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while restoring the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing restores from NFS.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default read from the file.  These two
 * flags are mutually exclusive.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestoreFlags(virConnectPtr conn, const char *from, const char *dxml,
                      unsigned int flags)
{
    VIR_DEBUG("conn=%p, from=%s, dxml=%s, flags=%x",
              conn, NULLSTR(from), NULLSTR(dxml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(from, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SAVE_RUNNING,
                             VIR_DOMAIN_SAVE_PAUSED,
                             error);

    if (conn->driver->domainRestoreFlags) {
        int ret;
        char *absolute_from;

        /* We must absolutize the file path as the restore is done out of process */
        if (virFileAbsPath(from, &absolute_from) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainRestoreFlags(conn, absolute_from, dxml,
                                               flags);

        VIR_FREE(absolute_from);

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
 * virDomainSaveImageGetXMLDesc:
 * @conn: pointer to the hypervisor connection
 * @file: path to saved state file
 * @flags: bitwise-OR of subset of virDomainXMLFlags
 *
 * This method will extract the XML describing the domain at the time
 * a saved state file was created.  @file must be a file created
 * previously by virDomainSave() or virDomainSaveFlags().
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_XML_SECURE; this flag is rejected on read-only
 * connections.  For this API, @flags should not contain either
 * VIR_DOMAIN_XML_INACTIVE or VIR_DOMAIN_XML_UPDATE_CPU.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of
 * error.  The caller must free() the returned value.
 */
char *
virDomainSaveImageGetXMLDesc(virConnectPtr conn, const char *file,
                             unsigned int flags)
{
    VIR_DEBUG("conn=%p, file=%s, flags=%x",
              conn, NULLSTR(file), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(file, error);

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("virDomainSaveImageGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainSaveImageGetXMLDesc) {
        char *ret;
        char *absolute_file;

        /* We must absolutize the file path as the read is done out of process */
        if (virFileAbsPath(file, &absolute_file) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainSaveImageGetXMLDesc(conn, absolute_file,
                                                      flags);

        VIR_FREE(absolute_file);

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
 * virDomainSaveImageDefineXML:
 * @conn: pointer to the hypervisor connection
 * @file: path to saved state file
 * @dxml: XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This updates the definition of a domain stored in a saved state
 * file.  @file must be a file created previously by virDomainSave()
 * or virDomainSaveFlags().
 *
 * @dxml can be used to alter host-specific portions of the domain XML
 * that will be used when restoring an image.  For example, it is
 * possible to alter the backing filename that is associated with a
 * disk device, to match renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default saved into the file; omitting both
 * leaves the file's default unchanged.  These two flags are mutually
 * exclusive.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSaveImageDefineXML(virConnectPtr conn, const char *file,
                            const char *dxml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, file=%s, dxml=%s, flags=%x",
              conn, NULLSTR(file), NULLSTR(dxml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(file, error);
    virCheckNonNullArgGoto(dxml, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SAVE_RUNNING,
                             VIR_DOMAIN_SAVE_PAUSED,
                             error);

    if (conn->driver->domainSaveImageDefineXML) {
        int ret;
        char *absolute_file;

        /* We must absolutize the file path as the read is done out of process */
        if (virFileAbsPath(file, &absolute_file) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainSaveImageDefineXML(conn, absolute_file,
                                                     dxml, flags);

        VIR_FREE(absolute_file);

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
 * virDomainCoreDump:
 * @domain: a domain object
 * @to: path for the core file
 * @flags: bitwise-OR of virDomainCoreDumpFlags
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host. Hypervisors may require  the user to manually ensure
 * proper permissions on the file named by @to.
 *
 * If @flags includes VIR_DUMP_CRASH, then leave the guest shut off with
 * a crashed state after the dump completes.  If @flags includes
 * VIR_DUMP_LIVE, then make the core dump while continuing to allow
 * the guest to run; otherwise, the guest is suspended during the dump.
 * VIR_DUMP_RESET flag forces reset of the guest after dump.
 * The above three flags are mutually exclusive.
 *
 * Additionally, if @flags includes VIR_DUMP_BYPASS_CACHE, then libvirt
 * will attempt to bypass the file system cache while creating the file,
 * or fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * For more control over the output format, see virDomainCoreDumpWithFormat().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainCoreDump(virDomainPtr domain, const char *to, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s, flags=%x", to, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(to, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_CRASH, VIR_DUMP_LIVE, error);
    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_CRASH, VIR_DUMP_RESET, error);
    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_LIVE, VIR_DUMP_RESET, error);

    if (conn->driver->domainCoreDump) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute core file path"));
            goto error;
        }

        ret = conn->driver->domainCoreDump(domain, absolute_to, flags);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainCoreDumpWithFormat:
 * @domain: a domain object
 * @to: path for the core file
 * @dumpformat: format of domain memory's dump (one of virDomainCoreDumpFormat enum)
 * @flags: bitwise-OR of virDomainCoreDumpFlags
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host. Hypervisors may require  the user to manually ensure
 * proper permissions on the file named by @to.
 *
 * @dumpformat controls which format the dump will have; use of
 * VIR_DOMAIN_CORE_DUMP_FORMAT_RAW mirrors what virDomainCoreDump() will
 * perform.  Not all hypervisors are able to support all formats.
 *
 * If @flags includes VIR_DUMP_CRASH, then leave the guest shut off with
 * a crashed state after the dump completes.  If @flags includes
 * VIR_DUMP_LIVE, then make the core dump while continuing to allow
 * the guest to run; otherwise, the guest is suspended during the dump.
 * VIR_DUMP_RESET flag forces reset of the guest after dump.
 * The above three flags are mutually exclusive.
 *
 * Additionally, if @flags includes VIR_DUMP_BYPASS_CACHE, then libvirt
 * will attempt to bypass the file system cache while creating the file,
 * or fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainCoreDumpWithFormat(virDomainPtr domain, const char *to,
                            unsigned int dumpformat, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s, dumpformat=%u, flags=%x",
                     to, dumpformat, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(to, error);

    if (dumpformat >= VIR_DOMAIN_CORE_DUMP_FORMAT_LAST) {
        virReportInvalidArg(flags, _("dumpformat '%d' is not supported"),
                            dumpformat);
        goto error;
    }

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_CRASH, VIR_DUMP_LIVE, error);
    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_CRASH, VIR_DUMP_RESET, error);
    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DUMP_LIVE, VIR_DUMP_RESET, error);

    if (conn->driver->domainCoreDumpWithFormat) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not build absolute core file path"));
            goto error;
        }

        ret = conn->driver->domainCoreDumpWithFormat(domain, absolute_to,
                                                     dumpformat, flags);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainScreenshot:
 * @domain: a domain object
 * @stream: stream to use as output
 * @screen: monitor ID to take screenshot from
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Take a screenshot of current domain console as a stream. The image format
 * is hypervisor specific. Moreover, some hypervisors supports multiple
 * displays per domain. These can be distinguished by @screen argument.
 *
 * This call sets up a stream; subsequent use of stream API is necessary
 * to transfer actual data, determine how much data is successfully
 * transferred, and detect any errors.
 *
 * The screen ID is the sequential number of screen. In case of multiple
 * graphics cards, heads are enumerated before devices, e.g. having
 * two graphics cards, both with four heads, screen ID 5 addresses
 * the second head on the second card.
 *
 * Returns a string representing the mime-type of the image format, or
 * NULL upon error. The caller must free() the returned value.
 */
char *
virDomainScreenshot(virDomainPtr domain,
                    virStreamPtr stream,
                    unsigned int screen,
                    unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "stream=%p, flags=%x", stream, flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    virCheckStreamGoto(stream, error);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    if (domain->conn != stream->conn) {
        virReportInvalidArg(stream,
                            _("stream must match connection of domain '%s'"),
                            domain->name);
        goto error;
    }

    if (domain->conn->driver->domainScreenshot) {
        char *ret;
        ret = domain->conn->driver->domainScreenshot(domain, stream,
                                                     screen, flags);

        if (ret == NULL)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainShutdown:
 * @domain: a domain object
 *
 * Shutdown a domain, the domain object is still usable thereafter, but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request. Additionally, the hypervisor may check and support the domain
 * 'on_poweroff' XML setting resulting in a domain that reboots instead of
 * shutting down. For guests that react to a shutdown request, the differences
 * from virDomainDestroy() are that the guests disk storage will be in a
 * stable state rather than having the (virtual) power cord pulled, and
 * this command returns as soon as the shutdown request is issued rather
 * than blocking until the guest is no longer running.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdown(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainShutdown) {
        int ret;
        ret = conn->driver->domainShutdown(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainShutdownFlags:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainShutdownFlagValues
 *
 * Shutdown a domain, the domain object is still usable thereafter but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request. Additionally, the hypervisor may check and support the domain
 * 'on_poweroff' XML setting resulting in a domain that reboots instead of
 * shutting down. For guests that react to a shutdown request, the differences
 * from virDomainDestroy() are that the guest's disk storage will be in a
 * stable state rather than having the (virtual) power cord pulled, and
 * this command returns as soon as the shutdown request is issued rather
 * than blocking until the guest is no longer running.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * If @flags is set to zero, then the hypervisor will choose the
 * method of shutdown it considers best. To have greater control
 * pass one or more of the virDomainShutdownFlagValues. The order
 * in which the hypervisor tries each shutdown method is undefined,
 * and a hypervisor is not required to support all methods.
 *
 * To use guest agent (VIR_DOMAIN_SHUTDOWN_GUEST_AGENT) the domain XML
 * must have <channel> configured.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainShutdownFlags) {
        int ret;
        ret = conn->driver->domainShutdownFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainReboot:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainRebootFlagValues
 *
 * Reboot a domain, the domain object is still usable thereafter, but
 * the domain OS is being stopped for a restart.
 * Note that the guest OS may ignore the request.
 * Additionally, the hypervisor may check and support the domain
 * 'on_reboot' XML setting resulting in a domain that shuts down instead
 * of rebooting.
 *
 * If @flags is set to zero, then the hypervisor will choose the
 * method of shutdown it considers best. To have greater control
 * pass one or more of the virDomainRebootFlagValues. The order
 * in which the hypervisor tries each shutdown method is undefined,
 * and a hypervisor is not required to support all methods.
 *
 * To use guest agent (VIR_DOMAIN_REBOOT_GUEST_AGENT) the domain XML
 * must have <channel> configured.
 *
 * Due to implementation limitations in some drivers (the qemu driver,
 * for instance) it is not advised to migrate or save a guest that is
 * rebooting as a result of this API. Migrating such a guest can lead
 * to a plain shutdown on the destination.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainReboot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainReboot) {
        int ret;
        ret = conn->driver->domainReboot(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainReset:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reset a domain immediately without any guest OS shutdown.
 * Reset emulates the power reset button on a machine, where all
 * hardware sees the RST line set and reinitializes internal state.
 *
 * Note that there is a risk of data loss caused by reset without any
 * guest OS shutdown.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainReset(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainReset) {
        int ret;
        ret = conn->driver->domainReset(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetName:
 * @domain: a domain object
 *
 * Get the public name for that domain
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the domain object.
 */
const char *
virDomainGetName(virDomainPtr domain)
{
    VIR_DEBUG("domain=%p", domain);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);

    return domain->name;
}


/**
 * virDomainGetUUID:
 * @domain: a domain object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a domain
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetUUID(virDomainPtr domain, unsigned char *uuid)
{
    VIR_DOMAIN_DEBUG(domain, "uuid=%p", uuid);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &domain->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetUUIDString:
 * @domain: a domain object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a domain as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetUUIDString(virDomainPtr domain, char *buf)
{
    VIR_DOMAIN_DEBUG(domain, "buf=%p", buf);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(domain->uuid, buf);
    return 0;

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetID:
 * @domain: a domain object
 *
 * Get the hypervisor ID number for the domain
 *
 * Returns the domain ID number or (unsigned int) -1 in case of error
 */
unsigned int
virDomainGetID(virDomainPtr domain)
{
    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, (unsigned int)-1);

    return domain->id;
}


/**
 * virDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
char *
virDomainGetOSType(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    if (conn->driver->domainGetOSType) {
        char *ret;
        ret = conn->driver->domainGetOSType(domain);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainGetMaxMemory:
 * @domain: a domain object or NULL
 *
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kibibytes (blocks of 1024 bytes), or 0 in
 * case of error.
 */
unsigned long
virDomainGetMaxMemory(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, 0);
    conn = domain->conn;

    if (conn->driver->domainGetMaxMemory) {
        unsigned long long ret;
        ret = conn->driver->domainGetMaxMemory(domain);
        if (ret == 0)
            goto error;
        if ((unsigned long) ret != ret) {
            virReportError(VIR_ERR_OVERFLOW, _("result too large: %llu"),
                           ret);
            goto error;
        }
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return 0;
}


/**
 * virDomainSetMaxMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 *
 * Dynamically change the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
 *
 * This command is hypervisor-specific for whether active, persistent,
 * or both configurations are changed; for more control, use
 * virDomainSetMemoryFlags().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "memory=%lu", memory);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(memory, error);

    if (virMemoryMaxValue(true) / 1024 <= memory) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %lu"),
                       memory);
        goto error;
    }

    if (conn->driver->domainSetMaxMemory) {
        int ret;
        ret = conn->driver->domainSetMaxMemory(domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 *
 * Dynamically change the target amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
 *
 * This command is hypervisor-specific for whether active, persistent,
 * or both configurations are changed; for more control, use
 * virDomainSetMemoryFlags().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "memory=%lu", memory);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(memory, error);

    if (virMemoryMaxValue(true) / 1024 <= memory) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %lu"),
                       memory);
        goto error;
    }

    if (conn->driver->domainSetMemory) {
        int ret;
        ret = conn->driver->domainSetMemory(domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetMemoryFlags:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 * @flags: bitwise-OR of virDomainMemoryModFlags
 *
 * Dynamically change the target amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set. If VIR_DOMAIN_AFFECT_LIVE is set, the change affects
 * a running domain and will fail if domain is not active.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified
 * (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain
 * modifies persistent setup, while an active domain is hypervisor-dependent
 * on whether just live or both live and persistent state is changed.
 * If VIR_DOMAIN_MEM_MAXIMUM is set, the change affects domain's maximum memory
 * size rather than current memory size.
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSetMemoryFlags(virDomainPtr domain, unsigned long memory,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "memory=%lu, flags=%x", memory, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(memory, error);

    if (virMemoryMaxValue(true) / 1024 <= memory) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %lu"),
                       memory);
        goto error;
    }

    if (conn->driver->domainSetMemoryFlags) {
        int ret;
        ret = conn->driver->domainSetMemoryFlags(domain, memory, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetMemoryStatsPeriod:
 * @domain: a domain object or NULL
 * @period: the period in seconds for stats collection
 * @flags: bitwise-OR of virDomainMemoryModFlags
 *
 * Dynamically change the domain memory balloon driver statistics collection
 * period. Use 0 to disable and a positive value to enable.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set. If VIR_DOMAIN_AFFECT_LIVE is set, the change affects
 * a running domain and will fail if domain is not active.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified
 * (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain
 * modifies persistent setup, while an active domain is hypervisor-dependent
 * on whether just live or both live and persistent state is changed.
 *
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSetMemoryStatsPeriod(virDomainPtr domain, int period,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "period=%d, flags=%x", period, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    /* This must be positive to set the balloon collection period */
    virCheckNonNegativeArgGoto(period, error);

    if (conn->driver->domainSetMemoryStatsPeriod) {
        int ret;
        ret = conn->driver->domainSetMemoryStatsPeriod(domain, period, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetMemoryParameters:
 * @domain: pointer to domain object
 * @params: pointer to memory parameter objects
 * @nparams: number of memory parameter (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the memory tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Possible values for all *_limit memory tunables are in range from 0 to
 * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetMemoryParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetMemoryParameters) {
        int ret;
        ret = conn->driver->domainSetMemoryParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetMemoryParameters:
 * @domain: pointer to domain object
 * @params: pointer to memory parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of memory parameters; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all memory parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * Here is a sample code snippet:
 *
 *   if (virDomainGetMemoryParameters(dom, NULL, &nparams, 0) == 0 &&
 *       nparams != 0) {
 *       if ((params = malloc(sizeof(*params) * nparams)) == NULL)
 *           goto error;
 *       memset(params, 0, sizeof(*params) * nparams);
 *       if (virDomainGetMemoryParameters(dom, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetMemoryParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    conn = domain->conn;

    if (conn->driver->domainGetMemoryParameters) {
        int ret;
        ret = conn->driver->domainGetMemoryParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetNumaParameters:
 * @domain: pointer to domain object
 * @params: pointer to numa parameter objects
 * @nparams: number of numa parameters (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the numa tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetNumaParameters(virDomainPtr domain,
                           virTypedParameterPtr params,
                           int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);
    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetNumaParameters) {
        int ret;
        ret = conn->driver->domainSetNumaParameters(domain, params, nparams,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetNumaParameters:
 * @domain: pointer to domain object
 * @params: pointer to numa parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of numa parameters
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all numa parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * See virDomainGetMemoryParameters() for an equivalent usage example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetNumaParameters(virDomainPtr domain,
                           virTypedParameterPtr params,
                           int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    conn = domain->conn;

    if (conn->driver->domainGetNumaParameters) {
        int ret;
        ret = conn->driver->domainGetNumaParameters(domain, params, nparams,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetBlkioParameters:
 * @domain: pointer to domain object
 * @params: pointer to blkio parameter objects
 * @nparams: number of blkio parameters (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the blkio tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetBlkioParameters(virDomainPtr domain,
                            virTypedParameterPtr params,
                            int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetBlkioParameters) {
        int ret;
        ret = conn->driver->domainSetBlkioParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetBlkioParameters:
 * @domain: pointer to domain object
 * @params: pointer to blkio parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of blkio parameters; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all blkio parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * See virDomainGetMemoryParameters() for an equivalent usage example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetBlkioParameters(virDomainPtr domain,
                            virTypedParameterPtr params,
                            int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    conn = domain->conn;

    if (conn->driver->domainGetBlkioParameters) {
        int ret;
        ret = conn->driver->domainGetBlkioParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 *
 * Extract information about a domain. Note that if the connection
 * used to get the domain is limited only a partial set of the information
 * can be extracted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p", info);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(info, error);

    conn = domain->conn;

    if (conn->driver->domainGetInfo) {
        int ret;
        ret = conn->driver->domainGetInfo(domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetState:
 * @domain: a domain object
 * @state: returned state of the domain (one of virDomainState)
 * @reason: returned reason which led to @state (one of virDomain*Reason
 * corresponding to the current state); it is allowed to be NULL
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract domain state. Each state can be accompanied with a reason (if known)
 * which led to the state.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetState(virDomainPtr domain,
                  int *state,
                  int *reason,
                  unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "state=%p, reason=%p, flags=%x",
                     state, reason, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(state, error);

    conn = domain->conn;
    if (conn->driver->domainGetState) {
        int ret;
        ret = conn->driver->domainGetState(domain, state, reason, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetControlInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainControlInfo structure allocated by the user
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract details about current state of control interface to a domain.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetControlInfo(virDomainPtr domain,
                        virDomainControlInfoPtr info,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, flags=%x", info, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(info, error);

    conn = domain->conn;
    if (conn->driver->domainGetControlInfo) {
        int ret;
        ret = conn->driver->domainGetControlInfo(domain, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetXMLDesc:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainXMLFlags
 *
 * Provide an XML description of the domain. The description may be reused
 * later to relaunch the domain with virDomainCreateXML().
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_XML_SECURE; this flag is rejected on read-only
 * connections.  If @flags includes VIR_DOMAIN_XML_INACTIVE, then the
 * XML represents the configuration that will be used on the next boot
 * of a persistent domain; otherwise, the configuration represents the
 * currently running domain.  If @flags contains
 * VIR_DOMAIN_XML_UPDATE_CPU, then the portion of the domain XML
 * describing CPU capabilities is modified to match actual
 * capabilities of the host.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) &&
        (flags & (VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_MIGRATABLE))) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("virDomainGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainGetXMLDesc) {
        char *ret;
        ret = conn->driver->domainGetXMLDesc(domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virConnectDomainXMLFromNative:
 * @conn: a connection object
 * @nativeFormat: configuration format importing from
 * @nativeConfig: the configuration data to import
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reads native configuration data  describing a domain, and
 * generates libvirt domain XML. The format of the native
 * data is hypervisor dependent.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virConnectDomainXMLFromNative(virConnectPtr conn,
                              const char *nativeFormat,
                              const char *nativeConfig,
                              unsigned int flags)
{
    VIR_DEBUG("conn=%p, format=%s, config=%s, flags=%x",
              conn, NULLSTR(nativeFormat), NULLSTR(nativeConfig), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);

    virCheckNonNullArgGoto(nativeFormat, error);
    virCheckNonNullArgGoto(nativeConfig, error);

    if (conn->driver->connectDomainXMLFromNative) {
        char *ret;
        ret = conn->driver->connectDomainXMLFromNative(conn,
                                                       nativeFormat,
                                                       nativeConfig,
                                                       flags);
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
 * virConnectDomainXMLToNative:
 * @conn: a connection object
 * @nativeFormat: configuration format exporting to
 * @domainXml: the domain configuration to export
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reads a domain XML configuration document, and generates
 * a native configuration file describing the domain.
 * The format of the native data is hypervisor dependent.
 *
 * Returns a 0 terminated UTF-8 encoded native config datafile, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virConnectDomainXMLToNative(virConnectPtr conn,
                            const char *nativeFormat,
                            const char *domainXml,
                            unsigned int flags)
{
    VIR_DEBUG("conn=%p, format=%s, xml=%s, flags=%x",
              conn, NULLSTR(nativeFormat), NULLSTR(domainXml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);

    virCheckNonNullArgGoto(nativeFormat, error);
    virCheckNonNullArgGoto(domainXml, error);

    if (conn->driver->connectDomainXMLToNative) {
        char *ret;
        ret = conn->driver->connectDomainXMLToNative(conn,
                                                     nativeFormat,
                                                     domainXml,
                                                     flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/*
 * Sequence v1:
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Kill off VM if successful, resume if failed
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if unsuccessful
 *
 */
static virDomainPtr
virDomainMigrateVersion1(virDomainPtr domain,
                         virConnectPtr dconn,
                         unsigned long flags,
                         const char *dname,
                         const char *uri,
                         unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    int cookielen = 0, ret;
    virDomainInfo info;
    unsigned int destflags;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    ret = virDomainGetInfo(domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    /* Prepare the migration.
     *
     * The destination host may return a cookie, or leave cookie as
     * NULL.
     *
     * The destination host MUST set uri_out if uri_in is NULL.
     *
     * If uri_in is non-NULL, then the destination host may modify
     * the URI by setting uri_out.  If it does not wish to modify
     * the URI, it should leave uri_out as NULL.
     */
    if (dconn->driver->domainMigratePrepare
        (dconn, &cookie, &cookielen, uri, &uri_out, destflags, dname,
         bandwidth) == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare did not set uri"));
        goto done;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare change URI? */

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    if (domain->conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth) == -1)
        goto done;

    /* Get the destination domain and return it or error.
     * 'domain' no longer actually exists at this point
     * (or so we hope), but we still use the object in memory
     * in order to get the name.
     */
    dname = dname ? dname : domain->name;
    if (dconn->driver->domainMigrateFinish)
        ddomain = dconn->driver->domainMigrateFinish
            (dconn, dname, cookie, cookielen, uri, destflags);
    else
        ddomain = virDomainLookupByName(dconn, dname);

 done:
    VIR_FREE(uri_out);
    VIR_FREE(cookie);
    return ddomain;
}


/*
 * Sequence v2:
 *
 *  Src: DumpXML
 *        - Generate XML to pass to dst
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Kill off VM if successful, resume if failed
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if unsuccessful
 *
 */
static virDomainPtr
virDomainMigrateVersion2(virDomainPtr domain,
                         virConnectPtr dconn,
                         unsigned long flags,
                         const char *dname,
                         const char *uri,
                         unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret;
    virDomainInfo info;
    virErrorPtr orig_err = NULL;
    unsigned int getxml_flags = 0;
    int cancelled;
    unsigned long destflags;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    /* Prepare the migration.
     *
     * The destination host may return a cookie, or leave cookie as
     * NULL.
     *
     * The destination host MUST set uri_out if uri_in is NULL.
     *
     * If uri_in is non-NULL, then the destination host may modify
     * the URI by setting uri_out.  If it does not wish to modify
     * the URI, it should leave uri_out as NULL.
     */

    /* In version 2 of the protocol, the prepare step is slightly
     * different.  We fetch the domain XML of the source domain
     * and pass it to Prepare2.
     */
    if (!domain->conn->driver->domainGetXMLDesc) {
        virReportUnsupportedError();
        return NULL;
    }

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_XML_MIGRATABLE)) {
        getxml_flags |= VIR_DOMAIN_XML_MIGRATABLE;
    } else {
        getxml_flags |= VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_UPDATE_CPU;
    }

    dom_xml = domain->conn->driver->domainGetXMLDesc(domain, getxml_flags);
    if (!dom_xml)
        return NULL;

    ret = virDomainGetInfo(domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare2 %p flags=%lx", dconn, destflags);
    ret = dconn->driver->domainMigratePrepare2
        (dconn, &cookie, &cookielen, uri, &uri_out, destflags, dname,
         bandwidth, dom_xml);
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare2 did not set uri"));
        cancelled = 1;
        /* Make sure Finish doesn't overwrite the error */
        orig_err = virSaveLastError();
        goto finish;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare2 change URI? */

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", domain->conn);
    ret = domain->conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

 finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : domain->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen, uri, destflags, cancelled);
    if (cancelled && ddomain)
        VIR_ERROR(_("finish step ignored that migration was cancelled"));

 done:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookie);
    return ddomain;
}


/*
 * Sequence v3:
 *
 *  Src: Begin
 *        - Generate XML to pass to dst
 *        - Generate optional cookie to pass to dst
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Generate optional cookie to pass to dst
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if failed, resume if success
 *        - Generate optional cookie to pass to src
 *
 *  Src: Confirm
 *        - Kill off VM if success, resume if failed
 *
  * If useParams is true, params and nparams contain migration parameters and
  * we know it's safe to call the API which supports extensible parameters.
  * Otherwise, we have to use xmlin, dname, uri, and bandwidth and pass them
  * to the old-style APIs.
 */
static virDomainPtr
virDomainMigrateVersion3Full(virDomainPtr domain,
                             virConnectPtr dconn,
                             const char *xmlin,
                             const char *dname,
                             const char *uri,
                             unsigned long long bandwidth,
                             virTypedParameterPtr params,
                             int nparams,
                             bool useParams,
                             unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    char *dom_xml = NULL;
    int cookieinlen = 0;
    int cookieoutlen = 0;
    int ret;
    virDomainInfo info;
    virErrorPtr orig_err = NULL;
    int cancelled = 1;
    unsigned long protection = 0;
    bool notify_source = true;
    unsigned int destflags;
    int state;
    virTypedParameterPtr tmp;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, xmlin=%s, dname=%s, uri=%s, bandwidth=%llu, "
                     "params=%p, nparams=%d, useParams=%d, flags=%x",
                     dconn, NULLSTR(xmlin), NULLSTR(dname), NULLSTR(uri),
                     bandwidth, params, nparams, useParams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    if ((!useParams &&
         (!domain->conn->driver->domainMigrateBegin3 ||
          !domain->conn->driver->domainMigratePerform3 ||
          !domain->conn->driver->domainMigrateConfirm3 ||
          !dconn->driver->domainMigratePrepare3 ||
          !dconn->driver->domainMigrateFinish3)) ||
        (useParams &&
         (!domain->conn->driver->domainMigrateBegin3Params ||
          !domain->conn->driver->domainMigratePerform3Params ||
          !domain->conn->driver->domainMigrateConfirm3Params ||
          !dconn->driver->domainMigratePrepare3Params ||
          !dconn->driver->domainMigrateFinish3Params))) {
        virReportUnsupportedError();
        return NULL;
    }

    if (virTypedParamsCopy(&tmp, params, nparams) < 0)
        return NULL;
    params = tmp;

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION))
        protection = VIR_MIGRATE_CHANGE_PROTECTION;

    VIR_DEBUG("Begin3 %p", domain->conn);
    if (useParams) {
        dom_xml = domain->conn->driver->domainMigrateBegin3Params
            (domain, params, nparams, &cookieout, &cookieoutlen,
             flags | protection);
    } else {
        dom_xml = domain->conn->driver->domainMigrateBegin3
            (domain, xmlin, &cookieout, &cookieoutlen,
             flags | protection, dname, bandwidth);
    }
    if (!dom_xml)
        goto done;

    if (useParams) {
        /* If source is new enough to support extensible migration parameters,
         * it's certainly new enough to support virDomainGetState. */
        ret = virDomainGetState(domain, &state, NULL, 0);
    } else {
        ret = virDomainGetInfo(domain, &info);
        state = info.state;
    }
    if (ret == 0 && state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare3 %p flags=%x", dconn, destflags);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (useParams) {
        if (virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_XML,
                                        dom_xml) < 0)
            goto done;
        ret = dconn->driver->domainMigratePrepare3Params
            (dconn, params, nparams, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, &uri_out, destflags);
    } else {
        ret = dconn->driver->domainMigratePrepare3
            (dconn, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             uri, &uri_out, destflags, dname, bandwidth, dom_xml);
    }
    if (ret == -1) {
        if (protection) {
            /* Begin already started a migration job so we need to cancel it by
             * calling Confirm while making sure it doesn't overwrite the error
             */
            orig_err = virSaveLastError();
            goto confirm;
        } else {
            goto done;
        }
    }

    /* Did domainMigratePrepare3 change URI? */
    if (uri_out) {
        uri = uri_out;
        if (useParams &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_URI,
                                        uri_out) < 0) {
            cancelled = 1;
            orig_err = virSaveLastError();
            goto finish;
        }
    } else if (!uri &&
               virTypedParamsGetString(params, nparams,
                                       VIR_MIGRATE_PARAM_URI, &uri) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare3 did not set uri"));
        cancelled = 1;
        orig_err = virSaveLastError();
        goto finish;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        VIR_DEBUG("Offline migration, skipping Perform phase");
        VIR_FREE(cookieout);
        cookieoutlen = 0;
        cancelled = 0;
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s", domain->conn, uri);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    /* dconnuri not relevant in non-P2P modes, so left NULL here */
    if (useParams) {
        ret = domain->conn->driver->domainMigratePerform3Params
            (domain, NULL, params, nparams, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, flags | protection);
    } else {
        ret = domain->conn->driver->domainMigratePerform3
            (domain, NULL, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, NULL,
             uri, flags | protection, dname, bandwidth);
    }

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0) {
        orig_err = virSaveLastError();
        /* Perform failed so we don't need to call confirm to let source know
         * about the failure.
         */
        notify_source = false;
    }

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

 finish:
    /*
     * The status code from the source is passed to the destination.
     * The dest can cleanup if the source indicated it failed to
     * send all migration data. Returns NULL for ddomain if
     * the dest was unable to complete migration.
     */
    VIR_DEBUG("Finish3 %p ret=%d", dconn, ret);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (useParams) {
        if (virTypedParamsGetString(params, nparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, NULL) <= 0 &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_NAME,
                                        domain->name) < 0) {
            ddomain = NULL;
        } else {
            ddomain = dconn->driver->domainMigrateFinish3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags, cancelled);
        }
    } else {
        dname = dname ? dname : domain->name;
        ddomain = dconn->driver->domainMigrateFinish3
            (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             NULL, uri, destflags, cancelled);
    }

    if (cancelled) {
        if (ddomain) {
            VIR_ERROR(_("finish step ignored that migration was cancelled"));
        } else {
            /* If Finish reported a useful error, use it instead of the
             * original "migration unexpectedly failed" error.
             *
             * This is ugly but we can't do better with the APIs we have. We
             * only replace the error if Finish was called with cancelled == 1
             * and reported a real error (old libvirt would report an error
             * from RPC instead of MIGRATE_FINISH_OK), which only happens when
             * the domain died on destination. To further reduce a possibility
             * of false positives we also check that Perform returned
             * VIR_ERR_OPERATION_FAILED.
             */
            if (orig_err &&
                orig_err->domain == VIR_FROM_QEMU &&
                orig_err->code == VIR_ERR_OPERATION_FAILED) {
                virErrorPtr err = virGetLastError();
                if (err &&
                    err->domain == VIR_FROM_QEMU &&
                    err->code != VIR_ERR_MIGRATE_FINISH_OK) {
                    virFreeError(orig_err);
                    orig_err = NULL;
                }
            }
        }
    }

    /* If ddomain is NULL, then we were unable to start
     * the guest on the target, and must restart on the
     * source. There is a small chance that the ddomain
     * is NULL due to an RPC failure, in which case
     * ddomain could in fact be running on the dest.
     * The lock manager plugins should take care of
     * safety in this scenario.
     */
    cancelled = ddomain == NULL ? 1 : 0;

    /* If finish3 set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        orig_err = virSaveLastError();

 confirm:
    /*
     * If cancelled, then src VM will be restarted, else it will be killed.
     * Don't do this if migration failed on source and thus it was already
     * cancelled there.
     */
    if (notify_source) {
        VIR_DEBUG("Confirm3 %p ret=%d domain=%p", domain->conn, ret, domain);
        VIR_FREE(cookiein);
        cookiein = cookieout;
        cookieinlen = cookieoutlen;
        cookieout = NULL;
        cookieoutlen = 0;
        if (useParams) {
            ret = domain->conn->driver->domainMigrateConfirm3Params
                (domain, params, nparams, cookiein, cookieinlen,
                 flags | protection, cancelled);
        } else {
            ret = domain->conn->driver->domainMigrateConfirm3
                (domain, cookiein, cookieinlen,
                 flags | protection, cancelled);
        }
        /* If Confirm3 returns -1, there's nothing more we can
         * do, but fortunately worst case is that there is a
         * domain left in 'paused' state on source.
         */
        if (ret < 0) {
            VIR_WARN("Guest %s probably left in 'paused' state on source",
                     domain->name);
        }
    }

 done:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(dom_xml);
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);
    virTypedParamsFree(params, nparams);
    return ddomain;
}


static virDomainPtr
virDomainMigrateVersion3(virDomainPtr domain,
                         virConnectPtr dconn,
                         const char *xmlin,
                         unsigned long flags,
                         const char *dname,
                         const char *uri,
                         unsigned long bandwidth)
{
    return virDomainMigrateVersion3Full(domain, dconn, xmlin, dname, uri,
                                        bandwidth, NULL, 0, false, flags);
}


static virDomainPtr
virDomainMigrateVersion3Params(virDomainPtr domain,
                               virConnectPtr dconn,
                               virTypedParameterPtr params,
                               int nparams,
                               unsigned int flags)
{
    return virDomainMigrateVersion3Full(domain, dconn, NULL, NULL, NULL, 0,
                                        params, nparams, true, flags);
}


static int
virDomainMigrateCheckNotLocal(const char *dconnuri)
{
    virURIPtr tempuri = NULL;
    int ret = -1;

    if (!(tempuri = virURIParse(dconnuri)))
        goto cleanup;
    if (!tempuri->server || STRPREFIX(tempuri->server, "localhost")) {
        virReportInvalidArg(dconnuri, "%s",
                            _("Attempt to migrate guest to the same host"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virURIFree(tempuri);
    return ret;
}


static int
virDomainMigrateUnmanagedProto2(virDomainPtr domain,
                                const char *dconnuri,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    /* uri parameter is added for direct case */
    const char *compatParams[] = { VIR_MIGRATE_PARAM_DEST_NAME,
                                   VIR_MIGRATE_PARAM_BANDWIDTH,
                                   VIR_MIGRATE_PARAM_URI };
    const char *uri = NULL;
    const char *miguri = NULL;
    const char *dname = NULL;
    unsigned long long bandwidth = 0;

    if (!virTypedParamsCheck(params, nparams, compatParams,
                             ARRAY_CARDINALITY(compatParams))) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Some parameters are not supported by migration "
                         "protocol 2"));
        return -1;
    }

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI, &miguri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, &dname) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, &bandwidth) < 0) {
        return -1;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (miguri) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to override peer2peer migration URI"));
            return -1;
        }
        uri = dconnuri;
    } else {
        uri = miguri;
    }

    return domain->conn->driver->domainMigratePerform
            (domain, NULL, 0, uri, flags, dname, bandwidth);
}


static int
virDomainMigrateUnmanagedProto3(virDomainPtr domain,
                                const char *dconnuri,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    const char *compatParams[] = { VIR_MIGRATE_PARAM_URI,
                                   VIR_MIGRATE_PARAM_DEST_NAME,
                                   VIR_MIGRATE_PARAM_DEST_XML,
                                   VIR_MIGRATE_PARAM_BANDWIDTH };
    const char *miguri = NULL;
    const char *dname = NULL;
    const char *xmlin = NULL;
    unsigned long long bandwidth = 0;

    if (!virTypedParamsCheck(params, nparams, compatParams,
                             ARRAY_CARDINALITY(compatParams))) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Some parameters are not supported by migration "
                         "protocol 3"));
        return -1;
    }

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI, &miguri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML, &xmlin) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, &bandwidth) < 0) {
        return -1;
    }

    return domain->conn->driver->domainMigratePerform3
            (domain, xmlin, NULL, 0, NULL, NULL, dconnuri,
             miguri, flags, dname, bandwidth);
}


/*
 * In normal migration, the libvirt client co-ordinates communication
 * between the 2 libvirtd instances on source & dest hosts.
 *
 * This function encapsulates 2 alternatives to the above case.
 *
 * 1. peer-2-peer migration, the libvirt client only talks to the source
 * libvirtd instance. The source libvirtd then opens its own
 * connection to the destination and co-ordinates migration itself.
 *
 * 2. direct migration, where there is no requirement for a libvirtd instance
 * on the dest host. Eg, XenD can talk direct to XenD, so libvirtd on dest
 * does not need to be involved at all, or even running.
 */
static int
virDomainMigrateUnmanagedParams(virDomainPtr domain,
                                const char *dconnuri,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, params=%p, nparams=%d, flags=%x",
                     NULLSTR(dconnuri), params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    if ((flags & VIR_MIGRATE_PEER2PEER) &&
        virDomainMigrateCheckNotLocal(dconnuri) < 0)
        return -1;

    if ((flags & VIR_MIGRATE_PEER2PEER) &&
        VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_PARAMS)) {
        VIR_DEBUG("Using migration protocol 3 with extensible parameters");
        if (!domain->conn->driver->domainMigratePerform3Params) {
            virReportUnsupportedError();
            return -1;
        }
        return domain->conn->driver->domainMigratePerform3Params
                (domain, dconnuri, params, nparams,
                 NULL, 0, NULL, NULL, flags);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V3)) {
        VIR_DEBUG("Using migration protocol 3");
        if (!domain->conn->driver->domainMigratePerform3) {
            virReportUnsupportedError();
            return -1;
        }
        return virDomainMigrateUnmanagedProto3(domain, dconnuri,
                                               params, nparams, flags);
    } else {
        VIR_DEBUG("Using migration protocol 2");
        if (!domain->conn->driver->domainMigratePerform) {
            virReportUnsupportedError();
            return -1;
        }
        return virDomainMigrateUnmanagedProto2(domain, dconnuri,
                                               params, nparams, flags);
    }
}


static int
virDomainMigrateUnmanaged(virDomainPtr domain,
                          const char *xmlin,
                          unsigned int flags,
                          const char *dname,
                          const char *dconnuri,
                          const char *miguri,
                          unsigned long long bandwidth)
{
    int ret = -1;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;

    if (miguri &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_URI, miguri) < 0)
        goto cleanup;
    if (dname &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, dname) < 0)
        goto cleanup;
    if (xmlin &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_XML, xmlin) < 0)
        goto cleanup;
    if (virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, bandwidth) < 0)
        goto cleanup;

    ret = virDomainMigrateUnmanagedParams(domain, dconnuri, params,
                                          nparams, flags);

 cleanup:
    virTypedParamsFree(params, nparams);

    return ret;
}


/**
 * virDomainMigrate:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @uri: (optional) dest hostname/URI as seen from the source host
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
 *
 * Migrate the domain object from its current host to the destination
 * host given by dconn (a connection to the destination host).
 *
 * This function is similar to virDomainMigrate3, but it only supports a fixed
 * set of parameters: @dname corresponds to VIR_MIGRATE_PARAM_DEST_NAME, @uri
 * is VIR_MIGRATE_PARAM_URI, and @bandwidth is VIR_MIGRATE_PARAM_BANDWIDTH.
 *
 * virDomainFree should be used to free the resources after the
 * returned domain object is no longer needed.
 *
 * Returns the new domain object if the migration was successful,
 *   or NULL in case of error.  Note that the new domain object
 *   exists in the scope of the destination connection (dconn).
 */
virDomainPtr
virDomainMigrate(virDomainPtr domain,
                 virConnectPtr dconn,
                 unsigned long flags,
                 const char *dname,
                 const char *uri,
                 unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, NULL);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    /* Now checkout the destination */
    virCheckConnectGoto(dconn, error);
    virCheckReadOnlyGoto(dconn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_MIGRATE_NON_SHARED_DISK,
                             VIR_MIGRATE_NON_SHARED_INC,
                             error);

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the destination host"));
            goto error;
        }
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            char *dstURI = NULL;
            if (uri == NULL) {
                dstURI = virConnectGetURI(dconn);
                if (!dstURI)
                    return NULL;
            }

            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigrateUnmanaged(domain, NULL, flags, dname,
                                          uri ? uri : dstURI, NULL, bandwidth) < 0) {
                VIR_FREE(dstURI);
                goto error;
            }
            VIR_FREE(dstURI);

            ddomain = virDomainLookupByName(dconn, dname ? dname : domain->name);
        } else {
            /* This driver does not support peer to peer migration */
            virReportUnsupportedError();
            goto error;
        }
    } else {
        /* Change protection requires support only on source side, and
         * is only needed in v3 migration, which automatically re-adds
         * the flag for just the source side.  We mask it out for
         * non-peer2peer to allow migration from newer source to an
         * older destination that rejects the flag.  */
        if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
            !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("cannot enforce change protection"));
            goto error;
        }
        flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot perform tunnelled migration without using peer2peer flag"));
            goto error;
        }

        /* Check that migration is supported by both drivers. */
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_V3) &&
            VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                     VIR_DRV_FEATURE_MIGRATION_V3)) {
            VIR_DEBUG("Using migration protocol 3");
            ddomain = virDomainMigrateVersion3(domain, dconn, NULL,
                                               flags, dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V2) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                          VIR_DRV_FEATURE_MIGRATION_V2)) {
            VIR_DEBUG("Using migration protocol 2");
            ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V1) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                            VIR_DRV_FEATURE_MIGRATION_V1)) {
            VIR_DEBUG("Using migration protocol 1");
            ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else {
            /* This driver does not support any migration method */
            virReportUnsupportedError();
            goto error;
        }
    }

    if (ddomain == NULL)
        goto error;

    return ddomain;

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainMigrate2:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dxml: (optional) XML config for launching guest on target
 * @dname: (optional) rename domain to this at destination
 * @uri: (optional) dest hostname/URI as seen from the source host
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
 *
 * Migrate the domain object from its current host to the destination
 * host given by dconn (a connection to the destination host).
 *
 * This function is similar to virDomainMigrate3, but it only supports a fixed
 * set of parameters: @dxml corresponds to VIR_MIGRATE_PARAM_DEST_XML, @dname
 * is VIR_MIGRATE_PARAM_DEST_NAME, @uri is VIR_MIGRATE_PARAM_URI, and
 * @bandwidth is VIR_MIGRATE_PARAM_BANDWIDTH.
 *
 * virDomainFree should be used to free the resources after the
 * returned domain object is no longer needed.
 *
 * Returns the new domain object if the migration was successful,
 *   or NULL in case of error.  Note that the new domain object
 *   exists in the scope of the destination connection (dconn).
 */
virDomainPtr
virDomainMigrate2(virDomainPtr domain,
                  virConnectPtr dconn,
                  const char *dxml,
                  unsigned long flags,
                  const char *dname,
                  const char *uri,
                  unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, NULL);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    /* Now checkout the destination */
    virCheckConnectGoto(dconn, error);
    virCheckReadOnlyGoto(dconn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_MIGRATE_NON_SHARED_DISK,
                             VIR_MIGRATE_NON_SHARED_INC,
                             error);

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the destination host"));
            goto error;
        }
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            char *dstURI = virConnectGetURI(dconn);
            if (!dstURI)
                return NULL;

            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigrateUnmanaged(domain, dxml, flags, dname,
                                          dstURI, uri, bandwidth) < 0) {
                VIR_FREE(dstURI);
                goto error;
            }
            VIR_FREE(dstURI);

            ddomain = virDomainLookupByName(dconn, dname ? dname : domain->name);
        } else {
            /* This driver does not support peer to peer migration */
            virReportUnsupportedError();
            goto error;
        }
    } else {
        /* Change protection requires support only on source side, and
         * is only needed in v3 migration, which automatically re-adds
         * the flag for just the source side.  We mask it out for
         * non-peer2peer to allow migration from newer source to an
         * older destination that rejects the flag.  */
        if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
            !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("cannot enforce change protection"));
            goto error;
        }
        flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot perform tunnelled migration without using peer2peer flag"));
            goto error;
        }

        /* Check that migration is supported by both drivers. */
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_V3) &&
            VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                     VIR_DRV_FEATURE_MIGRATION_V3)) {
            VIR_DEBUG("Using migration protocol 3");
            ddomain = virDomainMigrateVersion3(domain, dconn, dxml,
                                               flags, dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V2) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                          VIR_DRV_FEATURE_MIGRATION_V2)) {
            VIR_DEBUG("Using migration protocol 2");
            if (dxml) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                               _("Unable to change target guest XML during migration"));
                goto error;
            }
            ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V1) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                            VIR_DRV_FEATURE_MIGRATION_V1)) {
            VIR_DEBUG("Using migration protocol 1");
            if (dxml) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                               _("Unable to change target guest XML during migration"));
                goto error;
            }
            ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else {
            /* This driver does not support any migration method */
            virReportUnsupportedError();
            goto error;
        }
    }

    if (ddomain == NULL)
        goto error;

    return ddomain;

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainMigrate3:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @params: (optional) migration parameters
 * @nparams: (optional) number of migration parameters in @params
 * @flags: bitwise-OR of virDomainMigrateFlags
 *
 * Migrate the domain object from its current host to the destination host
 * given by dconn (a connection to the destination host).
 *
 * See VIR_MIGRATE_PARAM_* and virDomainMigrateFlags for detailed description
 * of accepted migration parameters and flags.
 *
 * See virDomainMigrateFlags documentation for description of individual flags.
 *
 * VIR_MIGRATE_TUNNELLED and VIR_MIGRATE_PEER2PEER are not supported by this
 * API, use virDomainMigrateToURI3 instead.
 *
 * There are many limitations on migration imposed by the underlying
 * technology - for example it may not be possible to migrate between
 * different processors even with the same architecture, or between
 * different types of hypervisor.
 *
 * virDomainFree should be used to free the resources after the
 * returned domain object is no longer needed.
 *
 * Returns the new domain object if the migration was successful,
 *   or NULL in case of error.  Note that the new domain object
 *   exists in the scope of the destination connection (dconn).
 */
virDomainPtr
virDomainMigrate3(virDomainPtr domain,
                  virConnectPtr dconn,
                  virTypedParameterPtr params,
                  unsigned int nparams,
                  unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    const char *compatParams[] = { VIR_MIGRATE_PARAM_URI,
                                   VIR_MIGRATE_PARAM_DEST_NAME,
                                   VIR_MIGRATE_PARAM_DEST_XML,
                                   VIR_MIGRATE_PARAM_BANDWIDTH };
    const char *uri = NULL;
    const char *dname = NULL;
    const char *dxml = NULL;
    unsigned long long bandwidth = 0;

    VIR_DOMAIN_DEBUG(domain, "dconn=%p, params=%p, nparms=%u flags=%x",
                     dconn, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, NULL);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    /* Now checkout the destination */
    virCheckReadOnlyGoto(dconn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_MIGRATE_NON_SHARED_DISK,
                             VIR_MIGRATE_NON_SHARED_INC,
                             error);

    if (flags & VIR_MIGRATE_PEER2PEER) {
        virReportInvalidArg(flags, "%s",
                            _("use virDomainMigrateToURI3 for peer-to-peer "
                              "migration"));
        goto error;
    }
    if (flags & VIR_MIGRATE_TUNNELLED) {
        virReportInvalidArg(flags, "%s",
                            _("cannot perform tunnelled migration "
                              "without using peer2peer flag"));
        goto error;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("offline migration is not supported by "
                             "the destination host"));
            goto error;
        }
    }

    /* Change protection requires support only on source side, and
     * is only needed in v3 migration, which automatically re-adds
     * the flag for just the source side.  We mask it out to allow
     * migration from newer source to an older destination that
     * rejects the flag.  */
    if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
        !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                  VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("cannot enforce change protection"));
        goto error;
    }
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    /* Prefer extensible API but fall back to older migration APIs if params
     * only contains parameters which were supported by the older API. */
    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_PARAMS) &&
        VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                 VIR_DRV_FEATURE_MIGRATION_PARAMS)) {
        VIR_DEBUG("Using migration protocol 3 with extensible parameters");
        ddomain = virDomainMigrateVersion3Params(domain, dconn, params,
                                                 nparams, flags);
        goto done;
    }

    if (!virTypedParamsCheck(params, nparams, compatParams,
                             ARRAY_CARDINALITY(compatParams))) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Migration APIs with extensible parameters are not "
                         "supported but extended parameters were passed"));
        goto error;
    }

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI, &uri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML, &dxml) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, &bandwidth) < 0) {
        goto error;
    }

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_V3) &&
        VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                 VIR_DRV_FEATURE_MIGRATION_V3)) {
        VIR_DEBUG("Using migration protocol 3");
        ddomain = virDomainMigrateVersion3(domain, dconn, dxml, flags,
                                           dname, uri, bandwidth);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V2) &&
               VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_V2)) {
        VIR_DEBUG("Using migration protocol 2");
        if (dxml) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("Unable to change target guest XML during "
                             "migration"));
            goto error;
        }
        ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                           dname, uri, bandwidth);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V1) &&
               VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                        VIR_DRV_FEATURE_MIGRATION_V1)) {
        VIR_DEBUG("Using migration protocol 1");
        if (dxml) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("Unable to change target guest XML during "
                             "migration"));
            goto error;
        }
        ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                           dname, uri, bandwidth);
    } else {
        /* This driver does not support any migration method */
        virReportUnsupportedError();
        goto error;
    }

 done:
    if (ddomain == NULL)
        goto error;

    return ddomain;

 error:
    virDispatchError(domain->conn);
    return NULL;
}


static
int virDomainMigrateUnmanagedCheckCompat(virDomainPtr domain,
                                         unsigned int flags)
{
    VIR_EXCLUSIVE_FLAGS_RET(VIR_MIGRATE_NON_SHARED_DISK,
                            VIR_MIGRATE_NON_SHARED_INC,
                            -1);

    if (flags & VIR_MIGRATE_OFFLINE &&
        !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                  VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("offline migration is not supported by "
                         "the source host"));
        return -1;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_P2P)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("p2p migration is not supported by "
                             "the source host"));
            return -1;
        }
    } else {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_DIRECT)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("direct migration is not supported by "
                             "the source host"));
            return -1;
        }
    }

    return 0;
}


/**
 * virDomainMigrateToURI:
 * @domain: a domain object
 * @duri: mandatory URI for the destination host
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
 *
 * Migrate the domain object from its current host to the destination
 * host given by duri.
 *
 * This function is similar to virDomainMigrateToURI3, but it only supports a
 * fixed set of parameters: @dname corresponds to VIR_MIGRATE_PARAM_DEST_NAME,
 * and @bandwidth corresponds to VIR_MIGRATE_PARAM_BANDWIDTH.
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 *
 * If the VIR_MIGRATE_PEER2PEER flag IS set, the @duri parameter must be a
 * valid libvirt connection URI, by which the source libvirt driver can connect
 * to the destination libvirt. In other words, @duri corresponds to @dconnuri
 * of virDomainMigrateToURI3.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, the @duri parameter takes a
 * hypervisor specific URI used to initiate the migration. In this case @duri
 * corresponds to VIR_MIGRATE_PARAM_URI of virDomainMigrateToURI3.
 *
 * Returns 0 if the migration succeeded, -1 upon error.
 */
int
virDomainMigrateToURI(virDomainPtr domain,
                      const char *duri,
                      unsigned long flags,
                      const char *dname,
                      unsigned long bandwidth)
{
    const char *dconnuri = NULL;
    const char *miguri = NULL;

    VIR_DOMAIN_DEBUG(domain, "duri=%p, flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(duri), flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);
    virCheckNonNullArgGoto(duri, error);

    if (virDomainMigrateUnmanagedCheckCompat(domain, flags) < 0)
        goto error;

    if (flags & VIR_MIGRATE_PEER2PEER)
        dconnuri = duri;
    else
        miguri = duri;

    if (virDomainMigrateUnmanaged(domain, NULL, flags,
                                  dname, dconnuri, miguri, bandwidth) < 0)
        goto error;

    return 0;

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainMigrateToURI2:
 * @domain: a domain object
 * @dconnuri: (optional) URI for target libvirtd if @flags includes VIR_MIGRATE_PEER2PEER
 * @miguri: (optional) URI for invoking the migration, not if @flags includs VIR_MIGRATE_TUNNELLED
 * @dxml: (optional) XML config for launching guest on target
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
 *
 * Migrate the domain object from its current host to the destination
 * host given by @dconnuri.
 *
 * This function is similar to virDomainMigrateToURI3, but it only supports a
 * fixed set of parameters: @miguri corresponds to VIR_MIGRATE_PARAM_URI, @dxml
 * is VIR_MIGRATE_PARAM_DEST_XML, @dname is VIR_MIGRATE_PARAM_DEST_NAME, and
 * @bandwidth corresponds to VIR_MIGRATE_PARAM_BANDWIDTH.
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 *
 * If the VIR_MIGRATE_PEER2PEER flag IS set, the @dconnuri parameter must be a
 * valid libvirt connection URI, by which the source libvirt driver can connect
 * to the destination libvirt. In other words, @dconnuri has the same semantics
 * as in virDomainMigrateToURI3.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, the @dconnuri must be NULL
 * and the @miguri parameter takes a hypervisor specific URI used to initiate
 * the migration. In this case @miguri corresponds to VIR_MIGRATE_PARAM_URI of
 * virDomainMigrateToURI3.
 *
 * Returns 0 if the migration succeeded, -1 upon error.
 */
int
virDomainMigrateToURI2(virDomainPtr domain,
                       const char *dconnuri,
                       const char *miguri,
                       const char *dxml,
                       unsigned long flags,
                       const char *dname,
                       unsigned long bandwidth)
{
    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, miguri=%s, dxml=%s, "
                     "flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(dconnuri), NULLSTR(miguri), NULLSTR(dxml),
                     flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    if (virDomainMigrateUnmanagedCheckCompat(domain, flags) < 0)
        goto error;

    if (flags & VIR_MIGRATE_PEER2PEER)
        virCheckNonNullArgGoto(dconnuri, error);
    else
        dconnuri = NULL;

    if (virDomainMigrateUnmanaged(domain, dxml, flags,
                                  dname, dconnuri, miguri, bandwidth) < 0)
        goto error;

    return 0;

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainMigrateToURI3:
 * @domain: a domain object
 * @dconnuri: (optional) URI for target libvirtd if @flags includes VIR_MIGRATE_PEER2PEER
 * @params: (optional) migration parameters
 * @nparams: (optional) number of migration parameters in @params
 * @flags: bitwise-OR of virDomainMigrateFlags
 *
 * Migrate the domain object from its current host to the destination host
 * given by URI.
 *
 * See VIR_MIGRATE_PARAM_* and virDomainMigrateFlags for detailed description
 * of accepted migration parameters and flags.
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is set, the @dconnuri parameter must be a
 * valid libvirt connection URI, by which the source libvirt daemon can connect
 * to the destination libvirt.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, then @dconnuri must be NULL
 * and VIR_MIGRATE_PARAM_URI migration parameter must be filled in with
 * hypervisor specific URI used to initiate the migration. The uri_transports
 * element of the hypervisor capabilities XML includes supported URI schemes.
 * This is called "direct" migration. Not all hypervisors support this mode of
 * migration, so if the VIR_MIGRATE_PEER2PEER flag is not set, then it may be
 * necessary to use the alternative virDomainMigrate3 API providing an explicit
 * virConnectPtr for the destination host.
 *
 * There are many limitations on migration imposed by the underlying
 * technology - for example it may not be possible to migrate between
 * different processors even with the same architecture, or between
 * different types of hypervisor.
 *
 * Returns 0 if the migration succeeded, -1 upon error.
 */
int
virDomainMigrateToURI3(virDomainPtr domain,
                       const char *dconnuri,
                       virTypedParameterPtr params,
                       unsigned int nparams,
                       unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, params=%p, nparms=%u flags=%x",
                     NULLSTR(dconnuri), params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    /* First checkout the source */
    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    if (virDomainMigrateUnmanagedCheckCompat(domain, flags) < 0)
        goto error;

    if (flags & VIR_MIGRATE_PEER2PEER)
        virCheckNonNullArgGoto(dconnuri, error);
    else
        dconnuri = NULL;

    if (virDomainMigrateUnmanagedParams(domain, dconnuri,
                                        params, nparams, flags) < 0)
        goto error;

    return 0;

 error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare(virConnectPtr dconn,
                        char **cookie,
                        int *cookielen,
                        const char *uri_in,
                        char **uri_out,
                        unsigned long flags,
                        const char *dname,
                        unsigned long bandwidth)
{
    VIR_DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p, "
              "flags=%lx, dname=%s, bandwidth=%lu", dconn, cookie, cookielen,
              NULLSTR(uri_in), uri_out, flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    virCheckConnectReturn(dconn, -1);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigratePrepare) {
        int ret;
        ret = dconn->driver->domainMigratePrepare(dconn, cookie, cookielen,
                                                  uri_in, uri_out,
                                                  flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform(virDomainPtr domain,
                        const char *cookie,
                        int cookielen,
                        const char *uri,
                        unsigned long flags,
                        const char *dname,
                        unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cookie=%p, cookielen=%d, uri=%s, flags=%lx, "
                     "dname=%s, bandwidth=%lu", cookie, cookielen, uri, flags,
                     NULLSTR(dname), bandwidth);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigratePerform) {
        int ret;
        ret = conn->driver->domainMigratePerform(domain, cookie, cookielen,
                                                 uri,
                                                 flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish(virConnectPtr dconn,
                       const char *dname,
                       const char *cookie,
                       int cookielen,
                       const char *uri,
                       unsigned long flags)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lx", dconn, NULLSTR(dname), cookie, cookielen,
              NULLSTR(uri), flags);

    virResetLastError();

    virCheckConnectReturn(dconn, NULL);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigrateFinish) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish(dconn, dname,
                                                 cookie, cookielen,
                                                 uri, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare2(virConnectPtr dconn,
                         char **cookie,
                         int *cookielen,
                         const char *uri_in,
                         char **uri_out,
                         unsigned long flags,
                         const char *dname,
                         unsigned long bandwidth,
                         const char *dom_xml)
{
    VIR_DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p,"
              "flags=%lx, dname=%s, bandwidth=%lu, dom_xml=%s", dconn,
              cookie, cookielen, NULLSTR(uri_in), uri_out, flags, NULLSTR(dname),
              bandwidth, NULLSTR(dom_xml));

    virResetLastError();

    virCheckConnectReturn(dconn, -1);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigratePrepare2) {
        int ret;
        ret = dconn->driver->domainMigratePrepare2(dconn, cookie, cookielen,
                                                   uri_in, uri_out,
                                                   flags, dname, bandwidth,
                                                   dom_xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish2(virConnectPtr dconn,
                        const char *dname,
                        const char *cookie,
                        int cookielen,
                        const char *uri,
                        unsigned long flags,
                        int retcode)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lx, retcode=%d", dconn, NULLSTR(dname), cookie,
              cookielen, NULLSTR(uri), flags, retcode);

    virResetLastError();

    virCheckConnectReturn(dconn, NULL);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigrateFinish2) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish2(dconn, dname,
                                                  cookie, cookielen,
                                                  uri, flags,
                                                  retcode);
        if (!ret && !retcode)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel(virConnectPtr conn,
                              virStreamPtr st,
                              unsigned long flags,
                              const char *dname,
                              unsigned long bandwidth,
                              const char *dom_xml)
{
    VIR_DEBUG("conn=%p, stream=%p, flags=%lx, dname=%s, "
              "bandwidth=%lu, dom_xml=%s", conn, st, flags,
              NULLSTR(dname), bandwidth, NULLSTR(dom_xml));

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn != st->conn) {
        virReportInvalidArg(conn, "%s",
                            _("conn must match stream connection"));
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel) {
        int rv = conn->driver->domainMigratePrepareTunnel(conn, st,
                                                          flags, dname,
                                                          bandwidth, dom_xml);
        if (rv < 0)
            goto error;
        return rv;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
char *
virDomainMigrateBegin3(virDomainPtr domain,
                       const char *xmlin,
                       char **cookieout,
                       int *cookieoutlen,
                       unsigned long flags,
                       const char *dname,
                       unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlin=%s cookieout=%p, cookieoutlen=%p, "
                     "flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(xmlin), cookieout, cookieoutlen, flags,
                     NULLSTR(dname), bandwidth);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateBegin3) {
        char *xml;
        xml = conn->driver->domainMigrateBegin3(domain, xmlin,
                                                cookieout, cookieoutlen,
                                                flags, dname, bandwidth);
        VIR_DEBUG("xml %s", NULLSTR(xml));
        if (!xml)
            goto error;
        return xml;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare3(virConnectPtr dconn,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         const char *uri_in,
                         char **uri_out,
                         unsigned long flags,
                         const char *dname,
                         unsigned long bandwidth,
                         const char *dom_xml)
{
    VIR_DEBUG("dconn=%p, cookiein=%p, cookieinlen=%d, cookieout=%p, "
              "cookieoutlen=%p, uri_in=%s, uri_out=%p, flags=%lx, dname=%s, "
              "bandwidth=%lu, dom_xml=%s",
              dconn, cookiein, cookieinlen, cookieout, cookieoutlen, NULLSTR(uri_in),
              uri_out, flags, NULLSTR(dname), bandwidth, NULLSTR(dom_xml));

    virResetLastError();

    virCheckConnectReturn(dconn, -1);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigratePrepare3) {
        int ret;
        ret = dconn->driver->domainMigratePrepare3(dconn,
                                                   cookiein, cookieinlen,
                                                   cookieout, cookieoutlen,
                                                   uri_in, uri_out,
                                                   flags, dname, bandwidth,
                                                   dom_xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel3(virConnectPtr conn,
                               virStreamPtr st,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned long flags,
                               const char *dname,
                               unsigned long bandwidth,
                               const char *dom_xml)
{
    VIR_DEBUG("conn=%p, stream=%p, cookiein=%p, cookieinlen=%d, cookieout=%p, "
              "cookieoutlen=%p, flags=%lx, dname=%s, bandwidth=%lu, "
              "dom_xml=%s",
              conn, st, cookiein, cookieinlen, cookieout, cookieoutlen, flags,
              NULLSTR(dname), bandwidth, NULLSTR(dom_xml));

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn != st->conn) {
        virReportInvalidArg(conn, "%s",
                            _("conn must match stream connection"));
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel3) {
        int rv = conn->driver->domainMigratePrepareTunnel3(conn, st,
                                                           cookiein, cookieinlen,
                                                           cookieout, cookieoutlen,
                                                           flags, dname,
                                                           bandwidth, dom_xml);
        if (rv < 0)
            goto error;
        return rv;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform3(virDomainPtr domain,
                         const char *xmlin,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         const char *dconnuri,
                         const char *uri,
                         unsigned long flags,
                         const char *dname,
                         unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlin=%s cookiein=%p, cookieinlen=%d, "
                     "cookieout=%p, cookieoutlen=%p, dconnuri=%s, "
                     "uri=%s, flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(xmlin), cookiein, cookieinlen,
                     cookieout, cookieoutlen, NULLSTR(dconnuri),
                     NULLSTR(uri), flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigratePerform3) {
        int ret;
        ret = conn->driver->domainMigratePerform3(domain, xmlin,
                                                  cookiein, cookieinlen,
                                                  cookieout, cookieoutlen,
                                                  dconnuri, uri,
                                                  flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish3(virConnectPtr dconn,
                        const char *dname,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        const char *dconnuri,
                        const char *uri,
                        unsigned long flags,
                        int cancelled)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookiein=%p, cookieinlen=%d, cookieout=%p,"
              "cookieoutlen=%p, dconnuri=%s, uri=%s, flags=%lx, retcode=%d",
              dconn, NULLSTR(dname), cookiein, cookieinlen, cookieout,
              cookieoutlen, NULLSTR(dconnuri), NULLSTR(uri), flags, cancelled);

    virResetLastError();

    virCheckConnectReturn(dconn, NULL);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigrateFinish3) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish3(dconn, dname,
                                                  cookiein, cookieinlen,
                                                  cookieout, cookieoutlen,
                                                  dconnuri, uri, flags,
                                                  cancelled);
        if (!ret && !cancelled)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigrateConfirm3(virDomainPtr domain,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned long flags,
                         int cancelled)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "cookiein=%p, cookieinlen=%d, flags=%lx, cancelled=%d",
                     cookiein, cookieinlen, flags, cancelled);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateConfirm3) {
        int ret;
        ret = conn->driver->domainMigrateConfirm3(domain,
                                                  cookiein, cookieinlen,
                                                  flags, cancelled);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
char *
virDomainMigrateBegin3Params(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int nparams,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, "
                     "cookieout=%p, cookieoutlen=%p, flags=%x",
                     params, nparams, cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateBegin3Params) {
        char *xml;
        xml = conn->driver->domainMigrateBegin3Params(domain, params, nparams,
                                                      cookieout, cookieoutlen,
                                                      flags);
        VIR_DEBUG("xml %s", NULLSTR(xml));
        if (!xml)
            goto error;
        return xml;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare3Params(virConnectPtr dconn,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               char **uri_out,
                               unsigned int flags)
{
    VIR_DEBUG("dconn=%p, params=%p, nparams=%d, cookiein=%p, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_out=%p, flags=%x",
              dconn, params, nparams, cookiein, cookieinlen,
              cookieout, cookieoutlen, uri_out, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckConnectReturn(dconn, -1);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigratePrepare3Params) {
        int ret;
        ret = dconn->driver->domainMigratePrepare3Params(dconn, params, nparams,
                                                         cookiein, cookieinlen,
                                                         cookieout, cookieoutlen,
                                                         uri_out, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel3Params(virConnectPtr conn,
                                     virStreamPtr st,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     unsigned int flags)
{
    VIR_DEBUG("conn=%p, stream=%p, params=%p, nparams=%d, cookiein=%p, "
              "cookieinlen=%d, cookieout=%p, cookieoutlen=%p, flags=%x",
              conn, st, params, nparams, cookiein, cookieinlen,
              cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn != st->conn) {
        virReportInvalidArg(conn, "%s",
                            _("conn must match stream connection"));
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel3Params) {
        int rv;
        rv = conn->driver->domainMigratePrepareTunnel3Params(
                conn, st, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags);
        if (rv < 0)
            goto error;
        return rv;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform3Params(virDomainPtr domain,
                               const char *dconnuri,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, params=%p, nparams=%d, cookiein=%p, "
                     "cookieinlen=%d, cookieout=%p, cookieoutlen=%p, flags=%x",
                     NULLSTR(dconnuri), params, nparams, cookiein,
                     cookieinlen, cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigratePerform3Params) {
        int ret;
        ret = conn->driver->domainMigratePerform3Params(
                domain, dconnuri, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish3Params(virConnectPtr dconn,
                              virTypedParameterPtr params,
                              int nparams,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags,
                              int cancelled)
{
    VIR_DEBUG("dconn=%p, params=%p, nparams=%d, cookiein=%p, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%x, cancelled=%d",
              dconn, params, nparams, cookiein, cookieinlen, cookieout,
              cookieoutlen, flags, cancelled);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckConnectReturn(dconn, NULL);
    virCheckReadOnlyGoto(dconn->flags, error);

    if (dconn->driver->domainMigrateFinish3Params) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish3Params(
                dconn, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags, cancelled);
        if (!ret && !cancelled)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigrateConfirm3Params(virDomainPtr domain,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               unsigned int flags,
                               int cancelled)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, cookiein=%p, "
                     "cookieinlen=%d, flags=%x, cancelled=%d",
                     params, nparams, cookiein, cookieinlen, flags, cancelled);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateConfirm3Params) {
        int ret;
        ret = conn->driver->domainMigrateConfirm3Params(
                domain, params, nparams,
                cookiein, cookieinlen, flags, cancelled);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetSchedulerType:
 * @domain: pointer to domain object
 * @nparams: pointer to number of scheduler parameters, can be NULL
 *           (return value)
 *
 * Get the scheduler type and the number of scheduler parameters.
 *
 * Returns NULL in case of error. The caller must free the returned string.
 */
char *
virDomainGetSchedulerType(virDomainPtr domain, int *nparams)
{
    virConnectPtr conn;
    char *schedtype;

    VIR_DOMAIN_DEBUG(domain, "nparams=%p", nparams);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerType) {
        schedtype = conn->driver->domainGetSchedulerType(domain, nparams);
        if (!schedtype)
            goto error;
        return schedtype;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainGetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 *          (return value)
 * @nparams: pointer to number of scheduler parameter objects
 *          (this value should generally be as large as the returned value
 *           nparams of virDomainGetSchedulerType()); input and output
 *
 * Get all scheduler parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.  @nparams cannot be 0.
 *
 * It is hypervisor specific whether this returns the live or
 * persistent state; for more control, use
 * virDomainGetSchedulerParametersFlags().
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int *nparams)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p", params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckPositiveArgGoto(*nparams, error);

    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainGetSchedulerParameters(domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetSchedulerParametersFlags:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter object
 *          (return value)
 * @nparams: pointer to number of scheduler parameter
 *          (this value should be same than the returned value
 *           nparams of virDomainGetSchedulerType()); input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all scheduler parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.  @nparams cannot be 0.
 *
 * The value of @flags can be exactly VIR_DOMAIN_AFFECT_CURRENT,
 * VIR_DOMAIN_AFFECT_LIVE, or VIR_DOMAIN_AFFECT_CONFIG.
 *
 * Here is a sample code snippet:
 *
 *   char *ret = virDomainGetSchedulerType(dom, &nparams);
 *   if (ret && nparams != 0) {
 *       if ((params = malloc(sizeof(*params) * nparams)) == NULL)
 *           goto error;
 *       memset(params, 0, sizeof(*params) * nparams);
 *       if (virDomainGetSchedulerParametersFlags(dom, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params, int *nparams,
                                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p, flags=%x",
                     params, nparams, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckPositiveArgGoto(*nparams, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParametersFlags) {
        int ret;
        ret = conn->driver->domainGetSchedulerParametersFlags(domain, params,
                                                              nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned value
 *           nparams of virDomainGetSchedulerType)
 *
 * Change all or a subset or the scheduler parameters.  It is
 * hypervisor-specific whether this sets live, persistent, or both
 * settings; for more control, use
 * virDomainSetSchedulerParametersFlags.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int nparams)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d", params, nparams);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainSetSchedulerParameters(domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetSchedulerParametersFlags:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned value
 *           nparams of virDomainGetSchedulerType)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change a subset or all scheduler parameters.  The value of @flags
 * should be either VIR_DOMAIN_AFFECT_CURRENT, or a bitwise-or of
 * values from VIR_DOMAIN_AFFECT_LIVE and
 * VIR_DOMAIN_AFFECT_CURRENT, although hypervisors vary in which
 * flags are supported.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetSchedulerParametersFlags) {
        int ret;
        ret = conn->driver->domainSetSchedulerParametersFlags(domain,
                                                              params,
                                                              nparams,
                                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainBlockStats:
 * @dom: pointer to the domain object
 * @disk: path to the block device, or device shorthand
 * @stats: block device stats (returned)
 * @size: size of stats structure
 *
 * This function returns block device (disk) stats for block
 * devices attached to the domain.
 *
 * The @disk parameter is either the device target shorthand (the
 * <target dev='...'/> sub-element, such as "vda"), or (since 0.9.8)
 * an unambiguous source name of the block device (the <source
 * file='...'/> sub-element, such as "/path/to/image").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk. Some drivers might also
 * accept the empty string for the @disk parameter, and then yield
 * summary stats for the entire domain.
 *
 * Domains may have more than one block device.  To get stats for
 * each you should make multiple calls to this function.
 *
 * Individual fields within the stats structure may be returned
 * as -1, which indicates that the hypervisor does not support
 * that particular statistic.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockStats(virDomainPtr dom, const char *disk,
                    virDomainBlockStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    virDomainBlockStatsStruct stats2 = { -1, -1, -1, -1, -1 };

    VIR_DOMAIN_DEBUG(dom, "disk=%s, stats=%p, size=%zi", disk, stats, size);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(stats, error);
    if (size > sizeof(stats2)) {
        virReportInvalidArg(size,
                            _("size must not exceed %zu"),
                            sizeof(stats2));
        goto error;
    }
    conn = dom->conn;

    if (conn->driver->domainBlockStats) {
        if (conn->driver->domainBlockStats(dom, disk, &stats2) == -1)
            goto error;

        memcpy(stats, &stats2, size);
        return 0;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockStatsFlags:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: pointer to block stats parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of block stats; input and output
 * @flags: bitwise-OR of virTypedParameterFlags
 *
 * This function is to get block stats parameters for block
 * devices attached to the domain.
 *
 * The @disk parameter is either the device target shorthand (the
 * <target dev='...'/> sub-element, such as "vda"), or (since 0.9.8)
 * an unambiguous source name of the block device (the <source
 * file='...'/> sub-element, such as "/path/to/image").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk. Some drivers might also
 * accept the empty string for the @disk parameter, and then yield
 * summary stats for the entire domain.
 *
 * Domains may have more than one block device.  To get stats for
 * each you should make multiple calls to this function.
 *
 * On input, @nparams gives the size of the @params array; on output,
 * @nparams gives how many slots were filled with parameter
 * information, which might be less but will not exceed the input
 * value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. (Note that block devices of different types
 * might support different parameters, so it might be necessary to compute
 * @nparams for each block device). The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again. See virDomainGetMemoryParameters() for more details.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainBlockStatsFlags(virDomainPtr dom,
                         const char *disk,
                         virTypedParameterPtr params,
                         int *nparams,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     disk, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;
    conn = dom->conn;

    if (conn->driver->domainBlockStatsFlags) {
        int ret;
        ret = conn->driver->domainBlockStatsFlags(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainInterfaceStats:
 * @dom: pointer to the domain object
 * @path: path to the interface
 * @stats: network interface stats (returned)
 * @size: size of stats structure
 *
 * This function returns network interface stats for interfaces
 * attached to the domain.
 *
 * The path parameter is the name of the network interface.
 *
 * Domains may have more than one network interface.  To get stats for
 * each you should make multiple calls to this function.
 *
 * Individual fields within the stats structure may be returned
 * as -1, which indicates that the hypervisor does not support
 * that particular statistic.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainInterfaceStats(virDomainPtr dom, const char *path,
                        virDomainInterfaceStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    virDomainInterfaceStatsStruct stats2 = { -1, -1, -1, -1,
                                             -1, -1, -1, -1 };

    VIR_DOMAIN_DEBUG(dom, "path=%s, stats=%p, size=%zi",
                     path, stats, size);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckNonNullArgGoto(path, error);
    virCheckNonNullArgGoto(stats, error);
    if (size > sizeof(stats2)) {
        virReportInvalidArg(size,
                            _("size must not exceed %zu"),
                            sizeof(stats2));
        goto error;
    }

    conn = dom->conn;

    if (conn->driver->domainInterfaceStats) {
        if (conn->driver->domainInterfaceStats(dom, path, &stats2) == -1)
            goto error;

        memcpy(stats, &stats2, size);
        return 0;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainSetInterfaceParameters:
 * @domain: pointer to domain object
 * @device: the interface name or mac address
 * @params: pointer to interface parameter objects
 * @nparams: number of interface parameter (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change a subset or all parameters of interface; currently this
 * includes bandwidth parameters.  The value of @flags should be
 * either VIR_DOMAIN_AFFECT_CURRENT, or a bitwise-or of values
 * VIR_DOMAIN_AFFECT_LIVE and VIR_DOMAIN_AFFECT_CONFIG, although
 * hypervisors vary in which flags are supported.
 *
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetInterfaceParameters(virDomainPtr domain,
                                const char *device,
                                virTypedParameterPtr params,
                                int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "device=%s, params=%p, nparams=%d, flags=%x",
                     device, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetInterfaceParameters) {
        int ret;
        ret = conn->driver->domainSetInterfaceParameters(domain, device,
                                                         params, nparams,
                                                         flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetInterfaceParameters:
 * @domain: pointer to domain object
 * @device: the interface name or mac address
 * @params: pointer to interface parameter objects
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of interface parameter; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all interface parameters. On input, @nparams gives the size of
 * the @params array; on output, @nparams gives how many slots were
 * filled with parameter information, which might be less but will not
 * exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the
 * API again. See virDomainGetMemoryParameters() for an equivalent usage
 * example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetInterfaceParameters(virDomainPtr domain,
                                const char *device,
                                virTypedParameterPtr params,
                                int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "device=%s, params=%p, nparams=%d, flags=%x",
                     device, params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    conn = domain->conn;

    if (conn->driver->domainGetInterfaceParameters) {
        int ret;
        ret = conn->driver->domainGetInterfaceParameters(domain, device,
                                                         params, nparams,
                                                         flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainMemoryStats:
 * @dom: pointer to the domain object
 * @stats: nr_stats-sized array of stat structures (returned)
 * @nr_stats: number of memory statistics requested
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function provides memory statistics for the domain.
 *
 * Up to 'nr_stats' elements of 'stats' will be populated with memory statistics
 * from the domain.  Only statistics supported by the domain, the driver, and
 * this version of libvirt will be returned.
 *
 * Memory Statistics:
 *
 * VIR_DOMAIN_MEMORY_STAT_SWAP_IN:
 *     The total amount of data read from swap space (in kb).
 * VIR_DOMAIN_MEMORY_STAT_SWAP_OUT:
 *     The total amount of memory written out to swap space (in kb).
 * VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT:
 *     The number of page faults that required disk IO to service.
 * VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT:
 *     The number of page faults serviced without disk IO.
 * VIR_DOMAIN_MEMORY_STAT_UNUSED:
 *     The amount of memory which is not being used for any purpose (in kb).
 * VIR_DOMAIN_MEMORY_STAT_AVAILABLE:
 *     The total amount of memory available to the domain's OS (in kb).
 * VIR_DOMAIN_MEMORY_STAT_USABLE:
 *     How much the balloon can be inflated without pushing the guest system
 *     to swap, corresponds to 'Available' in /proc/meminfo
 * VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON:
 *     Current balloon value (in kb).
 * VIR_DOMAIN_MEMORY_STAT_LAST_UPDATE
 *     Timestamp of the last statistic
 *
 * Returns: The number of stats provided or -1 in case of failure.
 */
int
virDomainMemoryStats(virDomainPtr dom, virDomainMemoryStatPtr stats,
                     unsigned int nr_stats, unsigned int flags)
{
    virConnectPtr conn;
    unsigned long nr_stats_ret = 0;

    VIR_DOMAIN_DEBUG(dom, "stats=%p, nr_stats=%u, flags=%x",
                     stats, nr_stats, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (!stats || nr_stats == 0)
        return 0;

    if (nr_stats > VIR_DOMAIN_MEMORY_STAT_NR)
        nr_stats = VIR_DOMAIN_MEMORY_STAT_NR;

    conn = dom->conn;
    if (conn->driver->domainMemoryStats) {
        nr_stats_ret = conn->driver->domainMemoryStats(dom, stats, nr_stats,
                                                       flags);
        if (nr_stats_ret == -1)
            goto error;
        return nr_stats_ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockPeek:
 * @dom: pointer to the domain object
 * @disk: path to the block device, or device shorthand
 * @offset: offset within block device
 * @size: size to read
 * @buffer: return buffer (must be at least size bytes)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function allows you to read the contents of a domain's
 * disk device.
 *
 * Typical uses for this are to determine if the domain has
 * written a Master Boot Record (indicating that the domain
 * has completed installation), or to try to work out the state
 * of the domain's filesystems.
 *
 * (Note that in the local case you might try to open the
 * block device or file directly, but that won't work in the
 * remote case, nor if you don't have sufficient permission.
 * Hence the need for this call).
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * 'offset' and 'size' represent an area which must lie entirely
 * within the device or file.  'size' may be 0 to test if the
 * call would succeed.
 *
 * 'buffer' is the return buffer and must be at least 'size' bytes.
 *
 * NB. The remote driver imposes a 64K byte limit on 'size'.
 * For your program to be able to work reliably over a remote
 * connection you should split large requests to <= 65536 bytes.
 * However, with 0.9.13 this RPC limit has been raised to 1M byte.
 * Starting with version 1.0.6 the RPC limit has been raised again.
 * Now large requests up to 16M byte are supported.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockPeek(virDomainPtr dom,
                   const char *disk,
                   unsigned long long offset /* really 64 bits */,
                   size_t size,
                   void *buffer,
                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, offset=%lld, size=%zi, buffer=%p, flags=%x",
                     disk, offset, size, buffer, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonEmptyStringArgGoto(disk, error);

    /* Allow size == 0 as an access test. */
    if (size > 0)
        virCheckNonNullArgGoto(buffer, error);

    if (conn->driver->domainBlockPeek) {
        int ret;
        ret = conn->driver->domainBlockPeek(dom, disk, offset, size,
                                            buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockResize:
 * @dom: pointer to the domain object
 * @disk: path to the block image, or shorthand
 * @size: new size of the block image, see below for unit
 * @flags: bitwise-OR of virDomainBlockResizeFlags
 *
 * Resize a block device of domain while the domain is running.  If
 * @flags is 0, then @size is in kibibytes (blocks of 1024 bytes);
 * since 0.9.11, if @flags includes VIR_DOMAIN_BLOCK_RESIZE_BYTES,
 * @size is in bytes instead.  @size is taken directly as the new
 * size.  Depending on the file format, the hypervisor may round up
 * to the next alignment boundary.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it; this call requires privileged access to the
 * hypervisor.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockResize(virDomainPtr dom,
                     const char *disk,
                     unsigned long long size,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, size=%llu, flags=%x", disk, size, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockResize) {
        int ret;
        ret = conn->driver->domainBlockResize(dom, disk, size, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainMemoryPeek:
 * @dom: pointer to the domain object
 * @start: start of memory to peek
 * @size: size of memory to peek
 * @buffer: return buffer (must be at least size bytes)
 * @flags: bitwise-OR of virDomainMemoryFlags
 *
 * This function allows you to read the contents of a domain's
 * memory.
 *
 * The memory which is read is controlled by the 'start', 'size'
 * and 'flags' parameters.
 *
 * If 'flags' is VIR_MEMORY_VIRTUAL then the 'start' and 'size'
 * parameters are interpreted as virtual memory addresses for
 * whichever task happens to be running on the domain at the
 * moment.  Although this sounds haphazard it is in fact what
 * you want in order to read Linux kernel state, because it
 * ensures that pointers in the kernel image can be interpreted
 * coherently.
 *
 * 'buffer' is the return buffer and must be at least 'size' bytes.
 * 'size' may be 0 to test if the call would succeed.
 *
 * NB. The remote driver imposes a 64K byte limit on 'size'.
 * For your program to be able to work reliably over a remote
 * connection you should split large requests to <= 65536 bytes.
 * However, with 0.9.13 this RPC limit has been raised to 1M byte.
 * Starting with version 1.0.6 the RPC limit has been raised again.
 * Now large requests up to 16M byte are supported.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainMemoryPeek(virDomainPtr dom,
                    unsigned long long start /* really 64 bits */,
                    size_t size,
                    void *buffer,
                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "start=%lld, size=%zi, buffer=%p, flags=%x",
                     start, size, buffer, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    /* Note on access to physical memory: A VIR_MEMORY_PHYSICAL flag is
     * a possibility.  However it isn't really useful unless the caller
     * can also access registers, particularly CR3 on x86 in order to
     * get the Page Table Directory.  Since registers are different on
     * every architecture, that would imply another call to get the
     * machine registers.
     *
     * The QEMU driver handles VIR_MEMORY_VIRTUAL, mapping it
     * to the qemu 'memsave' command which does the virtual to physical
     * mapping inside qemu.
     *
     * The QEMU driver also handles VIR_MEMORY_PHYSICAL, mapping it
     * to the qemu 'pmemsave' command.
     *
     * At time of writing there is no Xen driver.  However the Xen
     * hypervisor only lets you map physical pages from other domains,
     * and so the Xen driver would have to do the virtual to physical
     * mapping by chasing 2, 3 or 4-level page tables from the PTD.
     * There is example code in libxc (xc_translate_foreign_address)
     * which does this, although we cannot copy this code directly
     * because of incompatible licensing.
     */

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_MEMORY_VIRTUAL, VIR_MEMORY_PHYSICAL, error);

    /* Allow size == 0 as an access test. */
    if (size > 0)
        virCheckNonNullArgGoto(buffer, error);

    if (conn->driver->domainMemoryPeek) {
        int ret;
        ret = conn->driver->domainMemoryPeek(dom, start, size,
                                             buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetBlockInfo:
 * @domain: a domain object
 * @disk: path to the block device, or device shorthand
 * @info: pointer to a virDomainBlockInfo structure allocated by the user
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract information about a domain's block device.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * For QEMU domains, the allocation and physical virDomainBlockInfo
 * values returned will generally be the same, except when using a
 * non raw, block backing device, such as qcow2 for an active domain.
 * When the persistent domain is not active, QEMU will return the
 * default which is the same value for allocation and physical.
 *
 * Active QEMU domains can return an allocation value which is more
 * representative of the currently used blocks by the device compared
 * to the physical size of the device. Applications can use/monitor
 * the allocation value with the understanding that if the domain
 * becomes inactive during an attempt to get the value, the default
 * values will be returned. Thus, the application should check
 * after the call for the domain being inactive if the values are
 * the same. Optionally, the application could be watching for a
 * shutdown event and then ignore any values received afterwards.
 * This can be an issue when a domain is being migrated and the
 * exact timing of the domain being made inactive and check of
 * the allocation value results the default being returned. For
 * a transient domain in the similar situation, this call will return
 * -1 and an error message indicating the "domain is not running".
 *
 * The following is some pseudo code illustrating the call sequence:
 *
 *   ...
 *   virDomainPtr dom;
 *   virDomainBlockInfo info;
 *   char *device;
 *   ...
 *   // Either get a list of all domains or a specific domain
 *   // via a virDomainLookupBy*() call.
 *   //
 *   // It's also required to fill in the device pointer, but that's
 *   // specific to the implementation. For the purposes of this example
 *   // a qcow2 backed device name string would need to be provided.
 *   ...
 *   // If the following call is made on a persistent domain with a
 *   // qcow2 block backed block device, then it's possible the returned
 *   // allocation equals the physical value. In that case, the domain
 *   // that may have been active prior to calling has become inactive,
 *   // such as is the case during a domain migration. Thus once we
 *   // get data returned, check for active domain when the values are
 *   // the same.
 *   if (virDomainGetBlockInfo(dom, device, &info, 0) < 0)
 *       goto failure;
 *   if (info.allocation == info.physical) {
 *       // If the domain is no longer active,
 *       // then the defaults are being returned.
 *       if (!virDomainIsActive())
 *               goto ignore_return;
 *   }
 *   // Do something with the allocation and physical values
 *   ...
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetBlockInfo(virDomainPtr domain, const char *disk,
                      virDomainBlockInfoPtr info, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, flags=%x", info, flags);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckDomainReturn(domain, -1);
    virCheckNonEmptyStringArgGoto(disk, error);
    virCheckNonNullArgGoto(info, error);

    conn = domain->conn;

    if (conn->driver->domainGetBlockInfo) {
        int ret;
        ret = conn->driver->domainGetBlockInfo(domain, disk, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the domain, preferably in UTF-8
 *
 * Define a domain, but does not start it.
 * This definition is persistent, until explicitly undefined with
 * virDomainUndefine(). A previous definition for this domain would be
 * overridden if it already exists.
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation on a transient domain with the same id as the
 * domain being defined; in that case, use virDomainBlockJobAbort() to
 * stop the block copy first.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXML(virConnectPtr conn, const char *xml)
{
    VIR_DEBUG("conn=%p, xml=%s", conn, NULLSTR(xml));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->driver->domainDefineXML) {
        virDomainPtr ret;
        ret = conn->driver->domainDefineXML(conn, xml);
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
 * virDomainDefineXMLFlags:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the domain, preferably in UTF-8
 * @flags: bitwise OR of the virDomainDefineFlags constants
 *
 * Defines a domain, but does not start it.
 * This definition is persistent, until explicitly undefined with
 * virDomainUndefine(). A previous definition for this domain would be
 * overridden if it already exists.
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation on a transient domain with the same id as the
 * domain being defined; in that case, use virDomainBlockJobAbort() to
 * stop the block copy first.
 *
 * virDomainFree should be used to free the resources after the
 * domain object is no longer needed.
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s flags=%x", conn, NULLSTR(xml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->driver->domainDefineXMLFlags) {
        virDomainPtr ret;
        ret = conn->driver->domainDefineXMLFlags(conn, xml, flags);
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
 * virDomainUndefine:
 * @domain: pointer to a defined domain
 *
 * Undefine a domain. If the domain is running, it's converted to
 * transient domain, without stopping it. If the domain is inactive,
 * the domain configuration is removed.
 *
 * If the domain has a managed save image (see
 * virDomainHasManagedSaveImage()), or if it is inactive and has any
 * snapshot metadata (see virDomainSnapshotNum()), then the undefine will
 * fail. See virDomainUndefineFlags() for more control.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefine(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainUndefine) {
        int ret;
        ret = conn->driver->domainUndefine(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainUndefineFlags:
 * @domain: pointer to a defined domain
 * @flags: bitwise-OR of supported virDomainUndefineFlagsValues
 *
 * Undefine a domain. If the domain is running, it's converted to
 * transient domain, without stopping it. If the domain is inactive,
 * the domain configuration is removed.
 *
 * If the domain has a managed save image (see virDomainHasManagedSaveImage()),
 * then including VIR_DOMAIN_UNDEFINE_MANAGED_SAVE in @flags will also remove
 * that file, and omitting the flag will cause the undefine process to fail.
 *
 * If the domain is inactive and has any snapshot metadata (see
 * virDomainSnapshotNum()), then including
 * VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA in @flags will also remove
 * that metadata.  Omitting the flag will cause the undefine of an
 * inactive domain to fail.  Active snapshots will retain snapshot
 * metadata until the (now-transient) domain halts, regardless of
 * whether this flag is present.  On hypervisors where snapshots do
 * not use libvirt metadata, this flag has no effect.
 *
 * If the domain has any nvram specified, then including
 * VIR_DOMAIN_UNDEFINE_NVRAM will also remove that file, and omitting the flag
 * will cause the undefine process to fail.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefineFlags(virDomainPtr domain,
                       unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainUndefineFlags) {
        int ret;
        ret = conn->driver->domainUndefineFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virConnectNumOfDefinedDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of defined but inactive domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDefinedDomains(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectNumOfDefinedDomains) {
        int ret;
        ret = conn->driver->connectNumOfDefinedDomains(conn);
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
 * virConnectListDefinedDomains:
 * @conn: pointer to the hypervisor connection
 * @names: pointer to an array to store the names
 * @maxnames: size of the array
 *
 * list the defined but inactive domains, stores the pointers to the names
 * in @names
 *
 * For active domains, see virConnectListDomains().  For more control over
 * the results, see virConnectListAllDomains().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a domain can be defined between
 * a call to virConnectNumOfDefinedDomains() and this call; you are only
 * guaranteed that all currently defined domains were listed if the return
 * is less than @maxids.  The client must call free() on each returned name.
 */
int
virConnectListDefinedDomains(virConnectPtr conn, char **const names,
                             int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->driver->connectListDefinedDomains) {
        int ret;
        ret = conn->driver->connectListDefinedDomains(conn, names, maxnames);
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
 * virConnectListAllDomains:
 * @conn: Pointer to the hypervisor connection.
 * @domains: Pointer to a variable to store the array containing domain objects
 *           or NULL if the list is not required (just returns number of guests).
 * @flags: bitwise-OR of virConnectListAllDomainsFlags
 *
 * Collect a possibly-filtered list of all domains, and return an allocated
 * array of information for each.  This API solves the race inherent in
 * virConnectListDomains() and virConnectListDefinedDomains().
 *
 * Normally, all domains are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted domains.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a domain, and where all bits
 * within a group describe all possible domains.  Some hypervisors might
 * reject explicit bits from a group where the hypervisor cannot make a
 * distinction (for example, not all hypervisors can tell whether domains
 * have snapshots).  For a group supported by a given hypervisor, the
 * behavior when no bits of a group are set is identical to the behavior
 * when all bits in that group are set.  When setting bits from more than
 * one group, it is possible to select an impossible combination (such
 * as an inactive transient domain), in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_CONNECT_LIST_DOMAINS_ACTIVE (online
 * domains) and VIR_CONNECT_LIST_DOMAINS_INACTIVE (offline domains).
 *
 * The next group of @flags is VIR_CONNECT_LIST_DOMAINS_PERSISTENT (defined
 * domains) and VIR_CONNECT_LIST_DOMAINS_TRANSIENT (running but not defined).
 *
 * The next group of @flags covers various domain states:
 * VIR_CONNECT_LIST_DOMAINS_RUNNING, VIR_CONNECT_LIST_DOMAINS_PAUSED,
 * VIR_CONNECT_LIST_DOMAINS_SHUTOFF, and a catch-all for all other states
 * (such as crashed, this catch-all covers the possibility of adding new
 * states).
 *
 * The remaining groups cover boolean attributes commonly asked about
 * domains; they include VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE and
 * VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE, for filtering based on whether
 * a managed save image exists; VIR_CONNECT_LIST_DOMAINS_AUTOSTART and
 * VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART, for filtering based on autostart;
 * VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT and
 * VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT, for filtering based on whether
 * a domain has snapshots.
 *
 * Example of usage:
 *
 *   virDomainPtr *domains;
 *   size_t i;
 *   int ret;
 *   unsigned int flags = VIR_CONNECT_LIST_DOMAINS_RUNNING |
 *                        VIR_CONNECT_LIST_DOMAINS_PERSISTENT;
 *   ret = virConnectListAllDomains(conn, &domains, flags);
 *   if (ret < 0)
 *       error();
 *   for (i = 0; i < ret; i++) {
 *        do_something_with_domain(domains[i]);
 *        //here or in a separate loop if needed
 *        virDomainFree(domains[i]);
 *   }
 *   free(domains);
 *
 * Returns the number of domains found or -1 and sets domains to NULL in case of
 * error.  On success, the array stored into @domains is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count, to
 * make iteration easier. The caller is responsible for calling virDomainFree()
 * on each array element, then calling free() on @domains.
 */
int
virConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr **domains,
                         unsigned int flags)
{
    VIR_DEBUG("conn=%p, domains=%p, flags=%x", conn, domains, flags);

    virResetLastError();

    if (domains)
        *domains = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectListAllDomains) {
        int ret;
        ret = conn->driver->connectListAllDomains(conn, domains, flags);
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
 * virDomainCreate:
 * @domain: pointer to a defined domain
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.  The domain will be paused only
 * if restoring from managed state created from a paused domain.  For more
 * control, see virDomainCreateWithFlags().
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreate(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreate) {
        int ret;
        ret = conn->driver->domainCreate(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainCreateWithFlags:
 * @domain: pointer to a defined domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, or if the guest domain
 * has a managed save image that requested paused state (see
 * virDomainManagedSave()) the guest domain will be started, but its
 * CPUs will remain paused. The CPUs can later be manually started
 * using virDomainResume().  In all other cases, the guest domain will
 * be running.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * If the VIR_DOMAIN_START_BYPASS_CACHE flag is set, and there is a
 * managed save file for this domain (created by virDomainManagedSave()),
 * then libvirt will attempt to bypass the file system cache while restoring
 * the file, or fail if it cannot do so for the given system; this can allow
 * less pressure on file system cache, but also risks slowing loads from NFS.
 *
 * If the VIR_DOMAIN_START_FORCE_BOOT flag is set, then any managed save
 * file for this domain is discarded, and the domain boots from scratch.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreateWithFlags) {
        int ret;
        ret = conn->driver->domainCreateWithFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainCreateWithFiles:
 * @domain: pointer to a defined domain
 * @nfiles: number of file descriptors passed
 * @files: list of file descriptors passed
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.
 *
 * @files provides an array of file descriptors which will be
 * made available to the 'init' process of the guest. The file
 * handles exposed to the guest will be renumbered to start
 * from 3 (ie immediately following stderr). This is only
 * supported for guests which use container based virtualization
 * technology.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, or if the guest domain
 * has a managed save image that requested paused state (see
 * virDomainManagedSave()) the guest domain will be started, but its
 * CPUs will remain paused. The CPUs can later be manually started
 * using virDomainResume().  In all other cases, the guest domain will
 * be running.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * If the VIR_DOMAIN_START_BYPASS_CACHE flag is set, and there is a
 * managed save file for this domain (created by virDomainManagedSave()),
 * then libvirt will attempt to bypass the file system cache while restoring
 * the file, or fail if it cannot do so for the given system; this can allow
 * less pressure on file system cache, but also risks slowing loads from NFS.
 *
 * If the VIR_DOMAIN_START_FORCE_BOOT flag is set, then any managed save
 * file for this domain is discarded, and the domain boots from scratch.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreateWithFiles(virDomainPtr domain, unsigned int nfiles,
                         int *files, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nfiles=%u, files=%p, flags=%x",
                     nfiles, files, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreateWithFiles) {
        int ret;
        ret = conn->driver->domainCreateWithFiles(domain,
                                                  nfiles, files,
                                                  flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetAutostart:
 * @domain: a domain object
 * @autostart: the value returned
 *
 * Provides a boolean value indicating whether the domain
 * configured to be automatically started when the host
 * machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetAutostart(virDomainPtr domain,
                      int *autostart)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "autostart=%p", autostart);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(autostart, error);

    conn = domain->conn;

    if (conn->driver->domainGetAutostart) {
        int ret;
        ret = conn->driver->domainGetAutostart(domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetAutostart:
 * @domain: a domain object
 * @autostart: whether the domain should be automatically started 0 or 1
 *
 * Configure the domain to be automatically started
 * when the host machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainSetAutostart(virDomainPtr domain,
                      int autostart)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "autostart=%d", autostart);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainSetAutostart) {
        int ret;
        ret = conn->driver->domainSetAutostart(domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainInjectNMI:
 * @domain: pointer to domain object, or NULL for Domain0
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Send NMI to the guest
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainInjectNMI(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainInjectNMI) {
        int ret;
        ret = conn->driver->domainInjectNMI(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSendKey:
 * @domain:    pointer to domain object, or NULL for Domain0
 * @codeset:   the code set of keycodes, from virKeycodeSet
 * @holdtime:  the duration (in milliseconds) that the keys will be held
 * @keycodes:  array of keycodes
 * @nkeycodes: number of keycodes, up to VIR_DOMAIN_SEND_KEY_MAX_KEYS
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Send key(s) to the guest.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSendKey(virDomainPtr domain,
                 unsigned int codeset,
                 unsigned int holdtime,
                 unsigned int *keycodes,
                 int nkeycodes,
                 unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "codeset=%u, holdtime=%u, nkeycodes=%u, flags=%x",
                     codeset, holdtime, nkeycodes, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(keycodes, error);
    virCheckPositiveArgGoto(nkeycodes, error);

    if (nkeycodes > VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
        virReportInvalidArg(nkeycodes,
                            _("nkeycodes must be <= %d"),
                            VIR_DOMAIN_SEND_KEY_MAX_KEYS);
        goto error;
    }

    if (conn->driver->domainSendKey) {
        int ret;
        ret = conn->driver->domainSendKey(domain, codeset, holdtime,
                                          keycodes, nkeycodes, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSendProcessSignal:
 * @domain: pointer to domain object
 * @pid_value: a positive integer process ID, or negative integer process group ID
 * @signum: a signal from the virDomainProcessSignal enum
 * @flags: currently unused, pass 0
 *
 * Send a signal to the designated process in the guest
 *
 * The signal numbers must be taken from the virDomainProcessSignal
 * enum. These will be translated to the corresponding signal
 * number for the guest OS, by the guest agent delivering the
 * signal. If there is no mapping from virDomainProcessSignal to
 * the native OS signals, this API will report an error.
 *
 * If @pid_value is an integer greater than zero, it is
 * treated as a process ID. If @pid_value is an integer
 * less than zero, it is treated as a process group ID.
 * All the @pid_value numbers are from the container/guest
 * namespace. The value zero is not valid.
 *
 * Not all hypervisors will support sending signals to
 * arbitrary processes or process groups. If this API is
 * implemented the minimum requirement is to be able to
 * use @pid_value == 1 (i.e. kill init). No other value is
 * required to be supported.
 *
 * If the @signum is VIR_DOMAIN_PROCESS_SIGNAL_NOP then this
 * API will simply report whether the process is running in
 * the container/guest.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSendProcessSignal(virDomainPtr domain,
                           long long pid_value,
                           unsigned int signum,
                           unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "pid=%lld, signum=%u flags=%x",
                     pid_value, signum, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonZeroArgGoto(pid_value, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainSendProcessSignal) {
        int ret;
        ret = conn->driver->domainSendProcessSignal(domain,
                                                    pid_value,
                                                    signum,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @nvcpus: the new number of virtual CPUs for this domain
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it or if growing the number is arbitrarily limited.
 * This function may require privileged access to the hypervisor.
 *
 * Note that if this call is executed before the guest has finished booting,
 * the guest may fail to process the change.
 *
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.  It is hypervisor-dependent
 * whether it also affects persistent configuration; for more control,
 * use virDomainSetVcpusFlags().
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nvcpus=%u", nvcpus);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(nvcpus, error);

    if (conn->driver->domainSetVcpus) {
        int ret;
        ret = conn->driver->domainSetVcpus(domain, nvcpus);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetVcpusFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @nvcpus: the new number of virtual CPUs for this domain, must be at least 1
 * @flags: bitwise-OR of virDomainVcpuFlags
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it or if growing the number is arbitrarily limited.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE to affect a running
 * domain (which may fail if domain is not active), or
 * VIR_DOMAIN_AFFECT_CONFIG to affect the next boot via the XML
 * description of the domain.  Both flags may be set.
 * If neither flag is specified (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT),
 * then an inactive domain modifies persistent setup, while an active domain
 * is hypervisor-dependent on whether just live or both live and persistent
 * state is changed.
 *
 * Note that if this call is executed before the guest has finished booting,
 * the guest may fail to process the change.
 *
 * If @flags includes VIR_DOMAIN_VCPU_MAXIMUM, then
 * VIR_DOMAIN_AFFECT_LIVE must be clear, and only the maximum virtual
 * CPU limit is altered; generally, this value must be less than or
 * equal to virConnectGetMaxVcpus().  Otherwise, this call affects the
 * current virtual CPU limit, which must be less than or equal to the
 * maximum limit.
 *
 * If @flags includes VIR_DOMAIN_VCPU_GUEST, then the state of processors is
 * modified inside the guest instead of the hypervisor. This flag can only
 * be used with live guests and is incompatible with VIR_DOMAIN_VCPU_MAXIMUM.
 * The usage of this flag may require a guest agent configured.
 *
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainSetVcpusFlags(virDomainPtr domain, unsigned int nvcpus,
                       unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nvcpus=%u, flags=%x", nvcpus, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    VIR_REQUIRE_FLAG_GOTO(VIR_DOMAIN_VCPU_MAXIMUM,
                          VIR_DOMAIN_AFFECT_CONFIG,
                          error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_VCPU_GUEST,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    virCheckNonZeroArgGoto(nvcpus, error);

    conn = domain->conn;

    if (conn->driver->domainSetVcpusFlags) {
        int ret;
        ret = conn->driver->domainSetVcpusFlags(domain, nvcpus, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetVcpusFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @flags: bitwise-OR of virDomainVcpuFlags
 *
 * Query the number of virtual CPUs used by the domain.  Note that
 * this call may fail if the underlying virtualization hypervisor does
 * not support it.  This function may require privileged access to the
 * hypervisor.
 *
 * If @flags includes VIR_DOMAIN_AFFECT_LIVE, this will query a
 * running domain (which will fail if domain is not active); if
 * it includes VIR_DOMAIN_AFFECT_CONFIG, this will query the XML
 * description of the domain.  It is an error to set both flags.
 * If neither flag is set (that is, VIR_DOMAIN_AFFECT_CURRENT),
 * then the configuration queried depends on whether the domain
 * is currently running.
 *
 * If @flags includes VIR_DOMAIN_VCPU_MAXIMUM, then the maximum
 * virtual CPU limit is queried.  Otherwise, this call queries the
 * current virtual CPU count.
 *
 * If @flags includes VIR_DOMAIN_VCPU_GUEST, then the state of the processors
 * is queried in the guest instead of the hypervisor. This flag is only usable
 * on live domains. Guest agent may be needed for this flag to be available.
 *
 * Returns the number of vCPUs in case of success, -1 in case of failure.
 */
int
virDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    if (flags & VIR_DOMAIN_VCPU_GUEST)
        virCheckReadOnlyGoto(conn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    if (conn->driver->domainGetVcpusFlags) {
        int ret;
        ret = conn->driver->domainGetVcpusFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainPinVcpu:
 * @domain: pointer to domain object, or NULL for Domain0
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * This function may require privileged access to the hypervisor.
 *
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                 unsigned char *cpumap, int maplen)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "vcpu=%u, cpumap=%p, maplen=%d",
                     vcpu, cpumap, maplen);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if (conn->driver->domainPinVcpu) {
        int ret;
        ret = conn->driver->domainPinVcpu(domain, vcpu, cpumap, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainPinVcpuFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 * Not all hypervisors can support all flag combinations.
 *
 * See also virDomainGetVcpuPinInfo for querying this information.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 */
int
virDomainPinVcpuFlags(virDomainPtr domain, unsigned int vcpu,
                      unsigned char *cpumap, int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "vcpu=%u, cpumap=%p, maplen=%d, flags=%x",
                     vcpu, cpumap, maplen, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if (conn->driver->domainPinVcpuFlags) {
        int ret;
        ret = conn->driver->domainPinVcpuFlags(domain, vcpu, cpumap, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetVcpuPinInfo:
 * @domain: pointer to domain object, or NULL for Domain0
 * @ncpumaps: the number of cpumap (listed first to match virDomainGetVcpus)
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this
 *     domain (in 8-bit bytes) (OUT)
 *     It's assumed there is <ncpumaps> cpumap in cpumaps array.
 *     The memory allocated to cpumaps must be (ncpumaps * maplen) bytes
 *     (ie: calloc(ncpumaps, maplen)).
 *     One cpumap inside cpumaps has the format described in
 *     virDomainPinVcpu() API.
 *     Must not be NULL.
 * @maplen: the number of bytes in one cpumap, from 1 up to size of CPU map.
 *     Must be positive.
 * @flags: bitwise-OR of virDomainModificationImpact
 *     Must not be VIR_DOMAIN_AFFECT_LIVE and
 *     VIR_DOMAIN_AFFECT_CONFIG concurrently.
 *
 * Query the CPU affinity setting of all virtual CPUs of domain, store it
 * in cpumaps.
 *
 * Returns the number of virtual CPUs in case of success,
 * -1 in case of failure.
 */
int
virDomainGetVcpuPinInfo(virDomainPtr domain, int ncpumaps,
                        unsigned char *cpumaps, int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "ncpumaps=%d, cpumaps=%p, maplen=%d, flags=%x",
                     ncpumaps, cpumaps, maplen, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(cpumaps, error);
    virCheckPositiveArgGoto(ncpumaps, error);
    virCheckPositiveArgGoto(maplen, error);

    if (INT_MULTIPLY_OVERFLOW(ncpumaps, maplen)) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %d * %d"),
                       ncpumaps, maplen);
        goto error;
    }

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    if (conn->driver->domainGetVcpuPinInfo) {
        int ret;
        ret = conn->driver->domainGetVcpuPinInfo(domain, ncpumaps,
                                                 cpumaps, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainPinEmulator:
 * @domain: pointer to domain object, or NULL for Domain0
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically change the real CPUs which can be allocated to all emulator
 * threads. This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 * Not all hypervisors can support all flag combinations.
 *
 * See also virDomainGetEmulatorPinInfo for querying this information.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 */
int
virDomainPinEmulator(virDomainPtr domain, unsigned char *cpumap,
                     int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cpumap=%p, maplen=%d, flags=%x",
                     cpumap, maplen, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if (conn->driver->domainPinEmulator) {
        int ret;
        ret = conn->driver->domainPinEmulator(domain, cpumap, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetEmulatorPinInfo:
 * @domain: pointer to domain object, or NULL for Domain0
 * @cpumap: pointer to a bit map of real CPUs for all emulator threads of
 *     this domain (in 8-bit bytes) (OUT)
 *     There is only one cpumap for all emulator threads.
 *     Must not be NULL.
 * @maplen: the number of bytes in one cpumap, from 1 up to size of CPU map.
 *     Must be positive.
 * @flags: bitwise-OR of virDomainModificationImpact
 *     Must not be VIR_DOMAIN_AFFECT_LIVE and
 *     VIR_DOMAIN_AFFECT_CONFIG concurrently.
 *
 * Query the CPU affinity setting of all emulator threads of domain, store
 * it in cpumap.
 *
 * Returns 1 in case of success,
 * 0 in case of no emulator threads are pined to pcpus,
 * -1 in case of failure.
 */
int
virDomainGetEmulatorPinInfo(virDomainPtr domain, unsigned char *cpumap,
                            int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cpumap=%p, maplen=%d, flags=%x",
                     cpumap, maplen, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    conn = domain->conn;

    if (conn->driver->domainGetEmulatorPinInfo) {
        int ret;
        ret = conn->driver->domainGetEmulatorPinInfo(domain, cpumap,
                                                     maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this
 *      domain (in 8-bit bytes) (OUT)
 *      If cpumaps is NULL, then no cpumap information is returned by the API.
 *      It's assumed there is <maxinfo> cpumap in cpumaps array.
 *      The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *      (ie: calloc(maxinfo, maplen)).
 *      One cpumap inside cpumaps has the format described in
 *      virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      Must be zero when cpumaps is NULL and positive when it is non-NULL.
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer isn't NULL.  This call may fail
 * on an inactive domain.
 *
 * See also virDomainGetVcpuPinInfo for querying just cpumaps, including on
 * an inactive domain.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
virDomainGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
                  unsigned char *cpumaps, int maplen)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, maxinfo=%d, cpumaps=%p, maplen=%d",
                     info, maxinfo, cpumaps, maplen);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(info, error);
    virCheckPositiveArgGoto(maxinfo, error);

    /* Ensure that domainGetVcpus (aka remoteDomainGetVcpus) does not
       try to memcpy anything into a NULL pointer.  */
    if (cpumaps)
        virCheckPositiveArgGoto(maplen, error);
    else
        virCheckZeroArgGoto(maplen, error);

    if (cpumaps && INT_MULTIPLY_OVERFLOW(maxinfo, maplen)) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %d * %d"),
                       maxinfo, maplen);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetVcpus) {
        int ret;
        ret = conn->driver->domainGetVcpus(domain, info, maxinfo,
                                           cpumaps, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetMaxVcpus:
 * @domain: pointer to domain object
 *
 * Provides the maximum number of virtual CPUs supported for
 * the guest VM. If the guest is inactive, this is basically
 * the same as virConnectGetMaxVcpus(). If the guest is running
 * this will reflect the maximum number of virtual CPUs the
 * guest was booted with.  For more details, see virDomainGetVcpusFlags().
 *
 * Returns the maximum of virtual CPU or -1 in case of error.
 */
int
virDomainGetMaxVcpus(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    if (conn->driver->domainGetMaxVcpus) {
        int ret;
        ret = conn->driver->domainGetMaxVcpus(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetIOThreadInfo:
 * @dom: a domain object
 * @info: pointer to an array of virDomainIOThreadInfo structures (OUT)
 * @flags: bitwise-OR of virDomainModificationImpact
 *     Must not be VIR_DOMAIN_AFFECT_LIVE and
 *     VIR_DOMAIN_AFFECT_CONFIG concurrently.
 *
 * Fetch IOThreads of an active domain including the cpumap information to
 * determine on which CPU the IOThread has affinity to run.
 *
 * Returns the number of IOThreads or -1 in case of error.
 * On success, the array of information is stored into @info. The caller is
 * responsible for calling virDomainIOThreadInfoFree() on each array element,
 * then calling free() on @info. On error, @info is set to NULL.
 */
int
virDomainGetIOThreadInfo(virDomainPtr dom,
                         virDomainIOThreadInfoPtr **info,
                         unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "info=%p flags=%x", info, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckNonNullArgGoto(info, error);
    *info = NULL;

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    if (dom->conn->driver->domainGetIOThreadInfo) {
        int ret;
        ret = dom->conn->driver->domainGetIOThreadInfo(dom, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainIOThreadInfoFree:
 * @info: pointer to a virDomainIOThreadInfo object
 *
 * Frees the memory used by @info.
 */
void
virDomainIOThreadInfoFree(virDomainIOThreadInfoPtr info)
{
    if (!info)
        return;

    VIR_FREE(info->cpumap);
    VIR_FREE(info);
}


/**
 * virDomainPinIOThread:
 * @domain: a domain object
 * @iothread_id: the IOThread ID to set the CPU affinity
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically change the real CPUs which can be allocated to an IOThread.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 * Not all hypervisors can support all flag combinations.
 *
 * See also virDomainGetIOThreadInfo for querying this information.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainPinIOThread(virDomainPtr domain,
                     unsigned int iothread_id,
                     unsigned char *cpumap,
                     int maplen,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "iothread_id=%u, cpumap=%p, maplen=%d",
                     iothread_id, cpumap, maplen);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if (conn->driver->domainPinIOThread) {
        int ret;
        ret = conn->driver->domainPinIOThread(domain, iothread_id,
                                              cpumap, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainAddIOThread:
 * @domain: a domain object
 * @iothread_id: the specific IOThread ID value to add
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically add an IOThread to the domain. It is left up to the
 * underlying virtual hypervisor to determine the valid range for an
 * @iothread_id and determining whether the @iothread_id already exists.
 *
 * Note that this call can fail if the underlying virtualization hypervisor
 * does not support it or if growing the number is arbitrarily limited.
 * This function requires privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainAddIOThread(virDomainPtr domain,
                     unsigned int iothread_id,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "iothread_id=%u, flags=%x",
                     iothread_id, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    conn = domain->conn;

    if (conn->driver->domainAddIOThread) {
        int ret;
        ret = conn->driver->domainAddIOThread(domain, iothread_id, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainDelIOThread:
 * @domain: a domain object
 * @iothread_id: the specific IOThread ID value to delete
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically delete an IOThread from the domain. The @iothread_id to be
 * deleted must not have a resource associated with it and can be any of
 * the currently valid IOThread ID's.
 *
 * Note that this call can fail if the underlying virtualization hypervisor
 * does not support it or if reducing the number is arbitrarily limited.
 * This function requires privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDelIOThread(virDomainPtr domain,
                     unsigned int iothread_id,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "iothread_id=%u, flags=%x", iothread_id, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);
    virCheckNonZeroArgGoto(iothread_id, error);

    conn = domain->conn;

    if (conn->driver->domainDelIOThread) {
        int ret;
        ret = conn->driver->domainDelIOThread(domain, iothread_id, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetSecurityLabel:
 * @domain: a domain object
 * @seclabel: pointer to a virSecurityLabel structure
 *
 * Extract security label of an active domain. The 'label' field
 * in the @seclabel argument will be initialized to the empty
 * string if the domain is not running under a security model.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virDomainGetSecurityLabel(virDomainPtr domain, virSecurityLabelPtr seclabel)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "seclabel=%p", seclabel);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(seclabel, error);

    if (conn->driver->domainGetSecurityLabel) {
        int ret;
        ret = conn->driver->domainGetSecurityLabel(domain, seclabel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetSecurityLabelList:
 * @domain: a domain object
 * @seclabels: will be auto-allocated and filled with domains' security labels.
 * Caller must free memory on return.
 *
 * Extract the security labels of an active domain. The 'label' field
 * in the @seclabels argument will be initialized to the empty
 * string if the domain is not running under a security model.
 *
 * Returns number of elemnets in @seclabels on success, -1 in case of failure.
 */
int
virDomainGetSecurityLabelList(virDomainPtr domain,
                              virSecurityLabelPtr* seclabels)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "seclabels=%p", seclabels);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    virCheckNonNullArgGoto(seclabels, error);

    conn = domain->conn;

    if (conn->driver->domainGetSecurityLabelList) {
        int ret;
        ret = conn->driver->domainGetSecurityLabelList(domain, seclabels);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetMetadata:
 * @domain: a domain object
 * @type: type of metadata, from virDomainMetadataType
 * @metadata: new metadata text
 * @key: XML namespace key, or NULL
 * @uri: XML namespace URI, or NULL
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Sets the appropriate domain element given by @type to the
 * value of @metadata.  A @type of VIR_DOMAIN_METADATA_DESCRIPTION
 * is free-form text; VIR_DOMAIN_METADATA_TITLE is free-form, but no
 * newlines are permitted, and should be short (although the length is
 * not enforced). For these two options @key and @uri are irrelevant and
 * must be set to NULL.
 *
 * For type VIR_DOMAIN_METADATA_ELEMENT @metadata  must be well-formed
 * XML belonging to namespace defined by @uri with local name @key.
 *
 * Passing NULL for @metadata says to remove that element from the
 * domain XML (passing the empty string leaves the element present).
 *
 * The resulting metadata will be present in virDomainGetXMLDesc(),
 * as well as quick access through virDomainGetMetadata().
 *
 * @flags controls whether the live domain, persistent configuration,
 * or both will be modified.
 *
 * Returns 0 on success, -1 in case of failure.
 */
int
virDomainSetMetadata(virDomainPtr domain,
                     int type,
                     const char *metadata,
                     const char *key,
                     const char *uri,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "type=%d, metadata='%s', key='%s', uri='%s', flags=%x",
                     type, NULLSTR(metadata), NULLSTR(key), NULLSTR(uri),
                     flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    switch (type) {
    case VIR_DOMAIN_METADATA_TITLE:
        if (metadata && strchr(metadata, '\n')) {
            virReportInvalidArg(metadata, "%s",
                                _("metadata title can't contain "
                                  "newlines"));
            goto error;
        }
        /* fallthrough */
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        virCheckNullArgGoto(key, error);
        break;
    case VIR_DOMAIN_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        if (metadata)
            virCheckNonNullArgGoto(key, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    if (conn->driver->domainSetMetadata) {
        int ret;
        ret = conn->driver->domainSetMetadata(domain, type, metadata, key, uri,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetMetadata:
 * @domain: a domain object
 * @type: type of metadata, from virDomainMetadataType
 * @uri: XML namespace identifier
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Retrieves the appropriate domain element given by @type.
 * If VIR_DOMAIN_METADATA_ELEMENT is requested parameter @uri
 * must be set to the name of the namespace the requested elements
 * belong to, otherwise must be NULL.
 *
 * If an element of the domain XML is not present, the resulting
 * error will be VIR_ERR_NO_DOMAIN_METADATA.  This method forms
 * a shortcut for seeing information from virDomainSetMetadata()
 * without having to go through virDomainGetXMLDesc().
 *
 * @flags controls whether the live domain or persistent
 * configuration will be queried.
 *
 * Returns the metadata string on success (caller must free),
 * or NULL in case of failure.
 */
char *
virDomainGetMetadata(virDomainPtr domain,
                     int type,
                     const char *uri,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "type=%d, uri='%s', flags=%x",
                     type, NULLSTR(uri), flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    switch (type) {
    case VIR_DOMAIN_METADATA_TITLE:
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        break;
    case VIR_DOMAIN_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    conn = domain->conn;

    if (conn->driver->domainGetMetadata) {
        char *ret;
        if (!(ret = conn->driver->domainGetMetadata(domain, type, uri, flags)))
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainAttachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * Create a virtual device attachment to backend.  This function,
 * having hotplug semantics, is only allowed on an active domain.
 *
 * For compatibility, this method can also be used to change the media
 * in an existing CDROM/Floppy device, however, applications are
 * recommended to use the virDomainUpdateDeviceFlag method instead.
 *
 * Be aware that hotplug changes might not persist across a domain going
 * into S4 state (also known as hibernation) unless you also modify the
 * persistent domain definition.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainAttachDevice(virDomainPtr domain, const char *xml)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s", xml);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainAttachDevice) {
       int ret;
       ret = conn->driver->domainAttachDevice(domain, xml);
       if (ret < 0)
          goto error;
       return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainAttachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Attach a virtual device to a domain, using the flags parameter
 * to control how the device is attached.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device allocation is made based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * allocated to the active domain instance only and is not added to the
 * persisted domain configuration.  VIR_DOMAIN_AFFECT_CONFIG
 * specifies that the device shall be allocated to the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports modifying the
 * persisted device allocation.
 *
 * For compatibility, this method can also be used to change the media
 * in an existing CDROM/Floppy device, however, applications are
 * recommended to use the virDomainUpdateDeviceFlag method instead.
 *
 * Be aware that hotplug changes might not persist across a domain going
 * into S4 state (also known as hibernation) unless you also modify the
 * persistent domain definition.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainAttachDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainAttachDeviceFlags) {
        int ret;
        ret = conn->driver->domainAttachDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainDetachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * This is an equivalent of virDomainDetachDeviceFlags() when called with
 * @flags parameter set to VIR_DOMAIN_AFFECT_LIVE.
 *
 * See virDomainDetachDeviceFlags() for more details.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDetachDevice(virDomainPtr domain, const char *xml)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s", xml);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainDetachDevice) {
        int ret;
        ret = conn->driver->domainDetachDevice(domain, xml);
         if (ret < 0)
             goto error;
         return ret;
     }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainDetachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Detach a virtual device from a domain, using the flags parameter
 * to control how the device is detached.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device allocation is removed based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * deallocated from the active domain instance only and is not from the
 * persisted domain configuration.  VIR_DOMAIN_AFFECT_CONFIG
 * specifies that the device shall be deallocated from the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports removing the
 * persisted device allocation.
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation on the device being detached; in that case,
 * use virDomainBlockJobAbort() to stop the block copy first.
 *
 * Beware that depending on the hypervisor and device type, detaching a device
 * from a running domain may be asynchronous. That is, calling
 * virDomainDetachDeviceFlags may just request device removal while the device
 * is actually removed later (in cooperation with a guest OS). Previously,
 * this fact was ignored and the device could have been removed from domain
 * configuration before it was actually removed by the hypervisor causing
 * various failures on subsequent operations. To check whether the device was
 * successfully removed, either recheck domain configuration using
 * virDomainGetXMLDesc() or add a handler for the VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED
 * event. In case the device is already gone when virDomainDetachDeviceFlags
 * returns, the event is delivered before this API call ends. To help existing
 * clients work better in most cases, this API will try to transform an
 * asynchronous device removal that finishes shortly after the request into
 * a synchronous removal. In other words, this API may wait a bit for the
 * removal to complete in case it was not synchronous.
 *
 * Be aware that hotplug changes might not persist across a domain going
 * into S4 state (also known as hibernation) unless you also modify the
 * persistent domain definition.
 *
 * The supplied XML description of the device should be as specific
 * as its definition in the domain XML. The set of attributes used
 * to match the device are internal to the drivers. Using a partial definition,
 * or attempting to detach a device that is not present in the domain XML,
 * but shares some specific attributes with one that is present,
 * may lead to unexpected results.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDetachDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainDetachDeviceFlags) {
        int ret;
        ret = conn->driver->domainDetachDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainUpdateDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Change a virtual device on a domain, using the flags parameter
 * to control how the device is changed.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device change is made based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * changed on the active domain instance only and is not added to the
 * persisted domain configuration. VIR_DOMAIN_AFFECT_CONFIG
 * specifies that the device shall be changed on the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports modifying the
 * persisted device allocation.
 *
 * This method is used for actions such changing CDROM/Floppy device
 * media, altering the graphics configuration such as password,
 * reconfiguring the NIC device backend connectivity, etc.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainUpdateDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(xml, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainUpdateDeviceFlags) {
        int ret;
        ret = conn->driver->domainUpdateDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virConnectDomainEventRegister:
 * @conn: pointer to the connection
 * @cb: callback to the function handling domain events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of domain lifecycle events
 * occurring on a connection.  This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * Use of this method is no longer recommended. Instead applications
 * should try virConnectDomainEventRegisterAny() which has a more flexible
 * API contract.
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback returns,
 * it shall take a reference to it, by calling virDomainRef.
 * The reference can be released once the object is no longer required
 * by calling virDomainFree.
 *
 * Returns 0 on success, -1 on failure.  Older versions of some hypervisors
 * sometimes returned a positive number on success, but without any reliable
 * semantics on what that number represents.
 */
int
virConnectDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback cb,
                              void *opaque,
                              virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p, cb=%p, opaque=%p, freecb=%p", conn, cb, opaque, freecb);
    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(cb, error);

    if (conn->driver && conn->driver->connectDomainEventRegister) {
        int ret;
        ret = conn->driver->connectDomainEventRegister(conn, cb, opaque, freecb);
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
 * virConnectDomainEventDeregister:
 * @conn: pointer to the connection
 * @cb: callback to the function handling domain events
 *
 * Removes a callback previously registered with the
 * virConnectDomainEventRegister() function.
 *
 * Use of this method is no longer recommended. Instead applications
 * should try virConnectDomainEventDeregisterAny() which has a more flexible
 * API contract
 *
 * Returns 0 on success, -1 on failure.  Older versions of some hypervisors
 * sometimes returned a positive number on success, but without any reliable
 * semantics on what that number represents.
 */
int
virConnectDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback cb)
{
    VIR_DEBUG("conn=%p, cb=%p", conn, cb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(cb, error);

    if (conn->driver && conn->driver->connectDomainEventDeregister) {
        int ret;
        ret = conn->driver->connectDomainEventDeregister(conn, cb);
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
 * virDomainIsActive:
 * @dom: pointer to the domain object
 *
 * Determine if the domain is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int
virDomainIsActive(virDomainPtr dom)
{
    VIR_DEBUG("dom=%p", dom);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (dom->conn->driver->domainIsActive) {
        int ret;
        ret = dom->conn->driver->domainIsActive(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainIsPersistent:
 * @dom: pointer to the domain object
 *
 * Determine if the domain has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 */
int
virDomainIsPersistent(virDomainPtr dom)
{
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (dom->conn->driver->domainIsPersistent) {
        int ret;
        ret = dom->conn->driver->domainIsPersistent(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainRename:
 * @dom: pointer to the domain object
 * @new_name: new domain name
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Rename a domain. New domain name is specified in the second
 * argument. Depending on each driver implementation it may be
 * required that domain is in a specific state.
 *
 * There might be some attributes and/or elements in domain XML that if no
 * value provided at XML defining time, libvirt will derive their value from
 * the domain name. These are not updated by this API. Users are strongly
 * advised to change these after the rename was successful.
 *
 * Returns 0 if successfully renamed, -1 on error
 */
int
virDomainRename(virDomainPtr dom,
                const char *new_name,
                unsigned int flags)
{
    VIR_DEBUG("dom=%p, new_name=%s", dom, NULLSTR(new_name));

    virResetLastError();
    virCheckDomainReturn(dom, -1);
    virCheckNonEmptyStringArgGoto(new_name, error);
    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (dom->conn->driver->domainRename) {
        int ret = dom->conn->driver->domainRename(dom, new_name, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainIsUpdated:
 * @dom: pointer to the domain object
 *
 * Determine if the domain has been updated.
 *
 * Returns 1 if updated, 0 if not, -1 on error
 */
int
virDomainIsUpdated(virDomainPtr dom)
{
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (dom->conn->driver->domainIsUpdated) {
        int ret;
        ret = dom->conn->driver->domainIsUpdated(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetJobInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainJobInfo structure allocated by the user
 *
 * Extract information about progress of a background job on a domain.
 * Will return an error if the domain is not active.
 *
 * This function returns a limited amount of information in comparison
 * to virDomainGetJobStats().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetJobInfo(virDomainPtr domain, virDomainJobInfoPtr info)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p", info);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(info, error);

    conn = domain->conn;

    if (conn->driver->domainGetJobInfo) {
        int ret;
        ret = conn->driver->domainGetJobInfo(domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetJobStats:
 * @domain: a domain object
 * @type: where to store the job type (one of virDomainJobType)
 * @params: where to store job statistics
 * @nparams: number of items in @params
 * @flags: bitwise-OR of virDomainGetJobStatsFlags
 *
 * Extract information about progress of a background job on a domain.
 * Will return an error if the domain is not active. The function returns
 * a superset of progress information provided by virDomainGetJobInfo.
 * Possible fields returned in @params are defined by VIR_DOMAIN_JOB_*
 * macros and new fields will likely be introduced in the future so callers
 * may receive fields that they do not understand in case they talk to a
 * newer server.
 *
 * When @flags contains VIR_DOMAIN_JOB_STATS_COMPLETED, the function will
 * return statistics about a recently completed job. Specifically, this
 * flag may be used to query statistics of a completed incoming pre-copy
 * migration (statistics for post-copy migration are only available on the
 * source hsot). Statistics of a completed job are automatically destroyed
 * once read or when libvirtd is restarted. Note that time information
 * returned for completed migrations may be completely irrelevant unless both
 * source and destination hosts have synchronized time (i.e., NTP daemon is
 * running on both of them). The statistics of a completed job can also be
 * obtained by listening to a VIR_DOMAIN_EVENT_ID_JOB_COMPLETED event (on the
 * source host in case of a migration job).
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetJobStats(virDomainPtr domain,
                     int *type,
                     virTypedParameterPtr *params,
                     int *nparams,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "type=%p, params=%p, nparams=%p, flags=%x",
                     type, params, nparams, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(type, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);

    conn = domain->conn;

    if (conn->driver->domainGetJobStats) {
        int ret;
        ret = conn->driver->domainGetJobStats(domain, type, params,
                                              nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainAbortJob:
 * @domain: a domain object
 *
 * Requests that the current background job be aborted at the
 * soonest opportunity.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainAbortJob(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainAbortJob) {
        int ret;
        ret = conn->driver->domainAbortJob(domain);
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
 * virDomainMigrateSetMaxDowntime:
 * @domain: a domain object
 * @downtime: maximum tolerable downtime for live migration, in milliseconds
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Sets maximum tolerable time for which the domain is allowed to be paused
 * at the end of live migration. It's supposed to be called while the domain is
 * being live-migrated as a reaction to migration progress.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetMaxDowntime(virDomainPtr domain,
                               unsigned long long downtime,
                               unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "downtime=%llu, flags=%x", downtime, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateSetMaxDowntime) {
        if (conn->driver->domainMigrateSetMaxDowntime(domain, downtime, flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateGetCompressionCache:
 * @domain: a domain object
 * @cacheSize: return value of current size of the cache (in bytes)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Gets current size of the cache (in bytes) used for compressing repeatedly
 * transferred memory pages during live migration.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateGetCompressionCache(virDomainPtr domain,
                                    unsigned long long *cacheSize,
                                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cacheSize=%p, flags=%x", cacheSize, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(cacheSize, error);

    if (conn->driver->domainMigrateGetCompressionCache) {
        if (conn->driver->domainMigrateGetCompressionCache(domain, cacheSize,
                                                           flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateSetCompressionCache:
 * @domain: a domain object
 * @cacheSize: size of the cache (in bytes) used for compression
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Sets size of the cache (in bytes) used for compressing repeatedly
 * transferred memory pages during live migration. It's supposed to be called
 * while the domain is being live-migrated as a reaction to migration progress
 * and increasing number of compression cache misses obtained from
 * virDomainGetJobStats.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetCompressionCache(virDomainPtr domain,
                                    unsigned long long cacheSize,
                                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cacheSize=%llu, flags=%x", cacheSize, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateSetCompressionCache) {
        if (conn->driver->domainMigrateSetCompressionCache(domain, cacheSize,
                                                           flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateSetMaxSpeed:
 * @domain: a domain object
 * @bandwidth: migration bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
 * can be specified with the bandwidth parameter. Not all hypervisors
 * will support a bandwidth cap
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetMaxSpeed(virDomainPtr domain,
                            unsigned long bandwidth,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "bandwidth=%lu, flags=%x", bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateSetMaxSpeed) {
        if (conn->driver->domainMigrateSetMaxSpeed(domain, bandwidth, flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateGetMaxSpeed:
 * @domain: a domain object
 * @bandwidth: return value of current migration bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the current maximum bandwidth (in MiB/s) that will be used if the
 * domain is migrated.  Not all hypervisors will support a bandwidth limit.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateGetMaxSpeed(virDomainPtr domain,
                            unsigned long *bandwidth,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "bandwidth = %p, flags=%x", bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(bandwidth, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateGetMaxSpeed) {
        if (conn->driver->domainMigrateGetMaxSpeed(domain, bandwidth, flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateStartPostCopy:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Starts post-copy migration. This function has to be called while
 * migration (initiated with VIR_MIGRATE_POSTCOPY flag) is in progress.
 *
 * Traditional pre-copy migration iteratively walks through guest memory
 * pages and migrates those that changed since the previous iteration. The
 * iterative phase stops when the number of dirty pages is low enough so that
 * the virtual CPUs can be paused, all dirty pages transferred to the
 * destination, where the virtual CPUs are unpaused, and all this can happen
 * within a predefined downtime period. It's clear that this process may never
 * converge if downtime is too short and/or the guest keeps changing a lot of
 * memory pages.
 *
 * When migration is switched to post-copy mode, the virtual CPUs are paused
 * immediately, only a minimum set of pages is transferred, and the CPUs are
 * unpaused on destination. The source keeps sending all remaining memory pages
 * to the destination while the guest is already running there. Whenever the
 * guest tries to read a memory page which has not been migrated yet, the
 * hypervisor has to tell the source to transfer that page in a priority
 * channel. To minimize such page faults, it is a good idea to run at least one
 * iteration of pre-copy migration before switching to post-copy.
 *
 * Post-copy migration is guaranteed to converge since each page is transferred
 * at most once no matter how fast it changes. On the other hand once the
 * guest is running on the destination host, the migration can no longer be
 * rolled back because none of the hosts has complete state. If this happens,
 * libvirt will leave the domain paused on both hosts with
 * VIR_DOMAIN_PAUSED_POSTCOPY_FAILED reason. It's up to the upper layer to
 * decide what to do in such case.
 *
 * The following domain life cycle events are emitted during post-copy
 * migration:
 *  VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY (on the source) -- migration entered
 *      post-copy mode.
 *  VIR_DOMAIN_EVENT_RESUMED_POSTCOPY (on the destination) -- the guest is
 *      running on the destination host while some of its memory pages still
 *      remain on the source host; neither the source nor the destination host
 *      contain a complete guest state from this point until migration
 *      finishes.
 *  VIR_DOMAIN_EVENT_RESUMED_MIGRATED (on the destination),
 *  VIR_DOMAIN_EVENT_STOPPED_MIGRATED (on the source) -- migration finished
 *      successfully and the destination host holds a complete guest state.
 *  VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED (on the destination) -- emitted
 *      when migration fails in post-copy mode and it's unclear whether any
 *      of the hosts has a complete guest state.
 *
 * The progress of a post-copy migration can be monitored normally using
 * virDomainGetJobStats on the source host. Fetching statistics of a completed
 * post-copy migration can also be done on the source host (by calling
 * virDomainGetJobStats or listening to VIR_DOMAIN_EVENT_ID_JOB_COMPLETED
 * event, but (in contrast to pre-copy migration) the statistics are not
 * available on the destination host. Thus, VIR_DOMAIN_EVENT_ID_JOB_COMPLETED
 * event is the only way of getting statistics of a completed post-copy
 * migration of a transient domain (because the domain is removed after
 * migration and there's no domain to run virDomainGetJobStats on).
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateStartPostCopy(virDomainPtr domain,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainMigrateStartPostCopy) {
        if (conn->driver->domainMigrateStartPostCopy(domain, flags) < 0)
            goto error;
        return 0;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectDomainEventRegisterAny:
 * @conn: pointer to the connection
 * @dom: pointer to the domain
 * @eventID: the event type to receive
 * @cb: callback to the function handling domain events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary domain events
 * occurring on a domain.  This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * If @dom is NULL, then events will be monitored for any domain. If @dom
 * is non-NULL, then only the specific domain will be monitored.
 *
 * Most types of event have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_DOMAIN_EVENT_CALLBACK() macro to cast the supplied function pointer
 * to match the signature of this method.
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback returns,
 * it shall take a reference to it, by calling virDomainRef().
 * The reference can be released once the object is no longer required
 * by calling virDomainFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectDomainEventDeregisterAny() method.
 *
 * Returns a callback identifier on success, -1 on failure.
 */
int
virConnectDomainEventRegisterAny(virConnectPtr conn,
                                 virDomainPtr dom,
                                 int eventID,
                                 virConnectDomainEventGenericCallback cb,
                                 void *opaque,
                                 virFreeCallback freecb)
{
    VIR_DOMAIN_DEBUG(dom, "conn=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
                     conn, eventID, cb, opaque, freecb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (dom) {
        virCheckDomainGoto(dom, error);
        if (dom->conn != conn) {
            virReportInvalidArg(dom,
                                _("domain '%s' must match connection"),
                                dom->name);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);
    if (eventID >= VIR_DOMAIN_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID must be less than %d"),
                            VIR_DOMAIN_EVENT_ID_LAST);
        goto error;
    }

    if (conn->driver && conn->driver->connectDomainEventRegisterAny) {
        int ret;
        ret = conn->driver->connectDomainEventRegisterAny(conn, dom, eventID, cb, opaque, freecb);
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
 * virConnectDomainEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectDomainEventRegisterAny() method.
 *
 * Returns 0 on success, -1 on failure.  Older versions of some hypervisors
 * sometimes returned a positive number on success, but without any reliable
 * semantics on what that number represents. */
int
virConnectDomainEventDeregisterAny(virConnectPtr conn,
                                   int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);

    if (conn->driver && conn->driver->connectDomainEventDeregisterAny) {
        int ret;
        ret = conn->driver->connectDomainEventDeregisterAny(conn, callbackID);
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
 * virDomainManagedSave:
 * @dom: pointer to the domain
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore.
 * The difference from virDomainSave() is that libvirt is keeping track of
 * the saved state itself, and will reuse it once the domain is being
 * restarted (automatically or via an explicit libvirt call).
 * As a result any running domain is sure to not have a managed saved image.
 * This also implies that managed save only works on persistent domains,
 * since the domain must still exist in order to use virDomainCreate() to
 * restart it.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while creating the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Normally, the managed saved state will remember whether the domain
 * was running or paused, and start will resume to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default saved into the file.  These two
 * flags are mutually exclusive.
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int
virDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SAVE_RUNNING,
                             VIR_DOMAIN_SAVE_PAUSED,
                             error);

    if (conn->driver->domainManagedSave) {
        int ret;

        ret = conn->driver->domainManagedSave(dom, flags);
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
 * virDomainHasManagedSaveImage:
 * @dom: pointer to the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Check if a domain has a managed save image as created by
 * virDomainManagedSave(). Note that any running domain should not have
 * such an image, as it should have been removed on restart.
 *
 * Returns 0 if no image is present, 1 if an image is present, and
 *         -1 in case of error
 */
int
virDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    if (conn->driver->domainHasManagedSaveImage) {
        int ret;

        ret = conn->driver->domainHasManagedSaveImage(dom, flags);
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
 * virDomainManagedSaveRemove:
 * @dom: pointer to the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Remove any managed save image for this domain.
 *
 * Returns 0 in case of success, and -1 in case of error
 */
int
virDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainManagedSaveRemove) {
        int ret;

        ret = conn->driver->domainManagedSaveRemove(dom, flags);
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
 * virDomainOpenConsole:
 * @dom: a domain object
 * @dev_name: the console, serial or parallel port device alias, or NULL
 * @st: a stream to associate with the console
 * @flags: bitwise-OR of virDomainConsoleFlags
 *
 * This opens the backend associated with a console, serial or
 * parallel port device on a guest, if the backend is supported.
 * If the @dev_name is omitted, then the first console or serial
 * device is opened. The console is associated with the passed
 * in @st stream, which should have been opened in non-blocking
 * mode for bi-directional I/O.
 *
 * By default, when @flags is 0, the open will fail if libvirt
 * detects that the console is already in use by another client;
 * passing VIR_DOMAIN_CONSOLE_FORCE will cause libvirt to forcefully
 * remove the other client prior to opening this console.
 *
 * If flag VIR_DOMAIN_CONSOLE_SAFE the console is opened only in the
 * case where the hypervisor driver supports safe (mutually exclusive)
 * console handling.
 *
 * Older servers did not support either flag, and also did not forbid
 * simultaneous clients on a console, with potentially confusing results.
 * When passing @flags of 0 in order to support a wider range of server
 * versions, it is up to the client to ensure mutual exclusion.
 *
 * Returns 0 if the console was opened, -1 on error
 */
int
virDomainOpenConsole(virDomainPtr dom,
                     const char *dev_name,
                     virStreamPtr st,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "dev_name=%s, st=%p, flags=%x",
                     NULLSTR(dev_name), st, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckStreamGoto(st, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn != st->conn) {
        virReportInvalidArg(st,
                            _("stream must match connection of domain '%s'"),
                            dom->name);
        goto error;
    }

    if (conn->driver->domainOpenConsole) {
        int ret;
        ret = conn->driver->domainOpenConsole(dom, dev_name, st, flags);
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
 * virDomainOpenChannel:
 * @dom: a domain object
 * @name: the channel name, or NULL
 * @st: a stream to associate with the channel
 * @flags: bitwise-OR of virDomainChannelFlags
 *
 * This opens the host interface associated with a channel device on a
 * guest, if the host interface is supported.  If @name is given, it
 * can match either the device alias (e.g. "channel0"), or the virtio
 * target name (e.g. "org.qemu.guest_agent.0").  If @name is omitted,
 * then the first channel is opened. The channel is associated with
 * the passed in @st stream, which should have been opened in
 * non-blocking mode for bi-directional I/O.
 *
 * By default, when @flags is 0, the open will fail if libvirt detects
 * that the channel is already in use by another client; passing
 * VIR_DOMAIN_CHANNEL_FORCE will cause libvirt to forcefully remove the
 * other client prior to opening this channel.
 *
 * Returns 0 if the channel was opened, -1 on error
 */
int
virDomainOpenChannel(virDomainPtr dom,
                     const char *name,
                     virStreamPtr st,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "name=%s, st=%p, flags=%x",
                     NULLSTR(name), st, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckStreamGoto(st, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn != st->conn) {
        virReportInvalidArg(st,
                            _("stream must match connection of domain '%s'"),
                            dom->name);
        goto error;
    }

    if (conn->driver->domainOpenChannel) {
        int ret;
        ret = conn->driver->domainOpenChannel(dom, name, st, flags);
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
 * virDomainGetPerfEvents:
 * @domain: a domain object
 * @params: where to store perf events setting
 * @nparams: number of items in @params
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Get all Linux perf events setting. Possible fields returned in
 * @params are defined by VIR_PERF_EVENT_* macros and new fields
 * will likely be introduced in the future.
 *
 * Linux perf events are performance analyzing tool in Linux.
 *
 * Returns -1 in case of failure, 0 in case of success.
 */
int virDomainGetPerfEvents(virDomainPtr domain,
                           virTypedParameterPtr *params,
                           int *nparams,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p flags=%x",
                     params, nparams, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);

    conn = domain->conn;

    if (conn->driver->domainGetPerfEvents) {
        int ret;
        ret = conn->driver->domainGetPerfEvents(domain, params,
                                                nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetPerfEvents:
 * @domain: a domain object
 * @params: pointer to perf events parameter object
 * @nparams: number of perf event parameters (this value can be the same
 *           less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Enable or disable the particular list of Linux perf events you
 * care about. The @params argument should contain any subset of
 * VIR_PERF_EVENT_ macros.
 *
 * Linux perf events are performance analyzing tool in Linux.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int virDomainSetPerfEvents(virDomainPtr domain,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetPerfEvents) {
        int ret;
        ret = conn->driver->domainSetPerfEvents(domain, params,
                                                nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainBlockJobAbort:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @flags: bitwise-OR of virDomainBlockJobAbortFlags
 *
 * Cancel the active block job on the given disk.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * If the current block job for @disk is VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, then
 * by default, this function performs a synchronous operation and the caller
 * may assume that the operation has completed when 0 is returned.  However,
 * BlockJob operations may take a long time to cancel, and during this time
 * further domain interactions may be unresponsive.  To avoid this problem,
 * pass VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC in the @flags argument to enable
 * asynchronous behavior, returning as soon as possible.  When the job has
 * been canceled, a BlockJob event will be emitted, with status
 * VIR_DOMAIN_BLOCK_JOB_CANCELED (even if the ABORT_ASYNC flag was not
 * used); it is also possible to poll virDomainBlockJobInfo() to see if
 * the job cancellation is still pending.  This type of job can be restarted
 * to pick up from where it left off.
 *
 * If the current block job for @disk is VIR_DOMAIN_BLOCK_JOB_TYPE_COPY, then
 * the default is to abort the mirroring and revert to the source disk;
 * likewise, if the current job is VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT,
 * the default is to abort without changing the active layer of @disk.
 * Adding @flags of VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT causes this call to
 * fail with VIR_ERR_BLOCK_COPY_ACTIVE if the copy or commit is not yet
 * ready; otherwise it will swap the disk over to the new active image
 * to end the mirroring or active commit.  An event will be issued when the
 * job is ended, and it is possible to use VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC
 * to control whether this command waits for the completion of the job.
 * Restarting a copy or active commit job requires starting over from the
 * beginning of the first phase.
 *
 * Returns -1 in case of failure, 0 when successful.
 */
int
virDomainBlockJobAbort(virDomainPtr dom, const char *disk,
                       unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, flags=%x", disk, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockJobAbort) {
        int ret;
        ret = conn->driver->domainBlockJobAbort(dom, disk, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetBlockJobInfo:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @info: pointer to a virDomainBlockJobInfo structure
 * @flags: bitwise-OR of virDomainBlockJobInfoFlags
 *
 * Request block job information for the given disk.  If an operation is active
 * @info will be updated with the current progress.  The units used for the
 * bandwidth field of @info depends on @flags.  If @flags includes
 * VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES, bandwidth is in bytes/second
 * (although this mode can risk failure due to overflow, depending on both
 * client and server word size); otherwise, the value is rounded up to MiB/s.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * As a corner case underlying hypervisor may report cur == 0 and
 * end == 0 when the block job hasn't been started yet. In this
 * case libvirt reports cur = 0 and end = 1. However, hypervisor
 * may return cur == 0 and end == 0 if the block job has finished
 * and was no-op. In this case libvirt reports cur = 1 and end = 1.
 * Since 2.3.0.
 *
 * Returns -1 in case of failure, 0 when nothing found, 1 when info was found.
 */
int
virDomainGetBlockJobInfo(virDomainPtr dom, const char *disk,
                         virDomainBlockJobInfoPtr info, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, info=%p, flags=%x", disk, info, flags);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(info, error);

    if (conn->driver->domainGetBlockJobInfo) {
        int ret;
        ret = conn->driver->domainGetBlockJobInfo(dom, disk, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockJobSetSpeed:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @bandwidth: specify bandwidth limit; flags determine the unit
 * @flags: bitwise-OR of virDomainBlockJobSetSpeedFlags
 *
 * Set the maximimum allowable bandwidth that a block job may consume.  If
 * bandwidth is 0, the limit will revert to the hypervisor default of
 * unlimited.
 *
 * If @flags contains VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES, @bandwidth
 * is in bytes/second; otherwise, it is in MiB/second.  Values larger than
 * 2^52 bytes/sec may be rejected due to overflow considerations based on
 * the word size of both client and server, and values larger than 2^31
 * bytes/sec may cause overflow problems if later queried by
 * virDomainGetBlockJobInfo() without scaling.  Hypervisors may further
 * restrict the range of valid bandwidth values.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Returns -1 in case of failure, 0 when successful.
 */
int
virDomainBlockJobSetSpeed(virDomainPtr dom, const char *disk,
                          unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, bandwidth=%lu, flags=%x",
                     disk, bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockJobSetSpeed) {
        int ret;
        ret = conn->driver->domainBlockJobSetSpeed(dom, disk, bandwidth, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockPull:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @bandwidth: (optional) specify bandwidth limit; flags determine the unit
 * @flags: bitwise-OR of virDomainBlockPullFlags
 *
 * Populate a disk image with data from its backing image.  Once all data from
 * its backing image has been pulled, the disk no longer depends on a backing
 * image.  This function pulls data for the entire device in the background.
 * Progress of the operation can be checked with virDomainGetBlockJobInfo() and
 * the operation can be aborted with virDomainBlockJobAbort().  When finished,
 * an asynchronous event is raised to indicate the final status.  To move
 * data in the opposite direction, see virDomainBlockCommit().
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The maximum bandwidth that will be used to do the copy can be
 * specified with the @bandwidth parameter.  If set to 0, there is no
 * limit.  If @flags includes VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES,
 * @bandwidth is in bytes/second; otherwise, it is in MiB/second.
 * Values larger than 2^52 bytes/sec may be rejected due to overflow
 * considerations based on the word size of both client and server,
 * and values larger than 2^31 bytes/sec may cause overflow problems
 * if later queried by virDomainGetBlockJobInfo() without scaling.
 * Hypervisors may further restrict the range of valid bandwidth
 * values.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still
 * be possible for a later call to virDomainBlockJobSetSpeed() to
 * succeed.  The actual speed can be determined with
 * virDomainGetBlockJobInfo().
 *
 * This is shorthand for virDomainBlockRebase() with a NULL base.
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int
virDomainBlockPull(virDomainPtr dom, const char *disk,
                   unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, bandwidth=%lu, flags=%x",
                     disk, bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockPull) {
        int ret;
        ret = conn->driver->domainBlockPull(dom, disk, bandwidth, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockRebase:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @base: path to backing file to keep, or device shorthand,
 *        or NULL for no backing file
 * @bandwidth: (optional) specify bandwidth limit; flags determine the unit
 * @flags: bitwise-OR of virDomainBlockRebaseFlags
 *
 * Populate a disk image with data from its backing image chain, and
 * setting the backing image to @base, or alternatively copy an entire
 * backing chain to a new file @base.
 *
 * When @flags is 0, this starts a pull, where @base must be the absolute
 * path of one of the backing images further up the chain, or NULL to
 * convert the disk image so that it has no backing image.  Once all
 * data from its backing image chain has been pulled, the disk no
 * longer depends on those intermediate backing images.  This function
 * pulls data for the entire device in the background.  Progress of
 * the operation can be checked with virDomainGetBlockJobInfo() with a
 * job type of VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, and the operation can be
 * aborted with virDomainBlockJobAbort().  When finished, an asynchronous
 * event is raised to indicate the final status, and the job no longer
 * exists.  If the job is aborted, a new one can be started later to
 * resume from the same point.
 *
 * If @flags contains VIR_DOMAIN_BLOCK_REBASE_RELATIVE, the name recorded
 * into the active disk as the location for @base will be kept relative.
 * The operation will fail if libvirt can't infer the name.
 *
 * When @flags includes VIR_DOMAIN_BLOCK_REBASE_COPY, this starts a copy,
 * where @base must be the name of a new file to copy the chain to.  By
 * default, the copy will pull the entire source chain into the destination
 * file, but if @flags also contains VIR_DOMAIN_BLOCK_REBASE_SHALLOW, then
 * only the top of the source chain will be copied (the source and
 * destination have a common backing file).  By default, @base will be
 * created with the same file format as the source, but this can be altered
 * by adding VIR_DOMAIN_BLOCK_REBASE_COPY_RAW to force the copy to be raw
 * (does not make sense with the shallow flag unless the source is also raw),
 * or by using VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT to reuse an existing file
 * which was pre-created with the correct format and metadata and sufficient
 * size to hold the copy. In case the VIR_DOMAIN_BLOCK_REBASE_SHALLOW flag
 * is used the pre-created file has to exhibit the same guest visible contents
 * as the backing file of the original image. This allows a management app to
 * pre-create files with relative backing file names, rather than the default
 * of absolute backing file names; as a security precaution, you should
 * generally only use reuse_ext with the shallow flag and a non-raw
 * destination file.  By default, the copy destination will be treated as
 * type='file', but using VIR_DOMAIN_BLOCK_REBASE_COPY_DEV treats the
 * destination as type='block' (affecting how virDomainGetBlockInfo() will
 * report allocation after pivoting).
 *
 * A copy job has two parts; in the first phase, the @bandwidth parameter
 * affects how fast the source is pulled into the destination, and the job
 * can only be canceled by reverting to the source file; progress in this
 * phase can be tracked via the virDomainBlockJobInfo() command, with a
 * job type of VIR_DOMAIN_BLOCK_JOB_TYPE_COPY.  The job transitions to the
 * second phase when the job info states cur == end, and remains alive to
 * mirror all further changes to both source and destination.  The user
 * must call virDomainBlockJobAbort() to end the mirroring while choosing
 * whether to revert to source or pivot to the destination.  An event is
 * issued when the job ends, and depending on the hypervisor, an event may
 * also be issued when the job transitions from pulling to mirroring.  If
 * the job is aborted, a new job will have to start over from the beginning
 * of the first phase.
 *
 * Some hypervisors will restrict certain actions, such as virDomainSave()
 * or virDomainDetachDevice(), while a copy job is active; they may
 * also restrict a copy job to transient domains.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the
 * <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The @base parameter can be either a path to a file within the backing
 * chain, or the device target shorthand (the <target dev='...'/>
 * sub-element, such as "vda") followed by an index to the backing chain
 * enclosed in square brackets. Backing chain indexes can be found by
 * inspecting //disk//backingStore/@index in the domain XML. Thus, for
 * example, "vda[3]" refers to the backing store with index equal to "3"
 * in the chain of disk "vda".
 *
 * The maximum bandwidth that will be used to do the copy can be
 * specified with the @bandwidth parameter.  If set to 0, there is no
 * limit.  If @flags includes VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES,
 * @bandwidth is in bytes/second; otherwise, it is in MiB/second.
 * Values larger than 2^52 bytes/sec may be rejected due to overflow
 * considerations based on the word size of both client and server,
 * and values larger than 2^31 bytes/sec may cause overflow problems
 * if later queried by virDomainGetBlockJobInfo() without scaling.
 * Hypervisors may further restrict the range of valid bandwidth
 * values.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still
 * be possible for a later call to virDomainBlockJobSetSpeed() to
 * succeed.  The actual speed can be determined with
 * virDomainGetBlockJobInfo().
 *
 * When @base is NULL and @flags is 0, this is identical to
 * virDomainBlockPull().  When @flags contains VIR_DOMAIN_BLOCK_REBASE_COPY,
 * this command is shorthand for virDomainBlockCopy() where the destination
 * XML encodes @base as a <disk type='file'>, @bandwidth is properly scaled
 * and passed as a typed parameter, the shallow and reuse external flags
 * are preserved, and remaining flags control whether the XML encodes a
 * destination format of raw instead of leaving the destination identical
 * to the source format or probed from the reused file.
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int
virDomainBlockRebase(virDomainPtr dom, const char *disk,
                     const char *base, unsigned long bandwidth,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY) {
        virCheckNonNullArgGoto(base, error);
    } else if (flags & (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                        VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_DEV)) {
        virReportInvalidArg(flags, "%s",
                            _("use of flags requires a copy job"));
        goto error;
    }

    if (conn->driver->domainBlockRebase) {
        int ret;
        ret = conn->driver->domainBlockRebase(dom, disk, base, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockCopy:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @destxml: XML description of the copy destination
 * @params: Pointer to block copy parameter objects, or NULL
 * @nparams: Number of block copy parameters (this value can be the same or
 *           less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainBlockCopyFlags
 *
 * Copy the guest-visible contents of a disk image to a new file described
 * by @destxml.  The destination XML has a top-level element of <disk>, and
 * resembles what is used when hot-plugging a disk via virDomainAttachDevice(),
 * except that only sub-elements related to describing the new host resource
 * are necessary (sub-elements related to the guest view, such as <target>,
 * are ignored).  It is strongly recommended to include a <driver type='...'/>
 * format designation for the destination, to avoid the potential of any
 * security problem that might be caused by probing a file for its format.
 *
 * This command starts a long-running copy.  By default, the copy will pull
 * the entire source chain into the destination file, but if @flags also
 * contains VIR_DOMAIN_BLOCK_COPY_SHALLOW, then only the top of the source
 * chain will be copied (the source and destination have a common backing
 * file).  The format of the destination file is controlled by the <driver>
 * sub-element of the XML.  The destination will be created unless the
 * VIR_DOMAIN_BLOCK_COPY_REUSE_EXT flag is present stating that the file
 * was pre-created with the correct format and metadata and sufficient
 * size to hold the copy. In case the VIR_DOMAIN_BLOCK_COPY_SHALLOW flag
 * is used the pre-created file has to exhibit the same guest visible contents
 * as the backing file of the original image. This allows a management app to
 * pre-create files with relative backing file names, rather than the default
 * of absolute backing file names.
 *
 * A copy job has two parts; in the first phase, the source is copied into
 * the destination, and the job can only be canceled by reverting to the
 * source file; progress in this phase can be tracked via the
 * virDomainBlockJobInfo() command, with a job type of
 * VIR_DOMAIN_BLOCK_JOB_TYPE_COPY.  The job transitions to the second
 * phase when the job info states cur == end, and remains alive to mirror
 * all further changes to both source and destination.  The user must
 * call virDomainBlockJobAbort() to end the mirroring while choosing
 * whether to revert to source or pivot to the destination.  An event is
 * issued when the job ends, and depending on the hypervisor, an event may
 * also be issued when the job transitions from pulling to mirroring.  If
 * the job is aborted, a new job will have to start over from the beginning
 * of the first phase.
 *
 * Some hypervisors will restrict certain actions, such as virDomainSave()
 * or virDomainDetachDevice(), while a copy job is active; they may
 * also restrict a copy job to transient domains.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the
 * <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The @params and @nparams arguments can be used to set hypervisor-specific
 * tuning parameters, such as maximum bandwidth or granularity.  For a
 * parameter that the hypervisor understands, explicitly specifying 0
 * behaves the same as omitting the parameter, to use the hypervisor
 * default; however, omitting a parameter is less likely to fail.
 *
 * This command is a superset of the older virDomainBlockRebase() when used
 * with the VIR_DOMAIN_BLOCK_REBASE_COPY flag, and offers better control
 * over the destination format, the ability to copy to a destination that
 * is not a local file, and the possibility of additional tuning parameters.
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int
virDomainBlockCopy(virDomainPtr dom, const char *disk,
                   const char *destxml,
                   virTypedParameterPtr params,
                   int nparams,
                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom,
                     "disk=%s, destxml=%s, params=%p, nparams=%d, flags=%x",
                     disk, destxml, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(destxml, error);
    virCheckNonNegativeArgGoto(nparams, error);
    if (nparams)
        virCheckNonNullArgGoto(params, error);

    if (conn->driver->domainBlockCopy) {
        int ret;
        ret = conn->driver->domainBlockCopy(dom, disk, destxml,
                                            params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockCommit:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @base: path to backing file to merge into, or device shorthand,
 *        or NULL for default
 * @top: path to file within backing chain that contains data to be merged,
 *       or device shorthand, or NULL to merge all possible data
 * @bandwidth: (optional) specify bandwidth limit; flags determine the unit
 * @flags: bitwise-OR of virDomainBlockCommitFlags
 *
 * Commit changes that were made to temporary top-level files within a disk
 * image backing file chain into a lower-level base file.  In other words,
 * take all the difference between @base and @top, and update @base to contain
 * that difference; after the commit, any portion of the chain that previously
 * depended on @top will now depend on @base, and all files after @base up
 * to and including @top will now be invalidated.  A typical use of this
 * command is to reduce the length of a backing file chain after taking an
 * external disk snapshot.  To move data in the opposite direction, see
 * virDomainBlockPull().
 *
 * This command starts a long-running commit block job, whose status may
 * be tracked by virDomainBlockJobInfo() with a job type of
 * VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT, and the operation can be aborted with
 * virDomainBlockJobAbort().  When finished, an asynchronous event is
 * raised to indicate the final status, and the job no longer exists.  If
 * the job is aborted, it is up to the hypervisor whether starting a new
 * job will resume from the same point, or start over.
 *
 * As a special case, if @top is the active image (or NULL), and @flags
 * includes VIR_DOMAIN_BLOCK_COMMIT_ACTIVE, the block job will have a type
 * of VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT, and operates in two phases.
 * In the first phase, the contents are being committed into @base, and the
 * job can only be canceled.  The job transitions to the second phase when
 * the job info states cur == end, and remains alive to keep all further
 * changes to @top synchronized into @base; an event with status
 * VIR_DOMAIN_BLOCK_JOB_READY is also issued to mark the job transition.
 * Once in the second phase, the user must choose whether to cancel the job
 * (keeping @top as the active image, but now containing only the changes
 * since the time the job ended) or to pivot the job (adjusting to @base as
 * the active image, and invalidating @top).
 *
 * Be aware that this command may invalidate files even if it is aborted;
 * the user is cautioned against relying on the contents of invalidated
 * intermediate files such as @top (when @top is not the active image)
 * without manually rebasing those files to use a backing file of a
 * read-only copy of @base prior to the point where the commit operation
 * was started (and such a rebase cannot be safely done until the commit
 * has successfully completed).  However, the domain itself will not have
 * any issues; the active layer remains valid throughout the entire commit
 * operation.
 *
 * Some hypervisors may support a shortcut where if @flags contains
 * VIR_DOMAIN_BLOCK_COMMIT_DELETE, then this command will unlink all files
 * that were invalidated, after the commit successfully completes.
 *
 * If @flags contains VIR_DOMAIN_BLOCK_COMMIT_RELATIVE, the name recorded
 * into the overlay of the @top image (if there is such image) as the
 * path to the new backing file will be kept relative to other images.
 * The operation will fail if libvirt can't infer the name.
 *
 * By default, if @base is NULL, the commit target will be the bottom of
 * the backing chain; if @flags contains VIR_DOMAIN_BLOCK_COMMIT_SHALLOW,
 * then the immediate backing file of @top will be used instead.  If @top
 * is NULL, the active image at the top of the chain will be used.  Some
 * hypervisors place restrictions on how much can be committed, and might
 * fail if @base is not the immediate backing file of @top, or if @top is
 * the active layer in use by a running domain but @flags did not include
 * VIR_DOMAIN_BLOCK_COMMIT_ACTIVE, or if @top is not the top-most file;
 * restrictions may differ for online vs. offline domains.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the
 * <target dev='...'/> sub-element, such as "vda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The @base and @top parameters can be either paths to files within the
 * backing chain, or the device target shorthand (the <target dev='...'/>
 * sub-element, such as "vda") followed by an index to the backing chain
 * enclosed in square brackets. Backing chain indexes can be found by
 * inspecting //disk//backingStore/@index in the domain XML. Thus, for
 * example, "vda[3]" refers to the backing store with index equal to "3"
 * in the chain of disk "vda".
 *
 * The maximum bandwidth that will be used to do the commit can be
 * specified with the @bandwidth parameter.  If set to 0, there is no
 * limit.  If @flags includes VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES,
 * @bandwidth is in bytes/second; otherwise, it is in MiB/second.
 * Values larger than 2^52 bytes/sec may be rejected due to overflow
 * considerations based on the word size of both client and server,
 * and values larger than 2^31 bytes/sec may cause overflow problems
 * if later queried by virDomainGetBlockJobInfo() without scaling.
 * Hypervisors may further restrict the range of valid bandwidth
 * values.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still
 * be possible for a later call to virDomainBlockJobSetSpeed() to
 * succeed.  The actual speed can be determined with
 * virDomainGetBlockJobInfo().
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int
virDomainBlockCommit(virDomainPtr dom, const char *disk,
                     const char *base, const char *top,
                     unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, top=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), NULLSTR(top), bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockCommit) {
        int ret;
        ret = conn->driver->domainBlockCommit(dom, disk, base, top, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainOpenGraphics:
 * @dom: pointer to domain object
 * @idx: index of graphics config to open
 * @fd: file descriptor to attach graphics to
 * @flags: bitwise-OR of virDomainOpenGraphicsFlags
 *
 * This will attempt to connect the file descriptor @fd, to
 * the graphics backend of @dom. If @dom has multiple graphics
 * backends configured, then @idx will determine which one is
 * opened, starting from @idx 0.
 *
 * To disable any authentication, pass the VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH
 * constant for @flags.
 *
 * The caller should use an anonymous socketpair to open
 * @fd before invocation.
 *
 * This method can only be used when connected to a local
 * libvirt hypervisor, over a UNIX domain socket. Attempts
 * to use this method over a TCP connection will always fail
 *
 * Returns 0 on success, -1 on failure
 */
int
virDomainOpenGraphics(virDomainPtr dom,
                      unsigned int idx,
                      int fd,
                      unsigned int flags)
{
    struct stat sb;
    VIR_DOMAIN_DEBUG(dom, "idx=%u, fd=%d, flags=%x",
                     idx, fd, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckNonNegativeArgGoto(fd, error);

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access file descriptor %d"), fd);
        goto error;
    }

    if (!S_ISSOCK(sb.st_mode)) {
        virReportInvalidArg(fd,
                            _("fd %d must be a socket"),
                            fd);
        goto error;
    }

    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (!VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                  VIR_DRV_FEATURE_FD_PASSING)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("fd passing is not supported by this connection"));
        goto error;
    }

    if (dom->conn->driver->domainOpenGraphics) {
        int ret;
        ret = dom->conn->driver->domainOpenGraphics(dom, idx, fd, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainOpenGraphicsFD:
 * @dom: pointer to domain object
 * @idx: index of graphics config to open
 * @flags: bitwise-OR of virDomainOpenGraphicsFlags
 *
 * This will create a socket pair connected to the graphics backend of @dom.
 * One end of the socket will be returned on success, and the other end is
 * handed to the hypervisor.
 * If @dom has multiple graphics backends configured, then @idx will determine
 * which one is opened, starting from @idx 0.
 *
 * To disable any authentication, pass the VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH
 * constant for @flags.
 *
 * This method can only be used when connected to a local
 * libvirt hypervisor, over a UNIX domain socket. Attempts
 * to use this method over a TCP connection will always fail.
 *
 * Returns an fd on success, -1 on failure
 */
int
virDomainOpenGraphicsFD(virDomainPtr dom,
                        unsigned int idx,
                        unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "idx=%u, flags=%x", idx, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (!VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                  VIR_DRV_FEATURE_FD_PASSING)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("fd passing is not supported by this connection"));
        goto error;
    }

    if (dom->conn->driver->domainOpenGraphicsFD) {
        int ret;
        ret = dom->conn->driver->domainOpenGraphicsFD(dom, idx, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainSetBlockIoTune:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: Pointer to blkio parameter objects
 * @nparams: Number of blkio parameters (this value can be the same or
 *           less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the per-device block IO tunables.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the <target
 * dev='...'/> sub-element, such as "xvda").  Valid names can be found
 * by calling virDomainGetXMLDesc() and inspecting elements
 * within //domain/devices/disk.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetBlockIoTune(virDomainPtr dom,
                        const char *disk,
                        virTypedParameterPtr params,
                        int nparams,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     disk, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);
    virCheckPositiveArgGoto(nparams, error);
    virCheckNonNullArgGoto(params, error);

    if (virTypedParameterValidateSet(dom->conn, params, nparams) < 0)
        goto error;

    if (conn->driver->domainSetBlockIoTune) {
        int ret;
        ret = conn->driver->domainSetBlockIoTune(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetBlockIoTune:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: Pointer to blkio parameter object
 *          (return value, allocated by the caller)
 * @nparams: Pointer to number of blkio parameters
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all block IO tunable parameters for a given device.  On input,
 * @nparams gives the size of the @params array; on output, @nparams
 * gives how many slots were filled with parameter information, which
 * might be less but will not exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0
 * on input will cause @nparams on output to contain the number of
 * parameters supported by the hypervisor, either for the given @disk
 * (note that block devices of different types might support different
 * parameters), or if @disk is NULL, for all possible disks. The
 * caller should then allocate @params array,
 * i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.  See virDomainGetMemoryParameters() for more details.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the <target
 * dev='...'/> sub-element, such as "xvda").  Valid names can be found
 * by calling virDomainGetXMLDesc() and inspecting elements
 * within //domain/devices/disk.  This parameter cannot be NULL
 * unless @nparams is 0 on input.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetBlockIoTune(virDomainPtr dom,
                        const char *disk,
                        virTypedParameterPtr params,
                        int *nparams,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     NULLSTR(disk), params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0) {
        virCheckNonNullArgGoto(params, error);
        virCheckNonNullArgGoto(disk, error);
    }

    if (VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_AFFECT_LIVE,
                             VIR_DOMAIN_AFFECT_CONFIG,
                             error);

    conn = dom->conn;

    if (conn->driver->domainGetBlockIoTune) {
        int ret;
        ret = conn->driver->domainGetBlockIoTune(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetCPUStats:
 * @domain: domain to query
 * @params: array to populate on output
 * @nparams: number of parameters per cpu
 * @start_cpu: which cpu to start with, or -1 for summary
 * @ncpus: how many cpus to query
 * @flags: bitwise-OR of virTypedParameterFlags
 *
 * Get statistics relating to CPU usage attributable to a single
 * domain (in contrast to the statistics returned by
 * virNodeGetCPUStats() for all processes on the host).  @dom
 * must be running (an inactive domain has no attributable cpu
 * usage).  On input, @params must contain at least @nparams * @ncpus
 * entries, allocated by the caller.
 *
 * If @start_cpu is -1, then @ncpus must be 1, and the returned
 * results reflect the statistics attributable to the entire
 * domain (such as user and system time for the process as a
 * whole).  Otherwise, @start_cpu represents which cpu to start
 * with, and @ncpus represents how many consecutive processors to
 * query, with statistics attributable per processor (such as
 * per-cpu usage).  If @ncpus is larger than the number of cpus
 * available to query, then the trailing part of the array will
 * be unpopulated.
 *
 * The remote driver imposes a limit of 128 @ncpus and 16 @nparams;
 * the number of parameters per cpu should not exceed 16, but if you
 * have a host with more than 128 CPUs, your program should split
 * the request into multiple calls.
 *
 * As special cases, if @params is NULL and @nparams is 0 and
 * @ncpus is 1, and the return value will be how many
 * statistics are available for the given @start_cpu.  This number
 * may be different for @start_cpu of -1 than for any non-negative
 * value, but will be the same for all non-negative @start_cpu.
 * Likewise, if @params is NULL and @nparams is 0 and @ncpus is 0,
 * the number of cpus available to query is returned.  From the
 * host perspective, this would typically match the cpus member
 * of virNodeGetInfo(), but might be less due to host cpu hotplug.
 *
 * For now, @flags is unused, and the statistics all relate to the
 * usage from the host perspective.  It is possible that a future
 * version will support a flag that queries the cpu usage from the
 * guest's perspective, where the maximum cpu to query would be
 * related to virDomainGetVcpusFlags() rather than virNodeGetInfo().
 * An individual guest vcpu cannot be reliably mapped back to a
 * specific host cpu unless a single-processor vcpu pinning was used,
 * but when @start_cpu is -1, any difference in usage between a host
 * and guest perspective would serve as a measure of hypervisor overhead.
 *
 * Typical use sequence is below.
 *
 * getting total stats: set start_cpu as -1, ncpus 1
 *
 *   virDomainGetCPUStats(dom, NULL, 0, -1, 1, 0); // nparams
 *   params = calloc(nparams, sizeof(virTypedParameter))
 *   virDomainGetCPUStats(dom, params, nparams, -1, 1, 0); // total stats.
 *
 * getting per-cpu stats:
 *
 *   virDomainGetCPUStats(dom, NULL, 0, 0, 0, 0); // ncpus
 *   virDomainGetCPUStats(dom, NULL, 0, 0, 1, 0); // nparams
 *   params = calloc(ncpus * nparams, sizeof(virTypedParameter));
 *   virDomainGetCPUStats(dom, params, nparams, 0, ncpus, 0); // per-cpu stats
 *
 * Returns -1 on failure, or the number of statistics that were
 * populated per cpu on success (this will be less than the total
 * number of populated @params, unless @ncpus was 1; and may be
 * less than @nparams).  The populated parameters start at each
 * stride of @nparams, which means the results may be discontiguous;
 * any unpopulated parameters will be zeroed on success (this includes
 * skipped elements if @nparams is too large, and tail elements if
 * @ncpus is too large).  The caller is responsible for freeing any
 * returned string parameters.
 */
int
virDomainGetCPUStats(virDomainPtr domain,
                     virTypedParameterPtr params,
                     unsigned int nparams,
                     int start_cpu,
                     unsigned int ncpus,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "params=%p, nparams=%d, start_cpu=%d, ncpus=%u, flags=%x",
                     params, nparams, start_cpu, ncpus, flags);
    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    /* Special cases:
     * start_cpu must be non-negative, or else -1
     * if start_cpu is -1, ncpus must be 1
     * params == NULL must match nparams == 0
     * ncpus must be non-zero unless params == NULL
     * nparams * ncpus must not overflow (RPC may restrict it even more)
     */
    if (start_cpu == -1) {
        if (ncpus != 1) {
            virReportInvalidArg(start_cpu, "%s",
                                _("ncpus must be 1 when start_cpu is -1"));
            goto error;
        }
    } else {
        virCheckNonNegativeArgGoto(start_cpu, error);
    }
    if (nparams)
        virCheckNonNullArgGoto(params, error);
    else
        virCheckNullArgGoto(params, error);
    if (ncpus == 0)
        virCheckNullArgGoto(params, error);

    if (nparams && ncpus > UINT_MAX / nparams) {
        virReportError(VIR_ERR_OVERFLOW, _("input too large: %u * %u"),
                       nparams, ncpus);
        goto error;
    }
    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    if (conn->driver->domainGetCPUStats) {
        int ret;

        ret = conn->driver->domainGetCPUStats(domain, params, nparams,
                                              start_cpu, ncpus, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetDiskErrors:
 * @dom: a domain object
 * @errors: array to populate on output
 * @maxerrors: size of @errors array
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * The function populates @errors array with all disks that encountered an
 * I/O error.  Disks with no error will not be returned in the @errors array.
 * Each disk is identified by its target (the dev attribute of target
 * subelement in domain XML), such as "vda", and accompanied with the error
 * that was seen on it.  The caller is also responsible for calling free()
 * on each disk name returned.
 *
 * In a special case when @errors is NULL and @maxerrors is 0, the function
 * returns preferred size of @errors that the caller should use to get all
 * disk errors.
 *
 * Since calling virDomainGetDiskErrors(dom, NULL, 0, 0) to get preferred size
 * of @errors array and getting the errors are two separate operations, new
 * disks may be hotplugged to the domain and new errors may be encountered
 * between the two calls.  Thus, this function may not return all disk errors
 * because the supplied array is not large enough.  Such errors may, however,
 * be detected by listening to domain events.
 *
 * Returns number of disks with errors filled in the @errors array or -1 on
 * error.
 */
int
virDomainGetDiskErrors(virDomainPtr dom,
                       virDomainDiskErrorPtr errors,
                       unsigned int maxerrors,
                       unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "errors=%p, maxerrors=%u, flags=%x",
                     errors, maxerrors, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (maxerrors)
        virCheckNonNullArgGoto(errors, error);
    else
        virCheckNullArgGoto(errors, error);

    if (dom->conn->driver->domainGetDiskErrors) {
        int ret = dom->conn->driver->domainGetDiskErrors(dom, errors,
                                                         maxerrors, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetHostname:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the hostname for that domain.
 *
 * Dependent on hypervisor used, this may require a guest agent to be
 * available.
 *
 * Returns the hostname which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virDomainGetHostname(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    if (conn->driver->domainGetHostname) {
        char *ret;
        ret = conn->driver->domainGetHostname(domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainFSTrim:
 * @dom: a domain object
 * @mountPoint: which mount point to trim
 * @minimum: Minimum contiguous free range to discard in bytes
 * @flags: extra flags, not used yet, so callers should always pass 0
 *
 * Calls FITRIM within the guest (hence guest agent may be
 * required depending on hypervisor used). Either call it on each
 * mounted filesystem (@mountPoint is NULL) or just on specified
 * @mountPoint. @minimum hints that free ranges smaller than this
 * may be ignored (this is a hint and the guest may not respect
 * it).  By increasing this value, the fstrim operation will
 * complete more quickly for filesystems with badly fragmented
 * free space, although not all blocks will be discarded.
 * If @minimum is not zero, the command may fail.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainFSTrim(virDomainPtr dom,
                const char *mountPoint,
                unsigned long long minimum,
                unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "mountPoint=%s, minimum=%llu, flags=%x",
                     mountPoint, minimum, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (dom->conn->driver->domainFSTrim) {
        int ret = dom->conn->driver->domainFSTrim(dom, mountPoint,
                                                  minimum, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainFSFreeze:
 * @dom: a domain object
 * @mountpoints: list of mount points to be frozen
 * @nmountpoints: the number of mount points specified in @mountpoints
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Freeze specified filesystems within the guest (hence guest agent
 * may be required depending on hypervisor used). If @mountpoints is NULL and
 * @nmountpoints is 0, every mounted filesystem on the guest is frozen.
 * In some environments (e.g. QEMU guest with guest agent which doesn't
 * support mountpoints argument), @mountpoints may need to be NULL.
 *
 * Returns the number of frozen filesystems on success, -1 otherwise.
 */
int
virDomainFSFreeze(virDomainPtr dom,
                  const char **mountpoints,
                  unsigned int nmountpoints,
                  unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "mountpoints=%p, nmountpoints=%d, flags=%x",
                     mountpoints, nmountpoints, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);
    if (nmountpoints)
        virCheckNonNullArgGoto(mountpoints, error);
    else
        virCheckNullArgGoto(mountpoints, error);

    if (dom->conn->driver->domainFSFreeze) {
        int ret = dom->conn->driver->domainFSFreeze(
            dom, mountpoints, nmountpoints, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainFSThaw:
 * @dom: a domain object
 * @mountpoints: list of mount points to be thawed
 * @nmountpoints: the number of mount points specified in @mountpoints
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Thaw specified filesystems within the guest. If @mountpoints is NULL and
 * @nmountpoints is 0, every mounted filesystem on the guest is thawed.
 * In some drivers (e.g. QEMU driver), @mountpoints may need to be NULL.
 *
 * Returns the number of thawed filesystems on success, -1 otherwise.
 */
int
virDomainFSThaw(virDomainPtr dom,
                const char **mountpoints,
                unsigned int nmountpoints,
                unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);
    if (nmountpoints)
        virCheckNonNullArgGoto(mountpoints, error);
    else
        virCheckNullArgGoto(mountpoints, error);

    if (dom->conn->driver->domainFSThaw) {
        int ret = dom->conn->driver->domainFSThaw(
            dom, mountpoints, nmountpoints, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainGetTime:
 * @dom: a domain object
 * @seconds: domain's time in seconds
 * @nseconds: the nanoscond part of @seconds
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract information about guest time and store it into
 * @seconds and @nseconds. The @seconds represents the number of
 * seconds since the UNIX Epoch of 1970-01-01 00:00:00 in UTC.
 *
 * Please note that some hypervisors may require guest agent to
 * be configured and running in order to run this API.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainGetTime(virDomainPtr dom,
                 long long *seconds,
                 unsigned int *nseconds,
                 unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "seconds=%p, nseconds=%p, flags=%x",
                     seconds, nseconds, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (dom->conn->driver->domainGetTime) {
        int ret = dom->conn->driver->domainGetTime(dom, seconds,
                                                   nseconds, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainSetTime:
 * @dom: a domain object
 * @seconds: time to set
 * @nseconds: the nanosecond part of @seconds
 * @flags: bitwise-OR of virDomainSetTimeFlags
 *
 * When a domain is suspended or restored from a file the
 * domain's OS has no idea that there was a big gap in the time.
 * Depending on how long the gap was, NTP might not be able to
 * resynchronize the guest.
 *
 * This API tries to set guest time to the given value. The time
 * to set (@seconds and @nseconds) should be in seconds relative
 * to the Epoch of 1970-01-01 00:00:00 in UTC.
 *
 * Please note that some hypervisors may require guest agent to
 * be configured and running in order to be able to run this API.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainSetTime(virDomainPtr dom,
                 long long seconds,
                 unsigned int nseconds,
                 unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "seconds=%lld, nseconds=%u, flags=%x",
                     seconds, nseconds, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);

    if (dom->conn->driver->domainSetTime) {
        int ret = dom->conn->driver->domainSetTime(dom, seconds,
                                                   nseconds, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainSetUserPassword:
 * @dom: a domain object
 * @user: the username that will get a new password
 * @password: the password to set
 * @flags: bitwise-OR of virDomainSetUserPasswordFlags
 *
 * Sets the @user password to the value specified by @password.
 * If @flags contain VIR_DOMAIN_PASSWORD_ENCRYPTED, the password
 * is assumed to be encrypted by the method required by the guest OS.
 *
 * Please note that some hypervisors may require guest agent to
 * be configured and running in order to be able to run this API.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainSetUserPassword(virDomainPtr dom,
                         const char *user,
                         const char *password,
                         unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "user=%s, password=%s, flags=%x",
                     NULLSTR(user), NULLSTR(password), flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);
    virCheckNonNullArgGoto(user, error);
    virCheckNonNullArgGoto(password, error);

    if (dom->conn->driver->domainSetUserPassword) {
        int ret = dom->conn->driver->domainSetUserPassword(dom, user, password,
                                                           flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virConnectGetDomainCapabilities:
 * @conn: pointer to the hypervisor connection
 * @emulatorbin: path to emulator
 * @arch: domain architecture
 * @machine: machine type
 * @virttype: virtualization type
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Prior creating a domain (for instance via virDomainCreateXML
 * or virDomainDefineXML) it may be suitable to know what the
 * underlying emulator and/or libvirt is capable of. For
 * instance, if host, libvirt and qemu is capable of VFIO
 * passthrough and so on.
 *
 * Returns NULL in case of error or an XML string
 * defining the capabilities.
 */
char *
virConnectGetDomainCapabilities(virConnectPtr conn,
                                const char *emulatorbin,
                                const char *arch,
                                const char *machine,
                                const char *virttype,
                                unsigned int flags)
{
    VIR_DEBUG("conn=%p, emulatorbin=%s, arch=%s, "
              "machine=%s, virttype=%s, flags=%x",
              conn, NULLSTR(emulatorbin), NULLSTR(arch),
              NULLSTR(machine), NULLSTR(virttype), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetDomainCapabilities) {
        char *ret;
        ret = conn->driver->connectGetDomainCapabilities(conn, emulatorbin,
                                                         arch, machine,
                                                         virttype, flags);
        if (!ret)
            goto error;
        VIR_DEBUG("conn=%p, ret=%s", conn, ret);
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectGetAllDomainStats:
 * @conn: pointer to the hypervisor connection
 * @stats: stats to return, binary-OR of virDomainStatsTypes
 * @retStats: Pointer that will be filled with the array of returned stats
 * @flags: extra flags; binary-OR of virConnectGetAllDomainStatsFlags
 *
 * Query statistics for all domains on a given connection.
 *
 * Report statistics of various parameters for a running VM according to @stats
 * field. The statistics are returned as an array of structures for each queried
 * domain. The structure contains an array of typed parameters containing the
 * individual statistics. The typed parameter name for each statistic field
 * consists of a dot-separated string containing name of the requested group
 * followed by a group specific description of the statistic value.
 *
 * The statistic groups are enabled using the @stats parameter which is a
 * binary-OR of enum virDomainStatsTypes. The following groups are available
 * (although not necessarily implemented for each hypervisor):
 *
 * VIR_DOMAIN_STATS_STATE:
 *     Return domain state and reason for entering that state. The typed
 *     parameter keys are in this format:
 *
 *     "state.state" - state of the VM, returned as int from virDomainState enum
 *     "state.reason" - reason for entering given state, returned as int from
 *                      virDomain*Reason enum corresponding to given state.
 *
 * VIR_DOMAIN_STATS_CPU_TOTAL:
 *     Return CPU statistics and usage information. The typed parameter keys
 *     are in this format:
 *
 *     "cpu.time" - total cpu time spent for this domain in nanoseconds
 *                  as unsigned long long.
 *     "cpu.user" - user cpu time spent in nanoseconds as unsigned long long.
 *     "cpu.system" - system cpu time spent in nanoseconds as unsigned long
 *                    long.
 *
 * VIR_DOMAIN_STATS_BALLOON:
 *     Return memory balloon device information.
 *     The typed parameter keys are in this format:
 *
 *     "balloon.current" - the memory in kiB currently used
 *                         as unsigned long long.
 *     "balloon.maximum" - the maximum memory in kiB allowed
 *                         as unsigned long long.
 *
 * VIR_DOMAIN_STATS_VCPU:
 *     Return virtual CPU statistics.
 *     Due to VCPU hotplug, the vcpu.<num>.* array could be sparse.
 *     The actual size of the array corresponds to "vcpu.current".
 *     The array size will never exceed "vcpu.maximum".
 *     The typed parameter keys are in this format:
 *
 *     "vcpu.current" - current number of online virtual CPUs as unsigned int.
 *     "vcpu.maximum" - maximum number of online virtual CPUs as unsigned int.
 *     "vcpu.<num>.state" - state of the virtual CPU <num>, as int
 *                          from virVcpuState enum.
 *     "vcpu.<num>.time" - virtual cpu time spent by virtual CPU <num>
 *                         as unsigned long long.
 *
 * VIR_DOMAIN_STATS_INTERFACE:
 *     Return network interface statistics.
 *     The typed parameter keys are in this format:
 *
 *     "net.count" - number of network interfaces on this domain
 *                   as unsigned int.
 *     "net.<num>.name" - name of the interface <num> as string.
 *     "net.<num>.rx.bytes" - bytes received as unsigned long long.
 *     "net.<num>.rx.pkts" - packets received as unsigned long long.
 *     "net.<num>.rx.errs" - receive errors as unsigned long long.
 *     "net.<num>.rx.drop" - receive packets dropped as unsigned long long.
 *     "net.<num>.tx.bytes" - bytes transmitted as unsigned long long.
 *     "net.<num>.tx.pkts" - packets transmitted as unsigned long long.
 *     "net.<num>.tx.errs" - transmission errors as unsigned long long.
 *     "net.<num>.tx.drop" - transmit packets dropped as unsigned long long.
 *
 * VIR_DOMAIN_STATS_BLOCK:
 *     Return block devices statistics.  By default,
 *     this information is limited to the active layer of each <disk> of the
 *     domain (where block.count is equal to the number of disks), but adding
 *     VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING to @flags will expand the
 *     array to cover backing chains (block.count corresponds to the number
 *     of host resources used together to provide the guest disks).
 *     The typed parameter keys are in this format:
 *
 *     "block.count" - number of block devices in the subsequent list,
 *                     as unsigned int.
 *     "block.<num>.name" - name of the block device <num> as string.
 *                          matches the target name (vda/sda/hda) of the
 *                          block device.  If the backing chain is listed,
 *                          this name is the same for all host resources tied
 *                          to the same guest device.
 *     "block.<num>.backingIndex" - unsigned int giving the <backingStore>
 *                                   index, only used when backing images
 *                                   are listed.
 *     "block.<num>.path" - string describing the source of block device <num>,
 *                          if it is a file or block device (omitted for network
 *                          sources and drives with no media inserted).
 *     "block.<num>.rd.reqs" - number of read requests as unsigned long long.
 *     "block.<num>.rd.bytes" - number of read bytes as unsigned long long.
 *     "block.<num>.rd.times" - total time (ns) spent on reads as
 *                              unsigned long long.
 *     "block.<num>.wr.reqs" - number of write requests as unsigned long long.
 *     "block.<num>.wr.bytes" - number of written bytes as unsigned long long.
 *     "block.<num>.wr.times" - total time (ns) spent on writes as
 *                              unsigned long long.
 *     "block.<num>.fl.reqs" - total flush requests as unsigned long long.
 *     "block.<num>.fl.times" - total time (ns) spent on cache flushing as
 *                              unsigned long long.
 *     "block.<num>.errors" - Xen only: the 'oo_req' value as
 *                            unsigned long long.
 *     "block.<num>.allocation" - offset of the highest written sector
 *                                as unsigned long long.
 *     "block.<num>.capacity" - logical size in bytes of the block device
 *                              backing image as unsigned long long.
 *     "block.<num>.physical" - physical size in bytes of the container of the
 *                              backing image as unsigned long long.
 *
 * VIR_DOMAIN_STATS_PERF:
 *     Return perf event statistics.
 *     The typed parameter keys are in this format:
 *
 *     "perf.cmt" - the usage of l3 cache (bytes) by applications running on
 *                  the platform as unsigned long long. It is produced by cmt
 *                  perf event.
 *     "perf.mbmt" - the total system bandwidth (bytes/s) from one level of
 *                   cache to another as unsigned long long. It is produced
 *                   by mbmt perf event.
 *     "perf.mbml" - the amount of data (bytes/s) sent through the memory
 *                   controller on the socket as unsigned long long. It is
 *                   produced by mbml perf event.
 *     "perf.cache_misses" - the count of cache misses as unsigned long long.
 *                           It is produced by cache_misses perf event.
 *     "perf.cache_references" - the count of cache hits as unsigned long long.
 *                               It is produced by cache_references perf event.
 *     "perf.instructions" - The count of instructions as unsigned long long.
 *                           It is produced by instructions perf event.
 *     "perf.cpu_cycles" - The count of cpu cycles (total/elapsed) as an
 *                         unsigned long long. It is produced by cpu_cycles
 *                         perf event.
 *     "perf.branch_instructions" - The count of branch instructions as
 *                                  unsigned long long. It is produced by
 *                                  branch_instructions perf event.
 *     "perf.branch_misses" - The count of branch misses as unsigned long
 *                            long. It is produced by branch_misses perf event.
 *     "perf.bus_cycles" - The count of bus cycles as unsigned long
 *                         long. It is produced by bus_cycles perf event.
 *     "perf.stalled_cycles_frontend" - The count of stalled cpu cycles in the
 *                                      frontend of the instruction processor
 *                                      pipeline as unsigned long long. It is
 *                                      produced by stalled_cycles_frontend
 *                                      perf event.
 *     "perf.stalled_cycles_backend"  - The count of stalled cpu cycles in the
 *                                      backend of the instruction processor
 *                                      pipeline as unsigned long long. It is
 *                                      produced by stalled_cycles_backend
 *                                      perf event.
 *     "perf.ref_cpu_cycles" - The count of total cpu cycles not affected by
 *                             CPU frequency scaling by applications running
 *                             as unsigned long long. It is produced by the
 *                             ref_cpu_cycles perf event.
 *
 * Note that entire stats groups or individual stat fields may be missing from
 * the output in case they are not supported by the given hypervisor, are not
 * applicable for the current state of the guest domain, or their retrieval
 * was not successful.
 *
 * Using 0 for @stats returns all stats groups supported by the given
 * hypervisor.
 *
 * Specifying VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS as @flags makes
 * the function return error in case some of the stat types in @stats were
 * not recognized by the daemon.  However, even with this flag, a hypervisor
 * may omit individual fields within a known group if the information is not
 * available; as an extreme example, a supported group may produce zero
 * fields for offline domains if the statistics are meaningful only for a
 * running domain.
 *
 * Similarly to virConnectListAllDomains, @flags can contain various flags to
 * filter the list of domains to provide stats for.
 *
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_ACTIVE selects online domains while
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_INACTIVE selects offline ones.
 *
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_PERSISTENT and
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_TRANSIENT allow to filter the list
 * according to their persistence.
 *
 * To filter the list of VMs by domain state @flags can contain
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_RUNNING,
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_PAUSED,
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_SHUTOFF and/or
 * VIR_CONNECT_GET_ALL_DOMAINS_STATS_OTHER for all other states.
 *
 * Returns the count of returned statistics structures on success, -1 on error.
 * The requested data are returned in the @retStats parameter. The returned
 * array should be freed by the caller. See virDomainStatsRecordListFree.
 */
int
virConnectGetAllDomainStats(virConnectPtr conn,
                            unsigned int stats,
                            virDomainStatsRecordPtr **retStats,
                            unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, stats=0x%x, retStats=%p, flags=0x%x",
              conn, stats, retStats, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(retStats, cleanup);

    if (!conn->driver->connectGetAllDomainStats) {
        virReportUnsupportedError();
        goto cleanup;
    }

    ret = conn->driver->connectGetAllDomainStats(conn, NULL, 0, stats,
                                                 retStats, flags);

 cleanup:
    if (ret < 0)
        virDispatchError(conn);

    return ret;
}


/**
 * virDomainListGetStats:
 * @doms: NULL terminated array of domains
 * @stats: stats to return, binary-OR of virDomainStatsTypes
 * @retStats: Pointer that will be filled with the array of returned stats
 * @flags: extra flags; binary-OR of virConnectGetAllDomainStatsFlags
 *
 * Query statistics for domains provided by @doms. Note that all domains in
 * @doms must share the same connection.
 *
 * Report statistics of various parameters for a running VM according to @stats
 * field. The statistics are returned as an array of structures for each queried
 * domain. The structure contains an array of typed parameters containing the
 * individual statistics. The typed parameter name for each statistic field
 * consists of a dot-separated string containing name of the requested group
 * followed by a group specific description of the statistic value.
 *
 * The statistic groups are enabled using the @stats parameter which is a
 * binary-OR of enum virDomainStatsTypes. The stats groups are documented
 * in virConnectGetAllDomainStats.
 *
 * Using 0 for @stats returns all stats groups supported by the given
 * hypervisor.
 *
 * Specifying VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS as @flags makes
 * the function return error in case some of the stat types in @stats were
 * not recognized by the daemon.  However, even with this flag, a hypervisor
 * may omit individual fields within a known group if the information is not
 * available; as an extreme example, a supported group may produce zero
 * fields for offline domains if the statistics are meaningful only for a
 * running domain.
 *
 * Note that any of the domain list filtering flags in @flags may be rejected
 * by this function.
 *
 * Returns the count of returned statistics structures on success, -1 on error.
 * The requested data are returned in the @retStats parameter. The returned
 * array should be freed by the caller. See virDomainStatsRecordListFree.
 * Note that the count of returned stats may be less than the domain count
 * provided via @doms.
 */
int
virDomainListGetStats(virDomainPtr *doms,
                      unsigned int stats,
                      virDomainStatsRecordPtr **retStats,
                      unsigned int flags)
{
    virConnectPtr conn = NULL;
    virDomainPtr *nextdom = doms;
    unsigned int ndoms = 0;
    int ret = -1;

    VIR_DEBUG("doms=%p, stats=0x%x, retStats=%p, flags=0x%x",
              doms, stats, retStats, flags);

    virResetLastError();

    virCheckNonNullArgGoto(doms, cleanup);
    virCheckNonNullArgGoto(retStats, cleanup);

    if (!*doms) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("doms array in %s must contain at least one domain"),
                       __FUNCTION__);
        goto cleanup;
    }

    conn = doms[0]->conn;
    virCheckConnectReturn(conn, -1);

    if (!conn->driver->connectGetAllDomainStats) {
        virReportUnsupportedError();
        goto cleanup;
    }

    while (*nextdom) {
        virDomainPtr dom = *nextdom;

        virCheckDomainGoto(dom, cleanup);

        if (dom->conn != conn) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("domains in 'doms' array must belong to a "
                             "single connection"));
            goto cleanup;
        }

        ndoms++;
        nextdom++;
    }

    ret = conn->driver->connectGetAllDomainStats(conn, doms, ndoms,
                                                 stats, retStats, flags);

 cleanup:
    if (ret < 0)
        virDispatchError(conn);
    return ret;
}


/**
 * virDomainStatsRecordListFree:
 * @stats: NULL terminated array of virDomainStatsRecords to free
 *
 * Convenience function to free a list of domain stats returned by
 * virDomainListGetStats and virConnectGetAllDomainStats.
 */
void
virDomainStatsRecordListFree(virDomainStatsRecordPtr *stats)
{
    virDomainStatsRecordPtr *next;

    if (!stats)
        return;

    for (next = stats; *next; next++) {
        virTypedParamsFree((*next)->params, (*next)->nparams);
        virDomainFree((*next)->dom);
        VIR_FREE(*next);
    }

    VIR_FREE(stats);
}


/**
 * virDomainGetFSInfo:
 * @dom: a domain object
 * @info: a pointer to a variable to store an array of mount points information
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get a list of mapping information for each mounted file systems within the
 * specified guest and the disks.
 *
 * Returns the number of returned mount points, or -1 in case of error.
 * On success, the array of the information is stored into @info. The caller is
 * responsible for calling virDomainFSInfoFree() on each array element, then
 * calling free() on @info. On error, @info is set to NULL.
 */
int
virDomainGetFSInfo(virDomainPtr dom,
                   virDomainFSInfoPtr **info,
                   unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "info=%p, flags=%x", info, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    virCheckReadOnlyGoto(dom->conn->flags, error);
    virCheckNonNullArgGoto(info, error);
    *info = NULL;

    if (dom->conn->driver->domainGetFSInfo) {
        int ret = dom->conn->driver->domainGetFSInfo(dom, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainFSInfoFree:
 * @info: pointer to a FSInfo object
 *
 * Frees all the memory occupied by @info.
 */
void
virDomainFSInfoFree(virDomainFSInfoPtr info)
{
    size_t i;

    if (!info)
        return;

    VIR_FREE(info->mountpoint);
    VIR_FREE(info->name);
    VIR_FREE(info->fstype);

    for (i = 0; i < info->ndevAlias; i++)
        VIR_FREE(info->devAlias[i]);
    VIR_FREE(info->devAlias);

    VIR_FREE(info);
}

/**
 * virDomainInterfaceAddresses:
 * @dom: domain object
 * @ifaces: pointer to an array of pointers pointing to interface objects
 * @source: one of the virDomainInterfaceAddressesSource constants
 * @flags: currently unused, pass zero
 *
 * Return a pointer to the allocated array of pointers to interfaces
 * present in given domain along with their IP and MAC addresses. Note that
 * single interface can have multiple or even 0 IP addresses.
 *
 * This API dynamically allocates the virDomainInterfacePtr struct based on
 * how many interfaces domain @dom has, usually there's 1:1 correlation. The
 * count of the interfaces is returned as the return value.
 *
 * If @source is VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, the DHCP lease
 * file associated with any virtual networks will be examined to obtain
 * the interface addresses. This only returns data for interfaces which
 * are connected to virtual networks managed by libvirt.
 *
 * If @source is VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT, a configured
 * guest agent is needed for successful return from this API. Moreover, if
 * guest agent is used then the interface name is the one seen by guest OS.
 * To match such interface with the one from @dom XML use MAC address or IP
 * range.
 *
 * @ifaces->name and @ifaces->hwaddr are never NULL.
 *
 * The caller *must* free @ifaces when no longer needed. Usual use case
 * looks like this:
 *
 *   virDomainInterfacePtr *ifaces = NULL;
 *   int ifaces_count = 0;
 *   size_t i, j;
 *   virDomainPtr dom = ... obtain a domain here ...;
 *
 *   if ((ifaces_count = virDomainInterfaceAddresses(dom, &ifaces,
 *            VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)) < 0)
 *       goto cleanup;
 *
 *  ... do something with returned values, for example:
 *
 *   for (i = 0; i < ifaces_count; i++) {
 *       printf("name: %s", ifaces[i]->name);
 *       if (ifaces[i]->hwaddr)
 *           printf(" hwaddr: %s", ifaces[i]->hwaddr);
 *
 *       for (j = 0; j < ifaces[i]->naddrs; j++) {
 *           virDomainIPAddressPtr ip_addr = ifaces[i]->addrs + j;
 *           printf("[addr: %s prefix: %d type: %d]",
 *                  ip_addr->addr, ip_addr->prefix, ip_addr->type);
 *       }
 *       printf("\n");
 *   }
 *
 *   cleanup:
 *       if (ifaces && ifaces_count > 0)
 *           for (i = 0; i < ifaces_count; i++)
 *               virDomainInterfaceFree(ifaces[i]);
 *       free(ifaces);
 *
 * Returns the number of interfaces on success, -1 in case of error.
 */
int
virDomainInterfaceAddresses(virDomainPtr dom,
                            virDomainInterfacePtr **ifaces,
                            unsigned int source,
                            unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "ifaces=%p, source=%d, flags=%x", ifaces, source, flags);

    virResetLastError();

    if (ifaces)
        *ifaces = NULL;
    virCheckDomainReturn(dom, -1);
    virCheckNonNullArgGoto(ifaces, error);
    if (source == VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT)
        virCheckReadOnlyGoto(dom->conn->flags, error);

    if (dom->conn->driver->domainInterfaceAddresses) {
        int ret;
        ret = dom->conn->driver->domainInterfaceAddresses(dom, ifaces, source, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

 error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainInterfaceFree:
 * @iface: an interface object
 *
 * Free the interface object. The data structure is
 * freed and should not be used thereafter. If @iface
 * is NULL, then this method has no effect.
 */
void
virDomainInterfaceFree(virDomainInterfacePtr iface)
{
    size_t i;

    if (!iface)
        return;

    VIR_FREE(iface->name);
    VIR_FREE(iface->hwaddr);

    for (i = 0; i < iface->naddrs; i++)
        VIR_FREE(iface->addrs[i].addr);
    VIR_FREE(iface->addrs);

    VIR_FREE(iface);
}


/**
 * virDomainGetGuestVcpus:
 * @domain: pointer to domain object
 * @params: pointer that will be filled with an array of typed parameters
 * @nparams: pointer filled with number of elements in @params
 * @flags: currently unused, callers shall pass 0
 *
 * Queries the guest agent for state and information regarding vCPUs from
 * guest's perspective. The reported data depends on the guest agent
 * implementation.
 *
 * Reported fields stored in @params:
 * 'vcpus': string containing bitmap representing vCPU ids as reported by the
 *          guest
 * 'online': string containing bitmap representing online vCPUs as reported
 *           by the guest agent.
 * 'offlinable': string containing bitmap representing ids of vCPUs that can be
 *               offlined
 *
 * This API requires the VM to run. The caller is responsible for calling
 * virTypedParamsFree to free memory returned in @params.
 *
 * Returns 0 on success, -1 on error.
 */
int
virDomainGetGuestVcpus(virDomainPtr domain,
                       virTypedParameterPtr *params,
                       unsigned int *nparams,
                       unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p, flags=%x",
                     params, nparams, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);

    if (domain->conn->driver->domainGetGuestVcpus) {
        int ret;
        ret = domain->conn->driver->domainGetGuestVcpus(domain, params, nparams,
                                                        flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetGuestVcpus:
 * @domain: pointer to domain object
 * @cpumap: text representation of a bitmap of vcpus to set
 * @state: 0 to disable/1 to enable cpus described by @cpumap
 * @flags: currently unused, callers shall pass 0
 *
 * Sets state of individual vcpus described by @cpumap via guest agent. Other
 * vcpus are not modified.
 *
 * This API requires the VM to run. Various hypervisors or guest agent
 * implementation may limit to operate on just 1 vCPU per call.
 *
 * @cpumap is a list of vCPU numbers. Its syntax is a comma separated list and
 * a special markup using '-' and '^' (ex. '0-4', '0-3,^2'). The '-' denotes
 * the range and the '^' denotes exclusive. The expression is sequentially
 * evaluated, so "0-15,^8" is identical to "9-14,0-7,15" but not identical to
 * "^8,0-15".
 *
 * Note that OSes (notably Linux) may require vCPU 0 to stay online to support
 * low-level features a S3 sleep.
 *
 * Returns 0 on success, -1 on error.
 */
int
virDomainSetGuestVcpus(virDomainPtr domain,
                       const char *cpumap,
                       int state,
                       unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "cpumap='%s' state=%x flags=%x",
                     NULLSTR(cpumap), state, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    virCheckReadOnlyGoto(domain->conn->flags, error);

    virCheckNonNullArgGoto(cpumap, error);

    if (domain->conn->driver->domainSetGuestVcpus) {
        int ret;
        ret = domain->conn->driver->domainSetGuestVcpus(domain, cpumap, state,
                                                        flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}
