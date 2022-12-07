/*
 * libvirt-domain-snapshot.c: entry points for virDomainSnapshotPtr APIs
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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

VIR_LOG_INIT("libvirt.domain-snapshot");

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

/**
 * virDomainSnapshotGetName:
 * @snapshot: a snapshot object
 *
 * Get the public name for that snapshot
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * as its lifetime will be the same as the snapshot object.
 *
 * Since: 0.9.5
 */
const char *
virDomainSnapshotGetName(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, NULL);

    return snapshot->name;
}


/**
 * virDomainSnapshotGetDomain:
 * @snapshot: a snapshot object
 *
 * Provides the domain pointer associated with a snapshot.  The
 * reference counter on the domain is not increased by this
 * call.
 *
 * Returns the domain or NULL.
 *
 * Since: 0.9.5
 */
virDomainPtr
virDomainSnapshotGetDomain(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, NULL);

    return snapshot->domain;
}


/**
 * virDomainSnapshotGetConnect:
 * @snapshot: a snapshot object
 *
 * Provides the connection pointer associated with a snapshot.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the connection or NULL.
 *
 * Since: 0.9.5
 */
virConnectPtr
virDomainSnapshotGetConnect(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, NULL);

    return snapshot->domain->conn;
}


/**
 * virDomainSnapshotCreateXML:
 * @domain: a domain object
 * @xmlDesc: string containing an XML description of the domain snapshot
 * @flags: bitwise-OR of virDomainSnapshotCreateFlags
 *
 * Creates a new snapshot of a domain based on the snapshot xml
 * contained in xmlDesc, with a top-level element <domainsnapshot>.
 *
 * If @flags is 0, the domain can be active, in which case the
 * snapshot will be a full system snapshot (capturing both disk state,
 * and runtime VM state such as RAM contents), where reverting to the
 * snapshot is
 * the same as resuming from hibernation (TCP connections may have
 * timed out, but everything else picks up where it left off); or
 * the domain can be inactive, in which case the snapshot includes
 * just the disk state prior to booting.  The newly created snapshot
 * becomes current (see virDomainSnapshotCurrent()), and is a child
 * of any previous current snapshot.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE, then @xmlDesc
 * is validated against the <domainsnapshot> XML schema.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE, then this
 * is a request to reinstate snapshot metadata that was previously
 * captured from virDomainSnapshotGetXMLDesc() before removing that
 * metadata, rather than creating a new snapshot.  This can be used to
 * recreate a snapshot hierarchy on a destination, then remove it on
 * the source, in order to allow migration (since migration normally
 * fails if snapshot metadata still remains on the source machine).
 * Note that while original creation can omit a number of elements
 * from @xmlDesc (and libvirt will supply sane defaults based on the
 * domain state at that point in time), a redefinition must supply
 * more elements (as the domain may have changed in the meantime, so
 * that libvirt no longer has a way to resupply correct
 * defaults). When redefining snapshot metadata, the domain's current
 * snapshot will not be altered unless the
 * VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT flag is also present.  It is an
 * error to request the VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT flag
 * without VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.  On some hypervisors,
 * redefining an existing snapshot can be used to alter host-specific
 * portions of the domain XML to be used during revert (such as
 * backing filenames associated with disk devices), but must not alter
 * guest-visible layout.  When redefining a snapshot name that does
 * not exist, the hypervisor may validate that reverting to the
 * snapshot appears to be possible (for example, disk images have
 * snapshot contents by the requested name).  Not all hypervisors
 * support these flags.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA, then the
 * domain's disk images are modified according to @xmlDesc, but
 * libvirt does not track any metadata (similar to immediately calling
 * virDomainSnapshotDelete() with
 * VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY).  This flag is
 * incompatible with VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_HALT, then the domain
 * will be inactive after the snapshot completes, regardless of whether
 * it was active before; otherwise, a running domain will still be
 * running after the snapshot.  This flag is invalid on transient domains,
 * and is incompatible with VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_LIVE, then the domain
 * is not paused while creating the snapshot. This increases the size
 * of the memory dump file, but reduces downtime of the guest while
 * taking the snapshot. Some hypervisors only support this flag during
 * external snapshots.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY, then the
 * snapshot will be limited to the disks described in @xmlDesc, and no
 * VM state will be saved.  For an active guest, the disk image may be
 * inconsistent (as if power had been pulled), and specifying this
 * with the VIR_DOMAIN_SNAPSHOT_CREATE_HALT flag risks data loss.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE, then the
 * libvirt will attempt to use guest agent to freeze and thaw all
 * file systems in use within domain OS. However, if the guest agent
 * is not present, an error is thrown. Moreover, this flag requires
 * VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY to be passed as well.
 * For better control and error recovery users should invoke virDomainFSFreeze
 * manually before taking the snapshot and then virDomainFSThaw to restore the
 * VM rather than using VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE.
 *
 * By default, if the snapshot involves external files, and any of the
 * destination files already exist as a non-empty regular file, the
 * snapshot is rejected to avoid losing contents of those files.
 * However, if @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT,
 * then the destination files must be pre-created manually with
 * the correct image format and metadata including backing store path
 * (this allows a management app to pre-create files with relative backing
 * file names, rather than the default of creating with absolute backing
 * file names). Note that only the file specified in the snapshot XML is
 * inserted as a snapshot thus setting incorrect metadata in the pre-created
 * image may lead to the VM being unable to start or other block jobs may fail.
 *
 * Be aware that although libvirt prefers to report errors up front with
 * no other effect, some hypervisors have certain types of failures where
 * the overall command can easily fail even though the guest configuration
 * was partially altered (for example, if a disk snapshot request for two
 * disks fails on the second disk, but the first disk alteration cannot be
 * rolled back).  If this API call fails, it is therefore normally
 * necessary to follow up with virDomainGetXMLDesc() and check each disk
 * to determine if any partial changes occurred.  However, if @flags
 * contains VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC, then libvirt guarantees
 * that this command will not alter any disks unless the entire set of
 * changes can be done atomically, making failure recovery simpler (note
 * that it is still possible to fail after disks have changed, but only
 * in the much rarer cases of running out of memory or disk space).
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation; in that case, use virDomainBlockJobAbort()
 * to stop the block copy first.
 *
 * virDomainSnapshotFree should be used to free the resources after the
 * snapshot object is no longer needed.
 *
 * Returns an (opaque) new virDomainSnapshotPtr on success or NULL on
 * failure.
 *
 * Since: 0.8.0
 */
virDomainSnapshotPtr
virDomainSnapshotCreateXML(virDomainPtr domain,
                           const char *xmlDesc,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlDesc=%s, flags=0x%x", xmlDesc, flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    VIR_REQUIRE_FLAG_GOTO(VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT,
                          VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE,
                          error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE,
                             VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA,
                             error);
    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE,
                             VIR_DOMAIN_SNAPSHOT_CREATE_HALT,
                             error);

    if (conn->driver->domainSnapshotCreateXML) {
        virDomainSnapshotPtr ret;
        ret = conn->driver->domainSnapshotCreateXML(domain, xmlDesc, flags);
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
 * virDomainSnapshotGetXMLDesc:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of supported virDomainSnapshotXMLFlags
 *
 * Provide an XML description of the domain snapshot, with a top-level
 * element of <domainsnapshot>.
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_SNAPSHOT_XML_SECURE; this flag is rejected on read-only
 * connections.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance or NULL in case
 * of error. The caller must free() the returned value.
 *
 * Since: 0.8.0
 */
char *
virDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, NULL);
    conn = snapshot->domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) &&
        (flags & VIR_DOMAIN_SNAPSHOT_XML_SECURE)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("virDomainSnapshotGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainSnapshotGetXMLDesc) {
        char *ret;
        ret = conn->driver->domainSnapshotGetXMLDesc(snapshot, flags);
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
 * virDomainSnapshotNum:
 * @domain: a domain object
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Provides the number of domain snapshots for this domain.
 *
 * This function will accept VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL in
 * @flags only if virDomainSnapshotListNames() can honor it, although
 * the flag has no other effect here.
 *
 * By default, this command covers all snapshots. It is also possible
 * to limit things to just snapshots with no parents, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are
 * provided via the same @flags values as documented in
 * virDomainListAllSnapshots().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 *
 * Since: 0.8.0
 */
int
virDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=0x%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);

    conn = domain->conn;
    if (conn->driver->domainSnapshotNum) {
        int ret = conn->driver->domainSnapshotNum(domain, flags);
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
 * virDomainSnapshotListNames:
 * @domain: a domain object
 * @names: array to collect the list of names of snapshots
 * @nameslen: size of @names
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots for the given domain, and store
 * their names in @names.  The value to use for @nameslen can be determined
 * by virDomainSnapshotNum() with the same @flags.
 *
 * If @flags contains VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL, and no
 * other connection is modifying snapshots, then it is guaranteed that
 * for any snapshot in the resulting list, no snapshots later in the
 * list can be reached by a sequence of virDomainSnapshotGetParent()
 * starting from that earlier snapshot; otherwise, the order of
 * snapshots in the resulting list is unspecified.
 *
 * By default, this command covers all snapshots. It is also possible
 * to limit things to just snapshots with no parents, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are
 * provided via the same @flags values as documented in
 * virDomainListAllSnapshots().
 *
 * Note that this command is inherently racy: another connection can
 * define a new snapshot between a call to virDomainSnapshotNum() and
 * this call.  You are only guaranteed that all currently defined
 * snapshots were listed if the return is less than @nameslen.  Likewise,
 * you should be prepared for virDomainSnapshotLookupByName() to fail when
 * converting a name from this call into a snapshot object, if another
 * connection deletes the snapshot in the meantime.
 *
 * The use of this function is discouraged. Instead, use
 * virDomainListAllSnapshots().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 * The caller is responsible to call free() for each member of the array.
 *
 * Since: 0.8.0
 */
int
virDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "names=%p, nameslen=%d, flags=0x%x",
                     names, nameslen, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArrayArgGoto(names, nameslen, error);
    virCheckNonNegativeArgGoto(nameslen, error);

    if (conn->driver->domainSnapshotListNames) {
        int ret = conn->driver->domainSnapshotListNames(domain, names,
                                                        nameslen, flags);
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
 * virDomainListAllSnapshots:
 * @domain: a domain object
 * @snaps: pointer to variable to store the array containing snapshot objects
 *         or NULL if the list is not required (just returns number of
 *         snapshots)
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots for the given domain and allocate
 * an array to store those objects.  This API solves the race inherent in
 * virDomainSnapshotListNames().
 *
 * If @flags contains VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL and @snaps
 * is non-NULL, and no other connection is modifying snapshots, then
 * it is guaranteed that for any snapshot in the resulting list, no
 * snapshots later in the list can be reached by a sequence of
 * virDomainSnapshotGetParent() starting from that earlier snapshot;
 * otherwise, the order of snapshots in the resulting list is
 * unspecified.
 *
 * By default, this command covers all snapshots. It is also possible
 * to limit things to just snapshots with no parents, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are
 * provided in groups listed below. Within a group, bits are mutually
 * exclusive, where all possible snapshots are described by exactly
 * one bit from the group. Some hypervisors might reject particular
 * flags where it cannot make a distinction for filtering. If the set
 * of filter flags selected forms an impossible combination, the
 * hypervisor may return either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 and sets @snaps to
 * NULL in case of error.  On success, the array stored into @snaps is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virDomainSnapshotFree() on each array element, then calling
 * free() on @snaps.
 *
 * Since: 0.9.13
 */
int
virDomainListAllSnapshots(virDomainPtr domain, virDomainSnapshotPtr **snaps,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "snaps=%p, flags=0x%x", snaps, flags);

    virResetLastError();

    if (snaps)
        *snaps = NULL;

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    if (conn->driver->domainListAllSnapshots) {
        int ret = conn->driver->domainListAllSnapshots(domain, snaps, flags);
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
 * virDomainSnapshotNumChildren:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Provides the number of child snapshots for this domain snapshot.
 *
 * This function will accept VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL in
 * @flags only if virDomainSnapshotListChildrenNames() can honor it,
 * although the flag has no other effect here.
 *
 * By default, this command covers only direct children. It is also
 * possible to expand things to cover all descendants, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS. Additional filters
 * are provided via the same @flags values as documented in
 * virDomainSnapshotListAllChildren().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 *
 * Since: 0.9.7
 */
int
virDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotNumChildren) {
        int ret = conn->driver->domainSnapshotNumChildren(snapshot, flags);
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
 * virDomainSnapshotListChildrenNames:
 * @snapshot: a domain snapshot object
 * @names: array to collect the list of names of snapshots
 * @nameslen: size of @names
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots that are children of the given
 * snapshot, and store their names in @names.  The value to use for
 * @nameslen can be determined by virDomainSnapshotNumChildren() with
 * the same @flags.
 *
 * If @flags lacks VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS or contains
 * VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL, and no other connection is
 * modifying snapshots, then it is guaranteed that for any snapshot in
 * the resulting list, no snapshots later in the list can be reached
 * by a sequence of virDomainSnapshotGetParent() starting from that
 * earlier snapshot; otherwise, the order of snapshots in the
 * resulting list is unspecified.
 *
 * By default, this command covers only direct children. It is also
 * possible to expand things to cover all descendants, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS. Additional filters
 * are provided via the same @flags values as documented in
 * virDomainSnapshotListAllChildren().
 *
 * Note that this command is inherently racy: another connection can
 * define a new snapshot between a call to virDomainSnapshotNumChildren()
 * and this call.  You are only guaranteed that all currently defined
 * snapshots were listed if the return is less than @nameslen.  Likewise,
 * you should be prepared for virDomainSnapshotLookupByName() to fail when
 * converting a name from this call into a snapshot object, if another
 * connection deletes the snapshot in the meantime.
 *
 * The use of this function is discouraged. Instead, use
 * virDomainSnapshotListAllChildren().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 * The caller is responsible to call free() for each member of the array.
 *
 * Since: 0.9.7
 */
int
virDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                   char **names, int nameslen,
                                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, names=%p, nameslen=%d, flags=0x%x",
              snapshot, names, nameslen, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    virCheckNonNullArrayArgGoto(names, nameslen, error);
    virCheckNonNegativeArgGoto(nameslen, error);

    if (conn->driver->domainSnapshotListChildrenNames) {
        int ret = conn->driver->domainSnapshotListChildrenNames(snapshot,
                                                                names,
                                                                nameslen,
                                                                flags);
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
 * virDomainSnapshotListAllChildren:
 * @snapshot: a domain snapshot object
 * @snaps: pointer to variable to store the array containing snapshot objects
 *         or NULL if the list is not required (just returns number of
 *         snapshots)
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots that are children of the given
 * snapshot, and allocate an array to store those objects.  This API solves
 * the race inherent in virDomainSnapshotListChildrenNames().
 *
 * If @flags lacks VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS or contains
 * VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL, @snaps is non-NULL, and no
 * other connection is modifying snapshots, then it is guaranteed that
 * for any snapshot in the resulting list, no snapshots later in the
 * list can be reached by a sequence of virDomainSnapshotGetParent()
 * starting from that earlier snapshot; otherwise, the order of
 * snapshots in the resulting list is unspecified.
 *
 * By default, this command covers only direct children. It is also
 * possible to expand things to cover all descendants, when @flags
 * includes VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS. Additional filters
 * are provided via the remaining @flags values as documented in
 * virDomainListAllSnapshots(), with the exception that
 * VIR_DOMAIN_SNAPSHOT_LIST_ROOTS is not supported (in fact,
 * VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS has the same bit value but
 * opposite semantics of widening rather than narrowing the listing).
 *
 * Returns the number of domain snapshots found or -1 and sets @snaps to
 * NULL in case of error.  On success, the array stored into @snaps is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virDomainSnapshotFree() on each array element, then calling
 * free() on @snaps.
 *
 * Since: 0.9.13
 */
int
virDomainSnapshotListAllChildren(virDomainSnapshotPtr snapshot,
                                 virDomainSnapshotPtr **snaps,
                                 unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, snaps=%p, flags=0x%x", snapshot, snaps, flags);

    virResetLastError();

    if (snaps)
        *snaps = NULL;

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotListAllChildren) {
        int ret = conn->driver->domainSnapshotListAllChildren(snapshot, snaps,
                                                              flags);
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
 * virDomainSnapshotLookupByName:
 * @domain: a domain object
 * @name: name for the domain snapshot
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Try to lookup a domain snapshot based on its name.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * domain snapshot cannot be found, then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 *
 * Since: 0.8.0
 */
virDomainSnapshotPtr
virDomainSnapshotLookupByName(virDomainPtr domain,
                              const char *name,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "name=%s, flags=0x%x", name, flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckNonNullArgGoto(name, error);

    if (conn->driver->domainSnapshotLookupByName) {
        virDomainSnapshotPtr dom;
        dom = conn->driver->domainSnapshotLookupByName(domain, name, flags);
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
 * virDomainHasCurrentSnapshot:
 * @domain: pointer to the domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the domain has a current snapshot.
 *
 * Returns 1 if such snapshot exists, 0 if it doesn't, -1 on error.
 *
 * Since: 0.8.0
 */
int
virDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=0x%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    if (conn->driver->domainHasCurrentSnapshot) {
        int ret = conn->driver->domainHasCurrentSnapshot(domain, flags);
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
 * virDomainSnapshotCurrent:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the current snapshot for a domain, if any.
 *
 * virDomainSnapshotFree should be used to free the resources after the
 * snapshot object is no longer needed.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * current domain snapshot cannot be found, then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 *
 * Since: 0.8.0
 */
virDomainSnapshotPtr
virDomainSnapshotCurrent(virDomainPtr domain,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=0x%x", flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    if (conn->driver->domainSnapshotCurrent) {
        virDomainSnapshotPtr snap;
        snap = conn->driver->domainSnapshotCurrent(domain, flags);
        if (!snap)
            goto error;
        return snap;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainSnapshotGetParent:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the parent snapshot for @snapshot, if any.
 *
 * virDomainSnapshotFree should be used to free the resources after the
 * snapshot object is no longer needed.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * given snapshot is a root (no parent), then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 *
 * Since: 0.9.7
 */
virDomainSnapshotPtr
virDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, NULL);
    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotGetParent) {
        virDomainSnapshotPtr snap;
        snap = conn->driver->domainSnapshotGetParent(snapshot, flags);
        if (!snap)
            goto error;
        return snap;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainSnapshotIsCurrent:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the given snapshot is the domain's current snapshot.  See
 * also virDomainHasCurrentSnapshot().
 *
 * Returns 1 if current, 0 if not current, or -1 on error.
 *
 * Since: 0.9.13
 */
int
virDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotIsCurrent) {
        int ret;
        ret = conn->driver->domainSnapshotIsCurrent(snapshot, flags);
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
 * virDomainSnapshotHasMetadata:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the given snapshot is associated with libvirt metadata
 * that would prevent the deletion of the domain.
 *
 * Returns 1 if the snapshot has metadata, 0 if the snapshot exists without
 * help from libvirt, or -1 on error.
 *
 * Since: 0.9.13
 */
int
virDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                             unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotHasMetadata) {
        int ret;
        ret = conn->driver->domainSnapshotHasMetadata(snapshot, flags);
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
 * virDomainRevertToSnapshot:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of virDomainSnapshotRevertFlags
 *
 * Revert the domain to a given snapshot.
 *
 * Normally, the domain will revert to the same state the domain was
 * in while the snapshot was taken (whether inactive, running, or
 * paused), except that disk snapshots default to reverting to
 * inactive state.  Including VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING in
 * @flags overrides the snapshot state to guarantee a running domain
 * after the revert; or including VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED in
 * @flags guarantees a paused domain after the revert.  These two
 * flags are mutually exclusive.  While a persistent domain does not
 * need either flag, it is not possible to revert a transient domain
 * into an inactive state, so transient domains require the use of one
 * of these two flags.
 *
 * Reverting to any snapshot discards all configuration changes made since
 * the last snapshot.  Additionally, reverting to a snapshot from a running
 * domain is a form of data loss, since it discards whatever is in the
 * guest's RAM at the time.  Since the very nature of keeping snapshots
 * implies the intent to roll back state, no additional confirmation is
 * normally required for these lossy effects.
 *
 * Since libvirt 7.10.0 the VM process is always restarted so the following
 * paragraph is no longer valid. If the snapshot metadata lacks the full
 * VM XML it's no longer possible to revert to such snapshot.
 *
 * However, there are two particular situations where reverting will
 * be refused by default, and where @flags must include
 * VIR_DOMAIN_SNAPSHOT_REVERT_FORCE to acknowledge the risks.  1) Any
 * attempt to revert to a snapshot that lacks the metadata to perform
 * ABI compatibility checks (generally the case for snapshots that
 * lack a full <domain> when listed by virDomainSnapshotGetXMLDesc(),
 * such as those created prior to libvirt 0.9.5).  2) Any attempt to
 * revert a running domain to an active state that requires starting a
 * new hypervisor instance rather than reusing the existing hypervisor
 * (since this would terminate all connections to the domain, such as
 * such as VNC or Spice graphics) - this condition arises from active
 * snapshots that are provably ABI incompatible, as well as from
 * inactive snapshots with a @flags request to start the domain after
 * the revert.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_REVERT_RESET_NVRAM, then
 * libvirt will discard any existing NVRAM file and re-initialize
 * NVRAM from the pristine template.
 *
 * Returns 0 if the creation is successful, -1 on error.
 *
 * Since: 0.8.0
 */
int
virDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING,
                             VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED,
                             error);

    if (conn->driver->domainRevertToSnapshot) {
        int ret = conn->driver->domainRevertToSnapshot(snapshot, flags);
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
 * virDomainSnapshotDelete:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of supported virDomainSnapshotDeleteFlags
 *
 * Delete the snapshot.
 *
 * If @flags is 0, then just this snapshot is deleted, and changes
 * from this snapshot are automatically merged into children
 * snapshots.  If @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN,
 * then this snapshot and any descendant snapshots are deleted.  If
 * @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, then any
 * descendant snapshots are deleted, but this snapshot remains.  These
 * two flags are mutually exclusive.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, then
 * any snapshot metadata tracked by libvirt is removed while keeping
 * the snapshot contents intact; if a hypervisor does not require any
 * libvirt metadata to track snapshots, then this flag is silently
 * ignored.
 *
 * Since libvirt 9.0.0 deletion of external snapshots is supported
 * for QEMU driver. Using @flags VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN
 * and VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY is not supported with
 * external snapshots. In case that daemon process is terminated
 * while the snapshot delete is in process the operation will be
 * aborted when the daemon starts again.
 *
 * Returns 0 if the selected snapshot(s) were successfully deleted,
 * -1 on error.
 *
 * Since: 0.8.0
 */
int
virDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=0x%x", snapshot, flags);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);
    conn = snapshot->domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN,
                             VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY,
                             error);

    if (conn->driver->domainSnapshotDelete) {
        int ret = conn->driver->domainSnapshotDelete(snapshot, flags);
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
 * virDomainSnapshotRef:
 * @snapshot: the snapshot to hold a reference on
 *
 * Increment the reference count on the snapshot. For each
 * additional call to this method, there shall be a corresponding
 * call to virDomainSnapshotFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection and domain remain open until all threads have finished
 * using the snapshot. ie, each new thread using a snapshot would
 * increment the reference count.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 0.9.13
 */
int
virDomainSnapshotRef(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);

    virObjectRef(snapshot);
    return 0;
}


/**
 * virDomainSnapshotFree:
 * @snapshot: a domain snapshot object
 *
 * Free the domain snapshot object.  The snapshot itself is not modified.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 0.8.0
 */
int
virDomainSnapshotFree(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    virCheckDomainSnapshotReturn(snapshot, -1);

    virObjectUnref(snapshot);
    return 0;
}
