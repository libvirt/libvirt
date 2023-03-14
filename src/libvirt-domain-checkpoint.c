/*
 * libvirt-domain-checkpoint.c: entry points for virDomainCheckpointPtr APIs
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

VIR_LOG_INIT("libvirt.domain-checkpoint");

#define VIR_FROM_THIS VIR_FROM_DOMAIN_CHECKPOINT

/**
 * virDomainCheckpointGetName:
 * @checkpoint: a checkpoint object
 *
 * Get the public name for that checkpoint
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * as its lifetime will be the same as the checkpoint object.
 *
 * Since: 5.6.0
 */
const char *
virDomainCheckpointGetName(virDomainCheckpointPtr checkpoint)
{
    VIR_DEBUG("checkpoint=%p", checkpoint);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, NULL);

    return checkpoint->name;
}


/**
 * virDomainCheckpointGetDomain:
 * @checkpoint: a checkpoint object
 *
 * Provides the domain pointer associated with a checkpoint.  The
 * reference counter on the domain is not increased by this
 * call.
 *
 * Returns the domain or NULL.
 *
 * Since: 5.6.0
 */
virDomainPtr
virDomainCheckpointGetDomain(virDomainCheckpointPtr checkpoint)
{
    VIR_DEBUG("checkpoint=%p", checkpoint);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, NULL);

    return checkpoint->domain;
}


/**
 * virDomainCheckpointGetConnect:
 * @checkpoint: a checkpoint object
 *
 * Provides the connection pointer associated with a checkpoint.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the connection or NULL.
 *
 * Since: 5.6.0
 */
virConnectPtr
virDomainCheckpointGetConnect(virDomainCheckpointPtr checkpoint)
{
    VIR_DEBUG("checkpoint=%p", checkpoint);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, NULL);

    return checkpoint->domain->conn;
}


/**
 * virDomainCheckpointCreateXML:
 * @domain: a domain object
 * @xmlDesc: description of the checkpoint to create
 * @flags: bitwise-OR of supported virDomainCheckpointCreateFlags
 *
 * Create a new checkpoint using @xmlDesc, with a top-level
 * <domaincheckpoint> element, on a running @domain.  Note that
 * @xmlDesc must validate against the <domaincheckpoint> XML schema.
 * Typically, it is more common to create a new checkpoint as part of
 * kicking off a backup job with virDomainBackupBegin(); however, it
 * is also possible to start a checkpoint without a backup.
 *
 * See https://libvirt.org/formatcheckpoint.html#checkpoint-xml
 * for more details on @xmlDesc. In particular, some hypervisors may require
 * particular disk formats, such as qcow2, in order to support this
 * command; where @xmlDesc can be used to limit the checkpoint to a working
 * subset of the domain's disks.
 *
 * If @flags includes VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE, then this
 * is a request to reinstate checkpoint metadata that was previously
 * captured from virDomainCheckpointGetXMLDesc() before removing that
 * metadata, rather than creating a new checkpoint.  Note that while
 * original creation can omit a number of elements from @xmlDesc (and
 * libvirt will supply sane defaults based on the domain state at that
 * point in time), a redefinition must supply more elements (as the
 * domain may have changed in the meantime, so that libvirt no longer
 * has a way to resupply correct defaults).  Not all hypervisors support
 * this flag.
 *
 * If @flags includes VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE along with
 * VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE the state of the metadata related
 * to the disk state of the redefined checkpoint is validated. Note that
 * hypervisors may require that the @domain is running to perform validation.
 *
 * If @flags includes VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE, then the
 * libvirt will attempt to use guest agent to freeze and thaw all file
 * systems in use within domain OS. However, if the guest agent is not
 * present, an error is thrown. This flag is incompatible with
 * VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE.
 *
 * Note: A checkpoint represents point in time after which blocks changed by
 * the hypervisor are tracked. The tracking of changed blocks notes only whether
 * a block was modified, but does not preserve the old contents.
 * The main purpose of checkpoints is to enable incremental backups. But for a
 * checkpoint to be useful for this purpose, a backup must be performed at the
 * same time as the checkpoint is created.
 * This is done via the virDomainBackupBegin API, which also allows to create a
 * checkpoint at the same time. Creating checkpoints with
 * virDomainCheckpointCreateXML is generally only useful for re-creating the
 * libvirt metadata.
 *
 * Returns an (opaque) new virDomainCheckpointPtr on success or NULL
 * on failure.
 *
 * Since: 5.6.0
 */
virDomainCheckpointPtr
virDomainCheckpointCreateXML(virDomainPtr domain,
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

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE,
                             VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE,
                             error);

    VIR_REQUIRE_FLAG_GOTO(VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE,
                          VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE,
                          error);

    if (conn->driver->domainCheckpointCreateXML) {
        virDomainCheckpointPtr ret;
        ret = conn->driver->domainCheckpointCreateXML(domain, xmlDesc, flags);
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
 * virDomainCheckpointGetXMLDesc:
 * @checkpoint: a domain checkpoint object
 * @flags: bitwise-OR of supported virDomainCheckpointXMLFlags
 *
 * Provide an XML description of the domain checkpoint.
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_CHECKPOINT_XML_SECURE; this flag is rejected on read-only
 * connections.
 *
 * Normally, the XML description includes an element giving a full
 * description of the domain at the time the checkpoint was created; to
 * reduce parsing time, it will be suppressed when @flags contains
 * VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN.
 *
 * By default, the XML description contains only static information that
 * does not change over time. However, when @flags contains
 * VIR_DOMAIN_CHECKPOINT_XML_SIZE, each <disk> listing adds an additional
 * attribute that shows an estimate of the current size in bytes that
 * have been dirtied between the time the checkpoint was created and the
 * current point in time. Note that updating the size may be expensive and
 * data will be inaccurate once guest OS writes to the disk. Also note that
 * hypervisors may require that the domain associated with @checkpoint is
 * running when VIR_DOMAIN_CHECKPOINT_XML_SIZE is used.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance or NULL in case
 * of error. The caller must free() the returned value.
 *
 * Since: 5.6.0
 */
char *
virDomainCheckpointGetXMLDesc(virDomainCheckpointPtr checkpoint,
                              unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("checkpoint=%p, flags=0x%x", checkpoint, flags);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, NULL);
    conn = checkpoint->domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) &&
        (flags & VIR_DOMAIN_CHECKPOINT_XML_SECURE)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("virDomainCheckpointGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainCheckpointGetXMLDesc) {
        char *ret;
        ret = conn->driver->domainCheckpointGetXMLDesc(checkpoint, flags);
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
 * virDomainListAllCheckpoints:
 * @domain: a domain object
 * @checkpoints: pointer to variable to store the array containing checkpoint
 *               object, or NULL if the list is not required (just returns
 *               number of checkpoints)
 * @flags: bitwise-OR of supported virDomainCheckpointListFlags
 *
 * Collect the list of domain checkpoints for the given domain and allocate
 * an array to store those objects.
 *
 * If @flags contains VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL,
 * @checkpoints is non-NULL, and no other connection is modifying
 * checkpoints, then it is guaranteed that for any checkpoint in the
 * resulting list, no checkpoints later in the list can be reached by
 * a sequence of virDomainCheckpointGetParent() starting from that
 * earlier checkpoint; otherwise, the order of checkpoints in the
 * resulting list is unspecified.
 *
 * By default, this command covers all checkpoints. It is also
 * possible to limit things to just checkpoints with no parents, when
 * @flags includes VIR_DOMAIN_CHECKPOINT_LIST_ROOTS.  Additional
 * filters are provided in groups listed below. Within a group, bits
 * are mutually exclusive, where all possible checkpoints are
 * described by exactly one bit from the group. Some hypervisors might
 * reject particular flags where it cannot make a distinction for
 * filtering. If the set of filter flags selected forms an impossible
 * combination, the hypervisor may return either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_CHECKPOINT_LIST_LEAVES and
 * VIR_DOMAIN_CHECKPOINT_LIST_NO_LEAVES, to filter based on checkpoints that
 * have no further children (a leaf checkpoint).
 *
 * Returns the number of domain checkpoints found or -1 and sets @checkpoints
 * to NULL in case of error.  On success, the array stored into @checkpoints
 * is guaranteed to have an extra allocated element set to NULL but not
 * included in the return count, to make iteration easier.  The caller is
 * responsible for calling virDomainCheckpointFree() on each array element,
 * then calling free() on @checkpoints.
 *
 * Since: 5.6.0
 */
int
virDomainListAllCheckpoints(virDomainPtr domain,
                            virDomainCheckpointPtr **checkpoints,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "checkpoints=%p, flags=0x%x", checkpoints, flags);

    virResetLastError();

    if (checkpoints)
        *checkpoints = NULL;

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    if (conn->driver->domainListAllCheckpoints) {
        int ret = conn->driver->domainListAllCheckpoints(domain, checkpoints,
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
 * virDomainCheckpointListAllChildren:
 * @checkpoint: a domain checkpoint object
 * @children: pointer to variable to store the array containing checkpoint
 *            objects or NULL if the list is not required (just returns
 *            number of checkpoints)
 * @flags: bitwise-OR of supported virDomainCheckpointListFlags
 *
 * Collect the list of domain checkpoints that are children of the given
 * checkpoint, and allocate an array to store those objects.
 *
 * If @flags contains VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL,
 * @checkpoints is non-NULL, and no other connection is modifying
 * checkpoints, then it is guaranteed that for any checkpoint in the
 * resulting list, no checkpoints later in the list can be reached by
 * a sequence of virDomainCheckpointGetParent() starting from that
 * earlier checkpoint; otherwise, the order of checkpoints in the
 * resulting list is unspecified.
 *
 * By default, this command covers only direct children. It is also
 * possible to expand things to cover all descendants, when @flags
 * includes VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS.  Additional
 * are provided via the remaining @flags values as documented in
 * virDomainListAllCheckpoints(), with the exception that
 * VIR_DOMAIN_CHECKPOINT_LIST_ROOTS is not supported (in fact,
 * VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS has the same bit value but
 * opposite semantics of widening rather than narrowing the listing).
 *
 * Returns the number of domain checkpoints found or -1 and sets @children to
 * NULL in case of error.  On success, the array stored into @children is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virDomainCheckpointFree() on each array element, then calling
 * free() on @children.
 *
 * Since: 5.6.0
 */
int
virDomainCheckpointListAllChildren(virDomainCheckpointPtr checkpoint,
                                   virDomainCheckpointPtr **children,
                                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("checkpoint=%p, children=%p, flags=0x%x",
              checkpoint, children, flags);

    virResetLastError();

    if (children)
        *children = NULL;

    virCheckDomainCheckpointReturn(checkpoint, -1);
    conn = checkpoint->domain->conn;

    if (conn->driver->domainCheckpointListAllChildren) {
        int ret = conn->driver->domainCheckpointListAllChildren(checkpoint,
                                                                children,
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
 * virDomainCheckpointLookupByName:
 * @domain: a domain object
 * @name: name for the domain checkpoint
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Try to lookup a domain checkpoint based on its name.
 *
 * Returns a domain checkpoint object or NULL in case of failure.  If the
 * domain checkpoint cannot be found, then the VIR_ERR_NO_DOMAIN_CHECKPOINT
 * error is raised.
 *
 * Since: 5.6.0
 */
virDomainCheckpointPtr
virDomainCheckpointLookupByName(virDomainPtr domain,
                                const char *name,
                                unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "name=%s, flags=0x%x", name, flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckNonNullArgGoto(name, error);

    if (conn->driver->domainCheckpointLookupByName) {
        virDomainCheckpointPtr checkpoint;
        checkpoint = conn->driver->domainCheckpointLookupByName(domain, name,
                                                                flags);
        if (!checkpoint)
            goto error;
        return checkpoint;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainCheckpointGetParent:
 * @checkpoint: a checkpoint object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the parent checkpoint for @checkpoint, if any.
 *
 * virDomainCheckpointFree should be used to free the resources after the
 * checkpoint object is no longer needed.
 *
 * Returns a domain checkpoint object or NULL in case of failure.  If the
 * given checkpoint is a root (no parent), then the VIR_ERR_NO_DOMAIN_CHECKPOINT
 * error is raised.
 *
 * Since: 5.6.0
 */
virDomainCheckpointPtr
virDomainCheckpointGetParent(virDomainCheckpointPtr checkpoint,
                             unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("checkpoint=%p, flags=0x%x", checkpoint, flags);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, NULL);
    conn = checkpoint->domain->conn;

    if (conn->driver->domainCheckpointGetParent) {
        virDomainCheckpointPtr parent;
        parent = conn->driver->domainCheckpointGetParent(checkpoint, flags);
        if (!parent)
            goto error;
        return parent;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainCheckpointDelete:
 * @checkpoint: the checkpoint to remove
 * @flags: bitwise-OR of supported virDomainCheckpointDeleteFlags
 *
 * Removes a checkpoint from the domain.
 *
 * When removing a checkpoint, the record of which portions of the
 * disk were dirtied after the checkpoint will be merged into the
 * record tracked by the parent checkpoint, if any.
 *
 * If @flags includes VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN, then any
 * descendant checkpoints are also deleted. If @flags includes
 * VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY, then any descendant
 * checkepoints are deleted, but this checkpoint remains. These two
 * flags are mutually exclusive.
 *
 * If @flags includes VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY, then
 * any checkpoint metadata tracked by libvirt is removed while keeping
 * the checkpoint contents intact; if a hypervisor does not require
 * any libvirt metadata to track checkpoints, then this flag is
 * silently ignored.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 5.6.0
 */
int
virDomainCheckpointDelete(virDomainCheckpointPtr checkpoint,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("checkpoint=%p, flags=0x%x", checkpoint, flags);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, -1);
    conn = checkpoint->domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN,
                             VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY,
                             error);

    if (conn->driver->domainCheckpointDelete) {
        int ret = conn->driver->domainCheckpointDelete(checkpoint, flags);
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
 * virDomainCheckpointRef:
 * @checkpoint: the checkpoint to hold a reference on
 *
 * Increment the reference count on the checkpoint. For each
 * additional call to this method, there shall be a corresponding
 * call to virDomainCheckpointFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection and domain remain open until all threads have finished
 * using the checkpoint. ie, each new thread using a checkpoint would
 * increment the reference count.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 5.6.0
 */
int
virDomainCheckpointRef(virDomainCheckpointPtr checkpoint)
{
    VIR_DEBUG("checkpoint=%p", checkpoint);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, -1);

    virObjectRef(checkpoint);
    return 0;
}


/**
 * virDomainCheckpointFree:
 * @checkpoint: a domain checkpoint object
 *
 * Free the domain checkpoint object.  The checkpoint itself is not modified.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 5.6.0
 */
int
virDomainCheckpointFree(virDomainCheckpointPtr checkpoint)
{
    VIR_DEBUG("checkpoint=%p", checkpoint);

    virResetLastError();

    virCheckDomainCheckpointReturn(checkpoint, -1);

    virObjectUnref(checkpoint);
    return 0;
}
