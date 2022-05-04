/*
 * libvirt-domain-snapshot.h
 * Summary: APIs for management of domain snapshots
 * Description: Provides APIs for the management of domain snapshots
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

#ifndef LIBVIRT_DOMAIN_SNAPSHOT_H
# define LIBVIRT_DOMAIN_SNAPSHOT_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virDomainSnapshot:
 *
 * A virDomainSnapshot is a private structure representing a snapshot of
 * a domain.  A snapshot captures the state of the domain at a point in
 * time, with the intent that the guest can be reverted back to that
 * state at a later time.
 *
 * Since: 0.8.0
 */
typedef struct _virDomainSnapshot virDomainSnapshot;

/**
 * virDomainSnapshotPtr:
 *
 * A virDomainSnapshotPtr is pointer to a virDomainSnapshot private structure,
 * and is the type used to reference a domain snapshot in the API.
 *
 * Since: 0.8.0
 */
typedef virDomainSnapshot *virDomainSnapshotPtr;

const char *virDomainSnapshotGetName(virDomainSnapshotPtr snapshot);
virDomainPtr virDomainSnapshotGetDomain(virDomainSnapshotPtr snapshot);
virConnectPtr virDomainSnapshotGetConnect(virDomainSnapshotPtr snapshot);

/**
 * virDomainSnapshotCreateFlags:
 *
 * Since: 0.9.5
 */
typedef enum {
    VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE    = (1 << 0), /* Restore or alter
                                                          metadata (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT     = (1 << 1), /* With redefine, make
                                                          snapshot current (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA = (1 << 2), /* Make snapshot without
                                                          remembering it (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_CREATE_HALT        = (1 << 3), /* Stop running guest
                                                          after snapshot (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY   = (1 << 4), /* disk snapshot, not
                                                          full system (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT   = (1 << 5), /* reuse any existing
                                                          external files (Since: 0.9.10) */
    VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE     = (1 << 6), /* use guest agent to
                                                          quiesce all mounted
                                                          file systems within
                                                          the domain (Since: 0.9.10) */
    VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC      = (1 << 7), /* atomically avoid
                                                          partial changes (Since: 0.9.11) */
    VIR_DOMAIN_SNAPSHOT_CREATE_LIVE        = (1 << 8), /* create the snapshot
                                                          while the guest is
                                                          running (Since: 1.0.1) */
    VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE    = (1 << 9), /* validate the XML
                                                          against the schema (Since: 5.6.0) */
} virDomainSnapshotCreateFlags;

/* Take a snapshot of the current VM state */
virDomainSnapshotPtr virDomainSnapshotCreateXML(virDomainPtr domain,
                                                const char *xmlDesc,
                                                unsigned int flags);
/**
 * virDomainSnapshotXMLFlags:
 *
 * Since: 5.1.0
 */
typedef enum {
    VIR_DOMAIN_SNAPSHOT_XML_SECURE         = VIR_DOMAIN_XML_SECURE, /* dump security sensitive information too (Since: 5.1.0) */
} virDomainSnapshotXMLFlags;

/* Dump the XML of a snapshot */
char *virDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                                  unsigned int flags);

/**
 * virDomainSnapshotListFlags:
 *
 * Flags valid for virDomainSnapshotNum(),
 * virDomainSnapshotListNames(), virDomainSnapshotNumChildren(), and
 * virDomainSnapshotListChildrenNames(), virDomainListAllSnapshots(),
 * and virDomainSnapshotListAllChildren().  Note that the interpretation
 * of flag (1<<0) depends on which function it is passed to; but serves
 * to toggle the per-call default of whether the listing is shallow or
 * recursive.  Remaining bits come in groups; if all bits from a group are
 * 0, then that group is not used to filter results.
 *
 * Since: 0.9.5
 */
typedef enum {
    VIR_DOMAIN_SNAPSHOT_LIST_ROOTS       = (1 << 0), /* Filter by snapshots
                                                        with no parents, when
                                                        listing a domain (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS = (1 << 0), /* List all descendants,
                                                        not just children, when
                                                        listing a snapshot (Since: 0.9.7) */

    VIR_DOMAIN_SNAPSHOT_LIST_LEAVES      = (1 << 2), /* Filter by snapshots
                                                        with no children (Since: 0.9.7) */
    VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES   = (1 << 3), /* Filter by snapshots
                                                        that have children (Since: 0.9.13) */

    VIR_DOMAIN_SNAPSHOT_LIST_METADATA    = (1 << 1), /* Filter by snapshots
                                                        which have metadata (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA = (1 << 4), /* Filter by snapshots
                                                        with no metadata (Since: 0.9.13) */

    VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE    = (1 << 5), /* Filter by snapshots
                                                        taken while guest was
                                                        shut off (Since: 1.0.1) */
    VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE      = (1 << 6), /* Filter by snapshots
                                                        taken while guest was
                                                        active, and with
                                                        memory state (Since: 1.0.1) */
    VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY   = (1 << 7), /* Filter by snapshots
                                                        taken while guest was
                                                        active, but without
                                                        memory state (Since: 1.0.1) */

    VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL    = (1 << 8), /* Filter by snapshots
                                                        stored internal to
                                                        disk images (Since: 1.0.1) */
    VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL    = (1 << 9), /* Filter by snapshots
                                                        that use files external
                                                        to disk images (Since: 1.0.1) */

    VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL = (1 << 10), /* Ensure parents occur
                                                         before children in
                                                         the resulting list (Since: 5.2.0) */
} virDomainSnapshotListFlags;

/* Return the number of snapshots for this domain */
int virDomainSnapshotNum(virDomainPtr domain, unsigned int flags);

/* Get the names of all snapshots for this domain */
int virDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                               unsigned int flags);

/* Get all snapshot objects for this domain */
int virDomainListAllSnapshots(virDomainPtr domain,
                              virDomainSnapshotPtr **snaps,
                              unsigned int flags);

/* Return the number of child snapshots for this snapshot */
int virDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot,
                                 unsigned int flags);

/* Get the names of all child snapshots for this snapshot */
int virDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                       char **names, int nameslen,
                                       unsigned int flags);

/* Get all snapshot object children for this snapshot */
int virDomainSnapshotListAllChildren(virDomainSnapshotPtr snapshot,
                                     virDomainSnapshotPtr **snaps,
                                     unsigned int flags);

/* Get a handle to a named snapshot */
virDomainSnapshotPtr virDomainSnapshotLookupByName(virDomainPtr domain,
                                                   const char *name,
                                                   unsigned int flags);

/* Check whether a domain has a snapshot which is currently used */
int virDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags);

/* Get a handle to the current snapshot */
virDomainSnapshotPtr virDomainSnapshotCurrent(virDomainPtr domain,
                                              unsigned int flags);

/* Get a handle to the parent snapshot, if one exists */
virDomainSnapshotPtr virDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                                                unsigned int flags);

/* Determine if a snapshot is the current snapshot of its domain.  */
int virDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                               unsigned int flags);

/* Determine if a snapshot has associated libvirt metadata that would
 * prevent the deletion of its domain.  */
int virDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                                 unsigned int flags);

/**
 * virDomainSnapshotRevertFlags:
 *
 * Since: 0.9.5
 */
typedef enum {
    VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING = 1 << 0, /* Run after revert (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED  = 1 << 1, /* Pause after revert (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_REVERT_FORCE   = 1 << 2, /* Allow risky reverts (Since: 0.9.7) */
    VIR_DOMAIN_SNAPSHOT_REVERT_RESET_NVRAM = 1 << 3, /* Re-initialize NVRAM from template (Since: 8.1.0) */
} virDomainSnapshotRevertFlags;

/* Revert the domain to a point-in-time snapshot.  The
 * state of the guest after this call will be the state
 * of the guest when the snapshot in question was taken
 */
int virDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                              unsigned int flags);

/**
 * virDomainSnapshotDeleteFlags:
 *
 * Delete a snapshot
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN      = (1 << 0), /* Also delete children (Since: 0.8.0) */
    VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY = (1 << 1), /* Delete just metadata (Since: 0.9.5) */
    VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY = (1 << 2), /* Delete just children (Since: 0.9.5) */
} virDomainSnapshotDeleteFlags;

int virDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                            unsigned int flags);

int virDomainSnapshotRef(virDomainSnapshotPtr snapshot);
int virDomainSnapshotFree(virDomainSnapshotPtr snapshot);

#endif /* LIBVIRT_DOMAIN_SNAPSHOT_H */
