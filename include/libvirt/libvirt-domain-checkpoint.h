/*
 * libvirt-domain-checkpoint.h
 * Summary: APIs for management of domain checkpoints
 * Description: Provides APIs for the management of domain checkpoints
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

#ifndef LIBVIRT_DOMAIN_CHECKPOINT_H
# define LIBVIRT_DOMAIN_CHECKPOINT_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virDomainCheckpoint:
 *
 * A virDomainCheckpoint is a private structure representing a checkpoint of
 * a domain.  A checkpoint is useful for tracking which portions of the
 * domain disks have been altered since a point in time, but by itself does
 * not allow reverting back to that point in time.
 *
 * Since: 5.2.0
 */
typedef struct _virDomainCheckpoint virDomainCheckpoint;

/**
 * virDomainCheckpointPtr:
 *
 * A virDomainCheckpointPtr is pointer to a virDomainCheckpoint
 * private structure, and is the type used to reference a domain
 * checkpoint in the API.
 *
 * Since: 5.2.0
 */
typedef virDomainCheckpoint *virDomainCheckpointPtr;

const char *virDomainCheckpointGetName(virDomainCheckpointPtr checkpoint);
virDomainPtr virDomainCheckpointGetDomain(virDomainCheckpointPtr checkpoint);
virConnectPtr virDomainCheckpointGetConnect(virDomainCheckpointPtr checkpoint);

/**
 * virDomainCheckpointCreateFlags:
 *
 * Since: 5.6.0
 */
typedef enum {
    VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE    = (1 << 0), /* Restore or alter
                                                            metadata (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE     = (1 << 1), /* use guest agent to
                                                            quiesce all mounted
                                                            file systems within
                                                            the domain (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE  = (1 << 2),   /* validate disk data state
                                                                     when redefining a checkpoint (Since: 6.10.0) */
} virDomainCheckpointCreateFlags;

/* Create a checkpoint using the current VM state. */
virDomainCheckpointPtr virDomainCheckpointCreateXML(virDomainPtr domain,
                                                    const char *xmlDesc,
                                                    unsigned int flags);
/**
 * virDomainCheckpointXMLFlags:
 *
 * Since: 5.6.0
 */
typedef enum {
    VIR_DOMAIN_CHECKPOINT_XML_SECURE    = (1 << 0), /* Include sensitive data (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN = (1 << 1), /* Suppress <domain>
                                                       subelement (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_XML_SIZE      = (1 << 2), /* Include dynamic
                                                       per-<disk> size (Since: 5.6.0) */
} virDomainCheckpointXMLFlags;

/* Dump the XML of a checkpoint */
char *virDomainCheckpointGetXMLDesc(virDomainCheckpointPtr checkpoint,
                                    unsigned int flags);

/**
 * virDomainCheckpointListFlags:
 *
 * Flags valid for virDomainListAllCheckpoints() and
 * virDomainCheckpointListAllChildren().  Note that the interpretation of
 * flag (1<<0) depends on which function it is passed to; but serves
 * to toggle the per-call default of whether the listing is shallow or
 * recursive.  Remaining bits come in groups; if all bits from a group
 * are 0, then that group is not used to filter results.
 *
 * Since: 5.6.0
 */
typedef enum {
    VIR_DOMAIN_CHECKPOINT_LIST_ROOTS       = (1 << 0), /* Filter by checkpoints
                                                          with no parents, when
                                                          listing a domain (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS = (1 << 0), /* List all descendants,
                                                          not just children, when
                                                          listing a checkpoint (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL = (1 << 1), /* Ensure parents occur
                                                          before children in
                                                          the resulting list (Since: 5.6.0) */

    VIR_DOMAIN_CHECKPOINT_LIST_LEAVES      = (1 << 2), /* Filter by checkpoints
                                                          with no children (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_LIST_NO_LEAVES   = (1 << 3), /* Filter by checkpoints
                                                          that have children (Since: 5.6.0) */
} virDomainCheckpointListFlags;

/* Get all checkpoint objects for this domain */
int virDomainListAllCheckpoints(virDomainPtr domain,
                                virDomainCheckpointPtr **checkpoints,
                                unsigned int flags);

/* Get all checkpoint object children for this checkpoint */
int virDomainCheckpointListAllChildren(virDomainCheckpointPtr checkpoint,
                                       virDomainCheckpointPtr **children,
                                       unsigned int flags);

/* Get a handle to a named checkpoint */
virDomainCheckpointPtr virDomainCheckpointLookupByName(virDomainPtr domain,
                                                       const char *name,
                                                       unsigned int flags);

/* Get a handle to the parent checkpoint, if one exists */
virDomainCheckpointPtr virDomainCheckpointGetParent(virDomainCheckpointPtr checkpoint,
                                                    unsigned int flags);

/**
 * virDomainCheckpointDeleteFlags:
 *
 * Delete a checkpoint
 *
 * Since: 5.6.0
 */
typedef enum {
    VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN      = (1 << 0), /* Also delete children (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY = (1 << 1), /* Delete just metadata (Since: 5.6.0) */
    VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY = (1 << 2), /* Delete just children (Since: 5.6.0) */
} virDomainCheckpointDeleteFlags;

int virDomainCheckpointDelete(virDomainCheckpointPtr checkpoint,
                              unsigned int flags);

int virDomainCheckpointRef(virDomainCheckpointPtr checkpoint);
int virDomainCheckpointFree(virDomainCheckpointPtr checkpoint);

#endif /* LIBVIRT_DOMAIN_CHECKPOINT_H */
