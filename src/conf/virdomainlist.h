/**
 * virdomainlist.h: Helpers for listing and filtering domains.
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Peter Krempa <pkrempa@redhat.com>
 */
#ifndef __VIR_DOMAIN_LIST_H__
# define __VIR_DOMAIN_LIST_H__

# include "internal.h"
# include "virhash.h"
# include "domain_conf.h"

# define VIR_CONNECT_LIST_FILTERS_ACTIVE           \
                (VIR_CONNECT_LIST_DOMAINS_ACTIVE | \
                 VIR_CONNECT_LIST_DOMAINS_INACTIVE)

# define VIR_CONNECT_LIST_FILTERS_PERSISTENT           \
                (VIR_CONNECT_LIST_DOMAINS_PERSISTENT | \
                 VIR_CONNECT_LIST_DOMAINS_TRANSIENT)

# define VIR_CONNECT_LIST_FILTERS_STATE             \
                (VIR_CONNECT_LIST_DOMAINS_RUNNING | \
                 VIR_CONNECT_LIST_DOMAINS_PAUSED  | \
                 VIR_CONNECT_LIST_DOMAINS_SHUTOFF | \
                 VIR_CONNECT_LIST_DOMAINS_OTHER)

# define VIR_CONNECT_LIST_FILTERS_MANAGEDSAVE           \
                (VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE)

# define VIR_CONNECT_LIST_FILTERS_AUTOSTART            \
                (VIR_CONNECT_LIST_DOMAINS_AUTOSTART | \
                 VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART)

# define VIR_CONNECT_LIST_FILTERS_SNAPSHOT               \
                (VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT | \
                 VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT)

# define VIR_CONNECT_LIST_FILTERS_ALL                   \
                (VIR_CONNECT_LIST_FILTERS_ACTIVE      | \
                 VIR_CONNECT_LIST_FILTERS_PERSISTENT  | \
                 VIR_CONNECT_LIST_FILTERS_STATE       | \
                 VIR_CONNECT_LIST_FILTERS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_FILTERS_AUTOSTART   | \
                 VIR_CONNECT_LIST_FILTERS_SNAPSHOT)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA           \
               (VIR_DOMAIN_SNAPSHOT_LIST_METADATA     | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES             \
               (VIR_DOMAIN_SNAPSHOT_LIST_LEAVES       | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_ALL                \
               (VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA  | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES)

int virDomainList(virConnectPtr conn, virHashTablePtr domobjs,
                  virDomainPtr **domains, unsigned int flags);

int virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                           virDomainSnapshotObjPtr from,
                           virDomainPtr dom,
                           virDomainSnapshotPtr **snaps,
                           unsigned int flags);

#endif /* __VIR_DOMAIN_LIST_H__ */
