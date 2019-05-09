/*
 * moment_conf.h: domain snapshot/checkpoint base class
 *                  (derived from snapshot_conf.h)
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#ifndef LIBVIRT_MOMENT_CONF_H
# define LIBVIRT_MOMENT_CONF_H

# include "internal.h"
# include "virconftypes.h"
# include "virobject.h"

/* Base class for a domain moment */
struct _virDomainMomentDef {
    virObject parent;

    /* Common portion of public XML.  */
    char *name;
    char *description;
    char *parent_name;
    long long creationTime; /* in seconds */

    virDomainDefPtr dom;
};

virClassPtr virClassForDomainMomentDef(void);

int virDomainMomentDefPostParse(virDomainMomentDefPtr def);

#endif /* LIBVIRT_MOMENT_CONF_H */
