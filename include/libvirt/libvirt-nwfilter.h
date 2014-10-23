/*
 * libvirt-nwfilter.h
 * Summary: APIs for management of nwfilters
 * Description: Provides APIs for the management of nwfilters
 * Author: Daniel Veillard <veillard@redhat.com>
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

#ifndef __VIR_LIBVIRT_NWFILTER_H__
# define __VIR_LIBVIRT_NWFILTER_H__

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virNWFilter:
 *
 * a virNWFilter is a private structure representing a network filter
 */
typedef struct _virNWFilter virNWFilter;

/**
 * virNWFilterPtr:
 *
 * a virNWFilterPtr is pointer to a virNWFilter private structure,
 * this is the type used to reference a network filter in the API.
 */
typedef virNWFilter *virNWFilterPtr;


/*
 * List NWFilters
 */
int                     virConnectNumOfNWFilters (virConnectPtr conn);
int                     virConnectListNWFilters  (virConnectPtr conn,
                                                  char **const names,
                                                  int maxnames);
int                     virConnectListAllNWFilters(virConnectPtr conn,
                                                   virNWFilterPtr **filters,
                                                   unsigned int flags);
/*
 * Lookup nwfilter by name or uuid
 */
virNWFilterPtr          virNWFilterLookupByName       (virConnectPtr conn,
                                                       const char *name);
virNWFilterPtr          virNWFilterLookupByUUID       (virConnectPtr conn,
                                                       const unsigned char *uuid);
virNWFilterPtr          virNWFilterLookupByUUIDString (virConnectPtr conn,
                                                       const char *uuid);

/*
 * Define persistent nwfilter
 */
virNWFilterPtr          virNWFilterDefineXML    (virConnectPtr conn,
                                                 const char *xmlDesc);

/*
 * Delete persistent nwfilter
 */
int                     virNWFilterUndefine     (virNWFilterPtr nwfilter);

/*
 * NWFilter destroy/free
 */
int                     virNWFilterRef          (virNWFilterPtr nwfilter);
int                     virNWFilterFree         (virNWFilterPtr nwfilter);

/*
 * NWFilter information
 */
const char*             virNWFilterGetName       (virNWFilterPtr nwfilter);
int                     virNWFilterGetUUID       (virNWFilterPtr nwfilter,
                                                  unsigned char *uuid);
int                     virNWFilterGetUUIDString (virNWFilterPtr nwfilter,
                                                  char *buf);
char *                  virNWFilterGetXMLDesc    (virNWFilterPtr nwfilter,
                                                  unsigned int flags);

#endif /* __VIR_LIBVIRT_NWFILTER_H__ */
