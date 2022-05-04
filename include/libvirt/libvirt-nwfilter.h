/*
 * libvirt-nwfilter.h
 * Summary: APIs for management of nwfilters
 * Description: Provides APIs for the management of nwfilters
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

#ifndef LIBVIRT_NWFILTER_H
# define LIBVIRT_NWFILTER_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virNWFilter:
 *
 * a virNWFilter is a private structure representing a network filter
 *
 * Since: 0.8.0
 */
typedef struct _virNWFilter virNWFilter;

/**
 * virNWFilterPtr:
 *
 * a virNWFilterPtr is pointer to a virNWFilter private structure,
 * this is the type used to reference a network filter in the API.
 *
 * Since: 0.8.0
 */
typedef virNWFilter *virNWFilterPtr;

/**
 * virNWFilterBinding:
 *
 * a virNWFilterBinding is a private structure representing a network
 * filter binding to a port
 *
 * Since: 4.5.0
 */
typedef struct _virNWFilterBinding virNWFilterBinding;

/**
 * virNWFilterBindingPtr:
 *
 * a virNWFilterBindingPtr is pointer to a virNWFilterBinding private
 * structure, this is the type used to reference a network filter
 * port binding in the API.
 *
 * Since: 4.5.0
 */
typedef virNWFilterBinding *virNWFilterBindingPtr;


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
/**
 * virNWFilterDefineFlags:
 *
 * Since: 7.7.0
 */
typedef enum {
    VIR_NWFILTER_DEFINE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.7.0) */
} virNWFilterDefineFlags;

/*
 * Define persistent nwfilter
 */
virNWFilterPtr          virNWFilterDefineXML    (virConnectPtr conn,
                                                 const char *xmlDesc);
virNWFilterPtr          virNWFilterDefineXMLFlags(virConnectPtr conn,
                                                  const char *xmlDesc,
                                                  unsigned int flags);

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

/**
 * virNWFilterBindingCreateFlags:
 *
 * Since: 7.8.0
 */
typedef enum {
    VIR_NWFILTER_BINDING_CREATE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.8.0) */
} virNWFilterBindingCreateFlags;

const char*             virNWFilterGetName       (virNWFilterPtr nwfilter);
int                     virNWFilterGetUUID       (virNWFilterPtr nwfilter,
                                                  unsigned char *uuid);
int                     virNWFilterGetUUIDString (virNWFilterPtr nwfilter,
                                                  char *buf);
char *                  virNWFilterGetXMLDesc    (virNWFilterPtr nwfilter,
                                                  unsigned int flags);


virNWFilterBindingPtr   virNWFilterBindingLookupByPortDev(virConnectPtr conn,
                                                          const char *portdev);

const char *            virNWFilterBindingGetPortDev(virNWFilterBindingPtr binding);
const char *            virNWFilterBindingGetFilterName(virNWFilterBindingPtr binding);

int                     virConnectListAllNWFilterBindings(virConnectPtr conn,
                                                          virNWFilterBindingPtr **bindings,
                                                          unsigned int flags);

virNWFilterBindingPtr   virNWFilterBindingCreateXML(virConnectPtr conn,
                                                    const char *xml,
                                                    unsigned int flags);

char *                  virNWFilterBindingGetXMLDesc(virNWFilterBindingPtr binding,
                                                     unsigned int flags);

int                     virNWFilterBindingDelete(virNWFilterBindingPtr binding);
int                     virNWFilterBindingRef(virNWFilterBindingPtr binding);
int                     virNWFilterBindingFree(virNWFilterBindingPtr binding);

#endif /* LIBVIRT_NWFILTER_H */
