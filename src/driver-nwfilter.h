/*
 * driver-nwfilter.h: entry points for nwfilter drivers
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

#ifndef __VIR_DRIVER_NWFILTER_H__
# define __VIR_DRIVER_NWFILTER_H__

# ifndef __VIR_DRIVER_H_INCLUDES___
#  error "Don't include this file directly, only use driver.h"
# endif

typedef int
(*virDrvConnectNumOfNWFilters)(virConnectPtr conn);

typedef int
(*virDrvConnectListNWFilters)(virConnectPtr conn,
                              char **const names,
                              int maxnames);

typedef int
(*virDrvConnectListAllNWFilters)(virConnectPtr conn,
                                 virNWFilterPtr **filters,
                                 unsigned int flags);

typedef virNWFilterPtr
(*virDrvNWFilterLookupByName)(virConnectPtr conn,
                              const char *name);

typedef virNWFilterPtr
(*virDrvNWFilterLookupByUUID)(virConnectPtr conn,
                              const unsigned char *uuid);

typedef virNWFilterPtr
(*virDrvNWFilterDefineXML)(virConnectPtr conn,
                           const char *xmlDesc);

typedef int
(*virDrvNWFilterUndefine)(virNWFilterPtr nwfilter);

typedef char *
(*virDrvNWFilterGetXMLDesc)(virNWFilterPtr nwfilter,
                            unsigned int flags);


typedef struct _virNWFilterDriver virNWFilterDriver;
typedef virNWFilterDriver *virNWFilterDriverPtr;

/**
 * _virNWFilterDriver:
 *
 * Structure associated to a network filter driver, defining the various
 * entry points for it.
 */
struct _virNWFilterDriver {
    const char *name; /* the name of the driver */
    virDrvConnectNumOfNWFilters connectNumOfNWFilters;
    virDrvConnectListNWFilters connectListNWFilters;
    virDrvConnectListAllNWFilters connectListAllNWFilters;
    virDrvNWFilterLookupByName nwfilterLookupByName;
    virDrvNWFilterLookupByUUID nwfilterLookupByUUID;
    virDrvNWFilterDefineXML nwfilterDefineXML;
    virDrvNWFilterUndefine nwfilterUndefine;
    virDrvNWFilterGetXMLDesc nwfilterGetXMLDesc;
};


#endif /* __VIR_DRIVER_NWFILTER_H__ */
