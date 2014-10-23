/*
 * libvirt-interface.h
 * Summary: APIs for management of interfaces
 * Description: Provides APIs for the management of interfaces
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

#ifndef __VIR_LIBVIRT_INTERFACE_H__
# define __VIR_LIBVIRT_INTERFACE_H__

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virInterface:
 *
 * a virInterface is a private structure representing a virtual interface.
 */
typedef struct _virInterface virInterface;

/**
 * virInterfacePtr:
 *
 * a virInterfacePtr is pointer to a virInterface private structure, this is the
 * type used to reference a virtual interface in the API.
 */
typedef virInterface *virInterfacePtr;

virConnectPtr           virInterfaceGetConnect    (virInterfacePtr iface);

int                     virConnectNumOfInterfaces (virConnectPtr conn);
int                     virConnectListInterfaces  (virConnectPtr conn,
                                                   char **const names,
                                                   int maxnames);

int                     virConnectNumOfDefinedInterfaces (virConnectPtr conn);
int                     virConnectListDefinedInterfaces  (virConnectPtr conn,
                                                          char **const names,
                                                          int maxnames);
/*
 * virConnectListAllInterfaces:
 *
 * Flags used to filter the returned interfaces.
 */
typedef enum {
    VIR_CONNECT_LIST_INTERFACES_INACTIVE      = 1 << 0,
    VIR_CONNECT_LIST_INTERFACES_ACTIVE        = 1 << 1,
} virConnectListAllInterfacesFlags;

int                     virConnectListAllInterfaces (virConnectPtr conn,
                                                     virInterfacePtr **ifaces,
                                                     unsigned int flags);

virInterfacePtr         virInterfaceLookupByName  (virConnectPtr conn,
                                                   const char *name);
virInterfacePtr         virInterfaceLookupByMACString (virConnectPtr conn,
                                                       const char *mac);

const char*             virInterfaceGetName       (virInterfacePtr iface);
const char*             virInterfaceGetMACString  (virInterfacePtr iface);

typedef enum {
    VIR_INTERFACE_XML_INACTIVE = 1 << 0 /* dump inactive interface information */
} virInterfaceXMLFlags;

char *                  virInterfaceGetXMLDesc    (virInterfacePtr iface,
                                                   unsigned int flags);
virInterfacePtr         virInterfaceDefineXML     (virConnectPtr conn,
                                                   const char *xmlDesc,
                                                   unsigned int flags);

int                     virInterfaceUndefine      (virInterfacePtr iface);

int                     virInterfaceCreate        (virInterfacePtr iface,
                                                   unsigned int flags);

int                     virInterfaceDestroy       (virInterfacePtr iface,
                                                   unsigned int flags);

int                     virInterfaceRef           (virInterfacePtr iface);
int                     virInterfaceFree          (virInterfacePtr iface);

int                     virInterfaceChangeBegin   (virConnectPtr conn,
                                                   unsigned int flags);
int                     virInterfaceChangeCommit  (virConnectPtr conn,
                                                   unsigned int flags);
int                     virInterfaceChangeRollback(virConnectPtr conn,
                                                   unsigned int flags);

int virInterfaceIsActive(virInterfacePtr iface);


#endif /* __VIR_LIBVIRT_INTERFACE_H__ */
