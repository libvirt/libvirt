/*
 * libvirt-interface.h
 * Summary: APIs for management of interfaces
 * Description: Provides APIs for the management of interfaces
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

#ifndef LIBVIRT_INTERFACE_H
# define LIBVIRT_INTERFACE_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virInterface:
 *
 * a virInterface is a private structure representing a virtual interface.
 *
 * Since: 0.6.4
 */
typedef struct _virInterface virInterface;

/**
 * virInterfacePtr:
 *
 * a virInterfacePtr is pointer to a virInterface private structure, this is the
 * type used to reference a virtual interface in the API.
 *
 * Since: 0.6.4
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
/**
 * virConnectListAllInterfacesFlags:
 *
 * Flags used to filter the returned interfaces.
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_CONNECT_LIST_INTERFACES_INACTIVE      = 1 << 0, /* (Since: 0.10.2) */
    VIR_CONNECT_LIST_INTERFACES_ACTIVE        = 1 << 1, /* (Since: 0.10.2) */
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

/**
 * virInterfaceXMLFlags:
 *
 * Since: 0.7.3
 */
typedef enum {
    VIR_INTERFACE_XML_INACTIVE = 1 << 0 /* dump inactive interface information (Since: 0.7.3) */
} virInterfaceXMLFlags;

/**
 * virInterfaceDefineFlags:
 *
 * Since: 7.7.0
 */
typedef enum {
    VIR_INTERFACE_DEFINE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.7.0) */
} virInterfaceDefineFlags;

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


#endif /* LIBVIRT_INTERFACE_H */
