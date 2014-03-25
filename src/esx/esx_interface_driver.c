/*
 * esx_interface_driver.c: interface driver functions for managing VMware ESX
 *                         host interfaces
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2010-2012 Matthias Bolte <matthias.bolte@googlemail.com>
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
 *
 */

#include <config.h>

#include "internal.h"
#include "viralloc.h"
#include "viruuid.h"
#include "interface_conf.h"
#include "virsocketaddr.h"
#include "esx_private.h"
#include "esx_interface_driver.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX



static virDrvOpenStatus
esxInterfaceOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->driver->no != VIR_DRV_ESX) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->interfacePrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
esxInterfaceClose(virConnectPtr conn)
{
    conn->interfacePrivateData = NULL;

    return 0;
}



static int
esxConnectNumOfInterfaces(virConnectPtr conn)
{
    esxPrivate *priv = conn->interfacePrivateData;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *physicalNic = NULL;
    int count = 0;

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupPhysicalNicList(priv->primary, &physicalNicList) < 0) {
        return -1;
    }

    for (physicalNic = physicalNicList; physicalNic;
         physicalNic = physicalNic->_next) {
        ++count;
    }

    esxVI_PhysicalNic_Free(&physicalNicList);

    return count;
}



static int
esxConnectListInterfaces(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->interfacePrivateData;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *physicalNic = NULL;
    int count = 0;
    size_t i;

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupPhysicalNicList(priv->primary, &physicalNicList) < 0) {
        return -1;
    }

    for (physicalNic = physicalNicList; physicalNic;
         physicalNic = physicalNic->_next) {
        if (VIR_STRDUP(names[count], physicalNic->device) < 0)
            goto cleanup;

        ++count;
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i) {
            VIR_FREE(names[i]);
        }

        count = -1;
    }

    esxVI_PhysicalNic_Free(&physicalNicList);

    return count;
}



static int
esxConnectNumOfDefinedInterfaces(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* ESX interfaces are always active */
    return 0;
}



static int
esxConnectListDefinedInterfaces(virConnectPtr conn ATTRIBUTE_UNUSED,
                                char **const names ATTRIBUTE_UNUSED,
                                int maxnames ATTRIBUTE_UNUSED)
{
    /* ESX interfaces are always active */
    return 0;
}



static virInterfacePtr
esxInterfaceLookupByName(virConnectPtr conn, const char *name)
{
    virInterfacePtr iface = NULL;
    esxPrivate *priv = conn->interfacePrivateData;
    esxVI_PhysicalNic *physicalNic = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupPhysicalNicByMACAddress(priv->primary, name, &physicalNic,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        return NULL;
    }

    iface = virGetInterface(conn, physicalNic->device, physicalNic->mac);

    esxVI_PhysicalNic_Free(&physicalNic);

    return iface;
}



static virInterfacePtr
esxInterfaceLookupByMACString(virConnectPtr conn, const char *mac)
{
    virInterfacePtr iface = NULL;
    esxPrivate *priv = conn->interfacePrivateData;
    esxVI_PhysicalNic *physicalNic = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupPhysicalNicByMACAddress(priv->primary, mac, &physicalNic,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        return NULL;
    }

    iface = virGetInterface(conn, physicalNic->device, physicalNic->mac);

    esxVI_PhysicalNic_Free(&physicalNic);

    return iface;
}



static char *
esxInterfaceGetXMLDesc(virInterfacePtr iface, unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = iface->conn->interfacePrivateData;
    esxVI_PhysicalNic *physicalNic = NULL;
    virInterfaceDef def;
    bool hasAddress = false;
    virInterfaceProtocolDefPtr protocols;
    virInterfaceProtocolDef protocol;
    virSocketAddr socketAddress;
    virInterfaceIpDefPtr ips;
    virInterfaceIpDef ip;

    virCheckFlags(VIR_INTERFACE_XML_INACTIVE, NULL);

    memset(&def, 0, sizeof(def));
    memset(&protocol, 0, sizeof(protocol));
    memset(&socketAddress, 0, sizeof(socketAddress));
    memset(&ip, 0, sizeof(ip));

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupPhysicalNicByMACAddress(priv->primary, iface->mac,
                                            &physicalNic,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        return NULL;
    }

    def.type = VIR_INTERFACE_TYPE_ETHERNET;
    def.name = physicalNic->device;
    def.mac = physicalNic->mac;
    def.startmode = VIR_INTERFACE_START_ONBOOT;

    /* FIXME: Add support for IPv6, requires to use vSphere API 4.0 */
    if (physicalNic->spec->ip) {
        protocol.family = (char *)"ipv4";

        if (physicalNic->spec->ip->dhcp == esxVI_Boolean_True) {
            protocol.dhcp = 1;
        }

        if (physicalNic->spec->ip->ipAddress &&
            physicalNic->spec->ip->subnetMask &&
            strlen(physicalNic->spec->ip->ipAddress) > 0 &&
            strlen(physicalNic->spec->ip->subnetMask) > 0) {
            hasAddress = true;
        }

        if (protocol.dhcp || hasAddress) {
            protocols = &protocol;
            def.nprotos = 1;
            def.protos = &protocols;
        }

        if (hasAddress &&
            !(protocol.dhcp && (flags & VIR_INTERFACE_XML_INACTIVE))) {
            ips = &ip;
            protocol.nips = 1;
            protocol.ips = &ips;

            if (virSocketAddrParseIPv4(&socketAddress,
                                       physicalNic->spec->ip->subnetMask) < 0) {
                goto cleanup;
            }

            ip.address = physicalNic->spec->ip->ipAddress;
            ip.prefix = virSocketAddrGetNumNetmaskBits(&socketAddress);
        }
    }

    xml = virInterfaceDefFormat(&def);

 cleanup:
    esxVI_PhysicalNic_Free(&physicalNic);

    return xml;
}



static int
esxInterfaceIsActive(virInterfacePtr iface ATTRIBUTE_UNUSED)
{
    /* ESX interfaces are always active */
    return 1;
}



static virInterfaceDriver esxInterfaceDriver = {
    .name = "ESX",
    .interfaceOpen = esxInterfaceOpen, /* 0.7.6 */
    .interfaceClose = esxInterfaceClose, /* 0.7.6 */
    .connectNumOfInterfaces = esxConnectNumOfInterfaces, /* 0.10.0 */
    .connectListInterfaces = esxConnectListInterfaces, /* 0.10.0 */
    .connectNumOfDefinedInterfaces = esxConnectNumOfDefinedInterfaces, /* 0.10.0 */
    .connectListDefinedInterfaces = esxConnectListDefinedInterfaces, /* 0.10.0 */
    .interfaceLookupByName = esxInterfaceLookupByName, /* 0.10.0 */
    .interfaceLookupByMACString = esxInterfaceLookupByMACString, /* 0.10.0 */
    .interfaceGetXMLDesc = esxInterfaceGetXMLDesc, /* 0.10.0 */
    .interfaceIsActive = esxInterfaceIsActive, /* 0.10.0 */
};



int
esxInterfaceRegister(void)
{
    return virRegisterInterfaceDriver(&esxInterfaceDriver);
}
