/*
 * Copyright (C) 2014 Taowei Luo (uaedante@gmail.com)
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
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

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "domain_event.h"
#include "virlog.h"
#include "viralloc.h"
#include "network_conf.h"

#include "vbox_common.h"
#include "vbox_uniformed_api.h"
#include "vbox_get_driver.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_network");

static vboxUniformedAPI gVBoxAPI;

/**
 * The Network Functions here on
 */


static int vboxConnectNumOfNetworks(virConnectPtr conn)
{
    struct _vboxDriver *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;
        PRUint32 interfaceType = 0;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status == HostNetworkInterfaceStatus_Up)
            ret++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxConnectListNetworks(virConnectPtr conn, char **const names, int nnames)
{
    struct _vboxDriver *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;
        PRUint32 interfaceType = 0;
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status != HostNetworkInterfaceStatus_Up)
            continue;

        gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

        VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
        names[ret] = g_strdup(nameUtf8);
        ret++;

        VBOX_UTF8_FREE(nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

static int vboxConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    struct _vboxDriver *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;
        PRUint32 interfaceType = 0;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status == HostNetworkInterfaceStatus_Down)
            ret++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxConnectListDefinedNetworks(virConnectPtr conn, char **const names, int nnames)
{
    struct _vboxDriver *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 interfaceType = 0;
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status != HostNetworkInterfaceStatus_Down)
            continue;

        gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

        VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
        names[ret] = g_strdup(nameUtf8);
        ret++;

        VBOX_UTF8_FREE(nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

static virNetworkPtr vboxNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    struct _vboxDriver *data = conn->privateData;
    PRUint32 interfaceType = 0;
    char *nameUtf8 = NULL;
    PRUnichar *nameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    vboxIID iid;
    IHost *host = NULL;
    virNetworkPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    vboxIIDFromUUID(&iid, uuid);

    /* TODO: "internal" networks are just strings and
     * thus can't do much with them
     */

    gVBoxAPI.UIHost.FindHostNetworkInterfaceById(host, &iid,
                                                 &networkInterface);
    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

    ret = virGetNetwork(conn, nameUtf8, uuid);

    VIR_DEBUG("Network Name: %s", nameUtf8);
    DEBUGIID("Network UUID", &iid);
    VBOX_UTF8_FREE(nameUtf8);
    VBOX_UTF16_FREE(nameUtf16);

 cleanup:
    VBOX_RELEASE(networkInterface);
    VBOX_RELEASE(host);
    vboxIIDUnalloc(&iid);
    return ret;
}

static virNetworkPtr vboxNetworkLookupByName(virConnectPtr conn, const char *name)
{
    struct _vboxDriver *data = conn->privateData;
    PRUnichar *nameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    PRUint32 interfaceType = 0;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID iid;
    IHost *host = NULL;
    virNetworkPtr ret = NULL;
    nsresult rc;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    VBOX_UTF8_TO_UTF16(name, &nameUtf16);

    gVBoxAPI.UIHost.FindHostNetworkInterfaceByName(host, nameUtf16, &networkInterface);

    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    rc = gVBoxAPI.UIHNInterface.GetId(networkInterface, &iid);
    if (NS_FAILED(rc))
        goto cleanup;
    vboxIIDToUUID(&iid, uuid);
    ret = virGetNetwork(conn, name, uuid);

    VIR_DEBUG("Network Name: %s", name);
    DEBUGIID("Network UUID", &iid);
    vboxIIDUnalloc(&iid);

 cleanup:
    VBOX_RELEASE(networkInterface);
    VBOX_UTF16_FREE(nameUtf16);
    VBOX_RELEASE(host);
    return ret;
}

static PRUnichar *
vboxSocketFormatAddrUtf16(struct _vboxDriver *data, virSocketAddr *addr)
{
    char *utf8 = NULL;
    PRUnichar *utf16 = NULL;

    utf8 = virSocketAddrFormat(addr);

    if (utf8 == NULL)
        return NULL;

    VBOX_UTF8_TO_UTF16(utf8, &utf16);
    VIR_FREE(utf8);

    return utf16;
}

static virNetworkPtr
vboxNetworkDefineCreateXML(virConnectPtr conn, const char *xml, bool start,
                           unsigned int flags)
{
    struct _vboxDriver *data = conn->privateData;
    PRUnichar *networkInterfaceNameUtf16 = NULL;
    char *networkInterfaceNameUtf8 = NULL;
    PRUnichar *networkNameUtf16 = NULL;
    char *networkNameUtf8 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    g_autoptr(virNetworkDef) def = NULL;
    virNetworkIPDef *ipdef = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID vboxnetiid;
    virSocketAddrRange addr;
    virSocketAddr netmask;
    IHost *host = NULL;
    virNetworkPtr ret = NULL;
    nsresult rc;
    bool validate;

    if (start) {
        virCheckFlags(VIR_NETWORK_CREATE_VALIDATE, NULL);
        validate = flags & VIR_NETWORK_CREATE_VALIDATE;
    } else {
        virCheckFlags(VIR_NETWORK_DEFINE_VALIDATE, NULL);
        validate = flags & VIR_NETWORK_DEFINE_VALIDATE;
    }

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    VBOX_IID_INITIALIZE(&vboxnetiid);

    if (!(def = virNetworkDefParse(xml, NULL, NULL, validate)) ||
        (def->forward.type != VIR_NETWORK_FORWARD_NONE) ||
        (def->nips == 0 || !def->ips))
        goto cleanup;

    /* Look for the first IPv4 IP address definition and use that.
     * If there weren't any IPv4 addresses, ignore the network (since it's
     * required below to have an IPv4 address)
    */
    ipdef = virNetworkDefGetIPByIndex(def, AF_INET, 0);
    if (!ipdef)
        goto cleanup;

    if (virNetworkIPDefNetmask(ipdef, &netmask) < 0)
        goto cleanup;

    /* the current limitation of hostonly network is that you can't
     * assign a name to it and it defaults to vboxnet*, for e.g:
     * vboxnet0, vboxnet1, etc. Also the UUID is assigned to it
     * automatically depending on the mac address and thus both
     * these parameters are ignored here for now.
     *
     * If the vbox is in 2.x and the def->name not equal to vboxnet0,
     * the function call will fail and the networkInterface set to
     * NULL. (We can't assign a new name to hostonly network, only
     * take the given name, say vboxnet0)
     */
    gVBoxAPI.UIHost.CreateHostOnlyNetworkInterface(host, &networkInterface);

    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetName(networkInterface, &networkInterfaceNameUtf16);
    if (!networkInterfaceNameUtf16)
        goto cleanup;

    VBOX_UTF16_TO_UTF8(networkInterfaceNameUtf16, &networkInterfaceNameUtf8);

    networkNameUtf8 = g_strdup_printf("HostInterfaceNetworking-%s",
                                      networkInterfaceNameUtf8);

    VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

    /* Currently support only one dhcp server per network
     * with contiguous address space from start to end
     */
    addr = ipdef->ranges[0].addr;
    if ((ipdef->nranges >= 1) &&
        VIR_SOCKET_ADDR_VALID(&addr.start) &&
        VIR_SOCKET_ADDR_VALID(&addr.end)) {
        IDHCPServer *dhcpServer = NULL;

        gVBoxAPI.UIVirtualBox.FindDHCPServerByNetworkName(data->vboxObj,
                                                          networkNameUtf16,
                                                          &dhcpServer);
        if (!dhcpServer) {
            /* create a dhcp server */
            gVBoxAPI.UIVirtualBox.CreateDHCPServer(data->vboxObj,
                                                   networkNameUtf16,
                                                   &dhcpServer);
            VIR_DEBUG("couldn't find dhcp server so creating one");
        }
        if (dhcpServer) {
            PRUnichar *ipAddressUtf16 = NULL;
            PRUnichar *networkMaskUtf16 = NULL;
            PRUnichar *fromIPAddressUtf16 = NULL;
            PRUnichar *toIPAddressUtf16 = NULL;
            PRUnichar *trunkTypeUtf16 = NULL;

            ipAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->address);
            networkMaskUtf16 = vboxSocketFormatAddrUtf16(data, &netmask);
            fromIPAddressUtf16 = vboxSocketFormatAddrUtf16(data, &addr.start);
            toIPAddressUtf16 = vboxSocketFormatAddrUtf16(data, &addr.end);

            if (ipAddressUtf16 == NULL || networkMaskUtf16 == NULL ||
                fromIPAddressUtf16 == NULL || toIPAddressUtf16 == NULL) {
                VBOX_UTF16_FREE(ipAddressUtf16);
                VBOX_UTF16_FREE(networkMaskUtf16);
                VBOX_UTF16_FREE(fromIPAddressUtf16);
                VBOX_UTF16_FREE(toIPAddressUtf16);
                VBOX_RELEASE(dhcpServer);
                goto cleanup;
            }

            VBOX_UTF8_TO_UTF16("netflt", &trunkTypeUtf16);

            gVBoxAPI.UIDHCPServer.SetEnabled(dhcpServer, PR_TRUE);

            gVBoxAPI.UIDHCPServer.SetConfiguration(dhcpServer,
                                                   ipAddressUtf16,
                                                   networkMaskUtf16,
                                                   fromIPAddressUtf16,
                                                   toIPAddressUtf16);

            if (start)
                gVBoxAPI.UIDHCPServer.Start(dhcpServer,
                                            networkNameUtf16,
                                            trunkTypeUtf16);

            VBOX_UTF16_FREE(ipAddressUtf16);
            VBOX_UTF16_FREE(networkMaskUtf16);
            VBOX_UTF16_FREE(fromIPAddressUtf16);
            VBOX_UTF16_FREE(toIPAddressUtf16);
            VBOX_UTF16_FREE(trunkTypeUtf16);
            VBOX_RELEASE(dhcpServer);
        }
    }

    if ((ipdef->nhosts >= 1) &&
        VIR_SOCKET_ADDR_VALID(&ipdef->hosts[0].ip)) {
        PRUnichar *ipAddressUtf16 = NULL;
        PRUnichar *networkMaskUtf16 = NULL;

        ipAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->hosts[0].ip);
        networkMaskUtf16 = vboxSocketFormatAddrUtf16(data, &netmask);

        if (ipAddressUtf16 == NULL || networkMaskUtf16 == NULL) {
            VBOX_UTF16_FREE(ipAddressUtf16);
            VBOX_UTF16_FREE(networkMaskUtf16);
            goto cleanup;
        }

        /* Current drawback is that since EnableStaticIpConfig() sets
         * IP and enables the interface so even if the dhcpserver is not
         * started the interface is still up and running
         */
        gVBoxAPI.UIHNInterface.EnableStaticIPConfig(networkInterface,
                                                    ipAddressUtf16,
                                                    networkMaskUtf16);

        VBOX_UTF16_FREE(ipAddressUtf16);
        VBOX_UTF16_FREE(networkMaskUtf16);
    } else {
        gVBoxAPI.UIHNInterface.EnableDynamicIPConfig(networkInterface);
        gVBoxAPI.UIHNInterface.DHCPRediscover(networkInterface);
    }

    rc = gVBoxAPI.UIHNInterface.GetId(networkInterface, &vboxnetiid);
    if (NS_FAILED(rc))
        goto cleanup;
    vboxIIDToUUID(&vboxnetiid, uuid);
    DEBUGIID("Real Network UUID", &vboxnetiid);
    vboxIIDUnalloc(&vboxnetiid);
    ret = virGetNetwork(conn, networkInterfaceNameUtf8, uuid);

 cleanup:
    VIR_FREE(networkNameUtf8);
    VBOX_UTF16_FREE(networkNameUtf16);
    VBOX_RELEASE(networkInterface);
    VBOX_UTF8_FREE(networkInterfaceNameUtf8);
    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);
    return ret;
}

static virNetworkPtr vboxNetworkCreateXML(virConnectPtr conn, const char *xml)
{
    return vboxNetworkDefineCreateXML(conn, xml, true, 0);
}

static virNetworkPtr vboxNetworkCreateXMLFlags(virConnectPtr conn, const char *xml,
                                               unsigned int flags)
{
    return vboxNetworkDefineCreateXML(conn, xml, true, flags);
}

static virNetworkPtr vboxNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    return vboxNetworkDefineCreateXML(conn, xml, false, 0);
}

static virNetworkPtr vboxNetworkDefineXMLFlags(virConnectPtr conn, const char *xml,
                                               unsigned int flags)
{
    return vboxNetworkDefineCreateXML(conn, xml, false, flags);
}

static int
vboxNetworkUndefineDestroy(virNetworkPtr network, bool removeinterface)
{
    struct _vboxDriver *data = network->conn->privateData;
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    PRUnichar *networkNameUtf16 = NULL;
    IDHCPServer *dhcpServer = NULL;
    PRUint32 interfaceType = 0;
    IHost *host = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    /* Current limitation of the function for VirtualBox 2.2.* is
     * that you can't delete the default hostonly adaptor namely:
     * vboxnet0 and thus all this functions does is remove the
     * dhcp server configuration, but the network can still be used
     * by giving the machine static IP and also it will still
     * show up in the net-list in virsh
     */

    networkNameUtf8 = g_strdup_printf("HostInterfaceNetworking-%s", network->name);

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    gVBoxAPI.UIHost.FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    if (removeinterface) {
        vboxIID iid;
        IProgress *progress = NULL;
        nsresult rc;
        resultCodeUnion resultCode;

        VBOX_IID_INITIALIZE(&iid);
        rc = gVBoxAPI.UIHNInterface.GetId(networkInterface, &iid);

        if (NS_FAILED(rc))
            goto cleanup;

        gVBoxAPI.UIHost.RemoveHostOnlyNetworkInterface(host, &iid, &progress);
        vboxIIDUnalloc(&iid);

        if (!progress)
            goto cleanup;

        gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
        gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
        if (RC_FAILED(resultCode)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Error while removing hostonly network interface, rc=%1$08x"),
                           resultCode.uResultCode);
            goto cleanup;
        }
        VBOX_RELEASE(progress);
    }

    VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

    gVBoxAPI.UIVirtualBox.FindDHCPServerByNetworkName(data->vboxObj,
                                                      networkNameUtf16,
                                                      &dhcpServer);
    if (!dhcpServer)
        goto cleanup;

    gVBoxAPI.UIDHCPServer.SetEnabled(dhcpServer, PR_FALSE);
    gVBoxAPI.UIDHCPServer.Stop(dhcpServer);
    if (removeinterface)
        gVBoxAPI.UIVirtualBox.RemoveDHCPServer(data->vboxObj, dhcpServer);
    ret = 0;
    VBOX_RELEASE(dhcpServer);

 cleanup:
    VBOX_UTF16_FREE(networkNameUtf16);
    VBOX_RELEASE(networkInterface);
    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);
    VIR_FREE(networkNameUtf8);
    return ret;
}

static int vboxNetworkUndefine(virNetworkPtr network)
{
    return vboxNetworkUndefineDestroy(network, true);
}

static int vboxNetworkDestroy(virNetworkPtr network)
{
    return vboxNetworkUndefineDestroy(network, false);
}

static int vboxNetworkCreate(virNetworkPtr network)
{
    struct _vboxDriver *data = network->conn->privateData;
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    PRUnichar *networkNameUtf16 = NULL;
    IDHCPServer *dhcpServer = NULL;
    PRUnichar *trunkTypeUtf16 = NULL;
    PRUint32 interfaceType = 0;
    IHost *host = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    /* Current limitation of the function for VirtualBox 2.2.* is
     * that the default hostonly network "vboxnet0" is always active
     * and thus all this functions does is start the dhcp server,
     * but the network can still be used without starting the dhcp
     * server by giving the machine static IP
     */

    networkNameUtf8 = g_strdup_printf("HostInterfaceNetworking-%s", network->name);

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    gVBoxAPI.UIHost.FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

    gVBoxAPI.UIVirtualBox.FindDHCPServerByNetworkName(data->vboxObj,
                                                      networkNameUtf16,
                                                      &dhcpServer);
    if (!dhcpServer)
        goto cleanup;

    gVBoxAPI.UIDHCPServer.SetEnabled(dhcpServer, PR_TRUE);

    VBOX_UTF8_TO_UTF16("netflt", &trunkTypeUtf16);

    gVBoxAPI.UIDHCPServer.Start(dhcpServer,
                                networkNameUtf16,
                                trunkTypeUtf16);

    VBOX_UTF16_FREE(trunkTypeUtf16);
    ret = 0;

 cleanup:
    VBOX_RELEASE(dhcpServer);
    VBOX_UTF16_FREE(networkNameUtf16);
    VBOX_RELEASE(networkInterface);
    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);
    VIR_FREE(networkNameUtf8);
    return ret;
}

static int
vboxSocketParseAddrUtf16(struct _vboxDriver *data, const PRUnichar *utf16,
                         virSocketAddr *addr)
{
    int result = -1;
    char *utf8 = NULL;

    VBOX_UTF16_TO_UTF8(utf16, &utf8);

    if (virSocketAddrParse(addr, utf8, AF_UNSPEC) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    VBOX_UTF8_FREE(utf8);

    return result;
}

static char *vboxNetworkGetXMLDesc(virNetworkPtr network, unsigned int flags)
{
    struct _vboxDriver *data = network->conn->privateData;
    g_autoptr(virNetworkDef) def = NULL;
    virNetworkIPDef *ipdef = NULL;
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    PRUint32 interfaceType = 0;
    PRUnichar *networkNameUtf16 = NULL;
    IDHCPServer *dhcpServer = NULL;
    vboxIID vboxnet0IID;
    IHost *host = NULL;
    char *ret = NULL;
    virSocketAddrRange addr;
    nsresult rc;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    VBOX_IID_INITIALIZE(&vboxnet0IID);
    virCheckFlags(0, NULL);

    def = g_new0(virNetworkDef, 1);
    ipdef = g_new0(virNetworkIPDef, 1);
    def->ips = ipdef;
    def->nips = 1;

    networkNameUtf8 = g_strdup_printf("HostInterfaceNetworking-%s", network->name);

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    gVBoxAPI.UIHost.FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    def->name = g_strdup(network->name);

    rc = gVBoxAPI.UIHNInterface.GetId(networkInterface, &vboxnet0IID);
    if (NS_FAILED(rc))
        goto cleanup;
    vboxIIDToUUID(&vboxnet0IID, def->uuid);

    VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

    def->forward.type = VIR_NETWORK_FORWARD_NONE;

    gVBoxAPI.UIVirtualBox.FindDHCPServerByNetworkName(data->vboxObj,
                                                      networkNameUtf16,
                                                      &dhcpServer);
    if (dhcpServer) {
        PRUnichar *ipAddressUtf16 = NULL;
        PRUnichar *networkMaskUtf16 = NULL;
        PRUnichar *fromIPAddressUtf16 = NULL;
        PRUnichar *toIPAddressUtf16 = NULL;
        PRUnichar *macAddressUtf16 = NULL;
        bool errorOccurred = false;

        ipdef->nranges = 1;
        ipdef->ranges = g_new0(virNetworkDHCPRangeDef, ipdef->nranges);

        gVBoxAPI.UIDHCPServer.GetIPAddress(dhcpServer, &ipAddressUtf16);
        gVBoxAPI.UIDHCPServer.GetNetworkMask(dhcpServer, &networkMaskUtf16);
        gVBoxAPI.UIDHCPServer.GetLowerIP(dhcpServer, &fromIPAddressUtf16);
        gVBoxAPI.UIDHCPServer.GetUpperIP(dhcpServer, &toIPAddressUtf16);
        /* Currently virtualbox supports only one dhcp server per network
         * with contiguous address space from start to end
         */
        addr = ipdef->ranges[0].addr;
        if (vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                     &ipdef->address) < 0 ||
            vboxSocketParseAddrUtf16(data, networkMaskUtf16,
                                     &ipdef->netmask) < 0 ||
            vboxSocketParseAddrUtf16(data, fromIPAddressUtf16,
                                     &addr.start) < 0 ||
            vboxSocketParseAddrUtf16(data, toIPAddressUtf16,
                                     &addr.end) < 0) {
            errorOccurred = true;
        }

        VBOX_UTF16_FREE(ipAddressUtf16);
        VBOX_UTF16_FREE(networkMaskUtf16);
        VBOX_UTF16_FREE(fromIPAddressUtf16);
        VBOX_UTF16_FREE(toIPAddressUtf16);

        if (errorOccurred)
            goto cleanup;

        ipdef->nhosts = 1;
        ipdef->hosts = g_new0(virNetworkDHCPHostDef, ipdef->nhosts);

        ipdef->hosts[0].name = g_strdup(network->name);
        gVBoxAPI.UIHNInterface.GetHardwareAddress(networkInterface, &macAddressUtf16);
        gVBoxAPI.UIHNInterface.GetIPAddress(networkInterface, &ipAddressUtf16);

        VBOX_UTF16_TO_UTF8(macAddressUtf16, &ipdef->hosts[0].mac);

        if (vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                     &ipdef->hosts[0].ip) < 0) {
            errorOccurred = true;
        }

        VBOX_UTF16_FREE(macAddressUtf16);
        VBOX_UTF16_FREE(ipAddressUtf16);

        if (errorOccurred)
            goto cleanup;
    } else {
        PRUnichar *networkMaskUtf16 = NULL;
        PRUnichar *ipAddressUtf16 = NULL;
        bool errorOccurred = false;

        gVBoxAPI.UIHNInterface.GetNetworkMask(networkInterface, &networkMaskUtf16);
        gVBoxAPI.UIHNInterface.GetIPAddress(networkInterface, &ipAddressUtf16);

        if (vboxSocketParseAddrUtf16(data, networkMaskUtf16,
                                     &ipdef->netmask) < 0 ||
            vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                     &ipdef->address) < 0) {
            errorOccurred = true;
        }

        VBOX_UTF16_FREE(networkMaskUtf16);
        VBOX_UTF16_FREE(ipAddressUtf16);

        if (errorOccurred)
            goto cleanup;
    }

    DEBUGIID("Network UUID", &vboxnet0IID);
    ret = virNetworkDefFormat(def, NULL, 0);

 cleanup:
    vboxIIDUnalloc(&vboxnet0IID);
    VBOX_UTF16_FREE(networkNameUtf16);
    VBOX_RELEASE(networkInterface);
    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);
    VIR_FREE(networkNameUtf8);
    VBOX_RELEASE(dhcpServer);
    return ret;
}

virNetworkDriver vboxNetworkDriver = {
    .connectNumOfNetworks = vboxConnectNumOfNetworks, /* 0.6.4 */
    .connectListNetworks = vboxConnectListNetworks, /* 0.6.4 */
    .connectNumOfDefinedNetworks = vboxConnectNumOfDefinedNetworks, /* 0.6.4 */
    .connectListDefinedNetworks = vboxConnectListDefinedNetworks, /* 0.6.4 */
    .networkLookupByUUID = vboxNetworkLookupByUUID, /* 0.6.4 */
    .networkLookupByName = vboxNetworkLookupByName, /* 0.6.4 */
    .networkCreateXML = vboxNetworkCreateXML, /* 0.6.4 */
    .networkCreateXMLFlags = vboxNetworkCreateXMLFlags, /* 7.8.0 */
    .networkDefineXML = vboxNetworkDefineXML, /* 0.6.4 */
    .networkDefineXMLFlags = vboxNetworkDefineXMLFlags, /* 7.7.0 */
    .networkUndefine = vboxNetworkUndefine, /* 0.6.4 */
    .networkCreate = vboxNetworkCreate, /* 0.6.4 */
    .networkDestroy = vboxNetworkDestroy, /* 0.6.4 */
    .networkGetXMLDesc = vboxNetworkGetXMLDesc, /* 0.6.4 */
};

virNetworkDriver *vboxGetNetworkDriver(uint32_t uVersion)
{
    /* Install gVBoxAPI according to the vbox API version. */
    int result = 0;
    installUniformedAPI(gVBoxAPI, result);
    if (result < 0) return NULL;
    return &vboxNetworkDriver;
}
