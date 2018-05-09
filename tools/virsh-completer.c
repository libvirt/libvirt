/*
 * virsh-completer.c: virsh completer callbacks
 *
 * Copyright (C) 2017 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "virsh-completer.h"
#include "virsh-domain.h"
#include "virsh.h"
#include "virsh-pool.h"
#include "virsh-nodedev.h"
#include "virsh-util.h"
#include "virsh-secret.h"
#include "internal.h"
#include "virutil.h"
#include "viralloc.h"
#include "virstring.h"
#include "virxml.h"


char **
virshDomainNameCompleter(vshControl *ctl,
                         const vshCmd *cmd ATTRIBUTE_UNUSED,
                         unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virDomainPtr *domains = NULL;
    int ndomains = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_ACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_INACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_OTHER |
                  VIR_CONNECT_LIST_DOMAINS_PAUSED |
                  VIR_CONNECT_LIST_DOMAINS_PERSISTENT |
                  VIR_CONNECT_LIST_DOMAINS_RUNNING |
                  VIR_CONNECT_LIST_DOMAINS_SHUTOFF,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndomains = virConnectListAllDomains(priv->conn, &domains, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, ndomains + 1) < 0)
        goto error;

    for (i = 0; i < ndomains; i++) {
        const char *name = virDomainGetName(domains[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virshDomainFree(domains[i]);
    }
    VIR_FREE(domains);

    return ret;

 error:
    for (; i < ndomains; i++)
        virshDomainFree(domains[i]);
    VIR_FREE(domains);
    for (i = 0; i < ndomains; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshDomainInterfaceCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ninterfaces;
    xmlNodePtr *interfaces = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    char **ret = NULL;
    char **tmp = NULL;

    virCheckFlags(VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (vshCommandOptBool(cmd, "config"))
        domainXMLFlags = VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXML(ctl, cmd, domainXMLFlags, &xmldoc, &ctxt) < 0)
        goto cleanup;

    ninterfaces = virXPathNodeSet("./devices/interface", ctxt, &interfaces);
    if (ninterfaces < 0)
        goto cleanup;

    if (VIR_ALLOC_N(tmp, ninterfaces + 1) < 0)
        goto cleanup;

    for (i = 0; i < ninterfaces; i++) {
        ctxt->node = interfaces[i];

        if (!(flags & VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC) &&
            (tmp[i] = virXPathString("string(./target/@dev)", ctxt)))
            continue;

        /* In case we are dealing with inactive domain XML there's no
         * <target dev=''/>. Offer MAC addresses then. */
        if (!(tmp[i] = virXPathString("string(./mac/@address)", ctxt)))
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);
 cleanup:
    VIR_FREE(interfaces);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    virStringListFree(tmp);
    return ret;
}


char **
virshDomainDiskTargetCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *disks = NULL;
    int ndisks;
    size_t i;
    char **tmp = NULL;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xmldoc, &ctxt) < 0)
        goto cleanup;

    ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks);
    if (ndisks < 0)
        goto cleanup;

    if (VIR_ALLOC_N(tmp, ndisks + 1) < 0)
        goto cleanup;

    for (i = 0; i < ndisks; i++) {
        ctxt->node = disks[i];
        if (!(tmp[i] = virXPathString("string(./target/@dev)", ctxt)))
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);
 cleanup:
    VIR_FREE(disks);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    virStringListFree(tmp);
    return ret;
}


char **
virshStoragePoolNameCompleter(vshControl *ctl,
                              const vshCmd *cmd ATTRIBUTE_UNUSED,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virStoragePoolPtr *pools = NULL;
    int npools = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((npools = virConnectListAllStoragePools(priv->conn, &pools, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, npools + 1) < 0)
        goto error;

    for (i = 0; i < npools; i++) {
        const char *name = virStoragePoolGetName(pools[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virStoragePoolFree(pools[i]);
    }
    VIR_FREE(pools);

    return ret;

 error:
    for (; i < npools; i++)
        virStoragePoolFree(pools[i]);
    VIR_FREE(pools);
    for (i = 0; i < npools; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshStorageVolNameCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr *vols = NULL;
    int nvols = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if ((nvols = virStoragePoolListAllVolumes(pool, &vols, flags)) < 0)
        goto error;

    if (VIR_ALLOC_N(ret, nvols + 1) < 0)
        goto error;

    for (i = 0; i < nvols; i++) {
        const char *name = virStorageVolGetName(vols[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virStorageVolFree(vols[i]);
    }
    VIR_FREE(vols);
    virStoragePoolFree(pool);

    return ret;

 error:
    for (; i < nvols; i++)
        virStorageVolFree(vols[i]);
    VIR_FREE(vols);
    for (i = 0; i < nvols; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    virStoragePoolFree(pool);
    return NULL;
}


char **
virshInterfaceNameCompleter(vshControl *ctl,
                            const vshCmd *cmd ATTRIBUTE_UNUSED,
                            unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virInterfacePtr *ifaces = NULL;
    int nifaces = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_ACTIVE |
                  VIR_CONNECT_LIST_INTERFACES_INACTIVE,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nifaces = virConnectListAllInterfaces(priv->conn, &ifaces, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nifaces + 1) < 0)
        goto error;

    for (i = 0; i < nifaces; i++) {
        const char *name = virInterfaceGetName(ifaces[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virInterfaceFree(ifaces[i]);
    }
    VIR_FREE(ifaces);

    return ret;

 error:
    for (; i < nifaces; i++)
        virInterfaceFree(ifaces[i]);
    VIR_FREE(ifaces);
    for (i = 0; i < nifaces; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshNetworkNameCompleter(vshControl *ctl,
                          const vshCmd *cmd ATTRIBUTE_UNUSED,
                          unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNetworkPtr *nets = NULL;
    int nnets = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_INACTIVE |
                  VIR_CONNECT_LIST_NETWORKS_ACTIVE |
                  VIR_CONNECT_LIST_NETWORKS_PERSISTENT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nnets = virConnectListAllNetworks(priv->conn, &nets, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nnets + 1) < 0)
        goto error;

    for (i = 0; i < nnets; i++) {
        const char *name = virNetworkGetName(nets[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virNetworkFree(nets[i]);
    }
    VIR_FREE(nets);

    return ret;

 error:
    for (; i < nnets; i++)
        virNetworkFree(nets[i]);
    VIR_FREE(nets);
    for (i = 0; i < nnets; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshNodeDeviceNameCompleter(vshControl *ctl,
                             const vshCmd *cmd ATTRIBUTE_UNUSED,
                             unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNodeDevicePtr *devs = NULL;
    int ndevs = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndevs = virConnectListAllNodeDevices(priv->conn, &devs, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, ndevs + 1) < 0)
        goto error;

    for (i = 0; i < ndevs; i++) {
        const char *name = virNodeDeviceGetName(devs[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virNodeDeviceFree(devs[i]);
    }
    VIR_FREE(devs);

    return ret;

 error:
    for (; i < ndevs; i++)
        virNodeDeviceFree(devs[i]);
    VIR_FREE(devs);
    for (i = 0; i < ndevs; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshNWFilterNameCompleter(vshControl *ctl,
                           const vshCmd *cmd ATTRIBUTE_UNUSED,
                           unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNWFilterPtr *nwfilters = NULL;
    int nnwfilters = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nnwfilters = virConnectListAllNWFilters(priv->conn, &nwfilters, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nnwfilters + 1) < 0)
        goto error;

    for (i = 0; i < nnwfilters; i++) {
        const char *name = virNWFilterGetName(nwfilters[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virNWFilterFree(nwfilters[i]);
    }
    VIR_FREE(nwfilters);

    return ret;

 error:
    for (; i < nnwfilters; i++)
        virNWFilterFree(nwfilters[i]);
    VIR_FREE(nwfilters);
    for (i = 0; i < nnwfilters; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshNWFilterBindingNameCompleter(vshControl *ctl,
                                  const vshCmd *cmd ATTRIBUTE_UNUSED,
                                  unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNWFilterBindingPtr *bindings = NULL;
    int nbindings = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nbindings = virConnectListAllNWFilterBindings(priv->conn, &bindings, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nbindings + 1) < 0)
        goto error;

    for (i = 0; i < nbindings; i++) {
        const char *name = virNWFilterBindingGetPortDev(bindings[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virNWFilterBindingFree(bindings[i]);
    }
    VIR_FREE(bindings);

    return ret;

 error:
    for (; i < nbindings; i++)
        virNWFilterBindingFree(bindings[i]);
    VIR_FREE(bindings);
    for (i = 0; i < nbindings; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshSecretUUIDCompleter(vshControl *ctl,
                         const vshCmd *cmd ATTRIBUTE_UNUSED,
                         unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virSecretPtr *secrets = NULL;
    int nsecrets = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nsecrets = virConnectListAllSecrets(priv->conn, &secrets, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nsecrets + 1) < 0)
        goto error;

    for (i = 0; i < nsecrets; i++) {
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virSecretGetUUIDString(secrets[i], uuid) < 0 ||
            VIR_STRDUP(ret[i], uuid) < 0)
            goto error;

        virSecretFree(secrets[i]);
    }
    VIR_FREE(secrets);

    return ret;

 error:
    for (; i < nsecrets; i++)
        virSecretFree(secrets[i]);
    VIR_FREE(secrets);
    for (i = 0; i < nsecrets; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}


char **
virshSnapshotNameCompleter(vshControl *ctl,
                           const vshCmd *cmd,
                           unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr *snapshots = NULL;
    int nsnapshots = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if ((nsnapshots = virDomainListAllSnapshots(dom, &snapshots, flags)) < 0)
        goto error;

    if (VIR_ALLOC_N(ret, nsnapshots + 1) < 0)
        goto error;

    for (i = 0; i < nsnapshots; i++) {
        const char *name = virDomainSnapshotGetName(snapshots[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virshDomainSnapshotFree(snapshots[i]);
    }
    VIR_FREE(snapshots);
    virshDomainFree(dom);

    return ret;

 error:
    for (; i < nsnapshots; i++)
        virshDomainSnapshotFree(snapshots[i]);
    VIR_FREE(snapshots);
    for (i = 0; i < nsnapshots; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    virshDomainFree(dom);
    return NULL;
}

char **
virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                 const vshCmd *cmd ATTRIBUTE_UNUSED,
                                 unsigned int flags)
{
    unsigned long long byteval = 0;
    xmlXPathContextPtr ctxt = NULL;
    virshControlPtr priv = ctl->privData;
    unsigned int npages = 0;
    xmlNodePtr *pages = NULL;
    xmlDocPtr doc = NULL;
    double size = 0;
    size_t i = 0;
    const char *suffix = NULL;
    const char *cellnum = NULL;
    bool cellno = vshCommandOptBool(cmd, "cellno");
    char *path = NULL;
    char *pagesize = NULL;
    char *cap_xml = NULL;
    char **ret = NULL;
    char *unit = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        goto error;

    if (!(cap_xml = virConnectGetCapabilities(priv->conn)))
        goto error;

    if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt)))
        goto error;

    if (cellno && vshCommandOptStringQuiet(ctl, cmd, "cellno", &cellnum) > 0) {
        if (virAsprintf(&path,
                        "/capabilities/host/topology/cells/cell[@id=\"%s\"]/pages",
                        cellnum) < 0)
            goto error;
    } else {
        if (virAsprintf(&path, "/capabilities/host/cpu/pages") < 0)
            goto error;
    }

    npages = virXPathNodeSet(path, ctxt, &pages);
    if (npages <= 0)
        goto error;

    if (VIR_ALLOC_N(ret, npages + 1) < 0)
        goto error;

    for (i = 0; i < npages; i++) {
        VIR_FREE(pagesize);
        VIR_FREE(unit);
        pagesize = virXMLPropString(pages[i], "size");
        unit = virXMLPropString(pages[i], "unit");
        if (virStrToLong_ull(pagesize, NULL, 10, &byteval) < 0)
            goto error;
        if (virScaleInteger(&byteval, unit, 1024, UINT_MAX) < 0)
            goto error;
        size = vshPrettyCapacity(byteval, &suffix);
        if (virAsprintf(&ret[i], "%.0f%s", size, suffix) < 0)
            goto error;
    }

 cleanup:
    xmlXPathFreeContext(ctxt);
    VIR_FREE(pages);
    xmlFreeDoc(doc);
    VIR_FREE(path);
    VIR_FREE(pagesize);
    VIR_FREE(cap_xml);
    VIR_FREE(unit);

    return ret;

 error:
    if (ret) {
        for (i = 0; i < npages; i++)
            VIR_FREE(ret[i]);
    }
    VIR_FREE(ret);
    goto cleanup;
}


char **
virshSecretEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                              const vshCmd *cmd ATTRIBUTE_UNUSED,
                              unsigned int flags)
{
    size_t i;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(ret, VIR_SECRET_EVENT_ID_LAST) < 0)
        goto error;

    for (i = 0; i < VIR_SECRET_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(ret[i], virshSecretEventCallbacks[i].name) < 0)
            goto error;
    }

    return ret;

 error:
    virStringListFree(ret);
    return NULL;
}


char **
virshDomainEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                              const vshCmd *cmd ATTRIBUTE_UNUSED,
                              unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(ret, VIR_DOMAIN_EVENT_ID_LAST + 1) < 0)
        goto error;

    for (i = 0; i < VIR_DOMAIN_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(ret[i], virshDomainEventCallbacks[i].name) < 0)
            goto error;
    }

    return ret;

 error:
    virStringListFree(ret);
    return NULL;
}


char **
virshPoolEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                            const vshCmd *cmd ATTRIBUTE_UNUSED,
                            unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(ret, VIR_STORAGE_POOL_EVENT_ID_LAST) < 0)
        goto error;

    for (i = 0; i < VIR_STORAGE_POOL_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(ret[i], virshPoolEventCallbacks[i].name) < 0)
            goto error;
    }

    return ret;

 error:
    virStringListFree(ret);
    return NULL;
}


char **
virshNodedevEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                               const vshCmd *cmd ATTRIBUTE_UNUSED,
                               unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(ret, VIR_NODE_DEVICE_EVENT_ID_LAST) < 0)
        goto error;

    for (i = 0; i < VIR_NODE_DEVICE_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(ret[i], virshNodedevEventCallbacks[i].name) < 0)
            goto error;
    }

    return ret;

 error:
    virStringListFree(ret);
    return NULL;
}


char **
virshCellnoCompleter(vshControl *ctl,
                     const vshCmd *cmd ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virshControlPtr priv = ctl->privData;
    unsigned int ncells = 0;
    xmlNodePtr *cells = NULL;
    xmlDocPtr doc = NULL;
    size_t i = 0;
    char *cap_xml = NULL;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        goto error;

    if (!(cap_xml = virConnectGetCapabilities(priv->conn)))
        goto error;

    if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt)))
        goto error;

    ncells = virXPathNodeSet("/capabilities/host/topology/cells/cell", ctxt, &cells);
    if (ncells <= 0)
        goto error;

    if (VIR_ALLOC_N(ret, ncells + 1))
        goto error;

    for (i = 0; i < ncells; i++) {
        if (!(ret[i] = virXMLPropString(cells[i], "id")))
            goto error;
    }

 cleanup:
    xmlXPathFreeContext(ctxt);
    VIR_FREE(cells);
    xmlFreeDoc(doc);
    VIR_FREE(cap_xml);

    return ret;

 error:
    if (ret) {
        for (i = 0; i < ncells; i++)
            VIR_FREE(ret[i]);
    }
    VIR_FREE(ret);
    goto cleanup;
}
