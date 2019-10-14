/*
 * bhyve_domain.c: bhyve domain private state
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#include "bhyve_conf.h"
#include "bhyve_device.h"
#include "bhyve_domain.h"
#include "bhyve_capabilities.h"
#include "viralloc.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_domain");

static void *
bhyveDomainObjPrivateAlloc(void *opaque G_GNUC_UNUSED)
{
    bhyveDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

static void
bhyveDomainObjPrivateFree(void *data)
{
    bhyveDomainObjPrivatePtr priv = data;

    virDomainPCIAddressSetFree(priv->pciaddrs);

    VIR_FREE(priv);
}

virDomainXMLPrivateDataCallbacks virBhyveDriverPrivateDataCallbacks = {
    .alloc = bhyveDomainObjPrivateAlloc,
    .free = bhyveDomainObjPrivateFree,
};

bool
bhyveDomainDefNeedsISAController(virDomainDefPtr def)
{
    if (def->os.bootloader == NULL && def->os.loader)
        return true;

    if (def->nserials)
        return true;

    if (def->ngraphics && def->nvideos)
        return true;

    return false;
}

static int
bhyveDomainDefPostParse(virDomainDefPtr def,
                        virCapsPtr caps G_GNUC_UNUSED,
                        unsigned int parseFlags G_GNUC_UNUSED,
                        void *opaque G_GNUC_UNUSED,
                        void *parseOpaque G_GNUC_UNUSED)
{
    /* Add an implicit PCI root controller */
    if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        return -1;

    return 0;
}

static int
bhyveDomainDiskDefAssignAddress(bhyveConnPtr driver,
                                virDomainDiskDefPtr def,
                                const virDomainDef *vmdef G_GNUC_UNUSED)
{
    int idx = virDiskNameToIndex(def->dst);

    if (idx < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unknown disk name '%s' and no address specified"),
                       def->dst);
        return -1;
    }

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        if ((driver->bhyvecaps & BHYVE_CAP_AHCI32SLOT) != 0) {
            def->info.addr.drive.controller = idx / 32;
            def->info.addr.drive.unit = idx % 32;
        } else {
            def->info.addr.drive.controller = idx;
            def->info.addr.drive.unit = 0;
        }

        def->info.addr.drive.bus = 0;
        break;
    }
    return 0;
}

static int
bhyveDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                              const virDomainDef *def,
                              virCapsPtr caps G_GNUC_UNUSED,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque,
                              void *parseOpaque G_GNUC_UNUSED)
{
    bhyveConnPtr driver = opaque;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDefPtr disk = dev->data.disk;

        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            bhyveDomainDiskDefAssignAddress(driver, disk, def) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        virDomainControllerDefPtr cont = dev->data.controller;

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
             cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) &&
            cont->idx != 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("pci-root and pcie-root controllers "
                             "should have index 0"));
            return -1;
        }
    }

    return 0;
}

static int
bhyveDomainDefAssignAddresses(virDomainDef *def,
                              virCapsPtr caps G_GNUC_UNUSED,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED,
                              void *parseOpaque G_GNUC_UNUSED)
{
    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        return -1;

    return 0;
}

virDomainXMLOptionPtr
virBhyveDriverCreateXMLConf(bhyveConnPtr driver)
{
    virBhyveDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virBhyveDriverDomainDefParserConfig,
                                 &virBhyveDriverPrivateDataCallbacks,
                                 &virBhyveDriverDomainXMLNamespace,
                                 NULL, NULL);
}

virDomainDefParserConfig virBhyveDriverDomainDefParserConfig = {
    .devicesPostParseCallback = bhyveDomainDeviceDefPostParse,
    .domainPostParseCallback = bhyveDomainDefPostParse,
    .assignAddressesCallback = bhyveDomainDefAssignAddresses,
};

static void
bhyveDomainDefNamespaceFree(void *nsdata)
{
    bhyveDomainCmdlineDefPtr cmd = nsdata;

    bhyveDomainCmdlineDefFree(cmd);
}

static int
bhyveDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                             void **data)
{
    bhyveDomainCmdlineDefPtr cmd = NULL;
    xmlNodePtr *nodes = NULL;
    int n;
    size_t i;
    int ret = -1;

    if (VIR_ALLOC(cmd) < 0)
        return -1;

    n = virXPathNodeSet("./bhyve:commandline/bhyve:arg", ctxt, &nodes);
    if (n == 0)
        ret = 0;
    if (n <= 0)
        goto cleanup;

    if (VIR_ALLOC_N(cmd->args, n) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        cmd->args[cmd->num_args] = virXMLPropString(nodes[i], "value");
        if (cmd->args[cmd->num_args] == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No bhyve command-line argument specified"));
            goto cleanup;
        }
        cmd->num_args++;
    }

    VIR_STEAL_PTR(*data, cmd);
    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    bhyveDomainDefNamespaceFree(cmd);

    return ret;
}

static int
bhyveDomainDefNamespaceFormatXML(virBufferPtr buf,
                                 void *nsdata)
{
    bhyveDomainCmdlineDefPtr cmd = nsdata;
    size_t i;

    if (!cmd->num_args)
        return 0;

    virBufferAddLit(buf, "<bhyve:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "<bhyve:arg value='%s'/>\n",
                              cmd->args[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bhyve:commandline>\n");

    return 0;
}

virXMLNamespace virBhyveDriverDomainXMLNamespace = {
    .parse = bhyveDomainDefNamespaceParse,
    .free = bhyveDomainDefNamespaceFree,
    .format = bhyveDomainDefNamespaceFormatXML,
    .prefix = "bhyve",
    .uri = "http://libvirt.org/schemas/domain/bhyve/1.0",

};
