/*
 * virnvme.c: helper APIs for managing NVMe devices
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

#include "virnvme.h"
#include "virobject.h"
#include "virpci.h"
#include "viralloc.h"
#include "virlog.h"

VIR_LOG_INIT("util.nvme");
#define VIR_FROM_THIS VIR_FROM_NONE

struct _virNVMeDevice {
    virPCIDeviceAddress address; /* PCI address of controller */
    unsigned int namespace; /* Namespace ID */
    bool managed;

    char *drvname;
    char *domname;
};


struct _virNVMeDeviceList {
    virObjectLockable parent;

    size_t count;
    virNVMeDevice **devs;
};


static virClass *virNVMeDeviceListClass;

static void virNVMeDeviceListDispose(void *obj);

static int
virNVMeOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNVMeDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNVMe);


virNVMeDevice *
virNVMeDeviceNew(const virPCIDeviceAddress *address,
                 unsigned long namespace,
                 bool managed)
{
    virNVMeDevice *dev = NULL;

    dev = g_new0(virNVMeDevice, 1);

    virPCIDeviceAddressCopy(&dev->address, address);
    dev->namespace = namespace;
    dev->managed = managed;

    return dev;
}


void
virNVMeDeviceFree(virNVMeDevice *dev)
{
    if (!dev)
        return;

    virNVMeDeviceUsedByClear(dev);
    g_free(dev);
}


virNVMeDevice *
virNVMeDeviceCopy(const virNVMeDevice *dev)
{
    virNVMeDevice *copy = NULL;

    copy = g_new0(virNVMeDevice, 1);
    copy->drvname = g_strdup(dev->drvname);
    copy->domname = g_strdup(dev->domname);

    virPCIDeviceAddressCopy(&copy->address, &dev->address);
    copy->namespace = dev->namespace;
    copy->managed = dev->managed;

    return copy;
}


const virPCIDeviceAddress *
virNVMeDeviceAddressGet(const virNVMeDevice *dev)
{
    return &dev->address;
}


void
virNVMeDeviceUsedByClear(virNVMeDevice *dev)
{
    VIR_FREE(dev->drvname);
    VIR_FREE(dev->domname);
}


void
virNVMeDeviceUsedByGet(const virNVMeDevice *dev,
                       const char **drv,
                       const char **dom)
{
    *drv = dev->drvname;
    *dom = dev->domname;
}


void
virNVMeDeviceUsedBySet(virNVMeDevice *dev,
                       const char *drv,
                       const char *dom)
{
    dev->drvname = g_strdup(drv);
    dev->domname = g_strdup(dom);
}


virNVMeDeviceList *
virNVMeDeviceListNew(void)
{
    virNVMeDeviceList *list;

    if (virNVMeInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virNVMeDeviceListClass)))
        return NULL;

    return list;
}


static void
virNVMeDeviceListDispose(void *obj)
{
    virNVMeDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++)
        virNVMeDeviceFree(list->devs[i]);

    g_free(list->devs);
}


size_t
virNVMeDeviceListCount(const virNVMeDeviceList *list)
{
    return list->count;
}


int
virNVMeDeviceListAdd(virNVMeDeviceList *list,
                     const virNVMeDevice *dev)
{
    virNVMeDevice *tmp;

    if ((tmp = virNVMeDeviceListLookup(list, dev))) {
        g_autofree char *addrStr = virPCIDeviceAddressAsString(&tmp->address);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("NVMe device %1$s namespace %2$u is already on the list"),
                       NULLSTR(addrStr), tmp->namespace);
        return -1;
    }

    if (!(tmp = virNVMeDeviceCopy(dev)))
        return -1;

    VIR_APPEND_ELEMENT(list->devs, list->count, tmp);

    return 0;
}


int
virNVMeDeviceListDel(virNVMeDeviceList *list,
                     const virNVMeDevice *dev)
{
    ssize_t idx;
    virNVMeDevice *tmp = NULL;

    if ((idx = virNVMeDeviceListLookupIndex(list, dev)) < 0) {
        g_autofree char *addrStr = virPCIDeviceAddressAsString(&dev->address);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("NVMe device %1$s namespace %2$u not found"),
                       NULLSTR(addrStr), dev->namespace);
        return -1;
    }

    tmp = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    virNVMeDeviceFree(tmp);
    return 0;
}


virNVMeDevice *
virNVMeDeviceListGet(virNVMeDeviceList *list,
                     size_t i)
{
    return i < list->count ? list->devs[i] : NULL;
}


virNVMeDevice *
virNVMeDeviceListLookup(virNVMeDeviceList *list,
                        const virNVMeDevice *dev)
{
    ssize_t idx;

    if ((idx = virNVMeDeviceListLookupIndex(list, dev)) < 0)
        return NULL;

    return list->devs[idx];
}


ssize_t
virNVMeDeviceListLookupIndex(virNVMeDeviceList *list,
                             const virNVMeDevice *dev)
{
    size_t i;

    if (!list)
        return -1;

    for (i = 0; i < list->count; i++) {
        virNVMeDevice *other = list->devs[i];

        if (virPCIDeviceAddressEqual(&dev->address, &other->address) &&
            dev->namespace == other->namespace)
            return i;
    }

    return -1;
}


static virNVMeDevice *
virNVMeDeviceListLookupByPCIAddress(virNVMeDeviceList *list,
                                    const virPCIDeviceAddress *address)
{
    size_t i;

    if (!list)
        return NULL;

    for (i = 0; i < list->count; i++) {
        virNVMeDevice *other = list->devs[i];

        if (virPCIDeviceAddressEqual(address, &other->address))
            return other;
    }

    return NULL;
}


static virPCIDevice *
virNVMeDeviceCreatePCIDevice(const virNVMeDevice *nvme)
{
    g_autoptr(virPCIDevice) pci = NULL;

    if (!(pci = virPCIDeviceNew(&nvme->address)))
        return NULL;

    /* NVMe devices must be bound to vfio */
    virPCIDeviceSetStubDriverType(pci, VIR_PCI_STUB_DRIVER_VFIO);
    virPCIDeviceSetManaged(pci, nvme->managed);

    return g_steal_pointer(&pci);
}


/**
 * virNVMeDeviceListCreateDetachList:
 * @activeList: list of active NVMe devices
 * @toDetachList: list of NVMe devices to detach from the host
 *
 * This function creates a list of PCI devices which can then be
 * reused by PCI device detach functions (e.g.
 * virHostdevPreparePCIDevicesImpl()) as each PCI device from the
 * returned list is initialized properly for detach.
 *
 * Basically, this just blindly collects unique PCI addresses
 * from @toDetachList that don't appear on @activeList.
 *
 * Returns: a list on success,
 *          NULL otherwise.
 */
virPCIDeviceList *
virNVMeDeviceListCreateDetachList(virNVMeDeviceList *activeList,
                                  virNVMeDeviceList *toDetachList)
{
    g_autoptr(virPCIDeviceList) pciDevices = NULL;
    size_t i;

    if (!(pciDevices = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < toDetachList->count; i++) {
        const virNVMeDevice *d = toDetachList->devs[i];
        g_autoptr(virPCIDevice) pci = NULL;

        /* If there is a NVMe device with the same PCI address on
         * the activeList, the device is already detached. */
        if (virNVMeDeviceListLookupByPCIAddress(activeList, &d->address))
            continue;

        /* It may happen that we want to detach two namespaces
         * from the same NVMe device. This will be represented as
         * two different instances of virNVMeDevice, but
         * obviously we want to put the PCI device on the detach
         * list only once. */
        if (virPCIDeviceListFindByIDs(pciDevices,
                                      d->address.domain,
                                      d->address.bus,
                                      d->address.slot,
                                      d->address.function))
            continue;

        if (!(pci = virNVMeDeviceCreatePCIDevice(d)))
            return NULL;

        if (virPCIDeviceListAdd(pciDevices, pci) < 0)
            return NULL;

        /* avoid freeing the device */
        pci = NULL;
    }

    return g_steal_pointer(&pciDevices);
}


/**
 * virNVMeDeviceListCreateReAttachList:
 * @activeList: list of active NVMe devices
 * @toReAttachList: list of devices to reattach to the host
 *
 * This is a counterpart to virNVMeDeviceListCreateDetachList.
 *
 * This function creates a list of PCI devices which can then be
 * reused by PCI device reattach functions (e.g.
 * virHostdevReAttachPCIDevicesImpl()) as each PCI device from
 * the returned list is initialized properly for reattach.
 *
 * Basically, this just collects unique PCI addresses
 * of devices that appear on @toReAttachList and are used
 * exactly once (i.e. no other namespaces are used from the same
 * NVMe device). For that purpose, this function needs to know
 * list of active NVMe devices (@activeList).
 *
 * Returns: a list on success,
 *          NULL otherwise.
 */
virPCIDeviceList *
virNVMeDeviceListCreateReAttachList(virNVMeDeviceList *activeList,
                                    virNVMeDeviceList *toReAttachList)
{
    g_autoptr(virPCIDeviceList) pciDevices = NULL;
    size_t i;

    if (!(pciDevices = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < toReAttachList->count; i++) {
        const virNVMeDevice *d = toReAttachList->devs[i];
        g_autoptr(virPCIDevice) pci = NULL;
        size_t nused = 0;
        size_t j;

        /* Check if there is any other NVMe device with the same PCI address as
         * @d. To simplify this, let's just count how many NVMe devices with
         * the same PCI address there are on the @activeList. */
        for (j = 0; j < activeList->count; j++) {
            virNVMeDevice *other = activeList->devs[j];

            if (!virPCIDeviceAddressEqual(&d->address, &other->address))
                continue;

            nused++;
        }

        /* Now, the following cases can happen:
         * nused > 1  -> there are other NVMe device active, do NOT detach it
         * nused == 1 -> we've found only @d on the @activeList, detach it
         * nused == 0 -> huh, wait, what? @d is NOT on the @active list, how can
         *               we reattach it?
         */

        if (nused == 0) {
            /* Shouldn't happen (TM) */
            g_autofree char *addrStr = virPCIDeviceAddressAsString(&d->address);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("NVMe device %1$s namespace %2$u not found"),
                           NULLSTR(addrStr), d->namespace);
            return NULL;
        } else if (nused > 1) {
            /* NVMe device is still in use */
            continue;
        }

        /* nused == 1 -> detach the device */
        if (!(pci = virNVMeDeviceCreatePCIDevice(d)))
            return NULL;

        if (virPCIDeviceListAdd(pciDevices, pci) < 0)
            return NULL;

        /* avoid freeing the device */
        pci = NULL;
    }

    return g_steal_pointer(&pciDevices);
}
