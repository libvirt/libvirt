/*
 * capabilities.c: hypervisor capabilities
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include <unistd.h>

#include "capabilities.h"
#include "cpu_conf.h"
#include "domain_conf.h"
#include "physmem.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "virarch.h"
#include "virbuffer.h"
#include "virerror.h"
#include "virfile.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "virlog.h"
#include "virnuma.h"
#include "virstring.h"
#include "virtypedparam.h"
#include "viruuid.h"
#include "virenum.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

#define SYSFS_SYSTEM_PATH "/sys/devices/system"

VIR_LOG_INIT("conf.capabilities");

VIR_ENUM_DECL(virCapsHostPMTarget);
VIR_ENUM_IMPL(virCapsHostPMTarget,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "suspend_mem", "suspend_disk", "suspend_hybrid",
);

static virClassPtr virCapsClass;
static void virCapsDispose(void *obj);

static int virCapabilitiesOnceInit(void)
{
    if (!VIR_CLASS_NEW(virCaps, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCapabilities);

/**
 * virCapabilitiesNew:
 * @hostarch: host machine architecture
 * @offlineMigrate: true if offline migration is available
 * @liveMigrate: true if live migration is available
 *
 * Allocate a new capabilities object
 */
virCapsPtr
virCapabilitiesNew(virArch hostarch,
                   bool offlineMigrate,
                   bool liveMigrate)
{
    virCapsPtr caps;

    if (virCapabilitiesInitialize() < 0)
        return NULL;

    if (!(caps = virObjectNew(virCapsClass)))
        return NULL;

    caps->host.arch = hostarch;
    caps->host.offlineMigrate = offlineMigrate;
    caps->host.liveMigrate = liveMigrate;

    return caps;
}

void
virCapabilitiesClearHostNUMACellCPUTopology(virCapsHostNUMACellCPUPtr cpus,
                                            size_t ncpus)
{
    size_t i;

    if (!cpus)
        return;

    for (i = 0; i < ncpus; i++) {
        virBitmapFree(cpus[i].siblings);
        cpus[i].siblings = NULL;
    }
}

static void
virCapabilitiesFreeHostNUMACell(virCapsHostNUMACellPtr cell)
{
    if (cell == NULL)
        return;

    virCapabilitiesClearHostNUMACellCPUTopology(cell->cpus, cell->ncpus);

    VIR_FREE(cell->cpus);
    VIR_FREE(cell->siblings);
    VIR_FREE(cell->pageinfo);
    VIR_FREE(cell);
}

static void
virCapabilitiesFreeGuestMachine(virCapsGuestMachinePtr machine)
{
    if (machine == NULL)
        return;
    VIR_FREE(machine->name);
    VIR_FREE(machine->canonical);
    VIR_FREE(machine);
}

static void
virCapabilitiesFreeGuestDomain(virCapsGuestDomainPtr dom)
{
    size_t i;
    if (dom == NULL)
        return;

    VIR_FREE(dom->info.emulator);
    VIR_FREE(dom->info.loader);
    for (i = 0; i < dom->info.nmachines; i++)
        virCapabilitiesFreeGuestMachine(dom->info.machines[i]);
    VIR_FREE(dom->info.machines);

    VIR_FREE(dom);
}

static void
virCapabilitiesFreeGuestFeature(virCapsGuestFeaturePtr feature)
{
    if (feature == NULL)
        return;
    VIR_FREE(feature->name);
    VIR_FREE(feature);
}

void
virCapabilitiesFreeGuest(virCapsGuestPtr guest)
{
    size_t i;
    if (guest == NULL)
        return;

    VIR_FREE(guest->arch.defaultInfo.emulator);
    VIR_FREE(guest->arch.defaultInfo.loader);
    for (i = 0; i < guest->arch.defaultInfo.nmachines; i++)
        virCapabilitiesFreeGuestMachine(guest->arch.defaultInfo.machines[i]);
    VIR_FREE(guest->arch.defaultInfo.machines);

    for (i = 0; i < guest->arch.ndomains; i++)
        virCapabilitiesFreeGuestDomain(guest->arch.domains[i]);
    VIR_FREE(guest->arch.domains);

    for (i = 0; i < guest->nfeatures; i++)
        virCapabilitiesFreeGuestFeature(guest->features[i]);
    VIR_FREE(guest->features);

    VIR_FREE(guest);
}


static void
virCapabilitiesFreeStoragePool(virCapsStoragePoolPtr pool)
{
    if (!pool)
        return;

    VIR_FREE(pool);
}


void
virCapabilitiesFreeNUMAInfo(virCapsPtr caps)
{
    size_t i;

    for (i = 0; i < caps->host.nnumaCell; i++)
        virCapabilitiesFreeHostNUMACell(caps->host.numaCell[i]);
    VIR_FREE(caps->host.numaCell);
    caps->host.nnumaCell = 0;
}

static void
virCapsHostMemBWNodeFree(virCapsHostMemBWNodePtr ptr)
{
    if (!ptr)
        return;

    virBitmapFree(ptr->cpus);
    VIR_FREE(ptr);
}

static void
virCapabilitiesClearSecModel(virCapsHostSecModelPtr secmodel)
{
    size_t i;
    for (i = 0; i < secmodel->nlabels; i++) {
        VIR_FREE(secmodel->labels[i].type);
        VIR_FREE(secmodel->labels[i].label);
    }

    VIR_FREE(secmodel->labels);
    VIR_FREE(secmodel->model);
    VIR_FREE(secmodel->doi);
}

static void
virCapsDispose(void *object)
{
    virCapsPtr caps = object;
    size_t i;

    for (i = 0; i < caps->npools; i++)
        virCapabilitiesFreeStoragePool(caps->pools[i]);
    VIR_FREE(caps->pools);

    for (i = 0; i < caps->nguests; i++)
        virCapabilitiesFreeGuest(caps->guests[i]);
    VIR_FREE(caps->guests);

    for (i = 0; i < caps->host.nfeatures; i++)
        VIR_FREE(caps->host.features[i]);
    VIR_FREE(caps->host.features);

    virCapabilitiesFreeNUMAInfo(caps);

    for (i = 0; i < caps->host.nmigrateTrans; i++)
        VIR_FREE(caps->host.migrateTrans[i]);
    VIR_FREE(caps->host.migrateTrans);

    for (i = 0; i < caps->host.nsecModels; i++)
        virCapabilitiesClearSecModel(&caps->host.secModels[i]);
    VIR_FREE(caps->host.secModels);

    for (i = 0; i < caps->host.cache.nbanks; i++)
        virCapsHostCacheBankFree(caps->host.cache.banks[i]);
    virResctrlInfoMonFree(caps->host.cache.monitor);
    VIR_FREE(caps->host.cache.banks);

    for (i = 0; i < caps->host.memBW.nnodes; i++)
        virCapsHostMemBWNodeFree(caps->host.memBW.nodes[i]);
    virResctrlInfoMonFree(caps->host.memBW.monitor);
    VIR_FREE(caps->host.memBW.nodes);

    VIR_FREE(caps->host.netprefix);
    VIR_FREE(caps->host.pagesSize);
    virCPUDefFree(caps->host.cpu);
    virObjectUnref(caps->host.resctrl);
}

/**
 * virCapabilitiesAddHostFeature:
 * @caps: capabilities to extend
 * @name: name of new feature
 *
 * Registers a new host CPU feature, eg 'pae', or 'vmx'
 */
int
virCapabilitiesAddHostFeature(virCapsPtr caps,
                              const char *name)
{
    if (VIR_RESIZE_N(caps->host.features, caps->host.nfeatures_max,
                     caps->host.nfeatures, 1) < 0)
        return -1;

    if (VIR_STRDUP(caps->host.features[caps->host.nfeatures], name) < 0)
        return -1;
    caps->host.nfeatures++;

    return 0;
}

/**
 * virCapabilitiesAddHostMigrateTransport:
 * @caps: capabilities to extend
 * @name: name of migration transport
 *
 * Registers a new domain migration transport URI
 */
int
virCapabilitiesAddHostMigrateTransport(virCapsPtr caps,
                                       const char *name)
{
    if (VIR_RESIZE_N(caps->host.migrateTrans, caps->host.nmigrateTrans_max,
                     caps->host.nmigrateTrans, 1) < 0)
        return -1;

    if (VIR_STRDUP(caps->host.migrateTrans[caps->host.nmigrateTrans], name) < 0)
        return -1;
    caps->host.nmigrateTrans++;

    return 0;
}

/**
 * virCapabilitiesSetNetPrefix:
 * @caps: capabilities to extend
 * @name: prefix for host generated network interfaces
 *
 * Registers the prefix that is used for generated network interfaces
 */
int
virCapabilitiesSetNetPrefix(virCapsPtr caps,
                            const char *prefix)
{
    if (VIR_STRDUP(caps->host.netprefix, prefix) < 0)
        return -1;

    return 0;
}


/**
 * virCapabilitiesAddHostNUMACell:
 * @caps: capabilities to extend
 * @num: ID number of NUMA cell
 * @mem: Total size of memory in the NUMA node (in KiB)
 * @ncpus: number of CPUs in cell
 * @cpus: array of CPU definition structures, the pointer is stolen
 * @nsiblings: number of sibling NUMA nodes
 * @siblings: info on sibling NUMA nodes
 * @npageinfo: number of pages at node @num
 * @pageinfo: info on each single memory page
 *
 * Registers a new NUMA cell for a host, passing in a
 * array of CPU IDs belonging to the cell
 */
int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               unsigned long long mem,
                               int ncpus,
                               virCapsHostNUMACellCPUPtr cpus,
                               int nsiblings,
                               virCapsHostNUMACellSiblingInfoPtr siblings,
                               int npageinfo,
                               virCapsHostNUMACellPageInfoPtr pageinfo)
{
    virCapsHostNUMACellPtr cell;

    if (VIR_RESIZE_N(caps->host.numaCell, caps->host.nnumaCell_max,
                     caps->host.nnumaCell, 1) < 0)
        return -1;

    if (VIR_ALLOC(cell) < 0)
        return -1;

    cell->num = num;
    cell->mem = mem;
    cell->ncpus = ncpus;
    cell->cpus = cpus;
    cell->nsiblings = nsiblings;
    cell->siblings = siblings;
    cell->npageinfo = npageinfo;
    cell->pageinfo = pageinfo;

    caps->host.numaCell[caps->host.nnumaCell++] = cell;

    return 0;
}


/**
 * virCapabilitiesSetHostCPU:
 * @caps: capabilities to extend
 * @cpu: CPU definition
 *
 * Sets host CPU specification
 */
int
virCapabilitiesSetHostCPU(virCapsPtr caps,
                          virCPUDefPtr cpu)
{
    if (cpu == NULL)
        return -1;

    caps->host.cpu = cpu;

    return 0;
}


/**
 * virCapabilitiesAllocMachines:
 * @machines: machine variants for emulator ('pc', or 'isapc', etc)
 * @nmachines: number of machine variants for emulator
 *
 * Allocate a table of virCapsGuestMachinePtr from the supplied table
 * of machine names.
 */
virCapsGuestMachinePtr *
virCapabilitiesAllocMachines(const char *const *names, int nnames)
{
    virCapsGuestMachinePtr *machines;
    size_t i;

    if (VIR_ALLOC_N(machines, nnames) < 0)
        return NULL;

    for (i = 0; i < nnames; i++) {
        if (VIR_ALLOC(machines[i]) < 0 ||
            VIR_STRDUP(machines[i]->name, names[i]) < 0) {
            virCapabilitiesFreeMachines(machines, nnames);
            return NULL;
        }
    }

    return machines;
}

/**
 * virCapabilitiesFreeMachines:
 * @machines: table of vircapsGuestMachinePtr
 *
 * Free a table of virCapsGuestMachinePtr
 */
void
virCapabilitiesFreeMachines(virCapsGuestMachinePtr *machines,
                            int nmachines)
{
    size_t i;
    if (!machines)
        return;
    for (i = 0; i < nmachines && machines[i]; i++) {
        virCapabilitiesFreeGuestMachine(machines[i]);
        machines[i] = NULL;
    }
    VIR_FREE(machines);
}

/**
 * virCapabilitiesAddGuest:
 * @caps: capabilities to extend
 * @ostype: guest operating system type, of enum VIR_DOMAIN_OSTYPE
 * @arch: guest CPU architecture
 * @wordsize: number of bits in CPU word
 * @emulator: path to default device emulator for arch/ostype
 * @loader: path to default BIOS loader for arch/ostype
 * @nmachines: number of machine variants for emulator
 * @machines: machine variants for emulator ('pc', or 'isapc', etc)
 *
 * Registers a new guest operating system. This should be
 * followed by registration of at least one domain for
 * running the guest
 */
virCapsGuestPtr
virCapabilitiesAddGuest(virCapsPtr caps,
                        int ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachinePtr *machines)
{
    virCapsGuestPtr guest;

    if (VIR_ALLOC(guest) < 0)
        goto error;

    guest->ostype = ostype;
    guest->arch.id = arch;
    guest->arch.wordsize = virArchGetWordSize(arch);

    if (VIR_STRDUP(guest->arch.defaultInfo.emulator, emulator) < 0 ||
        VIR_STRDUP(guest->arch.defaultInfo.loader, loader) < 0)
        goto error;

    if (VIR_RESIZE_N(caps->guests, caps->nguests_max,
                     caps->nguests, 1) < 0)
        goto error;
    caps->guests[caps->nguests++] = guest;

    if (nmachines) {
        guest->arch.defaultInfo.nmachines = nmachines;
        guest->arch.defaultInfo.machines = machines;
    }

    return guest;

 error:
    virCapabilitiesFreeGuest(guest);
    return NULL;
}


/**
 * virCapabilitiesAddGuestDomain:
 * @guest: guest to support
 * @hvtype: hypervisor type ('xen', 'qemu', 'kvm')
 * @emulator: specialized device emulator for domain
 * @loader: specialized BIOS loader for domain
 * @nmachines: number of machine variants for emulator
 * @machines: specialized machine variants for emulator
 *
 * Registers a virtual domain capable of running a
 * guest operating system
 */
virCapsGuestDomainPtr
virCapabilitiesAddGuestDomain(virCapsGuestPtr guest,
                              int hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachinePtr *machines)
{
    virCapsGuestDomainPtr dom;

    if (VIR_ALLOC(dom) < 0)
        goto error;

    dom->type = hvtype;
    if (VIR_STRDUP(dom->info.emulator, emulator) < 0 ||
        VIR_STRDUP(dom->info.loader, loader) < 0)
        goto error;

    if (VIR_RESIZE_N(guest->arch.domains, guest->arch.ndomains_max,
                     guest->arch.ndomains, 1) < 0)
        goto error;
    guest->arch.domains[guest->arch.ndomains] = dom;
    guest->arch.ndomains++;

    if (nmachines) {
        dom->info.nmachines = nmachines;
        dom->info.machines = machines;
    }

    return dom;

 error:
    virCapabilitiesFreeGuestDomain(dom);
    return NULL;
}


/**
 * virCapabilitiesAddGuestFeature:
 * @guest: guest to associate feature with
 * @name: name of feature ('pae', 'acpi', 'apic')
 * @defaultOn: true if it defaults to on
 * @toggle: true if its state can be toggled
 *
 * Registers a feature for a guest domain.
 */
virCapsGuestFeaturePtr
virCapabilitiesAddGuestFeature(virCapsGuestPtr guest,
                               const char *name,
                               bool defaultOn,
                               bool toggle)
{
    virCapsGuestFeaturePtr feature;

    if (VIR_ALLOC(feature) < 0)
        goto no_memory;

    if (VIR_STRDUP(feature->name, name) < 0)
        goto no_memory;
    feature->defaultOn = defaultOn;
    feature->toggle = toggle;

    if (VIR_RESIZE_N(guest->features, guest->nfeatures_max,
                     guest->nfeatures, 1) < 0)
        goto no_memory;
    guest->features[guest->nfeatures++] = feature;

    return feature;

 no_memory:
    virCapabilitiesFreeGuestFeature(feature);
    return NULL;
}

/**
 * virCapabilitiesHostSecModelAddBaseLabel
 * @secmodel: Security model to add a base label for
 * @type: virtualization type
 * @label: base label
 *
 * Returns non-zero on error.
 */
extern int
virCapabilitiesHostSecModelAddBaseLabel(virCapsHostSecModelPtr secmodel,
                                        const char *type,
                                        const char *label)
{
    char *t = NULL, *l = NULL;

    if (type == NULL || label == NULL)
        return -1;

    if (VIR_STRDUP(t, type) < 0)
        goto no_memory;

    if (VIR_STRDUP(l, label) < 0)
        goto no_memory;

    if (VIR_EXPAND_N(secmodel->labels, secmodel->nlabels, 1) < 0)
        goto no_memory;

    secmodel->labels[secmodel->nlabels - 1].type = t;
    secmodel->labels[secmodel->nlabels - 1].label = l;

    return 0;

 no_memory:
    VIR_FREE(l);
    VIR_FREE(t);
    return -1;
}


static virCapsDomainDataPtr
virCapabilitiesDomainDataLookupInternal(virCapsPtr caps,
                                        int ostype,
                                        virArch arch,
                                        virDomainVirtType domaintype,
                                        const char *emulator,
                                        const char *machinetype)
{
    virCapsGuestPtr foundguest = NULL;
    virCapsGuestDomainPtr founddomain = NULL;
    virCapsGuestMachinePtr foundmachine = NULL;
    virCapsDomainDataPtr ret = NULL;
    size_t i, j, k;

    VIR_DEBUG("Lookup ostype=%d arch=%d domaintype=%d emulator=%s machine=%s",
              ostype, arch, domaintype, NULLSTR(emulator), NULLSTR(machinetype));
    for (i = 0; i < caps->nguests; i++) {
        virCapsGuestPtr guest = caps->guests[i];

        if (ostype != -1 && guest->ostype != ostype) {
            VIR_DEBUG("Skip os type want=%d vs got=%d", ostype, guest->ostype);
            continue;
        }
        VIR_DEBUG("Match os type %d", ostype);

        if ((arch != VIR_ARCH_NONE) && (guest->arch.id != arch)) {
            VIR_DEBUG("Skip arch want=%d vs got=%d", arch, guest->arch.id);
            continue;
        }
        VIR_DEBUG("Match arch %d", arch);

        for (j = 0; j < guest->arch.ndomains; j++) {
            virCapsGuestDomainPtr domain = guest->arch.domains[j];
            virCapsGuestMachinePtr *machinelist;
            int nmachines;
            const char *check_emulator = NULL;

            if (domaintype != VIR_DOMAIN_VIRT_NONE &&
                (domain->type != domaintype)) {
                VIR_DEBUG("Skip domain type want=%d vs got=%d", domaintype, domain->type);
                continue;
            }
            VIR_DEBUG("Match domain type %d", domaintype);

            check_emulator = domain->info.emulator;
            if (!check_emulator)
                check_emulator = guest->arch.defaultInfo.emulator;
            if (emulator && STRNEQ_NULLABLE(check_emulator, emulator)) {
                VIR_DEBUG("Skip emulator got=%s vs want=%s",
                          emulator, NULLSTR(check_emulator));
                continue;
            }
            VIR_DEBUG("Match emulator %s", NULLSTR(emulator));

            if (domain->info.nmachines) {
                nmachines = domain->info.nmachines;
                machinelist = domain->info.machines;
            } else {
                nmachines = guest->arch.defaultInfo.nmachines;
                machinelist = guest->arch.defaultInfo.machines;
            }

            for (k = 0; k < nmachines; k++) {
                virCapsGuestMachinePtr machine = machinelist[k];

                if (machinetype &&
                    STRNEQ(machine->name, machinetype) &&
                    STRNEQ_NULLABLE(machine->canonical, machinetype)) {
                    VIR_DEBUG("Skip machine type want=%s vs got=%s got=%s",
                              machinetype, machine->name, NULLSTR(machine->canonical));
                    continue;
                }
                VIR_DEBUG("Match machine type machine %s", NULLSTR(machinetype));

                foundmachine = machine;
                break;
            }

            if (!foundmachine && nmachines)
                continue;

            founddomain = domain;
            break;
        }

        if (!founddomain)
            continue;

        foundguest = guest;
        break;
    }

    /* XXX check default_emulator, see how it uses this */
    if (!foundguest) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        if (ostype)
            virBufferAsprintf(&buf, "ostype=%s ",
                              virDomainOSTypeToString(ostype));
        if (arch)
            virBufferAsprintf(&buf, "arch=%s ", virArchToString(arch));
        if (domaintype > VIR_DOMAIN_VIRT_NONE)
            virBufferAsprintf(&buf, "domaintype=%s ",
                              virDomainVirtTypeToString(domaintype));
        if (emulator)
            virBufferEscapeString(&buf, "emulator=%s ", emulator);
        if (machinetype)
            virBufferEscapeString(&buf, "machine=%s ", machinetype);
        if (virBufferCurrentContent(&buf) &&
            !virBufferCurrentContent(&buf)[0])
            virBufferAsprintf(&buf, "%s", _("any configuration"));
        if (virBufferCheckError(&buf) < 0) {
            virBufferFreeAndReset(&buf);
            goto error;
        }

        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find capabilities for %s"),
                       virBufferCurrentContent(&buf));
        virBufferFreeAndReset(&buf);
        goto error;
    }

    if (VIR_ALLOC(ret) < 0)
        goto error;

    ret->ostype = foundguest->ostype;
    ret->arch = foundguest->arch.id;
    if (founddomain) {
        ret->domaintype = founddomain->type;
        ret->emulator = founddomain->info.emulator;
    }
    if (!ret->emulator)
        ret->emulator = foundguest->arch.defaultInfo.emulator;
    if (foundmachine)
        ret->machinetype = foundmachine->name;

 error:
    return ret;
}

/**
 * virCapabilitiesDomainDataLookup:
 * @caps: capabilities to query
 * @ostype: guest operating system type, of enum VIR_DOMAIN_OSTYPE
 * @arch: Architecture to search for
 * @domaintype: domain type to search for, of enum virDomainVirtType
 * @emulator: Emulator path to search for
 * @machinetype: Machine type to search for
 *
 * Search capabilities for the passed values, and if found return
 * virCapabilitiesDomainDataLookup filled in with the default values
 */
virCapsDomainDataPtr
virCapabilitiesDomainDataLookup(virCapsPtr caps,
                                int ostype,
                                virArch arch,
                                int domaintype,
                                const char *emulator,
                                const char *machinetype)
{
    virCapsDomainDataPtr ret;

    if (arch == VIR_ARCH_NONE) {
        /* Prefer host arch if its available */
        ret = virCapabilitiesDomainDataLookupInternal(caps, ostype,
                                                      caps->host.arch,
                                                      domaintype,
                                                      emulator, machinetype);
        if (ret)
            return ret;
    }

    return virCapabilitiesDomainDataLookupInternal(caps, ostype,
                                                   arch, domaintype,
                                                   emulator, machinetype);
}


int
virCapabilitiesAddStoragePool(virCapsPtr caps,
                              int poolType)
{
    virCapsStoragePoolPtr pool;

    if (VIR_ALLOC(pool) < 0)
        goto error;

    pool->type = poolType;

    if (VIR_RESIZE_N(caps->pools, caps->npools_max, caps->npools, 1) < 0)
        goto error;
    caps->pools[caps->npools++] = pool;

    return 0;

 error:
    virCapabilitiesFreeStoragePool(pool);
    return -1;
}


static int
virCapabilitiesFormatNUMATopology(virBufferPtr buf,
                                  size_t ncells,
                                  virCapsHostNUMACellPtr *cells)
{
    size_t i;
    size_t j;
    char *siblings;

    virBufferAddLit(buf, "<topology>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<cells num='%zu'>\n", ncells);
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < ncells; i++) {
        virBufferAsprintf(buf, "<cell id='%d'>\n", cells[i]->num);
        virBufferAdjustIndent(buf, 2);

        /* Print out the numacell memory total if it is available */
        if (cells[i]->mem)
            virBufferAsprintf(buf, "<memory unit='KiB'>%llu</memory>\n",
                              cells[i]->mem);

        for (j = 0; j < cells[i]->npageinfo; j++) {
            virBufferAsprintf(buf, "<pages unit='KiB' size='%u'>%llu</pages>\n",
                              cells[i]->pageinfo[j].size,
                              cells[i]->pageinfo[j].avail);
        }

        if (cells[i]->nsiblings) {
            virBufferAddLit(buf, "<distances>\n");
            virBufferAdjustIndent(buf, 2);
            for (j = 0; j < cells[i]->nsiblings; j++) {
                virBufferAsprintf(buf, "<sibling id='%d' value='%d'/>\n",
                                  cells[i]->siblings[j].node,
                                  cells[i]->siblings[j].distance);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</distances>\n");
        }

        virBufferAsprintf(buf, "<cpus num='%d'>\n", cells[i]->ncpus);
        virBufferAdjustIndent(buf, 2);
        for (j = 0; j < cells[i]->ncpus; j++) {
            virBufferAsprintf(buf, "<cpu id='%d'", cells[i]->cpus[j].id);

            if (cells[i]->cpus[j].siblings) {
                if (!(siblings = virBitmapFormat(cells[i]->cpus[j].siblings)))
                    return -1;

                virBufferAsprintf(buf,
                                  " socket_id='%d' core_id='%d' siblings='%s'",
                                  cells[i]->cpus[j].socket_id,
                                  cells[i]->cpus[j].core_id,
                                  siblings);
                VIR_FREE(siblings);
            }
            virBufferAddLit(buf, "/>\n");
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</cpus>\n");
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</cell>\n");
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cells>\n");
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</topology>\n");
    return 0;
}


static int
virCapabilitiesFormatResctrlMonitor(virBufferPtr buf,
                                    virResctrlInfoMonPtr monitor)
{
    size_t i = 0;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;

    /* monitor not supported, no capability */
    if (!monitor)
        return 0;

    /* no feature found in monitor means no capability, return */
    if (monitor->nfeatures == 0)
        return 0;

    virBufferAddLit(buf, "<monitor ");

    /* CMT might not enabled, if enabled show related attributes. */
    if (monitor->type == VIR_RESCTRL_MONITOR_TYPE_CACHE)
        virBufferAsprintf(buf,
                          "level='%u' reuseThreshold='%u' ",
                          monitor->cache_level,
                          monitor->cache_reuse_threshold);
    virBufferAsprintf(buf,
                      "maxMonitors='%u'>\n",
                      monitor->max_monitor);

    virBufferSetChildIndent(&childrenBuf, buf);
    for (i = 0; i < monitor->nfeatures; i++) {
        virBufferAsprintf(&childrenBuf,
                          "<feature name='%s'/>\n",
                          monitor->features[i]);
    }

    if (virBufferCheckError(&childrenBuf) < 0)
        return -1;

    virBufferAddBuffer(buf, &childrenBuf);
    virBufferAddLit(buf, "</monitor>\n");

    return 0;
}

static int
virCapabilitiesFormatCaches(virBufferPtr buf,
                            virCapsHostCachePtr cache)
{
    size_t i = 0;
    size_t j = 0;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;

    if (!cache->nbanks)
        return 0;

    virBufferAddLit(buf, "<cache>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cache->nbanks; i++) {
        virCapsHostCacheBankPtr bank = cache->banks[i];
        char *cpus_str = virBitmapFormat(bank->cpus);
        const char *unit = NULL;
        unsigned long long short_size = virFormatIntPretty(bank->size, &unit);

        if (!cpus_str)
            return -1;

        /*
         * Let's just *hope* the size is aligned to KiBs so that it does not
         * bite is back in the future
         */
        virBufferAsprintf(buf,
                          "<bank id='%u' level='%u' type='%s' "
                          "size='%llu' unit='%s' cpus='%s'",
                          bank->id, bank->level,
                          virCacheTypeToString(bank->type),
                          short_size, unit, cpus_str);
        VIR_FREE(cpus_str);

        virBufferSetChildIndent(&childrenBuf, buf);
        for (j = 0; j < bank->ncontrols; j++) {
            const char *min_unit;
            virResctrlInfoPerCachePtr controls = bank->controls[j];
            unsigned long long gran_short_size = controls->granularity;
            unsigned long long min_short_size = controls->min;

            gran_short_size = virFormatIntPretty(gran_short_size, &unit);
            min_short_size = virFormatIntPretty(min_short_size, &min_unit);

            /* Only use the smaller unit if they are different */
            if (min_short_size) {
                unsigned long long gran_div;
                unsigned long long min_div;

                gran_div = controls->granularity / gran_short_size;
                min_div = controls->min / min_short_size;

                if (min_div > gran_div) {
                    min_short_size *= min_div / gran_div;
                } else if (min_div < gran_div) {
                    unit = min_unit;
                    gran_short_size *= gran_div / min_div;
                }
            }

            virBufferAsprintf(&childrenBuf,
                              "<control granularity='%llu'",
                              gran_short_size);

            if (min_short_size)
                virBufferAsprintf(&childrenBuf, " min='%llu'", min_short_size);

            virBufferAsprintf(&childrenBuf,
                              " unit='%s' type='%s' maxAllocs='%u'/>\n",
                              unit,
                              virCacheTypeToString(controls->scope),
                              controls->max_allocation);
        }

        if (virBufferCheckError(&childrenBuf) < 0)
            return -1;

        if (virBufferUse(&childrenBuf)) {
            virBufferAddLit(buf, ">\n");
            virBufferAddBuffer(buf, &childrenBuf);
            virBufferAddLit(buf, "</bank>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    if (virCapabilitiesFormatResctrlMonitor(buf, cache->monitor) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cache>\n");

    return 0;
}

static int
virCapabilitiesFormatMemoryBandwidth(virBufferPtr buf,
                                     virCapsHostMemBWPtr memBW)
{
    size_t i = 0;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;

    if (!memBW->nnodes)
        return 0;

    virBufferAddLit(buf, "<memory_bandwidth>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < memBW->nnodes; i++) {
        virCapsHostMemBWNodePtr node = memBW->nodes[i];
        virResctrlInfoMemBWPerNodePtr control = &node->control;
        char *cpus_str = virBitmapFormat(node->cpus);

        if (!cpus_str)
            return -1;

        virBufferAsprintf(buf,
                          "<node id='%u' cpus='%s'",
                          node->id, cpus_str);
        VIR_FREE(cpus_str);

        virBufferSetChildIndent(&childrenBuf, buf);
        virBufferAsprintf(&childrenBuf,
                          "<control granularity='%u' min ='%u' "
                          "maxAllocs='%u'/>\n",
                          control->granularity, control->min,
                          control->max_allocation);

        if (virBufferCheckError(&childrenBuf) < 0)
            return -1;

        if (virBufferUse(&childrenBuf)) {
            virBufferAddLit(buf, ">\n");
            virBufferAddBuffer(buf, &childrenBuf);
            virBufferAddLit(buf, "</node>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    if (virCapabilitiesFormatResctrlMonitor(buf, memBW->monitor) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</memory_bandwidth>\n");

    return 0;
}


static int
virCapabilitiesFormatHostXML(virCapsHostPtr host,
                             virBufferPtr buf)
{
    size_t i, j;
    char host_uuid[VIR_UUID_STRING_BUFLEN];

    /* The lack of some data means we have nothing
     * minimally to format, so just return. */
    if (!virUUIDIsValid(host->host_uuid) &&
        !host->arch && !host->powerMgmt && !host->iommu)
        return 0;

    virBufferAddLit(buf, "<host>\n");
    virBufferAdjustIndent(buf, 2);
    if (virUUIDIsValid(host->host_uuid)) {
        virUUIDFormat(host->host_uuid, host_uuid);
        virBufferAsprintf(buf, "<uuid>%s</uuid>\n", host_uuid);
    }
    virBufferAddLit(buf, "<cpu>\n");
    virBufferAdjustIndent(buf, 2);

    if (host->arch)
        virBufferAsprintf(buf, "<arch>%s</arch>\n",
                          virArchToString(host->arch));
    if (host->nfeatures) {
        virBufferAddLit(buf, "<features>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < host->nfeatures; i++) {
            virBufferAsprintf(buf, "<%s/>\n",
                              host->features[i]);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</features>\n");
    }
    virCPUDefFormatBuf(buf, host->cpu);

    for (i = 0; i < host->nPagesSize; i++) {
        virBufferAsprintf(buf, "<pages unit='KiB' size='%u'/>\n",
                          host->pagesSize[i]);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cpu>\n");

    /* The PM query was successful. */
    if (host->powerMgmt) {
        /* The host supports some PM features. */
        unsigned int pm = host->powerMgmt;
        virBufferAddLit(buf, "<power_management>\n");
        virBufferAdjustIndent(buf, 2);
        while (pm) {
            int bit = __builtin_ffs(pm) - 1;
            virBufferAsprintf(buf, "<%s/>\n",
                              virCapsHostPMTargetTypeToString(bit));
            pm &= ~(1U << bit);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</power_management>\n");
    } else {
        /* The host does not support any PM feature. */
        virBufferAddLit(buf, "<power_management/>\n");
    }

    virBufferAsprintf(buf, "<iommu support='%s'/>\n",
                      host->iommu  ? "yes" : "no");

    if (host->offlineMigrate) {
        virBufferAddLit(buf, "<migration_features>\n");
        virBufferAdjustIndent(buf, 2);
        if (host->liveMigrate)
            virBufferAddLit(buf, "<live/>\n");
        if (host->nmigrateTrans) {
            virBufferAddLit(buf, "<uri_transports>\n");
            virBufferAdjustIndent(buf, 2);
            for (i = 0; i < host->nmigrateTrans; i++) {
                virBufferAsprintf(buf, "<uri_transport>%s</uri_transport>\n",
                                  host->migrateTrans[i]);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</uri_transports>\n");
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</migration_features>\n");
    }

    if (host->netprefix)
        virBufferAsprintf(buf, "<netprefix>%s</netprefix>\n",
                          host->netprefix);

    if (host->nnumaCell &&
        virCapabilitiesFormatNUMATopology(buf, host->nnumaCell,
                                          host->numaCell) < 0)
        goto error;

    if (virCapabilitiesFormatCaches(buf, &host->cache) < 0)
        goto error;

    if (virCapabilitiesFormatMemoryBandwidth(buf, &host->memBW) < 0)
        goto error;

    for (i = 0; i < host->nsecModels; i++) {
        virBufferAddLit(buf, "<secmodel>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<model>%s</model>\n",
                          host->secModels[i].model);
        virBufferAsprintf(buf, "<doi>%s</doi>\n",
                          host->secModels[i].doi);
        for (j = 0; j < host->secModels[i].nlabels; j++) {
            virBufferAsprintf(buf, "<baselabel type='%s'>%s</baselabel>\n",
                              host->secModels[i].labels[j].type,
                              host->secModels[i].labels[j].label);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</secmodel>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</host>\n\n");

    return 0;

 error:
    return -1;
}


static void
virCapabilitiesFormatGuestXML(virCapsGuestPtr *guests,
                              size_t nguests,
                              virBufferPtr buf)
{
    size_t i, j, k;

    for (i = 0; i < nguests; i++) {
        virBufferAddLit(buf, "<guest>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<os_type>%s</os_type>\n",
                          virDomainOSTypeToString(guests[i]->ostype));
        if (guests[i]->arch.id)
            virBufferAsprintf(buf, "<arch name='%s'>\n",
                              virArchToString(guests[i]->arch.id));
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<wordsize>%d</wordsize>\n",
                          guests[i]->arch.wordsize);
        if (guests[i]->arch.defaultInfo.emulator)
            virBufferAsprintf(buf, "<emulator>%s</emulator>\n",
                              guests[i]->arch.defaultInfo.emulator);
        if (guests[i]->arch.defaultInfo.loader)
            virBufferAsprintf(buf, "<loader>%s</loader>\n",
                              guests[i]->arch.defaultInfo.loader);

        for (j = 0; j < guests[i]->arch.defaultInfo.nmachines; j++) {
            virCapsGuestMachinePtr machine = guests[i]->arch.defaultInfo.machines[j];
            virBufferAddLit(buf, "<machine");
            if (machine->canonical)
                virBufferAsprintf(buf, " canonical='%s'", machine->canonical);
            if (machine->maxCpus > 0)
                virBufferAsprintf(buf, " maxCpus='%d'", machine->maxCpus);
            virBufferAsprintf(buf, ">%s</machine>\n", machine->name);
        }

        for (j = 0; j < guests[i]->arch.ndomains; j++) {
            virBufferAsprintf(buf, "<domain type='%s'",
                virDomainVirtTypeToString(guests[i]->arch.domains[j]->type));
            if (!guests[i]->arch.domains[j]->info.emulator &&
                !guests[i]->arch.domains[j]->info.loader &&
                !guests[i]->arch.domains[j]->info.nmachines) {
                virBufferAddLit(buf, "/>\n");
                continue;
            }
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            if (guests[i]->arch.domains[j]->info.emulator)
                virBufferAsprintf(buf, "<emulator>%s</emulator>\n",
                                  guests[i]->arch.domains[j]->info.emulator);
            if (guests[i]->arch.domains[j]->info.loader)
                virBufferAsprintf(buf, "<loader>%s</loader>\n",
                                  guests[i]->arch.domains[j]->info.loader);

            for (k = 0; k < guests[i]->arch.domains[j]->info.nmachines; k++) {
                virCapsGuestMachinePtr machine = guests[i]->arch.domains[j]->info.machines[k];
                virBufferAddLit(buf, "<machine");
                if (machine->canonical)
                    virBufferAsprintf(buf, " canonical='%s'", machine->canonical);
                if (machine->maxCpus > 0)
                    virBufferAsprintf(buf, " maxCpus='%d'", machine->maxCpus);
                virBufferAsprintf(buf, ">%s</machine>\n", machine->name);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</domain>\n");
        }

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</arch>\n");

        if (guests[i]->nfeatures) {
            virBufferAddLit(buf, "<features>\n");
            virBufferAdjustIndent(buf, 2);

            for (j = 0; j < guests[i]->nfeatures; j++) {
                if (STREQ(guests[i]->features[j]->name, "pae") ||
                    STREQ(guests[i]->features[j]->name, "nonpae") ||
                    STREQ(guests[i]->features[j]->name, "ia64_be") ||
                    STREQ(guests[i]->features[j]->name, "cpuselection") ||
                    STREQ(guests[i]->features[j]->name, "deviceboot")) {
                    virBufferAsprintf(buf, "<%s/>\n",
                                      guests[i]->features[j]->name);
                } else {
                    virBufferAsprintf(buf, "<%s default='%s' toggle='%s'/>\n",
                                      guests[i]->features[j]->name,
                                      guests[i]->features[j]->defaultOn ? "on" : "off",
                                      guests[i]->features[j]->toggle ? "yes" : "no");
                }
            }

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</features>\n");
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</guest>\n\n");
    }
}


static void
virCapabilitiesFormatStoragePoolXML(virCapsStoragePoolPtr *pools,
                                    size_t npools,
                                    virBufferPtr buf)
{
    size_t i;

    if (npools == 0)
        return;

    virBufferAddLit(buf, "<pool>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAddLit(buf, "<enum name='type'>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < npools; i++)
        virBufferAsprintf(buf, "<value>%s</value>\n",
                          virStoragePoolTypeToString(pools[i]->type));
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</enum>\n");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</pool>\n\n");
}


/**
 * virCapabilitiesFormatXML:
 * @caps: capabilities to format
 *
 * Convert the capabilities object into an XML representation
 *
 * Returns the XML document as a string
 */
char *
virCapabilitiesFormatXML(virCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "<capabilities>\n\n");
    virBufferAdjustIndent(&buf, 2);

    if (virCapabilitiesFormatHostXML(&caps->host, &buf) < 0)
        goto error;

    virCapabilitiesFormatGuestXML(caps->guests, caps->nguests, &buf);

    virCapabilitiesFormatStoragePoolXML(caps->pools, caps->npools, &buf);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</capabilities>\n");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

/* get the maximum ID of cpus in the host */
static unsigned int
virCapabilitiesGetHostMaxcpu(virCapsPtr caps)
{
    unsigned int maxcpu = 0;
    size_t node;
    size_t cpu;

    for (node = 0; node < caps->host.nnumaCell; node++) {
        virCapsHostNUMACellPtr cell = caps->host.numaCell[node];

        for (cpu = 0; cpu < cell->ncpus; cpu++) {
            if (cell->cpus[cpu].id > maxcpu)
                maxcpu = cell->cpus[cpu].id;
        }
    }

    return maxcpu;
}

/* set cpus of a numa node in the bitmask */
static int
virCapabilitiesGetCpusForNode(virCapsPtr caps,
                              size_t node,
                              virBitmapPtr cpumask)
{
    virCapsHostNUMACellPtr cell = NULL;
    size_t cpu;
    size_t i;
    /* The numa node numbers can be non-contiguous. Ex: 0,1,16,17. */
    for (i = 0; i < caps->host.nnumaCell; i++) {
        if (caps->host.numaCell[i]->num == node) {
            cell = caps->host.numaCell[i];
            break;
        }
    }

    for (cpu = 0; cell && cpu < cell->ncpus; cpu++) {
        if (virBitmapSetBit(cpumask, cell->cpus[cpu].id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cpu '%u' in node '%zu' is out of range "
                             "of the provided bitmap"),
                           cell->cpus[cpu].id, node);
            return -1;
        }
    }

    return 0;
}

virBitmapPtr
virCapabilitiesGetCpusForNodemask(virCapsPtr caps,
                                  virBitmapPtr nodemask)
{
    virBitmapPtr ret = NULL;
    unsigned int maxcpu = virCapabilitiesGetHostMaxcpu(caps);
    ssize_t node = -1;

    if (!(ret = virBitmapNew(maxcpu + 1)))
        return NULL;


    while ((node = virBitmapNextSetBit(nodemask, node)) >= 0) {
        if (virCapabilitiesGetCpusForNode(caps, node, ret) < 0) {
            virBitmapFree(ret);
            return NULL;
        }
    }

    return ret;
}


int
virCapabilitiesGetNodeInfo(virNodeInfoPtr nodeinfo)
{
    virArch hostarch = virArchFromHost();
    unsigned long long memorybytes;

    memset(nodeinfo, 0, sizeof(*nodeinfo));

    if (virStrcpyStatic(nodeinfo->model, virArchToString(hostarch)) < 0)
        return -1;

    if (virHostMemGetInfo(&memorybytes, NULL) < 0)
        return -1;
    nodeinfo->memory = memorybytes / 1024;

    if (virHostCPUGetInfo(hostarch,
                          &nodeinfo->cpus, &nodeinfo->mhz,
                          &nodeinfo->nodes, &nodeinfo->sockets,
                          &nodeinfo->cores, &nodeinfo->threads) < 0)
        return -1;

    return 0;
}

/* returns 1 on success, 0 if the detection failed and -1 on hard error */
static int
virCapabilitiesFillCPUInfo(int cpu_id G_GNUC_UNUSED,
                           virCapsHostNUMACellCPUPtr cpu G_GNUC_UNUSED)
{
#ifdef __linux__
    cpu->id = cpu_id;

    if (virHostCPUGetSocket(cpu_id, &cpu->socket_id) < 0 ||
        virHostCPUGetCore(cpu_id, &cpu->core_id) < 0)
        return -1;

    if (!(cpu->siblings = virHostCPUGetSiblingsList(cpu_id)))
        return -1;

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node cpu info not implemented on this platform"));
    return -1;
#endif
}

static int
virCapabilitiesGetNUMASiblingInfo(int node,
                                  virCapsHostNUMACellSiblingInfoPtr *siblings,
                                  int *nsiblings)
{
    virCapsHostNUMACellSiblingInfoPtr tmp = NULL;
    int tmp_size = 0;
    int ret = -1;
    int *distances = NULL;
    int ndistances = 0;
    size_t i;

    if (virNumaGetDistances(node, &distances, &ndistances) < 0)
        goto cleanup;

    if (!distances) {
        *siblings = NULL;
        *nsiblings = 0;
        return 0;
    }

    if (VIR_ALLOC_N(tmp, ndistances) < 0)
        goto cleanup;

    for (i = 0; i < ndistances; i++) {
        if (!distances[i])
            continue;

        tmp[tmp_size].node = i;
        tmp[tmp_size].distance = distances[i];
        tmp_size++;
    }

    if (VIR_REALLOC_N(tmp, tmp_size) < 0)
        goto cleanup;

    *siblings = tmp;
    *nsiblings = tmp_size;
    tmp = NULL;
    tmp_size = 0;
    ret = 0;
 cleanup:
    VIR_FREE(distances);
    VIR_FREE(tmp);
    return ret;
}

static int
virCapabilitiesGetNUMAPagesInfo(int node,
                                virCapsHostNUMACellPageInfoPtr *pageinfo,
                                int *npageinfo)
{
    int ret = -1;
    unsigned int *pages_size = NULL;
    unsigned long long *pages_avail = NULL;
    size_t npages, i;

    if (virNumaGetPages(node, &pages_size, &pages_avail, NULL, &npages) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(*pageinfo, npages) < 0)
        goto cleanup;
    *npageinfo = npages;

    for (i = 0; i < npages; i++) {
        (*pageinfo)[i].size = pages_size[i];
        (*pageinfo)[i].avail = pages_avail[i];
    }

    ret = 0;

 cleanup:
    VIR_FREE(pages_avail);
    VIR_FREE(pages_size);
    return ret;
}


static int
virCapabilitiesInitNUMAFake(virCapsPtr caps)
{
    virNodeInfo nodeinfo;
    virCapsHostNUMACellCPUPtr cpus;
    int ncpus;
    int s, c, t;
    int id, cid;
    int onlinecpus G_GNUC_UNUSED;
    bool tmp;

    if (virCapabilitiesGetNodeInfo(&nodeinfo) < 0)
        return -1;

    ncpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    onlinecpus = nodeinfo.cpus;

    if (VIR_ALLOC_N(cpus, ncpus) < 0)
        return -1;

    id = cid = 0;
    for (s = 0; s < nodeinfo.sockets; s++) {
        for (c = 0; c < nodeinfo.cores; c++) {
            for (t = 0; t < nodeinfo.threads; t++) {
                if (virHostCPUGetOnline(id, &tmp) < 0)
                    goto error;
                if (tmp) {
                    cpus[cid].id = id;
                    cpus[cid].socket_id = s;
                    cpus[cid].core_id = c;
                    if (!(cpus[cid].siblings = virBitmapNew(ncpus)))
                        goto error;
                    ignore_value(virBitmapSetBit(cpus[cid].siblings, id));
                    cid++;
                }

                id++;
            }
        }
    }

    if (virCapabilitiesAddHostNUMACell(caps, 0,
                                       nodeinfo.memory,
#ifdef __linux__
                                       onlinecpus, cpus,
#else
                                       ncpus, cpus,
#endif
                                       0, NULL,
                                       0, NULL) < 0)
        goto error;

    return 0;

 error:
    for (; id >= 0; id--)
        virBitmapFree(cpus[id].siblings);
    VIR_FREE(cpus);
    return -1;
}

int
virCapabilitiesInitNUMA(virCapsPtr caps)
{
    int n;
    unsigned long long memory;
    virCapsHostNUMACellCPUPtr cpus = NULL;
    virBitmapPtr cpumap = NULL;
    virCapsHostNUMACellSiblingInfoPtr siblings = NULL;
    int nsiblings = 0;
    virCapsHostNUMACellPageInfoPtr pageinfo = NULL;
    int npageinfo;
    int ret = -1;
    int ncpus = 0;
    int cpu;
    bool topology_failed = false;
    int max_node;

    if (!virNumaIsAvailable())
        return virCapabilitiesInitNUMAFake(caps);

    if ((max_node = virNumaGetMaxNode()) < 0)
        goto cleanup;

    for (n = 0; n <= max_node; n++) {
        size_t i;

        if ((ncpus = virNumaGetNodeCPUs(n, &cpumap)) < 0) {
            if (ncpus == -2)
                continue;

            goto cleanup;
        }

        if (VIR_ALLOC_N(cpus, ncpus) < 0)
            goto cleanup;
        cpu = 0;

        for (i = 0; i < virBitmapSize(cpumap); i++) {
            if (virBitmapIsBitSet(cpumap, i)) {
                if (virCapabilitiesFillCPUInfo(i, cpus + cpu++) < 0) {
                    topology_failed = true;
                    virResetLastError();
                }
            }
        }

        if (virCapabilitiesGetNUMASiblingInfo(n, &siblings, &nsiblings) < 0)
            goto cleanup;

        if (virCapabilitiesGetNUMAPagesInfo(n, &pageinfo, &npageinfo) < 0)
            goto cleanup;

        /* Detect the amount of memory in the numa cell in KiB */
        virNumaGetNodeMemory(n, &memory, NULL);
        memory >>= 10;

        if (virCapabilitiesAddHostNUMACell(caps, n, memory,
                                           ncpus, cpus,
                                           nsiblings, siblings,
                                           npageinfo, pageinfo) < 0)
            goto cleanup;

        cpus = NULL;
        siblings = NULL;
        pageinfo = NULL;
        virBitmapFree(cpumap);
        cpumap = NULL;
    }

    ret = 0;

 cleanup:
    if ((topology_failed || ret < 0) && cpus)
        virCapabilitiesClearHostNUMACellCPUTopology(cpus, ncpus);

    virBitmapFree(cpumap);
    VIR_FREE(cpus);
    VIR_FREE(siblings);
    VIR_FREE(pageinfo);
    return ret;
}

int
virCapabilitiesInitPages(virCapsPtr caps)
{
    int ret = -1;
    unsigned int *pages_size = NULL;
    size_t npages;

    if (virNumaGetPages(-1 /* Magic constant for overall info */,
                        &pages_size, NULL, NULL, &npages) < 0)
        goto cleanup;

    caps->host.pagesSize = pages_size;
    pages_size = NULL;
    caps->host.nPagesSize = npages;
    npages = 0;

    ret = 0;
 cleanup:
    VIR_FREE(pages_size);
    return ret;
}


bool
virCapsHostCacheBankEquals(virCapsHostCacheBankPtr a,
                           virCapsHostCacheBankPtr b)
{
    return (a->id == b->id &&
            a->level == b->level &&
            a->type == b->type &&
            a->size == b->size &&
            virBitmapEqual(a->cpus, b->cpus));
}

void
virCapsHostCacheBankFree(virCapsHostCacheBankPtr ptr)
{
    size_t i;

    if (!ptr)
        return;

    virBitmapFree(ptr->cpus);
    for (i = 0; i < ptr->ncontrols; i++)
        VIR_FREE(ptr->controls[i]);
    VIR_FREE(ptr->controls);
    VIR_FREE(ptr);
}


static int
virCapsHostCacheBankSorter(const void *a,
                           const void *b)
{
    virCapsHostCacheBankPtr ca = *(virCapsHostCacheBankPtr *)a;
    virCapsHostCacheBankPtr cb = *(virCapsHostCacheBankPtr *)b;

    if (ca->level < cb->level)
        return -1;
    if (ca->level > cb->level)
        return 1;

    return ca->id - cb->id;
}


static int
virCapabilitiesInitResctrl(virCapsPtr caps)
{
    if (caps->host.resctrl)
        return 0;

    caps->host.resctrl = virResctrlInfoNew();
    if (!caps->host.resctrl)
        return -1;

    return 0;
}


static int
virCapabilitiesInitResctrlMemory(virCapsPtr caps)
{
    virCapsHostMemBWNodePtr node = NULL;
    size_t i = 0;
    int ret = -1;
    const virResctrlMonitorType montype = VIR_RESCTRL_MONITOR_TYPE_MEMBW;
    const char *prefix = virResctrlMonitorPrefixTypeToString(montype);

    for (i = 0; i < caps->host.cache.nbanks; i++) {
        virCapsHostCacheBankPtr bank = caps->host.cache.banks[i];
        if (VIR_ALLOC(node) < 0)
            goto cleanup;

        if (virResctrlInfoGetMemoryBandwidth(caps->host.resctrl,
                                             bank->level, &node->control) > 0) {
            node->id = bank->id;
            if (!(node->cpus = virBitmapNewCopy(bank->cpus)))
                goto cleanup;

            if (VIR_APPEND_ELEMENT(caps->host.memBW.nodes,
                                   caps->host.memBW.nnodes, node) < 0) {
                goto cleanup;
            }
        }
        virCapsHostMemBWNodeFree(node);
        node = NULL;
    }

    if (virResctrlInfoGetMonitorPrefix(caps->host.resctrl, prefix,
                                       &caps->host.memBW.monitor) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCapsHostMemBWNodeFree(node);
    return ret;
}


int
virCapabilitiesInitCaches(virCapsPtr caps)
{
    size_t i = 0;
    virBitmapPtr cpus = NULL;
    ssize_t pos = -1;
    DIR *dirp = NULL;
    int ret = -1;
    char *path = NULL;
    char *type = NULL;
    struct dirent *ent = NULL;
    virCapsHostCacheBankPtr bank = NULL;
    const virResctrlMonitorType montype = VIR_RESCTRL_MONITOR_TYPE_CACHE;
    const char *prefix = virResctrlMonitorPrefixTypeToString(montype);

    /* Minimum level to expose in capabilities.  Can be lowered or removed (with
     * the appropriate code below), but should not be increased, because we'd
     * lose information. */
    const int cache_min_level = 3;

    if (virCapabilitiesInitResctrl(caps) < 0)
        return -1;

    /* offline CPUs don't provide cache info */
    if (virFileReadValueBitmap(&cpus, "%s/cpu/online", SYSFS_SYSTEM_PATH) < 0)
        return -1;

    while ((pos = virBitmapNextSetBit(cpus, pos)) >= 0) {
        int rv = -1;

        VIR_FREE(path);
        if (virAsprintf(&path, "%s/cpu/cpu%zd/cache/", SYSFS_SYSTEM_PATH, pos) < 0)
            goto cleanup;

        VIR_DIR_CLOSE(dirp);

        rv = virDirOpenIfExists(&dirp, path);
        if (rv < 0)
            goto cleanup;

        if (!dirp)
            continue;

        while ((rv = virDirRead(dirp, &ent, path)) > 0) {
            int kernel_type;
            unsigned int level;

            if (!STRPREFIX(ent->d_name, "index"))
                continue;

            if (virFileReadValueUint(&level,
                                     "%s/cpu/cpu%zd/cache/%s/level",
                                     SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            if (level < cache_min_level)
                continue;

            if (VIR_ALLOC(bank) < 0)
                goto cleanup;

            bank->level = level;

            if (virFileReadValueUint(&bank->id,
                                     "%s/cpu/cpu%zd/cache/%s/id",
                                     SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            if (virFileReadValueUint(&bank->level,
                                     "%s/cpu/cpu%zd/cache/%s/level",
                                     SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            if (virFileReadValueString(&type,
                                       "%s/cpu/cpu%zd/cache/%s/type",
                                       SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            if (virFileReadValueScaledInt(&bank->size,
                                          "%s/cpu/cpu%zd/cache/%s/size",
                                          SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            if (virFileReadValueBitmap(&bank->cpus,
                                       "%s/cpu/cpu%zd/cache/%s/shared_cpu_list",
                                       SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                goto cleanup;

            kernel_type = virCacheKernelTypeFromString(type);
            if (kernel_type < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown cache type '%s'"), type);
                goto cleanup;
            }

            bank->type = kernel_type;
            VIR_FREE(type);

            for (i = 0; i < caps->host.cache.nbanks; i++) {
                if (virCapsHostCacheBankEquals(bank, caps->host.cache.banks[i]))
                    break;
            }
            if (i == caps->host.cache.nbanks) {
                /* If it is a new cache, then update its resctrl information. */
                if (virResctrlInfoGetCache(caps->host.resctrl,
                                           bank->level,
                                           bank->size,
                                           &bank->ncontrols,
                                           &bank->controls) < 0)
                    goto cleanup;

                if (VIR_APPEND_ELEMENT(caps->host.cache.banks,
                                       caps->host.cache.nbanks,
                                       bank) < 0) {
                    goto cleanup;
                }
            }

            virCapsHostCacheBankFree(bank);
            bank = NULL;
        }
        if (rv < 0)
            goto cleanup;
    }

    /* Sort the array in order for the tests to be predictable.  This way we can
     * still traverse the directory instead of guessing names (in case there is
     * 'index1' and 'index3' but no 'index2'). */
    qsort(caps->host.cache.banks, caps->host.cache.nbanks,
          sizeof(*caps->host.cache.banks), virCapsHostCacheBankSorter);

    if (virCapabilitiesInitResctrlMemory(caps) < 0)
        goto cleanup;

    if (virResctrlInfoGetMonitorPrefix(caps->host.resctrl, prefix,
                                       &caps->host.cache.monitor) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(type);
    VIR_FREE(path);
    VIR_DIR_CLOSE(dirp);
    virCapsHostCacheBankFree(bank);
    virBitmapFree(cpus);
    return ret;
}


void
virCapabilitiesHostInitIOMMU(virCapsPtr caps)
{
    caps->host.iommu = virHostHasIOMMU();
}
