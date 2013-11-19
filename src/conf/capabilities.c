/*
 * capabilities.c: hypervisor capabilities
 *
 * Copyright (C) 2006-2008, 2010-2011, 2013 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <strings.h>

#include "capabilities.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "viruuid.h"
#include "cpu_conf.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

VIR_ENUM_DECL(virCapsHostPMTarget)
VIR_ENUM_IMPL(virCapsHostPMTarget, VIR_NODE_SUSPEND_TARGET_LAST,
              "suspend_mem", "suspend_disk", "suspend_hybrid");

static virClassPtr virCapsClass;
static void virCapabilitiesDispose(void *obj);

static int virCapabilitiesOnceInit(void)
{
    if (!(virCapsClass = virClassNew(virClassForObject(),
                                     "virCaps",
                                     sizeof(virCaps),
                                     virCapabilitiesDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCapabilities)

/**
 * virCapabilitiesNew:
 * @hostarch: host machine architecture
 * @offlineMigrate: non-zero if offline migration is available
 * @liveMigrate: non-zero if live migration is available
 *
 * Allocate a new capabilities object
 */
virCapsPtr
virCapabilitiesNew(virArch hostarch,
                   int offlineMigrate,
                   int liveMigrate)
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
    VIR_FREE(dom->type);

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

static void
virCapabilitiesFreeGuest(virCapsGuestPtr guest)
{
    size_t i;
    if (guest == NULL)
        return;

    VIR_FREE(guest->ostype);

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
virCapabilitiesDispose(void *object)
{
    virCapsPtr caps = object;
    size_t i;

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

    for (i = 0; i < caps->host.nsecModels; i++) {
        virCapabilitiesClearSecModel(&caps->host.secModels[i]);
    }
    VIR_FREE(caps->host.secModels);

    virCPUDefFree(caps->host.cpu);
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
 * virCapabilitiesAddHostNUMACell:
 * @caps: capabilities to extend
 * @num: ID number of NUMA cell
 * @ncpus: number of CPUs in cell
 * @mem: Total size of memory in the NUMA node (in KiB)
 * @cpus: array of CPU definition structures, the pointer is stolen
 *
 * Registers a new NUMA cell for a host, passing in a
 * array of CPU IDs belonging to the cell
 */
int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               int ncpus,
                               unsigned long long mem,
                               virCapsHostNUMACellCPUPtr cpus)
{
    virCapsHostNUMACellPtr cell;

    if (VIR_RESIZE_N(caps->host.numaCell, caps->host.nnumaCell_max,
                     caps->host.nnumaCell, 1) < 0)
        return -1;

    if (VIR_ALLOC(cell) < 0)
        return -1;

    cell->ncpus = ncpus;
    cell->num = num;
    cell->mem = mem;
    cell->cpus = cpus;

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
 * @ostype: guest operating system type ('hvm' or 'xen')
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
                        const char *ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachinePtr *machines)
{
    virCapsGuestPtr guest;

    if (VIR_ALLOC(guest) < 0)
        goto error;

    if (VIR_STRDUP(guest->ostype, ostype) < 0)
        goto error;

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
                              const char *hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachinePtr *machines)
{
    virCapsGuestDomainPtr dom;

    if (VIR_ALLOC(dom) < 0)
        goto error;

    if (VIR_STRDUP(dom->type, hvtype) < 0 ||
        VIR_STRDUP(dom->info.emulator, emulator) < 0 ||
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
 * @defaultOn: non-zero if it defaults to on
 * @toggle: non-zero if its state can be toggled
 *
 * Registers a feature for a guest domain
 */
virCapsGuestFeaturePtr
virCapabilitiesAddGuestFeature(virCapsGuestPtr guest,
                               const char *name,
                               int defaultOn,
                               int toggle)
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

/**
 * virCapabilitiesSupportsGuestArch:
 * @caps: capabilities to query
 * @arch: Architecture to search for
 *
 * Returns non-zero if the capabilities support the
 * requested architecture
 */
extern int
virCapabilitiesSupportsGuestArch(virCapsPtr caps,
                                 virArch arch)
{
    size_t i;
    for (i = 0; i < caps->nguests; i++) {
        if (caps->guests[i]->arch.id == arch)
            return 1;
    }
    return 0;
}


/**
 * virCapabilitiesSupportsGuestOSType:
 * @caps: capabilities to query
 * @ostype: OS type to search for (eg 'hvm', 'xen')
 *
 * Returns non-zero if the capabilities support the
 * requested operating system type
 */
extern int
virCapabilitiesSupportsGuestOSType(virCapsPtr caps,
                                   const char *ostype)
{
    size_t i;
    for (i = 0; i < caps->nguests; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype))
            return 1;
    }
    return 0;
}


/**
 * virCapabilitiesSupportsGuestOSTypeArch:
 * @caps: capabilities to query
 * @ostype: OS type to search for (eg 'hvm', 'xen')
 * @arch: Architecture to search for
 *
 * Returns non-zero if the capabilities support the
 * requested operating system type
 */
extern int
virCapabilitiesSupportsGuestOSTypeArch(virCapsPtr caps,
                                       const char *ostype,
                                       virArch arch)
{
    size_t i;
    for (i = 0; i < caps->nguests; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype) &&
            caps->guests[i]->arch.id == arch)
            return 1;
    }
    return 0;
}


/**
 * virCapabilitiesDefaultGuestArch:
 * @caps: capabilities to query
 * @ostype: OS type to search for
 *
 * Returns the first architecture able to run the
 * requested operating system type
 */
extern virArch
virCapabilitiesDefaultGuestArch(virCapsPtr caps,
                                const char *ostype,
                                const char *domain)
{
    size_t i, j;

    /* First try to find one matching host arch */
    for (i = 0; i < caps->nguests; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype)) {
            for (j = 0; j < caps->guests[i]->arch.ndomains; j++) {
                if (STREQ(caps->guests[i]->arch.domains[j]->type, domain) &&
                    caps->guests[i]->arch.id == caps->host.arch)
                    return caps->guests[i]->arch.id;
            }
        }
    }

    /* Otherwise find the first match */
    for (i = 0; i < caps->nguests; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype)) {
            for (j = 0; j < caps->guests[i]->arch.ndomains; j++) {
                if (STREQ(caps->guests[i]->arch.domains[j]->type, domain))
                    return caps->guests[i]->arch.id;
            }
        }
    }

    return VIR_ARCH_NONE;
}

/**
 * virCapabilitiesDefaultGuestMachine:
 * @caps: capabilities to query
 * @ostype: OS type to search for
 * @arch: architecture to search for
 * @domain: domain type to search for
 *
 * Returns the first machine variant associated with
 * the requested operating system type, architecture
 * and domain type
 */
extern const char *
virCapabilitiesDefaultGuestMachine(virCapsPtr caps,
                                   const char *ostype,
                                   virArch arch,
                                   const char *domain)
{
    size_t i;

    for (i = 0; i < caps->nguests; i++) {
        virCapsGuestPtr guest = caps->guests[i];
        size_t j;

        if (!STREQ(guest->ostype, ostype) ||
            guest->arch.id != arch)
            continue;

        for (j = 0; j < guest->arch.ndomains; j++) {
            virCapsGuestDomainPtr dom = guest->arch.domains[j];

            if (!STREQ(dom->type, domain))
                continue;

            if (!dom->info.nmachines)
                break;

            return dom->info.machines[0]->name;
        }

        if (guest->arch.defaultInfo.nmachines)
            return caps->guests[i]->arch.defaultInfo.machines[0]->name;
    }

    return NULL;
}

/**
 * virCapabilitiesDefaultGuestEmulator:
 * @caps: capabilities to query
 * @ostype: OS type to search for ('xen', 'hvm')
 * @arch: architecture to search for
 * @domain: domain type ('xen', 'qemu', 'kvm')
 *
 * Returns the first emulator path associated with
 * the requested operating system type, architecture
 * and domain type
 */
extern const char *
virCapabilitiesDefaultGuestEmulator(virCapsPtr caps,
                                    const char *ostype,
                                    virArch arch,
                                    const char *domain)
{
    size_t i, j;
    for (i = 0; i < caps->nguests; i++) {
        char *emulator;
        if (STREQ(caps->guests[i]->ostype, ostype) &&
            caps->guests[i]->arch.id == arch) {
            emulator = caps->guests[i]->arch.defaultInfo.emulator;
            for (j = 0; j < caps->guests[i]->arch.ndomains; j++) {
                if (STREQ(caps->guests[i]->arch.domains[j]->type, domain)) {
                    if (caps->guests[i]->arch.domains[j]->info.emulator)
                        emulator = caps->guests[i]->arch.domains[j]->info.emulator;
                }
            }
            return emulator;
        }
    }
    return NULL;
}

static int
virCapabilitiesFormatNUMATopology(virBufferPtr xml,
                                  size_t ncells,
                                  virCapsHostNUMACellPtr *cells)
{
    size_t i;
    size_t j;
    char *siblings;

    virBufferAddLit(xml, "    <topology>\n");
    virBufferAsprintf(xml, "      <cells num='%zu'>\n", ncells);
    for (i = 0; i < ncells; i++) {
        virBufferAsprintf(xml, "        <cell id='%d'>\n", cells[i]->num);

        /* Print out the numacell memory total if it is available */
        if (cells[i]->mem)
            virBufferAsprintf(xml,
                              "          <memory unit='KiB'>%llu</memory>\n",
                              cells[i]->mem);

        virBufferAsprintf(xml, "          <cpus num='%d'>\n", cells[i]->ncpus);
        for (j = 0; j < cells[i]->ncpus; j++) {
            virBufferAsprintf(xml, "            <cpu id='%d'",
                              cells[i]->cpus[j].id);

            if (cells[i]->cpus[j].siblings) {
                if (!(siblings = virBitmapFormat(cells[i]->cpus[j].siblings))) {
                    virReportOOMError();
                    return -1;
                }

                virBufferAsprintf(xml,
                                  " socket_id='%d' core_id='%d' siblings='%s'",
                                  cells[i]->cpus[j].socket_id,
                                  cells[i]->cpus[j].core_id,
                                  siblings);
                VIR_FREE(siblings);
            }
            virBufferAddLit(xml, "/>\n");
        }

        virBufferAddLit(xml, "          </cpus>\n");
        virBufferAddLit(xml, "        </cell>\n");
    }
    virBufferAddLit(xml, "      </cells>\n");
    virBufferAddLit(xml, "    </topology>\n");

    return 0;
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
    virBuffer xml = VIR_BUFFER_INITIALIZER;
    size_t i, j, k;
    char host_uuid[VIR_UUID_STRING_BUFLEN];

    virBufferAddLit(&xml, "<capabilities>\n\n");
    virBufferAddLit(&xml, "  <host>\n");
    if (virUUIDIsValid(caps->host.host_uuid)) {
        virUUIDFormat(caps->host.host_uuid, host_uuid);
        virBufferAsprintf(&xml, "    <uuid>%s</uuid>\n", host_uuid);
    }
    virBufferAddLit(&xml, "    <cpu>\n");
    if (caps->host.arch)
        virBufferAsprintf(&xml, "      <arch>%s</arch>\n",
                          virArchToString(caps->host.arch));

    if (caps->host.nfeatures) {
        virBufferAddLit(&xml, "      <features>\n");
        for (i = 0; i < caps->host.nfeatures; i++) {
            virBufferAsprintf(&xml, "        <%s/>\n",
                              caps->host.features[i]);
        }
        virBufferAddLit(&xml, "      </features>\n");
    }

    virBufferAdjustIndent(&xml, 6);
    virCPUDefFormatBuf(&xml, caps->host.cpu, 0);
    virBufferAdjustIndent(&xml, -6);

    virBufferAddLit(&xml, "    </cpu>\n");

    /* The PM query was successful. */
    if (caps->host.powerMgmt) {
        /* The host supports some PM features. */
        unsigned int pm = caps->host.powerMgmt;
        virBufferAddLit(&xml, "    <power_management>\n");
        while (pm) {
            int bit = ffs(pm) - 1;
            virBufferAsprintf(&xml, "      <%s/>\n",
                              virCapsHostPMTargetTypeToString(bit));
            pm &= ~(1U << bit);
        }
        virBufferAddLit(&xml, "    </power_management>\n");
    } else {
        /* The host does not support any PM feature. */
        virBufferAddLit(&xml, "    <power_management/>\n");
    }

    if (caps->host.offlineMigrate) {
        virBufferAddLit(&xml, "    <migration_features>\n");
        if (caps->host.liveMigrate)
            virBufferAddLit(&xml, "      <live/>\n");
        if (caps->host.nmigrateTrans) {
            virBufferAddLit(&xml, "      <uri_transports>\n");
            for (i = 0; i < caps->host.nmigrateTrans; i++) {
                virBufferAsprintf(&xml, "        <uri_transport>%s</uri_transport>\n",
                                      caps->host.migrateTrans[i]);
            }
            virBufferAddLit(&xml, "      </uri_transports>\n");
        }
        virBufferAddLit(&xml, "    </migration_features>\n");
    }

    if (caps->host.nnumaCell &&
        virCapabilitiesFormatNUMATopology(&xml, caps->host.nnumaCell,
                                          caps->host.numaCell) < 0)
        return NULL;

    for (i = 0; i < caps->host.nsecModels; i++) {
        virBufferAddLit(&xml, "    <secmodel>\n");
        virBufferAsprintf(&xml, "      <model>%s</model>\n",
                          caps->host.secModels[i].model);
        virBufferAsprintf(&xml, "      <doi>%s</doi>\n",
                          caps->host.secModels[i].doi);
        for (j = 0; j < caps->host.secModels[i].nlabels; j++) {
            virBufferAsprintf(&xml, "      <baselabel type='%s'>%s</baselabel>\n",
                              caps->host.secModels[i].labels[j].type,
                              caps->host.secModels[i].labels[j].label);
        }
        virBufferAddLit(&xml, "    </secmodel>\n");
    }

    virBufferAddLit(&xml, "  </host>\n\n");


    for (i = 0; i < caps->nguests; i++) {
        virBufferAddLit(&xml, "  <guest>\n");
        virBufferAsprintf(&xml, "    <os_type>%s</os_type>\n",
                          caps->guests[i]->ostype);
        if (caps->guests[i]->arch.id)
            virBufferAsprintf(&xml, "    <arch name='%s'>\n",
                              virArchToString(caps->guests[i]->arch.id));
        virBufferAsprintf(&xml, "      <wordsize>%d</wordsize>\n",
                          caps->guests[i]->arch.wordsize);
        if (caps->guests[i]->arch.defaultInfo.emulator)
            virBufferAsprintf(&xml, "      <emulator>%s</emulator>\n",
                              caps->guests[i]->arch.defaultInfo.emulator);
            if (caps->guests[i]->arch.defaultInfo.loader)
                virBufferAsprintf(&xml, "      <loader>%s</loader>\n",
                                  caps->guests[i]->arch.defaultInfo.loader);

        for (j = 0; j < caps->guests[i]->arch.defaultInfo.nmachines; j++) {
            virCapsGuestMachinePtr machine = caps->guests[i]->arch.defaultInfo.machines[j];
            virBufferAddLit(&xml, "      <machine");
            if (machine->canonical)
                virBufferAsprintf(&xml, " canonical='%s'", machine->canonical);
            if (machine->maxCpus > 0)
                virBufferAsprintf(&xml, " maxCpus='%d'", machine->maxCpus);
            virBufferAsprintf(&xml, ">%s</machine>\n", machine->name);
        }

        for (j = 0; j < caps->guests[i]->arch.ndomains; j++) {
            virBufferAsprintf(&xml, "      <domain type='%s'>\n",
                                  caps->guests[i]->arch.domains[j]->type);
            if (caps->guests[i]->arch.domains[j]->info.emulator)
                virBufferAsprintf(&xml, "        <emulator>%s</emulator>\n",
                                  caps->guests[i]->arch.domains[j]->info.emulator);
            if (caps->guests[i]->arch.domains[j]->info.loader)
                virBufferAsprintf(&xml, "        <loader>%s</loader>\n",
                                  caps->guests[i]->arch.domains[j]->info.loader);

            for (k = 0; k < caps->guests[i]->arch.domains[j]->info.nmachines; k++) {
                virCapsGuestMachinePtr machine = caps->guests[i]->arch.domains[j]->info.machines[k];
                virBufferAddLit(&xml, "        <machine");
                if (machine->canonical)
                    virBufferAsprintf(&xml, " canonical='%s'", machine->canonical);
                if (machine->maxCpus > 0)
                    virBufferAsprintf(&xml, " maxCpus='%d'", machine->maxCpus);
                virBufferAsprintf(&xml, ">%s</machine>\n", machine->name);
            }
            virBufferAddLit(&xml, "      </domain>\n");
        }

        virBufferAddLit(&xml, "    </arch>\n");

        if (caps->guests[i]->nfeatures) {
            virBufferAddLit(&xml, "    <features>\n");

            for (j = 0; j < caps->guests[i]->nfeatures; j++) {
                if (STREQ(caps->guests[i]->features[j]->name, "pae") ||
                    STREQ(caps->guests[i]->features[j]->name, "nonpae") ||
                    STREQ(caps->guests[i]->features[j]->name, "ia64_be") ||
                    STREQ(caps->guests[i]->features[j]->name, "cpuselection") ||
                    STREQ(caps->guests[i]->features[j]->name, "deviceboot")) {
                    virBufferAsprintf(&xml, "      <%s/>\n",
                                      caps->guests[i]->features[j]->name);
                } else {
                    virBufferAsprintf(&xml, "      <%s default='%s' toggle='%s'/>\n",
                                      caps->guests[i]->features[j]->name,
                                      caps->guests[i]->features[j]->defaultOn ? "on" : "off",
                                      caps->guests[i]->features[j]->toggle ? "yes" : "no");
                }
            }

            virBufferAddLit(&xml, "    </features>\n");
        }

        virBufferAddLit(&xml, "  </guest>\n\n");
    }

    virBufferAddLit(&xml, "</capabilities>\n");

    if (virBufferError(&xml)) {
        virBufferFreeAndReset(&xml);
        return NULL;
    }

    return virBufferContentAndReset(&xml);
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
    virCapsHostNUMACellPtr cell = caps->host.numaCell[node];
    size_t cpu;

    for (cpu = 0; cpu < cell->ncpus; cpu++) {
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
