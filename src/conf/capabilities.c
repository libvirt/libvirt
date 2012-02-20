/*
 * capabilities.c: hypervisor capabilities
 *
 * Copyright (C) 2006-2008, 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <strings.h>

#include "capabilities.h"
#include "buf.h"
#include "memory.h"
#include "util.h"
#include "uuid.h"
#include "cpu_conf.h"
#include "virterror_internal.h"


#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

VIR_ENUM_DECL(virCapsHostPMTarget)
VIR_ENUM_IMPL(virCapsHostPMTarget, VIR_NODE_SUSPEND_TARGET_LAST,
              "suspend_mem", "suspend_disk", "suspend_hybrid");

/**
 * virCapabilitiesNew:
 * @arch: host machine architecture
 * @offlineMigrate: non-zero if offline migration is available
 * @liveMigrate: non-zero if live migration is available
 *
 * Allocate a new capabilities object
 */
virCapsPtr
virCapabilitiesNew(const char *arch,
                   int offlineMigrate,
                   int liveMigrate)
{
    virCapsPtr caps;

    if (VIR_ALLOC(caps) < 0)
        return NULL;

    if ((caps->host.arch = strdup(arch)) == NULL)
        goto no_memory;
    caps->host.offlineMigrate = offlineMigrate;
    caps->host.liveMigrate = liveMigrate;

    return caps;

 no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

static void
virCapabilitiesFreeHostNUMACell(virCapsHostNUMACellPtr cell)
{
    if (cell == NULL)
        return;

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
    int i;
    if (dom == NULL)
        return;

    VIR_FREE(dom->info.emulator);
    VIR_FREE(dom->info.loader);
    for (i = 0 ; i < dom->info.nmachines ; i++)
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
    int i;
    if (guest == NULL)
        return;

    VIR_FREE(guest->ostype);

    VIR_FREE(guest->arch.name);
    VIR_FREE(guest->arch.defaultInfo.emulator);
    VIR_FREE(guest->arch.defaultInfo.loader);
    for (i = 0 ; i < guest->arch.defaultInfo.nmachines ; i++)
        virCapabilitiesFreeGuestMachine(guest->arch.defaultInfo.machines[i]);
    VIR_FREE(guest->arch.defaultInfo.machines);

    for (i = 0 ; i < guest->arch.ndomains ; i++)
        virCapabilitiesFreeGuestDomain(guest->arch.domains[i]);
    VIR_FREE(guest->arch.domains);

    for (i = 0 ; i < guest->nfeatures ; i++)
        virCapabilitiesFreeGuestFeature(guest->features[i]);
    VIR_FREE(guest->features);

    VIR_FREE(guest);
}

void
virCapabilitiesFreeNUMAInfo(virCapsPtr caps)
{
    int i;

    for (i = 0 ; i < caps->host.nnumaCell ; i++)
        virCapabilitiesFreeHostNUMACell(caps->host.numaCell[i]);
    VIR_FREE(caps->host.numaCell);
    caps->host.nnumaCell = 0;
}

/**
 * virCapabilitiesFree:
 * @caps: object to free
 *
 * Free all memory associated with capabilities
 */
void
virCapabilitiesFree(virCapsPtr caps) {
    int i;
    if (caps == NULL)
        return;

    for (i = 0 ; i < caps->nguests ; i++)
        virCapabilitiesFreeGuest(caps->guests[i]);
    VIR_FREE(caps->guests);

    for (i = 0 ; i < caps->host.nfeatures ; i++)
        VIR_FREE(caps->host.features[i]);
    VIR_FREE(caps->host.features);

    virCapabilitiesFreeNUMAInfo(caps);

    for (i = 0 ; i < caps->host.nmigrateTrans ; i++)
        VIR_FREE(caps->host.migrateTrans[i]);
    VIR_FREE(caps->host.migrateTrans);

    VIR_FREE(caps->host.arch);
    VIR_FREE(caps->host.secModel.model);
    VIR_FREE(caps->host.secModel.doi);
    virCPUDefFree(caps->host.cpu);

    VIR_FREE(caps);
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

    if ((caps->host.features[caps->host.nfeatures] = strdup(name)) == NULL)
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

    if ((caps->host.migrateTrans[caps->host.nmigrateTrans] = strdup(name)) == NULL)
        return -1;
    caps->host.nmigrateTrans++;

    return 0;
}


/**
 * virCapabilitiesAddHostNUMACell:
 * @caps: capabilities to extend
 * @num: ID number of NUMA cell
 * @ncpus: number of CPUs in cell
 * @cpus: array of CPU ID numbers for cell
 *
 * Registers a new NUMA cell for a host, passing in a
 * array of CPU IDs belonging to the cell
 */
int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               int ncpus,
                               const int *cpus)
{
    virCapsHostNUMACellPtr cell;

    if (VIR_RESIZE_N(caps->host.numaCell, caps->host.nnumaCell_max,
                     caps->host.nnumaCell, 1) < 0)
        return -1;

    if (VIR_ALLOC(cell) < 0)
        return -1;

    if (VIR_ALLOC_N(cell->cpus, ncpus) < 0) {
        VIR_FREE(cell);
        return -1;
    }
    memcpy(cell->cpus,
           cpus,
           ncpus * sizeof(*cpus));

    cell->ncpus = ncpus;
    cell->num = num;

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
    int i;

    if (VIR_ALLOC_N(machines, nnames) < 0)
        return NULL;

    for (i = 0; i < nnames; i++) {
        if (VIR_ALLOC(machines[i]) < 0 ||
            !(machines[i]->name = strdup(names[i]))) {
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
    int i;
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
 * @arch: guest CPU architecture ('i686', or 'x86_64', etc)
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
                        const char *arch,
                        int wordsize,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachinePtr *machines)
{
    virCapsGuestPtr guest;

    if (VIR_ALLOC(guest) < 0)
        goto no_memory;

    if ((guest->ostype = strdup(ostype)) == NULL)
        goto no_memory;

    if ((guest->arch.name = strdup(arch)) == NULL)
        goto no_memory;
    guest->arch.wordsize = wordsize;

    if (emulator &&
        (guest->arch.defaultInfo.emulator = strdup(emulator)) == NULL)
        goto no_memory;
    if (loader &&
        (guest->arch.defaultInfo.loader = strdup(loader)) == NULL)
        goto no_memory;

    if (VIR_RESIZE_N(caps->guests, caps->nguests_max,
                     caps->nguests, 1) < 0)
        goto no_memory;
    caps->guests[caps->nguests++] = guest;

    if (nmachines) {
        guest->arch.defaultInfo.nmachines = nmachines;
        guest->arch.defaultInfo.machines = machines;
    }

    return guest;

 no_memory:
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
        goto no_memory;

    if ((dom->type = strdup(hvtype)) == NULL)
        goto no_memory;

    if (emulator &&
        (dom->info.emulator = strdup(emulator)) == NULL)
        goto no_memory;
    if (loader &&
        (dom->info.loader = strdup(loader)) == NULL)
        goto no_memory;

    if (VIR_RESIZE_N(guest->arch.domains, guest->arch.ndomains_max,
                     guest->arch.ndomains, 1) < 0)
        goto no_memory;
    guest->arch.domains[guest->arch.ndomains] = dom;
    guest->arch.ndomains++;

    if (nmachines) {
        dom->info.nmachines = nmachines;
        dom->info.machines = machines;
    }

    return dom;

 no_memory:
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

    if ((feature->name = strdup(name)) == NULL)
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
 * virCapabilitiesSupportsGuestArch:
 * @caps: capabilities to query
 * @arch: Architecture to search for (eg, 'i686', 'x86_64')
 *
 * Returns non-zero if the capabilities support the
 * requested architecture
 */
extern int
virCapabilitiesSupportsGuestArch(virCapsPtr caps,
                                 const char *arch)
{
    int i;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->arch.name, arch))
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
    int i;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype))
            return 1;
    }
    return 0;
}


/**
 * virCapabilitiesSupportsGuestOSTypeArch:
 * @caps: capabilities to query
 * @ostype: OS type to search for (eg 'hvm', 'xen')
 * @arch: Architecture to search for (eg, 'i686', 'x86_64')
 *
 * Returns non-zero if the capabilities support the
 * requested operating system type
 */
extern int
virCapabilitiesSupportsGuestOSTypeArch(virCapsPtr caps,
                                       const char *ostype,
                                       const char *arch)
{
    int i;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype) &&
            STREQ(caps->guests[i]->arch.name, arch))
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
extern const char *
virCapabilitiesDefaultGuestArch(virCapsPtr caps,
                                const char *ostype,
                                const char *domain)
{
    int i, j;
    const char *arch = NULL;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype)) {
            for (j = 0 ; j < caps->guests[i]->arch.ndomains ; j++) {
                if (STREQ(caps->guests[i]->arch.domains[j]->type, domain)) {
                    /* Use the first match... */
                    if (!arch)
                        arch = caps->guests[i]->arch.name;
                    /* ...unless we can match the host's architecture. */
                    if (STREQ(caps->guests[i]->arch.name, caps->host.arch))
                        return caps->guests[i]->arch.name;
                }
            }
        }
    }
    return arch;
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
                                   const char *arch,
                                   const char *domain)
{
    int i;

    for (i = 0 ; i < caps->nguests ; i++) {
        virCapsGuestPtr guest = caps->guests[i];
        int j;

        if (!STREQ(guest->ostype, ostype) || !STREQ(guest->arch.name, arch))
            continue;

        for (j = 0; j < guest->arch.ndomains; j++) {
            virCapsGuestDomainPtr dom= guest->arch.domains[j];

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
                                    const char *arch,
                                    const char *domain)
{
    int i, j;
    for (i = 0 ; i < caps->nguests ; i++) {
        char *emulator;
        if (STREQ(caps->guests[i]->ostype, ostype) &&
            STREQ(caps->guests[i]->arch.name, arch)) {
            emulator = caps->guests[i]->arch.defaultInfo.emulator;
            for (j = 0 ; j < caps->guests[i]->arch.ndomains ; j++) {
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
    int i, j, k;
    char host_uuid[VIR_UUID_STRING_BUFLEN];

    virBufferAddLit(&xml, "<capabilities>\n\n");
    virBufferAddLit(&xml, "  <host>\n");
    if (virUUIDIsValid(caps->host.host_uuid)) {
        virUUIDFormat(caps->host.host_uuid, host_uuid);
        virBufferAsprintf(&xml,"    <uuid>%s</uuid>\n", host_uuid);
    }
    virBufferAddLit(&xml, "    <cpu>\n");
    virBufferAsprintf(&xml, "      <arch>%s</arch>\n",
                      caps->host.arch);

    if (caps->host.nfeatures) {
        virBufferAddLit(&xml, "      <features>\n");
        for (i = 0 ; i < caps->host.nfeatures ; i++) {
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
            for (i = 0 ; i < caps->host.nmigrateTrans ; i++) {
                virBufferAsprintf(&xml, "        <uri_transport>%s</uri_transport>\n",
                                      caps->host.migrateTrans[i]);
            }
            virBufferAddLit(&xml, "      </uri_transports>\n");
        }
        virBufferAddLit(&xml, "    </migration_features>\n");
    }

    if (caps->host.nnumaCell) {
        virBufferAddLit(&xml, "    <topology>\n");
        virBufferAsprintf(&xml, "      <cells num='%zu'>\n",
                          caps->host.nnumaCell);
        for (i = 0 ; i < caps->host.nnumaCell ; i++) {
            virBufferAsprintf(&xml, "        <cell id='%d'>\n",
                              caps->host.numaCell[i]->num);
            virBufferAsprintf(&xml, "          <cpus num='%d'>\n",
                              caps->host.numaCell[i]->ncpus);
            for (j = 0 ; j < caps->host.numaCell[i]->ncpus ; j++)
                virBufferAsprintf(&xml, "            <cpu id='%d'/>\n",
                                  caps->host.numaCell[i]->cpus[j]);
            virBufferAddLit(&xml, "          </cpus>\n");
            virBufferAddLit(&xml, "        </cell>\n");
        }
        virBufferAddLit(&xml, "      </cells>\n");
        virBufferAddLit(&xml, "    </topology>\n");
    }

    if (caps->host.secModel.model) {
        virBufferAddLit(&xml, "    <secmodel>\n");
        virBufferAsprintf(&xml, "      <model>%s</model>\n", caps->host.secModel.model);
        virBufferAsprintf(&xml, "      <doi>%s</doi>\n", caps->host.secModel.doi);
        virBufferAddLit(&xml, "    </secmodel>\n");
    }

    virBufferAddLit(&xml, "  </host>\n\n");


    for (i = 0 ; i < caps->nguests ; i++) {
        virBufferAddLit(&xml, "  <guest>\n");
        virBufferAsprintf(&xml, "    <os_type>%s</os_type>\n",
                          caps->guests[i]->ostype);
        virBufferAsprintf(&xml, "    <arch name='%s'>\n",
                          caps->guests[i]->arch.name);
        virBufferAsprintf(&xml, "      <wordsize>%d</wordsize>\n",
                          caps->guests[i]->arch.wordsize);
        if (caps->guests[i]->arch.defaultInfo.emulator)
            virBufferAsprintf(&xml, "      <emulator>%s</emulator>\n",
                              caps->guests[i]->arch.defaultInfo.emulator);
            if (caps->guests[i]->arch.defaultInfo.loader)
                virBufferAsprintf(&xml, "      <loader>%s</loader>\n",
                                  caps->guests[i]->arch.defaultInfo.loader);

        for (j = 0 ; j < caps->guests[i]->arch.defaultInfo.nmachines ; j++) {
            virCapsGuestMachinePtr machine = caps->guests[i]->arch.defaultInfo.machines[j];
            virBufferAddLit(&xml, "      <machine");
            if (machine->canonical)
                virBufferAsprintf(&xml, " canonical='%s'", machine->canonical);
            virBufferAsprintf(&xml, ">%s</machine>\n", machine->name);
        }

        for (j = 0 ; j < caps->guests[i]->arch.ndomains ; j++) {
            virBufferAsprintf(&xml, "      <domain type='%s'>\n",
                                  caps->guests[i]->arch.domains[j]->type);
            if (caps->guests[i]->arch.domains[j]->info.emulator)
                virBufferAsprintf(&xml, "        <emulator>%s</emulator>\n",
                                  caps->guests[i]->arch.domains[j]->info.emulator);
            if (caps->guests[i]->arch.domains[j]->info.loader)
                virBufferAsprintf(&xml, "        <loader>%s</loader>\n",
                                  caps->guests[i]->arch.domains[j]->info.loader);

            for (k = 0 ; k < caps->guests[i]->arch.domains[j]->info.nmachines ; k++) {
                virCapsGuestMachinePtr machine = caps->guests[i]->arch.domains[j]->info.machines[k];
                virBufferAddLit(&xml, "        <machine");
                if (machine->canonical)
                    virBufferAsprintf(&xml, " canonical='%s'", machine->canonical);
                virBufferAsprintf(&xml, ">%s</machine>\n", machine->name);
            }
            virBufferAddLit(&xml, "      </domain>\n");
        }

        virBufferAddLit(&xml, "    </arch>\n");

        if (caps->guests[i]->nfeatures) {
            virBufferAddLit(&xml, "    <features>\n");

            for (j = 0 ; j < caps->guests[i]->nfeatures ; j++) {
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

extern void
virCapabilitiesSetMacPrefix(virCapsPtr caps,
                            unsigned char *prefix)
{
    memcpy(caps->macPrefix, prefix, sizeof(caps->macPrefix));
}

extern void
virCapabilitiesGenerateMac(virCapsPtr caps,
                           unsigned char *mac)
{
    virMacAddrGenerate(caps->macPrefix, mac);
}

extern void
virCapabilitiesSetEmulatorRequired(virCapsPtr caps) {
    caps->emulatorRequired = 1;
}

extern unsigned int
virCapabilitiesIsEmulatorRequired(virCapsPtr caps) {
    return caps->emulatorRequired;
}
