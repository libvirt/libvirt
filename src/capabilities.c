/*
 * capabilities.c: hypervisor capabilities
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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

#include "capabilities.h"
#include "buf.h"


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

    if ((caps = calloc(1, sizeof(*caps))) == NULL)
        goto no_memory;

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
    free(cell->cpus);
    free(cell);
}

static void
virCapabilitiesFreeGuestDomain(virCapsGuestDomainPtr dom)
{
    int i;
    free(dom->info.emulator);
    free(dom->info.loader);
    for (i = 0 ; i < dom->info.nmachines ; i++)
        free(dom->info.machines[i]);
    free(dom->info.machines);
    free(dom->type);

    free(dom);
}

static void
virCapabilitiesFreeGuestFeature(virCapsGuestFeaturePtr feature)
{
    free(feature->name);
    free(feature);
}

static void
virCapabilitiesFreeGuest(virCapsGuestPtr guest)
{
    int i;
    free(guest->ostype);

    free(guest->arch.name);
    free(guest->arch.defaultInfo.emulator);
    free(guest->arch.defaultInfo.loader);
    for (i = 0 ; i < guest->arch.defaultInfo.nmachines ; i++)
        free(guest->arch.defaultInfo.machines[i]);
    free(guest->arch.defaultInfo.machines);

    for (i = 0 ; i < guest->arch.ndomains ; i++)
        virCapabilitiesFreeGuestDomain(guest->arch.domains[i]);
    free(guest->arch.domains);

    for (i = 0 ; i < guest->nfeatures ; i++)
        virCapabilitiesFreeGuestFeature(guest->features[i]);
    free(guest->features);

    free(guest);
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

    for (i = 0 ; i < caps->nguests ; i++)
        virCapabilitiesFreeGuest(caps->guests[i]);
    free(caps->guests);

    for (i = 0 ; i < caps->host.nfeatures ; i++)
        free(caps->host.features[i]);
    free(caps->host.features);
    for (i = 0 ; i < caps->host.nnumaCell ; i++)
        virCapabilitiesFreeHostNUMACell(caps->host.numaCell[i]);
    free(caps->host.numaCell);

    for (i = 0 ; i < caps->host.nmigrateTrans ; i++)
        free(caps->host.migrateTrans[i]);
    free(caps->host.migrateTrans);

    free(caps->host.arch);
    free(caps);
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
    char **features;

    if ((features = realloc(caps->host.features,
                            sizeof(*features) * (caps->host.nfeatures+1))) == NULL)
        return -1;
    caps->host.features = features;

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
    char **migrateTrans;

    if ((migrateTrans = realloc(caps->host.migrateTrans,
                                sizeof(*migrateTrans) * (caps->host.nmigrateTrans+1))) == NULL)
        return -1;
    caps->host.migrateTrans = migrateTrans;

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
    virCapsHostNUMACellPtr cell, *cells;

    if ((cells = realloc(caps->host.numaCell,
                         sizeof(*cells) * (caps->host.nnumaCell+1))) == NULL)
        return -1;
    caps->host.numaCell = cells;

    if ((cell = calloc(1, sizeof(cell))) == NULL)
        return -1;
    caps->host.numaCell[caps->host.nnumaCell] = cell;

    if ((caps->host.numaCell[caps->host.nnumaCell]->cpus =
         malloc(ncpus * sizeof(*cpus))) == NULL)
        return -1;
    memcpy(caps->host.numaCell[caps->host.nnumaCell]->cpus,
           cpus,
           ncpus * sizeof(*cpus));

    caps->host.numaCell[caps->host.nnumaCell]->ncpus = ncpus;
    caps->host.numaCell[caps->host.nnumaCell]->num = num;
    caps->host.nnumaCell++;

    return 0;
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
                        const char *const *machines)
{
    virCapsGuestPtr guest, *guests;
    int i;

    if ((guest = calloc(1, sizeof(*guest))) == NULL)
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
    if (nmachines) {
        if ((guest->arch.defaultInfo.machines =
             calloc(nmachines, sizeof(*guest->arch.defaultInfo.machines))) == NULL)
            goto no_memory;
        for (i = 0 ; i < nmachines ; i++) {
            if ((guest->arch.defaultInfo.machines[i] = strdup(machines[i])) == NULL)
                goto no_memory;
            guest->arch.defaultInfo.nmachines++;
        }
    }

    if ((guests = realloc(caps->guests,
                          sizeof(*guests) *
                          (caps->nguests + 1))) == NULL)
        goto no_memory;
    caps->guests = guests;
    caps->guests[caps->nguests] = guest;
    caps->nguests++;

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
                              const char *const *machines)
{
    virCapsGuestDomainPtr dom, *doms;
    int i;

    if ((dom = calloc(1, sizeof(*dom))) == NULL)
        goto no_memory;

    if ((dom->type = strdup(hvtype)) == NULL)
        goto no_memory;

    if (emulator &&
        (dom->info.emulator = strdup(emulator)) == NULL)
        goto no_memory;
    if (loader &&
        (dom->info.loader = strdup(loader)) == NULL)
        goto no_memory;
    if (nmachines) {
        if ((dom->info.machines =
             calloc(nmachines, sizeof(*dom->info.machines))) == NULL)
            goto no_memory;
        for (i = 0 ; i < nmachines ; i++) {
            if ((dom->info.machines[i] = strdup(machines[i])) == NULL)
                goto no_memory;
            dom->info.nmachines++;
        }
    }

    if ((doms = realloc(guest->arch.domains,
                        sizeof(*doms) *
                        (guest->arch.ndomains + 1))) == NULL)
        goto no_memory;
    guest->arch.domains = doms;
    guest->arch.domains[guest->arch.ndomains] = dom;
    guest->arch.ndomains++;


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
    virCapsGuestFeaturePtr feature, *features;

    if ((feature = calloc(1, sizeof(*feature))) == NULL)
        goto no_memory;

    if ((feature->name = strdup(name)) == NULL)
        goto no_memory;
    feature->defaultOn = defaultOn;
    feature->toggle = toggle;

    if ((features = realloc(guest->features,
                            sizeof(*features) *
                            (guest->nfeatures + 1))) == NULL)
        goto no_memory;
    guest->features = features;
    guest->features[guest->nfeatures] = feature;
    guest->nfeatures++;

    return feature;

 no_memory:
    virCapabilitiesFreeGuestFeature(feature);
    return NULL;
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
 * virCapabilitiesDefaultGuestArch:
 * @caps: capabilities to query
 * @ostype: OS type to search for
 *
 * Returns the first architecture able to run the
 * requested operating system type
 */
extern const char *
virCapabilitiesDefaultGuestArch(virCapsPtr caps,
                                const char *ostype)
{
    int i;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype))
            return caps->guests[i]->arch.name;
    }
    return NULL;
}

/**
 * virCapabilitiesDefaultGuestMachine:
 * @caps: capabilities to query
 * @ostype: OS type to search for
 * @arch: architecture to search for
 *
 * Returns the first machine variant associated with
 * the requested operating system type and architecture
 */
extern const char *
virCapabilitiesDefaultGuestMachine(virCapsPtr caps,
                                   const char *ostype,
                                   const char *arch)
{
    int i;
    for (i = 0 ; i < caps->nguests ; i++) {
        if (STREQ(caps->guests[i]->ostype, ostype) &&
            STREQ(caps->guests[i]->arch.name, arch) &&
            caps->guests[i]->arch.defaultInfo.nmachines)
            return caps->guests[i]->arch.defaultInfo.machines[0];
    }
    return NULL;
}

/**
 * virCapabilitiesDefaultGuestMachine:
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
    virBuffer xml = { NULL, 0, 0 };
    int i, j, k;

    if (virBufferAddLit(&xml, "<capabilities>\n\n") < 0)
      goto no_memory;
    if (virBufferAddLit(&xml, "  <host>\n") < 0)
        goto no_memory;
    if (virBufferAddLit(&xml, "    <cpu>\n") < 0)
        goto no_memory;
    if (virBufferVSprintf(&xml, "      <arch>%s</arch>\n",
                          caps->host.arch) < 0)
        goto no_memory;

    if (caps->host.nfeatures) {
        if (virBufferAddLit(&xml, "      <features>\n") < 0)
            goto no_memory;
        for (i = 0 ; i < caps->host.nfeatures ; i++) {
            if (virBufferVSprintf(&xml, "        <%s/>\n",
                                  caps->host.features[i]) <0)
                goto no_memory;
        }
        if (virBufferAddLit(&xml, "      </features>\n") < 0)
            goto no_memory;
    }
    if (virBufferAddLit(&xml, "    </cpu>\n") < 0)
        goto no_memory;

    if (caps->host.offlineMigrate) {
        if (virBufferAddLit(&xml, "    <migration_features>\n") < 0)
            goto no_memory;
        if (caps->host.liveMigrate &&
            virBufferAddLit(&xml, "      <live/>\n") < 0)
            goto no_memory;
        if (caps->host.nmigrateTrans) {
            if (virBufferAddLit(&xml, "      <uri_transports>\n") < 0)
                goto no_memory;
            for (i = 0 ; i < caps->host.nmigrateTrans ; i++) {
                if (virBufferVSprintf(&xml, "        <uri_transport>%s</uri_transport>\n",
                                      caps->host.migrateTrans[i]) < 0)
                    goto no_memory;
            }
            if (virBufferAddLit(&xml, "      </uri_transports>\n") < 0)
                goto no_memory;
        }
        if (virBufferAddLit(&xml, "    </migration_features>\n") < 0)
            goto no_memory;
    }

    if (caps->host.nnumaCell) {
        if (virBufferAddLit(&xml, "    <topology>\n") < 0)
            goto no_memory;
        if (virBufferVSprintf(&xml, "      <cells num='%d'>\n",
                              caps->host.nnumaCell) < 0)
            goto no_memory;
        for (i = 0 ; i < caps->host.nnumaCell ; i++) {
            if (virBufferVSprintf(&xml, "        <cell id='%d'>\n",
                                  caps->host.numaCell[i]->num) < 0)
                goto no_memory;
            if (virBufferVSprintf(&xml, "          <cpus num='%d'>\n",
                                  caps->host.numaCell[i]->ncpus) < 0)
                goto no_memory;
            for (j = 0 ; j < caps->host.numaCell[i]->ncpus ; j++)
                if (virBufferVSprintf(&xml, "            <cpu id='%d'/>\n",
                                      caps->host.numaCell[i]->cpus[j]) < 0)
                    goto no_memory;
            if (virBufferAddLit(&xml, "          </cpus>\n") < 0)
                goto no_memory;
            if (virBufferAddLit(&xml, "        </cell>\n") < 0)
                goto no_memory;
        }
        if (virBufferAddLit(&xml, "      </cells>\n") < 0)
            goto no_memory;
        if (virBufferAddLit(&xml, "    </topology>\n") < 0)
            goto no_memory;
    }
    if (virBufferAddLit(&xml, "  </host>\n\n") < 0)
        goto no_memory;


    for (i = 0 ; i < caps->nguests ; i++) {
        if (virBufferAddLit(&xml, "  <guest>\n") < 0)
            goto no_memory;
        if (virBufferVSprintf(&xml, "    <os_type>%s</os_type>\n",
                              caps->guests[i]->ostype) < 0)
            goto no_memory;
        if (virBufferVSprintf(&xml, "    <arch name='%s'>\n",
                              caps->guests[i]->arch.name) < 0)
            goto no_memory;
        if (virBufferVSprintf(&xml, "      <wordsize>%d</wordsize>\n",
                              caps->guests[i]->arch.wordsize) < 0)
            goto no_memory;
        if (caps->guests[i]->arch.defaultInfo.emulator &&
            virBufferVSprintf(&xml, "      <emulator>%s</emulator>\n",
                              caps->guests[i]->arch.defaultInfo.emulator) < 0)
            goto no_memory;
        if (caps->guests[i]->arch.defaultInfo.loader &&
            virBufferVSprintf(&xml, "      <loader>%s</loader>\n",
                              caps->guests[i]->arch.defaultInfo.loader) < 0)
            goto no_memory;

        for (j = 0 ; j < caps->guests[i]->arch.defaultInfo.nmachines ; j++) {
            if (virBufferVSprintf(&xml, "      <machine>%s</machine>\n",
                                  caps->guests[i]->arch.defaultInfo.machines[j]) < 0)
                goto no_memory;
        }

        for (j = 0 ; j < caps->guests[i]->arch.ndomains ; j++) {
            if (virBufferVSprintf(&xml, "      <domain type='%s'>\n",
                                  caps->guests[i]->arch.domains[j]->type) < 0)
            goto no_memory;
            if (caps->guests[i]->arch.domains[j]->info.emulator &&
                virBufferVSprintf(&xml, "        <emulator>%s</emulator>\n",
                                  caps->guests[i]->arch.domains[j]->info.emulator) < 0)
                goto no_memory;
            if (caps->guests[i]->arch.domains[j]->info.loader &&
                virBufferVSprintf(&xml, "        <loader>%s</loader>\n",
                                  caps->guests[i]->arch.domains[j]->info.loader) < 0)
                goto no_memory;

            for (k = 0 ; k < caps->guests[i]->arch.domains[j]->info.nmachines ; k++) {
                if (virBufferVSprintf(&xml, "        <machine>%s</machine>\n",
                                      caps->guests[i]->arch.domains[j]->info.machines[k]) < 0)
                    goto no_memory;
            }
            if (virBufferAddLit(&xml, "      </domain>\n") < 0)
                goto no_memory;
        }

        if (virBufferAddLit(&xml, "    </arch>\n") < 0)
            goto no_memory;

        if (caps->guests[i]->nfeatures) {
            if (virBufferAddLit(&xml, "    <features>\n") < 0)
                goto no_memory;

            for (j = 0 ; j < caps->guests[i]->nfeatures ; j++) {
                if (STREQ(caps->guests[i]->features[j]->name, "pae") ||
                    STREQ(caps->guests[i]->features[j]->name, "nonpae") ||
                    STREQ(caps->guests[i]->features[j]->name, "ia64_be")) {
                    if (virBufferVSprintf(&xml, "      <%s/>\n",
                                          caps->guests[i]->features[j]->name) < 0)
                        goto no_memory;
                } else {
                    if (virBufferVSprintf(&xml, "      <%s default='%s' toggle='%s'/>\n",
                                          caps->guests[i]->features[j]->name,
                                          caps->guests[i]->features[j]->defaultOn ? "on" : "off",
                                          caps->guests[i]->features[j]->toggle ? "yes" : "no") < 0)
                        goto no_memory;
                }
            }

            if (virBufferAddLit(&xml, "    </features>\n") < 0)
                goto no_memory;
        }


        if (virBufferAddLit(&xml, "  </guest>\n\n") < 0)
            goto no_memory;
    }

    if (virBufferAddLit(&xml, "</capabilities>\n") < 0)
      goto no_memory;

    return xml.content;

 no_memory:
    free(xml.content);
    return NULL;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
