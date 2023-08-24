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
#include "viruuid.h"
#include "virenum.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

#define SYSFS_SYSTEM_PATH "/sys/devices/system"

VIR_LOG_INIT("conf.capabilities");

VIR_ENUM_DECL(virCapsHostPMTarget);
VIR_ENUM_IMPL(virCapsHostPMTarget,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "suspend_mem", "suspend_disk", "suspend_hybrid",
);

static virClass *virCapsClass;
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
virCaps *
virCapabilitiesNew(virArch hostarch,
                   bool offlineMigrate,
                   bool liveMigrate)
{
    virCaps *caps;

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
virCapabilitiesClearHostNUMACellCPUTopology(virCapsHostNUMACellCPU *cpus,
                                            size_t ncpus)
{
    size_t i;

    if (!cpus)
        return;

    for (i = 0; i < ncpus; i++)
        g_clear_pointer(&cpus[i].siblings, virBitmapFree);
}

static void
virCapabilitiesFreeHostNUMACell(virCapsHostNUMACell *cell)
{
    if (cell == NULL)
        return;

    virCapabilitiesClearHostNUMACellCPUTopology(cell->cpus, cell->ncpus);

    g_free(cell->cpus);
    g_free(cell->distances);
    g_free(cell->pageinfo);
    if (cell->caches)
        g_array_unref(cell->caches);
    g_free(cell);
}

static void
virCapabilitiesFreeGuestMachine(virCapsGuestMachine *machine)
{
    if (machine == NULL)
        return;
    g_free(machine->name);
    g_free(machine->canonical);
    g_free(machine);
}

static void
virCapabilitiesFreeGuestDomain(virCapsGuestDomain *dom)
{
    size_t i;
    if (dom == NULL)
        return;

    g_free(dom->info.emulator);
    g_free(dom->info.loader);
    for (i = 0; i < dom->info.nmachines; i++)
        virCapabilitiesFreeGuestMachine(dom->info.machines[i]);
    g_free(dom->info.machines);

    g_free(dom);
}

void
virCapabilitiesFreeGuest(virCapsGuest *guest)
{
    size_t i;
    if (guest == NULL)
        return;

    g_free(guest->arch.defaultInfo.emulator);
    g_free(guest->arch.defaultInfo.loader);
    for (i = 0; i < guest->arch.defaultInfo.nmachines; i++)
        virCapabilitiesFreeGuestMachine(guest->arch.defaultInfo.machines[i]);
    g_free(guest->arch.defaultInfo.machines);

    for (i = 0; i < guest->arch.ndomains; i++)
        virCapabilitiesFreeGuestDomain(guest->arch.domains[i]);
    g_free(guest->arch.domains);

    g_free(guest);
}


static void
virCapabilitiesFreeStoragePool(virCapsStoragePool *pool)
{
    if (!pool)
        return;

    g_free(pool);
}


void
virCapabilitiesHostNUMAUnref(virCapsHostNUMA *caps)
{
    if (!caps)
        return;

    if (g_atomic_int_dec_and_test(&caps->refs)) {
        g_ptr_array_unref(caps->cells);
        if (caps->interconnects)
            g_array_unref(caps->interconnects);
        g_free(caps);
    }
}

void
virCapabilitiesHostNUMARef(virCapsHostNUMA *caps)
{
    g_atomic_int_inc(&caps->refs);
}

static void
virCapsHostMemBWNodeFree(virCapsHostMemBWNode *ptr)
{
    if (!ptr)
        return;

    virBitmapFree(ptr->cpus);
    g_free(ptr);
}

static void
virCapabilitiesClearSecModel(virCapsHostSecModel *secmodel)
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
    virCaps *caps = object;
    size_t i;

    for (i = 0; i < caps->npools; i++)
        virCapabilitiesFreeStoragePool(caps->pools[i]);
    g_free(caps->pools);

    for (i = 0; i < caps->nguests; i++)
        virCapabilitiesFreeGuest(caps->guests[i]);
    g_free(caps->guests);

    for (i = 0; i < caps->host.nfeatures; i++)
        g_free(caps->host.features[i]);
    g_free(caps->host.features);

    if (caps->host.numa)
        virCapabilitiesHostNUMAUnref(caps->host.numa);

    for (i = 0; i < caps->host.nmigrateTrans; i++)
        g_free(caps->host.migrateTrans[i]);
    g_free(caps->host.migrateTrans);

    for (i = 0; i < caps->host.nsecModels; i++)
        virCapabilitiesClearSecModel(&caps->host.secModels[i]);
    g_free(caps->host.secModels);

    for (i = 0; i < caps->host.cache.nbanks; i++)
        virCapsHostCacheBankFree(caps->host.cache.banks[i]);
    virResctrlInfoMonFree(caps->host.cache.monitor);
    g_free(caps->host.cache.banks);

    for (i = 0; i < caps->host.memBW.nnodes; i++)
        virCapsHostMemBWNodeFree(caps->host.memBW.nodes[i]);
    virResctrlInfoMonFree(caps->host.memBW.monitor);
    g_free(caps->host.memBW.nodes);

    g_free(caps->host.netprefix);
    g_free(caps->host.pagesSize);
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
virCapabilitiesAddHostFeature(virCaps *caps,
                              const char *name)
{
    VIR_RESIZE_N(caps->host.features, caps->host.nfeatures_max,
                 caps->host.nfeatures, 1);
    caps->host.features[caps->host.nfeatures] = g_strdup(name);
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
virCapabilitiesAddHostMigrateTransport(virCaps *caps,
                                       const char *name)
{
    VIR_RESIZE_N(caps->host.migrateTrans, caps->host.nmigrateTrans_max,
                 caps->host.nmigrateTrans, 1);
    caps->host.migrateTrans[caps->host.nmigrateTrans] = g_strdup(name);
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
virCapabilitiesSetNetPrefix(virCaps *caps,
                            const char *prefix)
{
    caps->host.netprefix = g_strdup(prefix);

    return 0;
}


/**
 * virCapabilitiesHostNUMAAddCell:
 * @caps: capabilities to extend
 * @num: ID number of NUMA cell
 * @mem: Total size of memory in the NUMA node (in KiB)
 * @ncpus: number of CPUs in cell
 * @cpus: array of CPU definition structures
 * @ndistances: number of sibling NUMA nodes
 * @distances: NUMA distances to other nodes
 * @npageinfo: number of pages at node @num
 * @pageinfo: info on each single memory page
 * @caches: info on memory side caches
 *
 * Registers a new NUMA cell for a host, passing in a array of
 * CPU IDs belonging to the cell, distances to other NUMA nodes
 * and info on hugepages on the node.
 *
 * All pointers are stolen.
 */
void
virCapabilitiesHostNUMAAddCell(virCapsHostNUMA *caps,
                               int num,
                               unsigned long long mem,
                               int ncpus,
                               virCapsHostNUMACellCPU **cpus,
                               int ndistances,
                               virNumaDistance **distances,
                               int npageinfo,
                               virCapsHostNUMACellPageInfo **pageinfo,
                               GArray **caches)
{
    virCapsHostNUMACell *cell = g_new0(virCapsHostNUMACell, 1);

    cell->num = num;
    cell->mem = mem;
    if (cpus) {
        cell->ncpus = ncpus;
        cell->cpus = g_steal_pointer(cpus);
    }
    if (distances) {
        cell->ndistances = ndistances;
        cell->distances = g_steal_pointer(distances);
    }
    if (pageinfo) {
        cell->npageinfo = npageinfo;
        cell->pageinfo = g_steal_pointer(pageinfo);
    }
    if (caches) {
        cell->caches = g_steal_pointer(caches);
    }

    g_ptr_array_add(caps->cells, cell);
}

/**
 * virCapabilitiesAllocMachines:
 * @machines: NULL-terminated list of machine variants for emulator ('pc', or 'isapc', etc)
 * @nmachines: filled with number of machine variants for emulator
 *
 * Allocate a table of virCapsGuestMachine *from the supplied table
 * of machine names.
 */
virCapsGuestMachine **
virCapabilitiesAllocMachines(const char *const *names,
                             int *nnames)
{
    virCapsGuestMachine **machines;
    size_t i;

    *nnames = g_strv_length((gchar **)names);
    machines = g_new0(virCapsGuestMachine *, *nnames);

    for (i = 0; i < *nnames; i++) {
        machines[i] = g_new0(virCapsGuestMachine, 1);
        machines[i]->name = g_strdup(names[i]);
    }

    return machines;
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
virCapsGuest *
virCapabilitiesAddGuest(virCaps *caps,
                        int ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachine **machines)
{
    virCapsGuest *guest;

    guest = g_new0(virCapsGuest, 1);

    guest->ostype = ostype;
    guest->arch.id = arch;
    guest->arch.wordsize = virArchGetWordSize(arch);

    guest->arch.defaultInfo.emulator = g_strdup(emulator);
    guest->arch.defaultInfo.loader = g_strdup(loader);

    VIR_RESIZE_N(caps->guests, caps->nguests_max, caps->nguests, 1);
    caps->guests[caps->nguests++] = guest;

    if (nmachines) {
        guest->arch.defaultInfo.nmachines = nmachines;
        guest->arch.defaultInfo.machines = machines;
    }

    return guest;
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
virCapsGuestDomain *
virCapabilitiesAddGuestDomain(virCapsGuest *guest,
                              int hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachine **machines)
{
    virCapsGuestDomain *dom;

    dom = g_new0(virCapsGuestDomain, 1);

    dom->type = hvtype;
    dom->info.emulator = g_strdup(emulator);
    dom->info.loader = g_strdup(loader);

    VIR_RESIZE_N(guest->arch.domains, guest->arch.ndomains_max,
                 guest->arch.ndomains, 1);
    guest->arch.domains[guest->arch.ndomains] = dom;
    guest->arch.ndomains++;

    if (nmachines) {
        dom->info.nmachines = nmachines;
        dom->info.machines = machines;
    }

    return dom;
}


struct virCapsGuestFeatureInfo {
    const char *name;
    bool togglesRequired;
};

static const struct virCapsGuestFeatureInfo virCapsGuestFeatureInfos[VIR_CAPS_GUEST_FEATURE_TYPE_LAST] = {
    [VIR_CAPS_GUEST_FEATURE_TYPE_PAE] = { "pae", false },
    [VIR_CAPS_GUEST_FEATURE_TYPE_NONPAE] = { "nonpae", false },
    [VIR_CAPS_GUEST_FEATURE_TYPE_IA64_BE] = { "ia64_be", false },
    [VIR_CAPS_GUEST_FEATURE_TYPE_ACPI] = { "acpi", true },
    [VIR_CAPS_GUEST_FEATURE_TYPE_APIC] = { "apic", true },
    [VIR_CAPS_GUEST_FEATURE_TYPE_CPUSELECTION] = { "cpuselection", false },
    [VIR_CAPS_GUEST_FEATURE_TYPE_DEVICEBOOT] = { "deviceboot", false },
    [VIR_CAPS_GUEST_FEATURE_TYPE_DISKSNAPSHOT] = { "disksnapshot", true },
    [VIR_CAPS_GUEST_FEATURE_TYPE_HAP] = { "hap", true },
    [VIR_CAPS_GUEST_FEATURE_TYPE_EXTERNAL_SNAPSHOT] = { "externalSnapshot", false },
};


static void
virCapabilitiesAddGuestFeatureInternal(virCapsGuest *guest,
                                       virCapsGuestFeatureType feature,
                                       bool defaultOn,
                                       bool toggle)
{
    guest->features[feature].present = true;

    if (virCapsGuestFeatureInfos[feature].togglesRequired) {
        guest->features[feature].defaultOn = virTristateSwitchFromBool(defaultOn);
        guest->features[feature].toggle = virTristateBoolFromBool(toggle);
    }
}


/**
 * virCapabilitiesAddGuestFeature:
 * @guest: guest to associate feature with
 * @feature: feature to add
 *
 * Registers a feature for a guest domain.
 */
void
virCapabilitiesAddGuestFeature(virCapsGuest *guest,
                               virCapsGuestFeatureType feature)
{
    virCapabilitiesAddGuestFeatureInternal(guest, feature, false, false);
}


/**
 * virCapabilitiesAddGuestFeatureWithToggle:
 * @guest: guest to associate feature with
 * @feature: feature to add
 * @defaultOn: true if it defaults to on
 * @toggle: true if its state can be toggled
 *
 * Registers a feature with toggles for a guest domain.
 */
void
virCapabilitiesAddGuestFeatureWithToggle(virCapsGuest *guest,
                                         virCapsGuestFeatureType feature,
                                         bool defaultOn,
                                         bool toggle)
{
    virCapabilitiesAddGuestFeatureInternal(guest, feature, defaultOn, toggle);
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
virCapabilitiesHostSecModelAddBaseLabel(virCapsHostSecModel *secmodel,
                                        const char *type,
                                        const char *label)
{
    if (type == NULL || label == NULL)
        return -1;

    VIR_EXPAND_N(secmodel->labels, secmodel->nlabels, 1);
    secmodel->labels[secmodel->nlabels - 1].type = g_strdup(type);
    secmodel->labels[secmodel->nlabels - 1].label = g_strdup(label);

    return 0;
}


static virCapsDomainData *
virCapabilitiesDomainDataLookupInternal(virCaps *caps,
                                        int ostype,
                                        virArch arch,
                                        virDomainVirtType domaintype,
                                        const char *emulator,
                                        const char *machinetype)
{
    virCapsGuest *foundguest = NULL;
    virCapsGuestDomain *founddomain = NULL;
    virCapsGuestMachine *foundmachine = NULL;
    virCapsDomainData *ret = NULL;
    size_t i, j, k;

    VIR_DEBUG("Lookup ostype=%d arch=%d domaintype=%d emulator=%s machine=%s",
              ostype, arch, domaintype, NULLSTR(emulator), NULLSTR(machinetype));
    for (i = 0; i < caps->nguests; i++) {
        virCapsGuest *guest = caps->guests[i];

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
            virCapsGuestDomain *domain = guest->arch.domains[j];
            virCapsGuestMachine **machinelist;
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
                virCapsGuestMachine *machine = machinelist[k];

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
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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

        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find capabilities for %1$s"),
                       virBufferCurrentContent(&buf));
        return ret;
    }

    ret = g_new0(virCapsDomainData, 1);

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
virCapsDomainData *
virCapabilitiesDomainDataLookup(virCaps *caps,
                                int ostype,
                                virArch arch,
                                int domaintype,
                                const char *emulator,
                                const char *machinetype)
{
    virCapsDomainData *ret;

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


bool
virCapabilitiesDomainSupported(virCaps *caps,
                               int ostype,
                               virArch arch,
                               int virttype)
{
    g_autofree virCapsDomainData *capsdata = NULL;

    capsdata = virCapabilitiesDomainDataLookup(caps, ostype,
                                               arch,
                                               virttype,
                                               NULL, NULL);

    return capsdata != NULL;
}


int
virCapabilitiesAddStoragePool(virCaps *caps,
                              int poolType)
{
    virCapsStoragePool *pool;

    pool = g_new0(virCapsStoragePool, 1);

    pool->type = poolType;

    VIR_RESIZE_N(caps->pools, caps->npools_max, caps->npools, 1);
    caps->pools[caps->npools++] = pool;

    return 0;
}


static int
virCapsHostNUMACellCPUFormat(virBuffer *buf,
                             const virCapsHostNUMACellCPU *cpus,
                             int ncpus)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t j;

    virBufferAsprintf(&attrBuf, " num='%d'", ncpus);

    for (j = 0; j < ncpus; j++) {
        virBufferAsprintf(&childBuf, "<cpu id='%d'", cpus[j].id);

        if (cpus[j].siblings) {
            g_autofree char *siblings = NULL;

            if (!(siblings = virBitmapFormat(cpus[j].siblings)))
                return -1;

            virBufferAsprintf(&childBuf,
                              " socket_id='%d' die_id='%d' core_id='%d' siblings='%s'",
                              cpus[j].socket_id,
                              cpus[j].die_id,
                              cpus[j].core_id,
                              siblings);
        }
        virBufferAddLit(&childBuf, "/>\n");
    }

    virXMLFormatElement(buf, "cpus", &attrBuf, &childBuf);
    return 0;
}


static int
virCapabilitiesHostNUMAFormat(virBuffer *buf,
                              virCapsHostNUMA *caps)
{
    size_t i;

    if (!caps)
        return 0;

    virBufferAddLit(buf, "<topology>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<cells num='%d'>\n", caps->cells->len);
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < caps->cells->len; i++) {
        virCapsHostNUMACell *cell = g_ptr_array_index(caps->cells, i);
        size_t j;

        virBufferAsprintf(buf, "<cell id='%d'>\n", cell->num);
        virBufferAdjustIndent(buf, 2);

        /* Print out the numacell memory total if it is available */
        if (cell->mem)
            virBufferAsprintf(buf, "<memory unit='KiB'>%llu</memory>\n",
                              cell->mem);

        for (j = 0; j < cell->npageinfo; j++) {
            virBufferAsprintf(buf, "<pages unit='KiB' size='%u'>%llu</pages>\n",
                              cell->pageinfo[j].size,
                              cell->pageinfo[j].avail);
        }

        virNumaDistanceFormat(buf, cell->distances, cell->ndistances);

        if (cell->caches) {
            virNumaCache *caches = &g_array_index(cell->caches, virNumaCache, 0);
            virNumaCacheFormat(buf, caches, cell->caches->len);
        }

        if (virCapsHostNUMACellCPUFormat(buf, cell->cpus, cell->ncpus) < 0)
            return -1;

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</cell>\n");
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cells>\n");

    if (caps->interconnects) {
        const virNumaInterconnect *interconnects;
        interconnects = &g_array_index(caps->interconnects, virNumaInterconnect, 0);
        virNumaInterconnectFormat(buf, interconnects, caps->interconnects->len);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</topology>\n");
    return 0;
}


static int
virCapabilitiesFormatResctrlMonitor(virBuffer *buf,
                                    virResctrlInfoMon *monitor)
{
    size_t i = 0;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);

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

    for (i = 0; i < monitor->nfeatures; i++) {
        virBufferAsprintf(&childrenBuf,
                          "<feature name='%s'/>\n",
                          monitor->features[i]);
    }

    virBufferAddBuffer(buf, &childrenBuf);
    virBufferAddLit(buf, "</monitor>\n");

    return 0;
}

static int
virCapabilitiesFormatCaches(virBuffer *buf,
                            virCapsHostCache *cache)
{
    size_t i = 0;
    size_t j = 0;

    if (!cache->nbanks && !cache->monitor)
        return 0;

    virBufferAddLit(buf, "<cache>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cache->nbanks; i++) {
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
        virCapsHostCacheBank *bank = cache->banks[i];
        g_autofree char *cpus_str = virBitmapFormat(bank->cpus);
        const char *unit = NULL;
        unsigned long long short_size = virFormatIntPretty(bank->size, &unit);

        if (!cpus_str)
            return -1;

        /*
         * Let's just *hope* the size is aligned to KiBs so that it does not
         * bite is back in the future
         */
        virBufferAsprintf(&attrBuf,
                          " id='%u' level='%u' type='%s' "
                          "size='%llu' unit='%s' cpus='%s'",
                          bank->id, bank->level,
                          virCacheTypeToString(bank->type),
                          short_size, unit, cpus_str);

        for (j = 0; j < bank->ncontrols; j++) {
            const char *min_unit;
            virResctrlInfoPerCache *controls = bank->controls[j];
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

        virXMLFormatElement(buf, "bank", &attrBuf, &childrenBuf);
    }

    if (virCapabilitiesFormatResctrlMonitor(buf, cache->monitor) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cache>\n");

    return 0;
}

static int
virCapabilitiesFormatMemoryBandwidth(virBuffer *buf,
                                     virCapsHostMemBW *memBW)
{
    size_t i = 0;

    if (!memBW->nnodes && !memBW->monitor)
        return 0;

    virBufferAddLit(buf, "<memory_bandwidth>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < memBW->nnodes; i++) {
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
        virCapsHostMemBWNode *node = memBW->nodes[i];
        virResctrlInfoMemBWPerNode *control = &node->control;
        g_autofree char *cpus_str = virBitmapFormat(node->cpus);

        if (!cpus_str)
            return -1;

        virBufferAsprintf(&attrBuf,
                          " id='%u' cpus='%s'",
                          node->id, cpus_str);

        virBufferAsprintf(&childrenBuf,
                          "<control granularity='%u' min='%u' "
                          "maxAllocs='%u'/>\n",
                          control->granularity, control->min,
                          control->max_allocation);

        virXMLFormatElement(buf, "node", &attrBuf, &childrenBuf);
    }

    if (virCapabilitiesFormatResctrlMonitor(buf, memBW->monitor) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</memory_bandwidth>\n");

    return 0;
}


static int
virCapabilitiesFormatHostXML(virCapsHost *host,
                             virBuffer *buf)
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

    if (virCapabilitiesHostNUMAFormat(buf, host->numa) < 0)
        return -1;

    if (virCapabilitiesFormatCaches(buf, &host->cache) < 0)
        return -1;

    if (virCapabilitiesFormatMemoryBandwidth(buf, &host->memBW) < 0)
        return -1;

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
}


static void
virCapabilitiesFormatGuestFeatures(virCapsGuest *guest,
                                   virBuffer *buf)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    for (i = 0; i < VIR_CAPS_GUEST_FEATURE_TYPE_LAST; i++) {
        virCapsGuestFeature *feature = guest->features + i;

        if (!feature->present)
            continue;

        virBufferAsprintf(&childBuf, "<%s", virCapsGuestFeatureInfos[i].name);

        if (feature->defaultOn) {
            virBufferAsprintf(&childBuf, " default='%s'",
                              virTristateSwitchTypeToString(feature->defaultOn));
        }

        if (feature->toggle) {
            virBufferAsprintf(&childBuf, " toggle='%s'",
                              virTristateBoolTypeToString(feature->toggle));
        }

        virBufferAddLit(&childBuf, "/>\n");
    }

    virXMLFormatElement(buf, "features", NULL, &childBuf);
}


static void
virCapabilitiesFormatGuestXML(virCapsGuest **guests,
                              size_t nguests,
                              virBuffer *buf)
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
            virCapsGuestMachine *machine = guests[i]->arch.defaultInfo.machines[j];
            virBufferAddLit(buf, "<machine");
            if (machine->canonical)
                virBufferAsprintf(buf, " canonical='%s'", machine->canonical);
            if (machine->maxCpus > 0)
                virBufferAsprintf(buf, " maxCpus='%d'", machine->maxCpus);
            if (machine->deprecated)
                virBufferAddLit(buf, " deprecated='yes'");
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
                virCapsGuestMachine *machine = guests[i]->arch.domains[j]->info.machines[k];
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

        virCapabilitiesFormatGuestFeatures(guests[i], buf);

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</guest>\n\n");
    }
}


static void
virCapabilitiesFormatStoragePoolXML(virCapsStoragePool **pools,
                                    size_t npools,
                                    virBuffer *buf)
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
virCapabilitiesFormatXML(virCaps *caps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "<capabilities>\n\n");
    virBufferAdjustIndent(&buf, 2);

    if (virCapabilitiesFormatHostXML(&caps->host, &buf) < 0)
        return NULL;

    virCapabilitiesFormatGuestXML(caps->guests, caps->nguests, &buf);

    virCapabilitiesFormatStoragePoolXML(caps->pools, caps->npools, &buf);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</capabilities>\n");

    return virBufferContentAndReset(&buf);
}

/* get the maximum ID of cpus in the host */
static unsigned int
virCapabilitiesHostNUMAGetMaxcpu(virCapsHostNUMA *caps)
{
    unsigned int maxcpu = 0;
    size_t node;
    size_t cpu;

    for (node = 0; node < caps->cells->len; node++) {
        virCapsHostNUMACell *cell = g_ptr_array_index(caps->cells, node);

        for (cpu = 0; cpu < cell->ncpus; cpu++) {
            if (cell->cpus[cpu].id > maxcpu)
                maxcpu = cell->cpus[cpu].id;
        }
    }

    return maxcpu;
}

/* set cpus of a numa node in the bitmask */
static int
virCapabilitiesHostNUMAGetCellCpus(virCapsHostNUMA *caps,
                                   size_t node,
                                   virBitmap *cpumask)
{
    virCapsHostNUMACell *cell = NULL;
    size_t cpu;
    size_t i;
    /* The numa node numbers can be non-contiguous. Ex: 0,1,16,17. */
    for (i = 0; i < caps->cells->len; i++) {
        cell = g_ptr_array_index(caps->cells, i);
        if (cell->num == node)
            break;
        cell = NULL;
    }

    for (cpu = 0; cell && cpu < cell->ncpus; cpu++) {
        if (virBitmapSetBit(cpumask, cell->cpus[cpu].id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cpu '%1$u' in node '%2$zu' is out of range of the provided bitmap"),
                           cell->cpus[cpu].id, node);
            return -1;
        }
    }

    return 0;
}

virBitmap *
virCapabilitiesHostNUMAGetCpus(virCapsHostNUMA *caps,
                               virBitmap *nodemask)
{
    g_autoptr(virBitmap) ret = NULL;
    unsigned int maxcpu = virCapabilitiesHostNUMAGetMaxcpu(caps);
    ssize_t node = -1;

    ret = virBitmapNew(maxcpu + 1);

    while ((node = virBitmapNextSetBit(nodemask, node)) >= 0) {
        if (virCapabilitiesHostNUMAGetCellCpus(caps, node, ret) < 0)
            return NULL;
    }

    return g_steal_pointer(&ret);
}


int
virCapabilitiesHostNUMAGetMaxNode(virCapsHostNUMA *caps)
{
    virCapsHostNUMACell *cell = g_ptr_array_index(caps->cells, caps->cells->len - 1);

    return cell->num;
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
                           virCapsHostNUMACellCPU *cpu G_GNUC_UNUSED)
{
#ifdef __linux__
    cpu->id = cpu_id;

    if (virHostCPUGetSocket(cpu_id, &cpu->socket_id) < 0 ||
        virHostCPUGetDie(cpu_id, &cpu->die_id) < 0 ||
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
virCapabilitiesGetNUMADistances(int node,
                                virNumaDistance **distancesRet,
                                int *ndistancesRet)
{
    g_autofree virNumaDistance *tmp = NULL;
    int tmp_size = 0;
    g_autofree int *distances = NULL;
    int ndistances = 0;
    size_t i;

    if (virNumaGetDistances(node, &distances, &ndistances) < 0)
        return -1;

    if (!distances) {
        *distancesRet = NULL;
        *ndistancesRet = 0;
        return 0;
    }

    tmp = g_new0(virNumaDistance, ndistances);

    for (i = 0; i < ndistances; i++) {
        if (!distances[i])
            continue;

        tmp[tmp_size].cellid = i;
        tmp[tmp_size].value = distances[i];
        tmp_size++;
    }

    VIR_REALLOC_N(tmp, tmp_size);

    *ndistancesRet = tmp_size;
    *distancesRet = g_steal_pointer(&tmp);
    tmp_size = 0;

    return 0;
}

static int
virCapabilitiesGetNUMAPagesInfo(int node,
                                virCapsHostNUMACellPageInfo **pageinfo,
                                int *npageinfo)
{
    g_autofree unsigned int *pages_size = NULL;
    g_autofree unsigned long long *pages_avail = NULL;
    size_t npages, i;

    if (virNumaGetPages(node, &pages_size, &pages_avail, NULL, &npages) < 0)
        return -1;

    *pageinfo = g_new0(virCapsHostNUMACellPageInfo, npages);
    *npageinfo = npages;

    for (i = 0; i < npages; i++) {
        (*pageinfo)[i].size = pages_size[i];
        (*pageinfo)[i].avail = pages_avail[i];
    }

    return 0;
}


static int
virCapabilitiesGetNodeCacheReadFileUint(const char *prefix,
                                        const char *dir,
                                        const char *file,
                                        unsigned int *value)
{
    g_autofree char *path = g_build_filename(prefix, dir, file, NULL);
    int rv = virFileReadValueUint(value, "%s", path);

    if (rv < 0) {
        if (rv == -2) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("File '%1$s' does not exist"),
                           path);
        }
        return -1;
    }

    return 0;
}


static int
virCapabilitiesGetNodeCacheReadFileUllong(const char *prefix,
                                          const char *dir,
                                          const char *file,
                                          unsigned long long *value)
{
    g_autofree char *path = g_build_filename(prefix, dir, file, NULL);
    int rv = virFileReadValueUllong(value, "%s", path);

    if (rv < 0) {
        if (rv == -2) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("File '%1$s' does not exist"),
                           path);
        }
        return -1;
    }

    return 0;
}


static int
virCapsHostNUMACellCacheComparator(const void *a,
                                   const void *b)
{
    const virNumaCache *aa = a;
    const virNumaCache *bb = b;

    return aa->level - bb->level;
}


static int
virCapabilitiesGetNodeCache(int node,
                            GArray **cachesRet)
{
    g_autoptr(DIR) dir = NULL;
    int direrr = 0;
    struct dirent *entry;
    g_autofree char *path = NULL;
    g_autoptr(GArray) caches = g_array_new(FALSE, FALSE, sizeof(virNumaCache));

    path = g_strdup_printf(SYSFS_SYSTEM_PATH "/node/node%d/memory_side_cache", node);

    if (virDirOpenIfExists(&dir, path) < 0)
        return -1;

    while (dir && (direrr = virDirRead(dir, &entry, path)) > 0) {
        const char *dname = STRSKIP(entry->d_name, "index");
        virNumaCache cache = { 0 };
        unsigned int indexing;
        unsigned int write_policy;

        if (!dname)
            continue;

        if (virStrToLong_ui(dname, NULL, 10, &cache.level) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse %1$s"),
                           entry->d_name);
            return -1;
        }

        if (virCapabilitiesGetNodeCacheReadFileUllong(path, entry->d_name,
                                                      "size", &cache.size) < 0)
            return -1;

        cache.size >>= 10; /* read in bytes but stored in kibibytes */

        if (virCapabilitiesGetNodeCacheReadFileUint(path, entry->d_name,
                                                    "line_size", &cache.line) < 0)
            return -1;

        if (virCapabilitiesGetNodeCacheReadFileUint(path, entry->d_name,
                                                    "indexing", &indexing) < 0)
            return -1;

        /* see enum cache_indexing in kernel */
        switch (indexing) {
        case 0: cache.associativity = VIR_NUMA_CACHE_ASSOCIATIVITY_DIRECT; break;
        case 1: cache.associativity = VIR_NUMA_CACHE_ASSOCIATIVITY_FULL; break;
        case 2: cache.associativity = VIR_NUMA_CACHE_ASSOCIATIVITY_NONE; break;
        default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown indexing value '%1$u'"),
                               indexing);
                return -1;
        }

        if (virCapabilitiesGetNodeCacheReadFileUint(path, entry->d_name,
                                                    "write_policy", &write_policy) < 0)
            return -1;

        /* see enum cache_write_policy in kernel */
        switch (write_policy) {
        case 0: cache.policy = VIR_NUMA_CACHE_POLICY_WRITEBACK; break;
        case 1: cache.policy = VIR_NUMA_CACHE_POLICY_WRITETHROUGH; break;
        case 2: cache.policy = VIR_NUMA_CACHE_POLICY_NONE; break;
        default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown write_policy value '%1$u'"),
                               write_policy);
                return -1;
        }

        g_array_append_val(caches, cache);
    }

    if (direrr < 0)
        return -1;

    if (caches->len > 0) {
        g_array_sort(caches, virCapsHostNUMACellCacheComparator);
        *cachesRet = g_steal_pointer(&caches);
    } else {
        *cachesRet = NULL;
    }

    return 0;
}


static int
virCapabilitiesHostNUMAInitFake(virCapsHostNUMA *caps)
{
    virNodeInfo nodeinfo;
    virCapsHostNUMACellCPU *cpus;
    int ncpus;
    int n, s, c, t;
    int id, cid;
    int onlinecpus G_GNUC_UNUSED;
    bool tmp;

    if (virCapabilitiesGetNodeInfo(&nodeinfo) < 0)
        return -1;

    ncpus = VIR_NODEINFO_MAXCPUS(nodeinfo);


    id = 0;
    for (n = 0; n < nodeinfo.nodes; n++) {
        int nodecpus = nodeinfo.sockets * nodeinfo.cores * nodeinfo.threads;
        cid = 0;

        cpus = g_new0(virCapsHostNUMACellCPU, nodecpus);

        for (s = 0; s < nodeinfo.sockets; s++) {
            for (c = 0; c < nodeinfo.cores; c++) {
                g_autoptr(virBitmap) siblings = virBitmapNew(ncpus);
                for (t = 0; t < nodeinfo.threads; t++)
                    ignore_value(virBitmapSetBit(siblings, id + t));

                for (t = 0; t < nodeinfo.threads; t++) {
                    if (virHostCPUGetOnline(id, &tmp) < 0)
                        goto error;
                    if (tmp) {
                        cpus[cid].id = id;
                        cpus[cid].die_id = 0;
                        cpus[cid].socket_id = s;
                        cpus[cid].core_id = c;
                        cpus[cid].siblings = virBitmapNewCopy(siblings);
                        cid++;
                    }

                    id++;
                }
            }
        }

        virCapabilitiesHostNUMAAddCell(caps, 0,
                                       nodeinfo.memory,
                                       cid, &cpus,
                                       0, NULL,
                                       0, NULL,
                                       NULL);
    }

    return 0;

 error:
    for (; cid >= 0; cid--)
        virBitmapFree(cpus[cid].siblings);
    VIR_FREE(cpus);
    return -1;
}


static void
virCapabilitiesHostInsertHMAT(GArray *interconnects,
                              unsigned int initiator,
                              unsigned int target,
                              unsigned int read_bandwidth,
                              unsigned int write_bandwidth,
                              unsigned int read_latency,
                              unsigned int write_latency)
{
    virNumaInterconnect ni;

    ni = (virNumaInterconnect) { VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH,
        initiator, target, 0, VIR_MEMORY_LATENCY_READ, read_bandwidth};
    g_array_append_val(interconnects, ni);

    ni = (virNumaInterconnect) { VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH,
        initiator, target, 0, VIR_MEMORY_LATENCY_WRITE, write_bandwidth};
    g_array_append_val(interconnects, ni);

    ni = (virNumaInterconnect) { VIR_NUMA_INTERCONNECT_TYPE_LATENCY,
        initiator, target, 0, VIR_MEMORY_LATENCY_READ, read_latency};
    g_array_append_val(interconnects, ni);

    ni = (virNumaInterconnect) { VIR_NUMA_INTERCONNECT_TYPE_LATENCY,
        initiator, target, 0, VIR_MEMORY_LATENCY_WRITE, write_latency};
    g_array_append_val(interconnects, ni);
}


static int
virCapabilitiesHostNUMAInitInterconnectsNode(GArray *interconnects,
                                             unsigned int node)
{
    g_autofree char *path = NULL;
    g_autofree char *initPath = NULL;
    g_autoptr(DIR) dir = NULL;
    int direrr = 0;
    struct dirent *entry;
    unsigned int read_bandwidth;
    unsigned int write_bandwidth;
    unsigned int read_latency;
    unsigned int write_latency;

    /* Unfortunately, kernel does not expose full HMAT table. I mean it does,
     * in its binary form under /sys/firmware/acpi/tables/HMAT but we don't
     * want to parse that. But some important info is still exposed, under
     * "access0" and "access1" directories. The former contains the best
     * interconnect to given node including CPUs and devices that might do I/O
     * (such as GPUs and NICs). The latter contains the best interconnect to
     * given node but only CPUs are considered. Stick with access1 until sysfs
     * exposes the full table in a sensible way.
     * NB on most system access0 and access1 contain the same values. */
    path = g_strdup_printf(SYSFS_SYSTEM_PATH "/node/node%d/access1", node);

    if (!virFileExists(path))
        return 0;

    if (virCapabilitiesGetNodeCacheReadFileUint(path, "initiators",
                                                "read_bandwidth",
                                                &read_bandwidth) < 0)
        return -1;
    if (virCapabilitiesGetNodeCacheReadFileUint(path, "initiators",
                                                "write_bandwidth",
                                                &write_bandwidth) < 0)
        return -1;

    /* Bandwidths are read in MiB but stored in KiB */
    read_bandwidth <<= 10;
    write_bandwidth <<= 10;

    if (virCapabilitiesGetNodeCacheReadFileUint(path, "initiators",
                                                "read_latency",
                                                &read_latency) < 0)
        return -1;
    if (virCapabilitiesGetNodeCacheReadFileUint(path, "initiators",
                                                "write_latency",
                                                &write_latency) < 0)
        return -1;

    initPath = g_strdup_printf("%s/initiators", path);

    if (virDirOpen(&dir, initPath) < 0)
        return -1;

    while ((direrr = virDirRead(dir, &entry, path)) > 0) {
        const char *dname = STRSKIP(entry->d_name, "node");
        unsigned int initNode;

        if (!dname)
            continue;

        if (virStrToLong_ui(dname, NULL, 10, &initNode) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse %1$s"),
                           entry->d_name);
            return -1;
        }

        virCapabilitiesHostInsertHMAT(interconnects,
                                      initNode, node,
                                      read_bandwidth,
                                      write_bandwidth,
                                      read_latency,
                                      write_latency);
    }

    return 0;
}


static int
virCapsHostNUMAInterconnectComparator(const void *a,
                                      const void *b)
{
    const virNumaInterconnect *aa = a;
    const virNumaInterconnect *bb = b;

    if (aa->type != bb->type)
        return aa->type - bb->type;

    if (aa->initiator != bb->initiator)
        return aa->initiator - bb->initiator;

    if (aa->target != bb->target)
        return aa->target - bb->target;

    if (aa->cache != bb->cache)
        return aa->cache - bb->cache;

    if (aa->accessType != bb->accessType)
        return aa->accessType - bb->accessType;

    return aa->value - bb->value;
}


static int
virCapabilitiesHostNUMAInitInterconnects(virCapsHostNUMA *caps)
{
    g_autoptr(DIR) dir = NULL;
    int direrr = 0;
    struct dirent *entry;
    const char *path = SYSFS_SYSTEM_PATH "/node/";
    g_autoptr(GArray) interconnects = g_array_new(FALSE, FALSE, sizeof(virNumaInterconnect));

    if (virDirOpenIfExists(&dir, path) < 0)
        return -1;

    while (dir && (direrr = virDirRead(dir, &entry, path)) > 0) {
        const char *dname = STRSKIP(entry->d_name, "node");
        unsigned int node;

        if (!dname)
            continue;

        if (virStrToLong_ui(dname, NULL, 10, &node) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse %1$s"),
                           entry->d_name);
            return -1;
        }

        if (virCapabilitiesHostNUMAInitInterconnectsNode(interconnects, node) < 0)
            return -1;
    }

    if (interconnects->len > 0) {
        g_array_sort(interconnects, virCapsHostNUMAInterconnectComparator);
        caps->interconnects = g_steal_pointer(&interconnects);
    }

    return 0;
}


static int
virCapabilitiesHostNUMAInitReal(virCapsHostNUMA *caps)
{
    int n;
    virCapsHostNUMACellCPU *cpus = NULL;
    int ret = -1;
    int ncpus = 0;
    int max_node;

    if ((max_node = virNumaGetMaxNode()) < 0)
        goto cleanup;

    for (n = 0; n <= max_node; n++) {
        g_autoptr(virBitmap) cpumap = NULL;
        g_autofree virNumaDistance *distances = NULL;
        int ndistances = 0;
        g_autofree virCapsHostNUMACellPageInfo *pageinfo = NULL;
        int npageinfo = 0;
        unsigned long long memory;
        g_autoptr(GArray) caches = NULL;
        int cpu;
        size_t i;

        if ((ncpus = virNumaGetNodeCPUs(n, &cpumap)) < 0) {
            if (ncpus == -2)
                continue;

            ncpus = 0;
            goto cleanup;
        }

        cpus = g_new0(virCapsHostNUMACellCPU, ncpus);
        cpu = 0;

        for (i = 0; i < virBitmapSize(cpumap); i++) {
            if (virBitmapIsBitSet(cpumap, i)) {
                if (virCapabilitiesFillCPUInfo(i, cpus + cpu++) < 0)
                    goto cleanup;
            }
        }

        if (virCapabilitiesGetNUMADistances(n, &distances, &ndistances) < 0)
            goto cleanup;

        if (virCapabilitiesGetNUMAPagesInfo(n, &pageinfo, &npageinfo) < 0)
            goto cleanup;

        if (virCapabilitiesGetNodeCache(n, &caches) < 0)
            goto cleanup;

        /* Detect the amount of memory in the numa cell in KiB */
        virNumaGetNodeMemory(n, &memory, NULL);
        memory >>= 10;

        virCapabilitiesHostNUMAAddCell(caps, n, memory,
                                       ncpus, &cpus,
                                       ndistances, &distances,
                                       npageinfo, &pageinfo,
                                       &caches);
    }

    if (virCapabilitiesHostNUMAInitInterconnects(caps) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCapabilitiesClearHostNUMACellCPUTopology(cpus, ncpus);
    VIR_FREE(cpus);
    return ret;
}


virCapsHostNUMA *
virCapabilitiesHostNUMANew(void)
{
    virCapsHostNUMA *caps = NULL;

    caps = g_new0(virCapsHostNUMA, 1);
    caps->refs = 1;
    caps->cells = g_ptr_array_new_with_free_func(
        (GDestroyNotify)virCapabilitiesFreeHostNUMACell);

    return caps;
}


virCapsHostNUMA *
virCapabilitiesHostNUMANewHost(void)
{
    virCapsHostNUMA *caps = virCapabilitiesHostNUMANew();

    if (virNumaIsAvailable()) {
        if (virCapabilitiesHostNUMAInitReal(caps) == 0)
            return caps;

        virCapabilitiesHostNUMAUnref(caps);
        caps = virCapabilitiesHostNUMANew();
        VIR_WARN("Failed to query host NUMA topology, faking single NUMA node");
    }

    if (virCapabilitiesHostNUMAInitFake(caps) < 0) {
        virCapabilitiesHostNUMAUnref(caps);
        return NULL;
    }

    return caps;
}


int
virCapabilitiesInitPages(virCaps *caps)
{
    g_autofree unsigned int *pages_size = NULL;
    size_t npages;

    if (virNumaGetPages(-1 /* Magic constant for overall info */,
                        &pages_size, NULL, NULL, &npages) < 0)
        return -1;

    caps->host.pagesSize = g_steal_pointer(&pages_size);
    caps->host.nPagesSize = npages;
    npages = 0;

    return 0;
}


bool
virCapsHostCacheBankEquals(virCapsHostCacheBank *a,
                           virCapsHostCacheBank *b)
{
    return (a->id == b->id &&
            a->level == b->level &&
            a->type == b->type &&
            a->size == b->size &&
            virBitmapEqual(a->cpus, b->cpus));
}

void
virCapsHostCacheBankFree(virCapsHostCacheBank *ptr)
{
    size_t i;

    if (!ptr)
        return;

    virBitmapFree(ptr->cpus);
    for (i = 0; i < ptr->ncontrols; i++)
        g_free(ptr->controls[i]);
    g_free(ptr->controls);
    g_free(ptr);
}


static int
virCapsHostCacheBankSorter(const void *a,
                           const void *b)
{
    virCapsHostCacheBank *ca = *(virCapsHostCacheBank **)a;
    virCapsHostCacheBank *cb = *(virCapsHostCacheBank **)b;

    if (ca->level < cb->level)
        return -1;
    if (ca->level > cb->level)
        return 1;

    return ca->id - cb->id;
}


static int
virCapabilitiesInitResctrl(virCaps *caps)
{
    if (caps->host.resctrl)
        return 0;

    caps->host.resctrl = virResctrlInfoNew();
    if (!caps->host.resctrl)
        return -1;

    return 0;
}


static int
virCapabilitiesInitResctrlMemory(virCaps *caps)
{
    virCapsHostMemBWNode *node = NULL;
    size_t i = 0;
    int ret = -1;
    const virResctrlMonitorType montype = VIR_RESCTRL_MONITOR_TYPE_MEMBW;
    const char *prefix = virResctrlMonitorPrefixTypeToString(montype);

    for (i = 0; i < caps->host.cache.nbanks; i++) {
        virCapsHostCacheBank *bank = caps->host.cache.banks[i];
        node = g_new0(virCapsHostMemBWNode, 1);

        if (virResctrlInfoGetMemoryBandwidth(caps->host.resctrl,
                                             bank->level, &node->control) > 0) {
            node->id = bank->id;
            node->cpus = virBitmapNewCopy(bank->cpus);

            VIR_APPEND_ELEMENT(caps->host.memBW.nodes, caps->host.memBW.nnodes, node);
        }
        g_clear_pointer(&node, virCapsHostMemBWNodeFree);
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
virCapabilitiesInitCaches(virCaps *caps)
{
    size_t i = 0;
    g_autoptr(virBitmap) cpus = NULL;
    ssize_t pos = -1;
    struct dirent *ent = NULL;
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
        g_autoptr(DIR) dirp = NULL;
        g_autofree char *path = g_strdup_printf("%s/cpu/cpu%zd/cache/", SYSFS_SYSTEM_PATH, pos);

        rv = virDirOpenIfExists(&dirp, path);
        if (rv < 0)
            return -1;

        if (!dirp)
            continue;

        while ((rv = virDirRead(dirp, &ent, path)) > 0) {
            g_autofree char *type = NULL;
            g_autoptr(virCapsHostCacheBank) bank = NULL;
            int kernel_type;
            unsigned int level;
            int ret;

            if (!STRPREFIX(ent->d_name, "index"))
                continue;

            if (virFileReadValueUint(&level,
                                     "%s/cpu/cpu%zd/cache/%s/level",
                                     SYSFS_SYSTEM_PATH, pos, ent->d_name) < 0)
                return -1;

            if (level < cache_min_level)
                continue;

            bank = g_new0(virCapsHostCacheBank, 1);
            bank->level = level;

            ret = virFileReadValueUint(&bank->id,
                                       "%s/cpu/cpu%zd/cache/%s/id",
                                       SYSFS_SYSTEM_PATH, pos, ent->d_name);
            if (ret == -2) {
                VIR_DEBUG("CPU %zd cache %s 'id' missing", pos, ent->d_name);
                continue;
            }
            if (ret < 0)
                return -1;

            ret = virFileReadValueUint(&bank->level,
                                       "%s/cpu/cpu%zd/cache/%s/level",
                                       SYSFS_SYSTEM_PATH, pos, ent->d_name);
            if (ret == -2) {
                VIR_DEBUG("CPU %zd cache %s 'level' missing", pos, ent->d_name);
                continue;
            }
            if (ret < 0)
                return -1;

            ret = virFileReadValueString(&type,
                                         "%s/cpu/cpu%zd/cache/%s/type",
                                         SYSFS_SYSTEM_PATH, pos, ent->d_name);
            if (ret == -2) {
                VIR_DEBUG("CPU %zd cache %s 'type' missing", pos, ent->d_name);
                continue;
            }
            if (ret < 0)
                return -1;

            ret = virFileReadValueScaledInt(&bank->size,
                                            "%s/cpu/cpu%zd/cache/%s/size",
                                            SYSFS_SYSTEM_PATH, pos, ent->d_name);
            if (ret == -2) {
                VIR_DEBUG("CPU %zd cache %s 'size' missing", pos, ent->d_name);
                continue;
            }
            if (ret < 0)
                return -1;

            ret = virFileReadValueBitmap(&bank->cpus,
                                         "%s/cpu/cpu%zd/cache/%s/shared_cpu_list",
                                         SYSFS_SYSTEM_PATH, pos, ent->d_name);
            if (ret == -2) {
                VIR_DEBUG("CPU %zd cache %s 'shared_cpu_list' missing", pos, ent->d_name);
                continue;
            }
            if (ret < 0)
                return -1;

            kernel_type = virCacheKernelTypeFromString(type);
            if (kernel_type < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown cache type '%1$s'"), type);
                return -1;
            }

            bank->type = kernel_type;

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
                    return -1;

                VIR_APPEND_ELEMENT(caps->host.cache.banks, caps->host.cache.nbanks, bank);
            }
        }
        if (rv < 0)
            return -1;
    }

    /* Sort the array in order for the tests to be predictable.  This way we can
     * still traverse the directory instead of guessing names (in case there is
     * 'index1' and 'index3' but no 'index2'). */
    if (caps->host.cache.banks) {
        qsort(caps->host.cache.banks, caps->host.cache.nbanks,
              sizeof(*caps->host.cache.banks), virCapsHostCacheBankSorter);
    }

    if (virCapabilitiesInitResctrlMemory(caps) < 0)
        return -1;

    if (virResctrlInfoGetMonitorPrefix(caps->host.resctrl, prefix,
                                       &caps->host.cache.monitor) < 0)
        return -1;

    return 0;
}


void
virCapabilitiesHostInitIOMMU(virCaps *caps)
{
    caps->host.iommu = virHostHasIOMMU();
}
