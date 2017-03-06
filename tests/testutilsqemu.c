#include <config.h>
#ifdef WITH_QEMU
# include <stdlib.h>

# include "testutilsqemu.h"
# include "testutils.h"
# include "viralloc.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"
# include "qemu/qemu_domain.h"
# define __QEMU_CAPSRIV_H_ALLOW__
# include "qemu/qemu_capspriv.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

virCPUDefPtr cpuDefault;
virCPUDefPtr cpuHaswell;
virCPUDefPtr cpuPower8;

static virCPUFeatureDef cpuDefaultFeatures[] = {
    { (char *) "ds",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ss",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "tm",        -1 },
    { (char *) "pbe",       -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "vmx",       -1 },
    { (char *) "est",       -1 },
    { (char *) "tm2",       -1 },
    { (char *) "cx16",      -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "lahf_lm",   -1 },
};
static virCPUDef cpuDefaultData = {
    VIR_CPU_TYPE_HOST,      /* type */
    0,                      /* mode */
    0,                      /* match */
    VIR_ARCH_X86_64,        /* arch */
    (char *) "core2duo",    /* model */
    NULL,                   /* vendor_id */
    0,                      /* fallback */
    (char *) "Intel",       /* vendor */
    1,                      /* sockets */
    2,                      /* cores */
    1,                      /* threads */
    ARRAY_CARDINALITY(cpuDefaultFeatures), /* nfeatures */
    ARRAY_CARDINALITY(cpuDefaultFeatures), /* nfeatures_max */
    cpuDefaultFeatures,     /* features */
};

static virCPUFeatureDef cpuHaswellFeatures[] = {
    { (char *) "vme",       -1 },
    { (char *) "ds",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ss",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "tm",        -1 },
    { (char *) "pbe",       -1 },
    { (char *) "dtes64",    -1 },
    { (char *) "monitor",   -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "vmx",       -1 },
    { (char *) "smx",       -1 },
    { (char *) "est",       -1 },
    { (char *) "tm2",       -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "pdcm",      -1 },
    { (char *) "osxsave",   -1 },
    { (char *) "f16c",      -1 },
    { (char *) "rdrand",    -1 },
    { (char *) "cmt",       -1 },
    { (char *) "pdpe1gb",   -1 },
    { (char *) "abm",       -1 },
    { (char *) "invtsc",    -1 },
    { (char *) "lahf_lm",   -1 },
};
static virCPUDef cpuHaswellData = {
    VIR_CPU_TYPE_HOST,      /* type */
    0,                      /* mode */
    0,                      /* match */
    VIR_ARCH_X86_64,        /* arch */
    (char *) "Haswell",     /* model */
    NULL,                   /* vendor_id */
    0,                      /* fallback */
    (char *) "Intel",       /* vendor */
    1,                      /* sockets */
    2,                      /* cores */
    2,                      /* threads */
    ARRAY_CARDINALITY(cpuHaswellFeatures), /* nfeatures */
    ARRAY_CARDINALITY(cpuHaswellFeatures), /* nfeatures_max */
    cpuHaswellFeatures,     /* features */
};

static virCPUDef cpuPower8Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC64,
    .model = (char *) "POWER8",
    .sockets = 1,
    .cores = 8,
    .threads = 8,
};

static virCapsGuestMachinePtr *testQemuAllocMachines(int *nmachines)
{
    virCapsGuestMachinePtr *machines;
    static const char *const x86_machines[] = {
        "pc", "isapc"
    };

    machines = virCapabilitiesAllocMachines(x86_machines,
                                            ARRAY_CARDINALITY(x86_machines));
    if (machines == NULL)
        return NULL;

    *nmachines = ARRAY_CARDINALITY(x86_machines);

    return machines;
}

/* Newer versions of qemu have versioned machine types to allow
 * compatibility with older releases.
 * The 'pc' machine type is an alias of the newest machine type.
 */
static virCapsGuestMachinePtr *testQemuAllocNewerMachines(int *nmachines)
{
    virCapsGuestMachinePtr *machines;
    char *canonical;
    static const char *const x86_machines[] = {
        "pc-0.11", "pc", "pc-0.10", "isapc"
    };

    if (VIR_STRDUP(canonical, x86_machines[0]) < 0)
        return NULL;

    machines = virCapabilitiesAllocMachines(x86_machines,
                                            ARRAY_CARDINALITY(x86_machines));
    if (machines == NULL) {
        VIR_FREE(canonical);
        return NULL;
    }

    machines[1]->canonical = canonical;

    *nmachines = ARRAY_CARDINALITY(x86_machines);

    return machines;
}


static int testQemuAddPPC64Guest(virCapsPtr caps)
{
    static const char *machine[] = { "pseries" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64,
                                    "/usr/bin/qemu-system-ppc64", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

static int testQemuAddPPC64LEGuest(virCapsPtr caps)
{
    static const char *machine[] = { "pseries" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64LE,
                                    "/usr/bin/qemu-system-ppc64", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

static int testQemuAddPPCGuest(virCapsPtr caps)
{
    static const char *machine[] = { "g3beige",
                                     "mac99",
                                     "prep",
                                     "ppce500" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC,
                                    "/usr/bin/qemu-system-ppc", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

static int testQemuAddS390Guest(virCapsPtr caps)
{
    static const char *s390_machines[] = { "s390-virtio",
                                           "s390-ccw-virtio" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(s390_machines,
                                            ARRAY_CARDINALITY(s390_machines));
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_S390X,
                                    "/usr/bin/qemu-system-s390x", NULL,
                                    ARRAY_CARDINALITY(s390_machines),
                                    machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, ARRAY_CARDINALITY(s390_machines));
    return -1;
}

static int testQemuAddArmGuest(virCapsPtr caps)
{
    static const char *machines[] = { "vexpress-a9",
                                      "vexpress-a15",
                                      "versatilepb" };
    virCapsGuestMachinePtr *capsmachines = NULL;
    virCapsGuestPtr guest;

    capsmachines = virCapabilitiesAllocMachines(machines,
                                                ARRAY_CARDINALITY(machines));
    if (!capsmachines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_ARMV7L,
                                    "/usr/bin/qemu-system-arm", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

static int testQemuAddAARCH64Guest(virCapsPtr caps)
{
    static const char *machines[] = { "virt"};
    virCapsGuestMachinePtr *capsmachines = NULL;
    virCapsGuestPtr guest;

    capsmachines = virCapabilitiesAllocMachines(machines,
                                                ARRAY_CARDINALITY(machines));
    if (!capsmachines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_AARCH64,
                                    "/usr/bin/qemu-system-aarch64", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

virCapsPtr testQemuCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines = NULL;
    int nmachines = 0;

    if (!(caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)))
        return NULL;

    /* Add dummy 'none' security_driver. This is equal to setting
     * security_driver = "none" in qemu.conf. */
    if (VIR_ALLOC_N(caps->host.secModels, 1) < 0)
        goto cleanup;
    caps->host.nsecModels = 1;

    if (VIR_STRDUP(caps->host.secModels[0].model, "none") < 0 ||
        VIR_STRDUP(caps->host.secModels[0].doi, "0") < 0)
        goto cleanup;

    if (!(cpuDefault = virCPUDefCopy(&cpuDefaultData)) ||
        !(cpuHaswell = virCPUDefCopy(&cpuHaswellData)) ||
        !(cpuPower8 = virCPUDefCopy(&cpuPower8Data)))
        goto cleanup;

    qemuTestSetHostCPU(caps, NULL);

    caps->host.nnumaCell_max = 4;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                         "/usr/bin/qemu", NULL,
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/qemu-kvm",
                                      NULL,
                                      nmachines,
                                      machines) == NULL)
        goto cleanup;
    machines = NULL;

    if ((machines = testQemuAllocNewerMachines(&nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                         "/usr/bin/qemu-system-x86_64", NULL,
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/kvm",
                                      NULL,
                                      nmachines,
                                      machines) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (testQemuAddPPC64Guest(caps))
        goto cleanup;

    if (testQemuAddPPC64LEGuest(caps))
        goto cleanup;

    if (testQemuAddPPCGuest(caps))
        goto cleanup;

    if (testQemuAddS390Guest(caps))
        goto cleanup;

    if (testQemuAddArmGuest(caps))
        goto cleanup;

    if (testQemuAddAARCH64Guest(caps))
        goto cleanup;

    if (virTestGetDebug()) {
        char *caps_str;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto cleanup;

        VIR_TEST_DEBUG("QEMU driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

 cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    caps->host.cpu = NULL;
    virCPUDefFree(cpuDefault);
    virCPUDefFree(cpuHaswell);
    virCPUDefFree(cpuPower8);
    virObjectUnref(caps);
    return NULL;
}


void
qemuTestSetHostArch(virCapsPtr caps,
                    virArch arch)
{
    if (arch == VIR_ARCH_NONE)
        arch = VIR_ARCH_X86_64;
    caps->host.arch = arch;
    qemuTestSetHostCPU(caps, NULL);
}


void
qemuTestSetHostCPU(virCapsPtr caps,
                   virCPUDefPtr cpu)
{
    virArch arch = caps->host.arch;

    if (!cpu) {
        if (ARCH_IS_X86(arch))
            cpu = cpuDefault;
        else if (ARCH_IS_PPC64(arch))
            cpu = cpuPower8;
    }

    if (cpu)
        caps->host.arch = cpu->arch;
    caps->host.cpu = cpu;
}


virQEMUCapsPtr
qemuTestParseCapabilities(virCapsPtr caps,
                          const char *capsFile)
{
    virQEMUCapsPtr qemuCaps = NULL;
    time_t selfctime;
    unsigned long version;

    if (!(qemuCaps = virQEMUCapsNew()) ||
        virQEMUCapsLoadCache(caps, qemuCaps, capsFile,
                             &selfctime, &version) < 0)
        goto error;

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}

void qemuTestDriverFree(virQEMUDriver *driver)
{
    virMutexDestroy(&driver->lock);
    if (driver->config) {
        virFileDeleteTree(driver->config->stateDir);
        virFileDeleteTree(driver->config->configDir);
    }
    virQEMUCapsCacheFree(driver->qemuCapsCache);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->config);
    virObjectUnref(driver->securityManager);
}

int qemuTestCapsCacheInsert(virQEMUCapsCachePtr cache, const char *binary,
                            virQEMUCapsPtr caps)
{
    int ret;

    if (caps) {
        /* Our caps were created artificially, so we don't want
         * virQEMUCapsCacheFree() to attempt to deallocate them */
        virObjectRef(caps);
    } else {
        caps = virQEMUCapsNew();
        if (!caps)
            return -ENOMEM;
    }

    /* We can have repeating names for our test data sets,
     * so make sure there's no old copy */
    virHashRemoveEntry(cache->binaries, binary);

    ret = virHashAddEntry(cache->binaries, binary, caps);
    if (ret < 0)
        virObjectUnref(caps);
    else
        qemuTestCapsName = binary;

    return ret;
}

# define STATEDIRTEMPLATE abs_builddir "/qemustatedir-XXXXXX"
# define CONFIGDIRTEMPLATE abs_builddir "/qemuconfigdir-XXXXXX"

int qemuTestDriverInit(virQEMUDriver *driver)
{
    virSecurityManagerPtr mgr = NULL;
    char statedir[] = STATEDIRTEMPLATE;
    char configdir[] = CONFIGDIRTEMPLATE;

    memset(driver, 0, sizeof(*driver));

    if (virMutexInit(&driver->lock) < 0)
        return -1;

    driver->config = virQEMUDriverConfigNew(false);
    if (!driver->config)
        goto error;

    /* Do this early so that qemuTestDriverFree() doesn't see (unlink) the real
     * dirs. */
    VIR_FREE(driver->config->stateDir);
    VIR_FREE(driver->config->configDir);

    /* Overwrite some default paths so it's consistent for tests. */
    VIR_FREE(driver->config->libDir);
    VIR_FREE(driver->config->channelTargetDir);
    if (VIR_STRDUP(driver->config->libDir, "/tmp/lib") < 0 ||
        VIR_STRDUP(driver->config->channelTargetDir, "/tmp/channel") < 0)
        goto error;

    if (!mkdtemp(statedir)) {
        virFilePrintf(stderr, "Cannot create fake stateDir");
        goto error;
    }

    if (VIR_STRDUP(driver->config->stateDir, statedir) < 0) {
        rmdir(statedir);
        goto error;
    }

    if (!mkdtemp(configdir)) {
        virFilePrintf(stderr, "Cannot create fake configDir");
        goto error;
    }

    if (VIR_STRDUP(driver->config->configDir, configdir) < 0) {
        rmdir(configdir);
        goto error;
    }

    driver->caps = testQemuCapsInit();
    if (!driver->caps)
        goto error;

    /* Using /dev/null for libDir and cacheDir automatically produces errors
     * upon attempt to use any of them */
    driver->qemuCapsCache = virQEMUCapsCacheNew("/dev/null", "/dev/null", 0, 0);
    if (!driver->qemuCapsCache)
        goto error;

    driver->xmlopt = virQEMUDriverCreateXMLConf(driver);
    if (!driver->xmlopt)
        goto error;

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, "empty", NULL) < 0)
        goto error;

    if (!(mgr = virSecurityManagerNew("none", "qemu",
                                      VIR_SECURITY_MANAGER_PRIVILEGED)))
        goto error;
    if (!(driver->securityManager = virSecurityManagerNewStack(mgr)))
        goto error;

    return 0;

 error:
    virObjectUnref(mgr);
    qemuTestDriverFree(driver);
    return -1;
}

int
testQemuCapsSetGIC(virQEMUCapsPtr qemuCaps,
                   int gic)
{
    virGICCapability *gicCapabilities = NULL;
    size_t ngicCapabilities = 0;
    int ret = -1;

    if (VIR_ALLOC_N(gicCapabilities, 2) < 0)
        goto out;

# define IMPL_BOTH \
         VIR_GIC_IMPLEMENTATION_KERNEL|VIR_GIC_IMPLEMENTATION_EMULATED

    if (gic & GIC_V2) {
        gicCapabilities[ngicCapabilities].version = VIR_GIC_VERSION_2;
        gicCapabilities[ngicCapabilities].implementation = IMPL_BOTH;
        ngicCapabilities++;
    }
    if (gic & GIC_V3) {
        gicCapabilities[ngicCapabilities].version = VIR_GIC_VERSION_3;
        gicCapabilities[ngicCapabilities].implementation = IMPL_BOTH;
        ngicCapabilities++;
    }

# undef IMPL_BOTH

    virQEMUCapsSetGICCapabilities(qemuCaps,
                                  gicCapabilities, ngicCapabilities);

    ret = 0;

 out:
    return ret;
}

#endif
