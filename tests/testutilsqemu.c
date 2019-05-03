#include <config.h>
#ifdef WITH_QEMU

# include "testutilsqemu.h"
# include "testutilshostcpus.h"
# include "testutils.h"
# include "viralloc.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"
# include "qemu/qemu_domain.h"
# define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
# include "qemu/qemu_capspriv.h"
# include "virstring.h"
# include "virfilecache.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

virCPUDefPtr cpuDefault;
virCPUDefPtr cpuHaswell;
virCPUDefPtr cpuPower8;
virCPUDefPtr cpuPower9;

typedef enum {
    TEST_UTILS_QEMU_BIN_I686,
    TEST_UTILS_QEMU_BIN_X86_64,
    TEST_UTILS_QEMU_BIN_AARCH64,
    TEST_UTILS_QEMU_BIN_ARM,
    TEST_UTILS_QEMU_BIN_PPC64,
    TEST_UTILS_QEMU_BIN_PPC,
    TEST_UTILS_QEMU_BIN_RISCV32,
    TEST_UTILS_QEMU_BIN_RISCV64,
    TEST_UTILS_QEMU_BIN_S390X
} QEMUBinType;

static const char *QEMUBinList[] = {
    "/usr/bin/qemu-system-i686",
    "/usr/bin/qemu-system-x86_64",
    "/usr/bin/qemu-system-aarch64",
    "/usr/bin/qemu-system-arm",
    "/usr/bin/qemu-system-ppc64",
    "/usr/bin/qemu-system-ppc",
    "/usr/bin/qemu-system-riscv32",
    "/usr/bin/qemu-system-riscv64",
    "/usr/bin/qemu-system-s390x"
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


static int
testQemuAddI686Guest(virCapsPtr caps)
{
    int nmachines = 0;
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    if (!(machines = testQemuAllocMachines(&nmachines)))
        goto error;

    if (!(guest = virCapabilitiesAddGuest(caps,
                                          VIR_DOMAIN_OSTYPE_HVM,
                                          VIR_ARCH_I686,
                                          QEMUBinList[TEST_UTILS_QEMU_BIN_I686],
                                          NULL,
                                          nmachines,
                                          machines)))
        goto error;

    if (!virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto error;

    machines = NULL;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_QEMU,
                                       NULL,
                                       NULL,
                                       0,
                                       NULL))
        goto error;

    if (!(machines = testQemuAllocMachines(&nmachines)))
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_KVM,
                                       QEMUBinList[TEST_UTILS_QEMU_BIN_I686],
                                       NULL,
                                       nmachines,
                                       machines))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
    return -1;
}


static int
testQemuAddX86_64Guest(virCapsPtr caps)
{
    int nmachines = 0;
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    if (!(machines = testQemuAllocNewerMachines(&nmachines)))
        goto error;

    if (!(guest = virCapabilitiesAddGuest(caps,
                                          VIR_DOMAIN_OSTYPE_HVM,
                                          VIR_ARCH_X86_64,
                                          QEMUBinList[TEST_UTILS_QEMU_BIN_X86_64],
                                          NULL,
                                          nmachines,
                                          machines)))
        goto error;

    if (!virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto error;

    machines = NULL;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_QEMU,
                                       NULL,
                                       NULL,
                                       0,
                                       NULL))
        goto error;

    if (!(machines = testQemuAllocMachines(&nmachines)))
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_KVM,
                                       QEMUBinList[TEST_UTILS_QEMU_BIN_X86_64],
                                       NULL,
                                       nmachines,
                                       machines))
        goto error;

    machines = NULL;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_KVM,
                                       QEMUBinList[TEST_UTILS_QEMU_BIN_X86_64],
                                       NULL,
                                       0,
                                       NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
    return -1;
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_PPC64],
                                    NULL, 1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_PPC64],
                                    NULL, 1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_PPC],
                                    NULL, 1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

static int testQemuAddRISCV32Guest(virCapsPtr caps)
{
    static const char *names[] = { "spike_v1.10",
                                   "spike_v1.9.1",
                                   "sifive_e",
                                   "virt",
                                   "sifive_u" };
    static const int nmachines = ARRAY_CARDINALITY(names);
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(names, nmachines);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_RISCV32,
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_RISCV32],
                                    NULL, nmachines, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
    return -1;
}

static int testQemuAddRISCV64Guest(virCapsPtr caps)
{
    static const char *names[] = { "spike_v1.10",
                                   "spike_v1.9.1",
                                   "sifive_e",
                                   "virt",
                                   "sifive_u" };
    static const int nmachines = ARRAY_CARDINALITY(names);
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(names, nmachines);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_RISCV64,
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_RISCV64],
                                    NULL, nmachines, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_S390X],
                                    NULL,
                                    ARRAY_CARDINALITY(s390_machines),
                                    machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, ARRAY_CARDINALITY(s390_machines));
    return -1;
}

static int testQemuAddArm6Guest(virCapsPtr caps)
{
    static const char *machines[] = { "versatilepb" };
    virCapsGuestMachinePtr *capsmachines = NULL;
    virCapsGuestPtr guest;

    capsmachines = virCapabilitiesAllocMachines(machines,
                                                ARRAY_CARDINALITY(machines));
    if (!capsmachines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_ARMV6L,
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_ARM],
                                    NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

static int testQemuAddArm7Guest(virCapsPtr caps)
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_ARM],
                                    NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
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
                                    QEMUBinList[TEST_UTILS_QEMU_BIN_AARCH64],
                                    NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;
    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                       NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

virCapsPtr testQemuCapsInit(void)
{
    virCapsPtr caps;

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
        !(cpuPower8 = virCPUDefCopy(&cpuPower8Data)) ||
        !(cpuPower9 = virCPUDefCopy(&cpuPower9Data)))
        goto cleanup;

    qemuTestSetHostCPU(caps, NULL);

    /*
     * Build a NUMA topology with cell_id (NUMA node id
     * being 3(0 + 3),4(1 + 3), 5 and 6
     */
    if (virTestCapsBuildNUMATopology(caps, 3) < 0)
        goto cleanup;

    if (testQemuAddI686Guest(caps) < 0)
        goto cleanup;

    if (testQemuAddX86_64Guest(caps) < 0)
        goto cleanup;

    if (testQemuAddPPC64Guest(caps))
        goto cleanup;

    if (testQemuAddPPC64LEGuest(caps))
        goto cleanup;

    if (testQemuAddPPCGuest(caps))
        goto cleanup;

    if (testQemuAddRISCV32Guest(caps) < 0)
        goto cleanup;

    if (testQemuAddRISCV64Guest(caps) < 0)
        goto cleanup;

    if (testQemuAddS390Guest(caps))
        goto cleanup;

    if (testQemuAddArm6Guest(caps))
        goto cleanup;

    if (testQemuAddArm7Guest(caps))
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

    unsetenv("VIR_TEST_MOCK_FAKE_HOST_CPU");
    if (cpu) {
        caps->host.arch = cpu->arch;
        if (cpu->model)
            setenv("VIR_TEST_MOCK_FAKE_HOST_CPU", cpu->model, 1);
    }
    caps->host.cpu = cpu;
}


virQEMUCapsPtr
qemuTestParseCapabilitiesArch(virArch arch,
                              const char *capsFile)
{
    virQEMUCapsPtr qemuCaps = NULL;

    if (!(qemuCaps = virQEMUCapsNew()) ||
        virQEMUCapsLoadCache(arch, qemuCaps, capsFile) < 0)
        goto error;

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}


virQEMUCapsPtr
qemuTestParseCapabilities(virCapsPtr caps,
                          const char *capsFile)
{
    if (!caps)
        return NULL;

    return qemuTestParseCapabilitiesArch(caps->host.arch, capsFile);
}


void qemuTestDriverFree(virQEMUDriver *driver)
{
    virMutexDestroy(&driver->lock);
    if (driver->config) {
        virFileDeleteTree(driver->config->stateDir);
        virFileDeleteTree(driver->config->configDir);
    }
    virObjectUnref(driver->qemuCapsCache);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->config);
    virObjectUnref(driver->securityManager);
}

int qemuTestCapsCacheInsert(virFileCachePtr cache,
                            virQEMUCapsPtr caps)
{
    size_t i;
    virQEMUCapsPtr tmpCaps;

    if (caps) {
        tmpCaps = caps;
    } else {
        if (!(tmpCaps = virQEMUCapsNew()))
            return -ENOMEM;
    }

    for (i = 0; i < ARRAY_CARDINALITY(QEMUBinList); i++) {
        virObjectRef(tmpCaps);
        if (virFileCacheInsertData(cache, QEMUBinList[i], tmpCaps) < 0) {
            virObjectUnref(tmpCaps);
            return -1;
        }
    }

    if (!caps)
        virObjectUnref(tmpCaps);

    return 0;
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

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, NULL) < 0)
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


char *
testQemuGetLatestCapsForArch(const char *arch,
                             const char *suffix)
{
    struct dirent *ent;
    DIR *dir = NULL;
    int rc;
    char *fullsuffix = NULL;
    char *tmp = NULL;
    unsigned long maxver = 0;
    unsigned long ver;
    const char *maxname = NULL;
    char *ret = NULL;

    if (virAsprintf(&fullsuffix, "%s.%s", arch, suffix) < 0)
        goto cleanup;

    if (virDirOpen(&dir, TEST_QEMU_CAPS_PATH) < 0)
        goto cleanup;

    while ((rc = virDirRead(dir, &ent, TEST_QEMU_CAPS_PATH)) > 0) {
        VIR_FREE(tmp);

        if ((rc = VIR_STRDUP(tmp, STRSKIP(ent->d_name, "caps_"))) < 0)
            goto cleanup;

        if (rc == 0)
            continue;

        if (!virStringStripSuffix(tmp, fullsuffix))
            continue;

        if (virParseVersionString(tmp, &ver, false) < 0) {
            VIR_TEST_DEBUG("skipping caps file '%s'", ent->d_name);
            continue;
        }

        if (ver > maxver) {
            maxname = ent->d_name;
            maxver = ver;
        }
    }

    if (rc < 0)
        goto cleanup;

    if (!maxname) {
        VIR_TEST_VERBOSE("failed to find capabilities for '%s' in '%s'\n",
                         arch, TEST_QEMU_CAPS_PATH);
        goto cleanup;
    }

    ignore_value(virAsprintf(&ret, "%s/%s", TEST_QEMU_CAPS_PATH, maxname));

 cleanup:
    VIR_FREE(tmp);
    VIR_FREE(fullsuffix);
    virDirClose(&dir);
    return ret;
}


virHashTablePtr
testQemuGetLatestCaps(void)
{
    const char *archs[] = {
        "aarch64",
        "ppc64",
        "riscv64",
        "s390x",
        "x86_64",
    };
    virHashTablePtr capslatest;
    size_t i;

    if (!(capslatest = virHashCreate(4, virHashValueFree)))
        goto error;

    VIR_TEST_VERBOSE("\n");

    for (i = 0; i < ARRAY_CARDINALITY(archs); ++i) {
        char *cap = testQemuGetLatestCapsForArch(archs[i], "xml");

        if (!cap || virHashAddEntry(capslatest, archs[i], cap) < 0)
            goto error;

        VIR_TEST_VERBOSE("latest caps for %s: %s\n", archs[i], cap);
    }

    VIR_TEST_VERBOSE("\n");
    return capslatest;

 error:
    virHashFree(capslatest);
    return NULL;
}


int
testQemuCapsIterate(const char *suffix,
                    testQemuCapsIterateCallback callback,
                    void *opaque)
{
    struct dirent *ent;
    DIR *dir = NULL;
    int rc;
    int ret = -1;

    if (!callback)
        return 0;

    if (virDirOpen(&dir, TEST_QEMU_CAPS_PATH) < 0)
        goto cleanup;

    while ((rc = virDirRead(dir, &ent, TEST_QEMU_CAPS_PATH)) > 0) {
        char *tmp = ent->d_name;
        char *base = NULL;
        char *archName = NULL;

        /* Strip the trailing suffix, moving on if it's not present */
        if (!virStringStripSuffix(tmp, suffix))
            continue;

        /* Find the last dot, moving on if none is present */
        if (!(archName = strrchr(tmp, '.')))
            continue;

        /* The base name is everything before the last dot, and
         * the architecture name everything after it */
        base = tmp;
        archName[0] = '\0';
        archName++;

        /* Run the user-provided callback */
        if (callback(base, archName, opaque) < 0)
            goto cleanup;
    }

    if (rc < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDirClose(&dir);

    return ret;
}


int
testQemuInfoSetArgs(struct testQemuInfo *info,
                    virHashTablePtr capslatest, ...)
{
    va_list argptr;
    testQemuInfoArgName argname;
    virQEMUCapsPtr qemuCaps = NULL;
    int gic = GIC_NONE;
    char *capsarch = NULL;
    char *capsver = NULL;
    VIR_AUTOFREE(char *) capsfile = NULL;
    int flag;
    int ret = -1;

    va_start(argptr, capslatest);
    argname = va_arg(argptr, testQemuInfoArgName);
    while (argname != ARG_END) {
        switch (argname) {
        case ARG_QEMU_CAPS:
            if (qemuCaps || !(qemuCaps = virQEMUCapsNew()))
                goto cleanup;

            while ((flag = va_arg(argptr, int)) < QEMU_CAPS_LAST)
                virQEMUCapsSet(qemuCaps, flag);

            /* Some tests are run with NONE capabilities, which is just
             * another name for QEMU_CAPS_LAST. If that is the case the
             * arguments look like this :
             *
             *   ARG_QEMU_CAPS, NONE, QEMU_CAPS_LAST, ARG_END
             *
             * Fetch one argument more and if it is QEMU_CAPS_LAST then
             * break from the switch() to force getting next argument
             * in the line. If it is not QEMU_CAPS_LAST then we've
             * fetched real ARG_* and we must process it.
             */
            if ((flag = va_arg(argptr, int)) != QEMU_CAPS_LAST) {
                argname = flag;
                continue;
            }

            break;

        case ARG_GIC:
            gic = va_arg(argptr, int);
            break;

        case ARG_MIGRATE_FROM:
            info->migrateFrom = va_arg(argptr, char *);
            break;

        case ARG_MIGRATE_FD:
            info->migrateFd = va_arg(argptr, int);
            break;

        case ARG_FLAGS:
            info->flags = va_arg(argptr, int);
            break;

        case ARG_PARSEFLAGS:
            info->parseFlags = va_arg(argptr, int);
            break;

        case ARG_CAPS_ARCH:
            capsarch = va_arg(argptr, char *);
            break;

        case ARG_CAPS_VER:
            capsver = va_arg(argptr, char *);
            break;

        case ARG_END:
        default:
            fprintf(stderr, "Unexpected test info argument");
            goto cleanup;
        }

        argname = va_arg(argptr, testQemuInfoArgName);
    }

    if (!!capsarch ^ !!capsver) {
        fprintf(stderr, "ARG_CAPS_ARCH and ARG_CAPS_VER "
                        "must be specified together.\n");
        goto cleanup;
    }

    if (qemuCaps && (capsarch || capsver)) {
        fprintf(stderr, "ARG_QEMU_CAPS can not be combined with ARG_CAPS_ARCH "
                        "or ARG_CAPS_VER\n");
        goto cleanup;
    }

    if (!qemuCaps && capsarch && capsver) {
        bool stripmachinealiases = false;

        if (STREQ(capsver, "latest")) {
            if (VIR_STRDUP(capsfile, virHashLookup(capslatest, capsarch)) < 0)
                goto cleanup;
            stripmachinealiases = true;
        } else if (virAsprintf(&capsfile, "%s/caps_%s.%s.xml",
                               TEST_QEMU_CAPS_PATH, capsver, capsarch) < 0) {
            goto cleanup;
        }

        if (!(qemuCaps = qemuTestParseCapabilitiesArch(virArchFromString(capsarch),
                                                       capsfile))) {
            goto cleanup;
        }

        if (stripmachinealiases)
            virQEMUCapsStripMachineAliases(qemuCaps);
        info->flags |= FLAG_REAL_CAPS;
    }

    if (!qemuCaps) {
        fprintf(stderr, "No qemuCaps generated\n");
        goto cleanup;
    }
    VIR_STEAL_PTR(info->qemuCaps, qemuCaps);

    if (gic != GIC_NONE && testQemuCapsSetGIC(info->qemuCaps, gic) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(qemuCaps);
    va_end(argptr);

    return ret;
}


void
testQemuInfoClear(struct testQemuInfo *info)
{
    VIR_FREE(info->infile);
    VIR_FREE(info->outfile);
    virObjectUnref(info->qemuCaps);
}
