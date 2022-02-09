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

# include <sys/types.h>
# include <fcntl.h>

# define VIR_FROM_THIS VIR_FROM_QEMU

virCPUDef *cpuDefault;
virCPUDef *cpuHaswell;
virCPUDef *cpuPower8;
virCPUDef *cpuPower9;


static const char *qemu_emulators[VIR_ARCH_LAST] = {
    [VIR_ARCH_I686] = "/usr/bin/qemu-system-i386",
    [VIR_ARCH_X86_64] = "/usr/bin/qemu-system-x86_64",
    [VIR_ARCH_AARCH64] = "/usr/bin/qemu-system-aarch64",
    [VIR_ARCH_ARMV7L] = "/usr/bin/qemu-system-arm",
    [VIR_ARCH_PPC64] = "/usr/bin/qemu-system-ppc64",
    [VIR_ARCH_PPC] = "/usr/bin/qemu-system-ppc",
    [VIR_ARCH_RISCV32] = "/usr/bin/qemu-system-riscv32",
    [VIR_ARCH_RISCV64] = "/usr/bin/qemu-system-riscv64",
    [VIR_ARCH_S390X] = "/usr/bin/qemu-system-s390x",
    [VIR_ARCH_SPARC] = "/usr/bin/qemu-system-sparc",
};

static const virArch arch_alias[VIR_ARCH_LAST] = {
    [VIR_ARCH_PPC64LE] = VIR_ARCH_PPC64,
    [VIR_ARCH_ARMV6L] = VIR_ARCH_ARMV7L,
};

static const char *const i386_machines[] = {
    "pc", NULL
};

static const char *const x86_64_machines[] = {
    "pc", "q35", NULL
};
static const char *const aarch64_machines[] = {
    "virt", "virt-2.6", "versatilepb", NULL
};
static const char *const arm_machines[] = {
    "vexpress-a9", "virt", NULL
};
static const char *const ppc64_machines[] = {
    "pseries", NULL
};
static const char *const ppc_machines[] = {
    "ppce500", NULL
};
static const char *const riscv32_machines[] = {
    "virt", NULL
};
static const char *const riscv64_machines[] = {
    "virt", NULL
};
static const char *const s390x_machines[] = {
    "s390-ccw-virtio", NULL
};
static const char *const sparc_machines[] = {
    "SS-5", NULL
};

static const char *const *qemu_machines[VIR_ARCH_LAST] = {
    [VIR_ARCH_I686] = i386_machines,
    [VIR_ARCH_X86_64] = x86_64_machines,
    [VIR_ARCH_AARCH64] = aarch64_machines,
    [VIR_ARCH_ARMV7L] = arm_machines,
    [VIR_ARCH_PPC64] = ppc64_machines,
    [VIR_ARCH_PPC] = ppc_machines,
    [VIR_ARCH_RISCV32] = riscv32_machines,
    [VIR_ARCH_RISCV64] = riscv64_machines,
    [VIR_ARCH_S390X] = s390x_machines,
    [VIR_ARCH_SPARC] = sparc_machines,
};

static const char *const *kvm_machines[VIR_ARCH_LAST] = {
    [VIR_ARCH_I686] = i386_machines,
    [VIR_ARCH_X86_64] = x86_64_machines,
    [VIR_ARCH_AARCH64] = aarch64_machines,
    [VIR_ARCH_ARMV7L] = arm_machines,
    [VIR_ARCH_PPC64] = ppc64_machines,
    [VIR_ARCH_PPC] = ppc_machines,
    [VIR_ARCH_RISCV32] = riscv32_machines,
    [VIR_ARCH_RISCV64] = riscv64_machines,
    [VIR_ARCH_S390X] = s390x_machines,
};

static const char *const *hvf_machines[VIR_ARCH_LAST] = {
    [VIR_ARCH_I686] = NULL,
    [VIR_ARCH_X86_64] = x86_64_machines,
    [VIR_ARCH_AARCH64] = aarch64_machines,
    [VIR_ARCH_ARMV7L] = NULL,
    [VIR_ARCH_PPC64] = NULL,
    [VIR_ARCH_PPC] = NULL,
    [VIR_ARCH_RISCV32] = NULL,
    [VIR_ARCH_RISCV64] = NULL,
    [VIR_ARCH_S390X] = NULL,
};

static const char *qemu_default_ram_id[VIR_ARCH_LAST] = {
    [VIR_ARCH_I686] = "pc.ram",
    [VIR_ARCH_X86_64] = "pc.ram",
    [VIR_ARCH_AARCH64] = "mach-virt.ram",
    [VIR_ARCH_ARMV7L] = "vexpress.highmem",
    [VIR_ARCH_PPC64] = "ppc_spapr.ram",
    [VIR_ARCH_PPC] = "ppc_spapr.ram",
    [VIR_ARCH_S390X] = "s390.ram",
    [VIR_ARCH_SPARC] = "sun4m.ram",
};

char *
virFindFileInPath(const char *file)
{
    if (g_str_has_prefix(file, "qemu-system") ||
        g_str_equal(file, "qemu-kvm")) {
        return g_strdup_printf("/usr/bin/%s", file);
    }

    /* Nothing in tests should be relying on real files
     * in host OS, so we return NULL to try to force
     * an error in such a case
     */
    return NULL;
}


virCapsHostNUMA *
virCapabilitiesHostNUMANewHost(void)
{
    /*
     * Build a NUMA topology with cell_id (NUMA node id
     * being 3(0 + 3),4(1 + 3), 5 and 6
     */
    return virTestCapsBuildNUMATopology(3);
}

void
virHostCPUX86GetCPUID(uint32_t leaf,
                      uint32_t extended,
                      uint32_t *eax,
                      uint32_t *ebx,
                      uint32_t *ecx,
                      uint32_t *edx)
{
    if (eax)
        *eax = 0;
    if (ebx)
        *ebx = 0;
    if (ecx)
        *ecx = 0;
    if (edx)
        *edx = 0;
    if (leaf == 0x8000001F && extended == 0) {
        if (ecx)
            *ecx = 509;
        if (edx)
            *edx = 451;
    }
}

static int
testQemuAddGuest(virCaps *caps,
                 virArch arch,
                 testQemuHostOS hostOS)
{
    size_t nmachines;
    virCapsGuestMachine **machines = NULL;
    virCapsGuest *guest;
    virArch emu_arch = arch;

    if (arch_alias[arch] != VIR_ARCH_NONE)
        emu_arch = arch_alias[arch];

    if (qemu_emulators[emu_arch] == NULL)
        return 0;

    nmachines = g_strv_length((gchar **)qemu_machines[emu_arch]);
    machines = virCapabilitiesAllocMachines(qemu_machines[emu_arch],
                                            nmachines);
    if (machines == NULL)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    arch, qemu_emulators[emu_arch],
                                    NULL, nmachines, machines);

    machines = NULL;
    nmachines = 0;

    if (arch == VIR_ARCH_I686 ||
        arch == VIR_ARCH_X86_64)
        virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_CPUSELECTION);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU,
                                  NULL, NULL, 0, NULL);

    if (hostOS == HOST_OS_LINUX) {
        if (kvm_machines[emu_arch] != NULL) {
            nmachines = g_strv_length((char **)kvm_machines[emu_arch]);
            machines = virCapabilitiesAllocMachines(kvm_machines[emu_arch],
                                                    nmachines);
            if (machines == NULL)
                goto error;

            virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                          qemu_emulators[emu_arch],
                                          NULL, nmachines, machines);
        }
    }

    if (hostOS == HOST_OS_MACOS) {
        if (hvf_machines[emu_arch] != NULL) {
            nmachines = g_strv_length((char **)hvf_machines[emu_arch]);
            machines = virCapabilitiesAllocMachines(hvf_machines[emu_arch],
                                                    nmachines);
            if (machines == NULL)
                goto error;

            virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HVF,
                                          qemu_emulators[emu_arch],
                                          NULL, nmachines, machines);
        }
    }

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
    return -1;
}


static virCaps*
testQemuCapsInitImpl(testQemuHostOS hostOS)
{
    virCaps *caps;
    size_t i;

    if (!(caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)))
        return NULL;

    /* Add dummy 'none' security_driver. This is equal to setting
     * security_driver = "none" in qemu.conf. */
    caps->host.secModels = g_new0(virCapsHostSecModel, 1);
    caps->host.nsecModels = 1;

    caps->host.secModels[0].model = g_strdup("none");
    caps->host.secModels[0].doi = g_strdup("0");

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto cleanup;

    for (i = 0; i < VIR_ARCH_LAST; i++) {
        if (testQemuAddGuest(caps, i, hostOS) < 0)
            goto cleanup;
    }

    if (virTestGetDebug()) {
        g_autofree char *caps_str = NULL;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto cleanup;

        VIR_TEST_DEBUG("QEMU driver capabilities:\n%s", caps_str);
    }

    return caps;

 cleanup:
    caps->host.cpu = NULL;
    virObjectUnref(caps);
    return NULL;
}

virCaps*
testQemuCapsInit(void)
{
    return testQemuCapsInitImpl(HOST_OS_LINUX);
}

virCaps*
testQemuCapsInitMacOS(void)
{
    return testQemuCapsInitImpl(HOST_OS_MACOS);
}


void
qemuTestSetHostArch(virQEMUDriver *driver,
                    virArch arch)
{
    if (arch == VIR_ARCH_NONE)
        arch = VIR_ARCH_X86_64;

    virTestHostArch = arch;
    driver->hostarch = virArchFromHost();
    driver->caps->host.arch = virArchFromHost();
    qemuTestSetHostCPU(driver, arch, NULL);
}


void
qemuTestSetHostCPU(virQEMUDriver *driver,
                   virArch arch,
                   virCPUDef *cpu)
{
    if (!cpu) {
        if (ARCH_IS_X86(arch))
            cpu = cpuDefault;
        else if (ARCH_IS_PPC64(arch))
            cpu = cpuPower8;
    }

    g_unsetenv("VIR_TEST_MOCK_FAKE_HOST_CPU");
    if (cpu) {
        if (cpu->model)
            g_setenv("VIR_TEST_MOCK_FAKE_HOST_CPU", cpu->model, TRUE);
    }
    if (driver) {
        if (cpu)
            driver->caps->host.arch = cpu->arch;
        driver->caps->host.cpu = cpu;

        virCPUDefFree(driver->hostcpu);
        if (cpu)
            virCPUDefRef(cpu);
        driver->hostcpu = cpu;
    }
}


virQEMUCaps *
qemuTestParseCapabilitiesArch(virArch arch,
                              const char *capsFile)
{
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    g_autofree char *binary = g_strdup_printf("/usr/bin/qemu-system-%s",
                                              virArchToString(arch));

    if (!(qemuCaps = virQEMUCapsNewBinary(binary)) ||
        virQEMUCapsLoadCache(arch, qemuCaps, capsFile, true) < 0)
        return NULL;

    return g_steal_pointer(&qemuCaps);
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

    virCPUDefFree(cpuDefault);
    virCPUDefFree(cpuHaswell);
    virCPUDefFree(cpuPower8);
    virCPUDefFree(cpuPower9);
}


static void
qemuTestCapsPopulateFakeMachines(virQEMUCaps *caps,
                                 virArch arch,
                                 testQemuHostOS hostOS)
{
    size_t i;
    const char *defaultRAMid = NULL;

    /* default-ram-id appeared in QEMU 5.2.0. Reflect
     * this in our capabilities, i.e. set it for new
     * enough versions only. */
    if (virQEMUCapsGetVersion(caps) >= 5002000)
        defaultRAMid = qemu_default_ram_id[arch];

    virQEMUCapsSetArch(caps, arch);

    for (i = 0; qemu_machines[arch][i] != NULL; i++) {
        virQEMUCapsAddMachine(caps,
                              VIR_DOMAIN_VIRT_QEMU,
                              qemu_machines[arch][i],
                              NULL,
                              NULL,
                              0,
                              false,
                              false,
                              true,
                              defaultRAMid,
                              false);
        virQEMUCapsSet(caps, QEMU_CAPS_TCG);
    }

    if (hostOS == HOST_OS_LINUX) {
        if (kvm_machines[arch] != NULL) {
            for (i = 0; kvm_machines[arch][i] != NULL; i++) {
                virQEMUCapsAddMachine(caps,
                                      VIR_DOMAIN_VIRT_KVM,
                                      kvm_machines[arch][i],
                                      NULL,
                                      NULL,
                                      0,
                                      false,
                                      false,
                                      true,
                                      defaultRAMid,
                                      false);
                virQEMUCapsSet(caps, QEMU_CAPS_KVM);
            }
        }
    }

    if (hostOS == HOST_OS_MACOS) {
        if (hvf_machines[arch] != NULL) {
            for (i = 0; hvf_machines[arch][i] != NULL; i++) {
                virQEMUCapsAddMachine(caps,
                        VIR_DOMAIN_VIRT_HVF,
                        hvf_machines[arch][i],
                        NULL,
                        NULL,
                        0,
                        false,
                        false,
                        true,
                        defaultRAMid,
                        false);
                virQEMUCapsSet(caps, QEMU_CAPS_HVF);
            }
        }
    }
}


static int
qemuTestCapsCacheInsertData(virFileCache *cache,
                            const char *binary,
                            virQEMUCaps *caps)
{
    if (virFileCacheInsertData(cache, binary, virObjectRef(caps)) < 0) {
        virObjectUnref(caps);
        return -1;
    }

    return 0;
}


static int
qemuTestCapsCacheInsertImpl(virFileCache *cache,
                            virQEMUCaps *caps,
                            testQemuHostOS hostOS)
{
    size_t i;

    if (caps && virQEMUCapsGetArch(caps) != VIR_ARCH_NONE) {
        /* for capabilities which have architecture set we populate only the
         * given architecture and poison all other so that the test doesn't
         * accidentally test a weird combination */
        virArch arch = virQEMUCapsGetArch(caps);
        g_autoptr(virQEMUCaps) emptyCaps = virQEMUCapsNew();
        g_autoptr(virQEMUCaps) copyCaps = NULL;
        virQEMUCaps *effCaps = caps;

        if (!emptyCaps)
            return -1;

        if (arch_alias[arch] != VIR_ARCH_NONE)
            arch = arch_alias[arch];

        if (qemu_emulators[arch]) {
            /* if we are dealing with fake caps we need to populate machine types */
            if (!virQEMUCapsHasMachines(caps)) {
                if (!(copyCaps = effCaps = virQEMUCapsNewCopy(caps)))
                    return -1;

                qemuTestCapsPopulateFakeMachines(copyCaps, arch, hostOS);
            }

            if (qemuTestCapsCacheInsertData(cache, qemu_emulators[arch], effCaps) < 0)
                return -1;
        }


        for (i = 0; i < G_N_ELEMENTS(qemu_emulators); i++) {
            if (!qemu_emulators[i])
                continue;

            if (i == arch)
                continue;

            if (qemuTestCapsCacheInsertData(cache, qemu_emulators[i], emptyCaps) < 0)
                return -1;
        }
    } else {
        /* in case when caps are missing or are missing architecture, we populate
         * everything */
        for (i = 0; i < G_N_ELEMENTS(qemu_emulators); i++) {
            g_autoptr(virQEMUCaps) tmp = NULL;

            if (qemu_emulators[i] == NULL)
                continue;

            if (caps)
                tmp = virQEMUCapsNewCopy(caps);
            else
                tmp = virQEMUCapsNew();

            if (!tmp)
                return -1;

            qemuTestCapsPopulateFakeMachines(tmp, i, hostOS);

            if (qemuTestCapsCacheInsertData(cache, qemu_emulators[i], tmp) < 0)
                return -1;
        }
    }

    return 0;
}

int
qemuTestCapsCacheInsert(virFileCache *cache,
                        virQEMUCaps *caps)
{
    return qemuTestCapsCacheInsertImpl(cache, caps, HOST_OS_LINUX);
}

int
qemuTestCapsCacheInsertMacOS(virFileCache *cache,
                             virQEMUCaps *caps)
{
    return qemuTestCapsCacheInsertImpl(cache, caps, HOST_OS_MACOS);
}


# define STATEDIRTEMPLATE abs_builddir "/qemustatedir-XXXXXX"
# define CONFIGDIRTEMPLATE abs_builddir "/qemuconfigdir-XXXXXX"

int qemuTestDriverInit(virQEMUDriver *driver)
{
    virSecurityManager *mgr = NULL;
    char statedir[] = STATEDIRTEMPLATE;
    char configdir[] = CONFIGDIRTEMPLATE;

    memset(driver, 0, sizeof(*driver));

    if (!(cpuDefault = virCPUDefCopy(&cpuDefaultData)) ||
        !(cpuHaswell = virCPUDefCopy(&cpuHaswellData)) ||
        !(cpuPower8 = virCPUDefCopy(&cpuPower8Data)) ||
        !(cpuPower9 = virCPUDefCopy(&cpuPower9Data)))
        return -1;

    if (virMutexInit(&driver->lock) < 0)
        return -1;

    driver->hostarch = virArchFromHost();
    driver->config = virQEMUDriverConfigNew(false, NULL);
    if (!driver->config)
        goto error;

    /* Do this early so that qemuTestDriverFree() doesn't see (unlink) the real
     * dirs. */
    VIR_FREE(driver->config->stateDir);
    VIR_FREE(driver->config->configDir);

    /* Overwrite some default paths so it's consistent for tests. */
    VIR_FREE(driver->config->libDir);
    VIR_FREE(driver->config->channelTargetDir);
    driver->config->libDir = g_strdup("/tmp/lib");
    driver->config->channelTargetDir = g_strdup("/tmp/channel");

    if (!g_mkdtemp(statedir)) {
        fprintf(stderr, "Cannot create fake stateDir");
        goto error;
    }

    driver->config->stateDir = g_strdup(statedir);

    if (!g_mkdtemp(configdir)) {
        fprintf(stderr, "Cannot create fake configDir");
        goto error;
    }

    driver->config->configDir = g_strdup(configdir);

    driver->caps = testQemuCapsInit();
    if (!driver->caps)
        goto error;

    /* Using /dev/null for libDir and cacheDir automatically produces errors
     * upon attempt to use any of them */
    driver->qemuCapsCache = virQEMUCapsCacheNew("/dev/null", "/dev/null", 0, 0);
    if (!driver->qemuCapsCache)
        goto error;

    driver->xmlopt = virQEMUDriverCreateXMLConf(driver, "none");
    if (!driver->xmlopt)
        goto error;

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, NULL) < 0)
        goto error;

    if (!(mgr = virSecurityManagerNew("none", "qemu",
                                      VIR_SECURITY_MANAGER_PRIVILEGED)))
        goto error;
    if (!(driver->securityManager = virSecurityManagerNewStack(mgr)))
        goto error;

    qemuTestSetHostCPU(driver, driver->hostarch, NULL);

    return 0;

 error:
    virObjectUnref(mgr);
    qemuTestDriverFree(driver);
    return -1;
}

int
testQemuCapsSetGIC(virQEMUCaps *qemuCaps,
                   int gic)
{
    virGICCapability *gicCapabilities = NULL;
    size_t ngicCapabilities = 0;

    gicCapabilities = g_new0(virGICCapability, 2);

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

    return 0;
}

#endif


char *
testQemuGetLatestCapsForArch(const char *arch,
                             const char *suffix)
{
    struct dirent *ent;
    g_autoptr(DIR) dir = NULL;
    int rc;
    g_autofree char *fullsuffix = NULL;
    unsigned long maxver = 0;
    unsigned long ver;
    g_autofree char *maxname = NULL;

    fullsuffix = g_strdup_printf("%s.%s", arch, suffix);

    if (virDirOpen(&dir, TEST_QEMU_CAPS_PATH) < 0)
        return NULL;

    while ((rc = virDirRead(dir, &ent, TEST_QEMU_CAPS_PATH)) > 0) {
        g_autofree char *tmp = NULL;

        tmp = g_strdup(STRSKIP(ent->d_name, "caps_"));

        if (!tmp)
            continue;

        if (!virStringStripSuffix(tmp, fullsuffix))
            continue;

        if (virStringParseVersion(&ver, tmp, false) < 0) {
            VIR_TEST_DEBUG("skipping caps file '%s'", ent->d_name);
            continue;
        }

        if (ver > maxver) {
            g_free(maxname);
            maxname = g_strdup(ent->d_name);
            maxver = ver;
        }
    }

    if (rc < 0)
        return NULL;

    if (!maxname) {
        VIR_TEST_VERBOSE("failed to find capabilities for '%s' in '%s'",
                         arch, TEST_QEMU_CAPS_PATH);
        return NULL;
    }

    return g_strdup_printf("%s/%s", TEST_QEMU_CAPS_PATH, maxname);
}


GHashTable *
testQemuGetLatestCaps(void)
{
    const char *archs[] = {
        "aarch64",
        "ppc64",
        "riscv64",
        "s390x",
        "x86_64",
    };
    g_autoptr(GHashTable) capslatest = virHashNew(g_free);
    size_t i;

    VIR_TEST_VERBOSE("");

    for (i = 0; i < G_N_ELEMENTS(archs); ++i) {
        char *cap = testQemuGetLatestCapsForArch(archs[i], "xml");

        if (!cap || virHashAddEntry(capslatest, archs[i], cap) < 0)
            return NULL;

        VIR_TEST_VERBOSE("latest caps for %s: %s", archs[i], cap);
    }

    VIR_TEST_VERBOSE("");

    return g_steal_pointer(&capslatest);
}


int
testQemuCapsIterate(const char *suffix,
                    testQemuCapsIterateCallback callback,
                    void *opaque)
{
    struct dirent *ent;
    g_autoptr(DIR) dir = NULL;
    int rc;
    bool fail = false;

    if (!callback)
        return 0;

    /* Validate suffix */
    if (!STRPREFIX(suffix, ".")) {
        VIR_TEST_VERBOSE("malformed suffix '%s'", suffix);
        return -1;
    }

    if (virDirOpen(&dir, TEST_QEMU_CAPS_PATH) < 0)
        return -1;

    while ((rc = virDirRead(dir, &ent, TEST_QEMU_CAPS_PATH)) > 0) {
        g_autofree char *tmp = g_strdup(ent->d_name);
        char *version = NULL;
        char *archName = NULL;

        /* Strip the trailing suffix, moving on if it's not present */
        if (!virStringStripSuffix(tmp, suffix))
            continue;

        /* Strip the leading prefix */
        if (!(version = STRSKIP(tmp, "caps_"))) {
            VIR_TEST_VERBOSE("malformed file name '%s'", ent->d_name);
            return -1;
        }

        /* Find the last dot */
        if (!(archName = strrchr(tmp, '.'))) {
            VIR_TEST_VERBOSE("malformed file name '%s'", ent->d_name);
            return -1;
        }

        /* The version number and the architecture name are separated by
         * a dot: overwriting that dot with \0 results in both being usable
         * as independent, null-terminated strings */
        archName[0] = '\0';
        archName++;

        /* Run the user-provided callback.
         *
         * We skip the dot that, as verified earlier, starts the suffix
         * to make it nicer to rebuild the original file name from inside
         * the callback.
         */
        if (callback(TEST_QEMU_CAPS_PATH, "caps", version,
                     archName, suffix + 1, opaque) < 0)
            fail = true;
    }

    if (rc < 0 || fail)
        return -1;

    return 0;
}


void
testQemuInfoSetArgs(struct testQemuInfo *info,
                    struct testQemuConf *conf, ...)
{
    va_list argptr;
    testQemuInfoArgName argname;
    int flag;

    if (!(info->args.fakeCaps = virQEMUCapsNew()))
        abort();

    info->conf = conf;
    info->args.newargs = true;

    va_start(argptr, conf);
    while ((argname = va_arg(argptr, testQemuInfoArgName)) != ARG_END) {
        switch (argname) {
        case ARG_QEMU_CAPS:
            info->args.fakeCapsUsed = true;

            while ((flag = va_arg(argptr, int)) < QEMU_CAPS_LAST)
                virQEMUCapsSet(info->args.fakeCaps, flag);
            break;

        case ARG_GIC:
            info->args.gic = va_arg(argptr, int);
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
            info->args.capsarch = va_arg(argptr, char *);
            break;

        case ARG_CAPS_VER:
            info->args.capsver = va_arg(argptr, char *);
            break;

        case ARG_HOST_OS:
            info->args.hostOS = va_arg(argptr, int);
            break;

        case ARG_END:
        default:
            info->args.invalidarg = true;
            break;
        }

        if (info->args.invalidarg)
            break;
    }

    va_end(argptr);
}


int
testQemuInfoInitArgs(struct testQemuInfo *info)
{
    g_autofree char *capsfile = NULL;

    if (!info->args.newargs)
        return 0;

    info->args.newargs = false;

    if (info->args.invalidarg) {
        fprintf(stderr, "Invalid argument encountered by 'testQemuInfoSetArgs'\n");
        return -1;
    }

    if (!!info->args.capsarch ^ !!info->args.capsver) {
        fprintf(stderr, "ARG_CAPS_ARCH and ARG_CAPS_VER must be specified together.\n");
        return -1;
    }

    if (info->args.capsarch && info->args.capsver) {
        bool stripmachinealiases = false;
        virQEMUCaps *cachedcaps = NULL;

        info->arch = virArchFromString(info->args.capsarch);

        if (STREQ(info->args.capsver, "latest")) {
            capsfile = g_strdup(virHashLookup(info->conf->capslatest, info->args.capsarch));

            if (!capsfile) {
                fprintf(stderr, "'latest' caps for '%s' were not found\n", info->args.capsarch);
                return -1;
            }

            stripmachinealiases = true;
        } else {
            capsfile = g_strdup_printf("%s/caps_%s.%s.xml",
                                       TEST_QEMU_CAPS_PATH,
                                       info->args.capsver,
                                       info->args.capsarch);
        }

        if (!g_hash_table_lookup_extended(info->conf->capscache, capsfile, NULL, (void **) &cachedcaps)) {
            if (!(cachedcaps = qemuTestParseCapabilitiesArch(info->arch, capsfile)))
                return -1;

            g_hash_table_insert(info->conf->capscache, g_strdup(capsfile), cachedcaps);
        }

        if (!(info->qemuCaps = virQEMUCapsNewCopy(cachedcaps)))
            return -1;

        if (info->args.fakeCapsUsed) {
            size_t i;
            for (i = 0; i < QEMU_CAPS_LAST; i++) {
                if (virQEMUCapsGet(info->args.fakeCaps, i)) {
                    virQEMUCapsSet(info->qemuCaps, i);
                }
            }
        }


        if (stripmachinealiases)
            virQEMUCapsStripMachineAliases(info->qemuCaps);

        info->flags |= FLAG_REAL_CAPS;

        /* provide path to the replies file for schema testing */
        capsfile[strlen(capsfile) - 3] = '\0';
        info->schemafile = g_strdup_printf("%sreplies", capsfile);
    } else {
        info->qemuCaps = g_steal_pointer(&info->args.fakeCaps);
    }

    if (info->args.gic != GIC_NONE &&
        testQemuCapsSetGIC(info->qemuCaps, info->args.gic) < 0)
        return -1;

    return 0;
}


void
testQemuInfoClear(struct testQemuInfo *info)
{
    VIR_FREE(info->infile);
    VIR_FREE(info->outfile);
    VIR_FREE(info->schemafile);
    VIR_FREE(info->errfile);
    virObjectUnref(info->qemuCaps);
    g_clear_pointer(&info->args.fakeCaps, virObjectUnref);
}


/**
 * testQemuPrepareHostBackendChardevOne:
 * @dev: device definition object
 * @chardev: chardev source object
 * @opaque: Caller is expected to pass pointer to virDomainObj or NULL
 *
 * This helper sets up a chardev source backend for FD passing with fake
 * file descriptros. It's expected to be used as  callback for
 * 'qemuDomainDeviceBackendChardevForeach', thus the VM object is passed via
 * @opaque. Callers may pass NULL if the test scope is limited.
 */
int
testQemuPrepareHostBackendChardevOne(virDomainDeviceDef *dev,
                                     virDomainChrSourceDef *chardev,
                                     void *opaque)
{
    virDomainObj *vm = opaque;
    qemuDomainObjPrivate *priv = NULL;
    qemuDomainChrSourcePrivate *charpriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chardev);
    int fakesourcefd = -1;
    const char *devalias = NULL;
    bool usefdset = true;

    if (vm)
        priv = vm->privateData;

    if (dev) {
        virDomainDeviceInfo *info = virDomainDeviceGetInfo(dev);
        devalias = info->alias;

        /* vhost-user disk doesn't use FD passing */
        if (dev->type == VIR_DOMAIN_DEVICE_DISK)
            return 0;

        if (dev->type == VIR_DOMAIN_DEVICE_NET) {
            /* due to a historical bug in qemu we don't use FD passtrhough for
             * vhost-sockets for network devices */
            return 0;
        }

        /* TPMs FD passing setup is special and handled separately */
        if (dev->type == VIR_DOMAIN_DEVICE_TPM)
            return 0;
    } else {
        devalias = "monitor";
    }

    switch ((virDomainChrType) chardev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        fakesourcefd = 1750;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (chardev->data.nix.listen &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHARDEV_FD_PASS_COMMANDLINE))
            fakesourcefd = 1729;

        usefdset = false;
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    if (fakesourcefd != -1) {
        if (fcntl(fakesourcefd, F_GETFD) != -1)
            abort();

        if (usefdset)
            charpriv->sourcefd = qemuFDPassNew(devalias, priv);
        else
            charpriv->sourcefd = qemuFDPassNewDirect(devalias, priv);

        if (qemuFDPassAddFD(charpriv->sourcefd, &fakesourcefd, "-source") < 0)
            return -1;
    }

    if (chardev->logfile) {
        int fd = 1751;

        if (fcntl(fd, F_GETFD) != -1)
            abort();

        charpriv->logfd = qemuFDPassNew(devalias, priv);

        if (qemuFDPassAddFD(charpriv->logfd, &fd, "-log") < 0)
            return -1;
    }

    return 0;
}
