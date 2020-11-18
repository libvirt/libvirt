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
# include "virutil.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

virCPUDefPtr cpuDefault;
virCPUDefPtr cpuHaswell;
virCPUDefPtr cpuPower8;
virCPUDefPtr cpuPower9;


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
    "pc", "isapc", NULL
};
/**
 * Oldest supported qemu-1.5 supports machine types back to pc-0.10.
 */
static const char *const x86_64_machines[] = {
    "pc", "isapc", "q35",
    "pc-1.0", "pc-1.2",
    "pc-i440fx-1.4", "pc-i440fx-2.1", "pc-i440fx-2.3", "pc-i440fx-2.5",
    "pc-i440fx-2.6", "pc-i440fx-2.9", "pc-i440fx-2.12",
    "pc-q35-2.3", "pc-q35-2.4", "pc-q35-2.5", "pc-q35-2.7", "pc-q35-2.10",
    NULL
};
static const char *const aarch64_machines[] = {
    "virt", "virt-2.6", "versatilepb", NULL
};
static const char *const arm_machines[] = {
    "vexpress-a9", "vexpress-a15", "versatilepb", "virt", NULL
};
static const char *const ppc64_machines[] = {
    "pseries", NULL
};
static const char *const ppc_machines[] = {
    "g3beige", "mac99", "prep", "ppce500", NULL
};
static const char *const riscv32_machines[] = {
    "spike_v1.10", "spike_v1.9.1", "sifive_e", "virt", "sifive_u", NULL
};
static const char *const riscv64_machines[] = {
    "spike_v1.10", "spike_v1.9.1", "sifive_e", "virt", "sifive_u", NULL
};
static const char *const s390x_machines[] = {
    "s390-virtio", "s390-ccw-virtio", "s390-ccw", NULL
};
static const char *const sparc_machines[] = {
    "SS-5", "LX", "SPARCClassic", "SPARCbook",
    "SS-10", "SS-20", "SS-4", "SS-600MP",
    "Voyager", "leon3_generic", NULL
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


virCapsHostNUMAPtr
virCapabilitiesHostNUMANewHost(void)
{
    /*
     * Build a NUMA topology with cell_id (NUMA node id
     * being 3(0 + 3),4(1 + 3), 5 and 6
     */
    return virTestCapsBuildNUMATopology(3);
}


static int
testQemuAddGuest(virCapsPtr caps,
                 virArch arch)
{
    size_t nmachines;
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;
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

    if (!(guest = virCapabilitiesAddGuest(caps,
                                          VIR_DOMAIN_OSTYPE_HVM,
                                          arch,
                                          qemu_emulators[emu_arch],
                                          NULL,
                                          nmachines,
                                          machines)))
        goto error;

    machines = NULL;
    nmachines = 0;

    if (arch == VIR_ARCH_I686 ||
        arch == VIR_ARCH_X86_64)
        virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_CPUSELECTION);

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_QEMU,
                                       NULL,
                                       NULL,
                                       0,
                                       NULL))
        goto error;

    if (kvm_machines[emu_arch] != NULL) {
        nmachines = g_strv_length((char **)kvm_machines[emu_arch]);
        machines = virCapabilitiesAllocMachines(kvm_machines[emu_arch],
                                                nmachines);
        if (machines == NULL)
            goto error;

        if (!virCapabilitiesAddGuestDomain(guest,
                                           VIR_DOMAIN_VIRT_KVM,
                                           qemu_emulators[emu_arch],
                                           NULL,
                                           nmachines,
                                           machines))
            goto error;
    }

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, nmachines);
    return -1;
}


virCapsPtr testQemuCapsInit(void)
{
    virCapsPtr caps;
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
        if (testQemuAddGuest(caps, i) < 0)
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


void
qemuTestSetHostArch(virQEMUDriverPtr driver,
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
qemuTestSetHostCPU(virQEMUDriverPtr driver,
                   virArch arch,
                   virCPUDefPtr cpu)
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


virQEMUCapsPtr
qemuTestParseCapabilitiesArch(virArch arch,
                              const char *capsFile)
{
    virQEMUCapsPtr qemuCaps = NULL;
    g_autofree char *binary = g_strdup_printf("/usr/bin/qemu-system-%s",
                                              virArchToString(arch));

    if (!(qemuCaps = virQEMUCapsNewBinary(binary)) ||
        virQEMUCapsLoadCache(arch, qemuCaps, capsFile, true) < 0)
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
    virObjectUnref(driver->qemuCapsCache);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->config);
    virObjectUnref(driver->securityManager);
}

int qemuTestCapsCacheInsert(virFileCachePtr cache,
                            virQEMUCapsPtr caps)
{
    size_t i, j;

    for (i = 0; i < G_N_ELEMENTS(qemu_emulators); i++) {
        virQEMUCapsPtr tmpCaps;
        if (qemu_emulators[i] == NULL)
            continue;
        if (caps) {
            tmpCaps = virQEMUCapsNewCopy(caps);
        } else {
            tmpCaps = virQEMUCapsNew();
        }

        if (!virQEMUCapsHasMachines(tmpCaps)) {
            const char *defaultRAMid = NULL;

            /* default-ram-id appeared in QEMU 5.2.0. Reflect
             * this in our capabilities, i.e. set it for new
             * enough versions only. */
            if (virQEMUCapsGetVersion(tmpCaps) >= 5002000)
                defaultRAMid = qemu_default_ram_id[i];

            virQEMUCapsSetArch(tmpCaps, i);

            for (j = 0; qemu_machines[i][j] != NULL; j++) {
                virQEMUCapsAddMachine(tmpCaps,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      qemu_machines[i][j],
                                      NULL,
                                      NULL,
                                      0,
                                      false,
                                      false,
                                      true,
                                      defaultRAMid);
                virQEMUCapsSet(tmpCaps, QEMU_CAPS_TCG);
            }
            if (kvm_machines[i] != NULL) {
                for (j = 0; kvm_machines[i][j] != NULL; j++) {
                    virQEMUCapsAddMachine(tmpCaps,
                                          VIR_DOMAIN_VIRT_KVM,
                                          kvm_machines[i][j],
                                          NULL,
                                          NULL,
                                          0,
                                          false,
                                      false,
                                          true,
                                          defaultRAMid);
                    virQEMUCapsSet(tmpCaps, QEMU_CAPS_KVM);
                }
            }
        }

        if (virFileCacheInsertData(cache, qemu_emulators[i], tmpCaps) < 0) {
            virObjectUnref(tmpCaps);
            return -1;
        }
    }

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
testQemuCapsSetGIC(virQEMUCapsPtr qemuCaps,
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

        if (virParseVersionString(tmp, &ver, false) < 0) {
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
    GHashTable *capslatest;
    size_t i;

    if (!(capslatest = virHashNew(g_free)))
        goto error;

    VIR_TEST_VERBOSE("");

    for (i = 0; i < G_N_ELEMENTS(archs); ++i) {
        char *cap = testQemuGetLatestCapsForArch(archs[i], "xml");

        if (!cap || virHashAddEntry(capslatest, archs[i], cap) < 0)
            goto error;

        VIR_TEST_VERBOSE("latest caps for %s: %s", archs[i], cap);
    }

    VIR_TEST_VERBOSE("");

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


int
testQemuInfoSetArgs(struct testQemuInfo *info,
                    GHashTable *capslatest, ...)
{
    va_list argptr;
    testQemuInfoArgName argname;
    virQEMUCapsPtr qemuCaps = NULL;
    int gic = GIC_NONE;
    char *capsarch = NULL;
    char *capsver = NULL;
    g_autofree char *capsfile = NULL;
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

        info->arch = virArchFromString(capsarch);

        if (STREQ(capsver, "latest")) {
            capsfile = g_strdup(virHashLookup(capslatest, capsarch));
            stripmachinealiases = true;
        } else capsfile = g_strdup_printf("%s/caps_%s.%s.xml",
                                          TEST_QEMU_CAPS_PATH, capsver, capsarch);

        if (!(qemuCaps = qemuTestParseCapabilitiesArch(info->arch, capsfile)))
            goto cleanup;

        if (stripmachinealiases)
            virQEMUCapsStripMachineAliases(qemuCaps);
        info->flags |= FLAG_REAL_CAPS;

        /* provide path to the replies file for schema testing */
        capsfile[strlen(capsfile) - 3] = '\0';
        info->schemafile = g_strdup_printf("%sreplies", capsfile);
    }

    if (!qemuCaps) {
        fprintf(stderr, "No qemuCaps generated\n");
        goto cleanup;
    }
    info->qemuCaps = g_steal_pointer(&qemuCaps);

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
    VIR_FREE(info->schemafile);
    VIR_FREE(info->errfile);
    virObjectUnref(info->qemuCaps);
}
