#include <config.h>
#ifdef WITH_QEMU

# include "testutilsqemu.h"
# include "testutilsqemuschema.h"
# include "testutilshostcpus.h"
# include "testutils.h"
# include "viralloc.h"
# include "cpu_conf.h"
# include "qemu/qemu_domain.h"
# define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
# include "qemu/qemu_capspriv.h"
# include "virstring.h"
# include "virfilecache.h"
# include "virtpm.h"

# include <sys/types.h>
# include <fcntl.h>

# define VIR_FROM_THIS VIR_FROM_QEMU

static virCPUDef *cpuDefault;
static virCPUDef *cpuHaswell;
static virCPUDef *cpuPower8;
static virCPUDef *cpuPower9;
static virCPUDef *cpuPower10;

char *
virFindFileInPath(const char *file)
{
    if (g_str_has_prefix(file, "qemu-system") ||
        g_str_equal(file, "qemu-kvm")) {
        return g_strdup_printf("/usr/bin/%s", file);
    }

    if (g_str_equal(file, "nbdkit")) {
        return g_strdup(TEST_NBDKIT_PATH);
    }

    /* Nothing in tests should be relying on real files
     * in host OS, so we return NULL to try to force
     * an error in such a case
     */
    return NULL;
}


/* Enough to tell capabilities code that swtpm is usable */
bool virTPMHasSwtpm(void)
{
    return true;
}



bool
virTPMSwtpmSetupCapsGet(virTPMSwtpmSetupFeature cap)
{
    const char *tpmver = getenv(TEST_TPM_ENV_VAR);

    switch (cap) {
    case VIR_TPM_SWTPM_SETUP_FEATURE_TPM_1_2:
        if (!tpmver || (tpmver && strstr(tpmver, TPM_VER_1_2)))
            return true;
        break;
    case VIR_TPM_SWTPM_SETUP_FEATURE_TPM_2_0:
        if (!tpmver || (tpmver && strstr(tpmver, TPM_VER_2_0)))
            return true;
        break;
    case VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_PWDFILE_FD:
    case VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_CREATE_CONFIG_FILES:
    case VIR_TPM_SWTPM_SETUP_FEATURE_TPM12_NOT_NEED_ROOT:
    case VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_RECONFIGURE_PCR_BANKS:
    case VIR_TPM_SWTPM_SETUP_FEATURE_LAST:
        break;
    }

    return false;
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

static virCaps *
testQemuCapsInit(void)
{
    virCaps *caps;

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

virCPUDef *
qemuTestGetCPUDef(qemuTestCPUDef d)
{
    switch (d) {
    case QEMU_CPU_DEF_DEFAULT: return cpuDefault;
    case QEMU_CPU_DEF_HASWELL: return cpuHaswell;
    case QEMU_CPU_DEF_POWER8: return cpuPower8;
    case QEMU_CPU_DEF_POWER9: return cpuPower9;
    case QEMU_CPU_DEF_POWER10: return cpuPower10;
    }

    return NULL;
}


void
qemuTestSetHostArch(virQEMUDriver *driver,
                    virArch arch)
{
    if (arch == VIR_ARCH_NONE)
        arch = VIR_ARCH_X86_64;

    virTestSetHostArch(arch);
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
    g_autofree char *binary = g_strdup_printf("/usr/bin/qemu-system-%s",
                                              virArchToString(arch));
    g_autoptr(virQEMUCaps) qemuCaps = virQEMUCapsNewBinary(binary);

    if (virQEMUCapsLoadCache(arch, qemuCaps, capsFile, true) < 0)
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
    g_clear_object(&driver->nbdkitCapsCache);

    virCPUDefFree(cpuDefault);
    virCPUDefFree(cpuHaswell);
    virCPUDefFree(cpuPower8);
    virCPUDefFree(cpuPower9);
    virCPUDefFree(cpuPower10);
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


int
qemuTestCapsCacheInsert(virFileCache *cache,
                        virQEMUCaps *caps)
{
    /* At this point we support only real capabilities. */
    if (virQEMUCapsGetArch(caps) == VIR_ARCH_NONE ||
        !virQEMUCapsGetBinary(caps)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "missing 'arch' or 'binary' in qemuCaps to be inserted into testing cache");
        return -1;
    }

    if (qemuTestCapsCacheInsertData(cache, virQEMUCapsGetBinary(caps), caps) < 0)
        return -1;

    return 0;
}

# define STATEDIRTEMPLATE abs_builddir "/qemustatedir-XXXXXX"
# define CONFIGDIRTEMPLATE abs_builddir "/qemuconfigdir-XXXXXX"

int qemuTestDriverInit(virQEMUDriver *driver)
{
    virQEMUDriverConfig *cfg = NULL;
    virSecurityManager *mgr = NULL;
    char statedir[] = STATEDIRTEMPLATE;
    char configdir[] = CONFIGDIRTEMPLATE;

    memset(driver, 0, sizeof(*driver));

    cpuDefault = virCPUDefCopy(&cpuDefaultData);
    cpuHaswell = virCPUDefCopy(&cpuHaswellData);
    cpuPower8 = virCPUDefCopy(&cpuPower8Data);
    cpuPower9 = virCPUDefCopy(&cpuPower9Data);
    cpuPower10 = virCPUDefCopy(&cpuPower10Data);

    if (virMutexInit(&driver->lock) < 0)
        return -1;

    driver->hostarch = virArchFromHost();

    cfg = virQEMUDriverConfigNew(false, NULL);
    if (!cfg)
        goto error;
    driver->config = cfg;

    /* Do this early so that qemuTestDriverFree() doesn't see (unlink) the real
     * dirs. */
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->configDir);

    /* Override paths to ensure predictable output
     *
     * FIXME Find a way to achieve the same result while avoiding
     *       code duplication
     */
    VIR_FREE(cfg->libDir);
    cfg->libDir = g_strdup("/var/lib/libvirt/qemu");
    VIR_FREE(cfg->channelTargetDir);
    cfg->channelTargetDir = g_strdup("/var/run/libvirt/qemu/channel");
    VIR_FREE(cfg->memoryBackingDir);
    cfg->memoryBackingDir = g_strdup("/var/lib/libvirt/qemu/ram");
    VIR_FREE(cfg->nvramDir);
    cfg->nvramDir = g_strdup("/var/lib/libvirt/qemu/nvram");
    VIR_FREE(cfg->passtStateDir);
    cfg->passtStateDir = g_strdup("/var/run/libvirt/qemu/passt");
    VIR_FREE(cfg->dbusStateDir);
    cfg->dbusStateDir = g_strdup("/var/run/libvirt/qemu/dbus");

    if (!g_mkdtemp(statedir)) {
        fprintf(stderr, "Cannot create fake stateDir");
        goto error;
    }

    cfg->stateDir = g_strdup(statedir);

    if (!g_mkdtemp(configdir)) {
        fprintf(stderr, "Cannot create fake configDir");
        goto error;
    }

    cfg->configDir = g_strdup(configdir);

    driver->caps = testQemuCapsInit();
    if (!driver->caps)
        goto error;

    /* Using /dev/null for libDir and cacheDir automatically produces errors
     * upon attempt to use any of them */
    driver->qemuCapsCache = virQEMUCapsCacheNew("/dev/null", "/dev/null", 0, 0);
    if (!driver->qemuCapsCache)
        goto error;

    driver->nbdkitCapsCache = qemuNbdkitCapsCacheNew("/dev/null");
    /* the nbdkitCapsCache just interprets the presence of a non-null private
     * data pointer as a signal to skip cache validation. This prevents the
     * cache from trying to validate the plugindir mtime, etc during test */
    virFileCacheSetPriv(driver->nbdkitCapsCache, GUINT_TO_POINTER(1));

    driver->xmlopt = virQEMUDriverCreateXMLConf(driver, "none");
    if (!driver->xmlopt)
        goto error;

    if (!(mgr = virSecurityManagerNew("none", "qemu",
                                      VIR_SECURITY_MANAGER_PRIVILEGED)))
        goto error;
    if (!(driver->securityManager = virSecurityManagerNewStack(mgr)))
        goto error;

    qemuTestSetHostCPU(driver, driver->hostarch, NULL);

    VIR_FREE(cfg->vncTLSx509certdir);
    cfg->vncTLSx509certdir = g_strdup("/etc/pki/libvirt-vnc");
    VIR_FREE(cfg->spiceTLSx509certdir);
    cfg->spiceTLSx509certdir = g_strdup("/etc/pki/libvirt-spice");
    VIR_FREE(cfg->chardevTLSx509certdir);
    cfg->chardevTLSx509certdir = g_strdup("/etc/pki/libvirt-chardev");
    VIR_FREE(cfg->vxhsTLSx509certdir);
    cfg->vxhsTLSx509certdir = g_strdup("/etc/pki/libvirt-vxhs");
    VIR_FREE(cfg->nbdTLSx509certdir);
    cfg->nbdTLSx509certdir = g_strdup("/etc/pki/libvirt-nbd");
    VIR_FREE(cfg->migrateTLSx509certdir);
    cfg->migrateTLSx509certdir = g_strdup("/etc/pki/libvirt-migrate");
    VIR_FREE(cfg->backupTLSx509certdir);
    cfg->backupTLSx509certdir = g_strdup("/etc/pki/libvirt-backup");

    VIR_FREE(cfg->vncSASLdir);
    cfg->vncSASLdir = g_strdup("/etc/sasl2");
    VIR_FREE(cfg->spiceSASLdir);
    cfg->spiceSASLdir = g_strdup("/etc/sasl2");

    VIR_FREE(cfg->spicePassword);
    cfg->spicePassword = g_strdup("123456");

    VIR_FREE(cfg->hugetlbfs);
    cfg->hugetlbfs = g_new0(virHugeTLBFS, 2);
    cfg->nhugetlbfs = 2;
    cfg->hugetlbfs[0].mnt_dir = g_strdup("/dev/hugepages2M");
    cfg->hugetlbfs[1].mnt_dir = g_strdup("/dev/hugepages1G");
    cfg->hugetlbfs[0].size = 2048;
    cfg->hugetlbfs[0].deflt = true;
    cfg->hugetlbfs[1].size = 1048576;

    driver->privileged = true;

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


struct testQemuCapsFile {
    unsigned long long ver;
    char *path;
};


static void
testQemuCapsFileFree(struct testQemuCapsFile *f)
{
    if (!f)
        return;

    g_free(f->path);
    g_free(f);
}


char *
testQemuGetLatestCapsForArch(const char *arch,
                             const char *suffix)
{
    g_autoptr(GHashTable) caps = testQemuGetLatestCaps();
    struct testQemuCapsFile *f;

    if (!(f = g_hash_table_lookup(caps, arch))) {
        VIR_TEST_VERBOSE("failed to find capabilities for '%s' in '%s'",
                         arch, TEST_QEMU_CAPS_PATH);
        return NULL;
    }

    if (STRNEQ(suffix, "xml")) {
        ignore_value(virStringStripSuffix(f->path, "xml"));
        return g_strdup_printf("%s%s", f->path, suffix);
    }

    return g_steal_pointer(&f->path);
}

GHashTable *
testQemuGetLatestCaps(void)
{
    g_autoptr(GHashTable) caps = virHashNew((GDestroyNotify)testQemuCapsFileFree);
    struct dirent *ent;
    g_autoptr(DIR) dir = NULL;
    int rc;

    if (virDirOpen(&dir, TEST_QEMU_CAPS_PATH) < 0)
        return NULL;

    while ((rc = virDirRead(dir, &ent, TEST_QEMU_CAPS_PATH)) > 0) {
        g_autofree char *version = NULL;
        char *arch = NULL;
        unsigned long long ver;
        struct testQemuCapsFile *f;

        if (!(version = g_strdup(STRSKIP(ent->d_name, "caps_"))))
            continue;

        if (!virStringStripSuffix(version, ".xml"))
            continue;

        if (!(arch = strchr(version, '_'))) {
            VIR_TEST_VERBOSE("malformed caps file name '%s'", ent->d_name);
            return NULL;
        }

        *arch = '\0';
        arch++;

        if (virStringParseVersion(&ver, version, false) < 0) {
            VIR_TEST_VERBOSE("malformed caps file name '%s'", ent->d_name);
            return NULL;
        }

        if (!(f = g_hash_table_lookup(caps, arch))) {
            VIR_TEST_DEBUG("CAPS: '%s': 'X' -> '%llu'", arch, ver);
            f = g_new0(struct testQemuCapsFile, 1);
            f->ver = ver;
            f->path = g_strdup_printf("%s/%s", TEST_QEMU_CAPS_PATH, ent->d_name);
            g_hash_table_insert(caps, g_strdup(arch), f);
            continue;
        }

        if (f->ver < ver) {
            VIR_TEST_DEBUG("CAPS: '%s': '%llu' -> '%llu'", arch, f->ver, ver);
            f->ver = ver;
            g_free(f->path);
            f->path = g_strdup_printf("%s/%s", TEST_QEMU_CAPS_PATH, ent->d_name);
        }
    }

    if (rc < 0)
        return NULL;

    return g_steal_pointer(&caps);
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
        g_autofree char *variant = NULL;
        char *var;

        /* Strip the trailing suffix, moving on if it's not present */
        if (!virStringStripSuffix(tmp, suffix))
            continue;

        /* Strip the leading prefix */
        if (!(version = STRSKIP(tmp, "caps_"))) {
            VIR_TEST_VERBOSE("malformed file name '%s'", ent->d_name);
            return -1;
        }

        /* Find the underscore separating version from arch */
        if (!(archName = strchr(version, '_'))) {
            VIR_TEST_VERBOSE("malformed file name '%s'", ent->d_name);
            return -1;
        }

        /* The version number and the architecture name are separated by
         * a underscore: overwriting that underscore with \0 results in both
         * being usable as independent, null-terminated strings */
        archName[0] = '\0';
        archName++;

        /* Find the 'variant' of the test and split it including the leading '+' */
        if ((var = strchr(archName, '+'))) {
            variant = g_strdup(var);
            var[0] = '\0';
        } else {
            variant = g_strdup("");
        }

        /* Run the user-provided callback.
         *
         * We skip the dot that, as verified earlier, starts the suffix
         * to make it nicer to rebuild the original file name from inside
         * the callback.
         */
        if (callback(TEST_QEMU_CAPS_PATH, "caps", version,
                     archName, variant, suffix + 1, opaque) < 0)
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

    info->conf = conf;
    info->args.newargs = true;

    va_start(argptr, conf);
    while ((argname = va_arg(argptr, testQemuInfoArgName)) != ARG_END) {
        switch (argname) {
        case ARG_QEMU_CAPS:
            if (!(info->args.fakeCapsAdd))
                info->args.fakeCapsAdd = virBitmapNew(QEMU_CAPS_LAST);

            while ((flag = va_arg(argptr, int)) < QEMU_CAPS_LAST)
                ignore_value(virBitmapSetBit(info->args.fakeCapsAdd, flag));
            break;

        case ARG_QEMU_CAPS_DEL:
            if (!(info->args.fakeCapsDel))
                info->args.fakeCapsDel = virBitmapNew(QEMU_CAPS_LAST);

            while ((flag = va_arg(argptr, int)) < QEMU_CAPS_LAST)
                ignore_value(virBitmapSetBit(info->args.fakeCapsDel, flag));
            break;

        case ARG_NBDKIT_CAPS:
            if (!(info->args.fakeNbdkitCaps))
                info->args.fakeNbdkitCaps = virBitmapNew(QEMU_NBDKIT_CAPS_LAST);

            while ((flag = va_arg(argptr, int)) < QEMU_NBDKIT_CAPS_LAST)
                ignore_value(virBitmapSetBit(info->args.fakeNbdkitCaps, flag));
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

        case ARG_CAPS_VARIANT:
            info->args.capsvariant = va_arg(argptr, char *);
            break;

        case ARG_CAPS_HOST_CPU_MODEL:
            info->args.capsHostCPUModel = va_arg(argptr, int);
            break;

        case ARG_FD_GROUP: {
            virStorageSourceFDTuple *new = virStorageSourceFDTupleNew();
            const char *fdname = va_arg(argptr, char *);
            VIR_AUTOCLOSE fakefd = open("/dev/zero", O_RDWR);
            size_t i;

            new->nfds = va_arg(argptr, unsigned int);
            new->fds = g_new0(int, new->nfds);
            new->testfds = g_new0(int, new->nfds);

            for (i = 0; i < new->nfds; i++) {
                new->testfds[i] = va_arg(argptr, unsigned int);

                if (fcntl(new->testfds[i], F_GETFD) != -1) {
                    fprintf(stderr, "fd '%d' is already in use\n", new->fds[i]);
                    abort();
                }

                if ((new->fds[i] = dup(fakefd)) < 0) {
                    fprintf(stderr, "failed to duplicate fake fd: %s",
                            g_strerror(errno));
                    abort();
                }
            }

            if (!info->args.fds)
                info->args.fds = virHashNew(g_object_unref);

            g_hash_table_insert(info->args.fds, g_strdup(fdname), new);
            break;
        }

        case ARG_VDPA_FD: {
            const char *vdpadev = va_arg(argptr, char *);
            int vdpafd = va_arg(argptr, unsigned int);

            if (!info->args.vdpafds)
                info->args.vdpafds = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

            g_hash_table_insert(info->args.vdpafds, g_strdup(vdpadev), GINT_TO_POINTER(vdpafd));
            break;
        }

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


/**
 * See testQemuGetRealCaps, this helper returns the pointer to the virQEMUCaps
 * object as stored in the cache hash table.
 */
static virQEMUCaps *
testQemuGetRealCapsInternal(const char *arch,
                            const char *version,
                            const char *variant,
                            GHashTable *capsLatestFiles,
                            GHashTable *capsCache,
                            GHashTable *schemaCache,
                            GHashTable **schema)
{
    g_autofree char *capsfile = NULL;
    bool stripmachinealiases = false;
    virQEMUCaps *cachedcaps = NULL;

    if (STREQ(version, "latest")) {
        g_autofree char *archvariant = g_strdup_printf("%s%s", arch, variant);
        struct testQemuCapsFile *f = g_hash_table_lookup(capsLatestFiles, archvariant);

        if (!f) {
            VIR_TEST_VERBOSE("'latest' caps for '%s' were not found\n", arch);
            return NULL;
        }

        capsfile = g_strdup(f->path);
        stripmachinealiases = true;
    } else {
        capsfile = g_strdup_printf("%s/caps_%s_%s%s.xml",
                                   TEST_QEMU_CAPS_PATH,
                                   version, arch, variant);
    }

    if (!g_hash_table_lookup_extended(capsCache, capsfile, NULL, (void **) &cachedcaps)) {
        if (!(cachedcaps = qemuTestParseCapabilitiesArch(virArchFromString(arch), capsfile))) {
            VIR_TEST_VERBOSE("Failed to parse qemu capabilities file '%s'", capsfile);
            return NULL;
        }

        if (stripmachinealiases)
            virQEMUCapsStripMachineAliases(cachedcaps);

        g_hash_table_insert(capsCache, g_strdup(capsfile), cachedcaps);
    }

    /* strip 'xml' suffix so that we can format the file to '.replies' */
    capsfile[strlen(capsfile) - 3] = '\0';

    if (schemaCache && schema) {
        g_autofree char *schemafile = g_strdup_printf("%sreplies", capsfile);

        if (!g_hash_table_lookup_extended(schemaCache, schemafile, NULL, (void **) schema)) {
            *schema = testQEMUSchemaLoad(schemafile);
            g_hash_table_insert(schemaCache, g_strdup(schemafile), *schema);
        }
    }

    return cachedcaps;
}


/**
 * testQemuGetRealCaps:
 *
 * @arch: architecture to fetch caps for
 * @version: qemu version to fetch caps for ("latest" for fetching the latest version from @capsLatestFiles)
 * @variant: capabilities variant to fetch caps for
 * @capsLatestFiles: hash table containing latest version of capabilities for the  @arch+@variant tuple
 * @capsCache: hash table filled with the cache of capabilities
 * @schemaCache: hash table for caching QMP schemas (may be NULL, see below)
 * @schema: Filled with the QMP schema (hash table) (may be NULL, see below)
 *
 * Fetches and returns the appropriate virQEMUCaps for the @arch+@version+@variant
 * tuple. The returned pointer is a copy of the cached object and thus can
 * be freely modified. Caller is responsible for freeing it.
 *
 * If @schemaCache and @schema are non-NULL, @schema is filled with with a
 * pointer (borrowed from the cache) to the hash table representing the QEMU QMP
 * schema used for validation of the monitor traffic.
 */
virQEMUCaps *
testQemuGetRealCaps(const char *arch,
                    const char *version,
                    const char *variant,
                    GHashTable *capsLatestFiles,
                    GHashTable *capsCache,
                    GHashTable *schemaCache,
                    GHashTable **schema)
{
    virQEMUCaps *cachedcaps;

    if (!(cachedcaps = testQemuGetRealCapsInternal(arch, version, variant,
                                                  capsLatestFiles, capsCache,
                                                  schemaCache, schema)))
        return NULL;

    return virQEMUCapsNewCopy(cachedcaps);
}


/**
 * testQemuInsertRealCaps:
 *
 * @arch: architecture to fetch caps for
 * @version: qemu version to fetch caps for ("latest" for fetching the latest version from @capsLatestFiles)
 * @variant: capabilities variant to fetch caps for
 * @capsLatestFiles: hash table containing latest version of capabilities for the  @arch+@variant tuple
 * @capsCache: hash table filled with the cache of capabilities
 * @schemaCache: hash table for caching QMP schemas (may be NULL, see below)
 * @schema: Filled with the QMP schema (hash table) (may be NULL, see below)
 *
 * Fetches and inserts into the test capability cache the appropriate virQEMUCaps
 * for the @arch+@version+@variant tuple. Note that the data inserted into
 * the cache is borrowed from the cache thus must not be further modified.
 *
 * If @schemaCache and @schema are non-NULL, @schema is filled with with a
 * pointer (borrowed from the cache) to the hash table representing the QEMU QMP
 * schema used for validation of the monitor traffic.
 */
int
testQemuInsertRealCaps(virFileCache *cache,
                       const char *arch,
                       const char *version,
                       const char *variant,
                       GHashTable *capsLatestFiles,
                       GHashTable *capsCache,
                       GHashTable *schemaCache,
                       GHashTable **schema)
{
    virQEMUCaps *cachedcaps;

    virFileCacheClear(cache);

    if (!(cachedcaps = testQemuGetRealCapsInternal(arch, version, variant,
                                                  capsLatestFiles, capsCache,
                                                  schemaCache, schema)))
        return -1;

    if (qemuTestCapsCacheInsertData(cache, virQEMUCapsGetBinary(cachedcaps), cachedcaps) < 0)
        return -1;

    return 0;
}


int
testQemuInfoInitArgs(struct testQemuInfo *info)
{
    ssize_t cap;

    if (!info->args.newargs)
        return 0;

    info->args.newargs = false;

    if (!info->args.capsvariant)
        info->args.capsvariant = "";

    if (info->args.invalidarg) {
        fprintf(stderr, "Invalid argument encountered by 'testQemuInfoSetArgs'\n");
        return -1;
    }

    if (!!info->args.capsarch ^ !!info->args.capsver) {
        fprintf(stderr, "ARG_CAPS_ARCH and ARG_CAPS_VER must be specified together.\n");
        return -1;
    }

    if (info->args.capsarch && info->args.capsver) {
        info->arch = virArchFromString(info->args.capsarch);
        info->flags |= FLAG_REAL_CAPS;
        info->qemuCaps = testQemuGetRealCaps(info->args.capsarch,
                                             info->args.capsver,
                                             info->args.capsvariant,
                                             info->conf->capslatest,
                                             info->conf->capscache,
                                             info->conf->qapiSchemaCache,
                                             &info->qmpSchema);

        if (!info->qemuCaps)
            return -1;
    } else {
        info->qemuCaps = virQEMUCapsNew();
    }

    for (cap = -1; (cap = virBitmapNextSetBit(info->args.fakeCapsAdd, cap)) >= 0;)
        virQEMUCapsSet(info->qemuCaps, cap);

    for (cap = -1; (cap = virBitmapNextSetBit(info->args.fakeCapsDel, cap)) >= 0;)
        virQEMUCapsClear(info->qemuCaps, cap);

    info->nbdkitCaps = qemuNbdkitCapsNew(TEST_NBDKIT_PATH);

    for (cap = -1; (cap = virBitmapNextSetBit(info->args.fakeNbdkitCaps, cap)) >= 0;)
        qemuNbdkitCapsSet(info->nbdkitCaps, cap);

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
    VIR_FREE(info->errfile);
    virObjectUnref(info->qemuCaps);
    g_clear_pointer(&info->args.fakeCapsAdd, virBitmapFree);
    g_clear_pointer(&info->args.fakeCapsDel, virBitmapFree);
    g_clear_pointer(&info->args.fds, g_hash_table_unref);
    g_clear_object(&info->nbdkitCaps);
    g_clear_pointer(&info->args.fakeNbdkitCaps, virBitmapFree);
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
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        fakesourcefd = 1750;

        if (fcntl(fakesourcefd, F_GETFD) != -1)
            abort();

        charpriv->sourcefd = qemuFDPassNew(devalias, priv);
        qemuFDPassAddFD(charpriv->sourcefd, &fakesourcefd, "-source");
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (chardev->data.nix.listen) {
            g_autofree char *name = g_strdup_printf("%s-source", devalias);
            fakesourcefd = 1729;

            charpriv->directfd = qemuFDPassDirectNew(name, &fakesourcefd);
        }

        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    if (chardev->logfile) {
        int fd = 1751;

        if (fcntl(fd, F_GETFD) != -1)
            abort();

        charpriv->logfd = qemuFDPassNew(devalias, priv);

        qemuFDPassAddFD(charpriv->logfd, &fd, "-log");
    }

    return 0;
}
