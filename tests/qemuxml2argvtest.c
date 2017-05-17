#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "viralloc.h"
# include "qemu/qemu_alias.h"
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_domain.h"
# include "qemu/qemu_migration.h"
# include "qemu/qemu_process.h"
# include "datatypes.h"
# include "conf/storage_conf.h"
# include "cpu/cpu_map.h"
# include "virstring.h"
# include "storage/storage_driver.h"
# include "virmock.h"

# define __QEMU_CAPSPRIV_H_ALLOW__
# include "qemu/qemu_capspriv.h"
# undef __QEMU_CAPSPRIV_H_ALLOW__

# include "testutilsqemu.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

static const char *abs_top_srcdir;
static virQEMUDriver driver;

static unsigned char *
fakeSecretGetValue(virSecretPtr obj ATTRIBUTE_UNUSED,
                   size_t *value_size,
                   unsigned int fakeflags ATTRIBUTE_UNUSED,
                   unsigned int internalFlags ATTRIBUTE_UNUSED)
{
    char *secret;
    if (VIR_STRDUP(secret, "AQCVn5hO6HzFAhAAq0NCv8jtJcIcE+HOBlMQ1A") < 0)
        return NULL;
    *value_size = strlen(secret);
    return (unsigned char *) secret;
}

static virSecretPtr
fakeSecretLookupByUsage(virConnectPtr conn,
                        int usageType,
                        const char *usageID)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    if (usageType == VIR_SECRET_USAGE_TYPE_VOLUME) {
        if (!STRPREFIX(usageID, "/storage/guest_disks/")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "test provided invalid volume storage prefix '%s'",
                           usageID);
            return NULL;
        }
    } else if (STRNEQ(usageID, "mycluster_myname")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "test provided incorrect usage '%s'", usageID);
        return NULL;
    }

    if (virUUIDGenerate(uuid) < 0)
        return NULL;

    return virGetSecret(conn, uuid, usageType, usageID);
}

static virSecretPtr
fakeSecretLookupByUUID(virConnectPtr conn,
                       const unsigned char *uuid)
{
    return virGetSecret(conn, uuid, 0, "");
}

static virSecretDriver fakeSecretDriver = {
    .connectNumOfSecrets = NULL,
    .connectListSecrets = NULL,
    .secretLookupByUUID = fakeSecretLookupByUUID,
    .secretLookupByUsage = fakeSecretLookupByUsage,
    .secretDefineXML = NULL,
    .secretGetXMLDesc = NULL,
    .secretSetValue = NULL,
    .secretGetValue = fakeSecretGetValue,
    .secretUndefine = NULL,
};


# define STORAGE_POOL_XML_PATH "storagepoolxml2xmlout/"
static const unsigned char fakeUUID[VIR_UUID_BUFLEN] = "fakeuuid";

static virStoragePoolPtr
fakeStoragePoolLookupByName(virConnectPtr conn,
                            const char *name)
{
    char *xmlpath = NULL;
    virStoragePoolPtr ret = NULL;

    if (STRNEQ(name, "inactive")) {
        if (virAsprintf(&xmlpath, "%s/%s%s.xml",
                        abs_srcdir,
                        STORAGE_POOL_XML_PATH,
                        name) < 0)
            return NULL;

        if (!virFileExists(xmlpath)) {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           "File '%s' not found", xmlpath);
            goto cleanup;
        }
    }

    ret = virGetStoragePool(conn, name, fakeUUID, NULL, NULL);

 cleanup:
    VIR_FREE(xmlpath);
    return ret;
}


static virStorageVolPtr
fakeStorageVolLookupByName(virStoragePoolPtr pool,
                           const char *name)
{
    char **volinfo = NULL;
    virStorageVolPtr ret = NULL;

    if (STREQ(pool->name, "inactive")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "storage pool '%s' is not active", pool->name);
        return NULL;
    }

    if (STREQ(name, "nonexistent")) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       "no storage vol with matching name '%s'", name);
        return NULL;
    }

    if (!strchr(name, '+'))
        goto fallback;

    if (!(volinfo = virStringSplit(name, "+", 2)))
        return NULL;

    if (!volinfo[1])
        goto fallback;

    ret = virGetStorageVol(pool->conn, pool->name, volinfo[1], volinfo[0],
                           NULL, NULL);

 cleanup:
    virStringListFree(volinfo);
    return ret;

 fallback:
    ret = virGetStorageVol(pool->conn, pool->name, name, "block", NULL, NULL);
    goto cleanup;
}

static int
fakeStorageVolGetInfo(virStorageVolPtr vol,
                      virStorageVolInfoPtr info)
{
    memset(info, 0, sizeof(*info));

    info->type = virStorageVolTypeFromString(vol->key);

    if (info->type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid volume type '%s'", vol->key);
        return -1;
    }

    return 0;
}


static char *
fakeStorageVolGetPath(virStorageVolPtr vol)
{
    char *ret = NULL;

    ignore_value(virAsprintf(&ret, "/some/%s/device/%s", vol->key, vol->name));

    return ret;
}


static char *
fakeStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                          unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    char *xmlpath = NULL;
    char *xmlbuf = NULL;

    if (STREQ(pool->name, "inactive")) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        return NULL;
    }

    if (virAsprintf(&xmlpath, "%s/%s%s.xml",
                    abs_srcdir,
                    STORAGE_POOL_XML_PATH,
                    pool->name) < 0)
        return NULL;

    if (virTestLoadFile(xmlpath, &xmlbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "failed to load XML file '%s'",
                       xmlpath);
        goto cleanup;
    }

 cleanup:
    VIR_FREE(xmlpath);

    return xmlbuf;
}

static int
fakeStoragePoolIsActive(virStoragePoolPtr pool)
{
    if (STREQ(pool->name, "inactive"))
        return 0;

    return 1;
}

/* Test storage pool implementation
 *
 * These functions aid testing of storage pool related stuff when creating a
 * qemu command line.
 *
 * There are a few "magic" values to pass to these functions:
 *
 * 1) "inactive" as a pool name to create an inactive pool. All other names are
 * interpreted as file names in storagepoolxml2xmlout/ and are used as the
 * definition for the pool. If the file doesn't exist the pool doesn't exist.
 *
 * 2) "nonexistent" returns an error while looking up a volume. Otherwise
 * pattern VOLUME_TYPE+VOLUME_PATH can be used to simulate a volume in a pool.
 * This creates a fake path for this volume. If the '+' sign is omitted, block
 * type is assumed.
 */
static virStorageDriver fakeStorageDriver = {
    .storagePoolLookupByName = fakeStoragePoolLookupByName,
    .storageVolLookupByName = fakeStorageVolLookupByName,
    .storagePoolGetXMLDesc = fakeStoragePoolGetXMLDesc,
    .storageVolGetPath = fakeStorageVolGetPath,
    .storageVolGetInfo = fakeStorageVolGetInfo,
    .storagePoolIsActive = fakeStoragePoolIsActive,
};

typedef enum {
    FLAG_EXPECT_FAILURE     = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR = 1 << 1,
    FLAG_JSON               = 1 << 2,
    FLAG_FIPS               = 1 << 3,
} virQemuXML2ArgvTestFlags;

struct testInfo {
    const char *name;
    virQEMUCapsPtr qemuCaps;
    const char *migrateFrom;
    int migrateFd;
    unsigned int flags;
    unsigned int parseFlags;
    bool skipLegacyCPUs;
};


static int
testAddCPUModels(virQEMUCapsPtr caps, bool skipLegacy)
{
    virArch arch = virQEMUCapsGetArch(caps);
    const char *x86Models[] = {
        "Opteron_G3", "Opteron_G2", "Opteron_G1",
        "Nehalem", "Penryn", "Conroe",
        "Haswell-noTSX", "Haswell",
    };
    const char *x86LegacyModels[] = {
        "n270", "athlon", "pentium3", "pentium2", "pentium",
        "486", "coreduo", "kvm32", "qemu32", "kvm64",
        "core2duo", "phenom", "qemu64",
    };
    const char *armModels[] = {
        "cortex-a9", "cortex-a8", "cortex-a57", "cortex-a53",
    };
    const char *ppc64Models[] = {
        "POWER8", "POWER7",
    };
    const char *s390xModels[] = {
        "z990", "zEC12", "z13",
    };

    if (ARCH_IS_X86(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, x86Models,
                                         ARRAY_CARDINALITY(x86Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, x86Models,
                                         ARRAY_CARDINALITY(x86Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;

        if (!skipLegacy) {
            if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM,
                                             x86LegacyModels,
                                             ARRAY_CARDINALITY(x86LegacyModels),
                                             VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
                virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU,
                                             x86LegacyModels,
                                             ARRAY_CARDINALITY(x86LegacyModels),
                                             VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
                return -1;
        }
    } else if (ARCH_IS_ARM(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, armModels,
                                         ARRAY_CARDINALITY(armModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, armModels,
                                         ARRAY_CARDINALITY(armModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    } else if (ARCH_IS_PPC64(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, ppc64Models,
                                         ARRAY_CARDINALITY(ppc64Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, ppc64Models,
                                         ARRAY_CARDINALITY(ppc64Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    } else if (ARCH_IS_S390(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, s390xModels,
                                         ARRAY_CARDINALITY(s390xModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    }

    return 0;
}


static int
testInitQEMUCaps(struct testInfo *info,
                 int gic)
{
    int ret = -1;

    if (!(info->qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    if (testQemuCapsSetGIC(info->qemuCaps, gic) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
testUpdateQEMUCaps(const struct testInfo *info,
                   virDomainObjPtr vm,
                   virCapsPtr caps)
{
    int ret = -1;

    virQEMUCapsSetArch(info->qemuCaps, vm->def->os.arch);

    virQEMUCapsInitQMPBasicArch(info->qemuCaps);

    /* We need to pretend QEMU 2.0.0 is in use so that pSeries guests
     * will get the correct alias assigned to their buses.
     * See virQEMUCapsHasPCIMultiBus() */
    virQEMUCapsSetVersion(info->qemuCaps, 2000000);

    if (testAddCPUModels(info->qemuCaps, info->skipLegacyCPUs) < 0)
        goto cleanup;

    virQEMUCapsInitHostCPUModel(info->qemuCaps, caps, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(info->qemuCaps, caps, VIR_DOMAIN_VIRT_QEMU);

    virQEMUCapsFilterByMachineType(info->qemuCaps, vm->def->os.machine);

    ret = 0;

 cleanup:
    return ret;
}


static int
testCompareXMLToArgv(const void *data)
{
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;
    char *migrateURI = NULL;
    char *actualargv = NULL;
    unsigned int flags = info->flags;
    unsigned int parseFlags = info->parseFlags;
    int ret = -1;
    virDomainObjPtr vm = NULL;
    virDomainChrSourceDef monitor_chr;
    virConnectPtr conn;
    char *log = NULL;
    virCommandPtr cmd = NULL;
    size_t i;
    qemuDomainObjPrivatePtr priv = NULL;

    memset(&monitor_chr, 0, sizeof(monitor_chr));

    if (!(conn = virGetConnect()))
        goto cleanup;

    conn->secretDriver = &fakeSecretDriver;
    conn->storageDriver = &fakeStorageDriver;

    if (virQEMUCapsGet(info->qemuCaps, QEMU_CAPS_MONITOR_JSON))
        flags |= FLAG_JSON;

    if (virQEMUCapsGet(info->qemuCaps, QEMU_CAPS_ENABLE_FIPS))
        flags |= FLAG_FIPS;

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
        goto cleanup;

    if (virAsprintf(&xml, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->migrateFrom &&
        !(migrateURI = qemuMigrationIncomingURI(info->migrateFrom,
                                                info->migrateFd)))
        goto cleanup;

    if (!(vm = virDomainObjNew(driver.xmlopt)))
        goto cleanup;

    parseFlags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;
    if (!(vm->def = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                          NULL, parseFlags))) {
        if (flags & FLAG_EXPECT_PARSE_ERROR)
            goto ok;
        goto cleanup;
    }
    priv = vm->privateData;

    if (virBitmapParse("0-3", &priv->autoNodeset, 4) < 0)
        goto cleanup;

    if (!virDomainDefCheckABIStability(vm->def, vm->def, driver.xmlopt)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", xml);
        goto cleanup;
    }

    vm->def->id = -1;

    if (qemuProcessPrepareMonitorChr(&monitor_chr, priv->libDir) < 0)
        goto cleanup;

    if (testUpdateQEMUCaps(info, vm, driver.caps) < 0)
        goto cleanup;

    log = virTestLogContentAndReset();
    VIR_FREE(log);
    virResetLastError();

    for (i = 0; i < vm->def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];

        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            hostdev->source.subsys.u.pci.backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT) {
            hostdev->source.subsys.u.pci.backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM;
        }
    }

    if (!(cmd = qemuProcessCreatePretendCmd(conn, &driver, vm, migrateURI,
                                            (flags & FLAG_FIPS), false,
                                            VIR_QEMU_PROCESS_START_COLD))) {
        if (flags & FLAG_EXPECT_FAILURE)
            goto ok;
        goto cleanup;
    }

    if (!(actualargv = virCommandToString(cmd)))
        goto cleanup;

    if (virTestCompareToFile(actualargv, args) < 0)
        goto cleanup;

    ret = 0;

 ok:
    if (ret == 0 && flags & FLAG_EXPECT_FAILURE) {
        ret = -1;
        VIR_TEST_DEBUG("Error expected but there wasn't any.\n");
        goto cleanup;
    }
    if (!virTestOOMActive()) {
        if (flags & FLAG_EXPECT_FAILURE) {
            if ((log = virTestLogContentAndReset()))
                VIR_TEST_DEBUG("Got expected error: \n%s", log);
        }
        virResetLastError();
        ret = 0;
    }

 cleanup:
    VIR_FREE(log);
    VIR_FREE(actualargv);
    virDomainChrSourceDefClear(&monitor_chr);
    virCommandFree(cmd);
    virObjectUnref(vm);
    virObjectUnref(conn);
    VIR_FREE(migrateURI);
    VIR_FREE(xml);
    VIR_FREE(args);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    bool skipLegacyCPUs = false;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = abs_srcdir "/..";

    /* Set the timezone because we are mocking the time() function.
     * If we don't do that, then localtime() may return unpredictable
     * results. In order to detect things that just work by a blind
     * chance, we need to set an virtual timezone that no libvirt
     * developer resides in. */
    if (setenv("TZ", "VIR00:30", 1) < 0) {
        perror("setenv");
        return EXIT_FAILURE;
    }

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    driver.privileged = true;

    VIR_FREE(driver.config->defaultTLSx509certdir);
    if (VIR_STRDUP_QUIET(driver.config->defaultTLSx509certdir, "/etc/pki/qemu") < 0)
        return EXIT_FAILURE;
    VIR_FREE(driver.config->vncTLSx509certdir);
    if (VIR_STRDUP_QUIET(driver.config->vncTLSx509certdir, "/etc/pki/libvirt-vnc") < 0)
        return EXIT_FAILURE;
    VIR_FREE(driver.config->spiceTLSx509certdir);
    if (VIR_STRDUP_QUIET(driver.config->spiceTLSx509certdir, "/etc/pki/libvirt-spice") < 0)
        return EXIT_FAILURE;
    VIR_FREE(driver.config->chardevTLSx509certdir);
    if (VIR_STRDUP_QUIET(driver.config->chardevTLSx509certdir, "/etc/pki/libvirt-chardev") < 0)
        return EXIT_FAILURE;

    VIR_FREE(driver.config->hugetlbfs);
    if (VIR_ALLOC_N(driver.config->hugetlbfs, 2) < 0)
        return EXIT_FAILURE;
    driver.config->nhugetlbfs = 2;
    if (VIR_STRDUP(driver.config->hugetlbfs[0].mnt_dir, "/dev/hugepages2M") < 0 ||
        VIR_STRDUP(driver.config->hugetlbfs[1].mnt_dir, "/dev/hugepages1G") < 0)
        return EXIT_FAILURE;
    driver.config->hugetlbfs[0].size = 2048;
    driver.config->hugetlbfs[0].deflt = true;
    driver.config->hugetlbfs[1].size = 1048576;
    driver.config->spiceTLS = 1;
    if (VIR_STRDUP_QUIET(driver.config->spicePassword, "123456") < 0)
        return EXIT_FAILURE;
    VIR_FREE(driver.config->memoryBackingDir);
    if (VIR_STRDUP_QUIET(driver.config->memoryBackingDir, "/var/lib/libvirt/qemu/ram") < 0)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, migrateFrom, migrateFd, flags,               \
                      parseFlags, gic, ...)                              \
    do {                                                                 \
        static struct testInfo info = {                                  \
            name, NULL, migrateFrom, migrateFd, (flags), parseFlags,     \
            false                                                        \
        };                                                               \
        info.skipLegacyCPUs = skipLegacyCPUs;                            \
        if (testInitQEMUCaps(&info, gic) < 0)                            \
            return EXIT_FAILURE;                                         \
        virQEMUCapsSetList(info.qemuCaps, __VA_ARGS__, QEMU_CAPS_LAST);  \
        if (virTestRun("QEMU XML-2-ARGV " name,                          \
                       testCompareXMLToArgv, &info) < 0)                 \
            ret = -1;                                                    \
        virObjectUnref(info.qemuCaps);                                   \
    } while (0)

# define DO_TEST(name, ...)                                              \
    DO_TEST_FULL(name, NULL, -1, 0, 0, GIC_NONE, __VA_ARGS__)

# define DO_TEST_GIC(name, gic, ...)                                     \
    DO_TEST_FULL(name, NULL, -1, 0, 0, gic, __VA_ARGS__)

# define DO_TEST_FAILURE(name, ...)                                      \
    DO_TEST_FULL(name, NULL, -1, FLAG_EXPECT_FAILURE,                    \
                 0, GIC_NONE, __VA_ARGS__)

# define DO_TEST_PARSE_ERROR(name, ...)                                  \
    DO_TEST_FULL(name, NULL, -1,                                         \
                 FLAG_EXPECT_PARSE_ERROR | FLAG_EXPECT_FAILURE,          \
                 0, GIC_NONE, __VA_ARGS__)

# define DO_TEST_PARSE_FLAGS_ERROR(name, parseFlags, ...)                \
    DO_TEST_FULL(name, NULL, -1,                                         \
                 FLAG_EXPECT_PARSE_ERROR | FLAG_EXPECT_FAILURE,          \
                 parseFlags, GIC_NONE, __VA_ARGS__)

# define DO_TEST_LINUX(name, ...)                                        \
    DO_TEST_LINUX_FULL(name, NULL, -1, 0, 0, GIC_NONE, __VA_ARGS__)

# ifdef __linux__
    /* This is a macro that invokes test only on Linux. It's
     * meant to be called in those cases where qemuxml2argvmock
     * cooperation is expected (e.g. we need a fixed time,
     * predictable NUMA topology and so on). On non-Linux
     * platforms the macro just consume its argument. */
#  define DO_TEST_LINUX_FULL(name, ...)                                  \
    DO_TEST_FULL(name, __VA_ARGS__)
# else  /* __linux__ */
#  define DO_TEST_LINUX_FULL(name, ...)                                  \
    do {                                                                 \
        const char *tmp ATTRIBUTE_UNUSED = name;                         \
    } while (0)
# endif /* __linux__ */

# define NONE QEMU_CAPS_LAST

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);
    setenv("USER", "test", 1);
    setenv("LOGNAME", "test", 1);
    setenv("HOME", "/home/test", 1);
    unsetenv("TMPDIR");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("QEMU_AUDIO_DRV");
    unsetenv("SDL_AUDIODRIVER");

    DO_TEST("minimal", NONE);
    DO_TEST_PARSE_ERROR("minimal-no-memory", NONE);
    DO_TEST("minimal-msg-timestamp", QEMU_CAPS_MSG_TIMESTAMP);
    DO_TEST("machine-aliases1", NONE);
    DO_TEST("machine-aliases2", QEMU_CAPS_KVM);
    DO_TEST("machine-core-on", QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_DUMP_GUEST_CORE);
    driver.config->dumpGuestCore = true;
    DO_TEST("machine-core-off", QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_DUMP_GUEST_CORE);
    driver.config->dumpGuestCore = false;
    DO_TEST("machine-core-cfg-off", QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_DUMP_GUEST_CORE);
    DO_TEST_FAILURE("machine-core-on", NONE);
    DO_TEST_FAILURE("machine-core-on", QEMU_CAPS_MACHINE_OPT);
    DO_TEST("machine-smm-opt",
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_SMM_OPT,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("machine-usb-opt", QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_USB_OPT);
    DO_TEST("machine-vmport-opt", QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_VMPORT_OPT);
    DO_TEST("kvm", QEMU_CAPS_MACHINE_OPT);
    DO_TEST("default-kvm-host-arch", QEMU_CAPS_MACHINE_OPT);
    DO_TEST("default-qemu-host-arch", QEMU_CAPS_MACHINE_OPT);
    DO_TEST("boot-cdrom", NONE);
    DO_TEST("boot-network", NONE);
    DO_TEST("boot-floppy", NONE);
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST("bootindex-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI, QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST("boot-multi", QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-enable",
            QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-enable-bootindex",
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST("boot-menu-enable-with-timeout",
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_SPLASH_TIMEOUT);
    DO_TEST_FAILURE("boot-menu-enable-with-timeout", QEMU_CAPS_BOOT_MENU);
    DO_TEST_PARSE_ERROR("boot-menu-enable-with-timeout-invalid", NONE);
    DO_TEST("boot-menu-disable", QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-disable-drive",
            QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-disable-drive-bootindex",
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST_PARSE_ERROR("boot-dev+order",
            QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-order",
            QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-complex",
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-complex-bootindex",
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-strict",
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_BOOT_STRICT,
            QEMU_CAPS_VIRTIO_BLK_SCSI);

    DO_TEST("reboot-timeout-disabled", QEMU_CAPS_REBOOT_TIMEOUT);
    DO_TEST("reboot-timeout-enabled", QEMU_CAPS_REBOOT_TIMEOUT);
    DO_TEST_FAILURE("reboot-timeout-enabled", NONE);

    DO_TEST("bios", QEMU_CAPS_SGA);
    DO_TEST("bios-nvram", NONE);
    DO_TEST("bios-nvram-secure",
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_SMM_OPT,
            QEMU_CAPS_VIRTIO_SCSI);

    /* Make sure all combinations of ACPI and UEFI behave as expected */
    DO_TEST("q35-acpi-uefi", NONE);
    DO_TEST_PARSE_ERROR("q35-noacpi-uefi", NONE);
    DO_TEST("q35-noacpi-nouefi", NONE);
    DO_TEST("q35-acpi-nouefi", NONE);

    DO_TEST("clock-utc", QEMU_CAPS_NODEFCONFIG);
    DO_TEST("clock-localtime", NONE);
    DO_TEST("clock-localtime-basis-localtime", QEMU_CAPS_RTC);
    DO_TEST("clock-variable", QEMU_CAPS_RTC);
    DO_TEST("clock-france", QEMU_CAPS_RTC);
    DO_TEST("clock-hpet-off", QEMU_CAPS_RTC);
    DO_TEST("clock-catchup", QEMU_CAPS_RTC);
    DO_TEST("cpu-kvmclock", QEMU_CAPS_ENABLE_KVM);
    DO_TEST("cpu-host-kvmclock", QEMU_CAPS_ENABLE_KVM);
    DO_TEST("kvmclock", QEMU_CAPS_KVM);
    DO_TEST("clock-timer-hyperv-rtc", QEMU_CAPS_KVM);

    DO_TEST("cpu-eoi-disabled", QEMU_CAPS_ENABLE_KVM);
    DO_TEST("cpu-eoi-enabled", QEMU_CAPS_ENABLE_KVM);
    DO_TEST("controller-order",
            QEMU_CAPS_KVM, QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_BOOT_MENU, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_CCID_PASSTHRU, QEMU_CAPS_CHARDEV,
            QEMU_CAPS_CHARDEV_SPICEVMC, QEMU_CAPS_SPICE,
            QEMU_CAPS_HDA_DUPLEX, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("eoi-disabled", NONE);
    DO_TEST("eoi-enabled", NONE);
    DO_TEST("pv-spinlock-disabled", NONE);
    DO_TEST("pv-spinlock-enabled", NONE);
    DO_TEST("kvmclock+eoi-disabled", QEMU_CAPS_ENABLE_KVM);

    DO_TEST("hyperv", NONE);
    DO_TEST("hyperv-off", NONE);
    DO_TEST("hyperv-panic", NONE);

    DO_TEST("kvm-features", NONE);
    DO_TEST("kvm-features-off", NONE);

    DO_TEST("pmu-feature", NONE);
    DO_TEST("pmu-feature-off", NONE);

    DO_TEST("hugepages", QEMU_CAPS_MEM_PATH);
    DO_TEST("hugepages-numa", QEMU_CAPS_RTC,
            QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_LINUX("hugepages-pages", QEMU_CAPS_MEM_PATH,
                  QEMU_CAPS_OBJECT_MEMORY_RAM,
                  QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-pages2", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-pages3", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_LINUX("hugepages-shared", QEMU_CAPS_MEM_PATH,
                  QEMU_CAPS_OBJECT_MEMORY_RAM,
                  QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_PARSE_ERROR("hugepages-memaccess-invalid", NONE);
    DO_TEST_FAILURE("hugepages-pages4", QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-pages5", QEMU_CAPS_MEM_PATH);
    DO_TEST("hugepages-pages6", NONE);
    DO_TEST("nosharepages", QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_MEM_MERGE);
    DO_TEST("disk-cdrom", NONE);
    DO_TEST("disk-iscsi", NONE);
    DO_TEST("disk-cdrom-network-http", QEMU_CAPS_KVM);
    DO_TEST("disk-cdrom-network-https", QEMU_CAPS_KVM);
    DO_TEST("disk-cdrom-network-ftp", QEMU_CAPS_KVM);
    DO_TEST("disk-cdrom-network-ftps", QEMU_CAPS_KVM);
    DO_TEST("disk-cdrom-network-tftp", QEMU_CAPS_KVM);
    DO_TEST("disk-cdrom-empty", NONE);
    DO_TEST("disk-cdrom-tray",
            QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("disk-cdrom-tray-no-device-cap", NONE);
    DO_TEST("disk-floppy", NONE);
    DO_TEST_FAILURE("disk-floppy-pseries", NONE);
    DO_TEST("disk-floppy-tray-no-device-cap", NONE);
    DO_TEST("disk-floppy-tray", NONE);
    DO_TEST("disk-virtio-s390",
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-many", NONE);
    DO_TEST("disk-virtio", QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-virtio-ccw",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-virtio-ccw-many",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-virtio-scsi-ccw", QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-order",
            QEMU_CAPS_DRIVE_BOOT, QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-drive-boot-disk",
            QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-drive-boot-cdrom",
            QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("floppy-drive-fat",
            QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-drive-readonly-disk",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-drive-readonly-no-device",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-drive-fmt-qcow",
            QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-drive-shared",
            QEMU_CAPS_DRIVE_SERIAL);
    DO_TEST("disk-drive-error-policy-stop",
            QEMU_CAPS_MONITOR_JSON);
    DO_TEST("disk-drive-error-policy-enospace",
            QEMU_CAPS_MONITOR_JSON);
    DO_TEST("disk-drive-error-policy-wreport-rignore",
            QEMU_CAPS_MONITOR_JSON);
    DO_TEST("disk-drive-cache-v2-wt", NONE);
    DO_TEST("disk-drive-cache-v2-wb", NONE);
    DO_TEST("disk-drive-cache-v2-none", NONE);
    DO_TEST("disk-drive-cache-directsync",
            QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
    DO_TEST("disk-drive-cache-unsafe",
            QEMU_CAPS_DRIVE_CACHE_UNSAFE);
    DO_TEST("disk-drive-copy-on-read",
            QEMU_CAPS_DRIVE_COPY_ON_READ);
    DO_TEST("disk-drive-network-nbd", NONE);
    DO_TEST("disk-drive-network-nbd-export", NONE);
    DO_TEST("disk-drive-network-nbd-ipv6", NONE);
    DO_TEST("disk-drive-network-nbd-ipv6-export", NONE);
    DO_TEST("disk-drive-network-nbd-unix", NONE);
    DO_TEST("disk-drive-network-iscsi", NONE);
    DO_TEST("disk-drive-network-iscsi-auth", NONE);
    DO_TEST("disk-drive-network-iscsi-lun",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("disk-drive-network-gluster",
            QEMU_CAPS_GLUSTER_DEBUG_LEVEL);
    DO_TEST("disk-drive-network-rbd", NONE);
    DO_TEST("disk-drive-network-sheepdog", NONE);
    DO_TEST("disk-drive-network-rbd-auth", NONE);
# ifdef HAVE_GNUTLS_CIPHER_ENCRYPT
    DO_TEST("disk-drive-network-rbd-auth-AES",
            QEMU_CAPS_OBJECT_SECRET, QEMU_CAPS_VIRTIO_SCSI);
# endif
    DO_TEST("disk-drive-network-rbd-ipv6", NONE);
    DO_TEST_FAILURE("disk-drive-network-rbd-no-colon", NONE);
    DO_TEST("disk-drive-no-boot",
            QEMU_CAPS_BOOTINDEX);
    DO_TEST_PARSE_ERROR("disk-device-lun-type-invalid",
                        QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FAILURE("disk-usb-nosupport", NONE);
    DO_TEST("disk-usb-device",
            QEMU_CAPS_DEVICE_USB_STORAGE,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-usb-device-removable",
            QEMU_CAPS_DEVICE_USB_STORAGE,
            QEMU_CAPS_USB_STORAGE_REMOVABLE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_FAILURE("disk-usb-pci",
                    QEMU_CAPS_DEVICE_USB_STORAGE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-device",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("disk-scsi-device-auto",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("disk-scsi-disk-split",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-scsi-disk-wwn",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST_FAILURE("disk-scsi-disk-vpd-build-error",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-scsi-vscsi",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-virtio-scsi",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-num_queues",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-cmd_per_lun",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-max_sectors",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-ioeventfd",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_IOEVENTFD, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-scsi-megasas",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_MEGASAS);
    DO_TEST("disk-scsi-mptsas1068",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SCSI_MPTSAS1068,
            QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-sata-device",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_ICH9_AHCI);
    DO_TEST("disk-aio",
            QEMU_CAPS_DRIVE_AIO);
    DO_TEST("disk-source-pool",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-source-pool-mode",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-ioeventfd",
            QEMU_CAPS_VIRTIO_IOEVENTFD,
            QEMU_CAPS_VIRTIO_TX_ALG,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-copy_on_read",
            QEMU_CAPS_DRIVE_COPY_ON_READ,
            QEMU_CAPS_VIRTIO_TX_ALG,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-drive-discard",
            QEMU_CAPS_DRIVE_DISCARD);
    DO_TEST("disk-drive-detect-zeroes",
            QEMU_CAPS_DRIVE_DISCARD,
            QEMU_CAPS_DRIVE_DETECT_ZEROES);
    DO_TEST("disk-snapshot", NONE);
    DO_TEST_PARSE_ERROR("disk-same-targets",
                        QEMU_CAPS_SCSI_LSI,
                        QEMU_CAPS_DEVICE_USB_STORAGE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("disk-drive-address-conflict",
                        QEMU_CAPS_ICH9_AHCI);
    DO_TEST_PARSE_ERROR("disk-hostdev-scsi-address-conflict",
                        QEMU_CAPS_VIRTIO_SCSI,
                        QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_PARSE_ERROR("hostdevs-drive-address-conflict",
                        QEMU_CAPS_VIRTIO_SCSI,
                        QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("event_idx",
            QEMU_CAPS_VIRTIO_BLK_EVENT_IDX,
            QEMU_CAPS_VIRTIO_NET_EVENT_IDX,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("virtio-lun",
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-scsi-lun-passthrough",
            QEMU_CAPS_SCSI_BLOCK,
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-serial",
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_SERIAL);
    DO_TEST_PARSE_ERROR("disk-fdc-incompatible-address",
                        NONE);
    DO_TEST_PARSE_ERROR("disk-ide-incompatible-address",
                        NONE);
    DO_TEST_PARSE_ERROR("disk-sata-incompatible-address",
                        QEMU_CAPS_ICH9_AHCI);
    DO_TEST_PARSE_ERROR("disk-scsi-incompatible-address",
                        QEMU_CAPS_VIRTIO_SCSI);

    DO_TEST("graphics-vnc", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-socket", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-websocket", QEMU_CAPS_VNC, QEMU_CAPS_VNC_WEBSOCKET,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-policy", QEMU_CAPS_VNC, QEMU_CAPS_VNC_SHARE_POLICY,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-no-listen-attr", QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-remove-generated-socket", QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->vncAutoUnixSocket = true;
    DO_TEST("graphics-vnc-auto-socket-cfg", QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->vncAutoUnixSocket = false;
    DO_TEST("graphics-vnc-socket", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-auto-socket", QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-none", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);

    driver.config->vncSASL = 1;
    VIR_FREE(driver.config->vncSASLdir);
    ignore_value(VIR_STRDUP(driver.config->vncSASLdir, "/root/.sasl2"));
    DO_TEST("graphics-vnc-sasl", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->vncTLS = 1;
    driver.config->vncTLSx509verify = 1;
    DO_TEST("graphics-vnc-tls", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->vncSASL = driver.config->vncTLSx509verify = driver.config->vncTLS = 0;
    VIR_FREE(driver.config->vncSASLdir);
    VIR_FREE(driver.config->vncTLSx509certdir);

    DO_TEST("graphics-sdl", QEMU_CAPS_SDL, QEMU_CAPS_DEVICE_VGA);
    DO_TEST("graphics-sdl-fullscreen", QEMU_CAPS_SDL,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("nographics", NONE);
    DO_TEST("nographics-display",
            QEMU_CAPS_DISPLAY);
    DO_TEST("nographics-vga",
            QEMU_CAPS_VGA_NONE);
    DO_TEST("graphics-spice",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE_FILE_XFER_DISABLE);
    DO_TEST("graphics-spice-no-args",
            QEMU_CAPS_SPICE, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->spiceSASL = 1;
    ignore_value(VIR_STRDUP(driver.config->spiceSASLdir, "/root/.sasl2"));
    DO_TEST("graphics-spice-sasl",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL);
    VIR_FREE(driver.config->spiceSASLdir);
    driver.config->spiceSASL = 0;
    DO_TEST("graphics-spice-agentmouse",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-spice-compression",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("graphics-spice-timeout",
            QEMU_CAPS_KVM,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_DEVICE_VGA);
    DO_TEST("graphics-spice-qxl-vga",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("graphics-spice-usb-redir",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_CHARDEV_SPICEVMC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-spice-agent-file-xfer",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE_FILE_XFER_DISABLE);
    DO_TEST("graphics-spice-socket",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-spice-auto-socket",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->spiceAutoUnixSocket = true;
    DO_TEST("graphics-spice-auto-socket-cfg",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->spiceAutoUnixSocket = false;

    DO_TEST("input-usbmouse", NONE);
    DO_TEST("input-usbtablet", NONE);
    DO_TEST("misc-acpi", NONE);
    DO_TEST("misc-disable-s3", QEMU_CAPS_PIIX_DISABLE_S3);
    DO_TEST("misc-disable-suspends", QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("misc-enable-s4", QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST_FAILURE("misc-enable-s4", NONE);
    DO_TEST("misc-no-reboot", NONE);
    DO_TEST("misc-uuid", NONE);
    DO_TEST_PARSE_ERROR("vhost_queues-invalid", NONE);
    DO_TEST("net-vhostuser", QEMU_CAPS_NETDEV);
    DO_TEST("net-vhostuser-multiq",
            QEMU_CAPS_NETDEV, QEMU_CAPS_VHOSTUSER_MULTIQUEUE);
    DO_TEST_FAILURE("net-vhostuser-multiq", QEMU_CAPS_NETDEV);
    DO_TEST_FAILURE("net-vhostuser-fail",
                    QEMU_CAPS_NETDEV,
                    QEMU_CAPS_VHOSTUSER_MULTIQUEUE);
    DO_TEST("net-user", NONE);
    DO_TEST("net-virtio", NONE);
    DO_TEST("net-virtio-device",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("net-virtio-disable-offloads",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("net-virtio-netdev",
            QEMU_CAPS_NETDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("net-virtio-s390",
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("net-virtio-ccw",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("net-virtio-rxqueuesize",
            QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE);
    DO_TEST_PARSE_ERROR("net-virtio-rxqueuesize-invalid-size", NONE);
    DO_TEST("net-eth", NONE);
    DO_TEST("net-eth-ifname", NONE);
    DO_TEST("net-eth-names", NONE);
    DO_TEST("net-eth-hostip", NONE);
    DO_TEST("net-client", NONE);
    DO_TEST("net-server", NONE);
    DO_TEST("net-mcast", NONE);
    DO_TEST("net-udp", NONE);
    DO_TEST("net-hostdev",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("net-hostdev-multidomain",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_HOST_PCI_MULTIDOMAIN);
    DO_TEST_FAILURE("net-hostdev-multidomain",
                    QEMU_CAPS_NODEFCONFIG);
    DO_TEST("net-hostdev-vfio",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-hostdev-vfio-multidomain",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI, QEMU_CAPS_HOST_PCI_MULTIDOMAIN);
    DO_TEST_FAILURE("net-hostdev-vfio-multidomain",
                    QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_FAILURE("net-hostdev-fail",
                    QEMU_CAPS_NODEFCONFIG,
                    QEMU_CAPS_DEVICE_VFIO_PCI);


    DO_TEST("serial-vc", NONE);
    DO_TEST("serial-pty", NONE);
    DO_TEST("serial-dev", NONE);
    DO_TEST("serial-file", NONE);
    DO_TEST("serial-file-log", QEMU_CAPS_CHARDEV, QEMU_CAPS_CHARDEV_FILE_APPEND,
            QEMU_CAPS_CHARDEV_LOGFILE);
    DO_TEST("serial-unix", NONE);
    DO_TEST("serial-tcp", NONE);
    DO_TEST("serial-udp", NONE);
    DO_TEST("serial-tcp-telnet", NONE);
    DO_TEST("serial-many", NONE);
    DO_TEST("serial-spiceport",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEPORT);
    DO_TEST("serial-spiceport-nospice", NONE);

    DO_TEST("parallel-tcp", NONE);
    DO_TEST("console-compat", NONE);
    DO_TEST("console-compat-auto", NONE);

    DO_TEST("serial-vc-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-pty-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-dev-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-dev-chardev-iobase",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-file-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_CHARDEV_FILE_APPEND);
    DO_TEST("serial-unix-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-tcp-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-udp-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-tcp-telnet-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    driver.config->chardevTLS = 1;
    DO_TEST("serial-tcp-tlsx509-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    driver.config->chardevTLSx509verify = 1;
    DO_TEST("serial-tcp-tlsx509-chardev-verify",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    driver.config->chardevTLSx509verify = 0;
    DO_TEST("serial-tcp-tlsx509-chardev-notls",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    VIR_FREE(driver.config->chardevTLSx509certdir);
    if (VIR_STRDUP_QUIET(driver.config->chardevTLSx509certdir, "/etc/pki/libvirt-chardev") < 0)
        return EXIT_FAILURE;
    if (VIR_STRDUP_QUIET(driver.config->chardevTLSx509secretUUID,
                         "6fd3f62d-9fe7-4a4e-a869-7acd6376d8ea") < 0)
        return EXIT_FAILURE;
# ifdef HAVE_GNUTLS_CIPHER_ENCRYPT
    DO_TEST("serial-tcp-tlsx509-secret-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_OBJECT_SECRET,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
# else
    DO_TEST_FAILURE("serial-tcp-tlsx509-secret-chardev",
                    QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
                    QEMU_CAPS_OBJECT_SECRET,
                    QEMU_CAPS_OBJECT_TLS_CREDS_X509);
# endif
    driver.config->chardevTLS = 0;
    VIR_FREE(driver.config->chardevTLSx509certdir);
    DO_TEST("serial-many-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("parallel-tcp-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("parallel-parport-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-compat-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pci-serial-dev-chardev",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_PCI_SERIAL);

    DO_TEST("channel-guestfwd",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-state",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-auto",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-autoassign",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-autoadd",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio-many",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio-s390",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("console-virtio-ccw",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("console-sclp",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_S390, QEMU_CAPS_SCLP_S390);
    DO_TEST("channel-spicevmc",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("channel-spicevmc-old",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SPICE, QEMU_CAPS_DEVICE_SPICEVMC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("channel-virtio-default",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("channel-virtio-unix",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);

    DO_TEST("smartcard-host",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-passthrough-tcp",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-passthrough-spicevmc",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_CCID_PASSTHRU, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("smartcard-controller",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);

    DO_TEST("usb-controller",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-piix3-controller",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ich9-ehci-addr",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("input-usbmouse-addr",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ich9-companion",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST_PARSE_ERROR("usb-ich9-no-companion",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("usb-ich9-autoassign",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-hub",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-hub-autoadd",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-hub-autoadd-deluxe",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-hub-conflict",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-hub-nonexistent",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-port-missing",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-bus-missing",
                        QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
                        QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ports",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-ports-out-of-range",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-port-autoassign",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-redir",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("usb-redir-boot",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC, QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_USB_REDIR_BOOTINDEX);
    DO_TEST("usb-redir-filter",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST("usb-redir-filter-version",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST("usb1-usb2",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_USB_HUB, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("usb-none",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-none-other",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("usb-none-hub",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-none-usbtablet",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-controller-default-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI);
    DO_TEST_FAILURE("usb-controller-default-unavailable-q35",
                    QEMU_CAPS_DEVICE_IOH3420,
                    QEMU_CAPS_PCI_OHCI,
                    QEMU_CAPS_NEC_USB_XHCI);
    DO_TEST("usb-controller-explicit-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI);
    DO_TEST_FAILURE("usb-controller-explicit-unavailable-q35",
                    QEMU_CAPS_DEVICE_IOH3420,
                    QEMU_CAPS_PCI_OHCI,
                    QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST("usb-controller-xhci",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI, QEMU_CAPS_NEC_USB_XHCI_PORTS);
    DO_TEST("usb-xhci-autoassign",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI, QEMU_CAPS_NEC_USB_XHCI_PORTS,
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-controller-xhci-limit",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI, QEMU_CAPS_NEC_USB_XHCI_PORTS);
    DO_TEST("usb-controller-qemu-xhci", QEMU_CAPS_DEVICE_QEMU_XHCI);
    DO_TEST_FAILURE("usb-controller-qemu-xhci-unavailable", NONE);
    DO_TEST_PARSE_ERROR("usb-controller-qemu-xhci-limit",
                        QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST("smbios", QEMU_CAPS_SMBIOS_TYPE);
    DO_TEST_PARSE_ERROR("smbios-date", QEMU_CAPS_SMBIOS_TYPE);
    DO_TEST_PARSE_ERROR("smbios-uuid-match", QEMU_CAPS_SMBIOS_TYPE);

    DO_TEST("watchdog", NONE);
    DO_TEST("watchdog-device", QEMU_CAPS_NODEFCONFIG);
    DO_TEST("watchdog-dump", NONE);
    DO_TEST("watchdog-injectnmi", NONE);
    DO_TEST("watchdog-diag288",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("balloon-device", QEMU_CAPS_NODEFCONFIG);
    DO_TEST("balloon-device-deflate", QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-ccw-deflate", QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-mmio-deflate", QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DTB, QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-device-deflate-off", QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-device-auto",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("balloon-device-period", QEMU_CAPS_NODEFCONFIG);
    DO_TEST("sound", NONE);
    DO_TEST("sound-device",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_HDA_DUPLEX, QEMU_CAPS_HDA_MICRO,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_OBJECT_USB_AUDIO);
    DO_TEST("fs9p",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT);
    DO_TEST("fs9p-ccw",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("hostdev-usb-address", NONE);
    DO_TEST("hostdev-usb-address-device",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("hostdev-usb-address-device-boot",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_USB_HOST_BOOTINDEX);
    DO_TEST("hostdev-pci-address", NONE);
    DO_TEST("hostdev-pci-address-device",
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("hostdev-vfio",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio-multidomain",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI, QEMU_CAPS_HOST_PCI_MULTIDOMAIN);
    DO_TEST("hostdev-mdev-precreated",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-mdev-src-address-invalid",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-mdev-invalid-target-address",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_FAILURE("hostdev-vfio-multidomain",
                    QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pci-rom",
            QEMU_CAPS_NODEFCONFIG);

    DO_TEST_FULL("restore-v2", "exec:cat", 7, 0, 0, GIC_NONE, NONE);
    DO_TEST_FULL("restore-v2-fd", "stdio", 7, 0, 0, GIC_NONE, NONE);
    DO_TEST_FULL("restore-v2-fd", "fd:7", 7, 0, 0, GIC_NONE, NONE);
    DO_TEST_FULL("migrate", "tcp:10.0.0.1:5000", -1, 0, 0, GIC_NONE, NONE);

    DO_TEST_LINUX_FULL("migrate-numa-unaligned", "stdio", 7, 0, 0, GIC_NONE,
                       QEMU_CAPS_NUMA,
                       QEMU_CAPS_OBJECT_MEMORY_RAM);

    DO_TEST("qemu-ns", NONE);
    DO_TEST("qemu-ns-no-env", NONE);

    DO_TEST("smp", NONE);

    DO_TEST("iothreads", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-ids", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-ids-partial", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST_FAILURE("iothreads-nocap", NONE);
    DO_TEST("iothreads-disk", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-disk-virtio-ccw", QEMU_CAPS_OBJECT_IOTHREAD,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("iothreads-virtio-scsi-pci", QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_OBJECT_IOTHREAD,
            QEMU_CAPS_VIRTIO_SCSI_IOTHREAD);
    DO_TEST("iothreads-virtio-scsi-ccw", QEMU_CAPS_OBJECT_IOTHREAD,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_SCSI_IOTHREAD,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("cpu-topology1", NONE);
    DO_TEST("cpu-topology2", NONE);
    DO_TEST("cpu-topology3", NONE);
    DO_TEST("cpu-minimum1", QEMU_CAPS_KVM);
    DO_TEST("cpu-minimum2", QEMU_CAPS_KVM);
    DO_TEST("cpu-exact1", QEMU_CAPS_KVM);
    DO_TEST("cpu-exact2", QEMU_CAPS_KVM);
    DO_TEST("cpu-exact2-nofallback", QEMU_CAPS_KVM);
    DO_TEST("cpu-fallback", QEMU_CAPS_KVM);
    DO_TEST_FAILURE("cpu-nofallback", QEMU_CAPS_KVM);
    DO_TEST("cpu-strict1", QEMU_CAPS_KVM);
    DO_TEST("cpu-numa1", NONE);
    DO_TEST("cpu-numa2", NONE);
    DO_TEST("cpu-numa-no-memory-element", NONE);
    DO_TEST_PARSE_ERROR("cpu-numa3", NONE);
    DO_TEST_FAILURE("cpu-numa-disjoint", NONE);
    DO_TEST("cpu-numa-disjoint", QEMU_CAPS_NUMA);
    DO_TEST_FAILURE("cpu-numa-memshared", QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_FAILURE("cpu-numa-memshared", NONE);
    DO_TEST("cpu-host-model", NONE);
    DO_TEST("cpu-host-model-vendor", NONE);
    skipLegacyCPUs = true;
    DO_TEST("cpu-host-model-fallback", NONE);
    DO_TEST_FAILURE("cpu-host-model-nofallback", NONE);
    skipLegacyCPUs = false;
    DO_TEST("cpu-host-passthrough", QEMU_CAPS_KVM);
    DO_TEST_FAILURE("cpu-host-passthrough", NONE);
    DO_TEST_FAILURE("cpu-qemu-host-passthrough", QEMU_CAPS_KVM);

    qemuTestSetHostArch(driver.caps, VIR_ARCH_S390X);
    DO_TEST("cpu-s390-zEC12", QEMU_CAPS_KVM, QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("cpu-s390-features", QEMU_CAPS_KVM, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION);
    DO_TEST_FAILURE("cpu-s390-features", QEMU_CAPS_KVM);
    qemuTestSetHostArch(driver.caps, VIR_ARCH_NONE);

    qemuTestSetHostCPU(driver.caps, cpuHaswell);
    DO_TEST("cpu-Haswell", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell2", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell3", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell-noTSX", QEMU_CAPS_KVM);
    DO_TEST("cpu-host-model-cmt", NONE);
    DO_TEST("cpu-tsc-frequency", QEMU_CAPS_KVM);
    qemuTestSetHostCPU(driver.caps, NULL);

    DO_TEST("encrypted-disk", NONE);
    DO_TEST("encrypted-disk-usage", NONE);
# ifdef HAVE_GNUTLS_CIPHER_ENCRYPT
    DO_TEST("luks-disks", QEMU_CAPS_OBJECT_SECRET);
# else
    DO_TEST_FAILURE("luks-disks", QEMU_CAPS_OBJECT_SECRET);
# endif

    DO_TEST("memtune", NONE);
    DO_TEST("memtune-unlimited", NONE);
    DO_TEST("blkiotune", NONE);
    DO_TEST("blkiotune-device", NONE);
    DO_TEST("cputune", NONE);
    DO_TEST("cputune-zero-shares", NONE);
    DO_TEST_PARSE_ERROR("cputune-iothreadsched-toomuch", NONE);
    DO_TEST_PARSE_ERROR("cputune-vcpusched-overlap", NONE);
    DO_TEST("cputune-numatune",
            QEMU_CAPS_KVM,
            QEMU_CAPS_OBJECT_IOTHREAD,
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("vcpu-placement-static",
            QEMU_CAPS_KVM,
            QEMU_CAPS_OBJECT_IOTHREAD);

    DO_TEST("numatune-memory", NONE);
    DO_TEST_PARSE_ERROR("numatune-memory-invalid-nodeset", NONE);
    DO_TEST_LINUX("numatune-memnode", QEMU_CAPS_NUMA,
                  QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_FAILURE("numatune-memnode", NONE);

    DO_TEST_LINUX("numatune-memnode-no-memory", QEMU_CAPS_NUMA,
                  QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_FAILURE("numatune-memnode-no-memory", NONE);

    DO_TEST("numatune-auto-nodeset-invalid", NONE);
    DO_TEST("numatune-auto-prefer", QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_FAILURE("numatune-static-nodeset-exceed-hostnode",
                    QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_PARSE_ERROR("numatune-memnode-nocpu", NONE);
    DO_TEST_PARSE_ERROR("numatune-memnodes-problematic", NONE);
    DO_TEST("numad", NONE);
    DO_TEST("numad-auto-vcpu-static-numatune", NONE);
    DO_TEST_PARSE_ERROR("numad-auto-vcpu-static-numatune-no-nodeset", NONE);
    DO_TEST("numad-auto-memory-vcpu-cpuset", NONE);
    DO_TEST("numad-auto-memory-vcpu-no-cpuset-and-placement", NONE);
    DO_TEST("numad-static-memory-auto-vcpu", NONE);
    DO_TEST("blkdeviotune",
            QEMU_CAPS_DRIVE_IOTUNE);
    DO_TEST("blkdeviotune-max",
            QEMU_CAPS_DRIVE_IOTUNE,
            QEMU_CAPS_DRIVE_IOTUNE_MAX);
    DO_TEST("blkdeviotune-group-num",
            QEMU_CAPS_DRIVE_IOTUNE,
            QEMU_CAPS_DRIVE_IOTUNE_MAX,
            QEMU_CAPS_DRIVE_IOTUNE_GROUP);
    DO_TEST("blkdeviotune-max-length",
            QEMU_CAPS_DRIVE_IOTUNE,
            QEMU_CAPS_DRIVE_IOTUNE_MAX,
            QEMU_CAPS_DRIVE_IOTUNE_MAX_LENGTH);

    DO_TEST("multifunction-pci-device",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_SCSI_LSI);

    DO_TEST("monitor-json",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("no-shutdown",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_NO_SHUTDOWN);

    DO_TEST("seclabel-dynamic", NONE);
    DO_TEST("seclabel-dynamic-baselabel", NONE);
    DO_TEST("seclabel-dynamic-override", NONE);
    DO_TEST("seclabel-dynamic-labelskip", NONE);
    DO_TEST("seclabel-dynamic-relabel", NONE);
    DO_TEST("seclabel-static", NONE);
    DO_TEST("seclabel-static-relabel", NONE);
    DO_TEST("seclabel-static-labelskip", NONE);
    DO_TEST("seclabel-none", NONE);
    DO_TEST("seclabel-dac-none", NONE);
    DO_TEST_PARSE_ERROR("seclabel-multiple", NONE);
    DO_TEST_PARSE_ERROR("seclabel-device-duplicates", NONE);

    DO_TEST("pseries-basic",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-vio",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-usb-default",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_OHCI, QEMU_CAPS_PCI_MULTIFUNCTION);
    DO_TEST("pseries-usb-multi",
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_OHCI, QEMU_CAPS_PCI_MULTIFUNCTION);
    DO_TEST("pseries-vio-user-assigned",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_PARSE_ERROR("pseries-vio-address-clash",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-nvram", QEMU_CAPS_DEVICE_NVRAM);
    DO_TEST("pseries-usb-kbd", QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_DEVICE_USB_KBD, QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-cpu-exact", QEMU_CAPS_CHARDEV,
            QEMU_CAPS_NODEFCONFIG);

    qemuTestSetHostArch(driver.caps, VIR_ARCH_PPC64);
    DO_TEST("pseries-cpu-compat", QEMU_CAPS_KVM,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-cpu-le", QEMU_CAPS_KVM,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_FAILURE("pseries-cpu-compat-power9", QEMU_CAPS_KVM);

    qemuTestSetHostCPU(driver.caps, cpuPower9);
    DO_TEST("pseries-cpu-compat-power9",
            QEMU_CAPS_KVM, QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    qemuTestSetHostCPU(driver.caps, NULL);

    qemuTestSetHostArch(driver.caps, VIR_ARCH_NONE);

    DO_TEST("pseries-panic-missing",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-panic-no-address",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST_FAILURE("pseries-panic-address",
                    QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-ide-drive-split",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_IDE_CD);
    DO_TEST("disk-ide-wwn",
            QEMU_CAPS_IDE_CD,
            QEMU_CAPS_DRIVE_SERIAL, QEMU_CAPS_IDE_DRIVE_WWN);

    DO_TEST("disk-geometry", NONE);
    DO_TEST("disk-blockio",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_IDE_CD, QEMU_CAPS_BLOCKIO);

    DO_TEST("video-device-pciaddr-default",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-vga-nodevice", QEMU_CAPS_DEVICE_VGA);
    DO_TEST("video-vga-device", QEMU_CAPS_DEVICE_VGA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-vga-device-vgamem", QEMU_CAPS_DEVICE_VGA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY, QEMU_CAPS_VGA_VGAMEM);
    DO_TEST("video-qxl-nodevice", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-device",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-qxl-device-vgamem",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_QXL_VGAMEM);
    DO_TEST("video-qxl-sec-device",
            QEMU_CAPS_DEVICE_QXL, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-qxl-sec-device-vgamem",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_QXL_VGAMEM);
    DO_TEST("video-qxl-heads",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_MAX_OUTPUTS);
    DO_TEST("video-qxl-noheads",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_MAX_OUTPUTS);
    DO_TEST("video-virtio-gpu-device",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-gpu-virgl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-gpu-spice-gl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_GL,
            QEMU_CAPS_SPICE_RENDERNODE,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-gpu-secondary",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-vga",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIRTIO_VGA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST_PARSE_ERROR("video-invalid", NONE);

    DO_TEST("virtio-rng-default", QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-random", QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-egd", QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST("virtio-rng-multiple", QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_PARSE_ERROR("virtio-rng-egd-crash",
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST("virtio-rng-ccw",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_CCW,
            QEMU_CAPS_VIRTIO_S390, QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("s390-allow-bogus-usb-none",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("s390-allow-bogus-usb-controller",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("s390-panic-no-address",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("s390-panic-address",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-missing",
            QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("ppc-dtb", QEMU_CAPS_KVM, QEMU_CAPS_DTB);
    DO_TEST("ppce500-serial", QEMU_CAPS_KVM, QEMU_CAPS_CHARDEV);

    DO_TEST("tpm-passthrough",
            QEMU_CAPS_DEVICE_TPM_PASSTHROUGH, QEMU_CAPS_DEVICE_TPM_TIS);
    DO_TEST_PARSE_ERROR("tpm-no-backend-invalid",
                        QEMU_CAPS_DEVICE_TPM_PASSTHROUGH, QEMU_CAPS_DEVICE_TPM_TIS);


    DO_TEST_PARSE_ERROR("pci-domain-invalid", NONE);
    DO_TEST_PARSE_ERROR("pci-bus-invalid", NONE);
    DO_TEST_PARSE_ERROR("pci-slot-invalid", NONE);
    DO_TEST_PARSE_ERROR("pci-function-invalid", NONE);

    DO_TEST("pci-bridge",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-autoadd-addr",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-autoadd-idx",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-autofill-addr", QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-many",
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-bridge-many-disks",
            QEMU_CAPS_DEVICE_PCI_BRIDGE);
    DO_TEST("pcie-root",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST_PARSE_ERROR("q35-dmi-bad-address1",
                        QEMU_CAPS_DEVICE_PCI_BRIDGE,
                        QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                        QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST_PARSE_ERROR("q35-dmi-bad-address2",
                        QEMU_CAPS_DEVICE_PCI_BRIDGE,
                        QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                        QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST("q35-pm-disable",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE, QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4,
            QEMU_CAPS_ICH9_DISABLE_S3, QEMU_CAPS_ICH9_DISABLE_S4);
    DO_TEST("q35-pm-disable-fallback",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE, QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("q35-usb2",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-multi",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-reorder",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    /* verify that devices with pcie capability are assigned to a pcie slot */
    DO_TEST("q35-pcie",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same XML as q35-pcie, but don't set
     * QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, so virtio devices should
     * be assigned to legacy pci slots
     */
    DO_TEST("q35-virtio-pci",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST("q35-pcie-autoadd",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-default-devices-only",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-multifunction",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-virt-manager-basic",
            QEMU_CAPS_KVM,
            QEMU_CAPS_RTC,
            QEMU_CAPS_ICH9_DISABLE_S3,
            QEMU_CAPS_ICH9_DISABLE_S4,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_USB_REDIR);

    /* Test automatic and manual setting of pcie-root-port attributes */
    DO_TEST("pcie-root-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    /* Make sure the default model for PCIe Root Ports is picked correctly
     * based on QEMU binary capabilities. We use x86/q35 for the test, but
     * any PCIe machine type (such as aarch64/virt) will behave the same */
    DO_TEST("pcie-root-port-model-generic",
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_MULTIFUNCTION);
    DO_TEST("pcie-root-port-model-ioh3420",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_MULTIFUNCTION);

    DO_TEST("autoindex",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI);
    /* Make sure the user can always override libvirt's default device
     * placement policy by providing an explicit PCI address */
    DO_TEST("q35-pci-force-address",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_HDA_DUPLEX);

    DO_TEST_PARSE_ERROR("q35-wrong-root",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST_PARSE_ERROR("440fx-wrong-root", NONE);

    DO_TEST_PARSE_ERROR("pcie-root-port-too-many",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    DO_TEST("pcie-switch-upstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pcie-switch-downstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    DO_TEST("pci-expander-bus",
            QEMU_CAPS_DEVICE_PXB);
    DO_TEST_PARSE_ERROR("pci-expander-bus-bad-node",
                        QEMU_CAPS_DEVICE_PXB);
    DO_TEST_PARSE_ERROR("pci-expander-bus-bad-machine",
                        QEMU_CAPS_DEVICE_PXB);
    DO_TEST_PARSE_ERROR("pci-expander-bus-bad-bus",
                        QEMU_CAPS_DEVICE_PXB);

    DO_TEST("pcie-expander-bus",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_DEVICE_PXB_PCIE);
    DO_TEST_PARSE_ERROR("pcie-expander-bus-bad-machine",
                        QEMU_CAPS_DEVICE_IOH3420,
                        QEMU_CAPS_DEVICE_X3130_UPSTREAM,
                        QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
                        QEMU_CAPS_DEVICE_PXB_PCIE);
    DO_TEST_PARSE_ERROR("pcie-expander-bus-bad-bus",
                        QEMU_CAPS_DEVICE_IOH3420,
                        QEMU_CAPS_DEVICE_PXB_PCIE);

    DO_TEST("hostdev-scsi-lsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-scsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-readonly",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-scsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC,
            QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX);
    DO_TEST("hostdev-scsi-lsi-iscsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-lsi-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-iscsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-vhost-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC, QEMU_CAPS_VIRTIO_CCW);
    DO_TEST("hostdev-scsi-vhost-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST("mlock-on", QEMU_CAPS_REALTIME_MLOCK);
    DO_TEST_FAILURE("mlock-on", NONE);
    DO_TEST("mlock-off", QEMU_CAPS_REALTIME_MLOCK);
    DO_TEST("mlock-unsupported", NONE);

    DO_TEST_PARSE_ERROR("pci-bridge-negative-index-invalid", NONE);
    DO_TEST_PARSE_ERROR("pci-bridge-duplicate-index", NONE);
    DO_TEST_PARSE_ERROR("pci-root-nonzero-index", NONE);
    DO_TEST_PARSE_ERROR("pci-root-address", NONE);

    DO_TEST("hotplug-base",
            QEMU_CAPS_KVM, QEMU_CAPS_VIRTIO_SCSI);

    DO_TEST("pcihole64", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
    DO_TEST_FAILURE("pcihole64-none", NONE);
    DO_TEST("pcihole64-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_Q35_PCI_HOLE64_SIZE);

    DO_TEST("arm-vexpressa9-nodevs",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB);
    DO_TEST("arm-vexpressa9-basic",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB);
    DO_TEST("arm-vexpressa9-virtio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("arm-virt-virtio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("aarch64-virt-virtio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);

    /* Demonstrates the virtio-pci default... namely that there isn't any!
       q35 style PCI controllers will be added if the binary supports it,
       but virtio-mmio is always used unless PCI addresses are manually
       specified. */
    DO_TEST("aarch64-virtio-pci-default",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-virt-2.6-virtio-pci-default",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420);
    /* Example of using virtio-pci with no explicit PCI controller
       but with manual PCI addresses */
    DO_TEST("aarch64-virtio-pci-manual-addresses",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-video-virtio-gpu-pci",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE, QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU, QEMU_CAPS_BOOTINDEX);
    DO_TEST("aarch64-aavmf-virtio-mmio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("aarch64-virt-default-nic",
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);
    qemuTestSetHostArch(driver.caps, VIR_ARCH_AARCH64);
    DO_TEST("aarch64-cpu-passthrough",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_KVM);
    DO_TEST_GIC("aarch64-gic-none", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT);
    DO_TEST_GIC("aarch64-gic-none", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-v2", GIC_V2,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-v3", GIC_V3,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-both", GIC_BOTH,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-tcg", GIC_BOTH,
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT);
    DO_TEST_GIC("aarch64-gic-default", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default", GIC_V2,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default", GIC_V3,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default", GIC_BOTH,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT);
    DO_TEST_GIC("aarch64-gic-v2", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_V2,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_V3,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_BOTH,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-v3",
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT);
    DO_TEST_GIC("aarch64-gic-v3", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_V2,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_V3,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_BOTH,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-host",
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT);
    DO_TEST_GIC("aarch64-gic-host", GIC_NONE,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_V2,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_V3,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_BOTH,
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_PARSE_ERROR("aarch64-gic-invalid",
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-not-virt",
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-not-arm",
            QEMU_CAPS_KVM, QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST("aarch64-kvm-32-on-64",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_KVM, QEMU_CAPS_CPU_AARCH64_OFF);
    DO_TEST_FAILURE("aarch64-kvm-32-on-64",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_KVM);

    /* Make sure all combinations of ACPI and UEFI behave as expected */
    DO_TEST("aarch64-acpi-uefi", NONE);
    DO_TEST("aarch64-noacpi-uefi", NONE);
    DO_TEST("aarch64-noacpi-nouefi", NONE);
    DO_TEST_PARSE_ERROR("aarch64-acpi-nouefi", NONE);

    qemuTestSetHostArch(driver.caps, VIR_ARCH_NONE);

    DO_TEST("kvm-pit-delay", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST("kvm-pit-discard", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST("no-kvm-pit-device", NONE);

    DO_TEST("panic", QEMU_CAPS_DEVICE_PANIC,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("panic-double", QEMU_CAPS_DEVICE_PANIC,
            QEMU_CAPS_NODEFCONFIG);

    DO_TEST("panic-no-address", QEMU_CAPS_DEVICE_PANIC,
            QEMU_CAPS_NODEFCONFIG);

    DO_TEST("fips-enabled", QEMU_CAPS_ENABLE_FIPS);

    DO_TEST("shmem", QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST("shmem-plain-doorbell", QEMU_CAPS_DEVICE_IVSHMEM,
            QEMU_CAPS_DEVICE_IVSHMEM_PLAIN,
            QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    DO_TEST_FAILURE("shmem", NONE);
    DO_TEST_FAILURE("shmem-invalid-size",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_FAILURE("shmem-invalid-address",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_FAILURE("shmem-small-size",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_PARSE_ERROR("shmem-msi-only", NONE);
    DO_TEST("cpu-host-passthrough-features", QEMU_CAPS_KVM);

    DO_TEST_FAILURE("memory-align-fail", NONE);
    DO_TEST_FAILURE("memory-hotplug-nonuma", QEMU_CAPS_DEVICE_PC_DIMM);
    DO_TEST("memory-hotplug", NONE);
    DO_TEST("memory-hotplug", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA);
    DO_TEST("memory-hotplug-dimm", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-dimm-addr", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-ppc64-nonuma", QEMU_CAPS_KVM, QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-nvdimm", QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_DEVICE_NVDIMM,
            QEMU_CAPS_NUMA, QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-nvdimm-access", QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_DEVICE_NVDIMM,
            QEMU_CAPS_NUMA, QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-nvdimm-label", QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_DEVICE_NVDIMM,
            QEMU_CAPS_NUMA, QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);

    DO_TEST("machine-aeskeywrap-on-caps",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-caps", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-caps", NONE);

    DO_TEST("machine-aeskeywrap-on-cap",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-cap", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-cap", NONE);

    DO_TEST("machine-aeskeywrap-off-caps",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-caps", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-caps", NONE);

    DO_TEST("machine-aeskeywrap-off-cap",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-cap", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-cap", NONE);

    DO_TEST("machine-deakeywrap-on-caps",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-caps", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-caps", NONE);

    DO_TEST("machine-deakeywrap-on-cap",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-cap", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-cap", NONE);

    DO_TEST("machine-deakeywrap-off-caps",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-caps", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-caps", NONE);

    DO_TEST("machine-deakeywrap-off-cap",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-cap", QEMU_CAPS_MACHINE_OPT,
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-cap", NONE);

    DO_TEST("machine-keywrap-none-caps",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("machine-keywrap-none",
            QEMU_CAPS_MACHINE_OPT, QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("qemu-ns-domain-ns0", NONE);
    DO_TEST("qemu-ns-domain-commandline", NONE);
    DO_TEST("qemu-ns-domain-commandline-ns0", NONE);
    DO_TEST("qemu-ns-commandline", NONE);
    DO_TEST("qemu-ns-commandline-ns0", NONE);
    DO_TEST("qemu-ns-commandline-ns1", NONE);

    DO_TEST("virtio-input", QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE, QEMU_CAPS_VIRTIO_TABLET);
    DO_TEST("virtio-input-passthrough", QEMU_CAPS_VIRTIO_INPUT_HOST);

    DO_TEST("ppc64-usb-controller",
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("ppc64-usb-controller-legacy",
            QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST_FULL("ppc64-usb-controller-qemu-xhci", NULL, -1, 0,
                 VIR_DOMAIN_DEF_PARSE_ABI_UPDATE, GIC_NONE,
                 QEMU_CAPS_NEC_USB_XHCI,
                 QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST("aarch64-usb-controller-qemu-xhci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST("aarch64-usb-controller-nec-xhci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_NEC_USB_XHCI);

    DO_TEST_PARSE_FLAGS_ERROR("missing-machine",
                              VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS,
                              NONE);

    DO_TEST("name-escape", QEMU_CAPS_NAME_DEBUG_THREADS,
            QEMU_CAPS_OBJECT_SECRET, QEMU_CAPS_CHARDEV, QEMU_CAPS_VNC,
            QEMU_CAPS_NAME_GUEST, QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE, QEMU_CAPS_SPICE_UNIX);
    DO_TEST("debug-threads", QEMU_CAPS_NAME_DEBUG_THREADS);

    DO_TEST("master-key", QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("usb-long-port-path", QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-too-long-port-path-invalid",
                        QEMU_CAPS_CHARDEV,
                        QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_USB_HUB);

    DO_TEST("acpi-table", NONE);
    DO_TEST("intel-iommu",
            QEMU_CAPS_DEVICE_INTEL_IOMMU);
    DO_TEST("intel-iommu-machine",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_IOMMU);
    DO_TEST("intel-iommu-ioapic",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT,
            QEMU_CAPS_INTEL_IOMMU_INTREMAP,
            QEMU_CAPS_DEVICE_INTEL_IOMMU);
    DO_TEST("intel-iommu-caching-mode",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_INTEL_IOMMU,
            QEMU_CAPS_INTEL_IOMMU_INTREMAP,
            QEMU_CAPS_INTEL_IOMMU_CACHING_MODE);
    DO_TEST("intel-iommu-eim",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT,
            QEMU_CAPS_INTEL_IOMMU_INTREMAP,
            QEMU_CAPS_INTEL_IOMMU_EIM,
            QEMU_CAPS_DEVICE_INTEL_IOMMU);
    DO_TEST("intel-iommu-device-iotlb",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP,
            QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT,
            QEMU_CAPS_INTEL_IOMMU_INTREMAP,
            QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB,
            QEMU_CAPS_DEVICE_INTEL_IOMMU);

    DO_TEST("cpu-hotplug-startup", QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);
    DO_TEST("virtio-options", QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE, QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_FSDEV, QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM,
            QEMU_CAPS_VIRTIO_PCI_ATS);

    DO_TEST("fd-memory-numa-topology", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology2", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology3", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST("fd-memory-no-numa-topology", QEMU_CAPS_MEM_PATH, QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST("cpu-check-none", QEMU_CAPS_KVM);
    DO_TEST("cpu-check-partial", QEMU_CAPS_KVM);
    DO_TEST("cpu-check-full", QEMU_CAPS_KVM);
    DO_TEST("cpu-check-default-none", QEMU_CAPS_KVM);
    DO_TEST("cpu-check-default-none2", NONE);
    DO_TEST("cpu-check-default-partial", QEMU_CAPS_KVM);
    DO_TEST("cpu-check-default-partial2", QEMU_CAPS_KVM);

    DO_TEST("cpu-cache-disable", QEMU_CAPS_KVM, QEMU_CAPS_CPU_CACHE);
    DO_TEST("cpu-cache-disable2", QEMU_CAPS_KVM);
    DO_TEST("cpu-cache-disable3", QEMU_CAPS_KVM, QEMU_CAPS_CPU_CACHE);
    DO_TEST("cpu-cache-passthrough", QEMU_CAPS_KVM, QEMU_CAPS_CPU_CACHE);
    DO_TEST("cpu-cache-passthrough2", QEMU_CAPS_KVM);
    DO_TEST("cpu-cache-emulate-l3", QEMU_CAPS_KVM, QEMU_CAPS_CPU_CACHE);
    DO_TEST_PARSE_ERROR("cpu-cache-emulate-l2", QEMU_CAPS_KVM);
    DO_TEST_PARSE_ERROR("cpu-cache-passthrough3", QEMU_CAPS_KVM);
    DO_TEST_PARSE_ERROR("cpu-cache-passthrough-l3", QEMU_CAPS_KVM);

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                       abs_builddir "/.libs/qemuxml2argvmock.so",
                       abs_builddir "/.libs/virrandommock.so",
                       abs_builddir "/.libs/qemucpumock.so")

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
