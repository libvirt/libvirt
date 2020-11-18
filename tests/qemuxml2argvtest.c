#include <config.h>

#include <unistd.h>

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
# include "qemu/qemu_slirp.h"
# include "qemu/qemu_qapi.h"
# include "datatypes.h"
# include "conf/storage_conf.h"
# include "cpu/cpu_map.h"
# include "virstring.h"
# include "storage/storage_driver.h"
# include "virmock.h"
# include "virfilewrapper.h"
# include "configmake.h"
# include "testutilsqemuschema.h"
# include "qemu/qemu_monitor_json.h"

# define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
# include "qemu/qemu_capspriv.h"

# include "testutilsqemu.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

static virQEMUDriver driver;

static unsigned char *
fakeSecretGetValue(virSecretPtr obj G_GNUC_UNUSED,
                   size_t *value_size,
                   unsigned int fakeflags G_GNUC_UNUSED,
                   unsigned int internalFlags G_GNUC_UNUSED)
{
    char *secret;
    secret = g_strdup("AQCVn5hO6HzFAhAAq0NCv8jtJcIcE+HOBlMQ1A");
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
    /* NB: This mocked value could be "tls" or "volume" depending on
     * which test is being run, we'll leave at NONE (or 0) */
    return virGetSecret(conn, uuid, VIR_SECRET_USAGE_TYPE_NONE, "");
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
    g_autofree char *xmlpath = NULL;
    virStoragePoolPtr ret = NULL;

    if (STRNEQ(name, "inactive")) {
        xmlpath = g_strdup_printf("%s/%s%s.xml", abs_srcdir,
                                  STORAGE_POOL_XML_PATH, name);

        if (!virFileExists(xmlpath)) {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           "File '%s' not found", xmlpath);
            goto cleanup;
        }
    }

    ret = virGetStoragePool(conn, name, fakeUUID, NULL, NULL);

 cleanup:
    return ret;
}


static virStorageVolPtr
fakeStorageVolLookupByName(virStoragePoolPtr pool,
                           const char *name)
{
    VIR_AUTOSTRINGLIST volinfo = NULL;
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
    return g_strdup_printf("/some/%s/device/%s", vol->key, vol->name);
}


static char *
fakeStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                          unsigned int flags_unused G_GNUC_UNUSED)
{
    g_autofree char *xmlpath = NULL;
    char *xmlbuf = NULL;

    if (STREQ(pool->name, "inactive")) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        return NULL;
    }

    xmlpath = g_strdup_printf("%s/%s%s.xml", abs_srcdir, STORAGE_POOL_XML_PATH,
                              pool->name);

    if (virTestLoadFile(xmlpath, &xmlbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "failed to load XML file '%s'",
                       xmlpath);
        goto cleanup;
    }

 cleanup:

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


/* virNetDevOpenvswitchGetVhostuserIfname mocks a portdev name - handle that */
static virNWFilterBindingPtr
fakeNWFilterBindingLookupByPortDev(virConnectPtr conn,
                                   const char *portdev)
{
    if (STREQ(portdev, "vhost-user0"))
        return virGetNWFilterBinding(conn, "fake_vnet0", "fakeFilterName");

    virReportError(VIR_ERR_NO_NWFILTER_BINDING,
                   "no nwfilter binding for port dev '%s'", portdev);
    return NULL;
}


static int
fakeNWFilterBindingDelete(virNWFilterBindingPtr binding G_GNUC_UNUSED)
{
    return 0;
}


static virNWFilterDriver fakeNWFilterDriver = {
    .nwfilterBindingLookupByPortDev = fakeNWFilterBindingLookupByPortDev,
    .nwfilterBindingDelete = fakeNWFilterBindingDelete,
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
                                         G_N_ELEMENTS(x86Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, x86Models,
                                         G_N_ELEMENTS(x86Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;

        if (!skipLegacy) {
            if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM,
                                             x86LegacyModels,
                                             G_N_ELEMENTS(x86LegacyModels),
                                             VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
                virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU,
                                             x86LegacyModels,
                                             G_N_ELEMENTS(x86LegacyModels),
                                             VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
                return -1;
        }
    } else if (ARCH_IS_ARM(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, armModels,
                                         G_N_ELEMENTS(armModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, armModels,
                                         G_N_ELEMENTS(armModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    } else if (ARCH_IS_PPC64(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, ppc64Models,
                                         G_N_ELEMENTS(ppc64Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
            virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_QEMU, ppc64Models,
                                         G_N_ELEMENTS(ppc64Models),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    } else if (ARCH_IS_S390(arch)) {
        if (virQEMUCapsAddCPUDefinitions(caps, VIR_DOMAIN_VIRT_KVM, s390xModels,
                                         G_N_ELEMENTS(s390xModels),
                                         VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            return -1;
    }

    return 0;
}


static int
testUpdateQEMUCaps(const struct testQemuInfo *info,
                   virDomainObjPtr vm,
                   virCapsPtr caps)
{
    if (!caps)
        return -1;

    virQEMUCapsSetArch(info->qemuCaps, vm->def->os.arch);

    virQEMUCapsInitQMPBasicArch(info->qemuCaps);

    if (testAddCPUModels(info->qemuCaps,
                         !!(info->flags & FLAG_SKIP_LEGACY_CPUS)) < 0)
        return -1;

    virQEMUCapsInitHostCPUModel(info->qemuCaps, caps->host.arch,
                                VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(info->qemuCaps, caps->host.arch,
                                VIR_DOMAIN_VIRT_QEMU);

    return 0;
}


static int
testCheckExclusiveFlags(int flags)
{
    virCheckFlags(FLAG_EXPECT_FAILURE |
                  FLAG_EXPECT_PARSE_ERROR |
                  FLAG_FIPS_HOST |
                  FLAG_REAL_CAPS |
                  FLAG_SKIP_LEGACY_CPUS |
                  FLAG_SLIRP_HELPER |
                  0, -1);

    VIR_EXCLUSIVE_FLAGS_RET(FLAG_REAL_CAPS, FLAG_SKIP_LEGACY_CPUS, -1);
    return 0;
}


static virCommandPtr
testCompareXMLToArgvCreateArgs(virQEMUDriverPtr drv,
                               virDomainObjPtr vm,
                               const char *migrateURI,
                               struct testQemuInfo *info,
                               unsigned int flags,
                               bool jsonPropsValidation)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool enableFips = !!(flags & FLAG_FIPS_HOST);
    size_t i;

    if (qemuProcessCreatePretendCmdPrepare(drv, vm, migrateURI, false,
                                           VIR_QEMU_PROCESS_START_COLD) < 0)
        return NULL;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        /* host cdrom requires special treatment in qemu, mock it */
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
            disk->src->format == VIR_STORAGE_FILE_RAW &&
            virStorageSourceIsBlockLocal(disk->src) &&
            STREQ(disk->src->path, "/dev/cdrom"))
            disk->src->hostcdrom = true;
    }

    for (i = 0; i < vm->def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];

        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            hostdev->source.subsys.u.pci.backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT) {
            hostdev->source.subsys.u.pci.backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
        }

        if (virHostdevIsSCSIDevice(hostdev)) {
            virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;

            switch ((virDomainHostdevSCSIProtocolType) scsisrc->protocol) {
            case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE:
                scsisrc->u.host.src->path = g_strdup("/dev/sg0");
                break;

            case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI:
                break;

            case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST:
            default:
                virReportEnumRangeError(virDomainHostdevSCSIProtocolType, scsisrc->protocol);
                return NULL;
            }
        }
    }

    for (i = 0; i < vm->def->nfss; i++) {
        virDomainFSDefPtr fs = vm->def->fss[i];
        char *s;

        if (fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS ||
            QEMU_DOMAIN_FS_PRIVATE(fs)->vhostuser_fs_sock)
            continue;

        s = g_strdup_printf("/tmp/lib/domain--1-guest/fs%zu.vhost-fs.sock", i);
        QEMU_DOMAIN_FS_PRIVATE(fs)->vhostuser_fs_sock = s;
    }

    if (vm->def->vsock) {
        virDomainVsockDefPtr vsock = vm->def->vsock;
        qemuDomainVsockPrivatePtr vsockPriv =
            (qemuDomainVsockPrivatePtr)vsock->privateData;

        if (vsock->auto_cid == VIR_TRISTATE_BOOL_YES)
            vsock->guest_cid = 42;

        vsockPriv->vhostfd = 6789;
    }

    for (i = 0; i < vm->def->ntpms; i++) {
        if (vm->def->tpms[i]->type != VIR_DOMAIN_TPM_TYPE_EMULATOR)
            continue;

        VIR_FREE(vm->def->tpms[i]->data.emulator.source.data.file.path);
        vm->def->tpms[i]->data.emulator.source.data.file.path = g_strdup("/dev/test");
        vm->def->tpms[i]->data.emulator.source.type = VIR_DOMAIN_CHR_TYPE_FILE;
    }

    for (i = 0; i < vm->def->nvideos; i++) {
        virDomainVideoDefPtr video = vm->def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            qemuDomainVideoPrivatePtr vpriv = QEMU_DOMAIN_VIDEO_PRIVATE(video);

            vpriv->vhost_user_fd = 1729;
        }
    }

    if (flags & FLAG_SLIRP_HELPER) {
        for (i = 0; i < vm->def->nnets; i++) {
            virDomainNetDefPtr net = vm->def->nets[i];

            if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
                virQEMUCapsGet(info->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {
                qemuSlirpPtr slirp = qemuSlirpNew();
                slirp->fd[0] = 42;
                QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp = slirp;
            }
        }
    }

    /* we can't use qemuCheckFips() directly as it queries host state */
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_ENABLE_FIPS))
        enableFips = false;

    return qemuProcessCreatePretendCmdBuild(drv, vm, migrateURI,
                                            enableFips, false,
                                            jsonPropsValidation);
}


static int
testCompareXMLToArgvValidateSchema(virQEMUDriverPtr drv,
                                   const char *migrateURI,
                                   struct testQemuInfo *info,
                                   unsigned int flags)
{
    VIR_AUTOSTRINGLIST args = NULL;
    g_autoptr(virDomainObj) vm = NULL;
    size_t nargs = 0;
    size_t i;
    g_autoptr(GHashTable) schema = NULL;
    g_autoptr(virCommand) cmd = NULL;
    unsigned int parseFlags = info->parseFlags;

    if (info->schemafile)
        schema = testQEMUSchemaLoad(info->schemafile);

    /* comment out with line comment to enable schema checking for non _CAPS tests
    if (!schema)
        schema = testQEMUSchemaLoadLatest(virArchToString(info->arch));
    // */

    if (!schema)
        return 0;

    if (!(vm = virDomainObjNew(driver.xmlopt)))
        return -1;

    parseFlags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;
    if (!(vm->def = virDomainDefParseFile(info->infile,
                                          driver.xmlopt,
                                          NULL, parseFlags)))
        return -1;

    if (!(cmd = testCompareXMLToArgvCreateArgs(drv, vm, migrateURI, info, flags,
                                               true)))
        return -1;

    if (virCommandGetArgList(cmd, &args, &nargs) < 0)
        return -1;

    for (i = 0; i < nargs; i++) {
        g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
        g_autoptr(virJSONValue) jsonargs = NULL;

        if (STREQ(args[i], "-blockdev")) {
            if (!(jsonargs = virJSONValueFromString(args[i + 1])))
                return -1;

            if (testQEMUSchemaValidateCommand("blockdev-add", jsonargs,
                                              schema, false, false, &debug) < 0) {
                VIR_TEST_VERBOSE("failed to validate -blockdev '%s' against QAPI schema: %s",
                                 args[i + 1], virBufferCurrentContent(&debug));
                return -1;
            }

            i++;
        } else if (STREQ(args[i], "-netdev")) {
            if (!(jsonargs = virJSONValueFromString(args[i + 1])))
                return -1;

            /* skip the validation for pre-QAPIfication cases */
            if (virQEMUQAPISchemaPathExists("netdev_add/arg-type/type/!string", schema))
                continue;

            if (testQEMUSchemaValidateCommand("netdev_add", jsonargs,
                                              schema, false, false, &debug) < 0) {
                VIR_TEST_VERBOSE("failed to validate -netdev '%s' against QAPI schema: %s",
                                 args[i + 1], virBufferCurrentContent(&debug));
                return -1;
            }

            i++;
        }
    }

    return 0;
}


static int
testCompareXMLToArgv(const void *data)
{
    struct testQemuInfo *info = (void *) data;
    g_autofree char *migrateURI = NULL;
    g_autofree char *actualargv = NULL;
    unsigned int flags = info->flags;
    unsigned int parseFlags = info->parseFlags;
    int ret = -1;
    virDomainObjPtr vm = NULL;
    virDomainChrSourceDef monitor_chr;
    g_autoptr(virConnect) conn = NULL;
    virError *err = NULL;
    char *log = NULL;
    g_autoptr(virCommand) cmd = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (info->arch != VIR_ARCH_NONE && info->arch != VIR_ARCH_X86_64)
        qemuTestSetHostArch(&driver, info->arch);

    memset(&monitor_chr, 0, sizeof(monitor_chr));

    if (!(conn = virGetConnect()))
        goto cleanup;

    conn->secretDriver = &fakeSecretDriver;
    conn->storageDriver = &fakeStorageDriver;
    conn->nwfilterDriver = &fakeNWFilterDriver;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

    if (testCheckExclusiveFlags(info->flags) < 0)
        goto cleanup;

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
        goto cleanup;

    if (info->migrateFrom &&
        !(migrateURI = qemuMigrationDstGetURI(info->migrateFrom,
                                              info->migrateFd)))
        goto cleanup;

    if (!(vm = virDomainObjNew(driver.xmlopt)))
        goto cleanup;

    if (!virFileExists(info->infile)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Input file '%s' not found", info->infile);
        goto cleanup;
    }

    parseFlags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;
    if (!(vm->def = virDomainDefParseFile(info->infile,
                                          driver.xmlopt,
                                          NULL, parseFlags))) {
        err = virGetLastError();
        if (!err) {
            VIR_TEST_DEBUG("no error was reported for expected parse error");
            goto cleanup;
        }
        if (flags & FLAG_EXPECT_PARSE_ERROR) {
            g_autofree char *tmperr = g_strdup_printf("%s\n", NULLSTR(err->message));
            if (virTestCompareToFile(tmperr, info->errfile) >= 0)
                goto ok;
        }
        goto cleanup;
    }
    if (flags & FLAG_EXPECT_PARSE_ERROR) {
        VIR_TEST_DEBUG("passed instead of expected parse error");
        goto cleanup;
    }
    priv = vm->privateData;

    if (virBitmapParse("0-3", &priv->autoNodeset, 4) < 0)
        goto cleanup;

    if (!virDomainDefCheckABIStability(vm->def, vm->def, driver.xmlopt)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", info->infile);
        goto cleanup;
    }

    vm->def->id = -1;

    if (qemuProcessPrepareMonitorChr(&monitor_chr, priv->libDir) < 0)
        goto cleanup;

    if (!(info->flags & FLAG_REAL_CAPS)) {
        if (testUpdateQEMUCaps(info, vm, driver.caps) < 0)
            goto cleanup;
        if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
            goto cleanup;
    }

    log = virTestLogContentAndReset();
    VIR_FREE(log);
    virResetLastError();

    if (!(cmd = testCompareXMLToArgvCreateArgs(&driver, vm, migrateURI, info,
                                               flags, false))) {
        err = virGetLastError();
        if (!err) {
            VIR_TEST_DEBUG("no error was reported for expected failure");
            goto cleanup;
        }
        if (flags & FLAG_EXPECT_FAILURE) {
            g_autofree char *tmperr = g_strdup_printf("%s\n", NULLSTR(err->message));
            if (virTestCompareToFile(tmperr, info->errfile) >= 0)
                goto ok;
        }
        goto cleanup;
    }
    if (flags & FLAG_EXPECT_FAILURE) {
        VIR_TEST_DEBUG("passed instead of expected failure");
        goto cleanup;
    }

    if (testCompareXMLToArgvValidateSchema(&driver, migrateURI, info, flags) < 0)
        goto cleanup;

    if (!(actualargv = virCommandToString(cmd, false)))
        goto cleanup;

    if (virTestCompareToFile(actualargv, info->outfile) < 0)
        goto cleanup;

    ret = 0;

 ok:
    if (ret == 0 && flags & FLAG_EXPECT_FAILURE) {
        ret = -1;
        VIR_TEST_DEBUG("Error expected but there wasn't any.");
        goto cleanup;
    }
    if (flags & FLAG_EXPECT_FAILURE) {
        if ((log = virTestLogContentAndReset()))
            VIR_TEST_DEBUG("Got expected error: \n%s", log);
    }
    virResetLastError();
    ret = 0;

 cleanup:
    VIR_FREE(log);
    virDomainChrSourceDefClear(&monitor_chr);
    virObjectUnref(vm);
    virSetConnectSecret(NULL);
    virSetConnectStorage(NULL);
    if (info->arch != VIR_ARCH_NONE && info->arch != VIR_ARCH_X86_64)
        qemuTestSetHostArch(&driver, VIR_ARCH_NONE);

    return ret;
}

static void
testInfoSetPaths(struct testQemuInfo *info,
                 const char *suffix)
{
    info->infile = g_strdup_printf("%s/qemuxml2argvdata/%s.xml",
                                   abs_srcdir, info->name);
    info->outfile = g_strdup_printf("%s/qemuxml2argvdata/%s%s.args",
                                    abs_srcdir, info->name, suffix ? suffix : "");
    info->errfile = g_strdup_printf("%s/qemuxml2argvdata/%s%s.err",
                                      abs_srcdir, info->name, suffix ? suffix : "");
}

# define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    g_autofree char *fakerootdir = NULL;
    g_autoptr(GHashTable) capslatest = NULL;

    fakerootdir = g_strdup(FAKEROOTDIRTEMPLATE);

    if (!g_mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    g_setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, TRUE);

    /* Set the timezone because we are mocking the time() function.
     * If we don't do that, then localtime() may return unpredictable
     * results. In order to detect things that just work by a blind
     * chance, we need to set an virtual timezone that no libvirt
     * developer resides in. */
    if (g_setenv("TZ", "VIR00:30", TRUE) == FALSE) {
        perror("g_setenv");
        return EXIT_FAILURE;
    }

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    driver.privileged = true;

    VIR_FREE(driver.config->defaultTLSx509certdir);
    driver.config->defaultTLSx509certdir = g_strdup("/etc/pki/qemu");
    VIR_FREE(driver.config->vncTLSx509certdir);
    driver.config->vncTLSx509certdir = g_strdup("/etc/pki/libvirt-vnc");
    VIR_FREE(driver.config->spiceTLSx509certdir);
    driver.config->spiceTLSx509certdir = g_strdup("/etc/pki/libvirt-spice");
    VIR_FREE(driver.config->chardevTLSx509certdir);
    driver.config->chardevTLSx509certdir = g_strdup("/etc/pki/libvirt-chardev");
    VIR_FREE(driver.config->vxhsTLSx509certdir);
    driver.config->vxhsTLSx509certdir = g_strdup("/etc/pki/libvirt-vxhs/dummy,path");
    VIR_FREE(driver.config->nbdTLSx509certdir);
    driver.config->nbdTLSx509certdir = g_strdup("/etc/pki/libvirt-nbd/dummy,path");

    VIR_FREE(driver.config->hugetlbfs);
    driver.config->hugetlbfs = g_new0(virHugeTLBFS, 2);
    driver.config->nhugetlbfs = 2;
    driver.config->hugetlbfs[0].mnt_dir = g_strdup("/dev/hugepages2M");
    driver.config->hugetlbfs[1].mnt_dir = g_strdup("/dev/hugepages1G");
    driver.config->hugetlbfs[0].size = 2048;
    driver.config->hugetlbfs[0].deflt = true;
    driver.config->hugetlbfs[1].size = 1048576;
    driver.config->spiceTLS = 1;
    driver.config->spicePassword = g_strdup("123456");
    VIR_FREE(driver.config->memoryBackingDir);
    driver.config->memoryBackingDir = g_strdup("/var/lib/libvirt/qemu/ram");
    VIR_FREE(driver.config->nvramDir);
    driver.config->nvramDir = g_strdup("/var/lib/libvirt/qemu/nvram");

    capslatest = testQemuGetLatestCaps();
    if (!capslatest)
        return EXIT_FAILURE;

    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/etc/qemu/firmware");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/usr/share/qemu/firmware");
    virFileWrapperAddPrefix("/home/user/.config/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/home/user/.config/qemu/firmware");

    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/etc/qemu/vhost-user");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/usr/share/qemu/vhost-user");
    virFileWrapperAddPrefix("/home/user/.config/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/home/user/.config/qemu/vhost-user");

    virFileWrapperAddPrefix("/usr/libexec/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/usr/libexec/qemu/vhost-user");

/**
 * The following set of macros allows testing of XML -> argv conversion with a
 * real set of capabilities gathered from a real qemu copy. It is desired to use
 * these for positive test cases as it provides combinations of flags which
 * can be met in real life.
 *
 * The capabilities are taken from the real capabilities stored in
 * tests/qemucapabilitiesdata.
 *
 * It is suggested to use the DO_TEST_CAPS_LATEST macro which always takes the
 * most recent capability set. In cases when the new code would change behaviour
 * the test cases should be forked using DO_TEST_CAPS_VER with the appropriate
 * version.
 */
# define DO_TEST_INTERNAL(_name, _suffix, ...) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        if (testQemuInfoSetArgs(&info, capslatest, \
                                __VA_ARGS__, ARG_END) < 0) \
            return EXIT_FAILURE; \
        testInfoSetPaths(&info, _suffix); \
        if (virTestRun("QEMU XML-2-ARGV " _name _suffix, \
                       testCompareXMLToArgv, &info) < 0) \
            ret = -1; \
        testQemuInfoClear(&info); \
    } while (0)

# define DO_TEST_CAPS_INTERNAL(name, arch, ver, ...) \
    DO_TEST_INTERNAL(name, "." arch "-" ver, \
                     ARG_CAPS_ARCH, arch, \
                     ARG_CAPS_VER, ver, \
                     __VA_ARGS__)

# define DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, "latest", __VA_ARGS__)

# define DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, ver, __VA_ARGS__)

# define DO_TEST_CAPS_ARCH_LATEST(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ARG_END)

# define DO_TEST_CAPS_ARCH_VER(name, arch, ver) \
    DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ARG_END)

# define DO_TEST_CAPS_LATEST(name) \
    DO_TEST_CAPS_ARCH_LATEST(name, "x86_64")

# define DO_TEST_CAPS_VER(name, ver) \
    DO_TEST_CAPS_ARCH_VER(name, "x86_64", ver)

# define DO_TEST_CAPS_LATEST_PPC64(name) \
    DO_TEST_CAPS_ARCH_LATEST(name, "ppc64")

# define DO_TEST_CAPS_ARCH_LATEST_FAILURE(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, \
                                  ARG_FLAGS, FLAG_EXPECT_FAILURE)

# define DO_TEST_CAPS_ARCH_VER_FAILURE(name, arch, ver) \
    DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, \
                               ARG_FLAGS, FLAG_EXPECT_FAILURE)

# define DO_TEST_CAPS_LATEST_FAILURE(name) \
    DO_TEST_CAPS_ARCH_LATEST_FAILURE(name, "x86_64")

# define DO_TEST_CAPS_VER_FAILURE(name, ver) \
    DO_TEST_CAPS_ARCH_VER_FAILURE(name, "x86_64", ver)

# define DO_TEST_CAPS_ARCH_LATEST_PARSE_ERROR(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, \
                                  ARG_FLAGS, FLAG_EXPECT_PARSE_ERROR)

# define DO_TEST_CAPS_ARCH_VER_PARSE_ERROR(name, arch, ver) \
    DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, \
                               ARG_FLAGS, FLAG_EXPECT_PARSE_ERROR)

# define DO_TEST_CAPS_LATEST_PARSE_ERROR(name) \
    DO_TEST_CAPS_ARCH_LATEST_PARSE_ERROR(name, "x86_64")

# define DO_TEST_CAPS_VER_PARSE_ERROR(name, ver) \
    DO_TEST_CAPS_ARCH_VER_PARSE_ERROR(name, "x86_64", ver)

# define DO_TEST_FULL(name, ...) \
    DO_TEST_INTERNAL(name, "", \
                     __VA_ARGS__, QEMU_CAPS_LAST)

/* All the following macros require an explicit QEMU_CAPS_* list
 * at the end of the argument list, or the NONE placeholder.
 * */
# define DO_TEST(name, ...) \
    DO_TEST_FULL(name, \
                 ARG_QEMU_CAPS, __VA_ARGS__)

# define DO_TEST_GIC(name, gic, ...) \
    DO_TEST_FULL(name, \
                 ARG_GIC, gic, \
                 ARG_QEMU_CAPS, __VA_ARGS__)

# define DO_TEST_FAILURE(name, ...) \
    DO_TEST_FULL(name, \
                 ARG_FLAGS, FLAG_EXPECT_FAILURE, \
                 ARG_QEMU_CAPS, __VA_ARGS__)

# define DO_TEST_PARSE_ERROR(name, ...) \
    DO_TEST_FULL(name, \
                 ARG_FLAGS, FLAG_EXPECT_PARSE_ERROR | FLAG_EXPECT_FAILURE, \
                 ARG_QEMU_CAPS, __VA_ARGS__)

# define NONE QEMU_CAPS_LAST

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);
    g_setenv("USER", "test", TRUE);
    g_setenv("LOGNAME", "test", TRUE);
    g_setenv("HOME", "/home/test", TRUE);
    g_setenv("LC_ALL", "C", TRUE);
    g_unsetenv("TMPDIR");
    g_unsetenv("LD_PRELOAD");
    g_unsetenv("LD_LIBRARY_PATH");
    g_unsetenv("QEMU_AUDIO_DRV");
    g_unsetenv("SDL_AUDIODRIVER");

    DO_TEST("minimal", NONE);
    DO_TEST("minimal-sandbox",
            QEMU_CAPS_SECCOMP_BLACKLIST);
    DO_TEST_PARSE_ERROR("minimal-no-memory", NONE);
    DO_TEST("minimal-msg-timestamp", QEMU_CAPS_MSG_TIMESTAMP);

    DO_TEST_CAPS_LATEST("genid");
    DO_TEST_CAPS_LATEST("genid-auto");

    DO_TEST("machine-aliases1", NONE);
    DO_TEST("machine-aliases2", QEMU_CAPS_KVM);
    DO_TEST("machine-core-on", NONE);
    driver.config->dumpGuestCore = true;
    DO_TEST("machine-core-off", NONE);
    driver.config->dumpGuestCore = false;
    DO_TEST("machine-smm-opt",
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_MACHINE_SMM_OPT,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("machine-vmport-opt",
            QEMU_CAPS_MACHINE_VMPORT_OPT);
    DO_TEST("default-kvm-host-arch", NONE);
    DO_TEST("default-qemu-host-arch", NONE);
    DO_TEST("x86-kvm-32-on-64", NONE);
    DO_TEST("boot-cdrom", NONE);
    DO_TEST("boot-network", NONE);
    DO_TEST("boot-floppy", NONE);
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST("boot-multi", NONE);
    DO_TEST("boot-menu-enable", NONE);
    DO_TEST("boot-menu-enable-with-timeout",
            QEMU_CAPS_SPLASH_TIMEOUT);
    DO_TEST_PARSE_ERROR("boot-menu-enable-with-timeout", NONE);
    DO_TEST_PARSE_ERROR("boot-menu-enable-with-timeout-invalid", NONE);
    DO_TEST("boot-menu-disable", NONE);
    DO_TEST("boot-menu-disable-drive", NONE);
    DO_TEST_PARSE_ERROR("boot-dev+order",
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-order",
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-complex",
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("boot-strict",
            QEMU_CAPS_BOOT_STRICT,
            QEMU_CAPS_VIRTIO_BLK_SCSI);

    DO_TEST("reboot-timeout-disabled", QEMU_CAPS_REBOOT_TIMEOUT);
    DO_TEST("reboot-timeout-enabled", QEMU_CAPS_REBOOT_TIMEOUT);
    DO_TEST_PARSE_ERROR("reboot-timeout-enabled", NONE);

    DO_TEST("bios",
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_SGA);
    DO_TEST("bios-nvram", NONE);
    DO_TEST("bios-nvram-secure",
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_MACHINE_SMM_OPT,
            QEMU_CAPS_VIRTIO_SCSI);

    /* Make sure all combinations of ACPI and UEFI behave as expected */
    DO_TEST("q35-acpi-uefi", NONE);
    DO_TEST_PARSE_ERROR("q35-noacpi-uefi", NONE);
    DO_TEST("q35-noacpi-nouefi", NONE);
    DO_TEST("q35-acpi-nouefi", NONE);

    DO_TEST("clock-utc", NONE);
    DO_TEST("clock-localtime", NONE);
    DO_TEST("clock-localtime-basis-localtime", NONE);
    DO_TEST("clock-variable", NONE);
    DO_TEST("clock-france", NONE);
    DO_TEST("clock-hpet-off", NONE);
    DO_TEST("clock-catchup", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST("cpu-kvmclock", NONE);
    DO_TEST("cpu-host-kvmclock", NONE);
    DO_TEST("kvmclock", QEMU_CAPS_KVM);
    DO_TEST("clock-timer-hyperv-rtc", QEMU_CAPS_KVM);

    DO_TEST("cpu-eoi-disabled", NONE);
    DO_TEST("cpu-eoi-enabled", NONE);
    DO_TEST("controller-order",
            QEMU_CAPS_KVM,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_CCID_PASSTHRU,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST_CAPS_VER("eoi-disabled", "2.7.0");
    DO_TEST_CAPS_VER("eoi-disabled", "4.0.0");
    DO_TEST_CAPS_LATEST("eoi-disabled");
    DO_TEST_CAPS_VER("eoi-enabled", "2.7.0");
    DO_TEST_CAPS_VER("eoi-enabled", "4.0.0");
    DO_TEST_CAPS_LATEST("eoi-enabled");
    DO_TEST_CAPS_VER("pv-spinlock-disabled", "2.7.0");
    DO_TEST_CAPS_VER("pv-spinlock-disabled", "4.0.0");
    DO_TEST_CAPS_LATEST("pv-spinlock-disabled");
    DO_TEST_CAPS_VER("pv-spinlock-enabled", "2.7.0");
    DO_TEST_CAPS_VER("pv-spinlock-enabled", "4.0.0");
    DO_TEST_CAPS_LATEST("pv-spinlock-enabled");
    DO_TEST_CAPS_VER("kvmclock+eoi-disabled", "2.7.0");
    DO_TEST_CAPS_VER("kvmclock+eoi-disabled", "4.0.0");
    DO_TEST_CAPS_LATEST("kvmclock+eoi-disabled");

    DO_TEST_CAPS_VER("hyperv", "4.0.0");
    DO_TEST_CAPS_LATEST("hyperv");
    DO_TEST_CAPS_VER("hyperv-off", "4.0.0");
    DO_TEST_CAPS_LATEST("hyperv-off");
    DO_TEST_CAPS_VER("hyperv-panic", "4.0.0");
    DO_TEST_CAPS_LATEST("hyperv-panic");
    DO_TEST_CAPS_LATEST("hyperv-stimer-direct");

    DO_TEST("kvm-features", NONE);
    DO_TEST("kvm-features-off", NONE);

    DO_TEST("pmu-feature", NONE);
    DO_TEST("pmu-feature-off", NONE);

    DO_TEST("pages-discard",
            QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD);
    DO_TEST("pages-discard-hugepages",
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD);
    DO_TEST("pages-dimm-discard",
            QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD);
    DO_TEST("hugepages-default", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-default-2M", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-default-system-size", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_PARSE_ERROR("hugepages-default-1G-nodeset-2M", NONE);
    DO_TEST("hugepages-nodeset", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_PARSE_ERROR("hugepages-nodeset-nonexist",
                        QEMU_CAPS_DEVICE_PC_DIMM,
                        QEMU_CAPS_OBJECT_MEMORY_FILE,
                        QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD);
    DO_TEST("hugepages-numa-default",
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-default-2M",
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-default-dimm",
            QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-nodeset",
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-nodeset-part",
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_PARSE_ERROR("hugepages-numa-nodeset-nonexist",
                        QEMU_CAPS_OBJECT_MEMORY_RAM,
                        QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-shared",
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_PARSE_ERROR("hugepages-memaccess-invalid", NONE);
    DO_TEST("hugepages-memaccess", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_NUMA);
    DO_TEST("hugepages-memaccess2", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_NUMA);
    DO_TEST_PARSE_ERROR("hugepages-memaccess3",
                        QEMU_CAPS_OBJECT_MEMORY_RAM,
                        QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_CAPS_LATEST("hugepages-nvdimm");
    DO_TEST("nosharepages", QEMU_CAPS_MEM_MERGE);
    DO_TEST("disk-cdrom", NONE);
    DO_TEST_CAPS_VER("disk-cdrom", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-cdrom");
    DO_TEST_CAPS_LATEST("disk-cdrom-empty-network-invalid");
    DO_TEST_CAPS_LATEST("disk-cdrom-bus-other");
    DO_TEST("disk-iscsi", NONE);
    DO_TEST("disk-cdrom-network", QEMU_CAPS_KVM);
    DO_TEST_CAPS_VER("disk-cdrom-network", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-cdrom-network");
    DO_TEST("disk-cdrom-tray",
            QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST_CAPS_VER("disk-cdrom-tray", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-cdrom-tray");
    DO_TEST("disk-floppy", NONE);
    DO_TEST_CAPS_VER("disk-floppy", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-floppy");
    DO_TEST_CAPS_VER("disk-floppy-q35-2_9", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-floppy-q35-2_9");
    DO_TEST_CAPS_VER("disk-floppy-q35-2_11", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-floppy-q35-2_11");
    DO_TEST_FAILURE("disk-floppy-pseries",
                    QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("disk-floppy-tray", NONE);
    DO_TEST("disk-virtio-s390",
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-virtio", NONE);
    DO_TEST("disk-virtio-ccw",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-virtio-ccw-many",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-virtio-s390-zpci",
            QEMU_CAPS_DEVICE_ZPCI,
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST_PARSE_ERROR("non-x86_64-timer-error",
                        QEMU_CAPS_VIRTIO_S390);
    DO_TEST("disk-order", QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-virtio-queues",
            QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES);
    DO_TEST("disk-boot-disk", NONE);
    DO_TEST("disk-boot-cdrom", NONE);
    DO_TEST("floppy-drive-fat", NONE);
    DO_TEST_CAPS_VER("floppy-drive-fat", "2.12.0");
    DO_TEST_CAPS_LATEST("floppy-drive-fat");
    DO_TEST("disk-readonly-disk", NONE);
    DO_TEST_CAPS_VER("disk-readonly-disk", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-readonly-disk");
    DO_TEST("disk-fmt-qcow", NONE);
    DO_TEST_PARSE_ERROR("disk-fmt-cow", NONE);
    DO_TEST_PARSE_ERROR("disk-fmt-dir", NONE);
    DO_TEST_PARSE_ERROR("disk-fmt-iso", NONE);
    DO_TEST_CAPS_VER("disk-shared", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-shared");
    DO_TEST_PARSE_ERROR("disk-shared-qcow", NONE);
    DO_TEST("disk-error-policy", NONE);
    DO_TEST_CAPS_VER("disk-error-policy", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-error-policy");
    DO_TEST_CAPS_ARCH_VER("disk-error-policy-s390x", "s390x", "2.12.0");
    DO_TEST_CAPS_ARCH_LATEST("disk-error-policy-s390x", "s390x");
    DO_TEST_CAPS_VER("disk-cache", "1.5.3");
    DO_TEST_CAPS_VER("disk-cache", "2.6.0");
    DO_TEST_CAPS_VER("disk-cache", "2.7.0");
    DO_TEST_CAPS_VER("disk-cache", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-cache");
    DO_TEST_CAPS_ARCH_VER_PARSE_ERROR("disk-transient", "x86_64", "4.1.0");
    DO_TEST_CAPS_LATEST("disk-transient");
    DO_TEST("disk-network-nbd", NONE);
    DO_TEST_CAPS_VER("disk-network-nbd", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-nbd");
    DO_TEST("disk-network-iscsi", QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("disk-network-iscsi-modern",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_BLOCK,
            QEMU_CAPS_ISCSI_PASSWORD_SECRET);
    DO_TEST_CAPS_VER("disk-network-iscsi", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-iscsi");
    DO_TEST_PARSE_ERROR("disk-network-iscsi-auth-secrettype-invalid", NONE);
    DO_TEST_PARSE_ERROR("disk-network-iscsi-auth-wrong-secrettype", NONE);
    DO_TEST_PARSE_ERROR("disk-network-source-auth-both", NONE);
    DO_TEST("disk-network-gluster",
            QEMU_CAPS_GLUSTER_DEBUG_LEVEL);
    DO_TEST_CAPS_VER("disk-network-gluster", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-gluster");
    DO_TEST_CAPS_VER("disk-network-rbd", "2.5.0");
    DO_TEST_CAPS_VER("disk-network-rbd", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-rbd");
    DO_TEST_FAILURE("disk-network-rbd-no-colon", NONE);
    DO_TEST("disk-network-sheepdog", NONE);
    DO_TEST_CAPS_VER("disk-network-sheepdog", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-sheepdog");
    DO_TEST("disk-network-source-auth", NONE);
    DO_TEST_CAPS_VER("disk-network-source-auth", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-source-auth");
    DO_TEST("disk-network-vxhs", QEMU_CAPS_VXHS);
    driver.config->vxhsTLS = 1;
    driver.config->nbdTLSx509secretUUID = g_strdup("6fd3f62d-9fe7-4a4e-a869-7acd6376d8ea");
    driver.config->vxhsTLSx509secretUUID = g_strdup("6fd3f62d-9fe7-4a4e-a869-7acd6376d8ea");
    DO_TEST_CAPS_VER("disk-network-tlsx509-nbd", "2.12.0");
    DO_TEST_CAPS_VER("disk-network-tlsx509-vxhs", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-network-tlsx509-nbd");
    DO_TEST_CAPS_VER("disk-network-tlsx509-vxhs", "5.0.0");
    DO_TEST_CAPS_LATEST("disk-network-http");
    driver.config->vxhsTLS = 0;
    VIR_FREE(driver.config->vxhsTLSx509certdir);
    DO_TEST("disk-no-boot", NONE);
    DO_TEST_CAPS_LATEST("disk-nvme");
    DO_TEST_PARSE_ERROR("disk-device-lun-type-invalid",
                        QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_CAPS_LATEST_PARSE_ERROR("disk-attaching-partition-nosupport");
    DO_TEST_PARSE_ERROR("disk-usb-nosupport", NONE);
    DO_TEST("disk-usb-device",
            QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST("disk-usb-device-removable",
            QEMU_CAPS_DEVICE_USB_STORAGE,
            QEMU_CAPS_USB_STORAGE_REMOVABLE);
    DO_TEST_PARSE_ERROR("disk-usb-pci",
                        QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST_CAPS_LATEST("disk-scsi");
    DO_TEST_CAPS_VER("disk-scsi-device-auto", "1.5.3");
    DO_TEST_CAPS_LATEST("disk-scsi-device-auto");
    DO_TEST("disk-scsi-disk-split",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-scsi-disk-wwn",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST_PARSE_ERROR("disk-scsi-disk-vpd-build-error",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST_CAPS_LATEST("controller-virtio-scsi");
    DO_TEST("disk-sata-device",
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST("disk-aio", NONE);
    DO_TEST_CAPS_VER("disk-aio", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-aio");
    DO_TEST_CAPS_LATEST("disk-aio-io_uring");
    DO_TEST("disk-source-pool", NONE);
    DO_TEST("disk-source-pool-mode", NONE);
    DO_TEST("disk-ioeventfd",
            QEMU_CAPS_VIRTIO_IOEVENTFD,
            QEMU_CAPS_VIRTIO_TX_ALG,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST("disk-copy_on_read",
            QEMU_CAPS_VIRTIO_TX_ALG,
            QEMU_CAPS_VIRTIO_BLK_SCSI);
    DO_TEST_CAPS_VER("disk-copy_on_read", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-copy_on_read");
    DO_TEST_CAPS_VER("disk-discard", "4.1.0");
    DO_TEST_CAPS_LATEST("disk-discard");
    DO_TEST_CAPS_VER("disk-detect-zeroes", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-detect-zeroes");
    DO_TEST("disk-snapshot", NONE);
    DO_TEST_PARSE_ERROR("disk-same-targets",
                        QEMU_CAPS_SCSI_LSI,
                        QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST_PARSE_ERROR("disk-address-conflict",
                        QEMU_CAPS_ICH9_AHCI);
    DO_TEST_PARSE_ERROR("disk-hostdev-scsi-address-conflict",
                        QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_PARSE_ERROR("hostdevs-drive-address-conflict",
                        QEMU_CAPS_VIRTIO_SCSI);
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
            QEMU_CAPS_KVM);
    DO_TEST_PARSE_ERROR("disk-fdc-incompatible-address",
                        NONE);
    DO_TEST_PARSE_ERROR("disk-ide-incompatible-address",
                        NONE);
    DO_TEST_PARSE_ERROR("disk-sata-incompatible-address",
                        QEMU_CAPS_ICH9_AHCI);
    DO_TEST_PARSE_ERROR("disk-scsi-incompatible-address",
                        QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_CAPS_VER("disk-backing-chains-index", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-backing-chains-index");
    DO_TEST_CAPS_VER("disk-backing-chains-noindex", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-backing-chains-noindex");

    DO_TEST_CAPS_LATEST("disk-slices");

    DO_TEST_CAPS_ARCH_VER("disk-arm-virtio-sd", "aarch64", "4.0.0");
    DO_TEST_CAPS_ARCH_LATEST("disk-arm-virtio-sd", "aarch64");

    DO_TEST("graphics-egl-headless",
            QEMU_CAPS_EGL_HEADLESS,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST_CAPS_LATEST("graphics-egl-headless");
    DO_TEST_CAPS_LATEST("graphics-egl-headless-rendernode");

    DO_TEST("graphics-vnc", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-socket", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-websocket",
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-vnc-policy", QEMU_CAPS_VNC,
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
    DO_TEST("graphics-vnc-socket-new-cmdline", QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA, QEMU_CAPS_VNC_MULTI_SERVERS);

    driver.config->vncSASL = 1;
    VIR_FREE(driver.config->vncSASLdir);
    driver.config->vncSASLdir = g_strdup("/root/.sasl2");
    DO_TEST("graphics-vnc-sasl", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->vncTLS = 1;
    driver.config->vncTLSx509verify = 1;
    DO_TEST("graphics-vnc-tls", QEMU_CAPS_VNC, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST_CAPS_VER("graphics-vnc-tls", "2.4.0");
    DO_TEST_CAPS_LATEST("graphics-vnc-tls");
    driver.config->vncTLSx509secretUUID = g_strdup("6fd3f62d-9fe7-4a4e-a869-7acd6376d8ea");
    DO_TEST_CAPS_LATEST("graphics-vnc-tls-secret");
    VIR_FREE(driver.config->vncTLSx509secretUUID);
    driver.config->vncSASL = driver.config->vncTLSx509verify = driver.config->vncTLS = 0;
    VIR_FREE(driver.config->vncSASLdir);
    VIR_FREE(driver.config->vncTLSx509certdir);
    DO_TEST("graphics-vnc-egl-headless",
            QEMU_CAPS_VNC,
            QEMU_CAPS_EGL_HEADLESS,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);

    DO_TEST("graphics-sdl",
            QEMU_CAPS_DEVICE_VGA);
    DO_TEST_CAPS_LATEST_PARSE_ERROR("graphics-sdl-egl-headless");
    DO_TEST("graphics-sdl-fullscreen",
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("graphics-spice",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE_FILE_XFER_DISABLE);
    DO_TEST("graphics-spice-no-args",
            QEMU_CAPS_SPICE, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    driver.config->spiceSASL = 1;
    driver.config->spiceSASLdir = g_strdup("/root/.sasl2");
    DO_TEST("graphics-spice-sasl",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL);
    VIR_FREE(driver.config->spiceSASLdir);
    driver.config->spiceSASL = 0;
    DO_TEST("graphics-spice-agentmouse",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE,
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
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
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
    DO_TEST("graphics-spice-egl-headless",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_EGL_HEADLESS,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST_CAPS_LATEST_PARSE_ERROR("graphics-spice-invalid-egl-headless");
    DO_TEST_CAPS_LATEST("graphics-spice-gl-auto-rendernode");

    DO_TEST("input-usbmouse", NONE);
    DO_TEST("input-usbtablet", NONE);
    DO_TEST("misc-acpi", NONE);
    DO_TEST("misc-disable-s3", QEMU_CAPS_PIIX_DISABLE_S3);
    DO_TEST("misc-disable-suspends", QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("misc-enable-s4", QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST_PARSE_ERROR("misc-enable-s4", NONE);
    DO_TEST("misc-no-reboot", NONE);
    DO_TEST("misc-uuid", NONE);
    DO_TEST_PARSE_ERROR("vhost_queues-invalid", NONE);
    DO_TEST("net-vhostuser", QEMU_CAPS_CHARDEV_FD_PASS);
    DO_TEST_CAPS_VER("net-vhostuser", "2.5.0");
    DO_TEST_CAPS_LATEST("net-vhostuser");
    DO_TEST("net-vhostuser-multiq",
            QEMU_CAPS_VHOSTUSER_MULTIQUEUE);
    DO_TEST_FAILURE("net-vhostuser-multiq", NONE);
    DO_TEST_FAILURE("net-vhostuser-fail",
                    QEMU_CAPS_VHOSTUSER_MULTIQUEUE);
    DO_TEST("net-user", NONE);
    DO_TEST_CAPS_ARCH_VER_FULL("net-user", "x86_64", "4.0.0", ARG_FLAGS, FLAG_SLIRP_HELPER);
    DO_TEST("net-user-addr", NONE);
    DO_TEST("net-virtio", NONE);
    DO_TEST("net-virtio-device",
            QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("net-virtio-disable-offloads", NONE);
    DO_TEST("net-virtio-netdev", NONE);
    DO_TEST("net-virtio-s390",
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("net-virtio-ccw",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("net-virtio-rxtxqueuesize",
            QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE,
            QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE);
    DO_TEST_PARSE_ERROR("net-virtio-rxqueuesize-invalid-size",
                        QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE);
    DO_TEST("net-virtio-teaming",
            QEMU_CAPS_VIRTIO_NET_FAILOVER,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("net-virtio-teaming", NONE);
    DO_TEST("net-eth", NONE);
    DO_TEST("net-eth-ifname", NONE);
    DO_TEST("net-eth-names", NONE);
    DO_TEST("net-eth-hostip", NONE);
    DO_TEST("net-eth-unmanaged-tap", NONE);
    DO_TEST("net-client", NONE);
    DO_TEST("net-server", NONE);
    DO_TEST("net-many-models", NONE);
    DO_TEST("net-mcast", NONE);
    DO_TEST("net-udp", NONE);
    DO_TEST("net-hostdev", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-hostdev-bootorder", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-hostdev-multidomain", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-hostdev-vfio",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-hostdev-vfio-multidomain",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_FAILURE("net-hostdev-fail",
                    QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_CAPS_LATEST("net-vdpa");

    DO_TEST("hostdev-pci-multifunction",
            QEMU_CAPS_KVM,
            QEMU_CAPS_DEVICE_VFIO_PCI);

    DO_TEST("hostdev-pci-address-unassigned",
            QEMU_CAPS_KVM,
            QEMU_CAPS_DEVICE_VFIO_PCI);

    DO_TEST("serial-file-log",
            QEMU_CAPS_CHARDEV_FILE_APPEND,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_CHARDEV_LOGFILE);
    DO_TEST("serial-spiceport",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-spiceport-nospice", NONE);

    DO_TEST("console-compat",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("console-compat-auto",
            QEMU_CAPS_DEVICE_ISA_SERIAL);

    DO_TEST("serial-vc-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-pty-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-dev-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-dev-chardev-iobase",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-file-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_CHARDEV_FILE_APPEND);
    DO_TEST("serial-unix-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST_CAPS_LATEST("serial-unix-chardev");
    DO_TEST_PARSE_ERROR("serial-unix-missing-source", NONE);
    DO_TEST("serial-tcp-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-udp-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("serial-tcp-telnet-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    driver.config->chardevTLS = 1;
    DO_TEST("serial-tcp-tlsx509-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    driver.config->chardevTLSx509verify = 1;
    DO_TEST("serial-tcp-tlsx509-chardev-verify",
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    driver.config->chardevTLSx509verify = 0;
    DO_TEST("serial-tcp-tlsx509-chardev-notls",
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    VIR_FREE(driver.config->chardevTLSx509certdir);
    driver.config->chardevTLSx509certdir = g_strdup("/etc/pki/libvirt-chardev");
    driver.config->chardevTLSx509secretUUID = g_strdup("6fd3f62d-9fe7-4a4e-a869-7acd6376d8ea");
    DO_TEST("serial-tcp-tlsx509-secret-chardev",
            QEMU_CAPS_OBJECT_SECRET,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_OBJECT_TLS_CREDS_X509);
    driver.config->chardevTLS = 0;
    VIR_FREE(driver.config->chardevTLSx509certdir);
    DO_TEST("serial-many-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("parallel-tcp-chardev", NONE);
    DO_TEST("parallel-parport-chardev", NONE);
    DO_TEST_CAPS_VER("parallel-unix-chardev", "2.5.0");
    DO_TEST_CAPS_LATEST("parallel-unix-chardev");
    DO_TEST("console-compat-chardev",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("pci-serial-dev-chardev",
            QEMU_CAPS_DEVICE_PCI_SERIAL);

    DO_TEST("channel-guestfwd", NONE);
    DO_TEST_CAPS_VER("channel-unix-guestfwd", "2.5.0");
    DO_TEST_CAPS_LATEST("channel-unix-guestfwd");
    DO_TEST("channel-virtio", NONE);
    DO_TEST("channel-virtio-state", NONE);
    DO_TEST("channel-virtio-auto", NONE);
    DO_TEST("channel-virtio-autoassign", NONE);
    DO_TEST("channel-virtio-autoadd", NONE);
    DO_TEST("console-virtio", NONE);
    DO_TEST("console-virtio-many",
            QEMU_CAPS_DEVICE_ISA_SERIAL);
    DO_TEST("console-virtio-s390",
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("console-virtio-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST_CAPS_VER("console-virtio-unix", "2.5.0");
    DO_TEST_CAPS_LATEST("console-virtio-unix");
    DO_TEST("console-sclp",
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_SCLPCONSOLE);
    DO_TEST("channel-spicevmc",
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("channel-virtio-default",
            QEMU_CAPS_SPICE);
    DO_TEST("channel-virtio-unix", NONE);

    DO_TEST("smartcard-host",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates-database",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-passthrough-tcp",
            QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-passthrough-spicevmc",
            QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-controller",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST_CAPS_VER("smartcard-passthrough-unix", "2.5.0");
    DO_TEST_CAPS_LATEST("smartcard-passthrough-unix");

    DO_TEST("chardev-reconnect",
            QEMU_CAPS_CHARDEV_RECONNECT,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD,
            QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST_PARSE_ERROR("chardev-reconnect-invalid-timeout",
                        QEMU_CAPS_CHARDEV_RECONNECT);
    DO_TEST_PARSE_ERROR("chardev-reconnect-generated-path",
                        QEMU_CAPS_CHARDEV_RECONNECT);

    DO_TEST("usb-controller", NONE);
    DO_TEST("usb-piix3-controller",
            QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST("usb-ich9-ehci-addr",
            QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("input-usbmouse-addr", NONE);
    DO_TEST("usb-ich9-companion",
            QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST_PARSE_ERROR("usb-ich9-no-companion",
            QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("usb-ich9-autoassign",
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-hub",
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-hub-autoadd",
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-hub-autoadd-deluxe",
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-hub-conflict",
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-hub-nonexistent",
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-port-missing",
            QEMU_CAPS_USB_HUB);
    DO_TEST_FAILURE("usb-bus-missing",
                    QEMU_CAPS_USB_HUB);
    DO_TEST("usb-ports",
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-ports-out-of-range",
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-port-autoassign",
            QEMU_CAPS_USB_HUB);
    DO_TEST("usb-redir",
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE);
    DO_TEST("usb-redir-boot",
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE);
    DO_TEST("usb-redir-filter",
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST("usb-redir-filter-version",
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST_CAPS_VER("usb-redir-unix", "2.5.0");
    DO_TEST_CAPS_LATEST("usb-redir-unix");
    DO_TEST("usb1-usb2",
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("usb-none", NONE);
    DO_TEST_PARSE_ERROR("usb-none-other", NONE);
    DO_TEST_PARSE_ERROR("usb-none-hub",
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-none-usbtablet", NONE);
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
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_NEC_USB_XHCI_PORTS);
    DO_TEST("usb-xhci-autoassign",
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_NEC_USB_XHCI_PORTS,
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-controller-xhci-limit",
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_NEC_USB_XHCI_PORTS);
    DO_TEST("usb-controller-qemu-xhci", QEMU_CAPS_DEVICE_QEMU_XHCI);
    DO_TEST_FAILURE("usb-controller-qemu-xhci-unavailable", NONE);
    DO_TEST_PARSE_ERROR("usb-controller-qemu-xhci-limit",
                        QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST("smbios", NONE);
    DO_TEST_PARSE_ERROR("smbios-date", NONE);
    DO_TEST_PARSE_ERROR("smbios-uuid-match", NONE);
    DO_TEST("smbios-type-fwcfg", QEMU_CAPS_FW_CFG);

    DO_TEST("watchdog", NONE);
    DO_TEST("watchdog-device", NONE);
    DO_TEST("watchdog-dump", NONE);
    DO_TEST("watchdog-injectnmi", NONE);
    DO_TEST("watchdog-diag288", QEMU_CAPS_VIRTIO_S390);
    DO_TEST("balloon-device", NONE);
    DO_TEST("balloon-device-deflate",
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-ccw-deflate",
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-mmio-deflate",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-device-deflate-off",
            QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE);
    DO_TEST("balloon-device-auto", NONE);
    DO_TEST("balloon-device-period", NONE);
    DO_TEST("sound", NONE);
    DO_TEST("sound-device",
            QEMU_CAPS_HDA_DUPLEX, QEMU_CAPS_HDA_MICRO,
            QEMU_CAPS_HDA_OUTPUT,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_OBJECT_USB_AUDIO);
    DO_TEST("fs9p", NONE);
    DO_TEST_CAPS_LATEST("fs9p");
    DO_TEST("fs9p-ccw",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_CAPS_ARCH_LATEST("fs9p-ccw", "s390x");

    DO_TEST("hostdev-usb-address", NONE);
    DO_TEST("hostdev-usb-address-device", NONE);
    DO_TEST("hostdev-usb-address-device-boot", NONE);
    DO_TEST("hostdev-pci-address", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-pci-address-device", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio-multidomain",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-mdev-precreated",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-mdev-src-address-invalid",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-mdev-invalid-target-address",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-spice-opengl");
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-spice-egl-headless");
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-vnc");
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-vnc-egl-headless");
    DO_TEST_PARSE_ERROR("hostdev-mdev-display-missing-graphics",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_VFIO_PCI_DISPLAY);
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-ramfb");
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-wrong-arch",
                        QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio-zpci",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-autogenerate-fids",
                        QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-invalid-uid-valid-fid",
                        QEMU_CAPS_DEVICE_VFIO_PCI,
                        QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-multidomain-many",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate-uids",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate-fids",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-uid-set-zero",
                        QEMU_CAPS_DEVICE_VFIO_PCI,
                        QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-boundaries",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci",
                        QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-duplicate",
                        QEMU_CAPS_DEVICE_VFIO_PCI,
                        QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST_PARSE_ERROR("hostdev-vfio-zpci-set-zero",
                        QEMU_CAPS_DEVICE_VFIO_PCI,
                        QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-ccw-memballoon",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);

    DO_TEST("pci-rom", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pci-rom-disabled", NONE);
    DO_TEST("pci-rom-disabled-invalid", NONE);

    DO_TEST("hostdev-subsys-mdev-vfio-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_CCW);
    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ccw-boot",
                             "s390x");
    DO_TEST_PARSE_ERROR("hostdev-subsys-mdev-vfio-ccw",
                        QEMU_CAPS_CCW,
                        QEMU_CAPS_CCW_CSSID_UNRESTRICTED);
    DO_TEST_PARSE_ERROR("hostdev-subsys-mdev-vfio-ccw-duplicate-address",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_CCW);
    DO_TEST_PARSE_ERROR("hostdev-subsys-mdev-vfio-ccw-invalid-address",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_CCW);

    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ap",
                             "s390x");
    DO_TEST_CAPS_ARCH_LATEST_PARSE_ERROR("hostdev-subsys-mdev-vfio-ap-boot-fail",
                                         "s390x");

    DO_TEST_FULL("restore-v2",
                 ARG_MIGRATE_FROM, "exec:cat",
                 ARG_MIGRATE_FD, 7,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("restore-v2-fd",
                 ARG_MIGRATE_FROM, "stdio",
                 ARG_MIGRATE_FD, 7,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("restore-v2-fd",
                 ARG_MIGRATE_FROM, "fd:7",
                 ARG_MIGRATE_FD, 7,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("migrate",
                 ARG_MIGRATE_FROM, "tcp:10.0.0.1:5000",
                 ARG_QEMU_CAPS, NONE);

    DO_TEST_FULL("migrate-numa-unaligned",
                 ARG_MIGRATE_FROM, "stdio",
                 ARG_MIGRATE_FD, 7,
                 ARG_QEMU_CAPS,
                 QEMU_CAPS_NUMA,
                 QEMU_CAPS_OBJECT_MEMORY_RAM);

    DO_TEST_CAPS_VER("qemu-ns", "4.0.0");
    DO_TEST_CAPS_LATEST("qemu-ns");
    DO_TEST("qemu-ns-no-env", NONE);
    DO_TEST("qemu-ns-alt", NONE);

    DO_TEST("smp", NONE);
    DO_TEST("smp-dies", QEMU_CAPS_SMP_DIES);

    DO_TEST("iothreads", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-ids", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-ids-partial", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST_FAILURE("iothreads-nocap", NONE);
    DO_TEST("iothreads-disk", QEMU_CAPS_OBJECT_IOTHREAD);
    DO_TEST("iothreads-disk-virtio-ccw", QEMU_CAPS_OBJECT_IOTHREAD,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_CAPS_LATEST("iothreads-virtio-scsi-pci");
    DO_TEST_CAPS_ARCH_LATEST("iothreads-virtio-scsi-ccw", "s390x");

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
    DO_TEST("cpu-no-removed-features", QEMU_CAPS_KVM);
    DO_TEST("cpu-numa1", NONE);
    DO_TEST("cpu-numa2", NONE);
    DO_TEST("cpu-numa-no-memory-element", NONE);
    DO_TEST_PARSE_ERROR("cpu-numa3", NONE);
    DO_TEST_PARSE_ERROR("cpu-numa-disjoint", NONE);
    DO_TEST("cpu-numa-disjoint", QEMU_CAPS_NUMA);
    DO_TEST_FAILURE("cpu-numa-memshared", QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_PARSE_ERROR("cpu-numa-memshared-1", NONE);
    DO_TEST("cpu-numa-memshared", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("cpu-host-model", NONE);
    DO_TEST("cpu-host-model-vendor", NONE);
    DO_TEST_FULL("cpu-host-model-fallback",
                 ARG_FLAGS, FLAG_SKIP_LEGACY_CPUS,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("cpu-host-model-nofallback",
                 ARG_FLAGS, FLAG_SKIP_LEGACY_CPUS | FLAG_EXPECT_FAILURE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST("cpu-host-passthrough", QEMU_CAPS_KVM);
    DO_TEST_FAILURE("cpu-qemu-host-passthrough", QEMU_CAPS_KVM);

    qemuTestSetHostArch(&driver, VIR_ARCH_S390X);
    DO_TEST("cpu-s390-zEC12", QEMU_CAPS_KVM, QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("cpu-s390-features", QEMU_CAPS_KVM, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION);
    DO_TEST_FAILURE("cpu-s390-features", QEMU_CAPS_KVM);
    qemuTestSetHostArch(&driver, VIR_ARCH_NONE);

    qemuTestSetHostCPU(&driver, driver.hostarch, cpuHaswell);
    DO_TEST("cpu-Haswell", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell2", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell3", QEMU_CAPS_KVM);
    DO_TEST("cpu-Haswell-noTSX", QEMU_CAPS_KVM);
    DO_TEST("cpu-host-model-cmt", NONE);
    DO_TEST_CAPS_VER("cpu-host-model-cmt", "4.0.0");
    DO_TEST("cpu-tsc-frequency", QEMU_CAPS_KVM);
    DO_TEST_CAPS_VER("cpu-tsc-frequency", "4.0.0");
    DO_TEST_CAPS_LATEST("cpu-tsc-high-frequency");
    DO_TEST_CAPS_VER("cpu-translation", "4.0.0");
    DO_TEST_CAPS_LATEST("cpu-translation");
    qemuTestSetHostCPU(&driver, driver.hostarch, NULL);

    DO_TEST("encrypted-disk", QEMU_CAPS_QCOW2_LUKS, QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("encrypted-disk-usage", QEMU_CAPS_QCOW2_LUKS, QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("luks-disks", QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("luks-disks-source", QEMU_CAPS_OBJECT_SECRET);
    DO_TEST_PARSE_ERROR("luks-disks-source-qcow2", QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("luks-disks-source-qcow2", QEMU_CAPS_OBJECT_SECRET, QEMU_CAPS_QCOW2_LUKS);
    DO_TEST_CAPS_LATEST("luks-disks-source-qcow2");
    DO_TEST_PARSE_ERROR("luks-disk-invalid", NONE);
    DO_TEST_PARSE_ERROR("luks-disks-source-both", QEMU_CAPS_OBJECT_SECRET);

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
    DO_TEST_CAPS_LATEST("cputune-cpuset-big-id");

    DO_TEST("numatune-memory", NONE);
    DO_TEST_PARSE_ERROR("numatune-memory-invalid-nodeset", NONE);
    DO_TEST("numatune-memnode",
            QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_PARSE_ERROR("numatune-memnode", NONE);

    DO_TEST("numatune-memnode-no-memory",
            QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_PARSE_ERROR("numatune-memnode-no-memory", NONE);

    DO_TEST("numatune-distances", QEMU_CAPS_NUMA, QEMU_CAPS_NUMA_DIST);
    DO_TEST("numatune-no-vcpu", NONE);
    DO_TEST_CAPS_LATEST("numatune-hmat");

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
    DO_TEST_CAPS_VER("blkdeviotune-max", "4.1.0");
    DO_TEST_CAPS_LATEST("blkdeviotune-max");
    DO_TEST_CAPS_VER("blkdeviotune-group-num", "4.1.0");
    DO_TEST_CAPS_LATEST("blkdeviotune-group-num");
    DO_TEST_CAPS_VER("blkdeviotune-max-length", "4.1.0");
    DO_TEST_CAPS_LATEST("blkdeviotune-max-length");

    DO_TEST("multifunction-pci-device",
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("monitor-json", NONE);

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
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-vio",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-usb-default",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("pseries-usb-multi",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("pseries-vio-user-assigned",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST_PARSE_ERROR("pseries-vio-address-clash", NONE);
    DO_TEST("pseries-nvram",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_NVRAM);
    DO_TEST("pseries-usb-kbd", QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_USB_KBD,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-cpu-exact",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST_PARSE_ERROR("pseries-no-parallel", NONE);

    qemuTestSetHostArch(&driver, VIR_ARCH_PPC64);
    DO_TEST("pseries-cpu-compat", QEMU_CAPS_KVM,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-machine-max-cpu-compat",
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACHINE_PSERIES_MAX_CPU_COMPAT,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-cpu-le", QEMU_CAPS_KVM,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST_FAILURE("pseries-cpu-compat-power9",
                    QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                    QEMU_CAPS_KVM);

    qemuTestSetHostCPU(&driver, driver.hostarch, cpuPower9);
    DO_TEST("pseries-cpu-compat-power9",
            QEMU_CAPS_KVM,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    qemuTestSetHostCPU(&driver, driver.hostarch, NULL);

    qemuTestSetHostArch(&driver, VIR_ARCH_NONE);

    DO_TEST("pseries-panic-missing",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-panic-no-address",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST_PARSE_ERROR("pseries-panic-address",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);

    DO_TEST("pseries-phb-simple",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-phb-default-missing",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-phb-numa-node",
            QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE);
    DO_TEST_PARSE_ERROR("pseries-default-phb-numa-node", NONE);
    DO_TEST_PARSE_ERROR("pseries-phb-invalid-target-index-1", NONE);
    DO_TEST_PARSE_ERROR("pseries-phb-invalid-target-index-2", NONE);
    DO_TEST_PARSE_ERROR("pseries-phb-invalid-target-index-3", NONE);

    DO_TEST("pseries-many-devices",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-many-buses-1",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-many-buses-2",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-hostdevs-1",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pseries-hostdevs-2",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pseries-hostdevs-3",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);

    DO_TEST("pseries-features",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
            QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
            QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
            QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
            QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
            QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
            QEMU_CAPS_MACHINE_PSERIES_CAP_IBS,
            QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT */
    DO_TEST_PARSE_ERROR("pseries-features-htp-resize",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE */
    DO_TEST_PARSE_ERROR("pseries-features-hpt-pagesize",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_CAP_HTM */
    DO_TEST_PARSE_ERROR("pseries-features-htm",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV */
    DO_TEST_PARSE_ERROR("pseries-features-nested-hv",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST */
    DO_TEST_PARSE_ERROR("pseries-features-ccf",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_CFPC */
    DO_TEST_PARSE_ERROR("pseries-features-cfpc",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_SBBC */
    DO_TEST_PARSE_ERROR("pseries-features-sbbc",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_IBS);

    /* parse error: no QEMU_CAPS_MACHINE_PSERIES_IBS */
    DO_TEST_PARSE_ERROR("pseries-features-ibs",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
                        QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC);

    DO_TEST_PARSE_ERROR("pseries-features-invalid-machine", NONE);

    DO_TEST("pseries-serial-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial+console-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial-compat",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial-pci",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);
    DO_TEST("pseries-serial-usb",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_QEMU_XHCI,
            QEMU_CAPS_DEVICE_USB_SERIAL);
    DO_TEST("pseries-console-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-console-virtio",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST_PARSE_ERROR("pseries-serial-invalid-machine", NONE);
    DO_TEST_PARSE_ERROR("pseries-spaprvio-invalid", "ppc64");

    DO_TEST("mach-virt-serial-native",
            QEMU_CAPS_DEVICE_PL011);
    DO_TEST("mach-virt-serial+console-native",
            QEMU_CAPS_DEVICE_PL011);
    DO_TEST("mach-virt-serial-compat",
            QEMU_CAPS_DEVICE_PL011);
    DO_TEST("mach-virt-serial-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);
    DO_TEST("mach-virt-serial-usb",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_QEMU_XHCI,
            QEMU_CAPS_DEVICE_USB_SERIAL);
    DO_TEST("mach-virt-console-native",
            QEMU_CAPS_DEVICE_PL011);
    DO_TEST("mach-virt-console-virtio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);
    DO_TEST_PARSE_ERROR("mach-virt-serial-invalid-machine", NONE);

    DO_TEST("disk-ide-split", NONE);
    DO_TEST("disk-ide-wwn",
            QEMU_CAPS_IDE_DRIVE_WWN,
            QEMU_CAPS_SCSI_DISK_WWN);

    DO_TEST("disk-geometry", NONE);
    DO_TEST("disk-blockio", QEMU_CAPS_BLOCKIO);

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
    DO_TEST_CAPS_LATEST("video-qxl-device-vram64");
    DO_TEST("video-qxl-sec-device",
            QEMU_CAPS_DEVICE_QXL, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-qxl-sec-device-vgamem",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_QXL_VGAMEM);
    DO_TEST_CAPS_LATEST("video-qxl-sec-device-vram64");
    DO_TEST("video-qxl-heads",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_MAX_OUTPUTS);
    DO_TEST("video-vga-qxl-heads",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_MAX_OUTPUTS);
    DO_TEST("video-qxl-noheads",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_MAX_OUTPUTS);
    DO_TEST("video-qxl-resolution",
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_QXL_VGAMEM);
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
    DO_TEST("video-virtio-gpu-sdl-gl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SDL_GL,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-gpu-secondary",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("video-virtio-vga",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIRTIO_VGA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS);
    DO_TEST_CAPS_LATEST("video-bochs-display-device");
    DO_TEST_CAPS_LATEST("video-ramfb-display-device");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("video-ramfb-display-device-pci-address");
    DO_TEST("video-none-device",
            QEMU_CAPS_VNC);
    DO_TEST_PARSE_ERROR("video-invalid-multiple-devices", NONE);
    DO_TEST_PARSE_ERROR("default-video-type-x86_64-caps-test-0", NONE);

    DO_TEST_CAPS_ARCH_LATEST("default-video-type-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-ppc64", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-riscv64", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-s390x", "s390x");

    DO_TEST("virtio-rng-default",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-random",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-egd",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST_CAPS_LATEST("virtio-rng-builtin");
    DO_TEST_CAPS_VER("virtio-rng-egd-unix", "2.5.0");
    DO_TEST_CAPS_LATEST("virtio-rng-egd-unix");
    DO_TEST("virtio-rng-multiple",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_PARSE_ERROR("virtio-rng-egd-crash",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST("virtio-rng-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("s390-allow-bogus-usb-none",
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("s390-allow-bogus-usb-controller",
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("s390-panic-no-address",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST_PARSE_ERROR("s390-panic-address",
                        QEMU_CAPS_CCW,
                        QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-missing",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST_PARSE_ERROR("s390-no-parallel",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-serial",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_SCLPCONSOLE);
    DO_TEST("s390-serial-2",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_SCLPCONSOLE,
            QEMU_CAPS_DEVICE_SCLPLMCONSOLE);
    DO_TEST("s390-serial-console",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_DEVICE_SCLPCONSOLE);

    DO_TEST("ppc-dtb",
            QEMU_CAPS_KVM);
    DO_TEST("ppce500-serial",
            QEMU_CAPS_KVM);

    DO_TEST_CAPS_LATEST("tpm-passthrough");
    DO_TEST_CAPS_LATEST("tpm-passthrough-crb");
    DO_TEST_PARSE_ERROR("tpm-no-backend-invalid",
                        QEMU_CAPS_DEVICE_TPM_PASSTHROUGH, QEMU_CAPS_DEVICE_TPM_TIS);
    DO_TEST_CAPS_LATEST("tpm-emulator");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-enc");
    DO_TEST_CAPS_LATEST_PPC64("tpm-emulator-spapr");

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
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-multi",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-reorder",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    /* verify that devices with pcie capability are assigned to a pcie slot */
    DO_TEST("q35-pcie",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
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
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST("q35-pcie-autoadd",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-default-devices-only",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-multifunction",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-virt-manager-basic",
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACHINE_VMPORT_OPT,
            QEMU_CAPS_ICH9_DISABLE_S3,
            QEMU_CAPS_ICH9_DISABLE_S4,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_USB_REDIR);

    /* Test automatic and manual setting of pcie-root-port attributes */
    DO_TEST("pcie-root-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    /* Make sure the default model for PCIe Root Ports is picked correctly
     * based on QEMU binary capabilities. We use x86/q35 for the test, but
     * any PCIe machine type (such as aarch64/virt) will behave the same */
    DO_TEST("pcie-root-port-model-generic",
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST("pcie-root-port-model-ioh3420",
            QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST_CAPS_LATEST("pcie-root-port-nohotplug");

    DO_TEST("autoindex",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
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
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST_PARSE_ERROR("440fx-wrong-root", NONE);
    DO_TEST_PARSE_ERROR("440fx-ide-address-conflict", NONE);

    DO_TEST_PARSE_ERROR("pcie-root-port-too-many",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    DO_TEST("pcie-switch-upstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_ICH9_AHCI,
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

    DO_TEST_CAPS_VER("hostdev-scsi-lsi", "2.8.0");
    DO_TEST_CAPS_VER("hostdev-scsi-lsi", "4.1.0");
    DO_TEST_CAPS_LATEST("hostdev-scsi-lsi");
    DO_TEST_CAPS_VER("hostdev-scsi-virtio-scsi", "2.8.0");
    DO_TEST_CAPS_VER("hostdev-scsi-virtio-scsi", "4.1.0");
    DO_TEST_CAPS_LATEST("hostdev-scsi-virtio-scsi");

    DO_TEST("hostdev-scsi-vhost-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_CCW);
    DO_TEST("hostdev-scsi-vhost-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VHOST_SCSI);
    DO_TEST_CAPS_LATEST_PARSE_ERROR("hostdev-scsi-vhost-scsi-pci-boot-fail");
    DO_TEST("hostdev-scsi-vhost-scsi-pcie",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY);

    DO_TEST_CAPS_VER("mlock-on", "3.0.0");
    DO_TEST_CAPS_VER("mlock-off", "3.0.0");
    DO_TEST_CAPS_LATEST("mlock-on");
    DO_TEST_CAPS_LATEST("mlock-off");

    DO_TEST_PARSE_ERROR("pci-bridge-negative-index-invalid", NONE);
    DO_TEST_PARSE_ERROR("pci-bridge-duplicate-index", NONE);
    DO_TEST_PARSE_ERROR("pci-root-nonzero-index", NONE);
    DO_TEST_PARSE_ERROR("pci-root-address", NONE);

    DO_TEST("hotplug-base",
            QEMU_CAPS_KVM, QEMU_CAPS_VIRTIO_SCSI);

    DO_TEST("pcihole64", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
    DO_TEST_PARSE_ERROR("pcihole64-none", NONE);
    DO_TEST("pcihole64-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_Q35_PCI_HOLE64_SIZE);

    DO_TEST("arm-vexpressa9-nodevs", NONE);
    DO_TEST("arm-vexpressa9-basic", NONE);
    DO_TEST("arm-vexpressa9-virtio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("arm-virt-virtio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_PL011,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);

    DO_TEST("aarch64-virt-virtio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_PL011,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);

    /* Demonstrates the virtio-pci default... namely that there isn't any!
       q35 style PCI controllers will be added if the binary supports it,
       but virtio-mmio is always used unless PCI addresses are manually
       specified. */
    DO_TEST("aarch64-virtio-pci-default",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_PL011,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-virt-2.6-virtio-pci-default",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PL011,
            QEMU_CAPS_DEVICE_IOH3420);
    /* Example of using virtio-pci with no explicit PCI controller
       but with manual PCI addresses */
    DO_TEST("aarch64-virtio-pci-manual-addresses",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-video-virtio-gpu-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE, QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST("aarch64-video-default",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE, QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU, QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_VNC);
    DO_TEST("aarch64-aavmf-virtio-mmio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("aarch64-virt-default-nic",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);
    qemuTestSetHostArch(&driver, VIR_ARCH_AARCH64);
    DO_TEST("aarch64-cpu-passthrough",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_KVM);
    DO_TEST_GIC("aarch64-gic-none", GIC_NONE,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-v2", GIC_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-v3", GIC_V3,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-both", GIC_BOTH,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-none-tcg", GIC_BOTH,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default", GIC_NONE,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default-v2", GIC_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default-v3", GIC_V3,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-default-both", GIC_BOTH,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_NONE,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_V3,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v2", GIC_BOTH,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-v3",
            QEMU_CAPS_KVM, NONE);
    DO_TEST_GIC("aarch64-gic-v3", GIC_NONE,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_V3,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-v3", GIC_BOTH,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_FAILURE("aarch64-gic-host",
            QEMU_CAPS_KVM, NONE);
    DO_TEST_GIC("aarch64-gic-host", GIC_NONE,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_V3,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_GIC("aarch64-gic-host", GIC_BOTH,
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_PARSE_ERROR("aarch64-gic-invalid",
            QEMU_CAPS_KVM,
            QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_PARSE_ERROR("aarch64-gic-not-virt",
                        QEMU_CAPS_KVM,
                        QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST_PARSE_ERROR("aarch64-gic-not-arm",
                        QEMU_CAPS_KVM,
                        QEMU_CAPS_MACH_VIRT_GIC_VERSION);
    DO_TEST("aarch64-kvm-32-on-64",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_PL011,
            QEMU_CAPS_KVM, QEMU_CAPS_CPU_AARCH64_OFF);
    DO_TEST_PARSE_ERROR("aarch64-kvm-32-on-64",
                        QEMU_CAPS_DEVICE_VIRTIO_MMIO,
                        QEMU_CAPS_KVM);
    DO_TEST("aarch64-pci-serial",
            QEMU_CAPS_DEVICE_PCI_SERIAL,
            QEMU_CAPS_CHARDEV_LOGFILE,
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT);
    DO_TEST("aarch64-traditional-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);

    /* Make sure all combinations of ACPI and UEFI behave as expected */
    DO_TEST("aarch64-acpi-uefi", NONE);
    DO_TEST("aarch64-noacpi-uefi", NONE);
    DO_TEST("aarch64-noacpi-nouefi", NONE);
    DO_TEST_PARSE_ERROR("aarch64-acpi-nouefi", NONE);

    /* QEMU 4.0.0 didn't have support for aarch64 CPU features */
    DO_TEST_CAPS_ARCH_VER_FAILURE("aarch64-features-sve", "aarch64", "4.0.0");
    /* aarch64 doesn't support the same CPU features as x86 */
    DO_TEST_CAPS_ARCH_LATEST_FAILURE("aarch64-features-wrong", "aarch64");
    /* Can't enable vector lengths when SVE is overall disabled */
    DO_TEST_CAPS_ARCH_LATEST_PARSE_ERROR("aarch64-features-sve-disabled", "aarch64");
    /* SVE aarch64 CPU features work on modern QEMU */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-features-sve", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST("clock-timer-armvtimer", "aarch64");

    qemuTestSetHostArch(&driver, VIR_ARCH_NONE);

    DO_TEST("kvm-pit-delay", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST("kvm-pit-discard", QEMU_CAPS_KVM_PIT_TICK_POLICY);

    DO_TEST("panic",
            QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-double",
            QEMU_CAPS_DEVICE_PANIC);

    DO_TEST("panic-no-address",
            QEMU_CAPS_DEVICE_PANIC);

    DO_TEST_CAPS_ARCH_VER_FULL("fips-enabled", "x86_64", "5.1.0", ARG_FLAGS, FLAG_FIPS_HOST);
    DO_TEST_CAPS_ARCH_LATEST_FULL("fips-enabled", "x86_64", ARG_FLAGS, FLAG_FIPS_HOST);

    DO_TEST("shmem", QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST("shmem-plain-doorbell", QEMU_CAPS_DEVICE_IVSHMEM,
            QEMU_CAPS_DEVICE_IVSHMEM_PLAIN,
            QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    DO_TEST_PARSE_ERROR("shmem", NONE);
    DO_TEST_FAILURE("shmem-invalid-size",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_FAILURE("shmem-invalid-address",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_FAILURE("shmem-small-size",
                    QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST_PARSE_ERROR("shmem-msi-only", NONE);
    DO_TEST("cpu-host-passthrough-features", QEMU_CAPS_KVM);

    DO_TEST_FAILURE("memory-align-fail", NONE);
    DO_TEST_PARSE_ERROR("memory-hotplug-nonuma", QEMU_CAPS_DEVICE_PC_DIMM);
    DO_TEST("memory-hotplug", NONE);
    DO_TEST("memory-hotplug", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA);
    DO_TEST("memory-hotplug-dimm", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-dimm-addr", QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memory-hotplug-ppc64-nonuma", QEMU_CAPS_KVM, QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-access");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-label");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-align");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-pmem");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-readonly");
    DO_TEST_CAPS_ARCH_LATEST("memory-hotplug-nvdimm-ppc64", "ppc64");

    DO_TEST("machine-aeskeywrap-on-caps",
            QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-caps",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-caps", NONE);

    DO_TEST("machine-aeskeywrap-on-cap",
            QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-cap",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-on-cap", NONE);

    DO_TEST("machine-aeskeywrap-off-caps",
            QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-caps",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-caps", NONE);

    DO_TEST("machine-aeskeywrap-off-cap",
            QEMU_CAPS_AES_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-cap",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-aeskeywrap-off-cap", NONE);

    DO_TEST("machine-deakeywrap-on-caps",
            QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-caps",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-caps", NONE);

    DO_TEST("machine-deakeywrap-on-cap",
            QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-cap",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-on-cap", NONE);

    DO_TEST("machine-deakeywrap-off-caps",
            QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-caps",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-caps", NONE);

    DO_TEST("machine-deakeywrap-off-cap",
            QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-cap",
                    QEMU_CAPS_VIRTIO_SCSI,
                    QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST_FAILURE("machine-deakeywrap-off-cap", NONE);

    DO_TEST("machine-keywrap-none-caps",
            QEMU_CAPS_AES_KEY_WRAP, QEMU_CAPS_DEA_KEY_WRAP,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("machine-keywrap-none",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("machine-loadparm-s390",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_LOADPARM);
    DO_TEST("machine-loadparm-net-s390",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_LOADPARM);
    DO_TEST("machine-loadparm-multiple-disks-nets-s390",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_S390,
            QEMU_CAPS_LOADPARM);
    DO_TEST_PARSE_ERROR("machine-loadparm-s390-char-invalid",
                        QEMU_CAPS_CCW,
                        QEMU_CAPS_VIRTIO_S390,
                        QEMU_CAPS_LOADPARM);
    DO_TEST_PARSE_ERROR("machine-loadparm-s390-len-invalid",
                        QEMU_CAPS_CCW,
                        QEMU_CAPS_VIRTIO_S390,
                        QEMU_CAPS_LOADPARM);

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
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("ppc64-usb-controller-legacy",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST_FULL("ppc64-usb-controller-qemu-xhci",
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                 ARG_QEMU_CAPS,
                 QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                 QEMU_CAPS_NEC_USB_XHCI,
                 QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST_PARSE_ERROR("ppc64-tpmproxy-double",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_PCI_OHCI,
                        QEMU_CAPS_DEVICE_TPM_PASSTHROUGH,
                        QEMU_CAPS_DEVICE_SPAPR_TPM_PROXY);

    DO_TEST_PARSE_ERROR("ppc64-tpm-double",
                        QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                        QEMU_CAPS_PCI_OHCI,
                        QEMU_CAPS_DEVICE_TPM_PASSTHROUGH,
                        QEMU_CAPS_DEVICE_SPAPR_TPM_PROXY);

    DO_TEST_CAPS_LATEST_PPC64("ppc64-tpmproxy-single");
    DO_TEST_CAPS_LATEST_PPC64("ppc64-tpmproxy-with-tpm");

    DO_TEST("aarch64-usb-controller-qemu-xhci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_QEMU_XHCI);

    DO_TEST("aarch64-usb-controller-nec-xhci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_NEC_USB_XHCI);

    DO_TEST("sparc-minimal",
            QEMU_CAPS_SCSI_NCR53C90);

    /* VM XML has invalid arch/ostype/virttype combo, but the SKIP flag
     * will avoid the error during parse. This will cause us to fill in
     * the missing machine type using the i386 binary, despite it being
     * the wrong binary for the arch. We expect to get a failure about
     * bad arch later when creating the pretend command.
     */
    DO_TEST_FULL("missing-machine",
                 ARG_FLAGS, FLAG_EXPECT_FAILURE,
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE,
                 ARG_QEMU_CAPS, NONE);

    DO_TEST("name-escape",
            QEMU_CAPS_NAME_DEBUG_THREADS,
            QEMU_CAPS_OBJECT_SECRET,
            QEMU_CAPS_DRIVE_IOTUNE_MAX,
            QEMU_CAPS_DRIVE_IOTUNE_GROUP,
            QEMU_CAPS_VNC,
            QEMU_CAPS_NAME_GUEST,
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SPICE_GL,
            QEMU_CAPS_SPICE_RENDERNODE,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_CHARDEV_FILE_APPEND,
            QEMU_CAPS_CCID_EMULATED,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("debug-threads", QEMU_CAPS_NAME_DEBUG_THREADS);

    DO_TEST("master-key", QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("usb-long-port-path",
            QEMU_CAPS_USB_HUB);
    DO_TEST_PARSE_ERROR("usb-too-long-port-path-invalid",
                        QEMU_CAPS_USB_HUB);

    DO_TEST("acpi-table", NONE);

    DO_TEST_CAPS_LATEST("intel-iommu");
    DO_TEST_CAPS_VER("intel-iommu", "2.6.0");
    DO_TEST_CAPS_LATEST("intel-iommu-caching-mode");
    DO_TEST_CAPS_LATEST("intel-iommu-eim");
    DO_TEST_CAPS_LATEST("intel-iommu-device-iotlb");
    DO_TEST_CAPS_LATEST("intel-iommu-aw-bits");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("intel-iommu-wrong-machine");
    DO_TEST_CAPS_ARCH_LATEST("iommu-smmuv3", "aarch64");

    DO_TEST("cpu-hotplug-startup", QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);
    DO_TEST_PARSE_ERROR("cpu-hotplug-granularity",
                        QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);

    DO_TEST_CAPS_LATEST("virtio-options");
    DO_TEST_CAPS_LATEST("virtio-options-controller-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-disk-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-fs-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-input-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-memballoon-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-net-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-rng-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-video-iommu");
    DO_TEST_CAPS_LATEST("virtio-options-controller-ats");
    DO_TEST_CAPS_LATEST("virtio-options-disk-ats");
    DO_TEST_CAPS_LATEST("virtio-options-fs-ats");
    DO_TEST_CAPS_LATEST("virtio-options-input-ats");
    DO_TEST_CAPS_LATEST("virtio-options-memballoon-ats");
    DO_TEST_CAPS_LATEST("virtio-options-net-ats");
    DO_TEST_CAPS_LATEST("virtio-options-rng-ats");
    DO_TEST_CAPS_LATEST("virtio-options-video-ats");
    DO_TEST_CAPS_LATEST("virtio-options-controller-packed");
    DO_TEST_CAPS_LATEST("virtio-options-disk-packed");
    DO_TEST_CAPS_LATEST("virtio-options-fs-packed");
    DO_TEST_CAPS_LATEST("virtio-options-input-packed");
    DO_TEST_CAPS_LATEST("virtio-options-memballoon-packed");
    DO_TEST_CAPS_LATEST("virtio-options-memballoon-freepage-reporting");
    DO_TEST_CAPS_LATEST("virtio-options-net-packed");
    DO_TEST_CAPS_LATEST("virtio-options-rng-packed");
    DO_TEST_CAPS_LATEST("virtio-options-video-packed");
    DO_TEST_PARSE_ERROR("virtio-options-controller-iommu", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_PARSE_ERROR("virtio-options-disk-iommu", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-fs-iommu", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-input-iommu", QEMU_CAPS_VIRTIO_MOUSE,
                        QEMU_CAPS_VIRTIO_KEYBOARD);
    DO_TEST_PARSE_ERROR("virtio-options-net-iommu", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-memballoon-iommu", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-rng-iommu", QEMU_CAPS_DEVICE_VIRTIO_RNG,
                        QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_PARSE_ERROR("virtio-options-video-iommu", QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_VIRTIO_GPU_VIRGL,
                        QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                        QEMU_CAPS_DEVICE_VHOST_USER_GPU);
    DO_TEST_PARSE_ERROR("virtio-options-controller-ats", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_PARSE_ERROR("virtio-options-disk-ats", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-fs-ats", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-input-ats", QEMU_CAPS_VIRTIO_MOUSE,
                        QEMU_CAPS_VIRTIO_KEYBOARD);
    DO_TEST_PARSE_ERROR("virtio-options-memballoon-ats", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-net-ats", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-rng-ats", QEMU_CAPS_DEVICE_VIRTIO_RNG,
                        QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_PARSE_ERROR("virtio-options-video-ats", QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_VIRTIO_GPU_VIRGL,
                        QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                        QEMU_CAPS_DEVICE_VHOST_USER_GPU);
    DO_TEST_PARSE_ERROR("virtio-options-controller-packed", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_PARSE_ERROR("virtio-options-disk-packed", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-fs-packed", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-input-packed", QEMU_CAPS_VIRTIO_MOUSE,
                        QEMU_CAPS_VIRTIO_KEYBOARD);
    DO_TEST_PARSE_ERROR("virtio-options-memballoon-packed", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-memballoon-freepage-reporting", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-net-packed", NONE);
    DO_TEST_PARSE_ERROR("virtio-options-rng-packed", QEMU_CAPS_DEVICE_VIRTIO_RNG,
                        QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_PARSE_ERROR("virtio-options-video-packed", QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_DEVICE_VIRTIO_GPU,
                        QEMU_CAPS_VIRTIO_GPU_VIRGL,
                        QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                        QEMU_CAPS_DEVICE_VHOST_USER_GPU);

    DO_TEST("fd-memory-numa-topology", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology2", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology3", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST("fd-memory-no-numa-topology", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST_CAPS_LATEST("memfd-memory-numa");
    DO_TEST_CAPS_LATEST("memfd-memory-default-hugepage");

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
    DO_TEST("vmcoreinfo", QEMU_CAPS_DEVICE_VMCOREINFO);

    DO_TEST("user-aliases", QEMU_CAPS_KVM, QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_OBJECT_MEMORY_FILE, QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4, QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_ISA_SERIAL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_CCID_EMULATED,
            QEMU_CAPS_QCOW2_LUKS, QEMU_CAPS_OBJECT_SECRET);
    DO_TEST("user-aliases2", QEMU_CAPS_DEVICE_IOH3420, QEMU_CAPS_ICH9_AHCI);
    DO_TEST("user-aliases-usb", QEMU_CAPS_KVM,
            QEMU_CAPS_PIIX_DISABLE_S3, QEMU_CAPS_PIIX_DISABLE_S4,
            QEMU_CAPS_ICH9_USB_EHCI1);

    DO_TEST_CAPS_VER("disk-virtio-scsi-reservations", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-virtio-scsi-reservations");

    DO_TEST_CAPS_LATEST("tseg-explicit-size");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("tseg-i440fx");
    DO_TEST_CAPS_VER_PARSE_ERROR("tseg-explicit-size", "2.10.0");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("tseg-invalid-size");

    DO_TEST("video-virtio-gpu-ccw", QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW);

    DO_TEST("input-virtio-ccw", QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_DEVICE_VIRTIO_KEYBOARD_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_MOUSE_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_TABLET_CCW);

    DO_TEST_CAPS_LATEST("vhost-vsock");
    DO_TEST_CAPS_LATEST("vhost-vsock-auto");
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw-auto", "s390x");

    DO_TEST_CAPS_VER("launch-security-sev", "2.12.0");
    DO_TEST_CAPS_VER("launch-security-sev-missing-platform-info", "2.12.0");

    DO_TEST_CAPS_LATEST("vhost-user-fs-fd-memory");
    DO_TEST_CAPS_LATEST("vhost-user-fs-hugepages");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("vhost-user-fs-readonly");

    DO_TEST("riscv64-virt",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);
    DO_TEST("riscv64-virt-pci",
            QEMU_CAPS_OBJECT_GPEX);

    /* Older version checks disable-legacy usage */
    DO_TEST_CAPS_VER("virtio-transitional", "3.1.0");
    DO_TEST_CAPS_VER("virtio-non-transitional", "3.1.0");
    DO_TEST_CAPS_LATEST("virtio-transitional");
    DO_TEST_CAPS_LATEST("virtio-non-transitional");
    DO_TEST_CAPS_LATEST_PARSE_ERROR("virtio-transitional-not-supported");

    /* Simple headless guests for various architectures */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virt-headless", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-pseries-headless", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt-headless", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("s390x-ccw-headless", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-pc-headless", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-q35-headless", "x86_64");

    /* Simple guests with graphics for various architectures */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virt-graphics", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-pseries-graphics", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt-graphics", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("s390x-ccw-graphics", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-pc-graphics", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-q35-graphics", "x86_64");

    DO_TEST_CAPS_LATEST("os-firmware-bios");
    DO_TEST_CAPS_LATEST("os-firmware-efi");
    DO_TEST_CAPS_LATEST("os-firmware-efi-secboot");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-os-firmware-efi", "aarch64");

    DO_TEST_CAPS_LATEST("vhost-user-vga");
    DO_TEST_CAPS_LATEST("vhost-user-gpu-secondary");

    DO_TEST_CAPS_VER("cpu-Icelake-Server-pconfig", "3.1.0");
    DO_TEST_CAPS_LATEST("cpu-Icelake-Server-pconfig");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-default-cpu-kvm-virt-4.2", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-default-cpu-tcg-virt-4.2", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-2.7", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-2.7", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-3.1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-3.1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-4.2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-4.2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-kvm-ccw-virtio-2.7", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-tcg-ccw-virtio-2.7", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-kvm-ccw-virtio-4.2", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-tcg-ccw-virtio-4.2", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-kvm-pc-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-tcg-pc-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-kvm-q35-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-tcg-q35-4.2", "x86_64");

    DO_TEST_CAPS_LATEST("virtio-9p-multidevs");
    DO_TEST_CAPS_LATEST("virtio-9p-createmode");

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    VIR_FREE(driver.config->nbdTLSx509certdir);
    qemuTestDriverFree(&driver);
    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("qemuxml2argv"),
                      VIR_TEST_MOCK("domaincaps"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("qemucpu"),
                      VIR_TEST_MOCK("virpci"))

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
