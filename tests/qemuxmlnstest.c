#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#ifdef WITH_QEMU

# include "internal.h"
# include "testutils.h"
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_domain.h"
# include "datatypes.h"
# include "cpu/cpu_map.h"

# include "testutilsqemu.h"

static const char *abs_top_srcdir;
static struct qemud_driver driver;

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     virBitmapPtr extraFlags,
                                     const char *migrateFrom,
                                     int migrateFd,
                                     bool json,
                                     bool expectError)
{
    char *expectargv = NULL;
    int len;
    char *actualargv = NULL;
    int ret = -1;
    virDomainDefPtr vmdef = NULL;
    virDomainChrSourceDef monitor_chr;
    virConnectPtr conn;
    char *log = NULL;
    char *emulator = NULL;
    virCommandPtr cmd = NULL;

    if (!(conn = virGetConnect()))
        goto fail;

    len = virtTestLoadFile(cmdline, &expectargv);
    if (len < 0)
        goto fail;
    if (len && expectargv[len - 1] == '\n')
        expectargv[len - 1] = '\0';

    if (!(vmdef = virDomainDefParseFile(driver.caps, xml,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    /*
     * For test purposes, we may want to fake emulator's output by providing
     * our own script instead of a real emulator. For this to work we need to
     * specify a relative path in <emulator/> element, which, however, is not
     * allowed by RelaxNG schema for domain XML. To work around it we add an
     * extra '/' at the beginning of relative emulator path so that it looks
     * like, e.g., "/./qemu.sh" or "/../emulator/qemu.sh" instead of
     * "./qemu.sh" or "../emulator/qemu.sh" respectively. The following code
     * detects such paths, strips the extra '/' and makes the path absolute.
     */
    if (vmdef->emulator && STRPREFIX(vmdef->emulator, "/.")) {
        if (!(emulator = strdup(vmdef->emulator + 1)))
            goto fail;
        VIR_FREE(vmdef->emulator);
        vmdef->emulator = NULL;
        if (virAsprintf(&vmdef->emulator, "%s/qemuxml2argvdata/%s",
                        abs_srcdir, emulator) < 0)
            goto fail;
    }

    if (qemuCapsGet(extraFlags, QEMU_CAPS_DOMID))
        vmdef->id = 6;
    else
        vmdef->id = -1;

    memset(&monitor_chr, 0, sizeof(monitor_chr));
    monitor_chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr.data.nix.path = (char *)"/tmp/test-monitor";
    monitor_chr.data.nix.listen = true;

    qemuCapsSetList(extraFlags,
                    QEMU_CAPS_VNC_COLON,
                    QEMU_CAPS_NO_REBOOT,
                    QEMU_CAPS_NO_ACPI,
                    QEMU_CAPS_LAST);

    if (qemudCanonicalizeMachine(&driver, vmdef) < 0)
        goto fail;

    if (qemuCapsGet(extraFlags, QEMU_CAPS_DEVICE)) {
        qemuDomainPCIAddressSetPtr pciaddrs;
        if (!(pciaddrs = qemuDomainPCIAddressSetCreate(vmdef)))
            goto fail;

        if (qemuAssignDevicePCISlots(vmdef, pciaddrs) < 0)
            goto fail;

        qemuDomainPCIAddressSetFree(pciaddrs);
    }


    log = virtTestLogContentAndReset();
    VIR_FREE(log);
    virResetLastError();

    /* We do not call qemuCapsExtractVersionInfo() before calling
     * qemuBuildCommandLine(), so we should set QEMU_CAPS_PCI_MULTIBUS for
     * x86_64 and i686 architectures here.
     */
    if (STREQLEN(vmdef->os.arch, "x86_64", 6) ||
        STREQLEN(vmdef->os.arch, "i686", 4)) {
        qemuCapsSet(extraFlags, QEMU_CAPS_PCI_MULTIBUS);
    }

    if (qemuAssignDeviceAliases(vmdef, extraFlags) < 0)
        goto fail;

    if (!(cmd = qemuBuildCommandLine(conn, &driver,
                                     vmdef, &monitor_chr, json, extraFlags,
                                     migrateFrom, migrateFd, NULL,
                                     VIR_NETDEV_VPORT_PROFILE_OP_NO_OP)))
        goto fail;

    if (!!virGetLastError() != expectError) {
        if (virTestGetDebug() && (log = virtTestLogContentAndReset()))
            fprintf(stderr, "\n%s", log);
        goto fail;
    }

    if (expectError) {
        /* need to suppress the errors */
        virResetLastError();
    }

    if (!(actualargv = virCommandToString(cmd)))
        goto fail;

    if (emulator) {
        /* Skip the abs_srcdir portion of replacement emulator.  */
        char *start_skip = strstr(actualargv, abs_srcdir);
        char *end_skip = strstr(actualargv, emulator);
        if (!start_skip || !end_skip)
            goto fail;
        memmove(start_skip, end_skip, strlen(end_skip) + 1);
    }

    if (STRNEQ(expectargv, actualargv)) {
        virtTestDifference(stderr, expectargv, actualargv);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(log);
    VIR_FREE(emulator);
    VIR_FREE(expectargv);
    VIR_FREE(actualargv);
    virCommandFree(cmd);
    virDomainDefFree(vmdef);
    virUnrefConnect(conn);
    return ret;
}


struct testInfo {
    const char *name;
    virBitmapPtr extraFlags;
    const char *migrateFrom;
    int migrateFd;
    bool json;
    bool expectError;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/qemuxmlnsdata/qemuxmlns-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/qemuxmlnsdata/qemuxmlns-%s.args",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    result = testCompareXMLToArgvFiles(xml, args, info->extraFlags,
                                       info->migrateFrom, info->migrateFd,
                                       info->json, info->expectError);

cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}



static int
mymain(void)
{
    int ret = 0;
    char *map = NULL;
    bool json = false;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = "..";

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;
    if ((driver.stateDir = strdup("/nowhere")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugetlbfs_mount = strdup("/dev/hugepages")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugepage_path = strdup("/dev/hugepages/libvirt/qemu")) == NULL)
        return EXIT_FAILURE;
    driver.spiceTLS = 1;
    if (!(driver.spiceTLSx509certdir = strdup("/etc/pki/libvirt-spice")))
        return EXIT_FAILURE;
    if (!(driver.spicePassword = strdup("123456")))
        return EXIT_FAILURE;
    if (virAsprintf(&map, "%s/src/cpu/cpu_map.xml", abs_top_srcdir) < 0 ||
        cpuMapOverride(map) < 0) {
        VIR_FREE(map);
        return EXIT_FAILURE;
    }

# define DO_TEST_FULL(name, migrateFrom, migrateFd, expectError, ...)   \
    do {                                                                \
        struct testInfo info = {                                        \
            name, NULL, migrateFrom, migrateFd, json, expectError       \
        };                                                              \
        if (!(info.extraFlags = qemuCapsNew()))                         \
            return EXIT_FAILURE;                                        \
        qemuCapsSetList(info.extraFlags, __VA_ARGS__, QEMU_CAPS_LAST);  \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
        qemuCapsFree(info.extraFlags);                                  \
    } while (0)

# define DO_TEST(name, expectError, ...)                                \
    DO_TEST_FULL(name, NULL, -1, expectError, __VA_ARGS__)

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

    DO_TEST("qemu-ns-domain", false, NONE);
    DO_TEST("qemu-ns-domain-ns0", false, NONE);
    DO_TEST("qemu-ns-domain-commandline", false, NONE);
    DO_TEST("qemu-ns-domain-commandline-ns0", false, NONE);
    DO_TEST("qemu-ns-commandline", false, NONE);
    DO_TEST("qemu-ns-commandline-ns0", false, NONE);
    DO_TEST("qemu-ns-commandline-ns1", false, NONE);

    VIR_FREE(driver.stateDir);
    virCapabilitiesFree(driver.caps);
    VIR_FREE(map);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else
# include "testutils.h"

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
