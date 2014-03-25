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
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_domain.h"
# include "datatypes.h"
# include "cpu/cpu_map.h"
# include "testutilsqemu.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

static const char *abs_top_srcdir;
static virQEMUDriver driver;

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     virQEMUCapsPtr extraFlags,
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

    if (!(vmdef = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!virDomainDefCheckABIStability(vmdef, vmdef)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        goto fail;
    }

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
        if (VIR_STRDUP(emulator, vmdef->emulator + 1) < 0)
            goto fail;
        VIR_FREE(vmdef->emulator);
        vmdef->emulator = NULL;
        if (virAsprintf(&vmdef->emulator, "%s/qemuxml2argvdata/%s",
                        abs_srcdir, emulator) < 0)
            goto fail;
    }

    if (virQEMUCapsGet(extraFlags, QEMU_CAPS_DOMID))
        vmdef->id = 6;
    else
        vmdef->id = -1;

    memset(&monitor_chr, 0, sizeof(monitor_chr));
    monitor_chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr.data.nix.path = (char *)"/tmp/test-monitor";
    monitor_chr.data.nix.listen = true;

    virQEMUCapsSetList(extraFlags,
                       QEMU_CAPS_VNC_COLON,
                       QEMU_CAPS_NO_REBOOT,
                       QEMU_CAPS_NO_ACPI,
                       QEMU_CAPS_LAST);

    if (virQEMUCapsGet(extraFlags, QEMU_CAPS_DEVICE))
        qemuDomainAssignAddresses(vmdef, extraFlags, NULL);

    log = virtTestLogContentAndReset();
    VIR_FREE(log);
    virResetLastError();

    if (vmdef->os.arch == VIR_ARCH_X86_64 ||
        vmdef->os.arch == VIR_ARCH_I686) {
        virQEMUCapsSet(extraFlags, QEMU_CAPS_PCI_MULTIBUS);
    }

    if (qemuAssignDeviceAliases(vmdef, extraFlags) < 0)
        goto fail;

    if (!(cmd = qemuBuildCommandLine(conn, &driver,
                                     vmdef, &monitor_chr, json, extraFlags,
                                     migrateFrom, migrateFd, NULL,
                                     VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                                     &testCallbacks, false)))
        goto fail;

    if (!virtTestOOMActive()) {
        if (!!virGetLastError() != expectError) {
            if (virTestGetDebug() && (log = virtTestLogContentAndReset()))
                fprintf(stderr, "\n%s", log);
            goto fail;
        }

        if (expectError) {
            /* need to suppress the errors */
            virResetLastError();
        }
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
    virObjectUnref(conn);
    return ret;
}


struct testInfo {
    const char *name;
    virQEMUCapsPtr extraFlags;
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
        abs_top_srcdir = abs_srcdir "/..";

    driver.config = virQEMUDriverConfigNew(false);
    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;
    if (!(driver.xmlopt = virQEMUDriverCreateXMLConf(&driver)))
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
        if (!(info.extraFlags = virQEMUCapsNew()))                      \
            return EXIT_FAILURE;                                        \
        virQEMUCapsSetList(info.extraFlags, __VA_ARGS__, QEMU_CAPS_LAST);\
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        testCompareXMLToArgvHelper, &info) < 0)         \
            ret = -1;                                                   \
        virObjectUnref(info.extraFlags);                                \
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

    virObjectUnref(driver.config);
    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);
    VIR_FREE(map);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
