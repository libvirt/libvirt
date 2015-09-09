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
# include "qemu/qemu_process.h"
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
    char *actualargv = NULL;
    int ret = -1;
    virDomainDefPtr vmdef = NULL;
    virDomainChrSourceDefPtr monitor_chr = NULL;
    virConnectPtr conn;
    char *log = NULL;
    char *emulator = NULL;
    virCommandPtr cmd = NULL;

    if (!(conn = virGetConnect()))
        goto fail;

    if (!(vmdef = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto fail;

    if (!virDomainDefCheckABIStability(vmdef, vmdef)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", xml);
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

    vmdef->id = -1;

    if (VIR_ALLOC(monitor_chr) < 0)
        goto fail;
    if (qemuProcessPrepareMonitorChr(driver.config,
                                     monitor_chr,
                                     vmdef->name) < 0)
        goto fail;

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
                                     vmdef, monitor_chr, json, extraFlags,
                                     migrateFrom, migrateFd, NULL,
                                     VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                                     &testCallbacks, false, false, NULL,
                                     NULL, NULL)))
        goto fail;

    if (!virtTestOOMActive()) {
        if (!!virGetLastError() != expectError) {
            if ((log = virtTestLogContentAndReset()))
                VIR_TEST_DEBUG("\n%s", log);
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

    if (virtTestCompareToFile(actualargv, cmdline) < 0)
        goto fail;

    ret = 0;

 fail:
    virDomainChrSourceDefFree(monitor_chr);
    VIR_FREE(log);
    VIR_FREE(emulator);
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

    qemuTestCapsName = info->name;
    result = qemuTestCapsCacheInsert(driver.qemuCapsCache, info->name,
                                     info->extraFlags);
    if (result < 0)
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
    bool json = false;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = abs_srcdir "/..";

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    VIR_FREE(driver.config->libDir);
    if (VIR_STRDUP_QUIET(driver.config->libDir, "/tmp") < 0)
        return EXIT_FAILURE;

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

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
