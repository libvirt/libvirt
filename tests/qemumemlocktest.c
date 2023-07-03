#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "conf/domain_conf.h"
# include "qemu/qemu_domain.h"

# include "testutilsqemu.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

static virQEMUDriver driver;

struct testInfo {
    const char *name;
    unsigned long long memlock;
};

static int
testCompareMemLock(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/qemumemlockdata/qemumemlock-%s.xml", abs_srcdir,
                          info->name);

    if (!(def = virDomainDefParseFile(xml, driver.xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
        return -1;
    }

    return virTestCompareToULL(info->memlock, qemuDomainGetMemLockLimitBytes(def));
}

static int
mymain(void)
{
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

# define DO_TEST(name, memlock) \
    do { \
        static struct testInfo info = { \
            name, memlock \
        }; \
        if (virTestRun("QEMU MEMLOCK " name, testCompareMemLock, &info) < 0) \
            ret = -1; \
    } while (0)

    /* The tests below make sure that the memory locking limit is being
     * calculated correctly in a number of situations. Each test is
     * performed both on x86_64/pc and ppc64/pseries in order to account
     * for some architecture-specific details.
     *
     * kvm: simple KMV guest
     * tcg: simple TCG guest
     *
     * hardlimit: guest where <memtune><hard_limit> has been configured
     * locked:    guest where <memoryBacking><locked> has been enabled
     * hostdev:   guest that has some hostdev assigned
     *
     * The remaining tests cover different combinations of the above to
     * ensure settings are prioritized as expected.
     */

    qemuTestSetHostArch(&driver, VIR_ARCH_X86_64);

    if (testQemuInsertRealCaps(driver.qemuCapsCache, "x86_64", "latest", "",
                               capslatest, capscache, NULL, NULL) < 0) {
        ret = -1;
        goto cleanup;
    }

    DO_TEST("pc-kvm", 0);
    DO_TEST("pc-tcg", 0);

    DO_TEST("pc-hardlimit", 2147483648);
    DO_TEST("pc-locked", VIR_DOMAIN_MEMORY_PARAM_UNLIMITED);
    DO_TEST("pc-hostdev", 2147483648);
    DO_TEST("pc-hostdev-nvme", 3221225472);

    DO_TEST("pc-hardlimit+locked", 2147483648);
    DO_TEST("pc-hardlimit+hostdev", 2147483648);
    DO_TEST("pc-hardlimit+locked+hostdev", 2147483648);
    DO_TEST("pc-locked+hostdev", VIR_DOMAIN_MEMORY_PARAM_UNLIMITED);

    qemuTestSetHostArch(&driver, VIR_ARCH_PPC64);

    if (testQemuInsertRealCaps(driver.qemuCapsCache, "ppc64", "latest", "",
                               capslatest, capscache, NULL, NULL) < 0) {
        ret = -1;
        goto cleanup;
    }

    DO_TEST("pseries-kvm", 20971520);
    DO_TEST("pseries-tcg", 0);

    DO_TEST("pseries-hardlimit", 2147483648);
    DO_TEST("pseries-locked", VIR_DOMAIN_MEMORY_PARAM_UNLIMITED);
    DO_TEST("pseries-hostdev", 4320133120);

    DO_TEST("pseries-hardlimit+locked", 2147483648);
    DO_TEST("pseries-hardlimit+hostdev", 2147483648);
    DO_TEST("pseries-hardlimit+locked+hostdev", 2147483648);
    DO_TEST("pseries-locked+hostdev", VIR_DOMAIN_MEMORY_PARAM_UNLIMITED);

 cleanup:
    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("domaincaps"))

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
