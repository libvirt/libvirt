#include <config.h>

#include "testutils.h"
#include "virfilewrapper.h"
#define LIBVIRT_VIRRESCTRLPRIV_H_ALLOW
#include "virresctrlpriv.h"


#define VIR_FROM_THIS VIR_FROM_NONE

struct virResctrlData {
    const char *filename;
    bool fail;
};


static int
test_virResctrlGetUnused(const void *opaque)
{
    struct virResctrlData *data = (struct virResctrlData *) opaque;
    g_autofree char *system_dir = NULL;
    g_autofree char *resctrl_dir = NULL;
    g_autoptr(virResctrlAlloc) alloc = NULL;
    g_autofree char *schemata_str = NULL;
    g_autofree char *schemata_file = NULL;
    g_autoptr(virCaps) caps = NULL;

    system_dir = g_strdup_printf("%s/vircaps2xmldata/linux-%s/system", abs_srcdir,
                                 data->filename);

    resctrl_dir = g_strdup_printf("%s/vircaps2xmldata/linux-%s/resctrl",
                                  abs_srcdir, data->filename);

    schemata_file = g_strdup_printf("%s/virresctrldata/%s.schemata", abs_srcdir,
                                    data->filename);

    virFileWrapperAddPrefix("/sys/devices/system", system_dir);
    virFileWrapperAddPrefix("/sys/fs/resctrl", resctrl_dir);

    caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false);
    if (!caps || virCapabilitiesInitCaches(caps) < 0) {
        fprintf(stderr, "Could not initialize capabilities");
        return -1;
    }

    alloc = virResctrlAllocGetUnused(caps->host.resctrl);

    virFileWrapperClearPrefixes();

    if (!alloc) {
        if (data->fail)
            return 0;
        return -1;
    } else if (data->fail) {
        VIR_TEST_DEBUG("Error expected but there wasn't any.");
        return -1;
    }

    schemata_str = virResctrlAllocFormat(alloc);

    if (virTestCompareToFile(schemata_str, schemata_file) < 0)
        return -1;

    return 0;
}


static int
mymain(void)
{
    struct virResctrlData data = {0};
    int ret = 0;

#define DO_TEST_UNUSED(_filename) \
    do { \
        data = (struct virResctrlData) { .filename = _filename }; \
        if (virTestRun("Free: " _filename, test_virResctrlGetUnused, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_UNUSED("resctrl");
    DO_TEST_UNUSED("resctrl-cdp");
    DO_TEST_UNUSED("resctrl-skx");
    DO_TEST_UNUSED("resctrl-skx-twocaches");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
