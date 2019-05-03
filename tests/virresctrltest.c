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
    char *system_dir = NULL;
    char *resctrl_dir = NULL;
    int ret = -1;
    virResctrlAllocPtr alloc = NULL;
    char *schemata_str = NULL;
    char *schemata_file;
    virCapsPtr caps = NULL;

    if (virAsprintf(&system_dir, "%s/vircaps2xmldata/linux-%s/system",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    if (virAsprintf(&resctrl_dir, "%s/vircaps2xmldata/linux-%s/resctrl",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    if (virAsprintf(&schemata_file, "%s/virresctrldata/%s.schemata",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    virFileWrapperAddPrefix("/sys/devices/system", system_dir);
    virFileWrapperAddPrefix("/sys/fs/resctrl", resctrl_dir);

    caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false);
    if (!caps || virCapabilitiesInitCaches(caps) < 0) {
        fprintf(stderr, "Could not initialize capabilities");
        goto cleanup;
    }

    alloc = virResctrlAllocGetUnused(caps->host.resctrl);

    virFileWrapperClearPrefixes();

    if (!alloc) {
        if (data->fail)
            ret = 0;
        goto cleanup;
    } else if (data->fail) {
        VIR_TEST_DEBUG("Error expected but there wasn't any.");
        ret = -1;
        goto cleanup;
    }

    schemata_str = virResctrlAllocFormat(alloc);

    if (virTestCompareToFile(schemata_str, schemata_file) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virObjectUnref(caps);
    virObjectUnref(alloc);
    VIR_FREE(system_dir);
    VIR_FREE(resctrl_dir);
    VIR_FREE(schemata_str);
    VIR_FREE(schemata_file);
    return ret;
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

    return ret;
}

VIR_TEST_MAIN(mymain)
