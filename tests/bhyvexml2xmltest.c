#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_domain.h"
# include "bhyve/bhyve_utils.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static bhyveConn driver;

struct testInfo {
    const char *name;
    bool different;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/bhyvexml2xmloutdata/bhyvexml2xmlout-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     false, NULL, NULL, 0,
                                     TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);

 cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = virBhyveCapsBuild()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virBhyveDriverCreateXMLConf(&driver)) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different)                        \
    do {                                                         \
        const struct testInfo info = {name, is_different};       \
        if (virTestRun("BHYVE XML-2-XML " name,                  \
                       testCompareXMLToXMLHelper, &info) < 0)    \
            ret = -1;                                            \
    } while (0)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, true)

    driver.bhyvecaps = BHYVE_CAP_AHCI32SLOT;

    DO_TEST_DIFFERENT("acpiapic");
    DO_TEST_DIFFERENT("base");
    DO_TEST_DIFFERENT("bhyveload-bootorder");
    DO_TEST_DIFFERENT("bhyveload-bootorder1");
    DO_TEST_DIFFERENT("bhyveload-bootorder2");
    DO_TEST_DIFFERENT("bhyveload-bootorder3");
    DO_TEST_DIFFERENT("bhyveload-bootorder4");
    DO_TEST_DIFFERENT("bhyveload-explicitargs");
    DO_TEST_DIFFERENT("console");
    DO_TEST_DIFFERENT("custom-loader");
    DO_TEST_DIFFERENT("disk-cdrom");
    DO_TEST_DIFFERENT("disk-cdrom-grub");
    DO_TEST_DIFFERENT("disk-virtio");
    DO_TEST_DIFFERENT("grub-bootorder");
    DO_TEST_DIFFERENT("grub-bootorder2");
    DO_TEST_DIFFERENT("grub-defaults");
    DO_TEST_DIFFERENT("localtime");
    DO_TEST_DIFFERENT("macaddr");
    DO_TEST_DIFFERENT("metadata");
    DO_TEST_DIFFERENT("serial");
    DO_TEST_DIFFERENT("serial-grub");
    DO_TEST_DIFFERENT("serial-grub-nocons");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
