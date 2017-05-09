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
    unsigned int flags;
};

typedef enum {
    FLAG_IS_DIFFERENT =   1 << 0,
    FLAG_EXPECT_FAILURE = 1 << 1,
} virBhyveXMLToXMLTestFlags;

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    bool is_different = info->flags & FLAG_IS_DIFFERENT;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/bhyvexml2xmloutdata/bhyvexml2xmlout-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, xml_in,
                                     is_different ? xml_out : xml_in,
                                     false, NULL, NULL, 0,
                                     TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);

    if ((ret != 0) && (info->flags & FLAG_EXPECT_FAILURE)) {
        ret = 0;
        VIR_TEST_DEBUG("Got expected error: %s\n",
                       virGetLastErrorMessage());
        virResetLastError();
    }

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

# define DO_TEST_FULL(name, flags)                               \
    do {                                                         \
        const struct testInfo info = {name, (flags)};            \
        if (virTestRun("BHYVE XML-2-XML " name,                  \
                       testCompareXMLToXMLHelper, &info) < 0)    \
            ret = -1;                                            \
    } while (0)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, FLAG_IS_DIFFERENT)

# define DO_TEST_FAILURE(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_FAILURE)

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
    DO_TEST_DIFFERENT("vnc");
    DO_TEST_DIFFERENT("vnc-vgaconf-on");
    DO_TEST_DIFFERENT("vnc-vgaconf-off");
    DO_TEST_DIFFERENT("vnc-vgaconf-io");

    /* Address allocation tests */
    DO_TEST_DIFFERENT("addr-single-sata-disk");
    DO_TEST_DIFFERENT("addr-multiple-sata-disks");
    DO_TEST_DIFFERENT("addr-more-than-32-sata-disks");
    DO_TEST_DIFFERENT("addr-single-virtio-disk");
    DO_TEST_DIFFERENT("addr-multiple-virtio-disks");

    /* The same without 32 devs per controller support */
    driver.bhyvecaps ^= BHYVE_CAP_AHCI32SLOT;
    DO_TEST_DIFFERENT("addr-no32devs-single-sata-disk");
    DO_TEST_DIFFERENT("addr-no32devs-multiple-sata-disks");
    DO_TEST_FAILURE("addr-no32devs-more-than-32-sata-disks");

    /* USB xhci tablet */
    DO_TEST_DIFFERENT("input-xhci-tablet");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/bhyvexml2argvmock.so")

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
