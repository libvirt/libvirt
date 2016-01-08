#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

struct testInfo {
    const char *name;
    int different;
    bool inactive_only;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/genericxml2xmlindata/generic-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/genericxml2xmloutdata/generic-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(caps, xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     !info->inactive_only);
 cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = virTestGenericCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = virTestGenericDomainXMLConfInit()))
        return EXIT_FAILURE;

#define DO_TEST_FULL(name, is_different, inactive)                      \
    do {                                                                \
        const struct testInfo info = {name, is_different, inactive};    \
        if (virtTestRun("GENERIC XML-2-XML " name,                      \
                        testCompareXMLToXMLHelper, &info) < 0)          \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false)

#define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false)

    DO_TEST_DIFFERENT("disk-virtio");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
