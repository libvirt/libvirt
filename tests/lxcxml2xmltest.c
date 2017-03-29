#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_LXC

# include "internal.h"
# include "lxc/lxc_conf.h"
# include "testutilslxc.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

struct testInfo {
    const char *name;
    int different;
    bool inactive_only;
    unsigned int parse_flags;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/lxcxml2xmldata/lxc-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/lxcxml2xmloutdata/lxc-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(caps, xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     !info->inactive_only,
                                     NULL, NULL, info->parse_flags,
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

    if ((caps = testLXCCapsInit()) == NULL)
        return EXIT_FAILURE;

    if (!(xmlopt = lxcDomainXMLConfInit()))
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different, inactive, parse_flags)        \
    do {                                                                \
        const struct testInfo info = {name, is_different, inactive,     \
                                      parse_flags};                     \
        if (virTestRun("LXC XML-2-XML " name,                           \
                       testCompareXMLToXMLHelper, &info) < 0)           \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false, 0)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false, 0)

    /* Unset or set all envvars here that are copied in lxcdBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("systemd");
    DO_TEST("hostdev");
    DO_TEST("disk-formats");
    DO_TEST_DIFFERENT("filesystem-ram");
    DO_TEST("filesystem-root");
    DO_TEST("idmap");
    DO_TEST("capabilities");
    DO_TEST("sharenet");
    DO_TEST("ethernet");
    DO_TEST("ethernet-hostip");
    DO_TEST_FULL("filesystem-root", 0, false,
                 VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS);

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LXC */
