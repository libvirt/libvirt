#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "interface_conf.h"
#include "testutilsqemu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *xml)
{
    char *xmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virInterfaceDefPtr dev = NULL;

    if (virTestLoadFile(xml, &xmlData) < 0)
        goto fail;

    if (!(dev = virInterfaceDefParseString(xmlData)))
        goto fail;

    if (!(actual = virInterfaceDefFormat(dev)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virTestDifferenceFull(stderr, xmlData, xml, actual, NULL);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(xmlData);
    VIR_FREE(actual);
    virInterfaceDefFree(dev);
    return ret;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    char *xml = NULL;

    if (virAsprintf(&xml, "%s/interfaceschemadata/%s.xml",
                    abs_srcdir, (const char*)data) < 0)
        return -1;

    result = testCompareXMLToXMLFiles(xml);

    VIR_FREE(xml);
    return result;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    if (virTestRun("Interface XML-2-XML " name, \
                   testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("ethernet-dhcp");
    DO_TEST("ethernet-dhcp-and-multi-static");
    DO_TEST("ethernet-static");
    DO_TEST("ethernet-static-no-prefix");
    DO_TEST("bridge");
    DO_TEST("bridge42");
    DO_TEST("bridge-bond");
    DO_TEST("bridge-empty");
    DO_TEST("bridge-no-address");
    DO_TEST("bridge-vlan");
    DO_TEST("bridge-no-address");
    DO_TEST("vlan");
    DO_TEST("bond");
    DO_TEST("bond-arp");
    DO_TEST("ipv6-autoconf-dhcp");
    DO_TEST("ipv6-autoconf");
    DO_TEST("ipv6-dhcp");
    DO_TEST("ipv6-local");
    DO_TEST("ipv6-static-multi");
    DO_TEST("ipv6-static");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
