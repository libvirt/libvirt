#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "interface_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *xml)
{
    g_autofree char *xmlData = NULL;
    g_autofree char *actual = NULL;
    g_autoptr(virInterfaceDef) dev = NULL;

    if (virTestLoadFile(xml, &xmlData) < 0)
        return -1;

    if (!(dev = virInterfaceDefParseString(xmlData, 0)))
        return -1;

    if (!(actual = virInterfaceDefFormat(dev)))
        return -1;

    if (STRNEQ(xmlData, actual)) {
        virTestDifferenceFull(stderr, xmlData, xml, actual, NULL);
        return -1;
    }

    return 0;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/interfaceschemadata/%s.xml", abs_srcdir,
                          (const char *)data);

    result = testCompareXMLToXMLFiles(xml);

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
