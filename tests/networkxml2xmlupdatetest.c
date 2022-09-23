#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *netxml, const char *updatexml,
                         const char *outxml, unsigned int flags,
                         unsigned int command, unsigned int section,
                         int parentIndex, bool expectFailure)
{
    g_autofree char *updateXmlData = NULL;
    g_autofree char *actual = NULL;
    int ret = -1;
    g_autoptr(virNetworkDef) def = NULL;

    if (virTestLoadFile(updatexml, &updateXmlData) < 0)
        return -1;

    if (!(def = virNetworkDefParse(NULL, netxml, NULL, false)))
        goto fail;

    if (virNetworkDefUpdateSection(def, command, section, parentIndex,
                                   updateXmlData, 0) < 0)
        goto fail;

    if (!(actual = virNetworkDefFormat(def, NULL, flags)))
        goto fail;

    if (!expectFailure) {
        if (virTestCompareToFile(actual, outxml) < 0)
            return -1;
    }

    ret = 0;

 fail:
    if (expectFailure) {
        if (ret == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", "Failed to fail.");
            ret = -1;
        } else {
            virResetLastError();
            ret = 0;
        }
    }
    return ret;
}

struct testInfo {
    const char *name;
    const char *updatexml;
    const char *netxml;
    const char *outxml;
    unsigned int command;
    unsigned int section;
    int parentIndex;
    unsigned int flags;
    bool expectFailure;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    int result = -1;
    g_autofree char *netxml = NULL;
    g_autofree char *updatexml = NULL;
    g_autofree char *outxml = NULL;

    netxml = g_strdup_printf("%s/networkxml2xmlin/%s.xml",
                             abs_srcdir, info->netxml);
    updatexml = g_strdup_printf("%s/networkxml2xmlupdatein/%s.xml",
                                abs_srcdir, info->updatexml);
    outxml = g_strdup_printf("%s/networkxml2xmlupdateout/%s.xml",
                             abs_srcdir, info->outxml);

    result = testCompareXMLToXMLFiles(netxml, updatexml, outxml, info->flags,
                                      info->command, info->section,
                                      info->parentIndex, info->expectFailure);

    return result;
}

static int
mymain(void)
{
    int ret = 0;
    unsigned int section;

#define DO_TEST_FULL(name, updatexml, netxml, outxml, command, section, \
                     parentIndex, flags, expectFailure) \
    do { \
        const struct testInfo info = {name, updatexml, netxml, outxml, \
                                      command, section, flags, \
                                      parentIndex, expectFailure}; \
        if (virTestRun("Network XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST(name, updatexml, netxml, outxml, command) \
    DO_TEST_FULL(name, updatexml, netxml, outxml, command, section, -12435, \
                 0, false)
#define DO_TEST_FAIL(name, updatexml, netxml, command) \
    DO_TEST_FULL(name, updatexml, netxml, "n/a", command, section, -12345, \
                 0, true)

#define DO_TEST_INDEX(name, updatexml, netxml, outxml, command, index) \
    DO_TEST_FULL(name, updatexml, netxml, outxml, command, section, index, \
                 0, false)
#define DO_TEST_INDEX_FAIL(name, updatexml, netxml, command, index) \
    DO_TEST_FULL(name, updatexml, netxml, "n/a", command, section, index, \
                 0, true)


    section = VIR_NETWORK_SECTION_IP_DHCP_HOST;
    DO_TEST_INDEX_FAIL("add-host-incomplete",
                       "host-incomplete",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_ADD_LAST,
                       0);
    DO_TEST_INDEX_FAIL("add-host-new-incomplete",
                       "host-new-incomplete",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_ADD_LAST,
                       0);
    DO_TEST_INDEX_FAIL("add-host-existing",
                       "host-existing",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_ADD_LAST,
                       0);
    DO_TEST_INDEX("add-host-new",
                  "host-new",
                  "nat-network",
                  "nat-network-hosts",
                  VIR_NETWORK_UPDATE_COMMAND_ADD_LAST,
                  0);
    DO_TEST_INDEX_FAIL("modify-host-missing",
                       "host-new",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_MODIFY,
                      0);
    DO_TEST_INDEX_FAIL("modify-host-incomplete",
                       "host-incomplete",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_MODIFY,
                      0);
    DO_TEST_INDEX("modify-host",
                  "host-updated",
                  "nat-network",
                  "nat-network-host-updated",
                  VIR_NETWORK_UPDATE_COMMAND_MODIFY,
                  0);
    DO_TEST_INDEX("delete-host-incomplete",
                  "host-incomplete",
                  "nat-network",
                  "nat-network-one-host",
                  VIR_NETWORK_UPDATE_COMMAND_DELETE,
                  0);
    DO_TEST_INDEX("delete-host-existing",
                  "host-existing",
                  "nat-network",
                  "nat-network-one-host",
                  VIR_NETWORK_UPDATE_COMMAND_DELETE,
                  0);
    DO_TEST_INDEX_FAIL("delete-host-missing",
                       "host-new",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_DELETE,
                       0);


    section = VIR_NETWORK_SECTION_IP_DHCP_RANGE;
    DO_TEST_INDEX("add-dhcp-range",
                  "dhcp-range",
                  "dhcp6host-routed-network",
                  "dhcp6host-routed-network-range",
                  VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST,
                  0);
    DO_TEST_INDEX_FAIL("add-dhcp-range-outside-net",
                       "dhcp-range-10",
                       "dhcp6host-routed-network",
                       VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST,
                       0);
    DO_TEST_INDEX("append-dhcp-range",
                  "dhcp-range",
                  "dhcp6host-routed-network",
                  "dhcp6host-routed-network-another-range",
                  VIR_NETWORK_UPDATE_COMMAND_ADD_LAST,
                  1);
    DO_TEST_INDEX("delete-dhcp-range",
                  "dhcp-range-existing",
                  "nat-network",
                  "nat-network-no-range",
                  VIR_NETWORK_UPDATE_COMMAND_DELETE,
                  0);
    DO_TEST_INDEX_FAIL("delete-dhcp-range",
                       "dhcp-range",
                       "nat-network",
                       VIR_NETWORK_UPDATE_COMMAND_DELETE,
                       0);


    section = VIR_NETWORK_SECTION_FORWARD_INTERFACE;
    DO_TEST("insert-forward-interface",
            "interface-eth47",
            "nat-network-dns-srv-record",
            "nat-network-forward-ifaces",
            VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST("delete-forward-interface",
            "interface-eth1",
            "nat-network-dns-srv-record",
            "nat-network-no-forward-ifaces",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST_FAIL("delete-forward-interface",
                 "interface-eth47",
                 "nat-network-dns-srv-record",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);


    section = VIR_NETWORK_SECTION_PORTGROUP;
    DO_TEST("insert-portgroup",
            "portgroup-alison",
            "openvswitch-net",
            "openvswitch-net-more-portgroups",
            VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST_FAIL("append-duplicate-portgroup",
                 "portgroup-alice-new",
                 "openvswitch-net",
                 VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    DO_TEST("modify-portgroup",
            "portgroup-alice-new",
            "openvswitch-net",
            "openvswitch-net-modified",
            VIR_NETWORK_UPDATE_COMMAND_MODIFY);
    DO_TEST_FAIL("modify-missing-portgroup",
                 "portgroup-alison",
                 "openvswitch-net",
                 VIR_NETWORK_UPDATE_COMMAND_MODIFY);
    DO_TEST("delete-portgroup",
            "portgroup-alice-new",
            "openvswitch-net",
            "openvswitch-net-without-alice",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST_FAIL("delete-missing-portgroup",
                 "portgroup-alice-new",
                 "nat-network-dns-srv-record",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);


    section = VIR_NETWORK_SECTION_DNS_HOST;
    DO_TEST_FAIL("insert-incomplete-host",
                 "dns-host-gateway-incomplete",
                 "nat-network-dns-hosts",
                 VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST("insert-host",
            "dns-host-pudding",
            "nat-network-dns-hosts",
            "nat-network-dns-more-hosts",
            VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST_FAIL("delete-missing-unparsable-dns-host",
                 "unparsable-dns-host",
                 "nat-network",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST("delete-dns-host",
            "dns-host-gateway-incomplete",
            "nat-network-dns-hosts",
            "nat-network-no-hosts",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);


    section = VIR_NETWORK_SECTION_DNS_TXT;
    DO_TEST("insert-dns-txt-record",
            "dns-txt-record-snowman",
            "nat-network-dns-txt-record",
            "nat-network-dns-txt-records",
            VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST_FAIL("append-duplicate-dns-txt-record",
                 "dns-txt-record-example",
                 "nat-network-dns-txt-record",
                 VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    DO_TEST("delete-dns-txt-record",
            "dns-txt-record-example",
            "nat-network-dns-txt-record",
            "nat-network-dns-txt-none",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST_FAIL("delete-missing-dns-txt-record",
                 "dns-txt-record-snowman",
                 "nat-network-dns-txt-record",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);


    section = VIR_NETWORK_SECTION_DNS_SRV;
    DO_TEST("insert-first-srv-record-service",
            "srv-record",
            "nat-network",
            "nat-network-dns-srv-record",
            VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST);
    DO_TEST("append-first-srv-record-service",
            "srv-record",
            "nat-network",
            "nat-network-dns-srv-record",
            VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    DO_TEST_FAIL("add-existing-dns-srv-record",
                 "srv-record",
                 "nat-network-dns-srv-record",
                 VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    DO_TEST("append-srv-record-service",
            "srv-record-donkey",
            "nat-network-dns-srv-record",
            "nat-network-dns-srv-records",
            VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);

    DO_TEST_FAIL("delete-missing-srv-record-service",
                 "srv-record-service",
                 "nat-network",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST_FAIL("delete-srv-record-invalid",
                 "srv-record-invalid",
                 "nat-network-dns-srv-record",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST("delete-srv-record-donkey",
            "srv-record-donkey",
            "nat-network-dns-srv-records",
            "nat-network-dns-srv-record",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST_FAIL("delete-ambiguous-srv-record-service",
                 "srv-record-service",
                 "nat-network-dns-srv-records",
                 VIR_NETWORK_UPDATE_COMMAND_DELETE);
    DO_TEST("delete-srv-record-protocol",
            "srv-record-protocol",
            "nat-network-dns-srv-record",
            "nat-network",
            VIR_NETWORK_UPDATE_COMMAND_DELETE);


    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
