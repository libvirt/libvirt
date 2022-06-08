/*
 * xmconfigtest.c: Test backend for xm_internal config file handling
 *
 * Copyright (C) 2007, 2010-2011, 2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <unistd.h>

#include "internal.h"
#include "datatypes.h"
#include "libxl/xen_xm.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "libxl/libxl_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static libxlDriverPrivate *driver;

static int
testCompareParseXML(const char *xmcfg, const char *xml)
{
    g_autofree char *gotxmcfgData = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autoptr(virConnect) conn = NULL;
    int wrote = 4096;
    g_autoptr(virDomainDef) def = NULL;

    gotxmcfgData = g_new0(char, wrote);

    conn = virGetConnect();
    if (!conn)
        return -1;

    if (!(def = virDomainDefParseFile(xml, driver->xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        return -1;

    if (!virDomainDefCheckABIStability(def, def, driver->xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        return -1;
    }

    if (!(conf = xenFormatXM(conn, def)))
        return -1;

    if (virConfWriteMem(gotxmcfgData, &wrote, conf) < 0)
        return -1;
    gotxmcfgData[wrote] = '\0';

    if (virTestCompareToFile(gotxmcfgData, xmcfg) < 0)
        return -1;

    return 0;
}

static int
testCompareFormatXML(const char *xmcfg, const char *xml)
{
    g_autofree char *xmcfgData = NULL;
    g_autofree char *gotxml = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);

    if (virTestLoadFile(xmcfg, &xmcfgData) < 0)
        return -1;

    if (!(conf = virConfReadString(xmcfgData, 0)))
        return -1;

    if (!(def = xenParseXM(conf, cfg->caps, driver->xmlopt)))
        return -1;

    if (!(gotxml = virDomainDefFormat(def, driver->xmlopt, VIR_DOMAIN_DEF_FORMAT_SECURE)))
        return -1;

    if (virTestCompareToFile(gotxml, xml) < 0)
        return -1;

    return 0;
}


struct testInfo {
    const char *name;
    int mode;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *cfg = NULL;

    xml = g_strdup_printf("%s/xmconfigdata/test-%s.xml", abs_srcdir, info->name);
    cfg = g_strdup_printf("%s/xmconfigdata/test-%s.cfg", abs_srcdir, info->name);

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml);
    else
        result = testCompareFormatXML(cfg, xml);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(driver = testXLInitDriver()))
        return EXIT_FAILURE;

#define DO_TEST_PARSE(name) \
    do { \
        struct testInfo info0 = { name, 0 }; \
        if (virTestRun("Xen XM-2-XML Parse  " name, \
                       testCompareHelper, &info0) < 0) \
            ret = -1; \
    } while (0)


#define DO_TEST_FORMAT(name) \
    do { \
        struct testInfo info1 = { name, 1 }; \
        if (virTestRun("Xen XM-2-XML Format " name, \
                       testCompareHelper, &info1) < 0) \
            ret = -1; \
    } while (0)


#define DO_TEST(name) \
    do { \
        DO_TEST_PARSE(name); \
        DO_TEST_FORMAT(name); \
    } while (0)

    DO_TEST("paravirt-new-pvfb");
    DO_TEST("paravirt-new-pvfb-vncdisplay");
    DO_TEST("paravirt-net-e1000");
    DO_TEST("paravirt-net-fakemodel");
    DO_TEST("paravirt-net-vifname");
    DO_TEST("paravirt-vcpu");
    DO_TEST("paravirt-maxvcpus");
    DO_TEST_FORMAT("paravirt-root");
    DO_TEST_FORMAT("paravirt-extra-root");
    DO_TEST("fullvirt-new-cdrom");
    DO_TEST("fullvirt-utc");
    DO_TEST("fullvirt-localtime");
    DO_TEST("fullvirt-usbtablet");
    DO_TEST("fullvirt-usbmouse");
    DO_TEST("fullvirt-serial-file");
    DO_TEST("fullvirt-serial-null");
    DO_TEST("fullvirt-serial-pipe");
    DO_TEST("fullvirt-serial-pty");
    DO_TEST("fullvirt-serial-stdio");
    DO_TEST("fullvirt-serial-tcp");
    DO_TEST("fullvirt-serial-tcp-telnet");
    DO_TEST("fullvirt-serial-udp");
    DO_TEST("fullvirt-serial-unix");

    DO_TEST("fullvirt-force-hpet");
    DO_TEST("fullvirt-force-nohpet");
    DO_TEST("fullvirt-nohap");

    DO_TEST("fullvirt-parallel-tcp");

    DO_TEST("fullvirt-sound");

    DO_TEST("fullvirt-net-netfront");

    DO_TEST_FORMAT("fullvirt-default-feature");

    DO_TEST("escape-paths");
    DO_TEST("no-source-cdrom");
    DO_TEST("pci-devs");
    DO_TEST_FORMAT("pci-dev-syntax");

    DO_TEST("disk-drv-blktap-raw");
    DO_TEST("disk-drv-blktap2-raw");

    testXLFreeDriver(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("xl"))
