/*
 * xlconfigtest.c: Test xl.cfg(5) <-> domXML config conversions
 *
 * Copyright (C) 2007, 2010-2011, 2014 Red Hat, Inc.
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2014 David Kiarie Kahurani
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
#include "libxl/xen_xl.h"
#include "virstring.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "libxl/libxl_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static libxlDriverPrivate *driver;

/*
 * This function provides a mechanism to replace variables in test
 * data files whose values are discovered at built time.
 */
static char *
testReplaceVarsXML(const char *xml)
{
    g_autofree char *xmlcfgData = NULL;
    char *replacedXML;

    if (virTestLoadFile(xml, &xmlcfgData) < 0)
        return NULL;

    replacedXML = virStringReplace(xmlcfgData, "/LIBXL_FIRMWARE_DIR",
                                   LIBXL_FIRMWARE_DIR);

    return replacedXML;
}

/*
 * Parses domXML to virDomainDef object, which is then converted to xl.cfg(5)
 * config and compared with expected config.
 */
static int
testCompareParseXML(const char *xlcfg, const char *xml, bool replaceVars)
{
    g_autofree char *gotxlcfgData = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autoptr(virConnect) conn = NULL;
    int wrote = 4096;
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *replacedXML = NULL;

    gotxlcfgData = g_new0(char, wrote);

    conn = virGetConnect();
    if (!conn)
        return -1;

    if (replaceVars) {
        if (!(replacedXML = testReplaceVarsXML(xml)))
            return -1;
        if (!(def = virDomainDefParseString(replacedXML, driver->xmlopt,
                                            NULL, VIR_DOMAIN_XML_INACTIVE)))
            return -1;
    } else {
        if (!(def = virDomainDefParseFile(xml, driver->xmlopt,
                                          NULL, VIR_DOMAIN_XML_INACTIVE)))
            return -1;
    }

    if (!virDomainDefCheckABIStability(def, def, driver->xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        return -1;
    }

    if (!(conf = xenFormatXL(def, conn)))
        return -1;

    if (virConfWriteMem(gotxlcfgData, &wrote, conf) < 0)
        return -1;
    gotxlcfgData[wrote] = '\0';

    if (virTestCompareToFile(gotxlcfgData, xlcfg) < 0)
        return -1;

    return 0;
}

/*
 * Parses xl.cfg(5) config to virDomainDef object, which is then converted to
 * domXML and compared to expected XML.
 */
static int
testCompareFormatXML(const char *xlcfg, const char *xml, bool replaceVars)
{
    g_autofree char *xlcfgData = NULL;
    g_autofree char *gotxml = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autoptr(virConnect) conn = NULL;
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *replacedXML = NULL;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);

    conn = virGetConnect();
    if (!conn)
        return -1;

    if (virTestLoadFile(xlcfg, &xlcfgData) < 0)
        return -1;

    if (!(conf = virConfReadString(xlcfgData, 0)))
        return -1;

    if (!(def = xenParseXL(conf, cfg->caps, driver->xmlopt)))
        return -1;

    if (!(gotxml = virDomainDefFormat(def, driver->xmlopt,
                                      VIR_DOMAIN_XML_INACTIVE |
                                      VIR_DOMAIN_XML_SECURE)))
        return -1;

    if (replaceVars) {
        if (!(replacedXML = testReplaceVarsXML(xml)))
            return -1;
        if (virTestCompareToString(gotxml, replacedXML) < 0)
            return -1;
    } else {
        if (virTestCompareToFile(gotxml, xml) < 0)
            return -1;
    }

    return 0;
}


struct testInfo {
    const char *name;
    int mode;
    bool replaceVars;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *cfg = NULL;

    xml = g_strdup_printf("%s/xlconfigdata/test-%s.xml", abs_srcdir, info->name);
    cfg = g_strdup_printf("%s/xlconfigdata/test-%s.cfg", abs_srcdir, info->name);

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml, info->replaceVars);
    else
        result = testCompareFormatXML(cfg, xml, info->replaceVars);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(driver = testXLInitDriver()))
        return EXIT_FAILURE;

#define DO_TEST_PARSE(name, replace) \
    do { \
        struct testInfo info0 = { name, 0, replace }; \
        if (virTestRun("Xen XL-2-XML Parse  " name, \
                       testCompareHelper, &info0) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_FORMAT(name, replace) \
    do { \
        struct testInfo info1 = { name, 1, replace }; \
        if (virTestRun("Xen XL-2-XML Format " name, \
                       testCompareHelper, &info1) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST(name) \
    do { \
        DO_TEST_PARSE(name, false); \
        DO_TEST_FORMAT(name, false); \
    } while (0)

#define DO_TEST_REPLACE_VARS(name) \
    do { \
        DO_TEST_PARSE(name, true); \
        DO_TEST_FORMAT(name, true); \
    } while (0)

    DO_TEST("fullvirt-ovswitch-tagged");
    DO_TEST("fullvirt-ovswitch-trunked");
    DO_TEST_REPLACE_VARS("fullvirt-ovmf");
    DO_TEST("paravirt-maxvcpus");
    DO_TEST("new-disk");
    DO_TEST_FORMAT("disk-positional-parms-full", false);
    DO_TEST_FORMAT("disk-positional-parms-partial", false);
    DO_TEST_FORMAT("disk-qed", false);
    DO_TEST("net-fakemodel");
    DO_TEST("spice");
    DO_TEST("spice-features");
    DO_TEST("vif-rate");
    DO_TEST("fullvirt-nohap");
    DO_TEST("fullvirt-hpet-timer");
    DO_TEST("fullvirt-tsc-timer");
    DO_TEST("fullvirt-multi-timer");
    DO_TEST("fullvirt-nestedhvm");
    DO_TEST("fullvirt-nestedhvm-disabled");
    DO_TEST("fullvirt-cpuid");
    DO_TEST("fullvirt-acpi-slic");
    DO_TEST("fullvirt-pci");
    DO_TEST("fullvirt-vnuma");
    DO_TEST_PARSE("fullvirt-vnuma-autocomplete", false);
    DO_TEST_PARSE("fullvirt-vnuma-nodistances", false);
    DO_TEST_PARSE("fullvirt-vnuma-partialdist", false);

    DO_TEST("paravirt-cmdline");
    DO_TEST_FORMAT("paravirt-cmdline-extra-root", false);
    DO_TEST_FORMAT("paravirt-cmdline-bogus-extra-root", false);
    DO_TEST("rbd-multihost-noauth");
    DO_TEST_FORMAT("paravirt-type", false);
    DO_TEST_FORMAT("fullvirt-type", false);
    DO_TEST("pvh-type");

    DO_TEST("channel-pty");
    DO_TEST("channel-unix");
    DO_TEST("fullvirt-multiserial");
    DO_TEST("fullvirt-multiusb");
    DO_TEST("fullvirt-direct-kernel-boot");
    DO_TEST_FORMAT("fullvirt-direct-kernel-boot-extra", false);
    DO_TEST_FORMAT("fullvirt-direct-kernel-boot-bogus-extra", false);
#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    DO_TEST("max-gntframes");
#endif

    DO_TEST("max-eventchannels");

    DO_TEST("vif-typename");
    DO_TEST("vif-multi-ip");
    DO_TEST("usb");
    DO_TEST("usbctrl");
    DO_TEST("paravirt-e820_host");
#ifdef LIBXL_HAVE_CREATEINFO_PASSTHROUGH
    DO_TEST("fullvirt-hypervisor-features");
#endif
    DO_TEST("qemu-passthrough");

    testXLFreeDriver(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("xl"))
