/*
 * xlconfigtest.c: Test xl.cfg(5) <-> domXML config conversions
 *
 * Copyright (C) 2007, 2010-2011, 2014 Red Hat, Inc.
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * Author: Kiarie Kahurani <davidkiarie4@gmail.com>
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "datatypes.h"
#include "xenconfig/xen_xl.h"
#include "viralloc.h"
#include "virstring.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "libxl/libxl_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;


/*
 * This function provides a mechanism to replace variables in test
 * data files whose values are discovered at built time.
 */
static char *
testReplaceVarsXML(const char *xml)
{
    char *xmlcfgData;
    char *replacedXML;

    if (virTestLoadFile(xml, &xmlcfgData) < 0)
        return NULL;

    replacedXML = virStringReplace(xmlcfgData, "/LIBXL_FIRMWARE_DIR",
                                   LIBXL_FIRMWARE_DIR);

    VIR_FREE(xmlcfgData);
    return replacedXML;
}

/*
 * Parses domXML to virDomainDef object, which is then converted to xl.cfg(5)
 * config and compared with expected config.
 */
static int
testCompareParseXML(const char *xlcfg, const char *xml, bool replaceVars)
{
    char *gotxlcfgData = NULL;
    virConfPtr conf = NULL;
    virConnectPtr conn = NULL;
    int wrote = 4096;
    int ret = -1;
    virDomainDefPtr def = NULL;
    char *replacedXML = NULL;

    if (VIR_ALLOC_N(gotxlcfgData, wrote) < 0)
        goto fail;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (replaceVars) {
        if (!(replacedXML = testReplaceVarsXML(xml)))
            goto fail;
        if (!(def = virDomainDefParseString(replacedXML, caps, xmlopt,
                                            NULL, VIR_DOMAIN_XML_INACTIVE)))
            goto fail;
    } else {
        if (!(def = virDomainDefParseFile(xml, caps, xmlopt,
                                          NULL, VIR_DOMAIN_XML_INACTIVE)))
            goto fail;
    }

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        goto fail;
    }

    if (!(conf = xenFormatXL(def, conn)))
        goto fail;

    if (virConfWriteMem(gotxlcfgData, &wrote, conf) < 0)
        goto fail;
    gotxlcfgData[wrote] = '\0';

    if (virTestCompareToFile(gotxlcfgData, xlcfg) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(replacedXML);
    VIR_FREE(gotxlcfgData);
    if (conf)
        virConfFree(conf);
    virDomainDefFree(def);
    virObjectUnref(conn);

    return ret;
}

/*
 * Parses xl.cfg(5) config to virDomainDef object, which is then converted to
 * domXML and compared to expected XML.
 */
static int
testCompareFormatXML(const char *xlcfg, const char *xml, bool replaceVars)
{
    char *xlcfgData = NULL;
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    virDomainDefPtr def = NULL;
    char *replacedXML = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virTestLoadFile(xlcfg, &xlcfgData) < 0)
        goto fail;

    if (!(conf = virConfReadMem(xlcfgData, strlen(xlcfgData), 0)))
        goto fail;

    if (!(def = xenParseXL(conf, caps, xmlopt)))
        goto fail;

    if (!(gotxml = virDomainDefFormat(def, caps, VIR_DOMAIN_XML_INACTIVE |
                                      VIR_DOMAIN_XML_SECURE)))
        goto fail;

    if (replaceVars) {
        if (!(replacedXML = testReplaceVarsXML(xml)))
            goto fail;
        if (virTestCompareToString(gotxml, replacedXML) < 0)
            goto fail;
    } else {
        if (virTestCompareToFile(gotxml, xml) < 0)
            goto fail;
    }

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
    VIR_FREE(replacedXML);
    VIR_FREE(xlcfgData);
    VIR_FREE(gotxml);
    virDomainDefFree(def);
    virObjectUnref(conn);

    return ret;
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
    char *xml = NULL;
    char *cfg = NULL;

    if (virAsprintf(&xml, "%s/xlconfigdata/test-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&cfg, "%s/xlconfigdata/test-%s.cfg",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml, info->replaceVars);
    else
        result = testCompareFormatXML(cfg, xml, info->replaceVars);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(cfg);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = testXLInitCaps()))
        return EXIT_FAILURE;

    if (!(xmlopt = libxlCreateXMLConf()))
        return EXIT_FAILURE;

#define DO_TEST_PARSE(name, replace)                                    \
    do {                                                                \
        struct testInfo info0 = { name, 0, replace };                   \
        if (virTestRun("Xen XL-2-XML Parse  " name,                     \
                       testCompareHelper, &info0) < 0)                  \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_FORMAT(name, replace)                                   \
    do {                                                                \
        struct testInfo info1 = { name, 1, replace };                   \
        if (virTestRun("Xen XL-2-XML Format " name,                     \
                       testCompareHelper, &info1) < 0)                  \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(name)                                                   \
    do {                                                                \
        DO_TEST_PARSE(name, false);                                     \
        DO_TEST_FORMAT(name, false);                                    \
    } while (0)

#define DO_TEST_REPLACE_VARS(name)                                      \
    do {                                                                \
        DO_TEST_PARSE(name, true);                                      \
        DO_TEST_FORMAT(name, true);                                     \
    } while (0)

    DO_TEST_REPLACE_VARS("fullvirt-ovmf");
    DO_TEST("paravirt-maxvcpus");
    DO_TEST("new-disk");
    DO_TEST_FORMAT("disk-positional-parms-full", false);
    DO_TEST_FORMAT("disk-positional-parms-partial", false);
#ifdef LIBXL_HAVE_QED
    DO_TEST_FORMAT("disk-qed", false);
#endif
    DO_TEST("spice");
    DO_TEST("spice-features");
    DO_TEST("vif-rate");
    DO_TEST("fullvirt-nohap");
    DO_TEST("fullvirt-hpet-timer");
    DO_TEST("fullvirt-tsc-timer");
    DO_TEST("fullvirt-multi-timer");
    DO_TEST("fullvirt-nestedhvm");
    DO_TEST("fullvirt-nestedhvm-disabled");

    DO_TEST("paravirt-cmdline");
    DO_TEST_FORMAT("paravirt-cmdline-extra-root", false);
    DO_TEST_FORMAT("paravirt-cmdline-bogus-extra-root", false);
    DO_TEST("rbd-multihost-noauth");

#ifdef LIBXL_HAVE_DEVICE_CHANNEL
    DO_TEST("channel-pty");
    DO_TEST("channel-unix");
#endif
#ifdef LIBXL_HAVE_BUILDINFO_SERIAL_LIST
    DO_TEST("fullvirt-multiserial");
#endif
#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
    DO_TEST("fullvirt-multiusb");
#endif
#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
    DO_TEST("fullvirt-direct-kernel-boot");
    DO_TEST_FORMAT("fullvirt-direct-kernel-boot-extra", false);
    DO_TEST_FORMAT("fullvirt-direct-kernel-boot-bogus-extra", false);
#endif
    DO_TEST("vif-typename");
    DO_TEST("usb");
    DO_TEST("usbctrl");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
