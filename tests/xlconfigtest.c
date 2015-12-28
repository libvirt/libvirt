/*
 * xlconfigtest.c: Test backend for xl_internal config file handling
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
 * parses the xml, creates a domain def and compare with equivalent xm config
 */
static int
testCompareParseXML(const char *xmcfg, const char *xml)
{
    char *gotxmcfgData = NULL;
    virConfPtr conf = NULL;
    virConnectPtr conn = NULL;
    int wrote = 4096;
    int ret = -1;
    virDomainDefPtr def = NULL;

    if (VIR_ALLOC_N(gotxmcfgData, wrote) < 0)
        goto fail;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (!(def = virDomainDefParseFile(xml, caps, xmlopt,
                                      VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!virDomainDefCheckABIStability(def, def)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        goto fail;
    }

    if (!(conf = xenFormatXL(def, conn)))
        goto fail;

    if (virConfWriteMem(gotxmcfgData, &wrote, conf) < 0)
        goto fail;
    gotxmcfgData[wrote] = '\0';

    if (virtTestCompareToFile(gotxmcfgData, xmcfg) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(gotxmcfgData);
    if (conf)
        virConfFree(conf);
    virDomainDefFree(def);
    virObjectUnref(conn);

    return ret;
}
/*
 * parses the xl config, develops domain def and compares with equivalent xm config
 */
static int
testCompareFormatXML(const char *xmcfg, const char *xml)
{
    char *xmcfgData = NULL;
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    virDomainDefPtr def = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgData) < 0)
        goto fail;

    if (!(conf = virConfReadMem(xmcfgData, strlen(xmcfgData), 0)))
        goto fail;

    if (!(def = xenParseXL(conf, caps, xmlopt)))
        goto fail;

    if (!(gotxml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE |
                                      VIR_DOMAIN_XML_SECURE)))
        goto fail;

    if (virtTestCompareToFile(gotxml, xml) < 0)
        goto fail;

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
    VIR_FREE(xmcfgData);
    VIR_FREE(gotxml);
    virDomainDefFree(def);
    virObjectUnref(conn);

    return ret;
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
    char *xml = NULL;
    char *cfg = NULL;

    if (virAsprintf(&xml, "%s/xlconfigdata/test-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&cfg, "%s/xlconfigdata/test-%s.cfg",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml);
    else
        result = testCompareFormatXML(cfg, xml);

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

#define DO_TEST(name)                                                   \
    do {                                                                \
        struct testInfo info0 = { name, 0 };                            \
        struct testInfo info1 = { name, 1 };                            \
        if (virtTestRun("Xen XM-2-XML Parse  " name,                    \
                        testCompareHelper, &info0) < 0)                 \
            ret = -1;                                                   \
        if (virtTestRun("Xen XM-2-XML Format " name,                    \
                        testCompareHelper, &info1) < 0)                 \
            ret = -1;                                                   \
    } while (0)

    DO_TEST("paravirt-maxvcpus");
    DO_TEST("new-disk");
    DO_TEST("spice");
    DO_TEST("spice-features");
    DO_TEST("vif-rate");

#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
    DO_TEST("fullvirt-multiusb");
#endif
#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
    DO_TEST("fullvirt-direct-kernel-boot");
#endif

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
