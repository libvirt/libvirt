/*
 * xmconfigtest.c: Test backend for xm_internal config file handling
 *
 * Copyright (C) 2007, 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "datatypes.h"
#include "xen/xen_driver.h"
#include "xen/xm_internal.h"
#include "xenxs/xen_xm.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "memory.h"

static virCapsPtr caps;

static int
testCompareParseXML(const char *xmcfg, const char *xml, int xendConfigVersion)
{
    char *xmlData = NULL;
    char *xmcfgData = NULL;
    char *gotxmcfgData = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn = NULL;
    int wrote = 4096;
    struct _xenUnifiedPrivate priv;
    virDomainDefPtr def = NULL;

    if (VIR_ALLOC_N(gotxmcfgData, wrote) < 0)
        goto fail;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virtTestLoadFile(xml, &xmlData) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgData) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(def = virDomainDefParseString(caps, xmlData, 1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!(conf = xenFormatXM(conn, def, xendConfigVersion)))
        goto fail;

    if (virConfWriteMem(gotxmcfgData, &wrote, conf) < 0)
        goto fail;
    gotxmcfgData[wrote] = '\0';

    if (STRNEQ(xmcfgData, gotxmcfgData)) {
        virtTestDifference(stderr, xmcfgData, gotxmcfgData);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(xmlData);
    VIR_FREE(xmcfgData);
    VIR_FREE(gotxmcfgData);
    if (conf)
        virConfFree(conf);
    virDomainDefFree(def);
    virUnrefConnect(conn);

    return ret;
}

static int
testCompareFormatXML(const char *xmcfg, const char *xml, int xendConfigVersion)
{
    char *xmlData = NULL;
    char *xmcfgData = NULL;
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    struct _xenUnifiedPrivate priv;
    virDomainDefPtr def = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virtTestLoadFile(xml, &xmlData) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgData) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(conf = virConfReadMem(xmcfgData, strlen(xmcfgData), 0)))
        goto fail;

    if (!(def = xenParseXM(conf, priv.xendConfigVersion, priv.caps)))
        goto fail;

    if (!(gotxml = virDomainDefFormat(def, VIR_DOMAIN_XML_SECURE)))
        goto fail;

    if (STRNEQ(xmlData, gotxml)) {
        virtTestDifference(stderr, xmlData, gotxml);
        goto fail;
    }

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
    VIR_FREE(xmlData);
    VIR_FREE(xmcfgData);
    VIR_FREE(gotxml);
    virDomainDefFree(def);
    virUnrefConnect(conn);

    return ret;
}


struct testInfo {
    const char *name;
    int version;
    int mode;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *cfg = NULL;

    if (virAsprintf(&xml, "%s/xmconfigdata/test-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&cfg, "%s/xmconfigdata/test-%s.cfg",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml, info->version);
    else
        result = testCompareFormatXML(cfg, xml, info->version);

cleanup:
    VIR_FREE(xml);
    VIR_FREE(cfg);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

#define DO_TEST(name, version)                                          \
    do {                                                                \
        struct testInfo info0 = { name, version, 0 };                   \
        struct testInfo info1 = { name, version, 1 };                   \
        if (virtTestRun("Xen XM-2-XML Parse  " name,                    \
                        1, testCompareHelper, &info0) < 0)              \
            ret = -1;                                                   \
        if (virtTestRun("Xen XM-2-XML Format " name,                    \
                        1, testCompareHelper, &info1) < 0)              \
            ret = -1;                                                   \
    } while (0)

    DO_TEST("paravirt-old-pvfb", 1);
    DO_TEST("paravirt-old-pvfb-vncdisplay", 1);
    DO_TEST("paravirt-new-pvfb", 3);
    DO_TEST("paravirt-new-pvfb-vncdisplay", 3);
    DO_TEST("paravirt-net-e1000", 3);
    DO_TEST("paravirt-net-vifname", 3);
    DO_TEST("paravirt-vcpu", 2);
    DO_TEST("fullvirt-old-cdrom", 1);
    DO_TEST("fullvirt-new-cdrom", 2);
    DO_TEST("fullvirt-utc", 2);
    DO_TEST("fullvirt-localtime", 2);
    DO_TEST("fullvirt-usbtablet", 2);
    DO_TEST("fullvirt-usbmouse", 2);
    DO_TEST("fullvirt-serial-file", 2);
    DO_TEST("fullvirt-serial-dev-2-ports", 2);
    DO_TEST("fullvirt-serial-dev-2nd-port", 2);
    DO_TEST("fullvirt-serial-null", 2);
    DO_TEST("fullvirt-serial-pipe", 2);
    DO_TEST("fullvirt-serial-pty", 2);
    DO_TEST("fullvirt-serial-stdio", 2);
    DO_TEST("fullvirt-serial-tcp", 2);
    DO_TEST("fullvirt-serial-tcp-telnet", 2);
    DO_TEST("fullvirt-serial-udp", 2);
    DO_TEST("fullvirt-serial-unix", 2);

    DO_TEST("fullvirt-force-hpet", 2);
    DO_TEST("fullvirt-force-nohpet", 2);

    DO_TEST("fullvirt-parallel-tcp", 2);

    DO_TEST("fullvirt-sound", 2);

    DO_TEST("fullvirt-net-ioemu", 2);
    DO_TEST("fullvirt-net-netfront", 2);

    DO_TEST("escape-paths", 2);
    DO_TEST("no-source-cdrom", 2);
    DO_TEST("pci-devs", 2);

    virCapabilitiesFree(caps);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
