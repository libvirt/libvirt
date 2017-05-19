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
#include "xenconfig/xen_xm.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

static int
testCompareParseXML(const char *xmcfg, const char *xml)
{
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

    /* Many puppies died to bring you this code. */
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(def = virDomainDefParseFile(xml, caps, xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto fail;

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        goto fail;
    }

    if (!(conf = xenFormatXM(conn, def)))
        goto fail;

    if (virConfWriteMem(gotxmcfgData, &wrote, conf) < 0)
        goto fail;
    gotxmcfgData[wrote] = '\0';

    if (virTestCompareToFile(gotxmcfgData, xmcfg) < 0)
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

static int
testCompareFormatXML(const char *xmcfg, const char *xml)
{
    char *xmcfgData = NULL;
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    struct _xenUnifiedPrivate priv;
    virDomainDefPtr def = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virTestLoadFile(xmcfg, &xmcfgData) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(conf = virConfReadMem(xmcfgData, strlen(xmcfgData), 0)))
        goto fail;

    if (!(def = xenParseXM(conf, caps, xmlopt)))
        goto fail;

    if (!(gotxml = virDomainDefFormat(def, caps, VIR_DOMAIN_DEF_FORMAT_SECURE)))
        goto fail;

    if (virTestCompareToFile(gotxml, xml) < 0)
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
    char *cfgout = NULL;

    if (virAsprintf(&xml, "%s/xmconfigdata/test-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&cfg, "%s/xmconfigdata/test-%s.cfg",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->mode == 0)
        result = testCompareParseXML(cfg, xml);
    else
        result = testCompareFormatXML(cfg, xml);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(cfg);
    VIR_FREE(cfgout);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = xenDomainXMLConfInit()))
        return EXIT_FAILURE;

#define DO_TEST_PARSE(name)                                             \
    do {                                                                \
        struct testInfo info0 = { name, 0 };                            \
        if (virTestRun("Xen XM-2-XML Parse  " name,                     \
                       testCompareHelper, &info0) < 0)                  \
            ret = -1;                                                   \
    } while (0)


#define DO_TEST_FORMAT(name)                                            \
    do {                                                                \
        struct testInfo info1 = { name, 1 };                            \
        if (virTestRun("Xen XM-2-XML Format " name,                     \
                       testCompareHelper, &info1) < 0)                  \
            ret = -1;                                                   \
    } while (0)


#define DO_TEST(name)                                                   \
    do {                                                                \
        DO_TEST_PARSE(name);                                            \
        DO_TEST_FORMAT(name);                                           \
    } while (0)

    DO_TEST("paravirt-new-pvfb");
    DO_TEST("paravirt-new-pvfb-vncdisplay");
    DO_TEST("paravirt-net-e1000");
    DO_TEST("paravirt-net-vifname");
    DO_TEST("paravirt-vcpu");
    DO_TEST("paravirt-maxvcpus");
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

    DO_TEST("disk-drv-blktap-raw");
    DO_TEST("disk-drv-blktap2-raw");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
