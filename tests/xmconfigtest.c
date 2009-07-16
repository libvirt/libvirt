/*
 * xmconfigtest.c: Test backend for xm_internal config file handling
 *
 * Copyright (C) 2007 Red Hat
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
#include "xen_unified.h"
#include "xm_internal.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "memory.h"

static char *progname;
static char *abs_srcdir;
static virCapsPtr caps;

#define MAX_FILE 4096

static int testCompareParseXML(const char *xmcfg, const char *xml,
                               int xendConfigVersion) {
    char xmlData[MAX_FILE];
    char xmcfgData[MAX_FILE];
    char gotxmcfgData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *xmcfgPtr = &(xmcfgData[0]);
    char *gotxmcfgPtr = &(gotxmcfgData[0]);
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    int wrote = MAX_FILE;
    struct _xenUnifiedPrivate priv;
    virDomainDefPtr def = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgPtr, MAX_FILE) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(def = virDomainDefParseString(NULL, caps, xmlPtr,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!(conf = xenXMDomainConfigFormat(conn, def)))
        goto fail;

    if (virConfWriteMem(gotxmcfgPtr, &wrote, conf) < 0)
        goto fail;
    gotxmcfgPtr[wrote] = '\0';

    if (STRNEQ(xmcfgData, gotxmcfgData)) {
        virtTestDifference(stderr, xmcfgData, gotxmcfgData);
        goto fail;
    }

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
    virDomainDefFree(def);
    virUnrefConnect(conn);

    return ret;
}

static int testCompareFormatXML(const char *xmcfg, const char *xml,
                                int xendConfigVersion) {
    char xmlData[MAX_FILE];
    char xmcfgData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *xmcfgPtr = &(xmcfgData[0]);
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    struct _xenUnifiedPrivate priv;
    virDomainDefPtr def = NULL;

    conn = virGetConnect();
    if (!conn) goto fail;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgPtr, MAX_FILE) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    priv.caps = caps;
    conn->privateData = &priv;

    if (!(conf = virConfReadMem(xmcfgPtr, strlen(xmcfgPtr), 0)))
        goto fail;

    if (!(def = xenXMDomainConfigParse(conn, conf)))
        goto fail;

    if (!(gotxml = virDomainDefFormat(conn, def, VIR_DOMAIN_XML_SECURE)))
        goto fail;

    if (STRNEQ(xmlData, gotxml)) {
        virtTestDifference(stderr, xmlData, gotxml);
        goto fail;
    }

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
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

static int testCompareHelper(const void *data) {
    const struct testInfo *info = data;
    char xml[PATH_MAX];
    char cfg[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/xmconfigdata/test-%s.xml",
             abs_srcdir, info->name);
    snprintf(cfg, PATH_MAX, "%s/xmconfigdata/test-%s.cfg",
             abs_srcdir, info->name);
    if (info->mode == 0)
        return testCompareParseXML(cfg, xml, info->version);
    else
        return testCompareFormatXML(cfg, xml, info->version);
}


static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return(EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    if (!(caps = testXenCapsInit()))
        return(EXIT_FAILURE);

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

    DO_TEST("paravirt-old-pvfb", 2);
    DO_TEST("paravirt-old-pvfb-vncdisplay", 2);
    DO_TEST("paravirt-new-pvfb", 3);
    DO_TEST("paravirt-new-pvfb-vncdisplay", 3);
    DO_TEST("paravirt-net-e1000", 3);
    DO_TEST("paravirt-net-vifname", 3);
    DO_TEST("fullvirt-old-cdrom", 1);
    DO_TEST("fullvirt-new-cdrom", 2);
    DO_TEST("fullvirt-utc", 2);
    DO_TEST("fullvirt-localtime", 2);
    DO_TEST("fullvirt-usbtablet", 2);
    DO_TEST("fullvirt-usbmouse", 2);
    DO_TEST("fullvirt-serial-file", 2);
    DO_TEST("fullvirt-serial-null", 2);
    DO_TEST("fullvirt-serial-pipe", 2);
    DO_TEST("fullvirt-serial-pty", 2);
    DO_TEST("fullvirt-serial-stdio", 2);
    DO_TEST("fullvirt-serial-tcp", 2);
    DO_TEST("fullvirt-serial-tcp-telnet", 2);
    DO_TEST("fullvirt-serial-udp", 2);
    DO_TEST("fullvirt-serial-unix", 2);

    DO_TEST("fullvirt-parallel-tcp", 2);

    DO_TEST("fullvirt-sound", 2);

    DO_TEST("escape-paths", 2);
    DO_TEST("no-source-cdrom", 2);
    DO_TEST("pci-devs", 2);

    virCapabilitiesFree(caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
