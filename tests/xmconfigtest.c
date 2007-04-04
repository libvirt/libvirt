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

#include <stdio.h>
#include <string.h>

#ifdef WITH_XEN
#include "xen_unified.h"
#include "xm_internal.h"
#include "testutils.h"
#include "internal.h"
#include "conf.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareParseXML(const char *xmcfg, const char *xml, int xendConfigVersion) {
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
    void *old_priv;
    struct _xenUnifiedPrivate priv;

    conn = virConnectOpen("test:///default");
    if (!conn) goto fail;
    old_priv = conn->privateData;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgPtr, MAX_FILE) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    conn->privateData = &priv;

    if (!(conf = xenXMParseXMLToConfig(conn, xmlPtr)))
        goto fail;

    if (virConfWriteMem(gotxmcfgPtr, &wrote, conf) < 0)
        goto fail;
    gotxmcfgPtr[wrote] = '\0';

    if (getenv("DEBUG_TESTS")) {
        printf("Expect %d '%s'\n", (int)strlen(xmcfgData), xmcfgData);
        printf("Actual %d '%s'\n", (int)strlen(gotxmcfgData), gotxmcfgData);
    }
    if (strcmp(xmcfgData, gotxmcfgData))
        goto fail;

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);

    if (conn) {
        conn->privateData = old_priv;
        virConnectClose(conn);
    }

    return ret;
}

static int testCompareFormatXML(const char *xmcfg, const char *xml, int xendConfigVersion) {
    char xmlData[MAX_FILE];
    char xmcfgData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *xmcfgPtr = &(xmcfgData[0]);
    char *gotxml = NULL;
    virConfPtr conf = NULL;
    int ret = -1;
    virConnectPtr conn;
    void *old_priv;
    struct _xenUnifiedPrivate priv;

    conn = virConnectOpen("test:///default");
    if (!conn) goto fail;
    old_priv = conn->privateData;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (virtTestLoadFile(xmcfg, &xmcfgPtr, MAX_FILE) < 0)
        goto fail;

    /* Many puppies died to bring you this code. */
    priv.xendConfigVersion = xendConfigVersion;
    conn->privateData = &priv;

    if (!(conf = virConfReadMem(xmcfgPtr, strlen(xmcfgPtr))))
        goto fail;

    if (!(gotxml = xenXMDomainFormatXML(conn, conf)))
        goto fail;

    if (getenv("DEBUG_TESTS")) {
        printf("Expect %d '%s'\n", (int)strlen(xmlData), xmlData);
        printf("Actual %d '%s'\n", (int)strlen(gotxml), gotxml);
    }
    if (strcmp(xmlData, gotxml))
        goto fail;

    ret = 0;

 fail:
    if (conf)
        virConfFree(conf);
    if (gotxml)
        free(gotxml);

    if (conn) {
        conn->privateData = old_priv;
        virConnectClose(conn);
    }

    return ret;
}

static int testCompareParavirtOldPVFBFormat(void *data ATTRIBUTE_UNUSED) {
    return testCompareFormatXML("xmconfigdata/test-paravirt-old-pvfb.cfg",
                                "xmconfigdata/test-paravirt-old-pvfb.xml",
                                2);
}
static int testCompareParavirtOldPVFBParse(void *data ATTRIBUTE_UNUSED) {
    return testCompareParseXML("xmconfigdata/test-paravirt-old-pvfb.cfg",
                               "xmconfigdata/test-paravirt-old-pvfb.xml",
                               2);
}

static int testCompareParavirtNewPVFBFormat(void *data ATTRIBUTE_UNUSED) {
    return testCompareFormatXML("xmconfigdata/test-paravirt-new-pvfb.cfg",
                                "xmconfigdata/test-paravirt-new-pvfb.xml",
                                3);
}
static int testCompareParavirtNewPVFBParse(void *data ATTRIBUTE_UNUSED) {
    return testCompareParseXML("xmconfigdata/test-paravirt-new-pvfb.cfg",
                               "xmconfigdata/test-paravirt-new-pvfb.xml",
                               3);
}

static int testCompareFullvirtOldCDROMFormat(void *data ATTRIBUTE_UNUSED) {
    return testCompareFormatXML("xmconfigdata/test-fullvirt-old-cdrom.cfg",
                                "xmconfigdata/test-fullvirt-old-cdrom.xml",
                                1);
}
static int testCompareFullvirtOldCDROMParse(void *data ATTRIBUTE_UNUSED) {
    return testCompareParseXML("xmconfigdata/test-fullvirt-old-cdrom.cfg",
                               "xmconfigdata/test-fullvirt-old-cdrom.xml",
                               1);
}

static int testCompareFullvirtNewCDROMFormat(void *data ATTRIBUTE_UNUSED) {
    return testCompareFormatXML("xmconfigdata/test-fullvirt-new-cdrom.cfg",
                                "xmconfigdata/test-fullvirt-new-cdrom.xml",
                                2);
}
static int testCompareFullvirtNewCDROMParse(void *data ATTRIBUTE_UNUSED) {
    return testCompareParseXML("xmconfigdata/test-fullvirt-new-cdrom.cfg",
                               "xmconfigdata/test-fullvirt-new-cdrom.xml",
                               2);
}


int
main(int argc, char **argv)
{
    int ret = 0;

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        exit(EXIT_FAILURE);
    }

    if (virtTestRun("Paravirt old PVFB (Format)",
                    1, testCompareParavirtOldPVFBFormat, NULL) != 0)
        ret = -1;

    if (virtTestRun("Paravirt new PVFB (Format)",
                    1, testCompareParavirtNewPVFBFormat, NULL) != 0)
        ret = -1;

    if (virtTestRun("Fullvirt old PVFB (Format)",
                    1, testCompareFullvirtOldCDROMFormat, NULL) != 0)
        ret = -1;

    if (virtTestRun("Fullvirt new PVFB (Format)",
                    1, testCompareFullvirtNewCDROMFormat, NULL) != 0)
        ret = -1;

    if (virtTestRun("Paravirt old PVFB (Parse)",
                    1, testCompareParavirtOldPVFBParse, NULL) != 0)
        ret = -1;
    if (virtTestRun("Paravirt new PVFB (Parse)",
                    1, testCompareParavirtNewPVFBParse, NULL) != 0)
        ret = -1;
    if (virtTestRun("Fullvirt old PVFB (Parse)",
                    1, testCompareFullvirtOldCDROMParse, NULL) != 0)
        ret = -1;
    if (virtTestRun("Fullvirt new PVFB (Parse)",
                    1, testCompareFullvirtNewCDROMParse, NULL) != 0)
        ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
#else /* WITHOUT_XEN */
int
main(void)
{
    fprintf(stderr, "libvirt compiled without Xen support\n");
    return(0);
}
#endif /* WITH_XEN */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
