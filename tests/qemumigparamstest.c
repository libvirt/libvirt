/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

#include "virjson.h"
#include "virbuffer.h"
#include "virxml.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "qemumonitortestutils.h"
#include "qemu/qemu_migration_params.h"
#define LIBVIRT_QEMU_MIGRATION_PARAMSPRIV_H_ALLOW
#include "qemu/qemu_migration_paramspriv.h"
#include "qemu/qemu_monitor.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _qemuMigParamsData qemuMigParamsData;
struct _qemuMigParamsData {
    virDomainXMLOptionPtr xmlopt;
    const char *name;
};


static void
qemuMigParamsTestFormatXML(virBufferPtr buf,
                           qemuMigrationParamsPtr migParams)
{
    virBufferAddLit(buf, "<test>\n");
    virBufferAdjustIndent(buf, 2);

    if (migParams)
        qemuMigrationParamsFormat(buf, migParams);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</test>\n");
}


static int
qemuMigParamsTestXML2XML(const void *opaque)
{
    const qemuMigParamsData *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xmlFile = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    qemuMigrationParamsPtr migParams = NULL;
    char *actualXML = NULL;
    int ret = -1;

    if (virAsprintf(&xmlFile, "%s/qemumigparamsdata/%s.xml",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (!(doc = virXMLParseFileCtxt(xmlFile, &ctxt)))
        goto cleanup;

    if (qemuMigrationParamsParse(ctxt, &migParams) < 0)
        goto cleanup;

    qemuMigParamsTestFormatXML(&buf, migParams);

    if (!(actualXML = virBufferContentAndReset(&buf)))
        goto cleanup;

    if (virTestCompareToFile(actualXML, xmlFile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(xmlFile);
    VIR_FREE(actualXML);
    qemuMigrationParamsFree(migParams);
    virBufferFreeAndReset(&buf);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return ret;
}


static int
qemuMigParamsTestXML(const void *opaque)
{
    const qemuMigParamsData *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *replyFile = NULL;
    char *xmlFile = NULL;
    qemuMonitorTestPtr mon = NULL;
    virJSONValuePtr params = NULL;
    qemuMigrationParamsPtr migParams = NULL;
    char *actualXML = NULL;
    int ret = -1;

    if (virAsprintf(&replyFile, "%s/qemumigparamsdata/%s.reply",
                    abs_srcdir, data->name) < 0 ||
        virAsprintf(&xmlFile, "%s/qemumigparamsdata/%s.xml",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (!(mon = qemuMonitorTestNewFromFile(replyFile, data->xmlopt, true)))
        goto cleanup;

    if (qemuMonitorGetMigrationParams(qemuMonitorTestGetMonitor(mon),
                                      &params) < 0)
        goto cleanup;

    if (!(migParams = qemuMigrationParamsFromJSON(params)))
        goto cleanup;

    qemuMigParamsTestFormatXML(&buf, migParams);

    if (!(actualXML = virBufferContentAndReset(&buf)))
        goto cleanup;

    if (virTestCompareToFile(actualXML, xmlFile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(replyFile);
    VIR_FREE(xmlFile);
    VIR_FREE(actualXML);
    virJSONValueFree(params);
    qemuMigrationParamsFree(migParams);
    virBufferFreeAndReset(&buf);
    qemuMonitorTestFree(mon);
    return ret;
}


static int
qemuMigParamsTestJSON(const void *opaque)
{
    const qemuMigParamsData *data = opaque;
    char *replyFile = NULL;
    char *jsonFile = NULL;
    qemuMonitorTestPtr mon = NULL;
    virJSONValuePtr paramsIn = NULL;
    virJSONValuePtr paramsOut = NULL;
    qemuMigrationParamsPtr migParams = NULL;
    char *actualJSON = NULL;
    int ret = -1;

    if (virAsprintf(&replyFile, "%s/qemumigparamsdata/%s.reply",
                    abs_srcdir, data->name) < 0 ||
        virAsprintf(&jsonFile, "%s/qemumigparamsdata/%s.json",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (!(mon = qemuMonitorTestNewFromFile(replyFile, data->xmlopt, true)))
        goto cleanup;

    if (qemuMonitorGetMigrationParams(qemuMonitorTestGetMonitor(mon),
                                      &paramsIn) < 0)
        goto cleanup;

    if (!(migParams = qemuMigrationParamsFromJSON(paramsIn)))
        goto cleanup;

    if (!(paramsOut = qemuMigrationParamsToJSON(migParams)) ||
        !(actualJSON = virJSONValueToString(paramsOut, true)))
        goto cleanup;

    if (virTestCompareToFile(actualJSON, jsonFile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(replyFile);
    VIR_FREE(jsonFile);
    VIR_FREE(actualJSON);
    virJSONValueFree(paramsIn);
    virJSONValueFree(paramsOut);
    qemuMigrationParamsFree(migParams);
    qemuMonitorTestFree(mon);
    return ret;
}


static int
mymain(void)
{
    virQEMUDriver driver;
    int ret = 0;

#if !WITH_YAJL
    fputs("libvirt not compiled with JSON support, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name) \
    do { \
        qemuMigParamsData data = { \
            driver.xmlopt, name \
        }; \
        if (virTestRun(name " (xml)", qemuMigParamsTestXML, &data) < 0) \
            ret = -1; \
        if (virTestRun(name " (json)", qemuMigParamsTestJSON, &data) < 0) \
            ret = -1; \
        if (virTestRun(name " (xml2xml)", qemuMigParamsTestXML2XML, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("unsupported");
    DO_TEST("empty");
    DO_TEST("basic");
    DO_TEST("tls");
    DO_TEST("tls-enabled");
    DO_TEST("tls-hostname");

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
