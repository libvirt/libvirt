/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 */

#include <config.h>


#include "testutils.h"

#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.schematest");

struct testSchemaData {
    virXMLValidatorPtr validator;
    const char *schema;
    const char *xml_path;
};


static int
testSchemaFile(const void *args)
{
    const struct testSchemaData *data = args;
    bool shouldFail = virStringHasSuffix(data->xml_path, "-invalid.xml");
    xmlDocPtr xml = NULL;
    int ret = -1;

    if (!(xml = virXMLParseFile(data->xml_path)))
        return -1;

    if (virXMLValidatorValidate(data->validator, xml) < 0) {
        if (!shouldFail)
            goto cleanup;
    } else {
        if (shouldFail)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    xmlFreeDoc(xml);
    return ret;
}


static int
testSchemaDir(const char *schema,
              virXMLValidatorPtr validator,
              const char *dir_path)
{
    DIR *dir = NULL;
    struct dirent *ent;
    int ret = 0;
    int rc;
    struct testSchemaData data = {
        .validator = validator,
    };

    if (virDirOpen(&dir, dir_path) < 0) {
        virTestPropagateLibvirtError();
        return -1;
    }

    while ((rc = virDirRead(dir, &ent, dir_path)) > 0) {
        g_autofree char *test_name = NULL;
        g_autofree char *xml_path = NULL;

        if (!virStringHasSuffix(ent->d_name, ".xml"))
            continue;
        if (ent->d_name[0] == '.')
            continue;

        xml_path = g_strdup_printf("%s/%s", dir_path, ent->d_name);

        test_name = g_strdup_printf("Checking %s against %s", ent->d_name, schema);

        data.xml_path = xml_path;
        if (virTestRun(test_name, testSchemaFile, &data) < 0)
            ret = -1;
    }

    if (rc < 0) {
        virTestPropagateLibvirtError();
        ret = -1;
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


static int
testSchemaDirs(const char *schema, virXMLValidatorPtr validator, ...)
{
    va_list args;
    int ret = 0;
    const char *dir;

    va_start(args, validator);

    while ((dir = va_arg(args, char *))) {
        g_autofree char *dir_path = g_strdup_printf("%s/%s", abs_srcdir, dir);
        if (testSchemaDir(schema, validator, dir_path) < 0)
            ret = -1;
    }

    va_end(args);
    return ret;
}


static int
testSchemaGrammar(const void *opaque)
{
    struct testSchemaData *data = (struct testSchemaData *) opaque;
    g_autofree char *schema_path = NULL;

    schema_path = g_strdup_printf("%s/docs/schemas/%s", abs_top_srcdir,
                                  data->schema);

    if (!(data->validator = virXMLValidatorInit(schema_path)))
        return -1;

    return 0;
}


static int
mymain(void)
{
    int ret = 0;
    struct testSchemaData data;

    memset(&data, 0, sizeof(data));

#define DO_TEST_DIR(sch, ...) \
    do { \
        data.schema = sch; \
        if (virTestRun("test schema grammar file: " sch, \
                       testSchemaGrammar, &data) == 0) { \
            /* initialize the validator even if the schema test \
             * was skipped because of VIR_TEST_RANGE */ \
            if (!data.validator && testSchemaGrammar(&data) < 0) { \
                ret = -1; \
                break; \
            } \
            if (testSchemaDirs(sch, data.validator, __VA_ARGS__, NULL) < 0) \
                ret = -1; \
 \
            virXMLValidatorFree(data.validator); \
            data.validator = NULL; \
        } else { \
            ret = -1; \
        } \
    } while (0)

#define DO_TEST_FILE(sch, xmlfile) \
    do { \
        data.schema = sch; \
        data.xml_path = abs_srcdir "/" xmlfile; \
        if (virTestRun("test schema grammar file: " sch, \
                       testSchemaGrammar, &data) == 0) { \
            /* initialize the validator even if the schema test \
             * was skipped because of VIR_TEST_RANGE */ \
            if (!data.validator && testSchemaGrammar(&data) < 0) { \
                ret = -1; \
                break; \
            } \
            if (virTestRun("Checking " xmlfile " against " sch, \
                           testSchemaFile, &data) < 0) \
                ret = -1; \
 \
            virXMLValidatorFree(data.validator); \
            data.validator = NULL; \
        } else { \
            ret = -1; \
        } \
    } while (0)

    DO_TEST_DIR("capability.rng", "capabilityschemadata", "vircaps2xmldata");
    DO_TEST_DIR("domain.rng", "domainschemadata",
                "qemuxml2argvdata", "xmconfigdata",
                "qemuxml2xmloutdata", "lxcxml2xmldata",
                "lxcxml2xmloutdata", "bhyvexml2argvdata", "genericxml2xmlindata",
                "genericxml2xmloutdata", "xlconfigdata", "libxlxml2domconfigdata",
                "qemuhotplugtestdomains");
    DO_TEST_DIR("domaincaps.rng", "domaincapsdata");
    DO_TEST_DIR("domainbackup.rng", "domainbackupxml2xmlin",
                "domainbackupxml2xmlout");
    DO_TEST_DIR("domaincheckpoint.rng", "qemudomaincheckpointxml2xmlin",
                "qemudomaincheckpointxml2xmlout");
    DO_TEST_DIR("domainsnapshot.rng", "qemudomainsnapshotxml2xmlin",
                "qemudomainsnapshotxml2xmlout");
    DO_TEST_DIR("interface.rng", "interfaceschemadata");
    DO_TEST_DIR("network.rng", "../src/network", "networkxml2xmlin",
                "networkxml2xmlout", "networkxml2confdata");
    DO_TEST_DIR("networkport.rng", "virnetworkportxml2xmldata");
    DO_TEST_DIR("nodedev.rng", "nodedevschemadata");
    DO_TEST_DIR("nwfilter.rng", "nwfilterxml2xmlout", "../src/nwfilter");
    DO_TEST_DIR("nwfilterbinding.rng", "virnwfilterbindingxml2xmldata");
    DO_TEST_DIR("secret.rng", "secretxml2xmlin");
    DO_TEST_DIR("storagepoolcaps.rng", "storagepoolcapsschemadata");
    DO_TEST_DIR("storagepool.rng", "storagepoolxml2xmlin", "storagepoolxml2xmlout",
                "storagepoolschemadata");
    DO_TEST_DIR("storagevol.rng", "storagevolxml2xmlin", "storagevolxml2xmlout",
                "storagevolschemadata");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
