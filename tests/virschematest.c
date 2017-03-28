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
 *
 * Author: Ján Tomko <jtomko@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

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
    bool shouldFail = virFileHasSuffix(data->xml_path, "-invalid.xml");
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
    char *test_name = NULL;
    char *xml_path = NULL;
    struct testSchemaData data = {
        .validator = validator,
    };

    if (virDirOpen(&dir, dir_path) < 0)
        return -1;

    while ((rc = virDirRead(dir, &ent, dir_path)) > 0) {
        if (!virFileHasSuffix(ent->d_name, ".xml"))
            continue;

        if (virAsprintf(&xml_path, "%s/%s", dir_path, ent->d_name) < 0)
            goto cleanup;

        if (virAsprintf(&test_name, "Checking %s against %s",
                        ent->d_name, schema) < 0)
            goto cleanup;

        data.xml_path = xml_path;
        if (virTestRun(test_name, testSchemaFile, &data) < 0)
            ret = -1;

        VIR_FREE(test_name);
        VIR_FREE(xml_path);
    }

    if (rc < 0)
        ret = -1;

 cleanup:
    VIR_FREE(test_name);
    VIR_FREE(xml_path);
    VIR_DIR_CLOSE(dir);
    return ret;
}


static int
testSchemaDirs(const char *schema, virXMLValidatorPtr validator, ...)
{
    va_list args;
    int ret = 0;
    char *dir_path = NULL;
    const char *dir;

    va_start(args, validator);

    while ((dir = va_arg(args, char *))) {
        if (virAsprintf(&dir_path, "%s/%s", abs_srcdir, dir) < 0) {
            ret = -1;
            goto cleanup;
        }
        if (testSchemaDir(schema, validator, dir_path) < 0)
            ret = -1;
        VIR_FREE(dir_path);
    }

 cleanup:
    VIR_FREE(dir_path);
    va_end(args);
    return ret;
}


static int
testSchemaGrammar(const void *opaque)
{
    struct testSchemaData *data = (struct testSchemaData *) opaque;
    char *schema_path;
    int ret = -1;

    if (virAsprintf(&schema_path, "%s/docs/schemas/%s",
                    abs_topsrcdir, data->schema) < 0)
        return -1;

    if (!(data->validator = virXMLValidatorInit(schema_path)))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(schema_path);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    struct testSchemaData data;

    memset(&data, 0, sizeof(data));

#define DO_TEST_DIR(sch, ...)                                                  \
    do {                                                                       \
        data.schema = sch;                                                     \
        if (virTestRun("test schema grammar file: " sch,                       \
                       testSchemaGrammar, &data) == 0) {                       \
            /* initialize the validator even if the schema test                \
             * was skipped because of VIR_TEST_RANGE */                        \
            if (!data.validator && testSchemaGrammar(&data) < 0) {             \
                ret = -1;                                                      \
                break;                                                         \
            }                                                                  \
            if (testSchemaDirs(sch, data.validator, __VA_ARGS__, NULL) < 0)    \
                ret = -1;                                                      \
                                                                               \
            virXMLValidatorFree(data.validator);                               \
            data.validator = NULL;                                             \
        } else {                                                               \
            ret = -1;                                                          \
        }                                                                      \
    } while (0)

#define DO_TEST_FILE(sch, xmlfile)                                             \
    do {                                                                       \
        data.schema = sch;                                                     \
        data.xml_path = abs_srcdir "/" xmlfile;                                \
        if (virTestRun("test schema grammar file: " sch,                       \
                       testSchemaGrammar, &data) == 0) {                       \
            /* initialize the validator even if the schema test                \
             * was skipped because of VIR_TEST_RANGE */                        \
            if (!data.validator && testSchemaGrammar(&data) < 0) {             \
                ret = -1;                                                      \
                break;                                                         \
            }                                                                  \
            if (virTestRun("Checking " xmlfile " against " sch,                \
                           testSchemaFile, &data) < 0)                         \
                ret = -1;                                                      \
                                                                               \
            virXMLValidatorFree(data.validator);                               \
            data.validator = NULL;                                             \
        } else {                                                               \
            ret = -1;                                                          \
        }                                                                      \
    } while (0)

    DO_TEST_DIR("capability.rng", "capabilityschemadata", "xencapsdata");
    DO_TEST_DIR("domain.rng", "domainschemadata", "qemuargv2xmldata",
                "qemuxml2argvdata", "sexpr2xmldata", "xmconfigdata",
                "xml2sexprdata", "qemuxml2xmloutdata", "lxcxml2xmldata",
                "lxcxml2xmloutdata", "bhyvexml2argvdata", "genericxml2xmlindata",
                "genericxml2xmloutdata", "xlconfigdata",
                "qemuhotplugtestdomains");
    DO_TEST_DIR("domaincaps.rng", "domaincapsschemadata");
    DO_TEST_DIR("domainsnapshot.rng", "domainsnapshotxml2xmlin",
                "domainsnapshotxml2xmlout");
    DO_TEST_DIR("interface.rng", "interfaceschemadata");
    DO_TEST_DIR("network.rng", "../src/network", "networkxml2xmlin",
                "networkxml2xmlout", "networkxml2confdata");
    DO_TEST_DIR("nodedev.rng", "nodedevschemadata");
    DO_TEST_DIR("nwfilter.rng", "nwfilterxml2xmlout");
    DO_TEST_DIR("secret.rng", "secretxml2xmlin");
    DO_TEST_DIR("storagepool.rng", "storagepoolxml2xmlin", "storagepoolxml2xmlout",
                "storagepoolschemadata");
    DO_TEST_DIR("storagevol.rng", "storagevolxml2xmlin", "storagevolxml2xmlout",
                "storagevolschemadata");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
