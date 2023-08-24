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

#include "virlog.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.schematest");

struct testSchemaEntry {
    const char *dir;
    /* if dirRegex is non-NULL the provided regular expression is used to match
     * the file names in a directory (without path prefixed) and only matching
     * files are validated */
    const char *dirRegex;
    const char *file;
};


struct testSchemaData {
    virXMLValidator *validator;
    const char *xml_path;
};


static int
testSchemaValidateXML(const void *args)
{
    const struct testSchemaData *data = args;
    /* invalid XMLs have a '-invalid.' suffix, but not necessarily at the end
     * of the file name e.g. in case of qemuxml2xmltest with real capabilities */
    bool shouldFail = !!strstr(data->xml_path, "-invalid.");
    g_autoptr(xmlDoc) xml = NULL;

    if (!(xml = virXMLParseFileCtxt(data->xml_path, NULL)))
        return -1;

    if ((virXMLValidatorValidate(data->validator, xml) < 0) != shouldFail)
        return -1;

    return 0;
}


static int
testSchemaFile(const char *schema,
               virXMLValidator *validator,
               const char *path)
{
    g_autofree char *test_name = NULL;
    struct testSchemaData data = {
        .validator = validator,
        .xml_path = path,
    };

    test_name = g_strdup_printf("Checking %s against %s", path, schema);

    return virTestRun(test_name, testSchemaValidateXML, &data);
}


static int
testSchemaDir(const char *schema,
              virXMLValidator *validator,
              const char *dir_path,
              const char *filterstr)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *ent;
    int ret = 0;
    int rc;
    g_autoptr(GRegex) filter = NULL;

    if (virDirOpen(&dir, dir_path) < 0) {
        virTestPropagateLibvirtError();
        return -1;
    }

    if (filterstr) {
        g_autoptr(GError) err = NULL;

        if (!(filter = g_regex_new(filterstr, 0, 0, &err))) {
            VIR_TEST_VERBOSE("\nfailed to compile regex '%s': %s", filterstr, err->message);
            return -1;
        }
    }

    while ((rc = virDirRead(dir, &ent, dir_path)) > 0) {
        g_autofree char *xml_path = NULL;

        if (!virStringHasSuffix(ent->d_name, ".xml"))
            continue;
        if (ent->d_name[0] == '.')
            continue;
        if (filter &&
            !g_regex_match(filter, ent->d_name, 0, NULL))
            continue;

        xml_path = g_strdup_printf("%s/%s", dir_path, ent->d_name);

        if (testSchemaFile(schema, validator, xml_path) < 0)
            ret = -1;
    }

    if (rc < 0) {
        virTestPropagateLibvirtError();
        ret = -1;
    }

    return ret;
}


/**
 * testSchemaGrammarReport:
 *
 * We need to parse the schema regardless since it's necessary also when tests
 * are skipped using VIR_TEST_RANGE so this function merely reports whether the
 * schema was parsed successfully via virTestRun.
 */
static int
testSchemaGrammarReport(const void *opaque)
{
    const virXMLValidator *validator = opaque;

    if (!validator)
        return -1;

    return 0;
}

static virXMLValidator *
testSchemaGrammarLoad(const char *schema)
{
    g_autofree char *testname = NULL;
    virXMLValidator *ret;

    ret = virXMLValidatorInit(schema);

    testname = g_strdup_printf("test schema grammar file: '%s'", schema);

    ignore_value(virTestRun(testname, testSchemaGrammarReport, ret));

    return ret;
}


static int
testSchemaEntries(const char *schema,
                  const struct testSchemaEntry *entries,
                  size_t nentries)
{
    g_autoptr(virXMLValidator) validator = NULL;
    size_t i;
    int ret = 0;

    if (!(validator = testSchemaGrammarLoad(schema)))
        return -1;

    for (i = 0; i < nentries; i++) {
        const struct testSchemaEntry *entry = entries + i;

        if (!entry->file == !entry->dir) {
            VIR_TEST_VERBOSE("\nmust specify exactly one of 'dir' and 'file' for struct testSchemaEntry\n");
            ret = -1;
            continue;
        }

        if (entry->dir) {
            g_autofree char *path = g_strdup_printf("%s/%s", abs_top_srcdir, entry->dir);

            if (testSchemaDir(schema, validator, path, entry->dirRegex) < 0)
                ret = -1;
        }

        if (entry->file) {
            g_autofree char *path = g_strdup_printf("%s/%s", abs_top_srcdir, entry->file);

            if (testSchemaFile(schema, validator, path) < 0)
                ret = -1;
        }
    }

    return ret;
}


static const struct testSchemaEntry schemaCapability[] = {
    { .dir = "tests/capabilityschemadata" },
    { .dir = "tests/vircaps2xmldata" },
    { .dir = "tests/qemucaps2xmloutdata" },
};

static const struct testSchemaEntry schemaDomain[] = {
    { .dir = "tests/domainschemadata" },
    { .dir = "tests/qemuxml2argvdata" },
    { .dir = "tests/xmconfigdata" },
    { .dir = "tests/qemuxml2xmloutdata" },
    { .dir = "tests/lxcxml2xmldata" },
    { .dir = "tests/lxcxml2xmloutdata" },
    { .dir = "tests/bhyvexml2argvdata" },
    { .dir = "tests/bhyvexml2xmloutdata" },
    { .dir = "tests/genericxml2xmlindata" },
    { .dir = "tests/genericxml2xmloutdata" },
    { .dir = "tests/xlconfigdata" },
    { .dir = "tests/libxlxml2domconfigdata" },
    { .dir = "tests/qemuhotplugtestdomains" },
    { .dir = "examples/xml/test/",
      .dirRegex = "testdom.*" },
    { .dir = "tests/qemuhotplugtestcpus" },
    { .dir = "tests/securityselinuxlabeldata" },
    { .dir = "tests/domainconfdata" },
    { .dir = "tests/lxcconf2xmldata" },
    { .dir = "tests/qemumemlockdata" },
    { .dir = "tests/vmx2xmldata" },
    { .dir = "tests/xml2vmxdata" },
    { .dir = "tests/bhyveargv2xmldata" },
    { .dir = "tests/qemuagentdata" },
    { .dir = "tests/chxml2xmlin" },
    { .dir = "tests/chxml2xmlout" },
};

static const struct testSchemaEntry schemaDomainCaps[] = {
    { .dir = "tests/domaincapsdata" },
};

static const struct testSchemaEntry schemaDomainBackup[] = {
    { .dir = "tests/domainbackupxml2xmlin" },
    { .dir = "tests/domainbackupxml2xmlout" },
};

static const struct testSchemaEntry schemaDomainCheckpoint[] = {
    { .dir = "tests/qemudomaincheckpointxml2xmlin" },
    { .dir = "tests/qemudomaincheckpointxml2xmlout" },
};

static const struct testSchemaEntry schemaDomainSnapshot[] = {
    { .dir = "tests/qemudomainsnapshotxml2xmlin" },
    { .dir = "tests/qemudomainsnapshotxml2xmlout" },
};

static const struct testSchemaEntry schemaInterface[] = {
    { .dir = "tests/interfaceschemadata" },
};

static const struct testSchemaEntry schemaNetwork[] = {
    { .dir = "src/network" },
    { .dir = "tests/networkxml2xmlin" },
    { .dir = "tests/networkxml2xmlout" },
    { .dir = "tests/networkxml2confdata" },
    { .dir = "examples/xml/test/",
      .dirRegex = "testnet.*" },
    { .dir = "tests/networkxml2xmlupdateout" },
    { .dir = "tests/networkxml2firewalldata" },
};

static const struct testSchemaEntry schemaNetworkport[] = {
    { .dir = "tests/virnetworkportxml2xmldata" },
};

static const struct testSchemaEntry schemaNodedev[] = {
    { .dir = "tests/nodedevschemadata" },
    { .dir = "tests/nodedevxml2xmlout" },
    { .file = "examples/xml/test/testdev.xml" },
};

static const struct testSchemaEntry schemaNwfilter[] = {
    { .dir = "tests/nwfilterxml2xmlout" },
    { .dir = "src/nwfilter/xml" },
    { .dir = "tests/nwfilterxml2xmlin" },
    { .dir = "tests/nwfilterxml2firewalldata" },
};

static const struct testSchemaEntry schemaNwfilterbinding[] = {
    { .dir = "tests/virnwfilterbindingxml2xmldata" },
};

static const struct testSchemaEntry schemaSecret[] = {
    { .dir = "tests/secretxml2xmlin" },
};

static const struct testSchemaEntry schemaStoragepoolcaps[] = {
    { .dir = "tests/storagepoolcapsschemadata" },
};

static const struct testSchemaEntry schemaStoragePool[] = {
    { .dir = "tests/storagepoolxml2xmlin" },
    { .dir = "tests/storagepoolxml2xmlout" },
    { .dir = "tests/storagepoolschemadata" },
    { .dir = "examples/xml/storage",
      .dirRegex = "pool-.*" },
    { .file = "examples/xml/test/testpool.xml" },
};

static const struct testSchemaEntry schemaStorageVol[] = {
    { .dir = "tests/storagevolxml2xmlin" },
    { .dir = "tests/storagevolxml2xmlout" },
    { .dir = "tests/storagevolschemadata" },
    { .dir = "examples/xml/storage",
      .dirRegex = "vol-.*" },
    { .file = "examples/xml/test/testvol.xml" },
};

static const struct testSchemaEntry testsCpuBaseline[] = {
    { . dir = "tests/cputestdata" },
};

static const struct testSchemaEntry testDevice[] = {
    { .dir = "tests/qemuhotplugtestdevices" },
    { .dir = "tests/qemublocktestdata/imagecreate" },
    { .dir = "tests/qemublocktestdata/xml2json" },
};

static int
mymain(void)
{
    int ret = 0;

#define SCHEMAS_PATH abs_top_srcdir "/src/conf/schemas/"
#define INTERNAL_SCHEMAS_PATH abs_builddir "/schemas/"

#define DO_TEST(sch, ent) \
    if (testSchemaEntries((sch), (ent), G_N_ELEMENTS(ent)) < 0) \
        ret = -1;

    DO_TEST(SCHEMAS_PATH "capability.rng", schemaCapability);
    DO_TEST(SCHEMAS_PATH "domain.rng", schemaDomain);
    DO_TEST(SCHEMAS_PATH "domaincaps.rng", schemaDomainCaps);
    DO_TEST(SCHEMAS_PATH "domainbackup.rng", schemaDomainBackup);
    DO_TEST(SCHEMAS_PATH "domaincheckpoint.rng", schemaDomainCheckpoint);
    DO_TEST(SCHEMAS_PATH "domainsnapshot.rng", schemaDomainSnapshot);
    DO_TEST(SCHEMAS_PATH "interface.rng", schemaInterface);
    DO_TEST(SCHEMAS_PATH "network.rng", schemaNetwork);
    DO_TEST(SCHEMAS_PATH "networkport.rng", schemaNetworkport);
    DO_TEST(SCHEMAS_PATH "nodedev.rng", schemaNodedev);
    DO_TEST(SCHEMAS_PATH "nwfilter.rng", schemaNwfilter);
    DO_TEST(SCHEMAS_PATH "nwfilterbinding.rng", schemaNwfilterbinding);
    DO_TEST(SCHEMAS_PATH "secret.rng", schemaSecret);
    DO_TEST(SCHEMAS_PATH "storagepoolcaps.rng", schemaStoragepoolcaps);
    DO_TEST(SCHEMAS_PATH "storagepool.rng", schemaStoragePool);
    DO_TEST(SCHEMAS_PATH "storagevol.rng", schemaStorageVol);

    DO_TEST(INTERNAL_SCHEMAS_PATH "cpu-baseline.rng", testsCpuBaseline);
    DO_TEST(INTERNAL_SCHEMAS_PATH "device.rng", testDevice);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
