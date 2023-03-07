/*
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

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#include "internal.h"
#include "testutilsqemu.h"
#include "testutilsqemuschema.h"
#include "configmake.h"

#define LIBVIRT_QEMU_MIGRATION_PARAMSPRIV_H_ALLOW

#include "qemu/qemu_migration_cookie.h"
#include "qemu/qemu_migration_paramspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

static virBuffer testnamebuf = VIR_BUFFER_INITIALIZER;

static const char *
tn(const char *str, ...)
{
    va_list ap;

    virBufferFreeAndReset(&testnamebuf);
    virBufferAdd(&testnamebuf, str, -1);

    va_start(ap, str);
    virBufferStrcatVArgs(&testnamebuf, ap);
    va_end(ap);

    return virBufferCurrentContent(&testnamebuf);
}


struct testQemuMigrationCookieData {
    const char *name;
    char *inStatus;
    virDomainObj *vm;

    unsigned int cookiePopulateFlags;
    unsigned int cookieParseFlags;

    qemuMigrationParty cookiePopulateParty;

    qemuMigrationCookie *cookie;

    char *xmlstr;
    int xmlstrlen;
    char *infile;
    char *outfile;
    char *outmigparamsfile;
};


static void
testQemuMigrationCookieDataFree(struct testQemuMigrationCookieData *data)
{
    if (!data)
        return;

    qemuMigrationCookieFree(data->cookie);
    g_free(data->xmlstr);
    g_free(data->outfile);
    g_free(data->infile);
    g_free(data->outmigparamsfile);
    g_free(data->inStatus);
    virDomainObjEndAPI(&data->vm);
    g_free(data);
}


static int
testQemuMigrationCookiePopulate(const void *opaque)
{
    struct testQemuMigrationCookieData *data = (struct testQemuMigrationCookieData *) opaque;
    g_autoptr(qemuMigrationCookie) cookie = NULL;

    if (!(cookie = qemuMigrationCookieNew(data->vm->def, NULL)))
        return -1;

    /* doctor the hostname and uuid, so that the output can be simply used for
     * the xml2xmltest where the parser validates UUID match (yuck) */
    g_free(cookie->localHostname);
    cookie->localHostname = g_strdup("hostname2");

    /* uuidgen --sha1 --namespace @dns --name "hostname2" */
    if (virUUIDParse("8b3f4dc4-6a8e-5f9b-94a5-4c35babd8d95", cookie->localHostuuid) < 0) {
        VIR_TEST_DEBUG("\nfailed to parse fake UUID");
        return -1;
    }

    /* allow re-run for checking both miration parties */
    g_clear_pointer(&data->xmlstr, g_free);

    if (qemuMigrationCookieFormat(cookie,
                                  &driver,
                                  data->vm,
                                  data->cookiePopulateParty,
                                  &data->xmlstr,
                                  &data->xmlstrlen,
                                  data->cookiePopulateFlags) < 0) {
        VIR_TEST_DEBUG("\n failed to populate and format qemu migration cookie");
        return -1;
    }

    if (virTestCompareToFile(data->xmlstr, data->outfile) < 0)
        return -1;

    return 0;
}


static int
testQemuMigrationCookieParse(const void *opaque)
{
    struct testQemuMigrationCookieData *data = (struct testQemuMigrationCookieData *) opaque;
    qemuDomainObjPrivate *priv = data->vm->privateData;
    g_auto(virBuffer) actual = VIR_BUFFER_INITIALIZER;

    if (!(data->cookie = qemuMigrationCookieParse(&driver,
                                                  data->vm,
                                                  data->vm->def,
                                                  NULL,
                                                  priv->qemuCaps,
                                                  data->xmlstr,
                                                  data->xmlstrlen,
                                                  data->cookieParseFlags))) {
        VIR_TEST_DEBUG("\nfailed to parse qemu migration cookie:\n%s\n", data->xmlstr);
        return -1;
    }

    /* set all flags so that formatter attempts to format everything */
    data->cookie->flags = ~0;

    if (qemuMigrationCookieXMLFormat(&driver,
                                     priv->qemuCaps,
                                     &actual,
                                     data->cookie) < 0) {
        VIR_TEST_DEBUG("\nfailed to format back qemu migration cookie");
        return -1;
    }

    if (virTestCompareToFile(virBufferCurrentContent(&actual), data->outfile) < 0)
        return -1;

    return 0;
}


static int
testQemuMigrationCookieDomInit(const void *opaque)
{
    struct testQemuMigrationCookieData *data = (struct testQemuMigrationCookieData *) opaque;

    if (!(data->vm = virDomainObjParseFile(data->inStatus, driver.xmlopt,
                                           VIR_DOMAIN_DEF_PARSE_STATUS |
                                           VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                           VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                           VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                           VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL))) {
        VIR_TEST_DEBUG("\nfailed to parse status xml'%s'", data->inStatus);
        return -1;
    }

    return 0;
}


static int
testQemuMigrationCookieXMLLoad(const void *opaque)
{
    struct testQemuMigrationCookieData *data = (struct testQemuMigrationCookieData *) opaque;

    if (virTestLoadFile(data->infile, &data->xmlstr) < 0)
        return -1;

    data->xmlstrlen = strlen(data->xmlstr) + 1;

    return 0;
}


static int
testQemuMigrationCookieDom2XML(const char *namesuffix,
                               const char *domxml,
                               unsigned int cookiePopulateFlags,
                               unsigned int cookieParseFlags)
{
    struct testQemuMigrationCookieData *data = g_new0(struct testQemuMigrationCookieData, 1);
    int ret = 0;

    if (cookiePopulateFlags == 0) {
        /* flags unsupported by default:
         * - lockstate: internals are NULL in tests, causes crash
         * - nbd: monitor not present
         * - dirty bitmaps: monitor not present
         */
        unsigned int cookiePopulateFlagMask = QEMU_MIGRATION_COOKIE_LOCKSTATE |
                                              QEMU_MIGRATION_COOKIE_NBD |
                                              QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS;
        data->cookiePopulateFlags = ~cookiePopulateFlagMask;
    }

    if (cookieParseFlags == 0)
        data->cookieParseFlags = ~0;

    data->inStatus = g_strconcat(abs_srcdir, "/", domxml, NULL);

    /* load status XML as domain object */

    if (virTestRun(tn("qemumigrationcookiedom2xml-load-", namesuffix, NULL),
                   testQemuMigrationCookieDomInit, data) < 0)
        ret = -1;

    /* test dom -> migration cookie conversion for source */

    data->cookiePopulateParty = QEMU_MIGRATION_SOURCE;
    data->outfile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                                namesuffix, "-dom-out-source.xml", NULL);

    if (virTestRun(tn("qemumigrationcookiedom2xml-source-populate-", namesuffix, NULL),
                   testQemuMigrationCookiePopulate, data) < 0)
        ret = -1;

    /* test dom -> migration cookie conversion for destination */

    g_free(data->outfile);
    data->cookiePopulateParty = QEMU_MIGRATION_DESTINATION;
    data->outfile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                                namesuffix, "-dom-out-dest.xml", NULL);

    if (virTestRun(tn("qemumigrationcookiedom2xml-dest-populate-", namesuffix, NULL),
                   testQemuMigrationCookiePopulate, data) < 0)
        ret = -1;

    testQemuMigrationCookieDataFree(data);

    return ret;
}


static int
testQemuMigrationCookieXML2XML(const char *name,
                               const char *statusxml,
                               unsigned int cookieParseFlags)
{
    struct testQemuMigrationCookieData *data = g_new0(struct testQemuMigrationCookieData, 1);
    int ret = 0;

    if (cookieParseFlags == 0)
        data->cookieParseFlags = ~0;

    data->inStatus = g_strconcat(abs_srcdir, "/", statusxml, NULL);
    data->infile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                               name, "-xml2xml-in.xml", NULL);
    data->outfile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                                name, "-xml2xml-out.xml", NULL);

    if (virTestRun(tn("qemumigrationcookieXML2XML-dom-", name, NULL),
                   testQemuMigrationCookieDomInit, data) < 0)
        ret = -1;

    if (virTestRun(tn("qemumigrationcookieXML2XML-load-", name, NULL),
                   testQemuMigrationCookieXMLLoad, data) < 0)
        ret = -1;

    if (virTestRun(tn("qemumigrationcookieXML2XML-parse-", name, NULL),
                   testQemuMigrationCookieParse, data) < 0)
        ret = -1;

    testQemuMigrationCookieDataFree(data);

    return ret;
}


static int
testQemuMigrationCookieBlockDirtyBitmaps(const void *opaque)
{
    const struct testQemuMigrationCookieData *data = opaque;
    g_autoptr(virJSONValue) migParamsBitmaps = NULL;
    g_autofree char *actualJSON = NULL;
    g_autoptr(virJSONValue) paramsOut = NULL;
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    g_autoptr(qemuMigrationParams) migParams = NULL;
    g_autoptr(GHashTable) qmpschema = NULL;
    GSList *next;

    if (!(qmpschema = testQEMUSchemaLoadLatest("x86_64"))) {
        VIR_TEST_VERBOSE("failed to load QMP schema");
        return -1;
    }

    if (qemuMigrationCookieBlockDirtyBitmapsMatchDisks(data->vm->def,
                                                       data->cookie->blockDirtyBitmaps) < 0)
        return -1;

    for (next = data->cookie->blockDirtyBitmaps; next; next = next->next) {
        qemuMigrationBlockDirtyBitmapsDisk *disk = next->data;
        qemuMigrationBlockDirtyBitmapsDiskBitmap *bitmap = disk->bitmaps->data;

        bitmap->persistent = VIR_TRISTATE_BOOL_YES;
    }

    if (qemuMigrationCookieBlockDirtyBitmapsToParams(data->cookie->blockDirtyBitmaps,
                                                     &migParamsBitmaps))
        return -1;

    if (!(migParams = qemuMigrationParamsNew()))
        return -1;

    qemuMigrationParamsSetBlockDirtyBitmapMapping(migParams, &migParamsBitmaps);

    if (!(paramsOut = qemuMigrationParamsToJSON(migParams, false)) ||
        !(actualJSON = virJSONValueToString(paramsOut, true)))
        return -1;

    if (testQEMUSchemaValidateCommand("migrate-set-parameters",
                                      paramsOut,
                                      qmpschema,
                                      false,
                                      false,
                                      false,
                                      &debug) < 0) {
        VIR_TEST_VERBOSE("failed to validate migration params '%s' against QMP schema: %s",
                         actualJSON, virBufferCurrentContent(&debug));
        return -1;
    }

    if (virTestCompareToFile(actualJSON, data->outmigparamsfile) < 0)
        return -1;

    return 0;
}


/* tests also the conversion to list of migrated bitmaps */
static int
testQemuMigrationCookieXML2XMLBitmaps(const char *name,
                                      const char *statusxml,
                                      unsigned int cookieParseFlags)
{
    struct testQemuMigrationCookieData *data = g_new0(struct testQemuMigrationCookieData, 1);
    int ret = 0;

    if (cookieParseFlags == 0)
        data->cookieParseFlags = ~0;

    data->inStatus = g_strconcat(abs_srcdir, "/", statusxml, NULL);
    data->infile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                               name, "-xml2xml-in.xml", NULL);
    data->outfile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                                name, "-xml2xml-out.xml", NULL);
    data->outmigparamsfile = g_strconcat(abs_srcdir, "/qemumigrationcookiexmldata/",
                                         name, "-xml2xml-migparams.json", NULL);

    if (virTestRun(tn("qemumigrationcookieXML2XML-dom-", name, NULL),
                   testQemuMigrationCookieDomInit, data) < 0)
        ret = -1;

    if (virTestRun(tn("qemumigrationcookieXML2XML-load-", name, NULL),
                   testQemuMigrationCookieXMLLoad, data) < 0)
        ret = -1;

    if (virTestRun(tn("qemumigrationcookieXML2XML-parse-", name, NULL),
                   testQemuMigrationCookieParse, data) < 0)
        ret = -1;

    if (virTestRun(tn("qemumigrationcookieXML2XML-migparams-", name, NULL),
                   testQemuMigrationCookieBlockDirtyBitmaps, data) < 0)
        ret = -1;

    testQemuMigrationCookieDataFree(data);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    g_autoptr(virConnect) conn = NULL;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    if (!(conn = virGetConnect()))
        goto cleanup;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

    if (testQemuMigrationCookieDom2XML("modern", "qemustatusxml2xmldata/modern-in.xml", 0, 0) < 0)
        ret = -1;

    if (testQemuMigrationCookieXML2XML("basic", "qemustatusxml2xmldata/modern-in.xml", 0) < 0 ||
        testQemuMigrationCookieXML2XML("full", "qemustatusxml2xmldata/modern-in.xml", 0) < 0)
        ret = -1;

    if (testQemuMigrationCookieXML2XMLBitmaps("nbd-bitmaps", "qemustatusxml2xmldata/migration-out-nbd-bitmaps-in.xml", 0) < 0)
        ret = -1;

    virBufferFreeAndReset(&testnamebuf);

 cleanup:

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"),
                      VIR_TEST_MOCK("virhostid"))
