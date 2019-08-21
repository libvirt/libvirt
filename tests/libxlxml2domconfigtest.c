/*
 * libxlxml2domconfigtest.c: test conversion of domXML to
 * libxl_domain_config structure.
 *
 * Copyright (C) 2017 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#if defined(WITH_LIBXL) && defined(WITH_YAJL)

# include "internal.h"
# include "viralloc.h"
# include "libxl/libxl_conf.h"
# include "datatypes.h"
# include "virstring.h"
# include "virmock.h"
# include "virjson.h"
# include "testutilsxen.h"

# define VIR_FROM_THIS VIR_FROM_LIBXL

static virCapsPtr caps;

static int
testCompareXMLToDomConfig(const char *xmlfile,
                          const char *jsonfile)
{
    int ret = -1;
    libxl_domain_config actualconfig;
    libxl_domain_config expectconfig;
    libxlDriverConfigPtr cfg;
    xentoollog_logger *log = NULL;
    virPortAllocatorRangePtr gports = NULL;
    virDomainXMLOptionPtr xmlopt = NULL;
    virDomainDefPtr vmdef = NULL;
    char *actualjson = NULL;
    char *tempjson = NULL;
    char *expectjson = NULL;

    if (!(cfg = libxlDriverConfigNew()))
        return -1;

    cfg->caps = caps;

    libxl_domain_config_init(&actualconfig);
    libxl_domain_config_init(&expectconfig);

    if (!(log = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr, XTL_DEBUG, 0)))
        goto cleanup;

    /* for testing nested HVM */
    cfg->nested_hvm = true;

    /* replace logger with stderr one */
    libxl_ctx_free(cfg->ctx);

    if (libxl_ctx_alloc(&cfg->ctx, LIBXL_VERSION, 0, log) < 0)
        goto cleanup;

    if (!(gports = virPortAllocatorRangeNew("vnc", 5900, 6000)))
        goto cleanup;

    if (!(xmlopt = libxlCreateXMLConf()))
        goto cleanup;

    if (!(vmdef = virDomainDefParseFile(xmlfile, caps, xmlopt,
                                        NULL, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (libxlBuildDomainConfig(gports, vmdef, cfg, &actualconfig) < 0)
        goto cleanup;

    if (!(actualjson = libxl_domain_config_to_json(cfg->ctx, &actualconfig))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Failed to retrieve JSON doc for libxl_domain_config");
        goto cleanup;
    }

    if (virTestLoadFile(jsonfile, &tempjson) < 0)
        goto cleanup;

    if (libxl_domain_config_from_json(cfg->ctx, &expectconfig, tempjson) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Failed to create libxl_domain_config from JSON doc");
        goto cleanup;
    }
    if (!(expectjson = libxl_domain_config_to_json(cfg->ctx, &expectconfig))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Failed to retrieve JSON doc for libxl_domain_config");
        goto cleanup;
    }

    if (virTestCompareToString(expectjson, actualjson) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (vmdef &&
        vmdef->ngraphics == 1 &&
        vmdef->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        virPortAllocatorRelease(vmdef->graphics[0]->data.vnc.port);

    VIR_FREE(expectjson);
    VIR_FREE(actualjson);
    VIR_FREE(tempjson);
    virDomainDefFree(vmdef);
    virPortAllocatorRangeFree(gports);
    virObjectUnref(xmlopt);
    libxl_domain_config_dispose(&actualconfig);
    libxl_domain_config_dispose(&expectconfig);
    xtl_logger_destroy(log);
    cfg->caps = NULL;
    virObjectUnref(cfg);
    return ret;
}


struct testInfo {
    const char *name;
};


static int
testCompareXMLToDomConfigHelper(const void *data)
{
    int ret = -1;
    const struct testInfo *info = data;
    char *xmlfile = NULL;
    char *jsonfile = NULL;

    if (virAsprintf(&xmlfile, "%s/libxlxml2domconfigdata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&jsonfile, "%s/libxlxml2domconfigdata/%s.json",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareXMLToDomConfig(xmlfile, jsonfile);

 cleanup:
    VIR_FREE(xmlfile);
    VIR_FREE(jsonfile);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    /* Set the timezone because we are mocking the time() function.
     * If we don't do that, then localtime() may return unpredictable
     * results. In order to detect things that just work by a blind
     * chance, we need to set an virtual timezone that no libvirt
     * developer resides in. */
    if (setenv("TZ", "VIR00:30", 1) < 0) {
        perror("setenv");
        return EXIT_FAILURE;
    }

    if ((caps = testXLInitCaps()) == NULL)
        return EXIT_FAILURE;

# define DO_TEST(name) \
    do { \
        static struct testInfo info = { \
            name, \
        }; \
        if (virTestRun("LibXL XML-2-JSON " name, \
                        testCompareXMLToDomConfigHelper, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("basic-pv");
    DO_TEST("basic-hvm");
# ifdef HAVE_XEN_PVH
    DO_TEST("basic-pvh");
# endif
    DO_TEST("cpu-shares-hvm");
    DO_TEST("variable-clock-hvm");
    DO_TEST("moredevs-hvm");
    DO_TEST("multiple-ip");

# ifdef LIBXL_HAVE_BUILDINFO_NESTED_HVM
    DO_TEST("vnuma-hvm");
    DO_TEST("fullvirt-cpuid");
# else
    DO_TEST("vnuma-hvm-legacy-nest");
    DO_TEST("fullvirt-cpuid-legacy-nest");
# endif

# ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    DO_TEST("max-gntframes-hvm");
# endif

    unlink("libxl-driver.log");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("xl"))

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LIBXL && WITH_YAJL */
