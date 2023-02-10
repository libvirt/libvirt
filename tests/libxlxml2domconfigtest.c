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
# include "libxl/libxl_conf.h"
# include "testutilsxen.h"

# define VIR_FROM_THIS VIR_FROM_LIBXL

static libxlDriverPrivate *driver;

static int
testCompareXMLToDomConfig(const char *xmlfile,
                          const char *jsonfile)
{
    int ret = -1;
    libxl_domain_config actualconfig;
    libxl_domain_config expectconfig;
    xentoollog_logger *log = NULL;
    virPortAllocatorRange *gports = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    g_autofree char *actualjson = NULL;
    g_autofree char *tempjson = NULL;
    g_autofree char *expectjson = NULL;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);

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

    if (!(vmdef = virDomainDefParseFile(xmlfile, driver->xmlopt,
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

    /*
     * In order to have common test files between Xen 4.9 and newer Xen versions,
     * tweak the expected libxl_domain_config object before getting a json
     * representation.
     */
# ifndef LIBXL_HAVE_BUILDINFO_APIC
    if (expectconfig.c_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        libxl_defbool_unset(&expectconfig.b_info.acpi);
        libxl_defbool_set(&expectconfig.b_info.u.hvm.apic, true);
        libxl_defbool_set(&expectconfig.b_info.u.hvm.acpi, true);
    }
# endif

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

    virPortAllocatorRangeFree(gports);
    libxl_domain_config_dispose(&actualconfig);
    libxl_domain_config_dispose(&expectconfig);
    xtl_logger_destroy(log);
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
    g_autofree char *xmlfile = NULL;
    g_autofree char *jsonfile = NULL;

    xmlfile = g_strdup_printf("%s/libxlxml2domconfigdata/%s.xml", abs_srcdir, info->name);
    jsonfile = g_strdup_printf("%s/libxlxml2domconfigdata/%s.json", abs_srcdir, info->name);

    ret = testCompareXMLToDomConfig(xmlfile, jsonfile);

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
    if (g_setenv("TZ", "VIR00:30", TRUE) == FALSE) {
        perror("g_setenv");
        return EXIT_FAILURE;
    }

    if ((driver = testXLInitDriver()) == NULL)
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
    DO_TEST("efi-hvm");
# ifdef WITH_XEN_PVH
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

    DO_TEST("fullvirt-acpi-slic");

# ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    DO_TEST("max-gntframes-hvm");
# endif

    DO_TEST("max-eventchannels-hvm");

    unlink("libxl-driver.log");

    testXLFreeDriver(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("xl"))

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LIBXL && WITH_YAJL */
