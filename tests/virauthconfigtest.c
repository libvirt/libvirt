/*
 * Copyright (C) 2012, 2014 Red Hat, Inc.
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

#include <signal.h>

#include "testutils.h"
#include "virlog.h"

#include "virauthconfig.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.authconfigtest");

struct ConfigLookupData {
    virAuthConfig *config;
    const char *hostname;
    const char *service;
    const char *credname;
    const char *expect;
};

static int testAuthLookup(const void *args)
{
    const struct ConfigLookupData *data = args;
    g_autofree char *actual = NULL;
    int rv;

    rv = virAuthConfigLookup(data->config,
                             data->service,
                             data->hostname,
                             data->credname,
                             &actual);

    if (rv < 0)
        return -1;

    if (data->expect) {
        if (!actual ||
            STRNEQ(actual, data->expect)) {
            VIR_WARN("Expected value '%s' for '%s' '%s' '%s', but got '%s'",
                     data->expect, data->hostname,
                     data->service, data->credname,
                     NULLSTR(actual));
            return -1;
        }
    } else {
        if (actual) {
            VIR_WARN("Did not expect a value for '%s' '%s' '%s', but got '%s'",
                     data->hostname,
                     data->service, data->credname,
                     actual);
            return -1;
        }
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

    virAuthConfig *config;

    const char *confdata =
        "[credentials-test]\n"
        "username=fred\n"
        "password=123456\n"
        "\n"
        "[credentials-prod]\n"
        "username=bar\n"
        "password=letmein\n"
        "\n"
        "[auth-libvirt-test1.example.com]\n"
        "credentials=test\n"
        "\n"
        "[auth-libvirt-test2.example.com]\n"
        "credentials=test\n"
        "\n"
        "[auth-libvirt-demo3.example.com]\n"
        "credentials=test\n"
        "\n"
        "[auth-libvirt-prod1.example.com]\n"
        "credentials=prod\n";

#define TEST_LOOKUP(config, hostname, service, credname, expect) \
    do  { \
        const struct ConfigLookupData data = { \
            config, hostname, service, credname, expect \
        }; \
        if (virTestRun("Test Lookup " hostname "-" service "-" credname, \
                        testAuthLookup, &data) < 0) \
            ret = -1; \
    } while (0)

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif /* WIN32 */

    if (!(config = virAuthConfigNewData("auth.conf", confdata, strlen(confdata))))
        return EXIT_FAILURE;

    TEST_LOOKUP(config, "test1.example.com", "libvirt", "username", "fred");
    TEST_LOOKUP(config, "test1.example.com", "vnc", "username", NULL);
    TEST_LOOKUP(config, "test1.example.com", "libvirt", "realm", NULL);
    TEST_LOOKUP(config, "test66.example.com", "libvirt", "username", NULL);
    TEST_LOOKUP(config, "prod1.example.com", "libvirt", "username", "bar");
    TEST_LOOKUP(config, "prod1.example.com", "libvirt", "password", "letmein");

    virAuthConfigFree(config);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
