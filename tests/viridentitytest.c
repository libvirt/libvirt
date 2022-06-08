/*
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>


#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "testutils.h"

#define LIBVIRT_VIRIDENTITYPRIV_H_ALLOW

#include "viridentitypriv.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.identitytest");

char *
virIdentityEnsureSystemToken(void)
{
    return g_strdup("3de80bcbf22d4833897f1638e01be9b2");
}


static int testIdentityAttrs(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virIdentity) ident = virIdentityNew();
    const char *val;
    int rc;

    if (virIdentitySetUserName(ident, "fred") < 0)
        return -1;

    if ((rc = virIdentityGetUserName(ident, &val)) < 0)
        return -1;

    if (STRNEQ_NULLABLE(val, "fred") || rc != 1) {
        VIR_DEBUG("Expected 'fred' got '%s'", NULLSTR(val));
        return -1;
    }

    if ((rc = virIdentityGetGroupName(ident, &val)) < 0)
        return -1;

    if (val != NULL || rc != 0) {
        VIR_DEBUG("Unexpected groupname attribute");
        return -1;
    }

    if (virIdentitySetUserName(ident, "joe") >= 0) {
        VIR_DEBUG("Unexpectedly overwrote attribute");
        return -1;
    }

    if ((rc = virIdentityGetUserName(ident, &val)) < 0)
        return -1;

    if (STRNEQ_NULLABLE(val, "fred") || rc != 1) {
        VIR_DEBUG("Expected 'fred' got '%s'", NULLSTR(val));
        return -1;
    }

    return 0;
}


static int testIdentityGetSystem(const void *data)
{
    const char *context = data;
    g_autoptr(virIdentity) ident = NULL;
    const char *val;
    int rc;

#if !WITH_SELINUX
    if (context) {
        VIR_DEBUG("libvirt not compiled with SELinux, skipping this test");
        return EXIT_AM_SKIP;
    }
#endif

    if (!(ident = virIdentityGetSystem())) {
        VIR_DEBUG("Unable to get system identity");
        return -1;
    }

    if ((rc = virIdentityGetSELinuxContext(ident, &val)) < 0)
        return -1;

    if (context == NULL) {
        if (val != NULL || rc != 0) {
            VIR_DEBUG("Unexpected SELinux context %s", NULLSTR(val));
            return -1;
        }
    } else {
        if (STRNEQ_NULLABLE(val, context) || rc != 1) {
            VIR_DEBUG("Want SELinux context '%s' got '%s'",
                      context, val);
            return -1;
        }
    }

    return 0;
}

static int testSetFakeSELinuxContext(const void *data G_GNUC_UNUSED)
{
#if WITH_SELINUX
    return setcon_raw(data);
#else
    VIR_DEBUG("libvirt not compiled with SELinux, skipping this test");
    return EXIT_AM_SKIP;
#endif
}

static int testDisableFakeSELinux(const void *data G_GNUC_UNUSED)
{
#if WITH_SELINUX
    return security_disable();
#else
    VIR_DEBUG("libvirt not compiled with SELinux, skipping this test");
    return EXIT_AM_SKIP;
#endif
}

static int
mymain(void)
{
    const char *context = "unconfined_u:unconfined_r:unconfined_t:s0";
    int ret = 0;

    if (virTestRun("Identity attributes ", testIdentityAttrs, NULL) < 0)
        ret = -1;
    if (virTestRun("Setting fake SELinux context ", testSetFakeSELinuxContext, context) < 0)
        ret = -1;
    if (virTestRun("System identity (fake SELinux enabled) ", testIdentityGetSystem, context) < 0)
        ret = -1;
    if (virTestRun("Disabling fake SELinux ", testDisableFakeSELinux, NULL) < 0)
        ret = -1;
    if (virTestRun("System identity (fake SELinux disabled) ", testIdentityGetSystem, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#if WITH_SELINUX
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/libsecurityselinuxhelper.so")
#else
VIR_TEST_MAIN(mymain)
#endif
