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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "testutils.h"

#include "viridentity.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "virlockspace.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.identitytest");

static int testIdentityAttrs(const void *data ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virIdentityPtr ident;
    const char *val;

    if (!(ident = virIdentityNew()))
        goto cleanup;

    if (virIdentitySetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           "fred") < 0)
        goto cleanup;

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           &val) < 0)
        goto cleanup;

    if (STRNEQ_NULLABLE(val, "fred")) {
        VIR_DEBUG("Expected 'fred' got '%s'", NULLSTR(val));
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           &val) < 0)
        goto cleanup;

    if (val != NULL) {
        VIR_DEBUG("Unexpected groupname attribute");
        goto cleanup;
    }

    if (virIdentitySetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           "joe") != -1) {
        VIR_DEBUG("Unexpectedly overwrote attribute");
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           &val) < 0)
        goto cleanup;

    if (STRNEQ_NULLABLE(val, "fred")) {
        VIR_DEBUG("Expected 'fred' got '%s'", NULLSTR(val));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(ident);
    return ret;
}


static int testIdentityEqual(const void *data ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virIdentityPtr identa = NULL;
    virIdentityPtr identb = NULL;

    if (!(identa = virIdentityNew()))
        goto cleanup;
    if (!(identb = virIdentityNew()))
        goto cleanup;

    if (!virIdentityIsEqual(identa, identb)) {
        VIR_DEBUG("Empty identities were not equal");
        goto cleanup;
    }

    if (virIdentitySetAttr(identa,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           "fred") < 0)
        goto cleanup;

    if (virIdentityIsEqual(identa, identb)) {
        VIR_DEBUG("Mis-matched identities should not be equal");
        goto cleanup;
    }

    if (virIdentitySetAttr(identb,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           "fred") < 0)
        goto cleanup;

    if (!virIdentityIsEqual(identa, identb)) {
        VIR_DEBUG("Matched identities were not equal");
        goto cleanup;
    }

    if (virIdentitySetAttr(identa,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           "flintstone") < 0)
        goto cleanup;
    if (virIdentitySetAttr(identb,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           "flintstone") < 0)
        goto cleanup;

    if (!virIdentityIsEqual(identa, identb)) {
        VIR_DEBUG("Matched identities were not equal");
        goto cleanup;
    }

    if (virIdentitySetAttr(identb,
                           VIR_IDENTITY_ATTR_SASL_USER_NAME,
                           "fred@FLINTSTONE.COM") < 0)
        goto cleanup;

    if (virIdentityIsEqual(identa, identb)) {
        VIR_DEBUG("Mis-matched identities should not be equal");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(identa);
    virObjectUnref(identb);
    return ret;
}

static int testIdentityGetSystem(const void *data)
{
    const char *context = data;
    int ret = -1;
    virIdentityPtr ident = NULL;
    const char *val;

#if !WITH_SELINUX
    if (context) {
        VIR_DEBUG("libvirt not compiled with SELinux, skipping this test");
        ret = EXIT_AM_SKIP;
        goto cleanup;
    }
#endif

    if (!(ident = virIdentityGetSystem())) {
        VIR_DEBUG("Unable to get system identity");
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                           &val) < 0)
        goto cleanup;

    if (STRNEQ_NULLABLE(val, context)) {
        VIR_DEBUG("Unexpected SELinux context attribute");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(ident);
    return ret;
}

static int testSetFakeSELinuxContext(const void *data ATTRIBUTE_UNUSED)
{
#if WITH_SELINUX
    return setcon_raw((security_context_t)data);
#else
    VIR_DEBUG("libvirt not compiled with SELinux, skipping this test");
    return EXIT_AM_SKIP;
#endif
}

static int testDisableFakeSELinux(const void *data ATTRIBUTE_UNUSED)
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

    if (virtTestRun("Identity attributes ", testIdentityAttrs, NULL) < 0)
        ret = -1;
    if (virtTestRun("Identity equality ", testIdentityEqual, NULL) < 0)
        ret = -1;
    if (virtTestRun("Setting fake SELinux context ", testSetFakeSELinuxContext, context) < 0)
        ret = -1;
    if (virtTestRun("System identity (fake SELinux enabled) ", testIdentityGetSystem, context) < 0)
        ret = -1;
    if (virtTestRun("Disabling fake SELinux ", testDisableFakeSELinux, NULL) < 0)
        ret = -1;
    if (virtTestRun("System identity (fake SELinux disabled) ", testIdentityGetSystem, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#if WITH_SELINUX
VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/libsecurityselinuxhelper.so")
#else
VIRT_TEST_MAIN(mymain)
#endif
