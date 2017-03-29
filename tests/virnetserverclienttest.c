/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "testutils.h"
#include "virerror.h"
#include "rpc/virnetserverclient.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#ifdef HAVE_SOCKETPAIR
static int testIdentity(const void *opaque ATTRIBUTE_UNUSED)
{
    int sv[2];
    int ret = -1;
    virNetSocketPtr sock = NULL;
    virNetServerClientPtr client = NULL;
    virIdentityPtr ident = NULL;
    const char *gotUsername = NULL;
    const char *gotUserID = NULL;
    const char *gotGroupname = NULL;
    const char *gotGroupID = NULL;
    const char *gotSELinuxContext = NULL;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        virReportSystemError(errno, "%s",
                             "Cannot create socket pair");
        return -1;
    }

    if (virNetSocketNewConnectSockFD(sv[0], &sock) < 0) {
        virDispatchError(NULL);
        goto cleanup;
    }
    sv[0] = -1;

    if (!(client = virNetServerClientNew(1, sock, 0, false, 1,
# ifdef WITH_GNUTLS
                                         NULL,
# endif
                                         NULL, NULL, NULL, NULL))) {
        virDispatchError(NULL);
        goto cleanup;
    }

    if (!(ident = virNetServerClientGetIdentity(client))) {
        fprintf(stderr, "Failed to create identity\n");
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           &gotUsername) < 0) {
        fprintf(stderr, "Missing username in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("astrochicken", gotUsername)) {
        fprintf(stderr, "Want username 'astrochicken' got '%s'\n",
                NULLSTR(gotUsername));
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_ID,
                           &gotUserID) < 0) {
        fprintf(stderr, "Missing user ID in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("666", gotUserID)) {
        fprintf(stderr, "Want username '666' got '%s'\n",
                NULLSTR(gotUserID));
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           &gotGroupname) < 0) {
        fprintf(stderr, "Missing groupname in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("fictionalusers", gotGroupname)) {
        fprintf(stderr, "Want groupname 'fictionalusers' got '%s'\n",
                NULLSTR(gotGroupname));
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
                           &gotGroupID) < 0) {
        fprintf(stderr, "Missing group ID in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("7337", gotGroupID)) {
        fprintf(stderr, "Want groupname '7337' got '%s'\n",
                NULLSTR(gotGroupID));
        goto cleanup;
    }

    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                           &gotSELinuxContext) < 0) {
        fprintf(stderr, "Missing SELinux context in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("foo_u:bar_r:wizz_t:s0-s0:c0.c1023", gotSELinuxContext)) {
        fprintf(stderr, "Want groupname 'foo_u:bar_r:wizz_t:s0-s0:c0.c1023' got '%s'\n",
                NULLSTR(gotGroupID));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(sock);
    virObjectUnref(client);
    virObjectUnref(ident);
    VIR_FORCE_CLOSE(sv[0]);
    VIR_FORCE_CLOSE(sv[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;


    if (virTestRun("Identity",
                   testIdentity, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnetserverclientmock.so")
#else
static int
mymain(void)
{
    return EXIT_AM_SKIP;
}
VIR_TEST_MAIN(mymain);
#endif
