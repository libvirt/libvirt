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
 */

#include <config.h>

#include "testutils.h"
#include "virerror.h"
#include "rpc/virnetserverclient.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#ifndef WIN32

static void *
testClientNew(virNetServerClient *client G_GNUC_UNUSED,
              void *opaque G_GNUC_UNUSED)
{
    return g_new0(char, 1);
}


static void
testClientFree(void *opaque)
{
    g_free(opaque);
}

static int testIdentity(const void *opaque G_GNUC_UNUSED)
{
    int sv[2];
    int ret = -1;
    virNetSocket *sock = NULL;
    virNetServerClient *client = NULL;
    g_autoptr(virIdentity) ident = NULL;
    const char *gotUsername = NULL;
    uid_t gotUserID;
    const char *gotGroupname = NULL;
    gid_t gotGroupID;
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
                                         NULL,
                                         testClientNew,
                                         NULL,
                                         testClientFree,
                                         NULL))) {
        virDispatchError(NULL);
        goto cleanup;
    }

    if (!(ident = virNetServerClientGetIdentity(client))) {
        fprintf(stderr, "Failed to create identity\n");
        goto cleanup;
    }

    if (virIdentityGetUserName(ident, &gotUsername) <= 0) {
        fprintf(stderr, "Missing username in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("astrochicken", gotUsername)) {
        fprintf(stderr, "Want username 'astrochicken' got '%s'\n",
                NULLSTR(gotUsername));
        goto cleanup;
    }

    if (virIdentityGetUNIXUserID(ident, &gotUserID) <= 0) {
        fprintf(stderr, "Missing user ID in identity\n");
        goto cleanup;
    }
    if (666 != gotUserID) {
        fprintf(stderr, "Want username '666' got '%llu'\n",
                (unsigned long long)gotUserID);
        goto cleanup;
    }

    if (virIdentityGetGroupName(ident, &gotGroupname) <= 0) {
        fprintf(stderr, "Missing groupname in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("fictionalusers", gotGroupname)) {
        fprintf(stderr, "Want groupname 'fictionalusers' got '%s'\n",
                NULLSTR(gotGroupname));
        goto cleanup;
    }

    if (virIdentityGetUNIXGroupID(ident, &gotGroupID) <= 0) {
        fprintf(stderr, "Missing group ID in identity\n");
        goto cleanup;
    }
    if (7337 != gotGroupID) {
        fprintf(stderr, "Want groupname '7337' got '%llu'\n",
                (unsigned long long)gotGroupID);
        goto cleanup;
    }

    if (virIdentityGetSELinuxContext(ident, &gotSELinuxContext) <= 0) {
        fprintf(stderr, "Missing SELinux context in identity\n");
        goto cleanup;
    }
    if (STRNEQ_NULLABLE("foo_u:bar_r:wizz_t:s0-s0:c0.c1023", gotSELinuxContext)) {
        fprintf(stderr, "Want SELinux context 'foo_u:bar_r:wizz_t:s0-s0:c0.c1023' got '%s'\n",
                NULLSTR(gotSELinuxContext));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(sock);
    if (client)
        virNetServerClientClose(client);
    virObjectUnref(client);
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
VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virnetserverclient"))
#else
static int
mymain(void)
{
    return EXIT_AM_SKIP;
}
VIR_TEST_MAIN(mymain);
#endif
