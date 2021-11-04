/*
 * dommigrate.c: This file is largely inspired from hellolibvirt and
 *               contains a trivial example that illustrate p2p domain
 *               migration with libvirt.
 *
 * Copyright (C) 2014 Cloudwatt
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

#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>


static void
usage(char *prgn)
{
    printf("Usage: %s <src uri> <dst uri> <domain name>\n", prgn);
}

int
main(int argc, char *argv[])
{
    char *src_uri, *dst_uri, *domname;
    int ret = EXIT_FAILURE;
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    if (argc < 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    src_uri = argv[1];
    dst_uri = argv[2];
    domname = argv[3];

    printf("Attempting to connect to the source hypervisor...\n");
    conn = virConnectOpenAuth(src_uri, virConnectAuthPtrDefault, 0);
    if (!conn) {
        fprintf(stderr, "No connection to the source hypervisor: %s.\n",
                virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

    printf("Attempting to retrieve domain %s...\n", domname);
    dom = virDomainLookupByName(conn, domname);
    if (!dom) {
        fprintf(stderr, "Failed to find domain %s.\n", domname);
        goto cleanup;
    }

    printf("Attempting to migrate %s to %s...\n", domname, dst_uri);
    if ((ret = virDomainMigrateToURI(dom, dst_uri,
                                     VIR_MIGRATE_PEER2PEER,
                                     NULL, 0)) != 0) {
        fprintf(stderr, "Failed to migrate domain %s.\n", domname);
        goto cleanup;
    }

    printf("Migration finished with success.\n");
    ret = EXIT_SUCCESS;

 cleanup:
    if (dom != NULL)
        virDomainFree(dom);
    virConnectClose(conn);
    return ret;
}
