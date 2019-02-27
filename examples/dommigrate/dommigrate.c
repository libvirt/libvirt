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


static int
usage(char *prgn, int ret)
{
    printf("Usage: %s <src uri> <dst uri> <domain name>\n", prgn);
    return ret;
}

int
main(int argc, char *argv[])
{
    char *src_uri, *dst_uri, *domname;
    int ret = 0;
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    if (argc < 4) {
        ret = usage(argv[0], 1);
        goto out;
    }

    src_uri = argv[1];
    dst_uri = argv[2];
    domname = argv[3];

    printf("Attempting to connect to the source hypervisor...\n");
    conn = virConnectOpenAuth(src_uri, virConnectAuthPtrDefault, 0);
    if (!conn) {
        ret = 1;
        fprintf(stderr, "No connection to the source hypervisor: %s.\n",
                virGetLastErrorMessage());
        goto out;
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

 cleanup:
    if (dom != NULL)
        virDomainFree(dom);
    virConnectClose(conn);

 out:
    return ret;
}
