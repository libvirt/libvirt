/*
 * virt-admin.c: a shell to exercise the libvirt admin API
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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
 * Martin Kletzander <mkletzan@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

#include "configmake.h"
#include "internal.h"

#include <viralloc.h>

int
main(int argc ATTRIBUTE_UNUSED,
     char **argv ATTRIBUTE_UNUSED)
{
    int ret = EXIT_FAILURE;
    char *greeting = NULL;
    const char *uri = NULL;
    virAdmConnectPtr conn = NULL;

    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }
    if (!bindtextdomain(PACKAGE, LOCALEDIR)) {
        perror("bindtextdomain");
        return EXIT_FAILURE;
    }
    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return EXIT_FAILURE;
    }

    if (argc > 1)
        uri = argv[1];

    if (!(conn = virAdmConnectOpen(uri, 0)))
        goto cleanup;

    if (!(greeting = virAdmHello(conn, 0)))
        goto cleanup;

    printf("%s\n", greeting);

    ret = EXIT_SUCCESS;
 cleanup:
    VIR_FREE(greeting);
    virAdmConnectClose(conn);
    return ret;
}
