/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 */

/*
 * This is a helper for shunloadtest.c. This function is built into
 * a shared library and linked with libvirto.so
 *
 * The function initializes libvirt and primes the thread local with
 * an error which needs to be freed at thread exit
 */

#include <config.h>
#include "internal.h"

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <stdlib.h>

static void shunloadError(void *userData ATTRIBUTE_UNUSED,
                          virErrorPtr error ATTRIBUTE_UNUSED)
{
}

void shunloadStart(void);

void shunloadStart(void) {
    virConnectPtr conn;

    virSetErrorFunc(NULL, shunloadError);
    virInitialize();

    conn = virConnectOpen("test:///default");
    virDomainDestroy(NULL);
    if (conn)
        virConnectClose(conn);
}
