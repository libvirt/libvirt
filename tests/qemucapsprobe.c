/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "testutils.h"
#include "internal.h"
#include "virthread.h"
#include "qemu/qemu_capabilities.h"
#define __QEMU_CAPSPRIV_H_ALLOW__ 1
#include "qemu/qemu_capspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE


static void
eventLoop(void *opaque ATTRIBUTE_UNUSED)
{
    while (1) {
        if (virEventRunDefaultImpl() < 0) {
            fprintf(stderr, "Failed to run event loop: %s\n",
                    virGetLastErrorMessage());
        }
    }
}


int
main(int argc, char **argv)
{
    virThread thread;
    virQEMUCapsPtr caps;

    VIR_TEST_PRELOAD(abs_builddir "/.libs/qemucapsprobemock.so");

    if (argc != 2) {
        fprintf(stderr, "%s QEMU_binary\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (virThreadInitialize() < 0 ||
        virInitialize() < 0) {
        fprintf(stderr, "Failed to initialize libvirt");
        return EXIT_FAILURE;
    }

    if (virEventRegisterDefaultImpl() < 0) {
        fprintf(stderr, "Failed to register event implementation: %s\n",
                virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

    if (virThreadCreate(&thread, false, eventLoop, NULL) < 0)
        return EXIT_FAILURE;

    if (!(caps = virQEMUCapsNewForBinaryInternal(NULL, argv[1], "/tmp", NULL,
                                                 -1, -1, true)))
        return EXIT_FAILURE;

    virObjectUnref(caps);

    return EXIT_SUCCESS;
}
