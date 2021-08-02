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
 */

#include <config.h>

#include "testutils.h"
#include "internal.h"
#include "virarch.h"
#include "virthread.h"
#include "qemu/qemu_capabilities.h"
#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu/qemu_capspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE


static void
eventLoop(void *opaque G_GNUC_UNUSED)
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
    virQEMUCaps *caps;
    virArch host;
    virArch guest;
    const char *mock = VIR_TEST_MOCK("qemucapsprobe");

    if (!virFileIsExecutable(mock)) {
        perror(mock);
        return EXIT_FAILURE;
    }

    VIR_TEST_PRELOAD(mock);

    virFileActivateDirOverrideForProg(argv[0]);

    if (argc != 2) {
        fprintf(stderr, "%s QEMU_binary\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (virInitialize() < 0) {
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

    if (!(caps = virQEMUCapsNewForBinaryInternal(VIR_ARCH_NONE, argv[1], "/tmp",
                                                 -1, -1, NULL, 0, NULL, NULL)))
        return EXIT_FAILURE;

    host = virArchFromHost();
    guest = virQEMUCapsGetArch(caps);

    if (host != guest) {
        fprintf(stderr,
                "WARNING: guest architecture '%s' does not match host '%s'.\n"
                "WARNING: When generating capabilities for the libvirt test\n"
                "WARNING: suite, it is strongly desired to generate capabilities\n"
                "WARNING: on the native host to capture KVM related features.\n",
                virArchToString(guest), virArchToString(host));
    }

    virObjectUnref(caps);

    return EXIT_SUCCESS;
}
