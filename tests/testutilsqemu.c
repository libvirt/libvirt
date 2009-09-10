#include <config.h>
#ifdef WITH_QEMU
#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsqemu.h"
#include "testutils.h"
#include "memory.h"

virCapsPtr testQemuCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines;
    int nmachines;
    static const char *const x86_machines[] = {
        "pc", "isapc"
    };
    static const char *const xen_machines[] = {
        "xenner"
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    nmachines = 2;
    if ((machines = virCapabilitiesAllocMachines(x86_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32,
                                         "/usr/bin/qemu", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "qemu",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    nmachines = 2;
    if ((machines = virCapabilitiesAllocMachines(x86_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "x86_64", 64,
                                         "/usr/bin/qemu-system-x86_64", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "qemu",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    nmachines = 1;
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "xen", "x86_64", 64,
                                         "/usr/bin/xenner", NULL,
                                         1, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (testDebug) {
        char *caps_str;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto cleanup;

        fprintf(stderr, "QEMU driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    virCapabilitiesFree(caps);
    return NULL;
}
#endif
