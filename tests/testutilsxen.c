#include <config.h>

#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsxen.h"

virCapsPtr testXenCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines;
    int nmachines;
    static const char *const x86_machines[] = {
        "xenfv"
    };
    static const char *const xen_machines[] = {
        "xenpv"
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    nmachines = ARRAY_CARDINALITY(x86_machines);
    if ((machines = virCapabilitiesAllocMachines(x86_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "xen",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    nmachines = ARRAY_CARDINALITY(xen_machines);
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "xen", "i686", 32,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "xen",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    return caps;

cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    virCapabilitiesFree(caps);
    return NULL;
}
