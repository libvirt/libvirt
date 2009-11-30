#include <config.h>
#ifdef WITH_QEMU
#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsqemu.h"
#include "testutils.h"
#include "memory.h"

static virCapsGuestMachinePtr *testQemuAllocMachines(int *nmachines)
{
    virCapsGuestMachinePtr *machines;
    static const char *const x86_machines[] = {
        "pc", "isapc"
    };

    machines = virCapabilitiesAllocMachines(x86_machines,
                                            ARRAY_CARDINALITY(x86_machines));
    if (machines == NULL)
        return NULL;

    *nmachines = ARRAY_CARDINALITY(x86_machines);

    return machines;
}

/* Newer versions of qemu have versioned machine types to allow
 * compatibility with older releases.
 * The 'pc' machine type is an alias of the newest machine type.
 */
static virCapsGuestMachinePtr *testQemuAllocNewerMachines(int *nmachines)
{
    virCapsGuestMachinePtr *machines;
    char *canonical;
    static const char *const x86_machines[] = {
        "pc-0.11", "pc", "pc-0.10", "isapc"
    };

    if ((canonical = strdup(x86_machines[0])) == NULL)
        return NULL;

    machines = virCapabilitiesAllocMachines(x86_machines,
                                            ARRAY_CARDINALITY(x86_machines));
    if (machines == NULL) {
        VIR_FREE(canonical);
        return NULL;
    }

    machines[1]->canonical = canonical;

    *nmachines = ARRAY_CARDINALITY(x86_machines);

    return machines;
}

virCapsPtr testQemuCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines;
    int nmachines;
    static const char *const xen_machines[] = {
        "xenner"
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
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

    if ((machines = testQemuAllocNewerMachines(&nmachines)) == NULL)
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

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      nmachines,
                                      machines) == NULL)
        goto cleanup;
    machines = NULL;

    nmachines = ARRAY_CARDINALITY(xen_machines);
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "xen", "x86_64", 64,
                                         "/usr/bin/xenner", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (virTestGetDebug()) {
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
