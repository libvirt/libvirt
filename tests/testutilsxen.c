#include <config.h>

#include <sys/utsname.h>

#include "testutilsxen.h"
#include "testutilshostcpus.h"
#include "domain_conf.h"

virCapsPtr
testXLInitCaps(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines;
    int nmachines;
    static const char *const x86_machines[] = {
        "xenfv"
    };
    static const char *const xen_machines[] = {
        "xenpv",
    };
    static const char *const pvh_machines[] = {
        "xenpvh",
    };

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    caps->host.cpu = virCPUDefCopy(&cpuDefaultData);

    nmachines = G_N_ELEMENTS(x86_machines);
    if ((machines = virCapabilitiesAllocMachines(x86_machines, nmachines)) == NULL)
        goto cleanup;
    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                         VIR_ARCH_X86_64,
                                         "/usr/lib/xen/bin/qemu-system-i386",
                                         "/usr/lib/xen/boot/hvmloader",
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;
    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN, NULL,
                                      NULL, 0, NULL) == NULL)
        goto cleanup;
    nmachines = G_N_ELEMENTS(xen_machines);
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XEN,
                                         VIR_ARCH_X86_64,
                                         "/usr/lib/xen/bin/qemu-system-i386",
                                         NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN, NULL,
                                      NULL, 0, NULL) == NULL)
        goto cleanup;
    nmachines = G_N_ELEMENTS(pvh_machines);
    if ((machines = virCapabilitiesAllocMachines(pvh_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XENPVH,
                                         VIR_ARCH_X86_64,
                                         "/usr/lib/xen/bin/qemu-system-i386",
                                         NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN, NULL,
                                      NULL, 0, NULL) == NULL)
        goto cleanup;
    return caps;

 cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    virObjectUnref(caps);
    return NULL;
}
