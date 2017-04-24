#include <config.h>

#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsxen.h"
#include "domain_conf.h"

static virCPUFeatureDef cpuDefaultFeatures[] = {
    { (char *) "ds",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ss",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "tm",        -1 },
    { (char *) "pbe",       -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "vmx",       -1 },
    { (char *) "est",       -1 },
    { (char *) "tm2",       -1 },
    { (char *) "cx16",      -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "lahf_lm",   -1 },
};
static virCPUDef cpuDefaultData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_X86_64,
    .model = (char *) "core2duo",
    .vendor = (char *) "Intel",
    .sockets = 1,
    .cores = 2,
    .threads = 1,
    .nfeatures = ARRAY_CARDINALITY(cpuDefaultFeatures),
    .nfeatures_max = ARRAY_CARDINALITY(cpuDefaultFeatures),
    .features = cpuDefaultFeatures,
};

virCapsPtr testXenCapsInit(void)
{
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

    uname(&utsname);
    if ((caps = virCapabilitiesNew(VIR_ARCH_I686,
                                   false, false)) == NULL)
        return NULL;

    nmachines = ARRAY_CARDINALITY(x86_machines);
    if ((machines = virCapabilitiesAllocMachines(x86_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_XEN,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    nmachines = ARRAY_CARDINALITY(xen_machines);
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XEN, VIR_ARCH_I686,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_XEN,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    return caps;

 cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    virObjectUnref(caps);
    return NULL;
}


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
        "xenpv"
    };

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    caps->host.cpu = virCPUDefCopy(&cpuDefaultData);

    nmachines = ARRAY_CARDINALITY(x86_machines);
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
    nmachines = ARRAY_CARDINALITY(xen_machines);
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
    return caps;

 cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    virObjectUnref(caps);
    return NULL;
}
