#include <config.h>
#ifdef WITH_QEMU
# include <sys/utsname.h>
# include <stdlib.h>

# include "testutilsqemu.h"
# include "testutils.h"
# include "memory.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"

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
    virCapsGuestMachinePtr *machines = NULL;
    int nmachines = 0;
    static const char *const xen_machines[] = {
        "xenner"
    };
    static virCPUFeatureDef host_cpu_features[] = {
        { (char *) "lahf_lm",   -1 },
        { (char *) "xtpr",      -1 },
        { (char *) "cx16",      -1 },
        { (char *) "tm2",       -1 },
        { (char *) "est",       -1 },
        { (char *) "vmx",       -1 },
        { (char *) "ds_cpl",    -1 },
        { (char *) "pbe",       -1 },
        { (char *) "tm",        -1 },
        { (char *) "ht",        -1 },
        { (char *) "ss",        -1 },
        { (char *) "acpi",      -1 },
        { (char *) "ds",        -1 }
    };
    static virCPUDef host_cpu = {
        VIR_CPU_TYPE_HOST,      /* type */
        0,                      /* match */
        (char *) "x86_64",      /* arch */
        (char *) "core2duo",    /* model */
        (char *) "Intel",       /* vendor */
        1,                      /* sockets */
        2,                      /* cores */
        1,                      /* threads */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures_max */
        host_cpu_features       /* features */
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    if ((caps->host.cpu = virCPUDefCopy(&host_cpu)) == NULL ||
        (machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    caps->ns.parse = qemuDomainDefNamespaceParse;
    caps->ns.free = qemuDomainDefNamespaceFree;
    caps->ns.format = qemuDomainDefNamespaceFormatXML;
    caps->ns.href = qemuDomainDefNamespaceHref;

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
