#include <config.h>
#ifdef WITH_QEMU
# include <stdlib.h>

# include "testutilsqemu.h"
# include "testutils.h"
# include "memory.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"
# include "qemu/qemu_domain.h"

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

static int testQemuDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}

static int testQemuAddPPC64Guest(virCapsPtr caps)
{
    static const char *machine[] = { "pseries" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", "ppc64", 64,
                                    "/usr/bin/qemu-system-ppc64", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "qemu", NULL, NULL, 0, NULL))
        goto error;

    return 0;

error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

virCapsPtr testQemuCapsInit(void) {
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
        0,                      /* mode */
        0,                      /* match */
        (char *) "x86_64",      /* arch */
        (char *) "core2duo",    /* model */
        0,                      /* fallback */
        (char *) "Intel",       /* vendor */
        1,                      /* sockets */
        2,                      /* cores */
        1,                      /* threads */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures_max */
        host_cpu_features       /* features */
    };

    if ((caps = virCapabilitiesNew(host_cpu.arch,
                                   0, 0)) == NULL)
        return NULL;

    caps->defaultConsoleTargetType = testQemuDefaultConsoleType;

    if ((caps->host.cpu = virCPUDefCopy(&host_cpu)) == NULL ||
        (machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    qemuDomainSetNamespaceHooks(caps);

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32,
                                         "/usr/bin/qemu", NULL,
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", 1, 0))
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
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", 1, 0))
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

    if (testQemuAddPPC64Guest(caps))
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
