#include <config.h>
#ifdef WITH_QEMU
# include <stdlib.h>

# include "testutilsqemu.h"
# include "testutils.h"
# include "viralloc.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"
# include "qemu/qemu_domain.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

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

    if (VIR_STRDUP(canonical, x86_machines[0]) < 0)
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


static int testQemuAddPPC64Guest(virCapsPtr caps)
{
    static const char *machine[] = { "pseries" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_PPC64,
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

static int testQemuAddPPCGuest(virCapsPtr caps)
{
    static const char *machine[] = { "g3beige",
                                     "mac99",
                                     "prep",
                                     "ppce500v2" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_PPC,
                                    "/usr/bin/qemu-system-ppc", NULL,
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

static int testQemuAddS390Guest(virCapsPtr caps)
{
    static const char *s390_machines[] = { "s390-virtio",
                                           "s390-ccw-virtio" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(s390_machines,
                                            ARRAY_CARDINALITY(s390_machines));
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_S390X,
                                    "/usr/bin/qemu-system-s390x", NULL,
                                    ARRAY_CARDINALITY(s390_machines),
                                    machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "qemu", NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(machines, ARRAY_CARDINALITY(s390_machines));
    return -1;
}

static int testQemuAddArmGuest(virCapsPtr caps)
{
    static const char *machines[] = { "vexpress-a9",
                                      "vexpress-a15",
                                      "versatilepb" };
    virCapsGuestMachinePtr *capsmachines = NULL;
    virCapsGuestPtr guest;

    capsmachines = virCapabilitiesAllocMachines(machines,
                                                ARRAY_CARDINALITY(machines));
    if (!capsmachines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_ARMV7L,
                                    "/usr/bin/qemu-system-arm", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "qemu", NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

static int testQemuAddAARCH64Guest(virCapsPtr caps)
{
    static const char *machines[] = { "virt"};
    virCapsGuestMachinePtr *capsmachines = NULL;
    virCapsGuestPtr guest;

    capsmachines = virCapabilitiesAllocMachines(machines,
                                                ARRAY_CARDINALITY(machines));
    if (!capsmachines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_AARCH64,
                                    "/usr/bin/qemu-system-aarch64", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "qemu", NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    virCapabilitiesFreeMachines(capsmachines, ARRAY_CARDINALITY(machines));
    return -1;
}

virCapsPtr testQemuCapsInit(void)
{
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
        VIR_ARCH_X86_64,        /* arch */
        (char *) "core2duo",    /* model */
        NULL,                   /* vendor_id */
        0,                      /* fallback */
        (char *) "Intel",       /* vendor */
        1,                      /* sockets */
        2,                      /* cores */
        1,                      /* threads */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures */
        ARRAY_CARDINALITY(host_cpu_features), /* nfeatures_max */
        host_cpu_features,      /* features */
        0,                      /* ncells */
        0,                      /* ncells_max */
        NULL,                   /* cells */
        0,                      /* cells_cpus */
    };

    if ((caps = virCapabilitiesNew(host_cpu.arch,
                                   0, 0)) == NULL)
        return NULL;

    if ((caps->host.cpu = virCPUDefCopy(&host_cpu)) == NULL ||
        (machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_I686,
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

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", VIR_ARCH_X86_64,
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

    if ((guest = virCapabilitiesAddGuest(caps, "xen", VIR_ARCH_X86_64,
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

    if (testQemuAddPPCGuest(caps))
        goto cleanup;

    if (testQemuAddS390Guest(caps))
        goto cleanup;

    if (testQemuAddArmGuest(caps))
        goto cleanup;

    if (testQemuAddAARCH64Guest(caps))
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
    virObjectUnref(caps);
    return NULL;
}


static char *
testSCSIDeviceGetSgName(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                        const char *adapter ATTRIBUTE_UNUSED,
                        unsigned int bus ATTRIBUTE_UNUSED,
                        unsigned int target ATTRIBUTE_UNUSED,
                        unsigned int unit ATTRIBUTE_UNUSED)
{
    char *sg = NULL;

    if (VIR_STRDUP(sg, "sg0") < 0)
        return NULL;

    return sg;
}

qemuBuildCommandLineCallbacks testCallbacks = {
    .qemuGetSCSIDeviceSgName = testSCSIDeviceGetSgName,
};
#endif
