#include <config.h>
#ifdef WITH_QEMU
# include <stdlib.h>

# include "testutilsqemu.h"
# include "testutils.h"
# include "viralloc.h"
# include "cpu_conf.h"
# include "qemu/qemu_driver.h"
# include "qemu/qemu_domain.h"
# define __QEMU_CAPSRIV_H_ALLOW__
# include "qemu/qemu_capspriv.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_QEMU

virCPUDefPtr cpuDefault;
virCPUDefPtr cpuHaswell;

static virCPUFeatureDef cpuDefaultFeatures[] = {
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
static virCPUDef cpuDefaultData = {
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
    ARRAY_CARDINALITY(cpuDefaultFeatures), /* nfeatures */
    ARRAY_CARDINALITY(cpuDefaultFeatures), /* nfeatures_max */
    cpuDefaultFeatures,     /* features */
};

static virCPUFeatureDef cpuHaswellFeatures[] = {
    { (char *) "lahf_lm",   -1 },
    { (char *) "invtsc",    -1 },
    { (char *) "abm",       -1 },
    { (char *) "pdpe1gb",   -1 },
    { (char *) "rdrand",    -1 },
    { (char *) "f16c",      -1 },
    { (char *) "osxsave",   -1 },
    { (char *) "pdcm",      -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "tm2",       -1 },
    { (char *) "est",       -1 },
    { (char *) "smx",       -1 },
    { (char *) "vmx",       -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "monitor",   -1 },
    { (char *) "dtes64",    -1 },
    { (char *) "pbe",       -1 },
    { (char *) "tm",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "ss",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ds",        -1 },
    { (char *) "vme",       -1 },
};
static virCPUDef cpuHaswellData = {
    VIR_CPU_TYPE_HOST,      /* type */
    0,                      /* mode */
    0,                      /* match */
    VIR_ARCH_X86_64,        /* arch */
    (char *) "Haswell",     /* model */
    NULL,                   /* vendor_id */
    0,                      /* fallback */
    (char *) "Intel",       /* vendor */
    1,                      /* sockets */
    2,                      /* cores */
    2,                      /* threads */
    ARRAY_CARDINALITY(cpuHaswellFeatures), /* nfeatures */
    ARRAY_CARDINALITY(cpuHaswellFeatures), /* nfeatures_max */
    cpuHaswellFeatures,     /* features */
};

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

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64,
                                    "/usr/bin/qemu-system-ppc64", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
        goto error;

    return 0;

 error:
    /* No way to free a guest? */
    virCapabilitiesFreeMachines(machines, 1);
    return -1;
}

static int testQemuAddPPC64LEGuest(virCapsPtr caps)
{
    static const char *machine[] = { "pseries" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64LE,
                                    "/usr/bin/qemu-system-ppc64", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
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
                                     "ppce500" };
    virCapsGuestMachinePtr *machines = NULL;
    virCapsGuestPtr guest;

    machines = virCapabilitiesAllocMachines(machine, 1);
    if (!machines)
        goto error;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC,
                                    "/usr/bin/qemu-system-ppc", NULL,
                                     1, machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
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

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_S390X,
                                    "/usr/bin/qemu-system-s390x", NULL,
                                    ARRAY_CARDINALITY(s390_machines),
                                    machines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
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

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_ARMV7L,
                                    "/usr/bin/qemu-system-arm", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
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

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_AARCH64,
                                    "/usr/bin/qemu-system-aarch64", NULL,
                                    ARRAY_CARDINALITY(machines),
                                    capsmachines);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU, NULL, NULL, 0, NULL))
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

    if (!(caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)))
        return NULL;

    /* Add dummy 'none' security_driver. This is equal to setting
     * security_driver = "none" in qemu.conf. */
    if (VIR_ALLOC_N(caps->host.secModels, 1) < 0)
        goto cleanup;
    caps->host.nsecModels = 1;

    if (VIR_STRDUP(caps->host.secModels[0].model, "none") < 0 ||
        VIR_STRDUP(caps->host.secModels[0].doi, "0") < 0)
        goto cleanup;

    if (!(cpuDefault = virCPUDefCopy(&cpuDefaultData)) ||
        !(cpuHaswell = virCPUDefCopy(&cpuHaswellData)))
        goto cleanup;

    caps->host.cpu = cpuDefault;

    caps->host.nnumaCell_max = 4;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                         "/usr/bin/qemu", NULL,
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/qemu-kvm",
                                      NULL,
                                      nmachines,
                                      machines) == NULL)
        goto cleanup;
    machines = NULL;

    if ((machines = testQemuAllocNewerMachines(&nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                         "/usr/bin/qemu-system-x86_64", NULL,
                                         nmachines, machines)) == NULL ||
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((machines = testQemuAllocMachines(&nmachines)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/kvm",
                                      NULL,
                                      nmachines,
                                      machines) == NULL)
        goto cleanup;
    machines = NULL;

    nmachines = ARRAY_CARDINALITY(xen_machines);
    if ((machines = virCapabilitiesAllocMachines(xen_machines, nmachines)) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XEN, VIR_ARCH_X86_64,
                                         "/usr/bin/xenner", NULL,
                                         nmachines, machines)) == NULL)
        goto cleanup;
    machines = NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (testQemuAddPPC64Guest(caps))
        goto cleanup;

    if (testQemuAddPPC64LEGuest(caps))
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

        VIR_TEST_DEBUG("QEMU driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

 cleanup:
    virCapabilitiesFreeMachines(machines, nmachines);
    if (caps->host.cpu != cpuDefault)
        virCPUDefFree(cpuDefault);
    if (caps->host.cpu != cpuHaswell)
        virCPUDefFree(cpuHaswell);
    virObjectUnref(caps);
    return NULL;
}


static char *
testSCSIDeviceGetSgName(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                        const char *adapter ATTRIBUTE_UNUSED,
                        unsigned int bus ATTRIBUTE_UNUSED,
                        unsigned int target ATTRIBUTE_UNUSED,
                        unsigned long long unit ATTRIBUTE_UNUSED)
{
    char *sg = NULL;

    if (VIR_STRDUP(sg, "sg0") < 0)
        return NULL;

    return sg;
}

qemuBuildCommandLineCallbacks testCallbacks = {
    .qemuGetSCSIDeviceSgName = testSCSIDeviceGetSgName,
};

virQEMUCapsPtr
qemuTestParseCapabilities(const char *capsFile)
{
    virQEMUCapsPtr qemuCaps = NULL;
    xmlDocPtr xml;
    xmlXPathContextPtr ctxt = NULL;
    ssize_t i, n;
    xmlNodePtr *nodes = NULL;

    if (!(xml = virXMLParseFileCtxt(capsFile, &ctxt)))
        goto error;

    if ((n = virXPathNodeSet("/qemuCaps/flag", ctxt, &nodes)) < 0) {
        fprintf(stderr, "failed to parse qemu capabilities flags");
        goto error;
    }

    if (n > 0) {
        if (!(qemuCaps = virQEMUCapsNew()))
            goto error;

        for (i = 0; i < n; i++) {
            char *str = virXMLPropString(nodes[i], "name");
            if (str) {
                int flag = virQEMUCapsTypeFromString(str);
                if (flag < 0) {
                    fprintf(stderr, "Unknown qemu capabilities flag %s", str);
                    VIR_FREE(str);
                    goto error;
                }
                VIR_FREE(str);
                virQEMUCapsSet(qemuCaps, flag);
            }
        }
    }

    VIR_FREE(nodes);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return qemuCaps;

 error:
    VIR_FREE(nodes);
    virObjectUnref(qemuCaps);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return NULL;
}

void qemuTestDriverFree(virQEMUDriver *driver)
{
    virMutexDestroy(&driver->lock);
    virQEMUCapsCacheFree(driver->qemuCapsCache);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->config);
}

int qemuTestCapsCacheInsert(virQEMUCapsCachePtr cache, const char *binary,
                            virQEMUCapsPtr caps)
{
    int ret;

    if (caps) {
        /* Our caps were created artificially, so we don't want
         * virQEMUCapsCacheFree() to attempt to deallocate them */
        virObjectRef(caps);
    } else {
        caps = virQEMUCapsNew();
        if (!caps)
            return -ENOMEM;
    }

    /* We can have repeating names for our test data sets,
     * so make sure there's no old copy */
    virHashRemoveEntry(cache->binaries, binary);

    ret = virHashAddEntry(cache->binaries, binary, caps);
    if (ret < 0)
        virObjectUnref(caps);
    else
        qemuTestCapsName = binary;

    return ret;
}

int qemuTestDriverInit(virQEMUDriver *driver)
{
    if (virMutexInit(&driver->lock) < 0)
        return -1;

    driver->config = virQEMUDriverConfigNew(false);
    if (!driver->config)
        goto error;

    driver->caps = testQemuCapsInit();
    if (!driver->caps)
        goto error;

    /* Using /dev/null for libDir and cacheDir automatically produces errors
     * upon attempt to use any of them */
    driver->qemuCapsCache = virQEMUCapsCacheNew("/dev/null", "/dev/null", 0, 0);
    if (!driver->qemuCapsCache)
        goto error;

    driver->xmlopt = virQEMUDriverCreateXMLConf(driver);
    if (!driver->xmlopt)
        goto error;

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, "empty", NULL) < 0)
        goto error;

    return 0;

 error:
    qemuTestDriverFree(driver);
    return -1;
}

#endif
