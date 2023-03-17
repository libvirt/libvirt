#include <config.h>

#include <sys/utsname.h>

#include "testutilsxen.h"
#include "testutilshostcpus.h"
#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

static virCaps *
testXLInitCaps(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;
    virCapsGuestMachine **machines;
    int nmachines;
    static const char *const x86_machines[] = {
        "xenfv", NULL,
    };
    static const char *const xen_machines[] = {
        "xenpv", NULL,
    };
    static const char *const pvh_machines[] = {
        "xenpvh", NULL,
    };

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    caps->host.cpu = virCPUDefCopy(&cpuDefaultData);

    machines = virCapabilitiesAllocMachines(x86_machines, &nmachines);
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_X86_64,
                                    "/usr/lib/xen/bin/qemu-system-i386",
                                    "/usr/lib/xen/boot/hvmloader",
                                    nmachines, machines);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN,
                                  NULL, NULL, 0, NULL);

    machines = virCapabilitiesAllocMachines(xen_machines, &nmachines);
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XEN,
                                    VIR_ARCH_X86_64,
                                    "/usr/lib/xen/bin/qemu-system-i386",
                                    NULL,
                                    nmachines, machines);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN,
                                  NULL, NULL, 0, NULL);

    machines = virCapabilitiesAllocMachines(pvh_machines, &nmachines);
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_XENPVH,
                                    VIR_ARCH_X86_64,
                                    "/usr/lib/xen/bin/qemu-system-i386",
                                    NULL,
                                    nmachines, machines);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN,
                                  NULL, NULL, 0, NULL);
    return g_steal_pointer(&caps);
}


libxlDriverPrivate *testXLInitDriver(void)
{
    libxlDriverPrivate *driver = g_new0(libxlDriverPrivate, 1);

    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", "cannot initialize mutex");
        g_free(driver);
        return NULL;
    }

    if (!(driver->config = libxlDriverConfigNew()))
        return NULL;

    g_free(driver->config->logDir);
    driver->config->logDir = g_strdup(abs_builddir);

    if (libxlDriverConfigInit(driver->config) < 0)
        return NULL;

    driver->config->caps = testXLInitCaps();

    driver->xmlopt = libxlCreateXMLConf(driver);

    return driver;
}

void testXLFreeDriver(libxlDriverPrivate *driver)
{
    virObjectUnref(driver->config);
    virObjectUnref(driver->xmlopt);
    virMutexDestroy(&driver->lock);
    g_free(driver);
}
