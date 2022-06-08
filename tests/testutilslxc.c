#include <config.h>
#ifdef WITH_LXC

# include "testutilslxc.h"
# include "testutils.h"
# include "domain_conf.h"

# define VIR_FROM_THIS VIR_FROM_LXC

virCaps *
testLXCCapsInit(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)) == NULL)
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                    VIR_ARCH_I686,
                                    "/usr/libexec/libvirt_lxc", NULL,
                                    0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC, NULL, NULL, 0, NULL);

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                    VIR_ARCH_X86_64,
                                    "/usr/libexec/libvirt_lxc", NULL,
                                    0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC, NULL, NULL, 0, NULL);

    if (virTestGetDebug()) {
        g_autofree char *caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            return NULL;

        VIR_TEST_DEBUG("LXC driver capabilities:\n%s", caps_str);
    }

    return g_steal_pointer(&caps);
}


virLXCDriver *
testLXCDriverInit(void)
{
    virLXCDriver *driver = g_new0(virLXCDriver, 1);

    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", "cannot initialize mutex");
        g_free(driver);
        return NULL;
    }

    driver->caps = testLXCCapsInit();
    driver->xmlopt = lxcDomainXMLConfInit(driver, NULL);

    return driver;
}


void
testLXCDriverFree(virLXCDriver *driver)
{
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virMutexDestroy(&driver->lock);
    g_free(driver);
}

#endif
