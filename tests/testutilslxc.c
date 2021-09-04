#include <config.h>
#ifdef WITH_LXC

# include "testutilslxc.h"
# include "testutils.h"
# include "viralloc.h"
# include "domain_conf.h"

# define VIR_FROM_THIS VIR_FROM_LXC

virCaps *
testLXCCapsInit(void)
{
    virCaps *caps;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64,
                                   false, false)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                         VIR_ARCH_I686,
                                         "/usr/libexec/libvirt_lxc", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC, NULL, NULL, 0, NULL))
        goto error;


    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                         VIR_ARCH_X86_64,
                                         "/usr/libexec/libvirt_lxc", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC, NULL, NULL, 0, NULL))
        goto error;


    if (virTestGetDebug()) {
        g_autofree char *caps_str = NULL;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto error;

        VIR_TEST_DEBUG("LXC driver capabilities:\n%s", caps_str);
    }

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
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
