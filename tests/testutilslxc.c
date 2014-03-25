#include <config.h>
#ifdef WITH_LXC
# include <stdlib.h>

# include "testutilslxc.h"
# include "testutils.h"
# include "viralloc.h"
# include "domain_conf.h"


virCapsPtr testLXCCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64,
                                   0, 0)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, "exe", VIR_ARCH_I686,
                                         "/usr/libexec/libvirt_lxc", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "lxc", NULL, NULL, 0, NULL))
        goto error;


    if ((guest = virCapabilitiesAddGuest(caps, "exe", VIR_ARCH_X86_64,
                                         "/usr/libexec/libvirt_lxc", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "lxc", NULL, NULL, 0, NULL))
        goto error;


    if (virTestGetDebug()) {
        char *caps_str;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto error;

        fprintf(stderr, "LXC driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}
#endif
