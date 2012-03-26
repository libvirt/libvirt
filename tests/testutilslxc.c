#include <config.h>
#ifdef WITH_LXC
# include <stdlib.h>

# include "testutilslxc.h"
# include "testutils.h"
# include "memory.h"
# include "domain_conf.h"


static int testLXCDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC;
}


virCapsPtr testLXCCapsInit(void) {
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew("x86_64",
                                   0, 0)) == NULL)
        return NULL;

    caps->defaultConsoleTargetType = testLXCDefaultConsoleType;

    if ((guest = virCapabilitiesAddGuest(caps, "exe", "i686", 32,
                                         "/usr/libexec/libvirt_lxc", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, "lxc", NULL, NULL, 0, NULL))
        goto error;


    if ((guest = virCapabilitiesAddGuest(caps, "exe", "x86_64", 64,
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
    virCapabilitiesFree(caps);
    return NULL;
}
#endif
