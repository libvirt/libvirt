#include <config.h>

#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsxen.h"

virCapsPtr testXenCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    static const char *const x86_machines[] = {
        "xenfv"
    };
    static const char *const xen_machines[] = {
        "xenpv"
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         1, x86_machines)) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "xen",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "xen", "i686", 32,
                                         "/usr/lib/xen/bin/qemu-dm", NULL,
                                         1, xen_machines)) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "xen",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    return caps;

cleanup:
    virCapabilitiesFree(caps);
    return NULL;
}
