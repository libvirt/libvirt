#include <config.h>
#ifdef WITH_QEMU
#include <sys/utsname.h>
#include <stdlib.h>

#include "testutilsqemu.h"

virCapsPtr testQemuCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    static const char *const x86_machines[] = {
        "pc", "isapc"
    };
    static const char *const xen_machines[] = {
        "xenner"
    };

    uname (&utsname);
    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32,
                                         "/usr/bin/qemu", NULL,
                                         2, x86_machines)) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "qemu",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", "x86_64", 64,
                                         "/usr/bin/qemu-system-x86_64", NULL,
                                         2, x86_machines)) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "qemu",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps, "xen", "x86_64", 64,
                                         "/usr/bin/xenner", NULL,
                                         1, xen_machines)) == NULL)
        goto cleanup;
    if (virCapabilitiesAddGuestDomain(guest,
                                      "kvm",
                                      "/usr/bin/kvm",
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    return caps;

cleanup:
    virCapabilitiesFree(caps);
    return NULL;
}
#endif
