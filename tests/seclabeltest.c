#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "security/security_driver.h"
#include "virrandom.h"

int
main (int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED)
{
    virSecurityManagerPtr mgr;
    const char *doi, *model;

    if (virThreadInitialize() < 0 ||
        virRandomInitialize(time(NULL) ^ getpid()))
        exit(EXIT_FAILURE);

    mgr = virSecurityManagerNew(NULL, "QEMU", false, true, false);
    if (mgr == NULL) {
        fprintf (stderr, "Failed to start security driver");
        exit(EXIT_FAILURE);
    }

    model = virSecurityManagerGetModel(mgr);
    if (!model)
    {
        fprintf (stderr, "Failed to copy secModel model: %s",
                 strerror (errno));
        exit(EXIT_FAILURE);
    }

    doi = virSecurityManagerGetDOI(mgr);
    if (!doi)
    {
        fprintf (stderr, "Failed to copy secModel DOI: %s",
                 strerror (errno));
        exit(EXIT_FAILURE);
    }

    virSecurityManagerFree(mgr);

    return 0;
}
