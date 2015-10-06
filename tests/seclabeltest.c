#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "security/security_driver.h"
#include "virrandom.h"

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED)
{
    virSecurityManagerPtr mgr;
    const char *doi, *model;

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;

    mgr = virSecurityManagerNew(NULL, "QEMU", VIR_SECURITY_MANAGER_DEFAULT_CONFINED);
    if (mgr == NULL) {
        fprintf(stderr, "Failed to start security driver");
        return EXIT_FAILURE;
    }

    model = virSecurityManagerGetModel(mgr);
    if (!model) {
        fprintf(stderr, "Failed to copy secModel model: %s",
                strerror(errno));
        return EXIT_FAILURE;
    }

    doi = virSecurityManagerGetDOI(mgr);
    if (!doi) {
        fprintf(stderr, "Failed to copy secModel DOI: %s",
                strerror(errno));
        return EXIT_FAILURE;
    }

    virObjectUnref(mgr);

    return 0;
}
