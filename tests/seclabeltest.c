#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "security/security_driver.h"

int
main (int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED)
{
    virSecurityManagerPtr mgr;
    const char *doi, *model;

    mgr = virSecurityManagerNew(NULL, false, true, false);
    if (mgr == NULL) {
        fprintf (stderr, "Failed to start security driver");
        exit (-1);
    }

    model = virSecurityManagerGetModel(mgr);
    if (!model)
    {
        fprintf (stderr, "Failed to copy secModel model: %s",
                 strerror (errno));
        exit (-1);
    }

    doi = virSecurityManagerGetDOI(mgr);
    if (!doi)
    {
        fprintf (stderr, "Failed to copy secModel DOI: %s",
                 strerror (errno));
        exit (-1);
    }

    virSecurityManagerFree(mgr);

    return 0;
}
