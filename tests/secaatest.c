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
    int ret;

    const char *doi, *model;
    virSecurityDriverPtr security_drv;

    ret = virSecurityDriverStartup (&security_drv, "apparmor");
    if (ret == -1)
    {
        fprintf (stderr, "Failed to start security driver");
        exit (-1);
    }
    /* No security driver wanted to be enabled: just return */
    if (ret == -2)
        return 0;

    model = virSecurityDriverGetModel (security_drv);
    if (!model)
    {
        fprintf (stderr, "Failed to copy secModel model: %s",
                 strerror (errno));
        exit (-1);
    }

    doi = virSecurityDriverGetDOI (security_drv);
    if (!doi)
    {
        fprintf (stderr, "Failed to copy secModel DOI: %s",
                 strerror (errno));
        exit (-1);
    }

    return 0;
}
