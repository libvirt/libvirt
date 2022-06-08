#include <config.h>

#include <unistd.h>
#include "security/security_driver.h"
#include "testutils.h"

static int
mymain(void)
{
    virSecurityManager *mgr;
    const char *doi, *model;

    mgr = virSecurityManagerNew(NULL, "QEMU", VIR_SECURITY_MANAGER_DEFAULT_CONFINED);
    if (mgr == NULL) {
        fprintf(stderr, "Failed to start security driver");
        return EXIT_FAILURE;
    }

    model = virSecurityManagerGetModel(mgr);
    if (!model) {
        fprintf(stderr, "Failed to copy secModel model: %s",
                g_strerror(errno));
        return EXIT_FAILURE;
    }

    doi = virSecurityManagerGetDOI(mgr);
    if (!doi) {
        fprintf(stderr, "Failed to copy secModel DOI: %s",
                g_strerror(errno));
        return EXIT_FAILURE;
    }

    virObjectUnref(mgr);

    return EXIT_SUCCESS;
}

VIR_TEST_MAIN(mymain)
