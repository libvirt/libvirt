#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

#include "configmake.h"
#include "internal.h"
#include "virconf.h"
#include "viralloc.h"
#include "domain_conf.h"


static int
getArgs(int argc,
        char **argv,
        const char **uri,
        const char **uuid,
        virDomainLockFailureAction *action)
{
    int act;

    if (argc != 4) {
        fprintf(stderr, _("%s uri uuid action\n"), argv[0]);
        return -1;
    }

    *uri = argv[1];
    *uuid = argv[2];

    act = virDomainLockFailureTypeFromString(argv[3]);
    if (act < 0) {
        fprintf(stderr, _("invalid failure action: '%s'\n"), argv[3]);
        return -1;
    }
    *action = act;

    return 0;
}


static int
authCallback(virConnectCredentialPtr cred ATTRIBUTE_UNUSED,
             unsigned int ncred ATTRIBUTE_UNUSED,
             void *cbdata ATTRIBUTE_UNUSED)
{
    return -1;
}


int
main(int argc, char **argv)
{
    const char *uri;
    const char *uuid;
    virDomainLockFailureAction action;
    char *xml = NULL;
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    int ret = EXIT_FAILURE;

    int authTypes[] = {
        VIR_CRED_AUTHNAME,
        VIR_CRED_ECHOPROMPT,
        VIR_CRED_PASSPHRASE,
        VIR_CRED_NOECHOPROMPT,
    };
    virConnectAuth auth = {
        .credtype = authTypes,
        .ncredtype = ARRAY_CARDINALITY(authTypes),
        .cb = authCallback,
    };

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    if (getArgs(argc, argv, &uri, &uuid, &action) < 0)
        goto cleanup;

    if (!(conn = virConnectOpenAuth(uri, &auth, 0)) ||
        !(dom = virDomainLookupByUUIDString(conn, uuid)))
        goto cleanup;

    switch (action) {
    case VIR_DOMAIN_LOCK_FAILURE_POWEROFF:
        if (virDomainDestroy(dom) == 0 ||
            virDomainIsActive(dom) == 0)
            ret = EXIT_SUCCESS;
        break;

    case VIR_DOMAIN_LOCK_FAILURE_PAUSE:
        if (virDomainSuspend(dom) == 0)
            ret = EXIT_SUCCESS;
        break;

    case VIR_DOMAIN_LOCK_FAILURE_DEFAULT:
    case VIR_DOMAIN_LOCK_FAILURE_RESTART:
    case VIR_DOMAIN_LOCK_FAILURE_IGNORE:
    case VIR_DOMAIN_LOCK_FAILURE_LAST:
        fprintf(stderr, _("unsupported failure action: '%s'\n"),
                virDomainLockFailureTypeToString(action));
        break;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);
    VIR_FREE(xml);

    return ret;
}
