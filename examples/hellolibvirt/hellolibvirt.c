/* This file contains trivial example code to connect to the running
 * hypervisor and gather a few bits of information.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

static void
showError(virConnectPtr conn)
{
    int ret;
    virErrorPtr err;

    err = malloc(sizeof(*err));
    if (NULL == err) {
        printf("Could not allocate memory for error data\n");
        goto out;
    }

    ret = virConnCopyLastError(conn, err);

    switch (ret) {
    case 0:
        printf("No error found\n");
        break;

    case -1:
        printf("Parameter error when attempting to get last error\n");
        break;

    default:
        printf("libvirt reported: \"%s\"\n", err->message);
        break;
    }

    virResetError(err);
    free(err);

out:
    return;
}


static int
showHypervisorInfo(virConnectPtr conn)
{
    int ret = 0;
    unsigned long hvVer, major, minor, release;
    const char *hvType;

    /* virConnectGetType returns a pointer to a static string, so no
     * allocation or freeing is necessary; it is possible for the call
     * to fail if, for example, there is no connection to a
     * hypervisor, so check what it returns. */
    hvType = virConnectGetType(conn);
    if (NULL == hvType) {
        ret = 1;
        printf("Failed to get hypervisor type\n");
        showError(conn);
        goto out;
    }

    if (0 != virConnectGetVersion(conn, &hvVer)) {
        ret = 1;
        printf("Failed to get hypervisor version\n");
        showError(conn);
        goto out;
    }

    major = hvVer / 1000000;
    hvVer %= 1000000;
    minor = hvVer / 1000;
    release = hvVer % 1000;

    printf("Hypervisor: \"%s\" version: %lu.%lu.%lu\n",
           hvType,
           major,
           minor,
           release);

out:
    return ret;
}


static int
showDomains(virConnectPtr conn)
{
    int ret = 0, i, numNames, numInactiveDomains, numActiveDomains;
    char **nameList = NULL;

    numActiveDomains = virConnectNumOfDomains(conn);
    if (-1 == numActiveDomains) {
        ret = 1;
        printf("Failed to get number of active domains\n");
        showError(conn);
        goto out;
    }

    numInactiveDomains = virConnectNumOfDefinedDomains(conn);
    if (-1 == numInactiveDomains) {
        ret = 1;
        printf("Failed to get number of inactive domains\n");
        showError(conn);
        goto out;
    }

    printf("There are %d active and %d inactive domains\n",
           numActiveDomains, numInactiveDomains);

    nameList = malloc(sizeof(*nameList) * numInactiveDomains);

    if (NULL == nameList) {
        ret = 1;
        printf("Could not allocate memory for list of inactive domains\n");
        goto out;
    }

    numNames = virConnectListDefinedDomains(conn,
                                            nameList,
                                            numInactiveDomains);

    if (-1 == numNames) {
        ret = 1;
        printf("Could not get list of defined domains from hypervisor\n");
        showError(conn);
        goto out;
    }

    if (numNames > 0) {
        printf("Inactive domains:\n");
    }

    for (i = 0 ; i < numNames ; i++) {
        printf("  %s\n", *(nameList + i));
        /* The API documentation doesn't say so, but the names
         * returned by virConnectListDefinedDomains are strdup'd and
         * must be freed here.  */
        free(*(nameList + i));
    }

out:
    free(nameList);
    return ret;
}


int
main(int argc, char *argv[])
{
    int ret = 0;
    virConnectPtr conn;
    char *uri;

    printf("Attempting to connect to hypervisor\n");

    uri = (argc > 0 ? argv[1] : NULL);

    /* virConnectOpenAuth is called here with all default parameters,
     * except, possibly, the URI of the hypervisor. */
    conn = virConnectOpenAuth(uri, virConnectAuthPtrDefault, 0);

    if (NULL == conn) {
        ret = 1;
        printf("No connection to hypervisor\n");
        showError(conn);
        goto out;
    }

    uri = virConnectGetURI(conn);
    if (NULL == uri) {
        ret = 1;
        printf("Failed to get URI for hypervisor connection\n");
        showError(conn);
        goto disconnect;
    }

    printf("Connected to hypervisor at \"%s\"\n", uri);
    free(uri);

    if (0 != showHypervisorInfo(conn)) {
        ret = 1;
        goto disconnect;
    }

    if (0 != showDomains(conn)) {
        ret = 1;
        goto disconnect;
    }

disconnect:
    if (0 != virConnectClose(conn)) {
        printf("Failed to disconnect from hypervisor\n");
        showError(conn);
        ret = 1;
    } else {
        printf("Disconnected from hypervisor\n");
    }

out:
    return ret;
}
