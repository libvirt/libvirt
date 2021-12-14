/* This file contains trivial example code to connect to the running
 * hypervisor and gather a few bits of information about domains.
 * Similar API's exist for storage pools, networks, and interfaces. */

#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

static int
showHypervisorInfo(virConnectPtr conn)
{
    unsigned long hvVer, major, minor, release;
    const char *hvType;

    /* virConnectGetType returns a pointer to a static string, so no
     * allocation or freeing is necessary; it is possible for the call
     * to fail if, for example, there is no connection to a
     * hypervisor, so check what it returns. */
    hvType = virConnectGetType(conn);
    if (!hvType) {
        printf("Failed to get hypervisor type: %s\n",
               virGetLastErrorMessage());
        return 1;
    }

    if (0 != virConnectGetVersion(conn, &hvVer)) {
        printf("Failed to get hypervisor version: %s\n",
               virGetLastErrorMessage());
        return 1;
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

    return 0;
}


static int
showDomains(virConnectPtr conn)
{
    int numNames, numInactiveDomains, numActiveDomains;
    ssize_t i;
    int flags = VIR_CONNECT_LIST_DOMAINS_ACTIVE |
                VIR_CONNECT_LIST_DOMAINS_INACTIVE;
    virDomainPtr *nameList = NULL;

    /* NB: The return from the virConnectNum*() APIs is only useful for
     * the current call.  A domain could be started or stopped and any
     * assumptions made purely on these return values could result in
     * unexpected results */
    numActiveDomains = virConnectNumOfDomains(conn);
    if (numActiveDomains == -1) {
        printf("Failed to get number of active domains: %s\n",
               virGetLastErrorMessage());
        return 1;
    }

    numInactiveDomains = virConnectNumOfDefinedDomains(conn);
    if (numInactiveDomains == -1) {
        printf("Failed to get number of inactive domains: %s\n",
               virGetLastErrorMessage());
        return 1;
    }

    printf("There are %d active and %d inactive domains\n",
           numActiveDomains, numInactiveDomains);

    /* Return a list of all active and inactive domains. Using this API
     * instead of virConnectListDomains() and virConnectListDefinedDomains()
     * is preferred since it "solves" an inherit race between separated API
     * calls if domains are started or stopped between calls */
    numNames = virConnectListAllDomains(conn,
                                        &nameList,
                                        flags);
    if (numNames == -1) {
        printf("Failed to get a list of all domains: %s\n",
               virGetLastErrorMessage());
        return 1;
    }

    for (i = 0; i < numNames; i++) {
        int active = virDomainIsActive(nameList[i]);
        printf("  %8s (%s)\n",
               virDomainGetName(nameList[i]),
               (active == 1 ? "active" : "non-active"));
        /* must free the returned named per the API documentation */
        virDomainFree(nameList[i]);
    }
    free(nameList);

    return 0;
}


int
main(int argc, char *argv[])
{
    int ret = 0;
    virConnectPtr conn;
    char *uri = NULL;

    printf("Attempting to connect to hypervisor\n");

    if (argc > 1)
        uri = argv[1];

    /* virConnectOpenAuth is called here with all default parameters,
     * except, possibly, the URI of the hypervisor. */
    conn = virConnectOpenAuth(uri, virConnectAuthPtrDefault, 0);

    if (!conn) {
        printf("No connection to hypervisor: %s\n",
               virGetLastErrorMessage());
        return 1;
    }

    uri = virConnectGetURI(conn);
    if (!uri) {
        ret = 1;
        printf("Failed to get URI for hypervisor connection: %s\n",
               virGetLastErrorMessage());
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
        printf("Failed to disconnect from hypervisor: %s\n",
               virGetLastErrorMessage());
        ret = 1;
    } else {
        printf("Disconnected from hypervisor\n");
    }

    return ret;
}
