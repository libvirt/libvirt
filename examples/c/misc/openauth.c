/* This is a copy of the hellolibvirt example demonstaring how to use
 * virConnectOpenAuth with a custom auth callback */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#define G_N_ELEMENTS(Array) (sizeof(Array) / sizeof(*(Array)))

static void
showError(virConnectPtr conn)
{
    int ret;
    virErrorPtr err;

    err = malloc(sizeof(*err));
    if (err == NULL) {
        printf("Could not allocate memory for error data\n");
        return;
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
}


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
    if (hvType == NULL) {
        printf("Failed to get hypervisor type\n");
        showError(conn);
        return 1;
    }

    if (virConnectGetVersion(conn, &hvVer) != 0) {
        printf("Failed to get hypervisor version\n");
        showError(conn);
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
    int ret = 0, numNames, numInactiveDomains, numActiveDomains;
    ssize_t i;
    char **nameList = NULL;

    numActiveDomains = virConnectNumOfDomains(conn);
    if (numActiveDomains == -1) {
        ret = 1;
        printf("Failed to get number of active domains\n");
        showError(conn);
        goto out;
    }

    numInactiveDomains = virConnectNumOfDefinedDomains(conn);
    if (numInactiveDomains == -1) {
        ret = 1;
        printf("Failed to get number of inactive domains\n");
        showError(conn);
        goto out;
    }

    printf("There are %d active and %d inactive domains\n",
           numActiveDomains, numInactiveDomains);

    nameList = malloc(sizeof(*nameList) * numInactiveDomains);

    if (nameList == NULL) {
        ret = 1;
        printf("Could not allocate memory for list of inactive domains\n");
        goto out;
    }

    numNames = virConnectListDefinedDomains(conn,
                                            nameList,
                                            numInactiveDomains);

    if (numNames == -1) {
        ret = 1;
        printf("Could not get list of defined domains from hypervisor\n");
        showError(conn);
        goto out;
    }

    if (numNames > 0)
        printf("Inactive domains:\n");

    for (i = 0; i < numNames; i++) {
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

/* Struct to pass the credentials to the auth callback via the cbdata pointer */
struct _AuthData {
    char *username;
    char *password;
};

typedef struct _AuthData AuthData;

/* This function will be called by libvirt to obtain credentials in order to
 * authenticate to the hypervisor */
static int
authCallback(virConnectCredentialPtr cred, unsigned int ncred, void *cbdata)
{
    size_t i;
    AuthData *authData = cbdata;

    /* libvirt might request multiple credentials in a single call.
     * This example supports VIR_CRED_AUTHNAME and VIR_CRED_PASSPHRASE
     * credentials only, but there are several other types.
     *
     * A request may also contain a prompt message that can be displayed
     * to the user and a challenge. The challenge is specific to the
     * credential type and hypervisor type.
     *
     * For example the ESX driver passes the hostname of the ESX or vCenter
     * server as challenge. This allows a auth callback to return the
     * proper credentials. */
    for (i = 0; i < ncred; ++i) {
        switch (cred[i].type) {
        case VIR_CRED_AUTHNAME:
            cred[i].result = strdup(authData->username);

            if (cred[i].result == NULL)
                return -1;

            cred[i].resultlen = strlen(cred[i].result);
            break;

        case VIR_CRED_PASSPHRASE:
            cred[i].result = strdup(authData->password);

            if (cred[i].result == NULL)
                return -1;

            cred[i].resultlen = strlen(cred[i].result);
            break;

        default:
            return -1;
        }
    }

    return 0;
}


/* The list of credential types supported by our auth callback */
static int credTypes[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE
};


/* The auth struct that will be passed to virConnectOpenAuth */
static virConnectAuth auth = {
    credTypes,
    G_N_ELEMENTS(credTypes),
    authCallback,
    NULL, /* cbdata will be initialized in main */
};


int
main(int argc, char *argv[])
{
    int ret = 0;
    virConnectPtr conn;
    char *uri;
    AuthData authData;

    if (argc != 4) {
        printf("Usage: %s <uri> <username> <password>\n", argv[0]);
        return 1;
    }

    uri = argv[1];
    authData.username = argv[2];
    authData.password = argv[3];
    auth.cbdata = &authData;

    printf("Attempting to connect to hypervisor\n");

    conn = virConnectOpenAuth(uri, &auth, 0);

    if (NULL == conn) {
        printf("No connection to hypervisor\n");
        showError(conn);
        return 1;
    }

    uri = virConnectGetURI(conn);
    if (uri == NULL) {
        ret = 1;
        printf("Failed to get URI for hypervisor connection\n");
        showError(conn);
        goto disconnect;
    }

    printf("Connected to hypervisor at \"%s\"\n", uri);
    free(uri);

    if (showHypervisorInfo(conn) != 0) {
        ret = 1;
        goto disconnect;
    }

    if (showDomains(conn) != 0) {
        ret = 1;
        goto disconnect;
    }

 disconnect:
    if (virConnectClose(conn) != 0) {
        printf("Failed to disconnect from hypervisor\n");
        showError(conn);
        ret = 1;
    } else {
        printf("Disconnected from hypervisor\n");
    }

    return ret;
}
