#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt-admin.h>

int main(int argc, char **argv)
{
    int ret = -1;
    virAdmConnectPtr conn = NULL;
    virAdmServerPtr srv = NULL;     /* which server to work with */
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    ssize_t i;

    if (argc != 2) {
        fprintf(stderr, "One argument specifying the server which to work "
                "with is expected\n");
        return -1;
    }

    /* first, open a connection to the daemon */
    if (!(conn = virAdmConnectOpen(NULL, 0)))
        goto cleanup;

    /* a server handle is necessary before any API regarding threadpool
     * parameters can be issued
     */
    if (!(srv = virAdmConnectLookupServer(conn, argv[1], 0)))
        goto cleanup;

    /* get the current client limits */
    if (virAdmServerGetClientLimits(srv, &params, &nparams, 0) < 0)
        goto cleanup;

    for (i = 0; i < nparams; i++)
        printf("%-15s: %d\n", params[i].field, params[i].value.ui);

    virTypedParamsFree(params, nparams);
    params = NULL;
    nparams = 0;

    /* set nclients_max to 100 and nclients_unauth_max to 20 */
    if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                              VIR_SERVER_CLIENTS_MAX, 100) < 0 ||
        virTypedParamsAddUInt(&params, &nparams, &maxparams,
                              VIR_SERVER_CLIENTS_UNAUTH_MAX, 20) < 0)
        goto cleanup;

    /* now, change the client limits on the server */
    if (virAdmServerSetClientLimits(srv, params, nparams, 0) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virTypedParamsFree(params, nparams);

    /* Once finished deallocate the server handle and close the connection
     * properly, @conn will be deallocated automatically
     */
    virAdmServerFree(srv);
    virAdmConnectClose(conn);
    return ret;
}
