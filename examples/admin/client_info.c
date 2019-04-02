#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <libvirt/libvirt-admin.h>

static const char *
exampleTransportToString(int transport)
{
    const char *str = NULL;

    switch ((virClientTransport) transport) {
    case VIR_CLIENT_TRANS_UNIX:
        str = "unix";
        break;
    case VIR_CLIENT_TRANS_TCP:
        str = "tcp";
        break;
    case VIR_CLIENT_TRANS_TLS:
        str = "tls";
        break;
    }

    return str ? str : "unknown";
}

static char *
exampleGetTimeStr(time_t then)
{
    char *ret = NULL;
    struct tm timeinfo;
    struct tm *timeinfop;

    /* localtime_r() is smarter, but since mingw lacks it and this
     * example is single-threaded, we can get away with localtime */
    if (!(timeinfop = localtime(&then)))
        return NULL;
    timeinfo = *timeinfop;

    if (!(ret = calloc(64, sizeof(char))))
        return NULL;

    if (strftime(ret, 64, "%Y-%m-%d %H:%M:%S%z",
                 &timeinfo) == 0) {
        free(ret);
        return NULL;
    }

    return ret;
}

static char *
exampleGetTypedParamValue(virTypedParameterPtr item)
{
    int ret = 0;
    char *str = NULL;

    switch (item->type) {
    case VIR_TYPED_PARAM_INT:
        ret = asprintf(&str, "%d", item->value.i);
        break;

    case VIR_TYPED_PARAM_UINT:
        ret = asprintf(&str, "%u", item->value.ui);
        break;

    case VIR_TYPED_PARAM_LLONG:
        ret = asprintf(&str, "%" PRId64, (int64_t)item->value.l);
        break;

    case VIR_TYPED_PARAM_ULLONG:
        ret = asprintf(&str, "%" PRIu64, (uint64_t)item->value.ul);
        break;

    case VIR_TYPED_PARAM_DOUBLE:
        ret = asprintf(&str, "%f", item->value.d);
        break;

    case VIR_TYPED_PARAM_BOOLEAN:
        str = strdup(item->value.b ? "yes" : "no");
        break;

    case VIR_TYPED_PARAM_STRING:
        str = strdup(item->value.s);
        break;

    default:
        fprintf(stderr, "unimplemented parameter type %d\n", item->type);
        return NULL;
    }

    if (ret < 0) {
        fprintf(stderr, "error formatting typed param value\n");
        return NULL;
    }

    return str;
}

int main(int argc, char **argv)
{
    int ret = -1;
    virAdmConnectPtr conn = NULL;
    virAdmServerPtr srv = NULL;    /* which server is the client connected to */
    virAdmClientPtr clnt = NULL;   /* which client get identity for */
    virTypedParameterPtr params = NULL;     /* where to store identity info */
    int nparams = 0;
    ssize_t i = 0;
    char *timestr = NULL;

    if (argc != 3) {
        fprintf(stderr, "Two arguments, first specifying the server client is "
                "connected to and second, specifying the client's ID for which "
                "identity information should be retrieved, are expected\n");
        return -1;
    }

    /* first, open a connection to the daemon */
    if (!(conn = virAdmConnectOpen(NULL, 0)))
        return -1;

    /* first a virAdmServerPtr handle is necessary to obtain, that is done by
     * doing a lookup for specific server, argv[1] holds the server name
     */
    if (!(srv = virAdmConnectLookupServer(conn, argv[1], 0)))
        goto cleanup;

    /* next, virAdmClientPtr handle is necessary to obtain, that is done by
     * doing a lookup on a specific server, argv[2] holds the client's ID
     */
    if (!(clnt = virAdmServerLookupClient(srv, strtoll(argv[2], NULL, 10), 0)))
        goto cleanup;

    /* finally, retrieve @clnt's identity information */
    if (virAdmClientGetInfo(clnt, &params, &nparams, 0) < 0)
        goto cleanup;

    /* this information is provided by the client object itself, not by typed
     * params container; it is unnecessary to call virAdmClientGetInfo if only
     * ID, transport method, and timestamp are the required data
     */
    if (!(timestr = exampleGetTimeStr(virAdmClientGetTimestamp(clnt))))
        goto cleanup;

    printf("%-15s: %" PRIu64 "\n", "id", (uint64_t)virAdmClientGetID(clnt));
    printf("%-15s: %s\n", "connection_time", timestr);
    printf("%-15s: %s\n", "transport",
             exampleTransportToString(virAdmClientGetTransport(clnt)));

    /* this is the actual identity information retrieved in typed params
     * container
     */
    for (i = 0; i < nparams; i++) {
        char *str = NULL;
        if (!(str = exampleGetTypedParamValue(&params[i])))
            goto cleanup;
        printf("%-15s: %s\n", params[i].field, str);
        free(str);
    }

    ret = 0;
 cleanup:
    /* Once finished, free the typed params container, server and client
     * handles and close the connection properly, @conn will be deallocated
     * automatically
     */
    virTypedParamsFree(params, nparams);
    virAdmClientFree(clnt);
    virAdmServerFree(srv);
    virAdmConnectClose(conn);
    free(timestr);
    return ret;
}
