#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

int main(int argc, char **argv)
{
    int ret = -1;
    virAdmConnectPtr conn = NULL;
    virAdmServerPtr srv = NULL;      /* which server to list the clients from */
    virAdmClientPtr *clients = NULL;    /* where to store the servers */
    ssize_t i = 0;
    int count = 0;

    if (argc != 2) {
        fprintf(stderr, "One argument specifying the server to list connected "
                "clients for is expected\n");
        return -1;
    }

    /* first, open a connection to the daemon */
    if (!(conn = virAdmConnectOpen(NULL, 0)))
        return -1;

    /* first a virAdmServerPtr handle is necessary to obtain, that is done by
     * doing a lookup for specific server, let's get a handle on "libvirtd"
     * server
     */
    if (!(srv = virAdmConnectLookupServer(conn, argv[1], 0)))
        goto cleanup;

    /* now get the currently connected clients to server @srv */
    if ((count = virAdmServerListClients(srv, &clients, 0)) < 0)
        goto cleanup;

    /* let's print the currently connected clients and some basic info about
     * them, we have 2 options how to iterate over the returned list,
     * use @count as the boundary or use the fact that @clients are guaranteed
     * to contain 1 extra element NULL;
     * this example uses the first option
     */
    printf(" %-5s %-15s %-15s\n%s\n", "Id", "Transport", "Connected since",
           "--------------------------------------------------");

    for (i = 0; i < count; i++) {
        virAdmClientPtr client = clients[i];
        unsigned long long id = virAdmClientGetID(client);
        int transport = virAdmClientGetTransport(client);
        char * timestr = NULL;
        if (!(timestr =
                exampleGetTimeStr(virAdmClientGetTimestamp(client))))
            goto cleanup;

        printf(" %-5" PRIu64 " %-15s %-15s\n", (uint64_t)id,
               exampleTransportToString(transport), timestr);
        free(timestr);
    }

    ret = 0;
 cleanup:
    /* Once finished, free the list of clients, free the server handle and
     * close the connection properly, @conn will be deallocated automatically
     */
    for (i = 0; i < count; i++)
        virAdmClientFree(clients[i]);
    free(clients);
    virAdmServerFree(srv);
    virAdmConnectClose(conn);
    return ret;
}
