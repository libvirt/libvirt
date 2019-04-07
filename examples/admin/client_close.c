#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>
#include <libvirt/libvirt-admin.h>

int main(void)
{
    int ret = -1;
    virAdmConnectPtr conn1 = NULL; /* admin connection */
    virConnectPtr conn2 = NULL;    /* libvirt standard connection */
    virAdmServerPtr srv = NULL;    /* which server is the client connected to */
    virAdmClientPtr clnt = NULL;   /* which client to disconnect */

    /* first, open a standard libvirt connection to the daemon */
    if (!(conn2 = virConnectOpen(NULL)))
        return -1;

    /* next, open an admin connection that will be used to disconnect the
     * standard libvirt client
     */
    if (!(conn1 = virAdmConnectOpen(NULL, 0)))
        goto cleanup;

    /* a virAdmServerPtr handle is needed, so a server lookup is performed */
    if (!(srv = virAdmConnectLookupServer(conn1, "libvirtd", 0)))
        goto cleanup;

    /* a virAdmClientPtr handle is also necessary, so lookup for client is
     * performed as well
     */
    if (!(clnt = virAdmServerLookupClient(srv, 1, 0)))
        goto cleanup;

    /* finally, use the client handle to disconnect the standard libvirt client
     * from libvirtd daemon
     */
    if (virAdmClientClose(clnt, 0) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    /* Once finished, both server and client handles need to be freed and
     * both connections @conn1 and @conn2 should be closed to free the
     * memory.
     * NOTE: Although @conn2 has been disconnected, unlike disconnecting by
     * calling virConnectClose which closes the connection voluntarily and
     * frees the object automatically, virAdmClientClose is a forceful
     * disconnect of another client (client can use it on itself as well).
     * Therefore no automatic deallocation of the object takes place and is
     * the callers responsibility to do so.
     */
    virAdmClientFree(clnt);
    virAdmServerFree(srv);
    virAdmConnectClose(conn1);
    virConnectClose(conn2);
    return ret;
}
