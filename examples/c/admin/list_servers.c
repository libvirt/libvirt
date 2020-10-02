#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt-admin.h>

int main(void)
{
    int ret = -1;
    virAdmConnectPtr conn = NULL;
    virAdmServerPtr *servers = NULL;    /* where to store the servers */
    virAdmServerPtr *tmp = NULL;
    ssize_t i = 0;
    int count = 0;

    /* first, open a connection to the daemon */
    if (!(conn = virAdmConnectOpen(NULL, 0)))
        goto cleanup;

    /* get the available servers on the default daemon - libvirtd */
    if ((count = virAdmConnectListServers(conn, &servers, 0)) < 0)
        goto cleanup;

    /* let's print the available servers, we have 2 options how to iterate
     * over the returned list, use @count as the boundary or use the fact
     * that @servers are guaranteed to contain 1 extra element NULL;
     * this example uses the second option
     */
    printf(" %-15s\n", "Server name");
    printf("---------------\n");
    for (tmp = servers; *tmp; tmp++)
        printf(" %-15s\n", virAdmServerGetName(*tmp));

    ret = 0;
 cleanup:
    /* Once finished, free the list of servers and close the connection
     * properly, @conn will be deallocated automatically
     */
    for (i = 0; i < count; i++)
        virAdmServerFree(servers[i]);
    free(servers);
    virAdmConnectClose(conn);
    return ret;
}
