#include <stdio.h>
#include <stdlib.h>
#include <libvirt/libvirt.h>

int main(void) {
    int id = 0;
    virConnectPtr conn;
    virDomainPtr dom;

    conn = virConnectOpen("");
    if (conn == NULL) {
        fprintf(stderr, "First virConnectOpen() failed\n");
	exit(1);
    }
    dom = virDomainLookupByID(conn, id);
    if (dom == NULL) {
        fprintf(stderr, "First lookup for domain %d failed\n", id);
	exit(1);
    }
    virDomainFree(dom);
    virConnectClose(conn);
    conn = virConnectOpen("");
    if (conn == NULL) {
        fprintf(stderr, "Second virConnectOpen() failed\n");
	exit(1);
    }
    dom = virDomainLookupByID(conn, id);
    if (dom == NULL) {
        fprintf(stderr, "Second lookup for domain %d failed\n", id);
	exit(1);
    }
    virDomainFree(dom);
    virConnectClose(conn);
    printf("OK\n");
    exit(0);
    
}

