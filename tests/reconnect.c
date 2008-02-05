#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"
#include "internal.h"

static void errorHandler(void *userData ATTRIBUTE_UNUSED,
			 virErrorPtr error ATTRIBUTE_UNUSED) {
}

int main(void) {
    int id = 0;
    int ro = 0;
    virConnectPtr conn;
    virDomainPtr dom;

    virSetErrorFunc(NULL, errorHandler);

    conn = virConnectOpen(NULL);
    if (conn == NULL) {
        ro = 1;
	conn = virConnectOpenReadOnly(NULL);
    }
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
    if (ro == 1)
	conn = virConnectOpenReadOnly(NULL);
    else
	conn = virConnectOpen(NULL);
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

