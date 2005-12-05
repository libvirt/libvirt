/*
 * virsh.c: a Xen shell used to exercise the libvir API
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvir.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#define MAX_DOM 100
int errcode = 0;
virConnectPtr conn;
virDomainPtr dom0;
int ids[MAX_DOM];

static void printDomain(virDomainPtr dom) {
    printf("id %d: name %s\n", virDomainGetID(dom), virDomainGetName(dom));
}

int main(int argc, char **argv) {
    int ret, i;
    virDomainPtr dom;
    
    if (getuid() == 0) {
	conn = virConnectOpen(NULL);
    } else {
	conn = virConnectOpenReadOnly(NULL);
    }
    if (conn == NULL) {
        fprintf(stderr, "Failed to connect to the hypervisor\n");
        errcode = 1;
	goto done;
    }
    dom0 = virDomainLookupByID(conn, 0);
    if (dom0 == NULL) {
        fprintf(stderr, "Failed to get domain 0 informations\n");
	errcode = 2;
	goto done;
    }

    printf("Dom0: ");
    printDomain(dom0);

    ret = virConnectListDomains(conn, &ids[0], MAX_DOM);
    if (ret < 0) {
        fprintf(stderr, "Failed to list active domains\n");
	errcode = 3;
	goto done;
    }
    printf("Found %d more active domains\n", ret - 1);
    for (i = 0;i < ret;i++) {
        if (ids[i] == 0)
	    continue;
        printf("  ");
	dom = virDomainLookupByID(conn, ids[i]);
	if (dom == NULL) {
	    printf("domain %d disapeared\n", ids[i]);
	} else {
	    printDomain(dom);
	}
    }
    
done:
    if (conn != NULL) {
        ret = virConnectClose(conn);
	if (ret != 0) {
	    fprintf(stderr, "Failed to connect to the hypervisor\n");
	    if (errcode == 0)
		errcode = 1;
	}
    }
    return(errcode);
}
