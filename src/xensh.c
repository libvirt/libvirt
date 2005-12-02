/*
 * xensh.c: a Xen shell used to exercise the libxen API
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libxen.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#define MAX_DOM 100
int errcode = 0;
xenConnectPtr conn;
xenDomainPtr dom0;
int ids[MAX_DOM];

static void printDomain(xenDomainPtr dom) {
    printf("id %d: name %s\n", xenDomainGetID(dom), xenDomainGetName(dom));
}

int main(int argc, char **argv) {
    int ret, i;
    xenDomainPtr dom;
    
    if (getuid() == 0) {
	conn = xenConnectOpen(NULL);
    } else {
	conn = xenConnectOpenReadOnly(NULL);
    }
    if (conn == NULL) {
        fprintf(stderr, "Failed to connect to the hypervisor\n");
        errcode = 1;
	goto done;
    }
    dom0 = xenDomainLookupByID(conn, 0);
    if (dom0 == NULL) {
        fprintf(stderr, "Failed to get domain 0 informations\n");
	errcode = 2;
	goto done;
    }

    printf("Dom0: ");
    printDomain(dom0);

    ret = xenConnectListDomains(conn, &ids[0], MAX_DOM);
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
	dom = xenDomainLookupByID(conn, ids[i]);
	if (dom == NULL) {
	    printf("domain %d disapeared\n", ids[i]);
	} else {
	    printDomain(dom);
	}
    }
    
done:
    if (conn != NULL) {
        ret = xenConnectClose(conn);
	if (ret != 0) {
	    fprintf(stderr, "Failed to connect to the hypervisor\n");
	    if (errcode == 0)
		errcode = 1;
	}
    }
    return(errcode);
}
