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
    virDomainInfo info;

    printf("id %d: name %s, ", virDomainGetID(dom), virDomainGetName(dom));
    virDomainGetInfo(dom, &info);
    if (virDomainGetInfo(dom, &info) < 0) {
        printf("failed to get informations\n");
    } else {
        float mem, maxMem;

        switch (info.state) {
	    case VIR_DOMAIN_RUNNING:
	        printf("running ");
		break;
            case VIR_DOMAIN_BLOCKED:
	        printf("blocked ");
		break;
            case VIR_DOMAIN_PAUSED:
	        printf("paused ");
		break;
            case VIR_DOMAIN_SHUTDOWN:
	        printf("in shutdown ");
		break;
            case VIR_DOMAIN_SHUTOFF:
	        printf("shut off ");
		break;
	    default:
	        break;
	}
	printf("%d vCPU, ", info.nrVirtCpu);
	if (info.cpuTime != 0) {
	    float cpuUsed = info.cpuTime;

	    cpuUsed /= 1000000000;
	    printf("%.1fs time, ", cpuUsed);
	}
	mem = info.memory;
	mem /= 1024;
	maxMem = info.maxMem;
	maxMem /= 1024;
        printf("%.0f MB mem used, %.0f MB max_mem\n", mem, maxMem);
    }

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
