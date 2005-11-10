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

int errcode = 0;
xenConnectPtr conn;

int main(int argc, char **argv) {
    int ret;
    
    conn = xenOpenConnect(NULL);
    if (conn == NULL) {
        fprintf(stderr, "Failed to connect to the hypervisor\n");
        errcode = 1;
	goto done;
    }

done:
    if (conn != NULL) {
        ret = xenCloseConnect(conn);
	if (ret != 0) {
	    fprintf(stderr, "Failed to connect to the hypervisor\n");
	    if (errcode == 0)
		errcode = 1;
	}
    }
    exit(errcode);
}
