#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>

#include "internal.h"
#include "testutils.h"
#include "vircommand.h"

static int
mymain(void)
{
    int id = 0;
    bool ro = false;
    virConnectPtr conn;
    virDomainPtr dom;
    virCommandPtr cmd;
    struct utsname ut;

    /* Skip test if xend is not running.  Calling xend on a non-xen
       kernel causes some versions of xend to issue a crash report, so
       we first probe uname results.  */
    uname(&ut);
    if (strstr(ut.release, "xen") == NULL)
        return EXIT_AM_SKIP;
    cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
    if (virCommandRun(cmd, NULL) < 0) {
        virCommandFree(cmd);
        return EXIT_AM_SKIP;
    }
    virCommandFree(cmd);

    virtTestQuiesceLibvirtErrors(true);

    conn = virConnectOpen(NULL);
    if (conn == NULL) {
        ro = true;
        conn = virConnectOpenReadOnly(NULL);
    }
    if (conn == NULL) {
        fprintf(stderr, "First virConnectOpen() failed\n");
        return EXIT_FAILURE;
    }
    dom = virDomainLookupByID(conn, id);
    if (dom == NULL) {
        fprintf(stderr, "First lookup for domain %d failed\n", id);
        return EXIT_FAILURE;
    }
    virDomainFree(dom);
    virConnectClose(conn);
    if (ro)
        conn = virConnectOpenReadOnly(NULL);
    else
        conn = virConnectOpen(NULL);
    if (conn == NULL) {
        fprintf(stderr, "Second virConnectOpen() failed\n");
        return EXIT_FAILURE;
    }
    dom = virDomainLookupByID(conn, id);
    if (dom == NULL) {
        fprintf(stderr, "Second lookup for domain %d failed\n", id);
        return EXIT_FAILURE;
    }
    virDomainFree(dom);
    virConnectClose(conn);

    return EXIT_SUCCESS;
}

VIRT_TEST_MAIN(mymain)
