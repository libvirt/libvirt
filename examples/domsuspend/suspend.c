/**
 * section: Scheduling
 * synopsis: Suspend a domain and then resume its execution
 * purpose: Demonstrate the basic use of the library to suspend and
 *          resume a domain. If no id is given on the command line
 *          this script will suspend and resume the first domain found
 *          which is not Domain 0.
 * usage: suspend [id]
 * test: suspend
 * author: Daniel Veillard
 * copy: see Copyright for the status of this software.
 */

#include <stdlib.h>
#include <stdio.h>
#include <libvirt/libvirt.h>

static virConnectPtr conn = NULL; /* the hypervisor connection */

/**
 * checkDomainState:
 * @dom: the domain
 *
 * Return the current state of a domain or -1 if non-exsitant
 */
static int
checkDomainState(virDomainPtr dom) {
    virDomainInfo info;        /* the information being fetched */
    int ret;

    ret = virDomainGetInfo(dom, &info);
    if (ret < 0) {
        return -1;
    }
    return info.state;
}

/**
 * SuspendAndResumeDomain:
 * @id: the id of the domain
 *
 * extract the domain 0 information
 */
static void
SuspendAndResumeDomain(int id) {
    virDomainPtr dom = NULL;   /* the domain being checked */
    int ret, state;

    /* Find the domain of the given id */
    dom = virDomainLookupByID(conn, id);
    if (dom == NULL) {
        fprintf(stderr, "Failed to find Domain %d\n", id);
        goto error;
    }

    /* Check state */
    state = checkDomainState(dom);
    if ((state == VIR_DOMAIN_RUNNING) ||
        (state == VIR_DOMAIN_NOSTATE) ||
        (state == VIR_DOMAIN_BLOCKED)) {
        printf("Suspending domain...\n");
        ret = virDomainSuspend(dom);
        if (ret < 0) {
            fprintf(stderr, "Failed to suspend Domain %d\n", id);
            goto error;
        }
        state = checkDomainState(dom);
        if (state != VIR_DOMAIN_PAUSED) {
            fprintf(stderr, "Domain %d state is not suspended\n", id);
        } else {
            printf("Domain suspended, resuming it...\n");
        }
        ret = virDomainResume(dom);
        if (ret < 0) {
            fprintf(stderr, "Failed to resume Domain %d\n", id);
            goto error;
        }
        state = checkDomainState(dom);
        if ((state == VIR_DOMAIN_RUNNING) ||
            (state == VIR_DOMAIN_NOSTATE) ||
            (state == VIR_DOMAIN_BLOCKED)) {
            printf("Domain resumed\n");
        } else {
            fprintf(stderr, "Domain %d state indicate it is not resumed\n", id);
        }
    } else {
        fprintf(stderr, "Domain %d is not in a state where it should be suspended\n", id);
        goto error;
    }

error:
    if (dom != NULL)
        virDomainFree(dom);
}

int main(int argc, char **argv) {
    int id = 0;

    /* NULL means connect to local Xen hypervisor */
    conn = virConnectOpenReadOnly(NULL);
    if (conn == NULL) {
        fprintf(stderr, "Failed to connect to hypervisor\n");
        goto error;
    }

    if (argc > 1) {
        id = atoi(argv[1]);
    }
    if (id == 0) {
        int i, j, ids[10];
        i = virConnectListDomains(conn, &ids[0], 10);
        if (i < 0) {
            fprintf(stderr, "Failed to list the domains\n");
            goto error;
        }
        for (j = 0;j < i;j++) {
            if (ids[j] != 0) {
                id = ids[j];
                break;
            }
        }
    }
    if (id == 0) {
        fprintf(stderr, "Failed find a running guest domain\n");
        goto error;
    }

    SuspendAndResumeDomain(id);

error:
    if (conn != NULL)
        virConnectClose(conn);
    return 0;
}
