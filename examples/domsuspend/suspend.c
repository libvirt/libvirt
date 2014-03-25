/*
 * suspend.c: Demo program showing how to suspend a domain
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <errno.h>
#include <getopt.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int debug;

#define ERROR(...)                                              \
do {                                                            \
    fprintf(stderr, "ERROR %s:%d : ", __FUNCTION__, __LINE__);  \
    fprintf(stderr, __VA_ARGS__);                               \
    fprintf(stderr, "\n");                                      \
} while (0)

#define DEBUG(...)                                              \
do {                                                            \
    if (!debug)                                                 \
        break;                                                  \
    fprintf(stderr, "DEBUG %s:%d : ", __FUNCTION__, __LINE__);  \
    fprintf(stderr, __VA_ARGS__);                               \
    fprintf(stderr, "\n");                                      \
} while (0)

static void
print_usage(const char *progname)
{
    const char *unified_progname;

    if (!(unified_progname = strrchr(progname, '/')))
        unified_progname = progname;
    else
        unified_progname++;

    printf("\n%s [options] [domain name]\n\n"
           "  options:\n"
           "    -d | --debug        enable debug printings\n"
           "    -h | --help         print this help\n"
           "    -c | --connect=URI  hypervisor connection URI\n"
           "    -s | --seconds=X    suspend domain for X seconds (default 1)\n",
           unified_progname);
}

static int
parse_argv(int argc, char *argv[],
           const char **uri,
           const char **dom_name,
           unsigned int *seconds)
{
    int ret = -1;
    int arg;
    unsigned long val;
    char *p;
    struct option opt[] = {
        {"debug", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"connect", required_argument, NULL, 'c'},
        {"seconds", required_argument, NULL, 's'},
        {NULL, 0, NULL, 0}
    };

    while ((arg = getopt_long(argc, argv, "+:dhc:s:", opt, NULL)) != -1) {
        switch (arg) {
        case 'd':
            debug = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'c':
            *uri = optarg;
            break;
        case 's':
            /* strtoul man page suggest clearing errno prior to call */
            errno = 0;
            val = strtoul(optarg, &p, 10);
            if (errno || *p || p == optarg) {
                ERROR("Invalid number: '%s'", optarg);
                goto cleanup;
            }
            *seconds = val;
            if (*seconds != val) {
                ERROR("Integer overflow: %ld", val);
                goto cleanup;
            }
            break;
        case ':':
            ERROR("option '-%c' requires an argument", optopt);
            exit(EXIT_FAILURE);
        case '?':
            if (optopt)
                ERROR("unsupported option '-%c'. See --help.", optopt);
            else
                ERROR("unsupported option '%s'. See --help.", argv[optind - 1]);
            exit(EXIT_FAILURE);
        default:
            ERROR("unknown option");
            exit(EXIT_FAILURE);
        }
    }

    if (argc > optind)
        *dom_name = argv[optind];

    ret = 0;
 cleanup:
    return ret;
}

static int
fetch_domains(virConnectPtr conn)
{
    int num_domains, ret = -1;
    virDomainPtr *domains = NULL;
    size_t i;
    const int list_flags = VIR_CONNECT_LIST_DOMAINS_ACTIVE;

    DEBUG("Fetching list of running domains");
    num_domains = virConnectListAllDomains(conn, &domains, list_flags);

    DEBUG("num_domains=%d", num_domains);
    if (num_domains < 0) {
        ERROR("Unable to fetch list of running domains");
        goto cleanup;
    }

    printf("Running domains:\n");
    printf("----------------\n");
    for (i = 0; i < num_domains; i++) {
        virDomainPtr dom = domains[i];
        const char *dom_name = virDomainGetName(dom);
        printf("%s\n", dom_name);
        virDomainFree(dom);
    }

    ret = 0;
 cleanup:
    free(domains);
    return ret;
}

static int
suspend_and_resume(virConnectPtr conn,
                   const char *dom_name,
                   unsigned int seconds)
{
    int ret = -1;
    virDomainPtr dom;
    virDomainInfo dom_info;

    if (!(dom = virDomainLookupByName(conn, dom_name))) {
        ERROR("Unable to find domain '%s'", dom_name);
        goto cleanup;
    }

    if (virDomainGetInfo(dom, &dom_info) < 0) {
        ERROR("Unable to get domain info");
        goto cleanup;
    }

    DEBUG("Domain state %d", dom_info.state);

    switch (dom_info.state) {
    case VIR_DOMAIN_NOSTATE:
    case VIR_DOMAIN_RUNNING:
    case VIR_DOMAIN_BLOCKED:
        /* In these states the domain can be suspended */
        DEBUG("Suspending domain");
        if (virDomainSuspend(dom) < 0) {
            ERROR("Unable to suspend domain");
            goto cleanup;
        }

        DEBUG("Domain suspended. Entering sleep for %u seconds.", seconds);
        sleep(seconds);
        DEBUG("Sleeping done. Resuming the domain.");

        if (virDomainResume(dom) < 0) {
            ERROR("Unable to resume domain");
            goto cleanup;
        }
        break;

    default:
        /* In all other states domain can't be suspended */
        ERROR("Domain is not in a state where it can be suspended: %d",
              dom_info.state);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (dom)
        virDomainFree(dom);
    return ret;
}

int
main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    virConnectPtr conn = NULL;
    const char *uri = NULL;
    const char *dom_name = NULL;
    unsigned int seconds = 1; /* Suspend domain for this long */
    const int connect_flags = 0; /* No connect flags for now */

    if (parse_argv(argc, argv, &uri, &dom_name, &seconds) < 0)
        goto cleanup;

    DEBUG("Proceeding with uri=%s dom_name=%s seconds=%u",
          uri, dom_name, seconds);

    if (!(conn = virConnectOpenAuth(uri,
                                    virConnectAuthPtrDefault,
                                    connect_flags))) {
        ERROR("Failed to connect to hypervisor");
        goto cleanup;
    }

    DEBUG("Successfully connected");

    if (!dom_name) {
        if (fetch_domains(conn) == 0)
            ret = EXIT_SUCCESS;
        goto cleanup;
    }

    if (suspend_and_resume(conn, dom_name, seconds) < 0)
        goto cleanup;

    ret = EXIT_SUCCESS;
 cleanup:
    if (conn) {
        int tmp;
        tmp = virConnectClose(conn);
        if (tmp < 0) {
            ERROR("Failed to disconnect from the hypervisor");
            ret = EXIT_FAILURE;
        } else if (tmp > 0) {
            ERROR("One or more references were leaked after "
                  "disconnect from the hypervisor");
            ret = EXIT_FAILURE;
        } else {
            DEBUG("Connection successfully closed");
        }
    }
    return ret;
}
