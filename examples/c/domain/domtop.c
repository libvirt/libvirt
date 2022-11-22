/*
 * domtop.c: Demo program showing how to calculate CPU usage
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 */

#include <errno.h>
#include <getopt.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <inttypes.h>

static bool debug;
static bool run_top;

#define ERROR(...) \
do { \
    fprintf(stderr, "ERROR %s:%d : ", __FUNCTION__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0)

#define DEBUG(...) \
do { \
    if (!debug) \
        break; \
    fprintf(stderr, "DEBUG %s:%d : ", __FUNCTION__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0)

#define STREQ(a, b) (strcmp(a, b) == 0)

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
           "    -d | --debug        enable debug messages\n"
           "    -h | --help         print this help\n"
           "    -c | --connect=URI  hypervisor connection URI\n"
           "    -D | --delay=X      delay between updates in milliseconds "
           "(default is 500ms)\n"
           "\n"
           "Print the cumulative usage of each host CPU.\n"
           "Without any domain name specified the list of\n"
           "all running domains is printed out.\n",
           unified_progname);
}

static void
parse_argv(int argc, char *argv[],
           const char **uri,
           const char **dom_name,
           unsigned int *milliseconds)
{
    int arg;
    unsigned long val;
    char *p;
    struct option opt[] = {
        { "debug", no_argument, NULL, 'd' },
        { "help", no_argument, NULL, 'h' },
        { "connect", required_argument, NULL, 'c' },
        { "delay", required_argument, NULL, 'D' },
        { NULL, 0, NULL, 0 },
    };

    while ((arg = getopt_long(argc, argv, "+:dhc:D:", opt, NULL)) != -1) {
        switch (arg) {
        case 'd':
            debug = true;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'c':
            *uri = optarg;
            break;
        case 'D':
            /* strtoul man page suggests clearing errno prior to call */
            errno = 0;
            val = strtoul(optarg, &p, 10);
            if (errno || *p || p == optarg) {
                ERROR("Invalid number: '%s'", optarg);
                exit(EXIT_FAILURE);
            }
            *milliseconds = val;
            if (*milliseconds != val) {
                ERROR("Integer overflow: %lu", val);
                exit(EXIT_FAILURE);
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
}

static int
fetch_domains(virConnectPtr conn)
{
    int num_domains, ret = -1;
    virDomainPtr *domains = NULL;
    ssize_t i;
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

static void
print_cpu_usage(size_t cpu,
                size_t ncpus,
                unsigned long long then,
                virTypedParameterPtr then_params,
                size_t then_nparams,
                unsigned long long now,
                virTypedParameterPtr now_params,
                size_t now_nparams)
{
    size_t i, j;
    size_t nparams = now_nparams;
    bool delim = false;

    if (then_nparams != now_nparams) {
        /* this should not happen (TM) */
        ERROR("parameters counts don't match");
        return;
    }

    for (i = 0; i < ncpus; i++) {
        size_t pos = 0;
        double usage;

        /* check if the vCPU is in the maps */
        if (now_params[i * nparams].type == 0 ||
            then_params[i * then_nparams].type == 0)
            continue;

        for (j = 0; j < nparams; j++) {
            pos = i * nparams + j;
            if (STREQ(then_params[pos].field, VIR_DOMAIN_CPU_STATS_CPUTIME) ||
                STREQ(then_params[pos].field, VIR_DOMAIN_CPU_STATS_VCPUTIME))
                break;
        }

        if (j == nparams) {
            ERROR("unable to find %s", VIR_DOMAIN_CPU_STATS_CPUTIME);
            return;
        }

        DEBUG("now_params=%" PRIu64 " then_params=%" PRIu64
              " now=%" PRIu64 " then=%" PRIu64,
              (uint64_t)now_params[pos].value.ul,
              (uint64_t)then_params[pos].value.ul,
              (uint64_t)now, (uint64_t)then);

        /* @now_params and @then_params are in nanoseconds, @now and @then are
         * in microseconds. In ideal world, we would translate them both into
         * the same scale, divide one by another and multiply by factor of 100
         * to get percentage. However, the count of floating point operations
         * performed has a bad effect on the precision, so instead of dividing
         * @now_params and @then_params by 1000 and then multiplying again by
         * 100, we divide only once by 10 and get the same result. */
        usage = (now_params[pos].value.ul - then_params[pos].value.ul) /
                (now - then) / 10;

        if (delim)
            printf("\t");
        /* mingw lacks %zu */
        printf("CPU%u: %.2lf", (unsigned)(cpu + i), usage);
        delim = true;
    }

    printf("\n");
}

static void
stop(int sig)
{
    DEBUG("Exiting on signal %d\n", sig);
    run_top = false;
}

static int
do_top(virConnectPtr conn,
       const char *dom_name,
       unsigned int milliseconds)
{
    int ret = -1;
    virDomainPtr dom;
    int max_id = 0;
    int nparams = 0, then_nparams = 0, now_nparams = 0;
    virTypedParameterPtr then_params = NULL, now_params = NULL;

    /* Lookup the domain */
    if (!(dom = virDomainLookupByName(conn, dom_name))) {
        ERROR("Unable to find domain '%s'", dom_name);
        goto cleanup;
    }

    /* and see how many vCPUs can we fetch stats for */
    if ((max_id = virDomainGetCPUStats(dom, NULL, 0, 0, 0, 0)) < 0) {
        ERROR("Unable to get cpu stats");
        goto cleanup;
    }

    /* how many stats can we get for a vCPU? */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, 0, 1, 0)) < 0) {
        ERROR("Unable to get cpu stats");
        goto cleanup;
    }

    if (!(now_params = calloc(nparams * max_id, sizeof(*now_params))) ||
        !(then_params = calloc(nparams * max_id, sizeof(*then_params)))) {
        ERROR("Unable to allocate memory");
        goto cleanup;
    }

    /* The ideal program would use sigaction to set this handler, but
     * this way is portable to mingw. */
    signal(SIGTERM, stop);
    signal(SIGINT, stop);

    run_top = true;
    while (run_top) {
        struct timeval then, now;

        /* Get current time */
        if (gettimeofday(&then, NULL) < 0) {
            ERROR("unable to get time");
            goto cleanup;
        }

        /* And current stats */
        if ((then_nparams = virDomainGetCPUStats(dom, then_params,
                                                 nparams, 0, max_id, 0)) < 0) {
            ERROR("Unable to get cpu stats");
            goto cleanup;
        }

        /* Now sleep some time */
        usleep(milliseconds * 1000); /* usleep expects microseconds */

        /* And get current time */
        if (gettimeofday(&now, NULL) < 0) {
            ERROR("unable to get time");
            goto cleanup;
        }

        /* And current stats */
        if ((now_nparams = virDomainGetCPUStats(dom, now_params,
                                                nparams, 0, max_id, 0)) < 0) {
            ERROR("Unable to get cpu stats");
            goto cleanup;
        }

        print_cpu_usage(0, max_id,
                        then.tv_sec * 1000000 + then.tv_usec,
                        then_params, then_nparams,
                        now.tv_sec * 1000000 + now.tv_usec,
                        now_params, now_nparams);

        virTypedParamsClear(now_params, now_nparams * max_id);
        virTypedParamsClear(then_params, then_nparams * max_id);
    }

    ret = 0;
 cleanup:
    virTypedParamsFree(now_params, nparams * max_id);
    virTypedParamsFree(then_params, nparams * max_id);
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
    unsigned int milliseconds = 500; /* Sleep this long between two API calls */
    const int connect_flags = 0; /* No connect flags for now */

    parse_argv(argc, argv, &uri, &dom_name, &milliseconds);

    DEBUG("Proceeding with uri=%s dom_name=%s milliseconds=%u",
          uri, dom_name, milliseconds);

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

    if (do_top(conn, dom_name, milliseconds) < 0)
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
