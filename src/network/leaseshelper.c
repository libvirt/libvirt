/*
 * leaseshelper.c: Helper program to create custom leases file
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2014 Nehal J Wani
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
 * Author: Nehal J Wani <nehaljw.kkd1@gmail.com>
 *
 * For IPv6 support, use dnsmasq >= 2.67
 */

#include <config.h>

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "virutil.h"
#include "virthread.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virbuffer.h"
#include "virstring.h"
#include "virerror.h"
#include "viralloc.h"
#include "virjson.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

/**
 * VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX:
 *
 * Macro providing the upper limit on the size of leases file
 */
#define VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX (32 * 1024 * 1024)

static const char *program_name;

/* Display version information. */
static void
helperVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

ATTRIBUTE_NORETURN static void
usage(int status)
{
    if (status) {
        fprintf(stderr, _("%s: try --help for more details\n"), program_name);
    } else {
        printf(_("Usage: %s add|old|del mac|clientid ip [hostname]\n"
                 "Designed for use with 'dnsmasq --dhcp-script'\n"
                 "Refer to man page of dnsmasq for more details'\n"),
               program_name);
    }
    exit(status);
}

static int
customLeaseRewriteFile(int fd, void *opaque)
{
    char **data = opaque;

    if (safewrite(fd, *data, strlen(*data)) < 0)
        return -1;

    return 0;
}

/* Flags denoting actions for a lease */
enum virLeaseActionFlags {
    VIR_LEASE_ACTION_ADD,       /* Create new lease */
    VIR_LEASE_ACTION_OLD,       /* Lease already exists, renew it */
    VIR_LEASE_ACTION_DEL,       /* Delete the lease */

    VIR_LEASE_ACTION_LAST
};

VIR_ENUM_DECL(virLeaseAction);

VIR_ENUM_IMPL(virLeaseAction, VIR_LEASE_ACTION_LAST,
              "add", "old", "del");

int
main(int argc, char **argv)
{
    char *exptime = NULL;
    char *pid_file = NULL;
    char *lease_entries = NULL;
    char *custom_lease_file = NULL;
    const char *ip = NULL;
    const char *mac = NULL;
    const char *iaid = virGetEnvAllowSUID("DNSMASQ_IAID");
    const char *clientid = virGetEnvAllowSUID("DNSMASQ_CLIENT_ID");
    const char *interface = virGetEnvAllowSUID("DNSMASQ_INTERFACE");
    const char *exptime_tmp = virGetEnvAllowSUID("DNSMASQ_LEASE_EXPIRES");
    const char *hostname = virGetEnvAllowSUID("DNSMASQ_SUPPLIED_HOSTNAME");
    const char *leases_str = NULL;
    long long currtime = 0;
    long long expirytime = 0;
    size_t i = 0;
    int action = -1;
    int pid_file_fd = -1;
    int rv = EXIT_FAILURE;
    int custom_lease_file_len = 0;
    bool add = false;
    bool delete = false;
    virJSONValuePtr lease_new = NULL;
    virJSONValuePtr lease_tmp = NULL;
    virJSONValuePtr leases_array = NULL;
    virJSONValuePtr leases_array_new = NULL;

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    program_name = argv[0];

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL) {
        fprintf(stderr, _("%s: initialization failed\n"), program_name);
        exit(EXIT_FAILURE);
    }

    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), program_name);
        exit(EXIT_FAILURE);
    }

    /* Doesn't hurt to check */
    if (argc > 1) {
        if (STREQ(argv[1], "--help"))
            usage(EXIT_SUCCESS);

        if (STREQ(argv[1], "--version")) {
            helperVersion(argv[0]);
            exit(EXIT_SUCCESS);
        }
    }

    if (argc != 4 && argc != 5) {
        /* Refer man page of dnsmasq --dhcp-script for more details */
        usage(EXIT_FAILURE);
    }

    /* Make sure dnsmasq knows the interface. The interface name is not known
     * when dnsmasq (re)starts and throws 'del' events for expired leases.
     * So, if any old lease has expired, it will be automatically removed the
     * next time this program is invoked */
    if (!interface)
        goto cleanup;

    ip = argv[3];
    mac = argv[2];
    action = virLeaseActionTypeFromString(argv[1]);

    /* In case hostname is known, it is the 5th argument */
    if (argc == 5)
        hostname = argv[4];

    if (VIR_STRDUP(exptime, exptime_tmp) < 0)
        goto cleanup;

    /* Removed extraneous trailing space in DNSMASQ_LEASE_EXPIRES (dnsmasq < 2.52) */
    if (exptime &&
        exptime[strlen(exptime) - 1] == ' ')
        exptime[strlen(exptime) - 1] = '\0';

    /* Check if it is an IPv6 lease */
    if (virGetEnvAllowSUID("DNSMASQ_IAID")) {
        mac = virGetEnvAllowSUID("DNSMASQ_MAC");
        clientid = argv[2];
    }

    if (virAsprintf(&custom_lease_file,
                    LOCALSTATEDIR "/lib/libvirt/dnsmasq/%s.status",
                    interface) < 0)
        goto cleanup;

    if (VIR_STRDUP(pid_file, LOCALSTATEDIR "/run/leaseshelper.pid") < 0)
        goto cleanup;

    /* Try to claim the pidfile, exiting if we can't */
    if ((pid_file_fd = virPidFileAcquirePath(pid_file, true, getpid())) < 0)
        goto cleanup;

    /* Since interfaces can be hot plugged, we need to make sure that the
     * corresponding custom lease file exists. If not, 'touch' it */
    if (virFileTouch(custom_lease_file, 0644) < 0)
        goto cleanup;

    /* Read entire contents */
    if ((custom_lease_file_len = virFileReadAll(custom_lease_file,
                                                VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX,
                                                &lease_entries)) < 0) {
        goto cleanup;
    }

    if (action == VIR_LEASE_ACTION_ADD ||
        action == VIR_LEASE_ACTION_OLD ||
        action == VIR_LEASE_ACTION_DEL) {
        /* Custom ipv6 leases *will not* be created if the env-var DNSMASQ_MAC
         * is not set. In the special case, when the $(interface).status file
         * is not already present and dnsmasq is (re)started, the corresponding
         * ipv6 custom lease will be created only when the guest sends the
         * 'old' action for its existing ipv6 interfaces.
         *
         * According to rfc3315, the combination of DUID and IAID can be used
         * to uniquely identify each ipv6 guest interface. So, in future, if
         * we introduce virNetworkGetDHCPLeaseBy(IAID|DUID|IAID+DUID) for ipv6
         * interfaces, then, the following if condition won't be required, as
         * the new lease will be created irrespective of whether the MACID is
         * known or not.
         */
        if (mac || action == VIR_LEASE_ACTION_DEL) {
            /* Delete the corresponding lease, if it already exists */
            delete = true;
            if (action == VIR_LEASE_ACTION_ADD ||
                action == VIR_LEASE_ACTION_OLD) {
                add = true;
                /* Create new lease */
                if (!(lease_new = virJSONValueNewObject())) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("failed to create json"));
                    goto cleanup;
                }

                if (virStrToLong_ll(exptime, NULL, 10, &expirytime) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to convert lease expiry time to long long: %s"),
                                   exptime);
                    goto cleanup;
                }

                if (iaid && virJSONValueObjectAppendString(lease_new, "iaid", iaid) < 0)
                    goto cleanup;
                if (ip && virJSONValueObjectAppendString(lease_new, "ip-address", ip) < 0)
                    goto cleanup;
                if (mac && virJSONValueObjectAppendString(lease_new, "mac-address", mac) < 0)
                    goto cleanup;
                if (hostname && virJSONValueObjectAppendString(lease_new, "hostname", hostname) < 0)
                    goto cleanup;
                if (clientid && virJSONValueObjectAppendString(lease_new, "client-id", clientid) < 0)
                    goto cleanup;
                if (expirytime && virJSONValueObjectAppendNumberLong(lease_new, "expiry-time", expirytime) < 0)
                    goto cleanup;
            }
        }
    } else {
        fprintf(stderr, _("Unsupported action: %s\n"),
                virLeaseActionTypeToString(action));
        exit(EXIT_FAILURE);
    }

    if (!(leases_array_new = virJSONValueNewArray())) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create json"));
        goto cleanup;
    }

    currtime = (long long) time(NULL);

    /* Check for previous leases */
    if (custom_lease_file_len) {
        if (!(leases_array = virJSONValueFromString(lease_entries))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid json in file: %s, rewriting it"),
                           custom_lease_file);
        } else {
            if (!virJSONValueIsArray(leases_array)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("couldn't fetch array of leases"));
                goto cleanup;
            }

            i = 0;
            while (i < virJSONValueArraySize(leases_array)) {
                const char *ip_tmp = NULL;
                long long expirytime_tmp = -1;

                if (!(lease_tmp = virJSONValueArrayGet(leases_array, i))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("failed to parse json"));
                    goto cleanup;
                }

                if (!(ip_tmp = virJSONValueObjectGetString(lease_tmp, "ip-address")) ||
                    (virJSONValueObjectGetNumberLong(lease_tmp, "expiry-time", &expirytime_tmp) < 0)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("failed to parse json"));
                    goto cleanup;
                }

                /* Check whether lease has expired or not */
                if (expirytime_tmp < currtime) {
                    i++;
                    continue;
                }

                /* Check whether lease has to be included or not */
                if (delete && STREQ(ip_tmp, ip)) {
                    i++;
                    continue;
                }

                /* Move old lease to new array */
                if (virJSONValueArrayAppend(leases_array_new, lease_tmp) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("failed to create json"));
                    goto cleanup;
                }

                ignore_value(virJSONValueArraySteal(leases_array, i));
            }
        }
    }

    if (add) {
        if (virJSONValueArrayAppend(leases_array_new, lease_new) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create json"));
            goto cleanup;
        }
        lease_new = NULL;
    }

    if (!(leases_str = virJSONValueToString(leases_array_new, true))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("empty json array"));
        goto cleanup;
    }

    /* Write to file */
    if (virFileRewrite(custom_lease_file, 0644,
                       customLeaseRewriteFile, &leases_str) < 0)
        goto cleanup;

    rv = EXIT_SUCCESS;

 cleanup:
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);

    VIR_FREE(pid_file);
    VIR_FREE(exptime);
    VIR_FREE(lease_entries);
    VIR_FREE(custom_lease_file);
    virJSONValueFree(lease_new);
    virJSONValueFree(leases_array);
    virJSONValueFree(leases_array_new);

    return rv;
}
