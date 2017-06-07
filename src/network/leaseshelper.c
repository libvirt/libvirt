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

#include <stdio.h>
#include <stdlib.h>

#include "virthread.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virstring.h"
#include "virerror.h"
#include "viralloc.h"
#include "virjson.h"
#include "virlease.h"
#include "configmake.h"
#include "virgettext.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

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
        printf(_("Usage: %s add|old|del|init mac|clientid ip [hostname]\n"
                 "Designed for use with 'dnsmasq --dhcp-script'\n"
                 "Refer to man page of dnsmasq for more details'\n"),
               program_name);
    }
    exit(status);
}

/* Flags denoting actions for a lease */
enum virLeaseActionFlags {
    VIR_LEASE_ACTION_ADD,       /* Create new lease */
    VIR_LEASE_ACTION_OLD,       /* Lease already exists, renew it */
    VIR_LEASE_ACTION_DEL,       /* Delete the lease */
    VIR_LEASE_ACTION_INIT,      /* Tell dnsmasq of existing leases on restart */

    VIR_LEASE_ACTION_LAST
};

VIR_ENUM_DECL(virLeaseAction);

VIR_ENUM_IMPL(virLeaseAction, VIR_LEASE_ACTION_LAST,
              "add", "old", "del", "init");

int
main(int argc, char **argv)
{
    char *pid_file = NULL;
    char *custom_lease_file = NULL;
    const char *ip = NULL;
    const char *mac = NULL;
    const char *leases_str = NULL;
    const char *iaid = virGetEnvAllowSUID("DNSMASQ_IAID");
    const char *clientid = virGetEnvAllowSUID("DNSMASQ_CLIENT_ID");
    const char *interface = virGetEnvAllowSUID("DNSMASQ_INTERFACE");
    const char *hostname = virGetEnvAllowSUID("DNSMASQ_SUPPLIED_HOSTNAME");
    char *server_duid = NULL;
    int action = -1;
    int pid_file_fd = -1;
    int rv = EXIT_FAILURE;
    bool delete = false;
    virJSONValuePtr lease_new = NULL;
    virJSONValuePtr leases_array_new = NULL;

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    program_name = argv[0];

    if (virGettextInitialize() < 0 ||
        virThreadInitialize() < 0 ||
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

    if (argc != 4 && argc != 5 && argc != 2) {
        /* Refer man page of dnsmasq --dhcp-script for more details */
        usage(EXIT_FAILURE);
    }

    /* Make sure dnsmasq knows the interface. The interface name is not known
     * via env variable set by dnsmasq when dnsmasq (re)starts and throws 'del'
     * events for expired leases. So, libvirtd sets another env var for this
     * purpose */
    if (!interface &&
        !(interface = virGetEnvAllowSUID("VIR_BRIDGE_NAME")))
        goto cleanup;

    ip = argv[3];
    mac = argv[2];

    if ((action = virLeaseActionTypeFromString(argv[1])) < 0) {
        fprintf(stderr, _("Unsupported action: %s\n"), argv[1]);
        exit(EXIT_FAILURE);
    }

    /* In case hostname is known, it is the 5th argument */
    if (argc == 5)
        hostname = argv[4];

    /* Check if it is an IPv6 lease */
    if (iaid) {
        mac = virGetEnvAllowSUID("DNSMASQ_MAC");
        clientid = argv[2];
    }

    if (VIR_STRDUP(server_duid, virGetEnvAllowSUID("DNSMASQ_SERVER_DUID")) < 0)
        goto cleanup;

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

    switch ((enum virLeaseActionFlags) action) {
    case VIR_LEASE_ACTION_ADD:
    case VIR_LEASE_ACTION_OLD:
        /* Create new lease */
        if (virLeaseNew(&lease_new, mac, clientid, ip, hostname, iaid, server_duid) < 0)
            goto cleanup;
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
        if (!lease_new)
            break;

        ATTRIBUTE_FALLTHROUGH;
    case VIR_LEASE_ACTION_DEL:
        /* Delete the corresponding lease, if it already exists */
        delete = true;
        break;

    case VIR_LEASE_ACTION_INIT:
    case VIR_LEASE_ACTION_LAST:
        break;
    }

    if (!(leases_array_new = virJSONValueNewArray())) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create json"));
        goto cleanup;
    }

    if (virLeaseReadCustomLeaseFile(leases_array_new, custom_lease_file,
                                    delete ? ip : NULL, &server_duid) < 0)
        goto cleanup;

    switch ((enum virLeaseActionFlags) action) {
    case VIR_LEASE_ACTION_INIT:
        if (virLeasePrintLeases(leases_array_new, server_duid) < 0)
            goto cleanup;

        break;

    case VIR_LEASE_ACTION_OLD:
    case VIR_LEASE_ACTION_ADD:
        if (lease_new && virJSONValueArrayAppend(leases_array_new, lease_new) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create json"));
            goto cleanup;
        }
        lease_new = NULL;

        ATTRIBUTE_FALLTHROUGH;
    case VIR_LEASE_ACTION_DEL:
        if (!(leases_str = virJSONValueToString(leases_array_new, true))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("empty json array"));
            goto cleanup;
        }

        /* Write to file */
        if (virFileRewriteStr(custom_lease_file, 0644, leases_str) < 0)
            goto cleanup;
        break;

    case VIR_LEASE_ACTION_LAST:
        break;
    }

    rv = EXIT_SUCCESS;

 cleanup:
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);

    VIR_FREE(pid_file);
    VIR_FREE(server_duid);
    VIR_FREE(custom_lease_file);
    virJSONValueFree(lease_new);
    virJSONValueFree(leases_array_new);

    return rv;
}
