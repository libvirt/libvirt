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
 * For IPv6 support, use dnsmasq >= 2.67
 */

#include <config.h>


#include "virfile.h"
#include "virpidfile.h"
#include "virerror.h"
#include "virjson.h"
#include "virlease.h"
#include "virenum.h"
#include "configmake.h"
#include "virgettext.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

static const char *program_name;

/* Display version information. */
static void
helperVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

G_GNUC_NORETURN static void
usage(int status)
{
    if (status) {
        fprintf(stderr, _("%1$s: try --help for more details\n"), program_name);
    } else {
        printf(_("Usage: %1$s add|old|del|init mac|clientid ip [hostname]\n"
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

VIR_ENUM_IMPL(virLeaseAction,
              VIR_LEASE_ACTION_LAST,
              "add", "old", "del", "init",
);

int
main(int argc, char **argv)
{
    g_autofree char *pid_file = NULL;
    g_autofree char *custom_lease_file = NULL;
    const char *ip = NULL;
    const char *mac = NULL;
    const char *leases_str = NULL;
    const char *iaid = getenv("DNSMASQ_IAID");
    const char *clientid = getenv("DNSMASQ_CLIENT_ID");
    const char *interface = getenv("DNSMASQ_INTERFACE");
    const char *hostname = getenv("DNSMASQ_SUPPLIED_HOSTNAME");
    g_autofree char *server_duid = NULL;
    int action = -1;
    int pid_file_fd = -1;
    int rv = EXIT_FAILURE;
    bool delete = false;
    g_autoptr(virJSONValue) lease_new = NULL;
    g_autoptr(virJSONValue) leases_array_new = NULL;

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    program_name = argv[0];

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), program_name);
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
        !(interface = getenv("VIR_BRIDGE_NAME"))) {
        fprintf(stderr, _("interface not set\n"));
        exit(EXIT_FAILURE);
    }

    ip = argv[3];
    mac = argv[2];

    if ((action = virLeaseActionTypeFromString(argv[1])) < 0) {
        fprintf(stderr, _("Unsupported action: %1$s\n"), argv[1]);
        exit(EXIT_FAILURE);
    }

    /* In case hostname is known, it is the 5th argument */
    if (argc == 5)
        hostname = argv[4];

    /* Check if it is an IPv6 lease */
    if (iaid) {
        mac = getenv("DNSMASQ_MAC");
        clientid = argv[2];
    }

    server_duid = g_strdup(getenv("DNSMASQ_SERVER_DUID"));

    custom_lease_file = g_strdup_printf(LOCALSTATEDIR "/lib/libvirt/dnsmasq/%s.status",
                                        interface);

    pid_file = g_strdup(RUNSTATEDIR "/leaseshelper.pid");

    /* Try to claim the pidfile, exiting if we can't */
    if ((pid_file_fd = virPidFileAcquirePathFull(pid_file, true, false, getpid())) < 0) {
        fprintf(stderr,
                _("Unable to acquire PID file: %1$s\n errno=%2$d"),
                pid_file, errno);
        goto cleanup;
    }

    /* Since interfaces can be hot plugged, we need to make sure that the
     * corresponding custom lease file exists. If not, 'touch' it */
    if (virFileTouch(custom_lease_file, 0644) < 0) {
        fprintf(stderr,
                _("Unable to create: %1$s\n errno=%2$d"),
                custom_lease_file, errno);
        goto cleanup;
    }

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

        G_GNUC_FALLTHROUGH;
    case VIR_LEASE_ACTION_DEL:
        /* Delete the corresponding lease, if it already exists */
        delete = true;
        break;

    case VIR_LEASE_ACTION_INIT:
    case VIR_LEASE_ACTION_LAST:
        break;
    }

    leases_array_new = virJSONValueNewArray();

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
        if (lease_new && virJSONValueArrayAppend(leases_array_new, &lease_new) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create json"));
            goto cleanup;
        }

        G_GNUC_FALLTHROUGH;
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
    if (rv != EXIT_SUCCESS)
        virDispatchError(NULL);
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);

    return rv;
}
