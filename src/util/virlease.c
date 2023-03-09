/*
 * virlease.c: Leases file handling
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
 */

#include <config.h>

#include "virlease.h"

#include <time.h>

#include "virfile.h"
#include "virstring.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

/**
 * VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX:
 *
 * Macro providing the upper limit on the size of leases file
 */
#define VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX (32 * 1024 * 1024)


int
virLeaseReadCustomLeaseFile(virJSONValue *leases_array_new,
                            const char *custom_lease_file,
                            const char *ip_to_delete,
                            char **server_duid)
{
    g_autofree char *lease_entries = NULL;
    g_autoptr(virJSONValue) leases_array = NULL;
    int custom_lease_file_len = 0;
    size_t i;

    /* Read entire contents */
    if ((custom_lease_file_len = virFileReadAll(custom_lease_file,
                                                VIR_NETWORK_DHCP_LEASE_FILE_SIZE_MAX,
                                                &lease_entries)) < 0) {
        return -1;
    }

    /* Check for previous leases */
    if (custom_lease_file_len == 0)
        return 0;

    if (!(leases_array = virJSONValueFromString(lease_entries))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid json in file: %1$s, rewriting it"),
                       custom_lease_file);
        return 0;
    }

    if (!virJSONValueIsArray(leases_array)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("couldn't fetch array of leases"));
        return -1;
    }

    i = 0;
    while (i < virJSONValueArraySize(leases_array)) {
        virJSONValue *lease_tmp = virJSONValueArrayGet(leases_array, i);
        long long expirytime;
        const char *ip_tmp = NULL;

        if (!lease_tmp) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse json"));
            return -1;
        }

        if (!(ip_tmp = virJSONValueObjectGetString(lease_tmp, "ip-address")) ||
            (virJSONValueObjectGetNumberLong(lease_tmp, "expiry-time", &expirytime) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse json"));
            return -1;
        }

        /* Check whether lease has to be included or not */
        if (ip_to_delete && STREQ(ip_tmp, ip_to_delete)) {
            i++;
            continue;
        }

        if (server_duid && strchr(ip_tmp, ':')) {
            const char *server_duid_tmp = NULL;

            /* This is an ipv6 lease */
            if ((server_duid_tmp = virJSONValueObjectGetString(lease_tmp, "server-duid"))) {
                if (!*server_duid)
                    *server_duid = g_strdup(server_duid_tmp);
            } else {
                /* Inject server-duid into those ipv6 leases which
                 * didn't have it previously, for example, those
                 * created by leaseshelper from libvirt 1.2.6 */
                if (virJSONValueObjectAppendString(lease_tmp, "server-duid", *server_duid) < 0)
                    return -1;
            }
        }

        /* Move old lease to new array */
        if (virJSONValueArrayAppend(leases_array_new, &lease_tmp) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create json"));
            return -1;
        }

        ignore_value(virJSONValueArraySteal(leases_array, i));
    }

    return 0;
}


int
virLeasePrintLeases(virJSONValue *leases_array_new,
                    const char *server_duid)
{
    virJSONValue *lease_tmp = NULL;
    const char *ip_tmp = NULL;
    long long expirytime = 0;
    size_t i;

    /* Man page of dnsmasq says: the script (helper program, in our case)
     * should write the saved state of the lease database, in dnsmasq
     * leasefile format, to stdout and exit with zero exit code, when
     * called with argument init. Format:
     * $expirytime $mac $ip $hostname $clientid # For all ipv4 leases
     * duid $server-duid # If DHCPv6 is present
     * $expirytime $iaid $ip $hostname $clientduid # For all ipv6 leases */

    /* Traversing the ipv4 leases */
    for (i = 0; i < virJSONValueArraySize(leases_array_new); i++) {
        lease_tmp = virJSONValueArrayGet(leases_array_new, i);
        if (!(ip_tmp = virJSONValueObjectGetString(lease_tmp, "ip-address"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse json"));
            return -1;
        }
        if (!strchr(ip_tmp, ':')) {
            if (virJSONValueObjectGetNumberLong(lease_tmp, "expiry-time",
                                                &expirytime) < 0)
                continue;

            printf("%lld %s %s %s %s\n",
                   expirytime,
                   virJSONValueObjectGetString(lease_tmp, "mac-address"),
                   virJSONValueObjectGetString(lease_tmp, "ip-address"),
                   NULLSTR_STAR(virJSONValueObjectGetString(lease_tmp, "hostname")),
                   NULLSTR_STAR(virJSONValueObjectGetString(lease_tmp, "client-id")));
        }
    }

    /* Traversing the ipv6 leases */
    if (server_duid) {
        printf("duid %s\n", server_duid);
        for (i = 0; i < virJSONValueArraySize(leases_array_new); i++) {
            lease_tmp = virJSONValueArrayGet(leases_array_new, i);
            if (!(ip_tmp = virJSONValueObjectGetString(lease_tmp, "ip-address"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to parse json"));
                return -1;
            }
            if (strchr(ip_tmp, ':')) {
                if (virJSONValueObjectGetNumberLong(lease_tmp, "expiry-time",
                                                    &expirytime) < 0)
                    continue;

                printf("%lld %s %s %s %s\n",
                       expirytime,
                       virJSONValueObjectGetString(lease_tmp, "iaid"),
                       virJSONValueObjectGetString(lease_tmp, "ip-address"),
                       NULLSTR_STAR(virJSONValueObjectGetString(lease_tmp, "hostname")),
                       NULLSTR_STAR(virJSONValueObjectGetString(lease_tmp, "client-id")));
            }
        }
    }

    return  0;
}


int
virLeaseNew(virJSONValue **lease_ret,
            const char *mac,
            const char *clientid,
            const char *ip,
            const char *hostname,
            const char *iaid,
            const char *server_duid)
{
    g_autoptr(virJSONValue) lease_new = NULL;
    const char *exptime_tmp = getenv("DNSMASQ_LEASE_EXPIRES");
    long long expirytime = 0;
    g_autofree char *exptime = NULL;

    /* In case hostname is still unknown, use the last known one */
    if (!hostname)
        hostname = getenv("DNSMASQ_OLD_HOSTNAME");

    if (!mac)
        return 0;

    if (exptime_tmp) {
        exptime = g_strdup(exptime_tmp);

        /* Removed extraneous trailing space in DNSMASQ_LEASE_EXPIRES
         * (dnsmasq < 2.52) */
        virTrimSpaces(exptime, NULL);

        if (virStrToLong_ll(exptime, NULL, 10, &expirytime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to convert lease expiry time to long long: %1$s"),
                           NULLSTR(exptime));
            return -1;
        }
    }

    /* Create new lease */
    lease_new = virJSONValueNewObject();

    if (iaid && virJSONValueObjectAppendString(lease_new, "iaid", iaid) < 0)
        return -1;
    if (ip && virJSONValueObjectAppendString(lease_new, "ip-address", ip) < 0)
        return -1;
    if (virJSONValueObjectAppendString(lease_new, "mac-address", mac) < 0)
        return -1;
    if (hostname && virJSONValueObjectAppendString(lease_new, "hostname", hostname) < 0)
        return -1;
    if (clientid && virJSONValueObjectAppendString(lease_new, "client-id", clientid) < 0)
        return -1;
    if (server_duid && virJSONValueObjectAppendString(lease_new, "server-duid", server_duid) < 0)
        return -1;
    if (virJSONValueObjectAppendNumberLong(lease_new, "expiry-time", expirytime) < 0)
        return -1;

    *lease_ret = g_steal_pointer(&lease_new);
    return 0;
}
