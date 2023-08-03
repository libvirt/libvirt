/*
 * virfirewalld.c: support for firewalld (https://firewalld.org)
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include <config.h>

#include <stdarg.h>

#include "virfirewall.h"
#include "virfirewalld.h"
#define LIBVIRT_VIRFIREWALLDPRIV_H_ALLOW
#include "virfirewalldpriv.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virgdbus.h"
#include "virenum.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_FIREWALLD

VIR_LOG_INIT("util.firewalld");

/* used to convert virFirewallLayer enum values to strings
 * understood by the firewalld.direct "passthrough" method
 */
VIR_ENUM_DECL(virFirewallLayerFirewallD);
VIR_ENUM_IMPL(virFirewallLayerFirewallD,
              VIR_FIREWALL_LAYER_LAST,
              "eb",
              "ipv4",
              "ipv6",
              );


VIR_ENUM_DECL(virFirewallDBackend);
VIR_ENUM_IMPL(virFirewallDBackend,
              VIR_FIREWALLD_BACKEND_LAST,
              "",
              "iptables",
              "nftables",
              );


/**
 * virFirewallDIsRegistered:
 *
 * Returns 0 if service is registered, -1 on fatal error, or -2 if service is not registered
 */
int
virFirewallDIsRegistered(void)
{
    return virGDBusIsServiceRegistered(VIR_FIREWALL_FIREWALLD_SERVICE);
}

/**
 * virFirewallDGetVersion:
 * @version: pointer to location to save version in the form of:
 *           1000000 * major + 1000 * minor + micro
 *
 * queries the firewalld version property from dbus, and converts it
 * from a string into a number.
 *
 * Returns 0 if version was successfully retrieved, or -1 on error
 */
int
virFirewallDGetVersion(unsigned long long *version)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) gvar = NULL;
    char *versionStr;

    if (!sysbus)
        return -1;

    message = g_variant_new("(ss)", "org.fedoraproject.FirewallD1", "version");

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("(v)"),
                           NULL,
                           VIR_FIREWALL_FIREWALLD_SERVICE,
                           "/org/fedoraproject/FirewallD1",
                           "org.freedesktop.DBus.Properties",
                           "Get",
                           message) < 0)
        return -1;

    g_variant_get(reply, "(v)", &gvar);
    g_variant_get(gvar, "&s", &versionStr);

    if (virStringParseVersion(version, versionStr, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse firewalld version '%1$s'"),
                       versionStr);
        return -1;
    }

    VIR_DEBUG("FirewallD version: %s - %llu", versionStr, *version);

    return 0;
}

/**
 * virFirewallDGetBackend:
 *
 * Returns virVirewallDBackendType value representing which packet
 * filtering backend is currently in use by firewalld, or -1 on error.
 */
int
virFirewallDGetBackend(void)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) gvar = NULL;
    g_autoptr(virError) error = NULL;
    char *backendStr = NULL;
    int backend = -1;

    if (!sysbus)
        return -1;

    error = g_new0(virError, 1);

    message = g_variant_new("(ss)",
                            "org.fedoraproject.FirewallD1.config",
                            "FirewallBackend");

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("(v)"),
                           error,
                           VIR_FIREWALL_FIREWALLD_SERVICE,
                           "/org/fedoraproject/FirewallD1/config",
                           "org.freedesktop.DBus.Properties",
                           "Get",
                           message) < 0)
        return -1;

    if (error->level == VIR_ERR_ERROR) {
        /* we don't want to log any error in the case that
         * FirewallBackend isn't implemented in this firewalld, since
         * that just means that it is an old version, and only has an
         * iptables backend.
         */
        VIR_DEBUG("Failed to get FirewallBackend setting, assuming 'iptables'");
        return VIR_FIREWALLD_BACKEND_IPTABLES;
    }

    g_variant_get(reply, "(v)", &gvar);
    g_variant_get(gvar, "&s", &backendStr);

    VIR_DEBUG("FirewallD backend: %s", backendStr);

    if ((backend = virFirewallDBackendTypeFromString(backendStr)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unrecognized firewalld backend type: %1$s"),
                       backendStr);
        return -1;
    }

    return backend;
}


/**
 * virFirewallDGetZones:
 * @zones: array of char *, each entry is a null-terminated zone name
 * @nzones: number of entries in @zones
 *
 * Get the number of currently active firewalld zones, and their names
 * in an array of null-terminated strings. The memory pointed to by
 * @zones will belong to the caller, and must be freed.
 *
 * Returns 0 on success, -1 (and failure logged) on error
 */
int
virFirewallDGetZones(char ***zones, size_t *nzones)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) array = NULL;

    *nzones = 0;
    *zones = NULL;

    if (!sysbus)
        return -1;

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("(as)"),
                           NULL,
                           VIR_FIREWALL_FIREWALLD_SERVICE,
                           "/org/fedoraproject/FirewallD1",
                           "org.fedoraproject.FirewallD1.zone",
                           "getZones",
                           NULL) < 0)
        return -1;

    g_variant_get(reply, "(@as)", &array);
    *zones = g_variant_dup_strv(array, nzones);

    return 0;
}

/**
 * virFirewallDGetPolicies:
 * @policies: array of char *, each entry is a null-terminated policy name
 * @npolicies: number of entries in @policies
 *
 * Get the number of currently active firewalld policies, and their names
 * in an array of null-terminated strings. The memory pointed to by
 * @policies will belong to the caller, and must be freed.
 *
 * Returns 0 on success, -1 (and failure logged) on error
 */
int
virFirewallDGetPolicies(char ***policies, size_t *npolicies)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) array = NULL;
    g_autoptr(virError) error = NULL;

    *npolicies = 0;
    *policies = NULL;

    if (!sysbus)
        return -1;

    error = g_new0(virError, 1);

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("(as)"),
                           error,
                           VIR_FIREWALL_FIREWALLD_SERVICE,
                           "/org/fedoraproject/FirewallD1",
                           "org.fedoraproject.FirewallD1.policy",
                           "getPolicies",
                           NULL) < 0)
        return -1;

    if (error->level == VIR_ERR_ERROR) {
        if (!virGDBusErrorIsUnknownMethod(error))
            virReportErrorObject(error);
        return -1;
    }

    g_variant_get(reply, "(@as)", &array);
    *policies = g_variant_dup_strv(array, npolicies);

    return 0;
}


/**
 * virFirewallDZoneExists:
 * @match: name of zone to look for
 *
 * Returns true if the requested zone exists, or false if it doesn't exist
 */
bool
virFirewallDZoneExists(const char *match)
{
    size_t nzones = 0, i;
    char **zones = NULL;
    bool result = false;

    if (virFirewallDGetZones(&zones, &nzones) < 0)
        goto cleanup;

    for (i = 0; i < nzones; i++) {
        if (STREQ_NULLABLE(zones[i], match))
            result = true;
    }

 cleanup:
    VIR_DEBUG("Requested zone '%s' %s exist",
              match, result ? "does" : "doesn't");
    for (i = 0; i < nzones; i++)
       VIR_FREE(zones[i]);
    VIR_FREE(zones);
    return result;
}


/**
 * virFirewallDPolicyExists:
 * @match: name of policy to look for
 *
 * Returns true if the requested policy exists, or false if it doesn't exist
 */
bool
virFirewallDPolicyExists(const char *match)
{
    size_t npolicies = 0, i;
    char **policies = NULL;
    bool result = false;

    if (virFirewallDGetPolicies(&policies, &npolicies) < 0)
        goto cleanup;

    for (i = 0; i < npolicies; i++) {
        if (STREQ_NULLABLE(policies[i], match))
            result = true;
    }

 cleanup:
    VIR_DEBUG("Requested policy '%s' %s exist",
              match, result ? "does" : "doesn't");
    for (i = 0; i < npolicies; i++)
       VIR_FREE(policies[i]);
    VIR_FREE(policies);
    return result;
}


/**
 * virFirewallDApplyRule:
 * @layer:        which layer to apply the rule to
 * @args:         list of args to send to this layer's passthrough command.
 * @argsLen:      number of items in @args
 * @ignoreErrors: true to suppress logging of errors and return success
 *                false to log errors and return actual status
 * @output:       output of the direct passthrough command, if it was successful
 */
int
virFirewallDApplyRule(virFirewallLayer layer,
                      char **args, size_t argsLen,
                      bool ignoreErrors,
                      char **output)
{
    const char *ipv = virFirewallLayerFirewallDTypeToString(layer);
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(virError) error = NULL;

    if (!sysbus)
        return -1;

    if (!ipv) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown firewall layer %1$d"),
                       layer);
        return -1;
    }

    error = g_new0(virError, 1);

    message = g_variant_new("(s@as)",
                            ipv,
                            g_variant_new_strv((const char * const*)args, argsLen));

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("(s)"),
                           error,
                           VIR_FIREWALL_FIREWALLD_SERVICE,
                           "/org/fedoraproject/FirewallD1",
                           "org.fedoraproject.FirewallD1.direct",
                           "passthrough",
                           message) < 0)
        return -1;

    if (error->level == VIR_ERR_ERROR) {
        /*
         * As of firewalld-0.3.9.3-1.fc20.noarch the name and
         * message fields in the error look like
         *
         *    name="org.freedesktop.DBus.Python.dbus.exceptions.DBusException"
         * message="COMMAND_FAILED: '/sbin/iptables --table filter --delete
         *          INPUT --in-interface virbr0 --protocol udp --destination-port 53
         *          --jump ACCEPT' failed: iptables: Bad rule (does a matching rule
         *          exist in that chain?)."
         *
         * We'd like to only ignore DBus errors precisely related to the failure
         * of iptables/ebtables commands. A well designed DBus interface would
         * return specific named exceptions not the top level generic python dbus
         * exception name. With this current scheme our only option is todo a
         * sub-string match for 'COMMAND_FAILED' on the message. eg like
         *
         * if (ignoreErrors &&
         *     STREQ(error.name,
         *           "org.freedesktop.DBus.Python.dbus.exceptions.DBusException") &&
         *     STRPREFIX(error.message, "COMMAND_FAILED"))
         *    ...
         *
         * But this risks our error detecting code being broken if firewalld changes
         * ever alter the message string, so we're avoiding doing that.
         */
        if (ignoreErrors) {
            VIR_DEBUG("Ignoring error '%s': '%s'",
                      error->str1, error->message);
        } else {
            virReportErrorObject(error);
            return -1;
        }
    } else {
        g_variant_get(reply, "(s)", output);
    }

    return 0;
}


int
virFirewallDInterfaceSetZone(const char *iface,
                             const char *zone)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();
    g_autoptr(GVariant) message = NULL;

    if (!sysbus)
        return -1;

    message = g_variant_new("(ss)", zone, iface);

    return virGDBusCallMethod(sysbus,
                             NULL,
                             NULL,
                             NULL,
                             VIR_FIREWALL_FIREWALLD_SERVICE,
                             "/org/fedoraproject/FirewallD1",
                             "org.fedoraproject.FirewallD1.zone",
                             "changeZoneOfInterface",
                             message);
}


void
virFirewallDSynchronize(void)
{
    const char *arg = "-V";
    g_autofree char *output = NULL;
    int firewallDRegistered = virFirewallDIsRegistered();

    /*
     * virFirewallDSynchronize() should be called after receiving an
     * ownership-change event or reload event for firewalld from dbus,
     * prior to performing any operations on the default table
     * "filter".
     *
     * Our iptables filter rules are added to (private chains within)
     * the default table named "filter", which is flushed by firewalld
     * any time it is restarted or reloads its rules. libvirt watches
     * for notifications that firewalld has been restarted / its rules
     * reloaded, and then reloads the libvirt rules. But it's possible
     * for libvirt to be notified that firewalld has restarted prior
     * to firewalld completing initialization, and when that race
     * happens, firewalld can potentially flush out rules that libvirt
     * has just added!
     *
     * To prevent this, we send a simple command ("iptables -V") via
     * firewalld's passthrough iptables API, and wait until it's
     * finished before sending our own directly-executed iptables
     * commands. This assures that firewalld has fully initialized and
     * caught up with its internal queue of iptables commands, and
     * won't stomp all over the new rules we subsequently add.
     *
     */

    VIR_DEBUG("Firewalld is registered ? %d", firewallDRegistered);

    if (firewallDRegistered < 0)
        return; /* firewalld (or dbus?) not functional, don't sync */

    ignore_value(virFirewallDApplyRule(VIR_FIREWALL_LAYER_IPV4,
                                       (char **)&arg, 1, true, &output));
    VIR_DEBUG("Result of 'iptables -V' via firewalld: %s", NULLSTR(output));
}
