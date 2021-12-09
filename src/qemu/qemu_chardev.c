/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_fd.h"

#include "vircommand.h"
#include "virlog.h"
#include "virqemu.h"

#include "domain_conf.h"

#include "qemu_chardev.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_command");

static int
qemuChardevBackendAddSocketAddressInet(virJSONValue **backendData,
                                       const char *backendFieldName,
                                       bool commandline,
                                       const char *commandlinePrefix,
                                       const char *host,
                                       const char *port)
{
    if (commandline) {
        g_autofree char *hostField = NULL;
        g_autofree char *portField = NULL;

        if (!commandlinePrefix) {
            hostField = g_strdup("s:host");
            portField = g_strdup("s:port");
        } else {
            hostField = g_strdup_printf("s:%saddr", commandlinePrefix);
            portField = g_strdup_printf("s:%sport", commandlinePrefix);
        }

        if (virJSONValueObjectAdd(backendData,
                                  hostField, host,
                                  portField, port,
                                  NULL) < 0)
            return -1;
    } else {
        g_autoptr(virJSONValue) addr = NULL;
        g_autoptr(virJSONValue) data = NULL;
        g_autofree char *datafield = g_strdup_printf("a:%s", backendFieldName);

        if (virJSONValueObjectAdd(&data,
                                  "s:host", host,
                                  "s:port", port,
                                  NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(&addr,
                                  "s:type", "inet",
                                  "a:data", &data,
                                  NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(backendData,
                                  datafield, &addr,
                                  NULL) < 0)
            return -1;
    }

    return 0;
}


static int
qemuChardevBackendAddSocketAddressFD(virJSONValue **backendData,
                                     const char *backendFieldName,
                                     bool commandline,
                                     const char *fdname)
{
    if (commandline) {
        if (virJSONValueObjectAdd(backendData,
                                  "s:fd", fdname,
                                  NULL) < 0)
            return -1;
    } else {
        g_autoptr(virJSONValue) addr = NULL;
        g_autoptr(virJSONValue) data = NULL;
        g_autofree char *datafield = g_strdup_printf("a:%s", backendFieldName);

        if (virJSONValueObjectAdd(&data, "s:str", fdname, NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(&addr,
                                  "s:type", "fd",
                                  "a:data", &data, NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(backendData,
                                  datafield, &addr,
                                  NULL) < 0)
            return -1;
    }

    return 0;
}


static int
qemuChardevBackendAddSocketAddressUNIX(virJSONValue **backendData,
                                       const char *backendFieldName,
                                       bool commandline,
                                       const char *path)
{
    if (commandline) {
        if (virJSONValueObjectAdd(backendData,
                                  "s:path", path,
                                  NULL) < 0)
            return -1;
    } else {
        g_autoptr(virJSONValue) addr = NULL;
        g_autoptr(virJSONValue) data = NULL;
        g_autofree char *datafield = g_strdup_printf("a:%s", backendFieldName);

        if (virJSONValueObjectAdd(&data, "s:path", path, NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(&addr,
                                  "s:type", "unix",
                                  "a:data", &data, NULL) < 0)
            return -1;

        if (virJSONValueObjectAdd(backendData,
                                  datafield, &addr,
                                  NULL) < 0)
            return -1;
    }

    return 0;
}


int
qemuChardevGetBackendProps(const virDomainChrSourceDef *chr,
                           bool commandline,
                           const char *alias,
                           const char **backendType,
                           virJSONValue **props)
{
    qemuDomainChrSourcePrivate *chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chr);
    const char *dummy = NULL;

    if (!backendType)
        backendType = &dummy;

    *props = NULL;

    switch ((virDomainChrType)chr->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
        *backendType = virDomainChrTypeToString(chr->type);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE: {
        const char *path = chr->data.file.path;
        virTristateSwitch append = chr->data.file.append;
        const char *pathfield = "s:out";

        if (commandline)
            pathfield = "s:path";

        *backendType = "file";

        if (chrSourcePriv->sourcefd) {
            path = qemuFDPassGetPath(chrSourcePriv->sourcefd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        if (virJSONValueObjectAdd(props,
                                  pathfield, path,
                                  "T:append", append,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_DEV: {
        const char *pathField = "s:device";

        if (commandline)
            pathField = "s:path";

        if (chr->type == VIR_DOMAIN_CHR_TYPE_PIPE) {
            *backendType = "pipe";
        } else {
            if (STRPREFIX(alias, "charparallel"))
                *backendType = "parallel";
            else
                *backendType = "serial";
        }

        if (virJSONValueObjectAdd(props,
                                  pathField, chr->data.file.path,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX: {
        virTristateBool waitval = VIR_TRISTATE_BOOL_ABSENT;
        virTristateBool server = VIR_TRISTATE_BOOL_ABSENT;
        int reconnect = -1;

        *backendType = "socket";

        if (!commandline)
            server = VIR_TRISTATE_BOOL_NO;

        if (chr->data.nix.listen) {
            server = VIR_TRISTATE_BOOL_YES;

            if (!chrSourcePriv->wait)
                waitval = VIR_TRISTATE_BOOL_NO;
        }

        if (chrSourcePriv->directfd) {
            if (qemuChardevBackendAddSocketAddressFD(props, "addr",
                                                     commandline,
                                                     qemuFDPassDirectGetPath(chrSourcePriv->directfd)) < 0)
                return -1;
        } else {
            if (qemuChardevBackendAddSocketAddressUNIX(props, "addr",
                                                       commandline,
                                                       chr->data.nix.path) < 0)
                return -1;

            if (chr->data.nix.reconnect.enabled == VIR_TRISTATE_BOOL_YES)
                reconnect = chr->data.nix.reconnect.timeout;
            else if (chr->data.nix.reconnect.enabled == VIR_TRISTATE_BOOL_NO)
                reconnect = 0;
        }

        if (virJSONValueObjectAdd(props,
                                  "T:server", server,
                                  "T:wait", waitval,
                                  "k:reconnect", reconnect,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP: {
        virTristateBool waitval = VIR_TRISTATE_BOOL_ABSENT;
        virTristateBool telnet = VIR_TRISTATE_BOOL_ABSENT;
        virTristateBool server = VIR_TRISTATE_BOOL_ABSENT;
        int reconnect = -1;

        *backendType = "socket";

        if (!commandline) {
            server = VIR_TRISTATE_BOOL_NO;
            telnet = VIR_TRISTATE_BOOL_NO;
        }

        if (chr->data.tcp.listen) {
            server = VIR_TRISTATE_BOOL_YES;

            if (!chrSourcePriv->wait)
                waitval = VIR_TRISTATE_BOOL_NO;
        }

        if (chr->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET)
            telnet = VIR_TRISTATE_BOOL_YES;

        if (chr->data.tcp.reconnect.enabled == VIR_TRISTATE_BOOL_YES)
            reconnect = chr->data.tcp.reconnect.timeout;
        else if (chr->data.tcp.reconnect.enabled == VIR_TRISTATE_BOOL_NO)
            reconnect = 0;

        if (qemuChardevBackendAddSocketAddressInet(props, "addr",
                                                   commandline, NULL,
                                                   chr->data.tcp.host,
                                                   chr->data.tcp.service) < 0)
            return -1;

        if (virJSONValueObjectAdd(props,
                                  "T:telnet", telnet,
                                  "T:server", server,
                                  "T:wait", waitval,
                                  "k:reconnect", reconnect,
                                  "S:tls-creds", chrSourcePriv->tlsCredsAlias,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        *backendType = "udp";

        if (qemuChardevBackendAddSocketAddressInet(props, "remote",
                                                   commandline, NULL,
                                                   NULLSTR_EMPTY(chr->data.udp.connectHost),
                                                   chr->data.udp.connectService) < 0)
            return -1;

        if (commandline || chr->data.udp.bindHost || chr->data.udp.bindService) {
            const char *bindHost = NULLSTR_EMPTY(chr->data.udp.bindHost);
            const char *bindService = chr->data.udp.bindService;

            if (!bindService)
                bindService = "0";

            if (qemuChardevBackendAddSocketAddressInet(props, "local",
                                                       commandline, "local",
                                                       bindHost, bindService) < 0)
                return -1;
        }

        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC: {
        const char *typeField = "s:type";

        *backendType = "spicevmc";

        if (commandline)
            typeField = "s:name";

        if (virJSONValueObjectAdd(props,
                                  typeField, virDomainChrSpicevmcTypeToString(chr->data.spicevmc),
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT: {
        virTristateBool mouse = VIR_TRISTATE_BOOL_ABSENT;

        *backendType = "qemu-vdagent";

        switch (chr->data.qemuVdagent.mouse) {
            case VIR_DOMAIN_MOUSE_MODE_CLIENT:
                mouse = VIR_TRISTATE_BOOL_YES;
                break;
            case VIR_DOMAIN_MOUSE_MODE_SERVER:
                mouse = VIR_TRISTATE_BOOL_NO;
                break;
            case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
                break;
            case VIR_DOMAIN_MOUSE_MODE_LAST:
            default:
                virReportEnumRangeError(virDomainMouseMode,
                                        chr->data.qemuVdagent.mouse);
                return -1;
        }

        if (commandline) {
            if (virJSONValueObjectAdd(props,
                                      "s:name", "vdagent",
                                      NULL) < 0)
                return -1;
        }

        if (virJSONValueObjectAdd(props,
                                  "T:clipboard", chr->data.qemuVdagent.clipboard,
                                  "T:mouse", mouse,
                                  NULL) < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        *backendType = "dbus";

        if (virJSONValueObjectAdd(props,
                                  "s:name", chr->data.dbus.channel,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT: {
        const char *channelField = "s:fqdn";

        *backendType = "spiceport";

        if (commandline)
            channelField = "s:name";

        if (virJSONValueObjectAdd(props,
                                  channelField, chr->data.spiceport.channel,
                                  NULL) < 0)
            return -1;
    }
        break;


    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainChrType, chr->type);
        return -1;
    }

    if (chr->logfile) {
        const char *path = chr->logfile;
        virTristateSwitch append = chr->logappend;

        if (chrSourcePriv->logfd) {
            path = qemuFDPassGetPath(chrSourcePriv->logfd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        if (virJSONValueObjectAdd(props,
                                  "s:logfile", path,
                                  "T:logappend", append,
                                  NULL) < 0)
            return -1;
    }

    if (!commandline) {
        /* The 'chardev-add' QMP command uses two extra layers of wrapping in
         * comparison to what the '-chardev' command syntax has */
        g_autoptr(virJSONValue) backend = g_steal_pointer(props);
        g_autoptr(virJSONValue) backendWrap = NULL;

        /* the 'data' field of the wrapper below must be present per QMP schema */
        if (!backend)
            backend = virJSONValueNewObject();

        if (virJSONValueObjectAdd(&backendWrap,
                                  "s:type", *backendType,
                                  "a:data", &backend,
                                  NULL) < 0)
            return -1;

        /* We now replace the value in the variable we're about to return */
        if (virJSONValueObjectAdd(props,
                                  "s:id", alias,
                                  "a:backend", &backendWrap,
                                  NULL) < 0)
            return -1;
    }

    return 0;
}


int
qemuChardevBuildCommandline(virCommand *cmd,
                            const virDomainChrSourceDef *dev,
                            const char *charAlias,
                            virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *arg = NULL;
    /* BEWARE: '-chardev' is not yet accepting JSON syntax.
     * QEMU_CAPS_CHARDEV_JSON is asserted just from tests */
    bool useJSON = virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_JSON);
    const char *backendType = NULL;

    if (qemuChardevGetBackendProps(dev, !useJSON, charAlias, &backendType, &props) < 0)
        return -1;

    if (useJSON) {
        if (!(arg = virJSONValueToString(props, false)))
            return -1;
    } else {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        virBufferAsprintf(&buf, "%s,id=%s", backendType, charAlias);

        if (props) {
            virBufferAddLit(&buf, ",");

            if (virQEMUBuildCommandLineJSON(props, &buf, NULL, NULL) < 0)
                return -1;
        }

        arg = virBufferContentAndReset(&buf);
    }

    virCommandAddArgList(cmd, "-chardev", arg, NULL);
    return 0;
}
