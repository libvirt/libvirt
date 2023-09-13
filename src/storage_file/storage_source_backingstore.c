/*
 * storage_source_backingstore.c: helpers for parsing backing store strings
 *
 * Copyright (C) 2007-2017 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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

#include "internal.h"

#include "storage_source_backingstore.h"

#include "viruri.h"
#include "virstring.h"
#include "virjson.h"
#include "virlog.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage_source_backingstore");


int
virStorageSourceParseBackingURI(virStorageSource *src,
                                const char *uristr)
{
    g_autoptr(virURI) uri = NULL;
    const char *path = NULL;
    int transport = 0;
    g_auto(GStrv) scheme = NULL;

    if (!(uri = virURIParse(uristr))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse backing file location '%1$s'"),
                       uristr);
        return -1;
    }

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (!(scheme = g_strsplit(uri->scheme, "+", 2)))
        return -1;

    if (!scheme[0] ||
        (src->protocol = virStorageNetProtocolTypeFromString(scheme[0])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%1$s'"),
                       NULLSTR(scheme[0]));
        return -1;
    }

    if (scheme[1]) {
        if ((transport = virStorageNetHostTransportTypeFromString(scheme[1])) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid protocol transport type '%1$s'"),
                           scheme[1]);
            return -1;
        }
        src->hosts->transport = transport;
    }

    if (uri->query) {
        if (src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTP ||
            src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS) {
            src->query = g_strdup(uri->query);
        } else {
            /* handle socket stored as a query */
            if (STRPREFIX(uri->query, "socket="))
                src->hosts->socket = g_strdup(STRSKIP(uri->query, "socket="));
        }
    }

    /* uri->path is NULL if the URI does not contain slash after host:
     * transport://host:port */
    if (uri->path)
        path = uri->path;
    else
        path = "";

    /* possibly skip the leading slash  */
    if (g_path_is_absolute(path))
        path++;

    /* NBD allows empty export name (path) */
    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_NBD &&
        path[0] == '\0')
        path = NULL;

    src->path = g_strdup(path);

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_GLUSTER) {
        char *tmp;

        if (!src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("missing volume name and path for gluster volume"));
            return -1;
        }

        if (!(tmp = strchr(src->path, '/')) ||
            tmp == src->path) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("missing volume name or file name in gluster source path '%1$s'"),
                           src->path);
            return -1;
        }

        src->volume = src->path;

        src->path = g_strdup(tmp + 1);

        tmp[0] = '\0';
    }

    src->hosts->port = uri->port;

    src->hosts->name = g_strdup(uri->server);

    /* Libvirt doesn't handle inline authentication. Make the caller aware. */
    if (uri->user)
        return 1;

    return 0;
}


static int
virStorageSourceRBDAddHost(virStorageSource *src,
                           char *hostport)
{
    char *port;
    size_t skip;
    g_auto(GStrv) parts = NULL;

    VIR_EXPAND_N(src->hosts, src->nhosts, 1);

    if ((port = strchr(hostport, ']'))) {
        /* ipv6, strip brackets */
        hostport += 1;
        skip = 3;
    } else {
        port = strstr(hostport, "\\:");
        skip = 2;
    }

    if (port) {
        *port = '\0';
        port += skip;
        if (virStringParsePort(port, &src->hosts[src->nhosts - 1].port) < 0)
            goto error;
    }

    parts = g_strsplit(hostport, "\\:", 0);
    if (!parts)
        goto error;
    src->hosts[src->nhosts-1].name = g_strjoinv(":", parts);

    src->hosts[src->nhosts-1].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    src->hosts[src->nhosts-1].socket = NULL;

    return 0;

 error:
    VIR_FREE(src->hosts[src->nhosts-1].name);
    return -1;
}


int
virStorageSourceParseRBDColonString(const char *rbdstr,
                                    virStorageSource *src)
{
    char *p, *e, *next;
    g_autofree char *options = NULL;
    g_autoptr(virStorageAuthDef) authdef = NULL;

    /* optionally skip the "rbd:" prefix if provided */
    if (STRPREFIX(rbdstr, "rbd:"))
        rbdstr += strlen("rbd:");

    src->path = g_strdup(rbdstr);

    p = strchr(src->path, ':');
    if (p) {
        options = g_strdup(p + 1);
        *p = '\0';
    }

    /* snapshot name */
    if ((p = strchr(src->path, '@'))) {
        src->snapshot = g_strdup(p + 1);
        *p = '\0';
    }

    /* pool vs. image name */
    if ((p = strchr(src->path, '/'))) {
        src->volume = g_steal_pointer(&src->path);
        src->path = g_strdup(p + 1);
        *p = '\0';
    }

    /* options */
    if (!options)
        return 0; /* all done */

    p = options;
    while (*p) {
        /* find : delimiter or end of string */
        for (e = p; *e && *e != ':'; ++e) {
            if (*e == '\\') {
                e++;
                if (*e == '\0')
                    break;
            }
        }
        if (*e == '\0') {
            next = e;    /* last kv pair */
        } else {
            next = e + 1;
            *e = '\0';
        }

        if (STRPREFIX(p, "id=")) {
            /* formulate authdef for src->auth */
            if (src->auth) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("duplicate 'id' found in '%1$s'"), src->path);
                return -1;
            }

            authdef = g_new0(virStorageAuthDef, 1);

            authdef->username = g_strdup(p + strlen("id="));

            authdef->secrettype = g_strdup(virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_CEPH));
            src->auth = g_steal_pointer(&authdef);

            /* Cannot formulate a secretType (eg, usage or uuid) given
             * what is provided.
             */
        }
        if (STRPREFIX(p, "mon_host=")) {
            char *h, *sep;

            h = p + strlen("mon_host=");
            while (h < e) {
                for (sep = h; sep < e; ++sep) {
                    if (*sep == '\\' && (sep[1] == ',' ||
                                         sep[1] == ';' ||
                                         sep[1] == ' ')) {
                        *sep = '\0';
                        sep += 2;
                        break;
                    }
                }

                if (virStorageSourceRBDAddHost(src, h) < 0)
                    return -1;

                h = sep;
            }
        }

        if (STRPREFIX(p, "conf="))
            src->configFile = g_strdup(p + strlen("conf="));

        p = next;
    }
    return 0;
}


static int
virStorageSourceParseNBDColonString(const char *nbdstr,
                                    virStorageSource *src)
{
    g_autofree char *nbd = g_strdup(nbdstr);
    char *export_name;
    char *host_spec;
    char *unixpath;
    char *port;

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    /* We extract the parameters in a similar way qemu does it */

    /* format: [] denotes optional sections, uppercase are variable strings
     * nbd:unix:/PATH/TO/SOCKET[:exportname=EXPORTNAME]
     * nbd:HOSTNAME:PORT[:exportname=EXPORTNAME]
     */

    /* first look for ':exportname=' and cut it off */
    if ((export_name = strstr(nbd, ":exportname="))) {
        src->path = g_strdup(export_name + strlen(":exportname="));
        export_name[0] = '\0';
    }

    /* Verify the prefix and contents. Note that we require a
     * "host_spec" part to be present. */
    if (!(host_spec = STRSKIP(nbd, "nbd:")) || host_spec[0] == '\0')
        goto malformed;

    if ((unixpath = STRSKIP(host_spec, "unix:"))) {
        src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;

        if (unixpath[0] == '\0')
            goto malformed;

        src->hosts->socket = g_strdup(unixpath);
    } else {
        src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

        if (host_spec[0] == ':') {
            /* no host given */
            goto malformed;
        } else if (host_spec[0] == '[') {
            host_spec++;
            /* IPv6 addr */
            if (!(port = strstr(host_spec, "]:")))
                goto malformed;

            port[0] = '\0';
            port += 2;

            if (host_spec[0] == '\0')
                goto malformed;
        } else {
            if (!(port = strchr(host_spec, ':')))
                goto malformed;

            port[0] = '\0';
            port++;
        }

        if (virStringParsePort(port, &src->hosts->port) < 0)
            return -1;

        src->hosts->name = g_strdup(host_spec);
    }

    return 0;

 malformed:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("malformed nbd string '%1$s'"), nbdstr);
    return -1;
}


int
virStorageSourceParseBackingColon(virStorageSource *src,
                                  const char *path)
{
    const char *p;
    g_autofree char *protocol = NULL;

    if (!(p = strchr(path, ':'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol string '%1$s'"),
                       path);
        return -1;
    }

    protocol = g_strndup(path, p - path);

    if ((src->protocol = virStorageNetProtocolTypeFromString(protocol)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%1$s'"),
                       protocol);
        return -1;
    }

    switch ((virStorageNetProtocol) src->protocol) {
    case VIR_STORAGE_NET_PROTOCOL_NBD:
        if (virStorageSourceParseNBDColonString(path, src) < 0)
            return -1;
        break;

    case VIR_STORAGE_NET_PROTOCOL_RBD:
        if (virStorageSourceParseRBDColonString(path, src) < 0)
            return -1;
        break;

    case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
    case VIR_STORAGE_NET_PROTOCOL_LAST:
    case VIR_STORAGE_NET_PROTOCOL_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store parser is not implemented for protocol %1$s"),
                       protocol);
        return -1;

    case VIR_STORAGE_NET_PROTOCOL_HTTP:
    case VIR_STORAGE_NET_PROTOCOL_HTTPS:
    case VIR_STORAGE_NET_PROTOCOL_FTP:
    case VIR_STORAGE_NET_PROTOCOL_FTPS:
    case VIR_STORAGE_NET_PROTOCOL_TFTP:
    case VIR_STORAGE_NET_PROTOCOL_ISCSI:
    case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
    case VIR_STORAGE_NET_PROTOCOL_SSH:
    case VIR_STORAGE_NET_PROTOCOL_VXHS:
    case VIR_STORAGE_NET_PROTOCOL_NFS:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed backing store path for protocol %1$s"),
                       protocol);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONInternal(virStorageSource *src,
                                         virJSONValue *json,
                                         const char *jsonstr,
                                         bool allowformat);


static int
virStorageSourceParseBackingJSONPath(virStorageSource *src,
                                     virJSONValue *json,
                                     const char *jsonstr G_GNUC_UNUSED,
                                     int type)
{
    const char *path;

    if (!(path = virJSONValueObjectGetString(json, "filename"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'filename' field in JSON backing volume definition"));
        return -1;
    }

    src->path = g_strdup(path);

    src->type = type;
    return 0;
}


static int
virStorageSourceParseBackingJSONUriStr(virStorageSource *src,
                                       const char *uri,
                                       int protocol)
{
    int rc;

    if ((rc = virStorageSourceParseBackingURI(src, uri)) < 0)
        return -1;

    if (src->protocol != protocol) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("expected protocol '%1$s' but got '%2$s' in URI JSON volume definition"),
                       virStorageNetProtocolTypeToString(protocol),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -1;
    }

    return rc;
}


static int
virStorageSourceParseBackingJSONUriCookies(virStorageSource *src,
                                           virJSONValue *json,
                                           const char *jsonstr)
{
    const char *cookiestr;
    g_auto(GStrv) cookies = NULL;
    size_t i;

    if (!virJSONValueObjectHasKey(json, "cookie"))
        return 0;

    if (!(cookiestr = virJSONValueObjectGetString(json, "cookie"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("wrong format of 'cookie' field in backing store definition '%1$s'"),
                       jsonstr);
        return -1;
    }

    if (!(cookies = g_strsplit(cookiestr, ";", 0)))
        return -1;

    src->ncookies = g_strv_length(cookies);
    src->cookies = g_new0(virStorageNetCookieDef *, src->ncookies);

    for (i = 0; i < src->ncookies; i++) {
        char *cookiename = cookies[i];
        char *cookievalue;

        virSkipSpaces((const char **) &cookiename);

        if (!(cookievalue = strchr(cookiename, '='))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("malformed http cookie '%1$s' in backing store definition '%2$s'"),
                           cookies[i], jsonstr);
            return -1;
        }

        *cookievalue = '\0';
        cookievalue++;

        src->cookies[i] = g_new0(virStorageNetCookieDef, 1);
        src->cookies[i]->name = g_strdup(cookiename);
        src->cookies[i]->value = g_strdup(cookievalue);
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONUri(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr,
                                    int protocol)
{
    const char *uri;

    if (!(uri = virJSONValueObjectGetString(json, "url"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'url' in JSON backing volume definition"));
        return -1;
    }

    if (protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS ||
        protocol == VIR_STORAGE_NET_PROTOCOL_FTPS) {
        if (virJSONValueObjectHasKey(json, "sslverify")) {
            const char *tmpstr;
            bool tmp;

            /* libguestfs still uses undocumented legacy value of 'off' */
            if ((tmpstr = virJSONValueObjectGetString(json, "sslverify")) &&
                STREQ(tmpstr, "off")) {
                src->sslverify = VIR_TRISTATE_BOOL_NO;
            } else {
                if (virJSONValueObjectGetBoolean(json, "sslverify", &tmp) < 0) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("malformed 'sslverify' field in backing store definition '%1$s'"),
                                   jsonstr);
                    return -1;
                }

                src->sslverify = virTristateBoolFromBool(tmp);
            }
        }
    }

    if (protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS ||
        protocol == VIR_STORAGE_NET_PROTOCOL_HTTP) {
        if (virStorageSourceParseBackingJSONUriCookies(src, json, jsonstr) < 0)
            return -1;
    }

    if (virJSONValueObjectHasKey(json, "readahead") &&
        virJSONValueObjectGetNumberUlong(json, "readahead", &src->readahead) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("malformed 'readahead' field in backing store definition '%1$s'"),
                       jsonstr);
        return -1;
    }

    if (virJSONValueObjectHasKey(json, "timeout") &&
        virJSONValueObjectGetNumberUlong(json, "timeout", &src->timeout) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("malformed 'timeout' field in backing store definition '%1$s'"),
                       jsonstr);
        return -1;
    }

    return virStorageSourceParseBackingJSONUriStr(src, uri, protocol);
}


static int
virStorageSourceParseBackingJSONInetSocketAddress(virStorageNetHostDef *host,
                                                  virJSONValue *json)
{
    const char *hostname;
    const char *port;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON backing volume definition"));
        return -1;
    }

    hostname = virJSONValueObjectGetString(json, "host");
    port = virJSONValueObjectGetString(json, "port");

    if (!hostname) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing hostname for tcp backing server in JSON backing volume definition"));
        return -1;
    }

    host->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    host->name = g_strdup(hostname);

    if (virStringParsePort(port, &host->port) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONSocketAddress(virStorageNetHostDef *host,
                                              virJSONValue *json)
{
    const char *type;
    const char *socket;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON backing volume definition"));
        return -1;
    }

    if (!(type = virJSONValueObjectGetString(json, "type"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing socket address type in JSON backing volume definition"));
        return -1;
    }

    if (STREQ(type, "tcp") || STREQ(type, "inet")) {
        return virStorageSourceParseBackingJSONInetSocketAddress(host, json);

    } else if (STREQ(type, "unix")) {
        host->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;

        socket = virJSONValueObjectGetString(json, "path");

        /* check for old spelling for gluster protocol */
        if (!socket)
            socket = virJSONValueObjectGetString(json, "socket");

        if (!socket) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("missing socket path for udp backing server in JSON backing volume definition"));
            return -1;
        }

        host->socket = g_strdup(socket);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store protocol '%1$s' is not yet supported"),
                       type);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONGluster(virStorageSource *src,
                                        virJSONValue *json,
                                        const char *jsonstr G_GNUC_UNUSED,
                                        int opaque G_GNUC_UNUSED)
{
    const char *uri = virJSONValueObjectGetString(json, "filename");
    const char *volume = virJSONValueObjectGetString(json, "volume");
    const char *path = virJSONValueObjectGetString(json, "path");
    virJSONValue *server = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;

    /* legacy URI based syntax passed via 'filename' option */
    if (uri)
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_GLUSTER);

    if (!volume || !path || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'volume', 'path' or 'server' attribute in JSON backing definition for gluster volume"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;

    src->volume = g_strdup(volume);
    src->path = g_strdup(path);

    nservers = virJSONValueArraySize(server);
    if (nservers == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("at least 1 server is necessary in JSON backing definition for gluster volume"));

        return -1;
    }

    src->hosts = g_new0(virStorageNetHostDef, nservers);
    src->nhosts = nservers;

    for (i = 0; i < nservers; i++) {
        if (virStorageSourceParseBackingJSONSocketAddress(src->hosts + i,
                                                          virJSONValueArrayGet(server, i)) < 0)
            return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONiSCSI(virStorageSource *src,
                                      virJSONValue *json,
                                      const char *jsonstr G_GNUC_UNUSED,
                                      int opaque G_GNUC_UNUSED)
{
    const char *transport = virJSONValueObjectGetString(json, "transport");
    const char *portal = virJSONValueObjectGetString(json, "portal");
    const char *target = virJSONValueObjectGetString(json, "target");
    const char *lun = virJSONValueObjectGetStringOrNumber(json, "lun");
    const char *uri;
    char *port;

    /* legacy URI based syntax passed via 'filename' option */
    if ((uri = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_ISCSI);

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    if (!lun)
        lun = "0";

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (STRNEQ_NULLABLE(transport, "tcp")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("only TCP transport is supported for iSCSI volumes"));
        return -1;
    }

    src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

    if (!portal) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'portal' address in iSCSI backing definition"));
        return -1;
    }

    if (!target) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'target' in iSCSI backing definition"));
        return -1;
    }

    src->hosts->name = g_strdup(portal);

    if ((port = strrchr(src->hosts->name, ':')) &&
        !strchr(port, ']')) {
        if (virStringParsePort(port + 1, &src->hosts->port) < 0)
            return -1;

        *port = '\0';
    }

    src->path = g_strdup_printf("%s/%s", target, lun);

    /* Libvirt doesn't handle inline authentication. Make the caller aware. */
    if (virJSONValueObjectGetString(json, "user") ||
        virJSONValueObjectGetString(json, "password"))
        return 1;

    return 0;
}


static int
virStorageSourceParseBackingJSONNbd(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    const char *export = virJSONValueObjectGetString(json, "export");
    virJSONValue *server = virJSONValueObjectGetObject(json, "server");

    if (!path && !host && !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host specification of NBD server in JSON backing volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;

    src->path = g_strdup(export);

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (server) {
        if (virStorageSourceParseBackingJSONSocketAddress(src->hosts, server) < 0)
            return -1;
    } else {
        if (path) {
            src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
            src->hosts[0].socket = g_strdup(path);
        } else {
            src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            src->hosts[0].name = g_strdup(host);

            if (virStringParsePort(port, &src->hosts[0].port) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONSheepdog(virStorageSource *src,
                                         virJSONValue *json,
                                         const char *jsonstr G_GNUC_UNUSED,
                                         int opaque G_GNUC_UNUSED)
{
    const char *filename;
    const char *vdi = virJSONValueObjectGetString(json, "vdi");
    virJSONValue *server = virJSONValueObjectGetObject(json, "server");

    /* legacy URI based syntax passed via 'filename' option */
    if ((filename = virJSONValueObjectGetString(json, "filename"))) {
        if (strstr(filename, "://"))
            return virStorageSourceParseBackingJSONUriStr(src, filename,
                                                          VIR_STORAGE_NET_PROTOCOL_SHEEPDOG);

        /* libvirt doesn't implement a parser for the legacy non-URI syntax */
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing sheepdog URI in JSON backing volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;

    if (!vdi) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("missing sheepdog vdi name"));
        return -1;
    }

    src->path = g_strdup(vdi);

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (virStorageSourceParseBackingJSONSocketAddress(src->hosts, server) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONSSH(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    const char *user = virJSONValueObjectGetString(json, "user");
    const char *host_key_check = virJSONValueObjectGetString(json, "host_key_check");
    virJSONValue *server = virJSONValueObjectGetObject(json, "server");

    if (!(host || server) || !path) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host/server or path of SSH JSON backing volume definition"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_SSH;

    src->path = g_strdup(path);

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (server) {
        if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts,
                                                              server) < 0)
            return -1;
    } else {
        src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
        src->hosts[0].name = g_strdup(host);

        if (virStringParsePort(port, &src->hosts[0].port) < 0)
            return -1;
    }

    /* these two are parsed just to be passed back as we don't model them yet */
    src->ssh_user = g_strdup(user);
    if (STREQ_NULLABLE(host_key_check, "no"))
        src->ssh_host_key_check_disabled = true;

    return 0;
}


static int
virStorageSourceParseBackingJSONRBD(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *filename;
    const char *pool = virJSONValueObjectGetString(json, "pool");
    const char *image = virJSONValueObjectGetString(json, "image");
    const char *conf = virJSONValueObjectGetString(json, "conf");
    const char *snapshot = virJSONValueObjectGetString(json, "snapshot");
    virJSONValue *servers = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;

    /* legacy syntax passed via 'filename' option */
    if ((filename = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseRBDColonString(filename, src);

    if (!pool || !image) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing pool or image name in ceph backing volume JSON specification"));
        return -1;
    }

    src->volume = g_strdup(pool);
    src->path = g_strdup(image);
    src->snapshot = g_strdup(snapshot);
    src->configFile = g_strdup(conf);

    if (servers) {
        nservers = virJSONValueArraySize(servers);

        src->hosts = g_new0(virStorageNetHostDef, nservers);
        src->nhosts = nservers;

        for (i = 0; i < nservers; i++) {
            if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts + i,
                                                                  virJSONValueArrayGet(servers, i)) < 0)
                return -1;
        }
    }

    return 0;
}

static int
virStorageSourceParseBackingJSONRaw(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr,
                                    int opaque G_GNUC_UNUSED)
{
    bool has_offset = virJSONValueObjectHasKey(json, "offset");
    bool has_size = virJSONValueObjectHasKey(json, "size");
    virJSONValue *file;

    if (has_offset || has_size) {
        src->sliceStorage = g_new0(virStorageSourceSlice, 1);

        if (has_offset &&
            virJSONValueObjectGetNumberUlong(json, "offset", &src->sliceStorage->offset) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("malformed 'offset' property of 'raw' driver"));
            return -1;
        }

        if (has_size &&
            virJSONValueObjectGetNumberUlong(json, "size", &src->sliceStorage->size) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("malformed 'size' property of 'raw' driver"));
            return -1;
        }
    }

    /* 'raw' is a format driver so it can have protocol driver children */
    if (!(file = virJSONValueObjectGetObject(json, "file"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume definition '%1$s' lacks 'file' object"),
                       jsonstr);
        return -1;
    }

    return virStorageSourceParseBackingJSONInternal(src, file, jsonstr, false);
}


static int
virStorageSourceParseBackingJSONVxHS(virStorageSource *src,
                                     virJSONValue *json,
                                     const char *jsonstr G_GNUC_UNUSED,
                                     int opaque G_GNUC_UNUSED)
{
    const char *vdisk_id = virJSONValueObjectGetString(json, "vdisk-id");
    virJSONValue *server = virJSONValueObjectGetObject(json, "server");

    if (!vdisk_id || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'vdisk-id' or 'server' attribute in JSON backing definition for VxHS volume"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_VXHS;

    src->path = g_strdup(vdisk_id);

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts,
                                                          server) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONNFS(virStorageSource *src,
                                    virJSONValue *json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    virJSONValue *server = virJSONValueObjectGetObject(json, "server");
    int uidStore = -1;
    int gidStore = -1;
    int gotUID = virJSONValueObjectGetNumberInt(json, "user", &uidStore);
    int gotGID = virJSONValueObjectGetNumberInt(json, "group", &gidStore);

    if (!server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'server' attribute in JSON backing definition for NFS volume"));
        return -1;
    }

    if (gotUID < 0 || gotGID < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'user' or 'group' attribute in JSON backing definition for NFS volume"));
        return -1;
    }

    src->path = g_strdup(virJSONValueObjectGetString(json, "path"));
    if (!src->path) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'path' attribute in JSON backing definition for NFS volume"));
        return -1;
    }

    src->nfs_user = g_strdup_printf("+%d", uidStore);
    src->nfs_group = g_strdup_printf("+%d", gidStore);

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_NFS;

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (virStorageSourceParseBackingJSONInetSocketAddress(src->hosts,
                                                          server) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONNVMe(virStorageSource *src,
                                     virJSONValue *json,
                                     const char *jsonstr G_GNUC_UNUSED,
                                     int opaque G_GNUC_UNUSED)
{
    g_autoptr(virStorageSourceNVMeDef) nvme = g_new0(virStorageSourceNVMeDef, 1);
    const char *device = virJSONValueObjectGetString(json, "device");

    if (!device || virPCIDeviceAddressParse((char *) device, &nvme->pciAddr) < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing or malformed 'device' field of 'nvme' storage"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(json, "namespace", &nvme->namespc) < 0 ||
        nvme->namespc == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing or malformed 'namespace' field of 'nvme' storage"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NVME;
    src->nvme = g_steal_pointer(&nvme);

    return 0;
}


struct virStorageSourceJSONDriverParser {
    const char *drvname;
    bool formatdriver;
    /**
     * The callback gets a pre-allocated storage source @src and the JSON
     * object to parse. The callback shall return -1 on error and report error
     * 0 on success and 1 in cases when the configuration itself is valid, but
     * can't be converted to libvirt's configuration (e.g. inline authentication
     * credentials are present).
     */
    int (*func)(virStorageSource *src, virJSONValue *json, const char *jsonstr, int opaque);
    int opaque;
};

static const struct virStorageSourceJSONDriverParser jsonParsers[] = {
    {"file", false, virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_FILE},
    {"host_device", false, virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_BLOCK},
    {"host_cdrom", false, virStorageSourceParseBackingJSONPath, VIR_STORAGE_TYPE_BLOCK},
    {"http", false, virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_HTTP},
    {"https", false, virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_HTTPS},
    {"ftp", false, virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_FTP},
    {"ftps", false, virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_FTPS},
    {"tftp", false, virStorageSourceParseBackingJSONUri, VIR_STORAGE_NET_PROTOCOL_TFTP},
    {"gluster", false, virStorageSourceParseBackingJSONGluster, 0},
    {"iscsi", false, virStorageSourceParseBackingJSONiSCSI, 0},
    {"nbd", false, virStorageSourceParseBackingJSONNbd, 0},
    {"sheepdog", false, virStorageSourceParseBackingJSONSheepdog, 0},
    {"ssh", false, virStorageSourceParseBackingJSONSSH, 0},
    {"rbd", false, virStorageSourceParseBackingJSONRBD, 0},
    {"raw", true, virStorageSourceParseBackingJSONRaw, 0},
    {"nfs", false, virStorageSourceParseBackingJSONNFS, 0},
    {"vxhs", false, virStorageSourceParseBackingJSONVxHS, 0},
    {"nvme", false, virStorageSourceParseBackingJSONNVMe, 0},
};



static int
virStorageSourceParseBackingJSONInternal(virStorageSource *src,
                                         virJSONValue *json,
                                         const char *jsonstr,
                                         bool allowformat)
{
    const char *drvname;
    size_t i;

    if (!(drvname = virJSONValueObjectGetString(json, "driver"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume definition '%1$s' lacks driver name"),
                       jsonstr);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(jsonParsers); i++) {
        if (STRNEQ(drvname, jsonParsers[i].drvname))
            continue;

        if (jsonParsers[i].formatdriver && !allowformat) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("JSON backing volume definition '%1$s' must not have nested format drivers"),
                           jsonstr);
            return -1;
        }

        return jsonParsers[i].func(src, json, jsonstr, jsonParsers[i].opaque);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing parser implementation for JSON backing volume driver '%1$s'"),
                   drvname);
    return -1;
}


int
virStorageSourceParseBackingJSON(virStorageSource *src,
                                 const char *json)
{
    g_autoptr(virJSONValue) root = NULL;
    g_autoptr(virJSONValue) deflattened = NULL;
    virJSONValue *file = NULL;

    if (!(root = virJSONValueFromString(json)))
        return -1;

    if (!(deflattened = virJSONValueObjectDeflatten(root)))
        return -1;

    /* There are 2 possible syntaxes:
     * 1) json:{"file":{"driver":...}}
     * 2) json:{"driver":...}
     * Remove the 'file' wrapper object in case 1.
     */
    if (!virJSONValueObjectHasKey(deflattened, "driver"))
        file = virJSONValueObjectGetObject(deflattened, "file");

    if (!file)
        file = deflattened;

    return virStorageSourceParseBackingJSONInternal(src, file, json, true);
}
