/*
 * storage_source.c: file utility functions for FS storage backend
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

#include <sys/types.h>
#include <unistd.h>

#include "internal.h"
#include "storage_file_backend.h"
#include "storage_file_probe.h"
#include "storage_source.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virjson.h"
#include "virlog.h"
#include "virobject.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "viruri.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage_source");


static virStorageSourcePtr
virStorageFileMetadataNew(const char *path,
                          int format)
{
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    def->format = format;
    def->type = VIR_STORAGE_TYPE_FILE;

    def->path = g_strdup(path);

    return g_steal_pointer(&def);
}


/**
 * virStorageFileGetMetadataFromBuf:
 * @path: name of file, for error messages
 * @buf: header bytes from @path
 * @len: length of @buf
 * @format: format of the storage file
 *
 * Extract metadata about the storage volume with the specified image format.
 * If image format is VIR_STORAGE_FILE_AUTO, it will probe to automatically
 * identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a format on a file
 * that might be raw if that file will then be passed to a guest, since a
 * malicious guest can turn a raw file into any other non-raw format at will.
 *
 * If the 'backingStoreRawFormat' field of the returned structure is
 * VIR_STORAGE_FILE_AUTO it indicates the image didn't specify an explicit
 * format for its backing store. Callers are advised against probing for the
 * backing store format in this case.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromBuf(const char *path,
                                 char *buf,
                                 size_t len,
                                 int format)
{
    virStorageSourcePtr ret = NULL;

    if (!(ret = virStorageFileMetadataNew(path, format)))
        return NULL;

    if (virStorageFileProbeGetMetadata(ret, buf, len) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    return ret;
}


/**
 * virStorageFileGetMetadataFromFD:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Does not recurse.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * Caller MUST free the result after use via virObjectUnref.
 */
virStorageSourcePtr
virStorageFileGetMetadataFromFD(const char *path,
                                int fd,
                                int format)

{
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    struct stat sb;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) meta = NULL;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"), path);
        return NULL;
    }

    if (!(meta = virStorageFileMetadataNew(path, format)))
        return NULL;

    if (S_ISDIR(sb.st_mode)) {
        /* No header to probe for directories, but also no backing file. Just
         * update the metadata.*/
        meta->type = VIR_STORAGE_TYPE_DIR;
        meta->format = VIR_STORAGE_FILE_DIR;
        return g_steal_pointer(&meta);
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        virReportSystemError(errno, _("cannot seek to start of '%s'"), meta->path);
        return NULL;
    }

    if ((len = virFileReadHeaderFD(fd, len, &buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), meta->path);
        return NULL;
    }

    if (virStorageFileProbeGetMetadata(meta, buf, len) < 0)
        return NULL;

    if (S_ISREG(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_FILE;
    else if (S_ISBLK(sb.st_mode))
        meta->type = VIR_STORAGE_TYPE_BLOCK;

    return g_steal_pointer(&meta);
}


/* Given a @chain, look for the backing store @name that is a backing file
 * of @startFrom (or any member of @chain if @startFrom is NULL) and return
 * that location within the chain.  @chain must always point to the top of
 * the chain.  Pass NULL for @name and 0 for @idx to find the base of the
 * chain.  Pass nonzero @idx to find the backing source according to its
 * position in the backing chain.  If @parent is not NULL, set *@parent to
 * the preferred name of the parent (or to NULL if @name matches the start
 * of the chain).  Since the results point within @chain, they must not be
 * independently freed. Reports an error and returns NULL if @name is not
 * found.
 */
virStorageSourcePtr
virStorageFileChainLookup(virStorageSourcePtr chain,
                          virStorageSourcePtr startFrom,
                          const char *name,
                          unsigned int idx,
                          virStorageSourcePtr *parent)
{
    virStorageSourcePtr prev;
    const char *start = chain->path;
    bool nameIsFile = virStorageIsFile(name);

    if (!parent)
        parent = &prev;
    *parent = NULL;

    if (startFrom) {
        while (virStorageSourceIsBacking(chain) &&
               chain != startFrom->backingStore)
            chain = chain->backingStore;

        *parent = startFrom;
    }

    while (virStorageSourceIsBacking(chain)) {
        if (!name && !idx) {
            if (!virStorageSourceHasBacking(chain))
                break;
        } else if (idx) {
            VIR_DEBUG("%u: %s", chain->id, chain->path);
            if (idx == chain->id)
                break;
        } else {
            if (STREQ_NULLABLE(name, chain->relPath) ||
                STREQ_NULLABLE(name, chain->path))
                break;

            if (nameIsFile && virStorageSourceIsLocalStorage(chain)) {
                g_autofree char *parentDir = NULL;
                int result;

                if (*parent && virStorageSourceIsLocalStorage(*parent))
                    parentDir = g_path_get_dirname((*parent)->path);
                else
                    parentDir = g_strdup(".");

                result = virFileRelLinkPointsTo(parentDir, name,
                                                chain->path);

                if (result < 0)
                    goto error;

                if (result > 0)
                    break;
            }
        }
        *parent = chain;
        chain = chain->backingStore;
    }

    if (!virStorageSourceIsBacking(chain))
        goto error;

    return chain;

 error:
    if (idx) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find backing store index %u in chain "
                         "for '%s'"),
                       idx, NULLSTR(start));
    } else if (name) {
        if (startFrom)
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%s' beneath '%s' in "
                             "chain for '%s'"), name, NULLSTR(startFrom->path),
                           NULLSTR(start));
        else
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not find image '%s' in chain for '%s'"),
                           name, NULLSTR(start));
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find base image in chain for '%s'"),
                       NULLSTR(start));
    }
    *parent = NULL;
    return NULL;
}


static virStorageSourcePtr
virStorageSourceNewFromBackingRelative(virStorageSourcePtr parent,
                                       const char *rel)
{
    g_autofree char *dirname = NULL;
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    /* store relative name */
    def->relPath = g_strdup(rel);

    dirname = g_path_get_dirname(parent->path);

    if (STRNEQ(dirname, "/")) {
        def->path = g_strdup_printf("%s/%s", dirname, rel);
    } else {
        def->path = g_strdup_printf("/%s", rel);
    }

    if (virStorageSourceGetActualType(parent) == VIR_STORAGE_TYPE_NETWORK) {
        def->type = VIR_STORAGE_TYPE_NETWORK;

        /* copy the host network part */
        def->protocol = parent->protocol;
        if (parent->nhosts) {
            if (!(def->hosts = virStorageNetHostDefCopy(parent->nhosts,
                                                        parent->hosts)))
                return NULL;

            def->nhosts = parent->nhosts;
        }

        def->volume = g_strdup(parent->volume);
    } else {
        /* set the type to _FILE, the caller shall update it to the actual type */
        def->type = VIR_STORAGE_TYPE_FILE;
    }

    return g_steal_pointer(&def);
}


static int
virStorageSourceParseBackingURI(virStorageSourcePtr src,
                                const char *uristr)
{
    g_autoptr(virURI) uri = NULL;
    const char *path = NULL;
    g_auto(GStrv) scheme = NULL;

    if (!(uri = virURIParse(uristr))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse backing file location '%s'"),
                       uristr);
        return -1;
    }

    src->hosts = g_new0(virStorageNetHostDef, 1);
    src->nhosts = 1;

    if (!(scheme = virStringSplit(uri->scheme, "+", 2)))
        return -1;

    if (!scheme[0] ||
        (src->protocol = virStorageNetProtocolTypeFromString(scheme[0])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
                       NULLSTR(scheme[0]));
        return -1;
    }

    if (scheme[1] &&
        (src->hosts->transport = virStorageNetHostTransportTypeFromString(scheme[1])) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid protocol transport type '%s'"),
                       scheme[1]);
        return -1;
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
    if (path[0] == '/')
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
                           _("missing volume name or file name in "
                             "gluster source path '%s'"), src->path);
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
virStorageSourceRBDAddHost(virStorageSourcePtr src,
                           char *hostport)
{
    char *port;
    size_t skip;
    g_auto(GStrv) parts = NULL;

    if (VIR_EXPAND_N(src->hosts, src->nhosts, 1) < 0)
        return -1;

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

    parts = virStringSplit(hostport, "\\:", 0);
    if (!parts)
        goto error;
    src->hosts[src->nhosts-1].name = virStringListJoin((const char **)parts, ":");
    if (!src->hosts[src->nhosts-1].name)
        goto error;

    src->hosts[src->nhosts-1].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    src->hosts[src->nhosts-1].socket = NULL;

    return 0;

 error:
    VIR_FREE(src->hosts[src->nhosts-1].name);
    return -1;
}


int
virStorageSourceParseRBDColonString(const char *rbdstr,
                                    virStorageSourcePtr src)
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
                               _("duplicate 'id' found in '%s'"), src->path);
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
                                    virStorageSourcePtr src)
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
                   _("malformed nbd string '%s'"), nbdstr);
    return -1;
}


static int
virStorageSourceParseBackingColon(virStorageSourcePtr src,
                                  const char *path)
{
    const char *p;
    g_autofree char *protocol = NULL;

    if (!(p = strchr(path, ':'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol string '%s'"),
                       path);
        return -1;
    }

    protocol = g_strndup(path, p - path);

    if ((src->protocol = virStorageNetProtocolTypeFromString(protocol)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid backing protocol '%s'"),
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
                       _("backing store parser is not implemented for protocol %s"),
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
                       _("malformed backing store path for protocol %s"),
                       protocol);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONInternal(virStorageSourcePtr src,
                                         virJSONValuePtr json,
                                         const char *jsonstr,
                                         bool allowformat);


static int
virStorageSourceParseBackingJSONPath(virStorageSourcePtr src,
                                     virJSONValuePtr json,
                                     const char *jsonstr G_GNUC_UNUSED,
                                     int type)
{
    const char *path;

    if (!(path = virJSONValueObjectGetString(json, "filename"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'filename' field in JSON backing volume "
                         "definition"));
        return -1;
    }

    src->path = g_strdup(path);

    src->type = type;
    return 0;
}


static int
virStorageSourceParseBackingJSONUriStr(virStorageSourcePtr src,
                                       const char *uri,
                                       int protocol)
{
    int rc;

    if ((rc = virStorageSourceParseBackingURI(src, uri)) < 0)
        return -1;

    if (src->protocol != protocol) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("expected protocol '%s' but got '%s' in URI JSON volume "
                         "definition"),
                       virStorageNetProtocolTypeToString(protocol),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -1;
    }

    return rc;
}


static int
virStorageSourceParseBackingJSONUriCookies(virStorageSourcePtr src,
                                           virJSONValuePtr json,
                                           const char *jsonstr)
{
    const char *cookiestr;
    g_auto(GStrv) cookies = NULL;
    size_t ncookies = 0;
    size_t i;

    if (!virJSONValueObjectHasKey(json, "cookie"))
        return 0;

    if (!(cookiestr = virJSONValueObjectGetString(json, "cookie"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("wrong format of 'cookie' field in backing store definition '%s'"),
                       jsonstr);
        return -1;
    }

    if (!(cookies = virStringSplitCount(cookiestr, ";", 0, &ncookies)))
        return -1;

    src->cookies = g_new0(virStorageNetCookieDefPtr, ncookies);
    src->ncookies = ncookies;

    for (i = 0; i < ncookies; i++) {
        char *cookiename = cookies[i];
        char *cookievalue;

        virSkipSpaces((const char **) &cookiename);

        if (!(cookievalue = strchr(cookiename, '='))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("malformed http cookie '%s' in backing store definition '%s'"),
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
virStorageSourceParseBackingJSONUri(virStorageSourcePtr src,
                                    virJSONValuePtr json,
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
                                   _("malformed 'sslverify' field in backing store definition '%s'"),
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
                       _("malformed 'readahead' field in backing store definition '%s'"),
                       jsonstr);
        return -1;
    }

    if (virJSONValueObjectHasKey(json, "timeout") &&
        virJSONValueObjectGetNumberUlong(json, "timeout", &src->timeout) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("malformed 'timeout' field in backing store definition '%s'"),
                       jsonstr);
        return -1;
    }

    return virStorageSourceParseBackingJSONUriStr(src, uri, protocol);
}


static int
virStorageSourceParseBackingJSONInetSocketAddress(virStorageNetHostDefPtr host,
                                                  virJSONValuePtr json)
{
    const char *hostname;
    const char *port;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON "
                         "backing volume definition"));
        return -1;
    }

    hostname = virJSONValueObjectGetString(json, "host");
    port = virJSONValueObjectGetString(json, "port");

    if (!hostname) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing hostname for tcp backing server in "
                         "JSON backing volume definition"));
        return -1;
    }

    host->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    host->name = g_strdup(hostname);

    if (virStringParsePort(port, &host->port) < 0)
        return -1;

    return 0;
}


static int
virStorageSourceParseBackingJSONSocketAddress(virStorageNetHostDefPtr host,
                                              virJSONValuePtr json)
{
    const char *type;
    const char *socket;

    if (!json) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing remote server specification in JSON "
                         "backing volume definition"));
        return -1;
    }

    if (!(type = virJSONValueObjectGetString(json, "type"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing socket address type in "
                         "JSON backing volume definition"));
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
                           _("missing socket path for udp backing server in "
                             "JSON backing volume definition"));
            return -1;
        }

        host->socket = g_strdup(socket);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store protocol '%s' is not yet supported"),
                       type);
        return -1;
    }

    return 0;
}


static int
virStorageSourceParseBackingJSONGluster(virStorageSourcePtr src,
                                        virJSONValuePtr json,
                                        const char *jsonstr G_GNUC_UNUSED,
                                        int opaque G_GNUC_UNUSED)
{
    const char *uri = virJSONValueObjectGetString(json, "filename");
    const char *volume = virJSONValueObjectGetString(json, "volume");
    const char *path = virJSONValueObjectGetString(json, "path");
    virJSONValuePtr server = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;

    /* legacy URI based syntax passed via 'filename' option */
    if (uri)
        return virStorageSourceParseBackingJSONUriStr(src, uri,
                                                      VIR_STORAGE_NET_PROTOCOL_GLUSTER);

    if (!volume || !path || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'volume', 'path' or 'server' attribute in "
                         "JSON backing definition for gluster volume"));
        return -1;
    }

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;

    src->volume = g_strdup(volume);
    src->path = g_strdup(path);

    nservers = virJSONValueArraySize(server);
    if (nservers == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("at least 1 server is necessary in "
                         "JSON backing definition for gluster volume"));

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
virStorageSourceParseBackingJSONiSCSI(virStorageSourcePtr src,
                                      virJSONValuePtr json,
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
virStorageSourceParseBackingJSONNbd(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    const char *export = virJSONValueObjectGetString(json, "export");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!path && !host && !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host specification of NBD server in JSON "
                         "backing volume definition"));
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
virStorageSourceParseBackingJSONSheepdog(virStorageSourcePtr src,
                                         virJSONValuePtr json,
                                         const char *jsonstr G_GNUC_UNUSED,
                                         int opaque G_GNUC_UNUSED)
{
    const char *filename;
    const char *vdi = virJSONValueObjectGetString(json, "vdi");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

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
virStorageSourceParseBackingJSONSSH(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *path = virJSONValueObjectGetString(json, "path");
    const char *host = virJSONValueObjectGetString(json, "host");
    const char *port = virJSONValueObjectGetString(json, "port");
    const char *user = virJSONValueObjectGetString(json, "user");
    const char *host_key_check = virJSONValueObjectGetString(json, "host_key_check");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!(host || server) || !path) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing host/server or path of SSH JSON backing "
                         "volume definition"));
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
virStorageSourceParseBackingJSONRBD(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    const char *filename;
    const char *pool = virJSONValueObjectGetString(json, "pool");
    const char *image = virJSONValueObjectGetString(json, "image");
    const char *conf = virJSONValueObjectGetString(json, "conf");
    const char *snapshot = virJSONValueObjectGetString(json, "snapshot");
    virJSONValuePtr servers = virJSONValueObjectGetArray(json, "server");
    size_t nservers;
    size_t i;

    src->type = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;

    /* legacy syntax passed via 'filename' option */
    if ((filename = virJSONValueObjectGetString(json, "filename")))
        return virStorageSourceParseRBDColonString(filename, src);

    if (!pool || !image) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing pool or image name in ceph backing volume "
                         "JSON specification"));
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
virStorageSourceParseBackingJSONRaw(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    const char *jsonstr,
                                    int opaque G_GNUC_UNUSED)
{
    bool has_offset = virJSONValueObjectHasKey(json, "offset");
    bool has_size = virJSONValueObjectHasKey(json, "size");
    virJSONValuePtr file;

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
                       _("JSON backing volume definition '%s' lacks 'file' object"),
                       jsonstr);
        return -1;
    }

    return virStorageSourceParseBackingJSONInternal(src, file, jsonstr, false);
}


static int
virStorageSourceParseBackingJSONVxHS(virStorageSourcePtr src,
                                     virJSONValuePtr json,
                                     const char *jsonstr G_GNUC_UNUSED,
                                     int opaque G_GNUC_UNUSED)
{
    const char *vdisk_id = virJSONValueObjectGetString(json, "vdisk-id");
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");

    if (!vdisk_id || !server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("missing 'vdisk-id' or 'server' attribute in "
                         "JSON backing definition for VxHS volume"));
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
virStorageSourceParseBackingJSONNFS(virStorageSourcePtr src,
                                    virJSONValuePtr json,
                                    const char *jsonstr G_GNUC_UNUSED,
                                    int opaque G_GNUC_UNUSED)
{
    virJSONValuePtr server = virJSONValueObjectGetObject(json, "server");
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
virStorageSourceParseBackingJSONNVMe(virStorageSourcePtr src,
                                     virJSONValuePtr json,
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
    int (*func)(virStorageSourcePtr src, virJSONValuePtr json, const char *jsonstr, int opaque);
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
virStorageSourceParseBackingJSONInternal(virStorageSourcePtr src,
                                         virJSONValuePtr json,
                                         const char *jsonstr,
                                         bool allowformat)
{
    const char *drvname;
    size_t i;

    if (!(drvname = virJSONValueObjectGetString(json, "driver"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("JSON backing volume definition '%s' lacks driver name"),
                       jsonstr);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(jsonParsers); i++) {
        if (STRNEQ(drvname, jsonParsers[i].drvname))
            continue;

        if (jsonParsers[i].formatdriver && !allowformat) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("JSON backing volume definition '%s' must not have nested format drivers"),
                           jsonstr);
            return -1;
        }

        return jsonParsers[i].func(src, json, jsonstr, jsonParsers[i].opaque);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing parser implementation for JSON backing volume "
                     "driver '%s'"), drvname);
    return -1;
}


static int
virStorageSourceParseBackingJSON(virStorageSourcePtr src,
                                 const char *json)
{
    g_autoptr(virJSONValue) root = NULL;
    g_autoptr(virJSONValue) deflattened = NULL;
    virJSONValuePtr file = NULL;

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


/**
 * virStorageSourceNewFromBackingAbsolute
 * @path: string representing absolute location of a storage source
 * @src: filled with virStorageSource object representing @path
 *
 * Returns 0 on success, 1 if we could parse all location data but @path
 * specified other data unrepresentable by libvirt (e.g. inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
int
virStorageSourceNewFromBackingAbsolute(const char *path,
                                       virStorageSourcePtr *src)
{
    const char *json;
    const char *dirpath;
    int rc = 0;
    g_autoptr(virStorageSource) def = virStorageSourceNew();

    *src = NULL;

    if (virStorageIsFile(path)) {
        def->type = VIR_STORAGE_TYPE_FILE;

        def->path = g_strdup(path);
    } else {
        if ((dirpath = STRSKIP(path, "fat:"))) {
            def->type = VIR_STORAGE_TYPE_DIR;
            def->format = VIR_STORAGE_FILE_FAT;
            def->path = g_strdup(dirpath);
            *src = g_steal_pointer(&def);
            return 0;
        }

        def->type = VIR_STORAGE_TYPE_NETWORK;

        VIR_DEBUG("parsing backing store string: '%s'", path);

        /* handle URI formatted backing stores */
        if ((json = STRSKIP(path, "json:")))
            rc = virStorageSourceParseBackingJSON(def, json);
        else if (strstr(path, "://"))
            rc = virStorageSourceParseBackingURI(def, path);
        else
            rc = virStorageSourceParseBackingColon(def, path);

        if (rc < 0)
            return -1;

        virStorageSourceNetworkAssignDefaultPorts(def);

        /* Some of the legacy parsers parse authentication data since they are
         * also used in other places. For backing store detection the
         * authentication data would be invalid anyways, so we clear it */
        if (def->auth) {
            virStorageAuthDefFree(def->auth);
            def->auth = NULL;
        }
    }

    *src = g_steal_pointer(&def);
    return rc;
}


/**
 * virStorageSourceNewFromChild:
 * @parent: storage source parent
 * @child: returned child/backing store definition
 * @parentRaw: raw child string (backingStoreRaw)
 *
 * Creates a storage source which describes the backing image of @parent and
 * fills it into @backing depending on the passed parentRaw (backingStoreRaw)
 * and other data. Note that for local storage this function accesses the file
 * to update the actual type of the child store.
 *
 * Returns 0 on success, 1 if we could parse all location data but the child
 * store specification contained other data unrepresentable by libvirt (e.g.
 * inline authentication).
 * In both cases @src is filled. On error -1 is returned @src is NULL and an
 * error is reported.
 */
static int
virStorageSourceNewFromChild(virStorageSourcePtr parent,
                             const char *parentRaw,
                             virStorageSourcePtr *child)
{
    struct stat st;
    g_autoptr(virStorageSource) def = NULL;
    int rc = 0;

    *child = NULL;

    if (virStorageIsRelative(parentRaw)) {
        if (!(def = virStorageSourceNewFromBackingRelative(parent, parentRaw)))
            return -1;
    } else {
        if ((rc = virStorageSourceNewFromBackingAbsolute(parentRaw, &def)) < 0)
            return -1;
    }

    /* possibly update local type */
    if (def->type == VIR_STORAGE_TYPE_FILE) {
        if (stat(def->path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_DIR;
                def->format = VIR_STORAGE_FILE_DIR;
            } else if (S_ISBLK(st.st_mode)) {
                def->type = VIR_STORAGE_TYPE_BLOCK;
            }
        }
    }

    /* copy parent's labelling and other top level stuff */
    if (virStorageSourceInitChainElement(def, parent, true) < 0)
        return -1;

    def->detected = true;

    *child = g_steal_pointer(&def);
    return rc;
}


int
virStorageSourceNewFromBacking(virStorageSourcePtr parent,
                               virStorageSourcePtr *backing)
{
    int rc;

    if ((rc = virStorageSourceNewFromChild(parent,
                                           parent->backingStoreRaw,
                                           backing)) < 0)
        return rc;

    (*backing)->format = parent->backingStoreRawFormat;
    (*backing)->readonly = true;
    return rc;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Updates src->physical depending on the actual type of storage being used.
 * To be called for domain storage source reporting as the volume code does
 * not set/use the 'type' field for the voldef->source.target
 *
 * Returns 0 on success, -1 on error. No libvirt errors are reported.
 */
int
virStorageSourceUpdatePhysicalSize(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb)
{
    off_t end;
    virStorageType actual_type = virStorageSourceGetActualType(src);

    switch (actual_type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_NETWORK:
        src->physical = sb->st_size;
        break;

    case VIR_STORAGE_TYPE_BLOCK:
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1)
            return -1;

        src->physical = end;
        break;

    case VIR_STORAGE_TYPE_DIR:
        src->physical = 0;
        break;

    /* We shouldn't get VOLUME, but the switch requires all cases */
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return -1;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @fd: file descriptor
 * @sb: stat buffer
 *
 * Update the capacity, allocation, physical values for the storage @src
 * Shared between the domain storage source for an inactive domain and the
 * voldef source target as the result is not affected by the 'type' field.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateBackingSizes(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb)
{
    /* Get info for normal formats */
    if (S_ISREG(sb->st_mode) || fd == -1) {
#ifndef WIN32
        src->allocation = (unsigned long long)sb->st_blocks *
            (unsigned long long)DEV_BSIZE;
#else
        src->allocation = sb->st_size;
#endif
        /* Regular files may be sparse, so logical size (capacity) is not same
         * as actual allocation above
         */
        src->capacity = sb->st_size;

        /* Allocation tracks when the file is sparse, physical is the
         * last offset of the file. */
        src->physical = sb->st_size;
    } else if (S_ISDIR(sb->st_mode)) {
        src->allocation = 0;
        src->capacity = 0;
        src->physical = 0;
    } else if (fd >= 0) {
        off_t end;

        /* XXX this is POSIX compliant, but doesn't work for CHAR files,
         * only BLOCK. There is a Linux specific ioctl() for getting
         * size of both CHAR / BLOCK devices we should check for in
         * configure
         *
         * NB. Because we configure with AC_SYS_LARGEFILE, off_t
         * should be 64 bits on all platforms.  For block devices, we
         * have to seek (safe even if someone else is writing) to
         * determine physical size, and assume that allocation is the
         * same as physical (but can refine that assumption later if
         * qemu is still running).
         */
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t)-1) {
            virReportSystemError(errno,
                                 _("failed to seek to end of %s"), src->path);
            return -1;
        }
        src->physical = end;
        src->allocation = end;
        src->capacity = end;
    }

    return 0;
}


/**
 * @src: disk source definition structure
 * @buf: buffer to the storage file header
 * @len: length of the storage file header
 *
 * Update the storage @src capacity.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStorageSourceUpdateCapacity(virStorageSourcePtr src,
                               char *buf,
                               ssize_t len)
{
    int format = src->format;
    g_autoptr(virStorageSource) meta = NULL;

    /* Raw files: capacity is physical size.  For all other files: if
     * the metadata has a capacity, use that, otherwise fall back to
     * physical size.  */
    if (format == VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no disk format for %s was specified"),
                       src->path);
        return -1;
    }

    if (format == VIR_STORAGE_FILE_RAW && !src->encryption) {
        src->capacity = src->physical;
    } else if ((meta = virStorageFileGetMetadataFromBuf(src->path, buf,
                                                        len, format))) {
        src->capacity = meta->capacity ? meta->capacity : src->physical;
        if (src->encryption && meta->encryption)
            src->encryption->payload_offset = meta->encryption->payload_offset;
    } else {
        return -1;
    }

    if (src->encryption && src->encryption->payload_offset != -1)
        src->capacity -= src->encryption->payload_offset * 512;

    return 0;
}


/**
 * virStorageFileRemoveLastPathComponent:
 *
 * @path: Path string to remove the last component from
 *
 * Removes the last path component of a path. This function is designed to be
 * called on file paths only (no trailing slashes in @path). Caller is
 * responsible to free the returned string.
 */
static char *
virStorageFileRemoveLastPathComponent(const char *path)
{
    char *ret;

    ret = g_strdup(NULLSTR_EMPTY(path));

    virFileRemoveLastComponent(ret);

    return ret;
}


/*
 * virStorageFileGetRelativeBackingPath:
 *
 * Resolve relative path to be written to the overlay of @top image when
 * collapsing the backing chain between @top and @base.
 *
 * Returns 0 on success; 1 if backing chain isn't relative and -1 on error.
 */
int
virStorageFileGetRelativeBackingPath(virStorageSourcePtr top,
                                     virStorageSourcePtr base,
                                     char **relpath)
{
    virStorageSourcePtr next;
    g_autofree char *tmp = NULL;
    g_autofree char *path = NULL;

    *relpath = NULL;

    for (next = top; virStorageSourceIsBacking(next); next = next->backingStore) {
        if (!next->relPath)
            return 1;

        if (!(tmp = virStorageFileRemoveLastPathComponent(path)))
            return -1;

        VIR_FREE(path);

        path = g_strdup_printf("%s%s", tmp, next->relPath);

        VIR_FREE(tmp);

        if (next == base)
            break;
    }

    if (next != base) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to resolve relative backing name: "
                         "base image is not in backing chain"));
        return -1;
    }

    *relpath = g_steal_pointer(&path);
    return 0;
}


static bool
virStorageFileIsInitialized(const virStorageSource *src)
{
    return src && src->drv;
}


/**
 * virStorageFileGetBackendForSupportCheck:
 * @src: storage source to check support for
 * @backend: pointer to the storage backend for @src if it's supported
 *
 * Returns 0 if @src is not supported by any storage backend currently linked
 * 1 if it is supported and -1 on error with an error reported.
 */
static int
virStorageFileGetBackendForSupportCheck(const virStorageSource *src,
                                        virStorageFileBackendPtr *backend)
{
    int actualType;


    if (!src) {
        *backend = NULL;
        return 0;
    }

    if (src->drv) {
        virStorageDriverDataPtr drv = src->drv;
        *backend = drv->backend;
        return 1;
    }

    actualType = virStorageSourceGetActualType(src);

    if (virStorageFileBackendForType(actualType, src->protocol, false, backend) < 0)
        return -1;

    if (!*backend)
        return 0;

    return 1;
}


int
virStorageFileSupportsBackingChainTraversal(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileGetUniqueIdentifier &&
           backend->storageFileRead &&
           backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageFileSupportsSecurityDriver:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports operations needed by the security
 * driver to perform labelling
 */
int
virStorageFileSupportsSecurityDriver(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileChown ? 1 : 0;
}


/**
 * virStorageFileSupportsAccess:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports checking if the storage source is accessible
 * for the given vm.
 */
int
virStorageFileSupportsAccess(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileAccess ? 1 : 0;
}


/**
 * virStorageFileSupportsCreate:
 * @src: a storage file structure
 *
 * Check if the storage driver supports creating storage described by @src
 * via virStorageFileCreate.
 */
int
virStorageFileSupportsCreate(const virStorageSource *src)
{
    virStorageFileBackendPtr backend;
    int rv;

    if ((rv = virStorageFileGetBackendForSupportCheck(src, &backend)) < 1)
        return rv;

    return backend->storageFileCreate ? 1 : 0;
}


void
virStorageFileDeinit(virStorageSourcePtr src)
{
    virStorageDriverDataPtr drv = NULL;

    if (!virStorageFileIsInitialized(src))
        return;

    drv = src->drv;

    if (drv->backend &&
        drv->backend->backendDeinit)
        drv->backend->backendDeinit(src);

    VIR_FREE(src->drv);
}


/**
 * virStorageFileInitAs:
 *
 * @src: storage source definition
 * @uid: uid used to access the file, or -1 for current uid
 * @gid: gid used to access the file, or -1 for current gid
 *
 * Initialize a storage source to be used with storage driver. Use the provided
 * uid and gid if possible for the operations.
 *
 * Returns 0 if the storage file was successfully initialized, -1 if the
 * initialization failed. Libvirt error is reported.
 */
int
virStorageFileInitAs(virStorageSourcePtr src,
                     uid_t uid, gid_t gid)
{
    int actualType = virStorageSourceGetActualType(src);
    virStorageDriverDataPtr drv = g_new0(virStorageDriverData, 1);

    src->drv = drv;

    if (uid == (uid_t) -1)
        drv->uid = geteuid();
    else
        drv->uid = uid;

    if (gid == (gid_t) -1)
        drv->gid = getegid();
    else
        drv->gid = gid;

    if (virStorageFileBackendForType(actualType,
                                     src->protocol,
                                     true,
                                     &drv->backend) < 0)
        goto error;

    if (drv->backend->backendInit &&
        drv->backend->backendInit(src) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(src->drv);
    return -1;
}


/**
 * virStorageFileInit:
 *
 * See virStorageFileInitAs. The file is initialized to be accessed by the
 * current user.
 */
int
virStorageFileInit(virStorageSourcePtr src)
{
    return virStorageFileInitAs(src, -1, -1);
}


/**
 * virStorageFileCreate: Creates an empty storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileCreate(virStorageSourcePtr src)
{
    virStorageDriverDataPtr drv = NULL;
    int ret;

    if (!virStorageFileIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileCreate(src);

    VIR_DEBUG("created storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileUnlink: Unlink storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileUnlink(virStorageSourcePtr src)
{
    virStorageDriverDataPtr drv = NULL;
    int ret;

    if (!virStorageFileIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileUnlink(src);

    VIR_DEBUG("unlinked storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileStat: returns stat struct of a file via storage driver
 *
 * @src: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageFileStat(virStorageSourcePtr src,
                   struct stat *st)
{
    virStorageDriverDataPtr drv = NULL;
    int ret;

    if (!virStorageFileIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileStat) {
        errno = ENOSYS;
        return -2;
    }

    ret = drv->backend->storageFileStat(src, st);

    VIR_DEBUG("stat of storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileRead: read bytes from a file into a buffer
 *
 * @src: file structure pointing to the file
 * @offset: number of bytes to skip in the storage file
 * @len: maximum number of bytes read from the storage file
 * @buf: buffer to read the data into. (buffer shall be freed by caller)
 *
 * Returns the count of bytes read on success and -1 on failure, -2 if the
 * function isn't supported by the backend.
 * Libvirt error is reported on failure.
 */
ssize_t
virStorageFileRead(virStorageSourcePtr src,
                   size_t offset,
                   size_t len,
                   char **buf)
{
    virStorageDriverDataPtr drv = NULL;
    ssize_t ret;

    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return -1;
    }

    drv = src->drv;

    if (!drv->backend->storageFileRead)
        return -2;

    ret = drv->backend->storageFileRead(src, offset, len, buf);

    VIR_DEBUG("read '%zd' bytes from storage '%p' starting at offset '%zu'",
              ret, src, offset);

    return ret;
}


/*
 * virStorageFileGetUniqueIdentifier: Get a unique string describing the volume
 *
 * @src: file structure pointing to the file
 *
 * Returns a string uniquely describing a single volume (canonical path).
 * The string shall not be freed and is valid until the storage file is
 * deinitialized. Returns NULL on error and sets a libvirt error code */
const char *
virStorageFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    virStorageDriverDataPtr drv = NULL;

    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return NULL;
    }

    drv = src->drv;

    if (!drv->backend->storageFileGetUniqueIdentifier) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unique storage file identifier not implemented for "
                         "storage type %s (protocol: %s)'"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    return drv->backend->storageFileGetUniqueIdentifier(src);
}


/**
 * virStorageFileAccess: Check accessibility of a storage file
 *
 * @src: storage file to check access permissions
 * @mode: accessibility check options (see man 2 access)
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileAccess(virStorageSourcePtr src,
                     int mode)
{
    virStorageDriverDataPtr drv = NULL;

    if (!virStorageFileIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileAccess) {
        errno = ENOSYS;
        return -2;
    }

    return drv->backend->storageFileAccess(src, mode);
}


/**
 * virStorageFileChown: Change owner of a storage file
 *
 * @src: storage file to change owner of
 * @uid: new owner id
 * @gid: new group id
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileChown(const virStorageSource *src,
                    uid_t uid,
                    gid_t gid)
{
    virStorageDriverDataPtr drv = NULL;

    if (!virStorageFileIsInitialized(src)) {
        errno = ENOSYS;
        return -2;
    }

    drv = src->drv;

    if (!drv->backend->storageFileChown) {
        errno = ENOSYS;
        return -2;
    }

    VIR_DEBUG("chown of storage file %p to %u:%u",
              src, (unsigned int)uid, (unsigned int)gid);

    return drv->backend->storageFileChown(src, uid, gid);
}


/**
 * virStorageFileReportBrokenChain:
 *
 * @errcode: errno when accessing @src
 * @src: inaccessible file in the backing chain of @parent
 * @parent: root virStorageSource being checked
 *
 * Reports the correct error message if @src is missing in the backing chain
 * for @parent.
 */
void
virStorageFileReportBrokenChain(int errcode,
                                virStorageSourcePtr src,
                                virStorageSourcePtr parent)
{
    if (src->drv) {
        virStorageDriverDataPtr drv = src->drv;
        unsigned int access_user = drv->uid;
        unsigned int access_group = drv->gid;

        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%s' "
                                   "(as uid:%u, gid:%u)"),
                                 src->path, access_user, access_group);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s' (as uid:%u, gid:%u)"),
                                 src->path, parent->path, access_user, access_group);
        }
    } else {
        if (src == parent) {
            virReportSystemError(errcode,
                                 _("Cannot access storage file '%s'"),
                                 src->path);
        } else {
            virReportSystemError(errcode,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s'"),
                                 src->path, parent->path);
        }
    }
}


static int
virStorageFileGetMetadataRecurseReadHeader(virStorageSourcePtr src,
                                           virStorageSourcePtr parent,
                                           uid_t uid,
                                           gid_t gid,
                                           char **buf,
                                           size_t *headerLen,
                                           GHashTable *cycle)
{
    int ret = -1;
    const char *uniqueName;
    ssize_t len;

    if (virStorageFileInitAs(src, uid, gid) < 0)
        return -1;

    if (virStorageFileAccess(src, F_OK) < 0) {
        virStorageFileReportBrokenChain(errno, src, parent);
        goto cleanup;
    }

    if (!(uniqueName = virStorageFileGetUniqueIdentifier(src)))
        goto cleanup;

    if (virHashHasEntry(cycle, uniqueName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %s (%s) is self-referential"),
                       NULLSTR(src->path), uniqueName);
        goto cleanup;
    }

    if (virHashAddEntry(cycle, uniqueName, NULL) < 0)
        goto cleanup;

    if ((len = virStorageFileRead(src, 0, VIR_STORAGE_MAX_HEADER, buf)) < 0)
        goto cleanup;

    *headerLen = len;
    ret = 0;

 cleanup:
    virStorageFileDeinit(src);
    return ret;
}


/* Recursive workhorse for virStorageFileGetMetadata.  */
static int
virStorageFileGetMetadataRecurse(virStorageSourcePtr src,
                                 virStorageSourcePtr parent,
                                 uid_t uid, gid_t gid,
                                 bool report_broken,
                                 GHashTable *cycle,
                                 unsigned int depth)
{
    virStorageFileFormat orig_format = src->format;
    size_t headerLen;
    int rv;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) backingStore = NULL;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u",
              NULLSTR(src->path), src->format,
              (unsigned int)uid, (unsigned int)gid);

    if (src->format == VIR_STORAGE_FILE_AUTO_SAFE)
        src->format = VIR_STORAGE_FILE_AUTO;

    /* exit if we can't load information about the current image */
    rv = virStorageFileSupportsBackingChainTraversal(src);
    if (rv <= 0) {
        if (orig_format == VIR_STORAGE_FILE_AUTO)
            return -2;

        return rv;
    }

    if (virStorageFileGetMetadataRecurseReadHeader(src, parent, uid, gid,
                                                   &buf, &headerLen, cycle) < 0)
        return -1;

    if (virStorageFileProbeGetMetadata(src, buf, headerLen) < 0)
        return -1;

    /* If we probed the format we MUST ensure that nothing else than the current
     * image is considered for security labelling and/or recursion. */
    if (orig_format == VIR_STORAGE_FILE_AUTO) {
        if (src->backingStoreRaw) {
            src->format = VIR_STORAGE_FILE_RAW;
            VIR_FREE(src->backingStoreRaw);
            return -2;
        }
    }

    if (src->backingStoreRaw) {
        if ((rv = virStorageSourceNewFromBacking(src, &backingStore)) < 0)
            return -1;

        /* the backing file would not be usable for VM usage */
        if (rv == 1)
            return 0;

        if ((rv = virStorageFileGetMetadataRecurse(backingStore, parent,
                                                   uid, gid,
                                                   report_broken,
                                                   cycle, depth + 1)) < 0) {
            if (!report_broken)
                return 0;

            if (rv == -2) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("format of backing image '%s' of image '%s' was not specified in the image metadata "
                                 "(See https://libvirt.org/kbase/backing_chains.html for troubleshooting)"),
                               src->backingStoreRaw, NULLSTR(src->path));
            }

            return -1;
        }

        backingStore->id = depth;
        src->backingStore = g_steal_pointer(&backingStore);
    } else {
        /* add terminator */
        src->backingStore = virStorageSourceNew();
    }

    return 0;
}


/**
 * virStorageFileGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Recurses through
 * the entire chain.
 *
 * Open files using UID and GID (or pass -1 for the current user/group).
 * Treat any backing files without explicit type as raw, unless ALLOW_PROBE.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If @report_broken is true, the whole function fails with a possibly sane
 * error instead of just returning a broken chain. Note that the inability for
 * libvirt to traverse a given source is not considered an error.
 *
 * Caller MUST free result after use via virObjectUnref.
 */
int
virStorageFileGetMetadata(virStorageSourcePtr src,
                          uid_t uid, gid_t gid,
                          bool report_broken)
{
    GHashTable *cycle = NULL;
    virStorageType actualType = virStorageSourceGetActualType(src);
    int ret = -1;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u report_broken=%d",
              src->path, src->format, (unsigned int)uid, (unsigned int)gid,
              report_broken);

    if (!(cycle = virHashNew(NULL)))
        return -1;

    if (src->format <= VIR_STORAGE_FILE_NONE) {
        if (actualType == VIR_STORAGE_TYPE_DIR)
            src->format = VIR_STORAGE_FILE_DIR;
        else
            src->format = VIR_STORAGE_FILE_RAW;
    }

    ret = virStorageFileGetMetadataRecurse(src, src, uid, gid,
                                           report_broken, cycle, 1);

    virHashFree(cycle);
    return ret;
}


/**
 * virStorageFileGetBackingStoreStr:
 * @src: storage object
 *
 * Extracts the backing store string as stored in the storage volume described
 * by @src and returns it to the user. Caller is responsible for freeing it.
 * In case when the string can't be retrieved or does not exist NULL is
 * returned.
 */
int
virStorageFileGetBackingStoreStr(virStorageSourcePtr src,
                                 char **backing)
{
    ssize_t headerLen;
    int rv;
    g_autofree char *buf = NULL;
    g_autoptr(virStorageSource) tmp = NULL;

    *backing = NULL;

    /* exit if we can't load information about the current image */
    if (!virStorageFileSupportsBackingChainTraversal(src))
        return 0;

    rv = virStorageFileAccess(src, F_OK);
    if (rv == -2)
        return 0;
    if (rv < 0) {
        virStorageFileReportBrokenChain(errno, src, src);
        return -1;
    }

    if ((headerLen = virStorageFileRead(src, 0, VIR_STORAGE_MAX_HEADER,
                                        &buf)) < 0) {
        if (headerLen == -2)
            return 0;
        return -1;
    }

    if (!(tmp = virStorageSourceCopy(src, false)))
        return -1;

    if (virStorageFileProbeGetMetadata(tmp, buf, headerLen) < 0)
        return -1;

    *backing = g_steal_pointer(&tmp->backingStoreRaw);
    return 0;
}
