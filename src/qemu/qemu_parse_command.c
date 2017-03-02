/*
 * qemu_parse_command.c: QEMU command parser
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_command.h"
#include "qemu_parse_command.h"
#include "dirname.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "c-ctype.h"
#include "secret_conf.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_parse_command");


static int
qemuParseRBDString(virDomainDiskDefPtr disk)
{
    char *source = disk->src->path;
    int ret;

    disk->src->path = NULL;

    ret = virStorageSourceParseRBDColonString(source, disk->src);

    VIR_FREE(source);
    return ret;
}


static int
qemuParseDriveURIString(virDomainDiskDefPtr def, virURIPtr uri,
                        const char *scheme)
{
    int ret = -1;
    char *transp = NULL;
    char *sock = NULL;
    char *volimg = NULL;
    char *secret = NULL;
    virStorageAuthDefPtr authdef = NULL;

    if (VIR_ALLOC(def->src->hosts) < 0)
        goto error;

    transp = strchr(uri->scheme, '+');
    if (transp)
        *transp++ = 0;

    if (STRNEQ(uri->scheme, scheme)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid transport/scheme '%s'"), uri->scheme);
        goto error;
    }

    if (!transp) {
        def->src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    } else {
        def->src->hosts->transport = virStorageNetHostTransportTypeFromString(transp);
        if (def->src->hosts->transport < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid %s transport type '%s'"), scheme, transp);
            goto error;
        }
    }
    def->src->nhosts = 0; /* set to 1 once everything succeeds */

    if (def->src->hosts->transport != VIR_STORAGE_NET_HOST_TRANS_UNIX) {
        if (VIR_STRDUP(def->src->hosts->name, uri->server) < 0)
            goto error;

        if (virAsprintf(&def->src->hosts->port, "%d", uri->port) < 0)
            goto error;
    } else {
        def->src->hosts->name = NULL;
        def->src->hosts->port = 0;
        if (uri->query) {
            if (STRPREFIX(uri->query, "socket=")) {
                sock = strchr(uri->query, '=') + 1;
                if (VIR_STRDUP(def->src->hosts->socket, sock) < 0)
                    goto error;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid query parameter '%s'"), uri->query);
                goto error;
            }
        }
    }
    if (uri->path) {
        volimg = uri->path + 1; /* skip the prefix slash */
        VIR_FREE(def->src->path);
        if (VIR_STRDUP(def->src->path, volimg) < 0)
            goto error;
    } else {
        VIR_FREE(def->src->path);
    }

    if (uri->user) {
        const char *secrettype;
        /* formulate authdef for disk->src->auth */
        if (VIR_ALLOC(authdef) < 0)
            goto error;

        secret = strchr(uri->user, ':');
        if (secret)
            *secret = '\0';

        if (VIR_STRDUP(authdef->username, uri->user) < 0)
            goto error;
        if (STREQ(scheme, "iscsi")) {
            secrettype =
                virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_ISCSI);
            if (VIR_STRDUP(authdef->secrettype, secrettype) < 0)
                goto error;
        }
        def->src->auth = authdef;
        authdef = NULL;

        /* Cannot formulate a secretType (eg, usage or uuid) given
         * what is provided.
         */
    }

    def->src->nhosts = 1;
    ret = 0;

 cleanup:
    virURIFree(uri);

    return ret;

 error:
    virStorageNetHostDefClear(def->src->hosts);
    VIR_FREE(def->src->hosts);
    virStorageAuthDefFree(authdef);
    goto cleanup;
}

static int
qemuParseGlusterString(virDomainDiskDefPtr def)
{
    virURIPtr uri = NULL;

    if (!(uri = virURIParse(def->src->path)))
        return -1;

    return qemuParseDriveURIString(def, uri, "gluster");
}

static int
qemuParseISCSIString(virDomainDiskDefPtr def)
{
    virURIPtr uri = NULL;
    char *slash;
    unsigned lun;

    if (!(uri = virURIParse(def->src->path)))
        return -1;

    if (uri->path &&
        (slash = strchr(uri->path + 1, '/')) != NULL) {

        if (slash[1] == '\0') {
            *slash = '\0';
        } else if (virStrToLong_ui(slash + 1, NULL, 10, &lun) == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid name '%s' for iSCSI disk"),
                           def->src->path);
            virURIFree(uri);
            return -1;
        }
    }

    return qemuParseDriveURIString(def, uri, "iscsi");
}

static int
qemuParseNBDString(virDomainDiskDefPtr disk)
{
    virStorageNetHostDefPtr h = NULL;
    char *host, *port;
    char *src;

    virURIPtr uri = NULL;

    if (strstr(disk->src->path, "://")) {
        if (!(uri = virURIParse(disk->src->path)))
            return -1;
        return qemuParseDriveURIString(disk, uri, "nbd");
    }

    if (VIR_ALLOC(h) < 0)
        goto error;

    host = disk->src->path + strlen("nbd:");
    if (STRPREFIX(host, "unix:/")) {
        src = strchr(host + strlen("unix:"), ':');
        if (src)
            *src++ = '\0';

        h->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
        if (VIR_STRDUP(h->socket, host + strlen("unix:")) < 0)
            goto error;
    } else {
        port = strchr(host, ':');
        if (!port) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse nbd filename '%s'"), disk->src->path);
            goto error;
        }

        *port++ = '\0';
        if (VIR_STRDUP(h->name, host) < 0)
            goto error;

        src = strchr(port, ':');
        if (src)
            *src++ = '\0';

        if (VIR_STRDUP(h->port, port) < 0)
            goto error;
    }

    if (src && STRPREFIX(src, "exportname=")) {
        if (VIR_STRDUP(src, strchr(src, '=') + 1) < 0)
            goto error;
    } else {
        src = NULL;
    }

    VIR_FREE(disk->src->path);
    disk->src->path = src;
    disk->src->nhosts = 1;
    disk->src->hosts = h;
    return 0;

 error:
    virStorageNetHostDefClear(h);
    VIR_FREE(h);
    return -1;
}


/*
 * This method takes a string representing a QEMU command line ARGV set
 * optionally prefixed by a list of environment variables. It then tries
 * to split it up into a NULL terminated list of env & argv, splitting
 * on space
 */
static int qemuStringToArgvEnv(const char *args,
                               char ***retenv,
                               char ***retargv)
{
    char **arglist = NULL;
    size_t argcount = 0;
    size_t argalloc = 0;
    size_t envend;
    size_t i;
    const char *curr = args;
    const char *start;
    char **progenv = NULL;
    char **progargv = NULL;

    /* Iterate over string, splitting on sequences of ' ' */
    while (curr && *curr != '\0') {
        char *arg;
        const char *next;

        start = curr;
        /* accept a space in CEPH_ARGS */
        if (STRPREFIX(curr, "CEPH_ARGS=-m "))
            start += strlen("CEPH_ARGS=-m ");
        if (*start == '\'') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '\'');
        } else if (*start == '"') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '"');
        } else {
            next = strchr(start, ' ');
        }
        if (!next)
            next = strchr(curr, '\n');

        if (VIR_STRNDUP(arg, curr, next ? next - curr : -1) < 0)
            goto error;

        if (next && (*next == '\'' || *next == '"'))
            next++;

        if (VIR_RESIZE_N(arglist, argalloc, argcount, 2) < 0) {
            VIR_FREE(arg);
            goto error;
        }

        arglist[argcount++] = arg;
        arglist[argcount] = NULL;

        while (next && c_isspace(*next))
            next++;

        curr = next;
    }

    /* Iterate over list of args, finding first arg not containing
     * the '=' character (eg, skip over env vars FOO=bar) */
    for (envend = 0; ((envend < argcount) &&
                       (strchr(arglist[envend], '=') != NULL));
         envend++)
        ; /* nada */

    /* Copy the list of env vars */
    if (envend > 0) {
        if (VIR_REALLOC_N(progenv, envend+1) < 0)
            goto error;
        for (i = 0; i < envend; i++)
            progenv[i] = arglist[i];
        progenv[i] = NULL;
    }

    /* Copy the list of argv */
    if (VIR_REALLOC_N(progargv, argcount-envend + 1) < 0)
        goto error;
    for (i = envend; i < argcount; i++)
        progargv[i-envend] = arglist[i];
    progargv[i-envend] = NULL;

    VIR_FREE(arglist);

    *retenv = progenv;
    *retargv = progargv;

    return 0;

 error:
    VIR_FREE(progenv);
    VIR_FREE(progargv);
    virStringListFree(arglist);
    return -1;
}


/*
 * Search for a named env variable, and return the value part
 */
static const char *qemuFindEnv(char **progenv,
                               const char *name)
{
    size_t i;
    int len = strlen(name);

    for (i = 0; progenv && progenv[i]; i++) {
        if (STREQLEN(progenv[i], name, len) &&
            progenv[i][len] == '=')
            return progenv[i] + len + 1;
    }
    return NULL;
}

/*
 * Takes a string containing a set of key=value,key=value,key...
 * parameters and splits them up, returning two arrays with
 * the individual keys and values. If allowEmptyValue is nonzero,
 * the "=value" part is optional and if a key with no value is found,
 * NULL is be placed into corresponding place in retvalues.
 */
int
qemuParseKeywords(const char *str,
                  char ***retkeywords,
                  char ***retvalues,
                  int *retnkeywords,
                  int allowEmptyValue)
{
    int keywordCount = 0;
    int keywordAlloc = 0;
    char **keywords = NULL;
    char **values = NULL;
    const char *start = str;
    const char *end;
    size_t i;

    *retkeywords = NULL;
    *retvalues = NULL;
    *retnkeywords = 0;
    end = start + strlen(str);

    while (start) {
        const char *separator;
        const char *endmark;
        char *keyword;
        char *value = NULL;

        endmark = start;
        do {
            /* Qemu accepts ',,' as an escape for a literal comma;
             * skip past those here while searching for the end of the
             * value, then strip them down below */
            endmark = strchr(endmark, ',');
        } while (endmark && endmark[1] == ',' && (endmark += 2));
        if (!endmark)
            endmark = end;
        if (!(separator = strchr(start, '=')))
            separator = end;

        if (separator >= endmark) {
            if (!allowEmptyValue) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("malformed keyword arguments in '%s'"), str);
                goto error;
            }
            separator = endmark;
        }

        if (VIR_STRNDUP(keyword, start, separator - start) < 0)
            goto error;

        if (separator < endmark) {
            separator++;
            if (VIR_STRNDUP(value, separator, endmark - separator) < 0) {
                VIR_FREE(keyword);
                goto error;
            }
            if (strchr(value, ',')) {
                char *p = strchr(value, ',') + 1;
                char *q = p + 1;
                while (*q) {
                    if (*q == ',')
                        q++;
                    *p++ = *q++;
                }
                *p = '\0';
            }
        }

        if (keywordAlloc == keywordCount) {
            if (VIR_REALLOC_N(keywords, keywordAlloc + 10) < 0 ||
                VIR_REALLOC_N(values, keywordAlloc + 10) < 0) {
                VIR_FREE(keyword);
                VIR_FREE(value);
                goto error;
            }
            keywordAlloc += 10;
        }

        keywords[keywordCount] = keyword;
        values[keywordCount] = value;
        keywordCount++;

        start = endmark < end ? endmark + 1 : NULL;
    }

    *retkeywords = keywords;
    *retvalues = values;
    *retnkeywords = keywordCount;
    return 0;

 error:
    for (i = 0; i < keywordCount; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return -1;
}


/* qemuParseCommandLineVnc
 *
 * Tries to parse the various "-vnc ..." argument formats.
 */
static int
qemuParseCommandLineVnc(virDomainDefPtr def,
                        const char *val)
{
    int ret = -1;
    virDomainGraphicsDefPtr vnc = NULL;
    char *listenAddr = NULL;
    char *tmp;

    if (VIR_ALLOC(vnc) < 0)
        goto cleanup;
    vnc->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

    if (STRPREFIX(val, "unix:")) {
        /* -vnc unix:/some/big/path */
        if (virDomainGraphicsListenAppendSocket(vnc, val + 5) < 0)
            goto cleanup;
    } else {
        /*
         * -vnc 127.0.0.1:4
         * -vnc [2001:1:2:3:4:5:1234:1234]:4
         * -vnc some.host.name:4
         */
        char *opts;
        char *port;
        const char *sep = ":";
        if (val[0] == '[')
            sep = "]:";
        tmp = strstr(val, sep);
        if (!tmp) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing VNC port number in '%s'"), val);
            goto cleanup;
        }
        port = tmp + strlen(sep);
        if (virStrToLong_i(port, &opts, 10,
                           &vnc->data.vnc.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse VNC port '%s'"), port);
            goto cleanup;
        }
        if (val[0] == '[')
            val++;
        if (VIR_STRNDUP(listenAddr, val, tmp-val) < 0 ||
            virDomainGraphicsListenAppendAddress(vnc, listenAddr) < 0)
            goto cleanup;

        if (*opts == ',') {
            char *orig_opts;

            if (VIR_STRDUP(orig_opts, opts + 1) < 0)
                goto cleanup;
            opts = orig_opts;

            while (opts && *opts) {
                char *nextopt = strchr(opts, ',');
                if (nextopt)
                    *(nextopt++) = '\0';

                if (STRPREFIX(opts, "websocket")) {
                    char *websocket = opts + strlen("websocket");
                    if (*(websocket++) == '=' &&
                        *websocket) {
                        /* If the websocket continues with
                         * '=<something>', we'll parse it */
                        if (virStrToLong_i(websocket,
                                           NULL, 0,
                                           &vnc->data.vnc.websocket) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse VNC "
                                             "WebSocket port '%s'"),
                                           websocket);
                            VIR_FREE(orig_opts);
                            goto cleanup;
                        }
                    } else {
                        /* Otherwise, we'll compute the port the same
                         * way QEMU does, by adding a 5700 to the
                         * display value. */
                        vnc->data.vnc.websocket =
                            vnc->data.vnc.port + 5700;
                    }
                } else if (STRPREFIX(opts, "share=")) {
                    char *sharePolicy = opts + strlen("share=");
                    if (sharePolicy && *sharePolicy) {
                        int policy =
                            virDomainGraphicsVNCSharePolicyTypeFromString(sharePolicy);

                        if (policy < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("unknown vnc display sharing policy '%s'"),
                                             sharePolicy);
                            VIR_FREE(orig_opts);
                            goto cleanup;
                        } else {
                            vnc->data.vnc.sharePolicy = policy;
                        }
                    } else {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("missing vnc sharing policy"));
                        VIR_FREE(orig_opts);
                        goto cleanup;
                    }
                }

                opts = nextopt;
            }
            VIR_FREE(orig_opts);
        }
        vnc->data.vnc.port += 5900;
        vnc->data.vnc.autoport = false;
    }

    if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, vnc) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainGraphicsDefFree(vnc);
    VIR_FREE(listenAddr);
    return ret;
}


/*
 * Tries to parse new style QEMU -drive  args.
 *
 * eg -drive file=/dev/HostVG/VirtData1,if=ide,index=1
 *
 * Will fail if not using the 'index' keyword
 */
static virDomainDiskDefPtr
qemuParseCommandLineDisk(virDomainXMLOptionPtr xmlopt,
                         const char *val,
                         virDomainDefPtr dom,
                         int nvirtiodisk,
                         bool old_style_ceph_args)
{
    virDomainDiskDefPtr def = NULL;
    char **keywords;
    char **values;
    int nkeywords;
    size_t i;
    int idx = -1;
    int busid = -1;
    int unitid = -1;

    if (qemuParseKeywords(val,
                          &keywords,
                          &values,
                          &nkeywords,
                          0) < 0)
        return NULL;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;
    if (VIR_ALLOC(def->src) < 0)
        goto error;

    if (qemuDomainMachineIsPSeries(dom))
        def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
    else
       def->bus = VIR_DOMAIN_DISK_BUS_IDE;
    def->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    def->src->type = VIR_STORAGE_TYPE_FILE;

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "file")) {
            if (values[i] && STRNEQ(values[i], "")) {
                def->src->path = values[i];
                values[i] = NULL;
                if (STRPREFIX(def->src->path, "/dev/"))
                    def->src->type = VIR_STORAGE_TYPE_BLOCK;
                else if (STRPREFIX(def->src->path, "nbd:") ||
                         STRPREFIX(def->src->path, "nbd+")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;

                    if (qemuParseNBDString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "rbd:")) {
                    char *p = def->src->path;

                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
                    if (VIR_STRDUP(def->src->path, p + strlen("rbd:")) < 0)
                        goto error;
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!old_style_ceph_args && qemuParseRBDString(def) < 0) {
                        VIR_FREE(p);
                        goto error;
                    }

                    VIR_FREE(p);
                } else if (STRPREFIX(def->src->path, "gluster:") ||
                           STRPREFIX(def->src->path, "gluster+")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;

                    if (qemuParseGlusterString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "iscsi:")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

                    if (qemuParseISCSIString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "sheepdog:")) {
                    char *p = def->src->path;
                    char *port, *vdi;

                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;
                    if (VIR_STRDUP(def->src->path, p + strlen("sheepdog:")) < 0)
                        goto error;
                    VIR_FREE(p);

                    /* def->src->path must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(def->src->path, ':');
                    if (port) {
                        *port = '\0';
                        vdi = strchr(port + 1, ':');
                        if (!vdi) {
                            *port = ':';
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse sheepdog filename '%s'"),
                                           def->src->path);
                            goto error;
                        }
                        port++;
                        *vdi++ = '\0';
                        if (VIR_ALLOC(def->src->hosts) < 0)
                            goto error;
                        def->src->nhosts = 1;
                        def->src->hosts->name = def->src->path;
                        if (VIR_STRDUP(def->src->hosts->port, port) < 0)
                            goto error;
                        def->src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
                        def->src->hosts->socket = NULL;
                        if (VIR_STRDUP(def->src->path, vdi) < 0)
                            goto error;
                    }
                } else {
                    def->src->type = VIR_STORAGE_TYPE_FILE;
                }
            } else {
                def->src->type = VIR_STORAGE_TYPE_FILE;
            }
        } else if (STREQ(keywords[i], "if")) {
            if (STREQ(values[i], "ide")) {
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
                if (qemuDomainMachineIsPSeries(dom)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("pseries systems do not support ide devices '%s'"), val);
                    goto error;
                }
            } else if (STREQ(values[i], "scsi")) {
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            } else if (STREQ(values[i], "floppy")) {
                def->bus = VIR_DOMAIN_DISK_BUS_FDC;
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
            } else if (STREQ(values[i], "virtio")) {
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            } else if (STREQ(values[i], "xen")) {
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
            } else if (STREQ(values[i], "sd")) {
                def->bus = VIR_DOMAIN_DISK_BUS_SD;
            }
        } else if (STREQ(keywords[i], "media")) {
            if (STREQ(values[i], "cdrom")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                def->src->readonly = true;
            } else if (STREQ(values[i], "floppy")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
            }
        } else if (STREQ(keywords[i], "format")) {
            if (VIR_STRDUP(def->src->driverName, "qemu") < 0)
                goto error;
            def->src->format = virStorageFileFormatTypeFromString(values[i]);
        } else if (STREQ(keywords[i], "cache")) {
            if (STREQ(values[i], "off") ||
                STREQ(values[i], "none"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DISABLE;
            else if (STREQ(values[i], "writeback") ||
                     STREQ(values[i], "on"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITEBACK;
            else if (STREQ(values[i], "writethrough"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITETHRU;
            else if (STREQ(values[i], "directsync"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DIRECTSYNC;
            else if (STREQ(values[i], "unsafe"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_UNSAFE;
        } else if (STREQ(keywords[i], "werror")) {
            if (STREQ(values[i], "stop"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
            else if (STREQ(values[i], "enospc"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE;
        } else if (STREQ(keywords[i], "rerror")) {
            if (STREQ(values[i], "stop"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
        } else if (STREQ(keywords[i], "index")) {
            if (virStrToLong_i(values[i], NULL, 10, &idx) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive index '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "bus")) {
            if (virStrToLong_i(values[i], NULL, 10, &busid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive bus '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "unit")) {
            if (virStrToLong_i(values[i], NULL, 10, &unitid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive unit '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "readonly")) {
            if ((values[i] == NULL) || STREQ(values[i], "on"))
                def->src->readonly = true;
        } else if (STREQ(keywords[i], "aio")) {
            if ((def->iomode = virDomainDiskIoTypeFromString(values[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse io mode '%s'"), values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "cyls")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.cylinders)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse cylinders value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "heads")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.heads)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse heads value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "secs")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.sectors)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sectors value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "trans")) {
            def->geometry.trans =
                virDomainDiskGeometryTransTypeFromString(values[i]);
            if ((def->geometry.trans < VIR_DOMAIN_DISK_TRANS_DEFAULT) ||
                (def->geometry.trans >= VIR_DOMAIN_DISK_TRANS_LAST)) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse translation value '%s'"),
                               values[i]);
                goto error;
            }
        }
    }

    if (def->rerror_policy == def->error_policy)
        def->rerror_policy = 0;

    if (!def->src->path &&
        def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        def->src->type != VIR_STORAGE_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing file parameter in drive '%s'"), val);
        goto error;
    }
    if (idx == -1 &&
        def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
        idx = nvirtiodisk;

    if (idx == -1 &&
        unitid == -1 &&
        busid == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing index/unit/bus parameter in drive '%s'"),
                       val);
        goto error;
    }

    if (idx == -1) {
        if (unitid == -1)
            unitid = 0;
        if (busid == -1)
            busid = 0;
        switch (def->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            idx = (busid * 2) + unitid;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            idx = (busid * 7) + unitid;
            break;
        default:
            idx = unitid;
            break;
        }
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        ignore_value(VIR_STRDUP(def->dst, "hda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
               def->bus == VIR_DOMAIN_DISK_BUS_SD) {
        ignore_value(VIR_STRDUP(def->dst, "sda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        ignore_value(VIR_STRDUP(def->dst, "vda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_XEN) {
        ignore_value(VIR_STRDUP(def->dst, "xvda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        ignore_value(VIR_STRDUP(def->dst, "fda"));
    } else {
        ignore_value(VIR_STRDUP(def->dst, "hda"));
    }

    if (!def->dst)
        goto error;
    if (STREQ(def->dst, "xvda"))
        def->dst[3] = 'a' + idx;
    else
        def->dst[2] = 'a' + idx;

    if (virDomainDiskDefAssignAddress(xmlopt, def, dom) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid device name '%s'"), def->dst);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }

 cleanup:
    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;

 error:
    virDomainDiskDefFree(def);
    def = NULL;
    goto cleanup;
}

/*
 * Tries to find a NIC definition matching a vlan we want
 */
static const char *
qemuFindNICForVLAN(int nnics,
                   const char **nics,
                   int wantvlan)
{
    size_t i;
    for (i = 0; i < nnics; i++) {
        int gotvlan;
        const char *tmp = strstr(nics[i], "vlan=");
        char *end;
        if (!tmp)
            continue;

        tmp += strlen("vlan=");

        if (virStrToLong_i(tmp, &end, 10, &gotvlan) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse NIC vlan in '%s'"), nics[i]);
            return NULL;
        }

        if (gotvlan == wantvlan)
            return nics[i];
    }

    if (wantvlan == 0 && nnics > 0)
        return nics[0];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot find NIC definition for vlan %d"), wantvlan);
    return NULL;
}


/*
 * Tries to parse a QEMU -net backend argument. Gets given
 * a list of all known -net frontend arguments to try and
 * match up against. Horribly complicated stuff
 */
static virDomainNetDefPtr
qemuParseCommandLineNet(virDomainXMLOptionPtr xmlopt,
                        const char *val,
                        int nnics,
                        const char **nics)
{
    virDomainNetDefPtr def = NULL;
    char **keywords = NULL;
    char **values = NULL;
    int nkeywords;
    const char *nic;
    int wantvlan = 0;
    const char *tmp;
    bool genmac = true;
    size_t i;

    tmp = strchr(val, ',');

    if (tmp) {
        if (qemuParseKeywords(tmp+1,
                              &keywords,
                              &values,
                              &nkeywords,
                              0) < 0)
            return NULL;
    } else {
        nkeywords = 0;
    }

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    /* 'tap' could turn into libvirt type=ethernet, type=bridge or
     * type=network, but we can't tell, so use the generic config */
    if (STRPREFIX(val, "tap,"))
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
    else if (STRPREFIX(val, "socket"))
        def->type = VIR_DOMAIN_NET_TYPE_CLIENT;
    else if (STRPREFIX(val, "user"))
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    else
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "vlan")) {
            if (virStrToLong_i(values[i], NULL, 10, &wantvlan) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse vlan in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "script") && STRNEQ(values[i], "")) {
            def->script = values[i];
            values[i] = NULL;
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "ifname")) {
            def->ifname = values[i];
            values[i] = NULL;
        }
    }


    /* Done parsing the nic backend. Now to try and find corresponding
     * frontend, based off vlan number. NB this assumes a 1-1 mapping
     */

    nic = qemuFindNICForVLAN(nnics, nics, wantvlan);
    if (!nic) {
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (!STRPREFIX(nic, "nic")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse NIC definition '%s'"), nic);
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);

    if (STRPREFIX(nic, "nic,")) {
        if (qemuParseKeywords(nic + strlen("nic,"),
                              &keywords,
                              &values,
                              &nkeywords,
                              0) < 0) {
            virDomainNetDefFree(def);
            def = NULL;
            goto cleanup;
        }
    } else {
        nkeywords = 0;
    }

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "macaddr")) {
            genmac = false;
            if (virMacAddrParse(values[i], &def->mac) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unable to parse mac address '%s'"),
                               values[i]);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "model")) {
            def->model = values[i];
            values[i] = NULL;
        } else if (STREQ(keywords[i], "vhost")) {
            if ((values[i] == NULL) || STREQ(values[i], "on")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_VHOST;
            } else if (STREQ(keywords[i], "off")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_QEMU;
            }
        } else if (STREQ(keywords[i], "sndbuf") && values[i]) {
            if (virStrToLong_ul(values[i], NULL, 10, &def->tune.sndbuf) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sndbuf size in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
            def->tune.sndbuf_specified = true;
        }
    }

    if (genmac)
        virDomainNetGenerateMAC(xmlopt, &def->mac);

 cleanup:
    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}


/*
 * Tries to parse a QEMU PCI device
 */
static virDomainHostdevDefPtr
qemuParseCommandLinePCI(const char *val)
{
    int bus = 0, slot = 0, func = 0;
    const char *start;
    char *end;
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc(NULL);

    if (!def)
        goto error;

    if (!STRPREFIX(val, "host=")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown PCI device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host=");
    if (virStrToLong_i(start, &end, 16, &bus) < 0 || *end != ':') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device bus '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, &end, 16, &slot) < 0 || *end != '.') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device slot '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, NULL, 16, &func) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device function '%s'"), val);
        goto error;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = true;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    def->source.subsys.u.pci.addr.bus = bus;
    def->source.subsys.u.pci.addr.slot = slot;
    def->source.subsys.u.pci.addr.function = func;
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU USB device
 */
static virDomainHostdevDefPtr
qemuParseCommandLineUSB(const char *val)
{
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc(NULL);
    virDomainHostdevSubsysUSBPtr usbsrc;
    int first = 0, second = 0;
    const char *start;
    char *end;

    if (!def)
        goto error;
    usbsrc = &def->source.subsys.u.usb;

    if (!STRPREFIX(val, "host:")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown USB device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host:");
    if (strchr(start, ':')) {
        if (virStrToLong_i(start, &end, 16, &first) < 0 || *end != ':') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device vendor '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 16, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device product '%s'"), val);
            goto error;
        }
    } else {
        if (virStrToLong_i(start, &end, 10, &first) < 0 || *end != '.') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device bus '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 10, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device address '%s'"), val);
            goto error;
        }
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = false;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
    if (*end == '.') {
        usbsrc->bus = first;
        usbsrc->device = second;
    } else {
        usbsrc->vendor = first;
        usbsrc->product = second;
    }
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU serial/parallel device
 */
static int
qemuParseCommandLineChr(virDomainChrSourceDefPtr source,
                        const char *val)
{
    if (STREQ(val, "null")) {
        source->type = VIR_DOMAIN_CHR_TYPE_NULL;
    } else if (STREQ(val, "vc")) {
        source->type = VIR_DOMAIN_CHR_TYPE_VC;
    } else if (STREQ(val, "pty")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if (STRPREFIX(val, "file:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_FILE;
        if (VIR_STRDUP(source->data.file.path, val + strlen("file:")) < 0)
            goto error;
    } else if (STRPREFIX(val, "pipe:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        if (VIR_STRDUP(source->data.file.path, val + strlen("pipe:")) < 0)
            goto error;
    } else if (STREQ(val, "stdio")) {
        source->type = VIR_DOMAIN_CHR_TYPE_STDIO;
    } else if (STRPREFIX(val, "udp:")) {
        const char *svc1, *host2, *svc2;
        source->type = VIR_DOMAIN_CHR_TYPE_UDP;
        val += strlen("udp:");
        svc1 = strchr(val, ':');
        host2 = svc1 ? strchr(svc1, '@') : NULL;
        svc2 = host2 ? strchr(host2, ':') : NULL;

        if (svc1 && svc1 != val &&
            VIR_STRNDUP(source->data.udp.connectHost, val, svc1 - val) < 0)
            goto error;

        if (svc1) {
            svc1++;
            if (VIR_STRNDUP(source->data.udp.connectService, svc1,
                            host2 ? host2 - svc1 : strlen(svc1)) < 0)
                goto error;
        }

        if (host2) {
            host2++;
            if (svc2 && svc2 != host2 &&
                VIR_STRNDUP(source->data.udp.bindHost, host2, svc2 - host2) < 0)
                goto error;
        }

        if (svc2) {
            svc2++;
            if (STRNEQ(svc2, "0")) {
                if (VIR_STRDUP(source->data.udp.bindService, svc2) < 0)
                    goto error;
            }
        }
    } else if (STRPREFIX(val, "tcp:") ||
               STRPREFIX(val, "telnet:")) {
        const char *opt, *svc;
        source->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (STRPREFIX(val, "tcp:")) {
            val += strlen("tcp:");
        } else {
            val += strlen("telnet:");
            source->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        }
        svc = strchr(val, ':');
        if (!svc) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot find port number in character device %s"), val);
            goto error;
        }
        opt = strchr(svc, ',');
        if (opt && strstr(opt, "server"))
            source->data.tcp.listen = true;

        if (VIR_STRNDUP(source->data.tcp.host, val, svc - val) < 0)
            goto error;
        svc++;
        if (VIR_STRNDUP(source->data.tcp.service, svc, opt ? opt - svc : -1) < 0)
            goto error;
    } else if (STRPREFIX(val, "unix:")) {
        const char *opt;
        val += strlen("unix:");
        opt = strchr(val, ',');
        source->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        if (VIR_STRNDUP(source->data.nix.path, val, opt ? opt - val : -1) < 0)
            goto error;

    } else if (STRPREFIX(val, "/dev")) {
        source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        if (VIR_STRDUP(source->data.file.path, val) < 0)
            goto error;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown character device syntax %s"), val);
        goto error;
    }

    return 0;

 error:
    return -1;
}


static virCPUDefPtr
qemuInitGuestCPU(virDomainDefPtr dom)
{
    if (!dom->cpu) {
        virCPUDefPtr cpu;

        if (VIR_ALLOC(cpu) < 0)
            return NULL;

        cpu->type = VIR_CPU_TYPE_GUEST;
        cpu->match = VIR_CPU_MATCH_EXACT;
        dom->cpu = cpu;
    }

    return dom->cpu;
}


static int
qemuParseCommandLineCPU(virDomainDefPtr dom,
                        const char *val)
{
    virCPUDefPtr cpu = NULL;
    char **tokens;
    char **hv_tokens = NULL;
    char *model = NULL;
    int ret = -1;
    size_t i;

    if (!(tokens = virStringSplit(val, ",", 0)))
        goto cleanup;

    if (tokens[0] == NULL)
        goto syntax;

    for (i = 0; tokens[i] != NULL; i++) {
        if (*tokens[i] == '\0')
            goto syntax;

        if (i == 0) {
            if (VIR_STRDUP(model, tokens[i]) < 0)
                goto cleanup;

            if (STRNEQ(model, "qemu32") && STRNEQ(model, "qemu64")) {
                if (!(cpu = qemuInitGuestCPU(dom)))
                    goto cleanup;

                cpu->model = model;
                model = NULL;
            }
        } else if (*tokens[i] == '+' || *tokens[i] == '-') {
            const char *feature = tokens[i] + 1; /* '+' or '-' */
            int policy;

            if (*tokens[i] == '+')
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = VIR_CPU_FEATURE_DISABLE;

            if (*feature == '\0')
                goto syntax;

            if (!ARCH_IS_X86(dom->os.arch)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("%s platform doesn't support CPU features'"),
                               virArchToString(dom->os.arch));
                goto cleanup;
             }

            if (STREQ(feature, "kvmclock")) {
                bool present = (policy == VIR_CPU_FEATURE_REQUIRE);
                size_t j;

                for (j = 0; j < dom->clock.ntimers; j++) {
                    if (dom->clock.timers[j]->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK)
                        break;
                }

                if (j == dom->clock.ntimers) {
                    virDomainTimerDefPtr timer;
                    if (VIR_ALLOC(timer) < 0 ||
                        VIR_APPEND_ELEMENT_COPY(dom->clock.timers,
                                                dom->clock.ntimers, timer) < 0) {
                        VIR_FREE(timer);
                        goto cleanup;
                    }
                    timer->name = VIR_DOMAIN_TIMER_NAME_KVMCLOCK;
                    timer->present = present;
                    timer->tickpolicy = -1;
                    timer->track = -1;
                    timer->mode = -1;
                } else if (dom->clock.timers[j]->present != -1 &&
                    dom->clock.timers[j]->present != present) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("conflicting occurrences of kvmclock feature"));
                    goto cleanup;
                }
            } else if (STREQ(feature, "kvm_pv_eoi")) {
                if (policy == VIR_CPU_FEATURE_REQUIRE)
                    dom->apic_eoi = VIR_TRISTATE_SWITCH_ON;
                else
                    dom->apic_eoi = VIR_TRISTATE_SWITCH_OFF;
            } else {
                if (!cpu) {
                    if (!(cpu = qemuInitGuestCPU(dom)))
                        goto cleanup;

                    cpu->model = model;
                    model = NULL;
                }

                if (virCPUDefAddFeature(cpu, feature, policy) < 0)
                    goto cleanup;
            }
        } else if (STREQ(tokens[i], "hv_crash")) {
            size_t j;
            for (j = 0; j < dom->npanics; j++) {
                 if (dom->panics[j]->model == VIR_DOMAIN_PANIC_MODEL_HYPERV)
                     break;
            }

            if (j == dom->npanics) {
                virDomainPanicDefPtr panic;
                if (VIR_ALLOC(panic) < 0 ||
                    VIR_APPEND_ELEMENT_COPY(dom->panics,
                                            dom->npanics, panic) < 0) {
                    VIR_FREE(panic);
                    goto cleanup;
                }
                panic->model = VIR_DOMAIN_PANIC_MODEL_HYPERV;
            }
        } else if (STRPREFIX(tokens[i], "hv_")) {
            const char *token = tokens[i] + 3; /* "hv_" */
            const char *feature, *value;
            int f;

            if (*token == '\0')
                goto syntax;

            if (!(hv_tokens = virStringSplit(token, "=", 2)))
                goto cleanup;

            feature = hv_tokens[0];
            value = hv_tokens[1];

            if (*feature == '\0')
                goto syntax;

            dom->features[VIR_DOMAIN_FEATURE_HYPERV] = VIR_TRISTATE_SWITCH_ON;

            if ((f = virDomainHypervTypeFromString(feature)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported HyperV Enlightenment feature "
                                 "'%s'"), feature);
                goto cleanup;
            }

            switch ((virDomainHyperv) f) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
            case VIR_DOMAIN_HYPERV_VPINDEX:
            case VIR_DOMAIN_HYPERV_RUNTIME:
            case VIR_DOMAIN_HYPERV_SYNIC:
            case VIR_DOMAIN_HYPERV_STIMER:
            case VIR_DOMAIN_HYPERV_RESET:
                if (value) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("HyperV feature '%s' should not "
                                     "have a value"), feature);
                    goto cleanup;
                }
                dom->hyperv_features[f] = VIR_TRISTATE_SWITCH_ON;
                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                dom->hyperv_features[f] = VIR_TRISTATE_SWITCH_ON;
                if (!value) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("missing HyperV spinlock retry count"));
                    goto cleanup;
                }

                if (virStrToLong_ui(value, NULL, 0, &dom->hyperv_spinlocks) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("cannot parse HyperV spinlock retry count"));
                    goto cleanup;
                }

                if (dom->hyperv_spinlocks < 0xFFF)
                    dom->hyperv_spinlocks = 0xFFF;
                break;

            case VIR_DOMAIN_HYPERV_VENDOR_ID:
                dom->hyperv_features[f] = VIR_TRISTATE_SWITCH_ON;
                if (!value) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("missing HyperV vendor_id value"));
                    goto cleanup;
                }

                if (VIR_STRDUP(dom->hyperv_vendor_id, value) < 0)
                    goto cleanup;

                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
            virStringListFree(hv_tokens);
            hv_tokens = NULL;
        } else if (STREQ(tokens[i], "kvm=off")) {
             dom->features[VIR_DOMAIN_FEATURE_KVM] = VIR_TRISTATE_SWITCH_ON;
             dom->kvm_features[VIR_DOMAIN_KVM_HIDDEN] = VIR_TRISTATE_SWITCH_ON;
        }
    }

    if (dom->os.arch == VIR_ARCH_X86_64) {
        bool is_32bit = false;
        if (cpu) {
            virCPUDataPtr cpuData = NULL;

            if (cpuEncode(VIR_ARCH_X86_64, cpu, NULL, &cpuData,
                          NULL, NULL, NULL, NULL) < 0)
                goto cleanup;

            is_32bit = (virCPUDataCheckFeature(cpuData, "lm") != 1);
            virCPUDataFree(cpuData);
        } else if (model) {
            is_32bit = STREQ(model, "qemu32");
        }

        if (is_32bit)
            dom->os.arch = VIR_ARCH_I686;
    }

    ret = 0;

 cleanup:
    VIR_FREE(model);
    virStringListFree(tokens);
    virStringListFree(hv_tokens);
    return ret;

 syntax:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("unknown CPU syntax '%s'"), val);
    goto cleanup;
}


static int
qemuParseCommandLineMem(virDomainDefPtr dom,
                        const char *val)
{
    unsigned long long mem;
    char *end;

    if (virStrToLong_ull(val, &end, 10, &mem) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse memory level '%s'"), val);
        return -1;
    }

    if (virScaleInteger(&mem, end, 1024*1024, ULLONG_MAX) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot scale memory: %s"),
                       virGetLastErrorMessage());
        return -1;
    }

    virDomainDefSetMemoryTotal(dom, mem / 1024);
    dom->mem.cur_balloon = mem / 1024;

    return 0;
}


static int
qemuParseCommandLineSmp(virDomainDefPtr dom,
                        const char *val,
                        virDomainXMLOptionPtr xmlopt)
{
    unsigned int sockets = 0;
    unsigned int cores = 0;
    unsigned int threads = 0;
    unsigned int maxcpus = 0;
    unsigned int vcpus = 0;
    size_t i;
    int nkws;
    char **kws;
    char **vals;
    int n;
    char *end;
    int ret;

    if (qemuParseKeywords(val, &kws, &vals, &nkws, 1) < 0)
        return -1;

    for (i = 0; i < nkws; i++) {
        if (vals[i] == NULL) {
            if (i > 0 ||
                virStrToLong_ui(kws[i], &end, 10, &vcpus) < 0 || *end != '\0')
                goto syntax;
        } else {
            if (virStrToLong_i(vals[i], &end, 10, &n) < 0 || *end != '\0')
                goto syntax;
            if (STREQ(kws[i], "sockets"))
                sockets = n;
            else if (STREQ(kws[i], "cores"))
                cores = n;
            else if (STREQ(kws[i], "threads"))
                threads = n;
            else if (STREQ(kws[i], "maxcpus"))
                maxcpus = n;
            else if (STREQ(kws[i], "cpus"))
                vcpus = n;
            else
                goto syntax;
        }
    }

    if (sockets && cores && threads) {
        virCPUDefPtr cpu;

        if (!(cpu = qemuInitGuestCPU(dom)))
            goto error;
        cpu->sockets = sockets;
        cpu->cores = cores;
        cpu->threads = threads;
    } else if (sockets || cores || threads) {
        goto syntax;
    }

    if (maxcpus == 0) {
        if (cores) {
            if (virDomainDefGetVcpusTopology(dom, &maxcpus) < 0)
                goto error;
        } else {
            maxcpus = vcpus;
        }
    }

    if (maxcpus == 0)
        goto syntax;

    if (vcpus == 0)
        vcpus = maxcpus;

    if (virDomainDefSetVcpusMax(dom, maxcpus, xmlopt) < 0)
        goto error;

    if (virDomainDefSetVcpus(dom, vcpus) < 0)
        goto error;

    ret = 0;

 cleanup:
    for (i = 0; i < nkws; i++) {
        VIR_FREE(kws[i]);
        VIR_FREE(vals[i]);
    }
    VIR_FREE(kws);
    VIR_FREE(vals);

    return ret;

 syntax:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse CPU topology '%s'"), val);
 error:
    ret = -1;
    goto cleanup;
}


static void
qemuParseCommandLineBootDevs(virDomainDefPtr def, const char *str)
{
    int n, b = 0;

    for (n = 0; str[n] && b < VIR_DOMAIN_BOOT_LAST; n++) {
        if (str[n] == 'a')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_FLOPPY;
        else if (str[n] == 'c')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_DISK;
        else if (str[n] == 'd')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_CDROM;
        else if (str[n] == 'n')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_NET;
        else if (str[n] == ',')
            break;
    }
    def->os.nBootDevs = b;
}


/*
 * Analyse the env and argv settings and reconstruct a
 * virDomainDefPtr representing these settings as closely
 * as is practical. This is not an exact science....
 */
static virDomainDefPtr
qemuParseCommandLine(virCapsPtr caps,
                     virDomainXMLOptionPtr xmlopt,
                     char **progenv,
                     char **progargv,
                     char **pidfile,
                     virDomainChrSourceDefPtr *monConfig,
                     bool *monJSON)
{
    virDomainDefPtr def;
    size_t i;
    bool nographics = false;
    bool fullscreen = false;
    char **list = NULL;
    char *path;
    size_t nnics = 0;
    const char **nics = NULL;
    int video = VIR_DOMAIN_VIDEO_TYPE_CIRRUS;
    int nvirtiodisk = 0;
    qemuDomainCmdlineDefPtr cmd = NULL;
    virDomainDiskDefPtr disk = NULL;
    const char *ceph_args = qemuFindEnv(progenv, "CEPH_ARGS");
    bool have_sdl = false;

    if (pidfile)
        *pidfile = NULL;
    if (monConfig)
        *monConfig = NULL;
    if (monJSON)
        *monJSON = false;

    if (!progargv[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no emulator path found"));
        return NULL;
    }

    if (!(def = virDomainDefNew()))
        goto error;

    /* allocate the cmdlinedef up-front; if it's unused, we'll free it later */
    if (VIR_ALLOC(cmd) < 0)
        goto error;

    if (virUUIDGenerate(def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        goto error;
    }

    def->id = -1;
    def->mem.cur_balloon = 64 * 1024;
    virDomainDefSetMemoryTotal(def, def->mem.cur_balloon);
    if (virDomainDefSetVcpusMax(def, 1, xmlopt) < 0)
        goto error;
    if (virDomainDefSetVcpus(def, 1) < 0)
        goto error;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;

    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->virtType = VIR_DOMAIN_VIRT_QEMU;
    if (VIR_STRDUP(def->emulator, progargv[0]) < 0)
        goto error;

    if (!(path = last_component(def->emulator)))
        goto error;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;
    if (strstr(path, "kvm")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
    }

    if (def->virtType == VIR_DOMAIN_VIRT_KVM)
        def->os.arch = caps->host.arch;
    else if (STRPREFIX(path, "qemu-system-"))
        def->os.arch = virArchFromString(path + strlen("qemu-system-"));
    else
        def->os.arch = VIR_ARCH_I686;

    if (ARCH_IS_X86(def->os.arch))
        def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;

#define WANT_VALUE()                                                   \
    const char *val = progargv[++i];                                   \
    if (!val) {                                                        \
        virReportError(VIR_ERR_INTERNAL_ERROR,                         \
                       _("missing value for %s argument"), arg);       \
        goto error;                                                    \
    }

    /* One initial loop to get list of NICs, so we
     * can correlate them later */
    for (i = 1; progargv[i]; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (STRPREFIX(val, "nic") &&
                VIR_APPEND_ELEMENT(nics, nnics, val) < 0)
                goto error;
        }
    }

    /* Now the real processing loop */
    for (i = 1; progargv[i]; i++) {
        const char *arg = progargv[i];
        bool argRecognized = true;

        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-vnc")) {
            WANT_VALUE();
            if (qemuParseCommandLineVnc(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-sdl")) {
            have_sdl = true;
        } else if (STREQ(arg, "-m")) {
            WANT_VALUE();
            if (qemuParseCommandLineMem(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-smp")) {
            WANT_VALUE();
            if (qemuParseCommandLineSmp(def, val, xmlopt) < 0)
                goto error;
        } else if (STREQ(arg, "-uuid")) {
            WANT_VALUE();
            if (virUUIDParse(val, def->uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, \
                               _("cannot parse UUID '%s'"), val);
                goto error;
            }
        } else if (STRPREFIX(arg, "-hd") ||
                   STRPREFIX(arg, "-sd") ||
                   STRPREFIX(arg, "-fd") ||
                   STREQ(arg, "-cdrom")) {
            WANT_VALUE();
            if (!(disk = virDomainDiskDefNew(xmlopt)))
                goto error;

            if (STRPREFIX(val, "/dev/")) {
                disk->src->type = VIR_STORAGE_TYPE_BLOCK;
            } else if (STRPREFIX(val, "nbd:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;
            } else if (STRPREFIX(val, "rbd:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
                val += strlen("rbd:");
            } else if (STRPREFIX(val, "gluster")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;
            } else if (STRPREFIX(val, "sheepdog:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;
                val += strlen("sheepdog:");
            } else {
                disk->src->type = VIR_STORAGE_TYPE_FILE;
            }
            if (STREQ(arg, "-cdrom")) {
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                if (qemuDomainMachineIsPSeries(def))
                    disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                if (VIR_STRDUP(disk->dst, "hdc") < 0)
                    goto error;
                disk->src->readonly = true;
            } else {
                if (STRPREFIX(arg, "-fd")) {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                    disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
                } else {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                    if (STRPREFIX(arg, "-hd"))
                        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
                    else
                        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                   if (qemuDomainMachineIsPSeries(def))
                       disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                }
                if (VIR_STRDUP(disk->dst, arg + 1) < 0)
                    goto error;
            }
            if (VIR_STRDUP(disk->src->path, val) < 0)
                goto error;

            if (disk->src->type == VIR_STORAGE_TYPE_NETWORK) {
                char *port;

                switch ((virStorageNetProtocol) disk->src->protocol) {
                case VIR_STORAGE_NET_PROTOCOL_NBD:
                    if (qemuParseNBDString(disk) < 0)
                        goto error;
                    break;
                case VIR_STORAGE_NET_PROTOCOL_RBD:
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!ceph_args && qemuParseRBDString(disk) < 0)
                        goto error;
                    break;
                case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
                    /* disk->src must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(disk->src->path, ':');
                    if (port) {
                        char *vdi;

                        *port++ = '\0';
                        vdi = strchr(port, ':');
                        if (!vdi) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse sheepdog filename '%s'"), val);
                            goto error;
                        }
                        *vdi++ = '\0';
                        if (VIR_ALLOC(disk->src->hosts) < 0)
                            goto error;
                        disk->src->nhosts = 1;
                        disk->src->hosts->name = disk->src->path;
                        if (VIR_STRDUP(disk->src->hosts->port, port) < 0)
                            goto error;
                        if (VIR_STRDUP(disk->src->path, vdi) < 0)
                            goto error;
                    }
                    break;
                case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
                    if (qemuParseGlusterString(disk) < 0)
                        goto error;

                    break;
                case VIR_STORAGE_NET_PROTOCOL_ISCSI:
                    if (qemuParseISCSIString(disk) < 0)
                        goto error;

                    break;
                case VIR_STORAGE_NET_PROTOCOL_HTTP:
                case VIR_STORAGE_NET_PROTOCOL_HTTPS:
                case VIR_STORAGE_NET_PROTOCOL_FTP:
                case VIR_STORAGE_NET_PROTOCOL_FTPS:
                case VIR_STORAGE_NET_PROTOCOL_TFTP:
                case VIR_STORAGE_NET_PROTOCOL_SSH:
                case VIR_STORAGE_NET_PROTOCOL_LAST:
                case VIR_STORAGE_NET_PROTOCOL_NONE:
                    /* ignored for now */
                    break;
                }
            }

            if (virDomainDiskDefAssignAddress(xmlopt, disk, def) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot assign address for device name '%s'"),
                               disk->dst);
                goto error;
            }

            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto error;
        } else if (STREQ(arg, "-no-acpi")) {
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ABSENT;
        } else if (STREQ(arg, "-no-reboot")) {
            def->onReboot = VIR_DOMAIN_LIFECYCLE_DESTROY;
        } else if (STREQ(arg, "-no-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_QEMU;
        } else if (STREQ(arg, "-enable-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_KVM;
        } else if (STREQ(arg, "-nographic")) {
            nographics = true;
        } else if (STREQ(arg, "-display")) {
            WANT_VALUE();
            if (STREQ(val, "none"))
                nographics = true;
        } else if (STREQ(arg, "-full-screen")) {
            fullscreen = true;
        } else if (STREQ(arg, "-localtime")) {
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
        } else if (STREQ(arg, "-kernel")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.kernel, val) < 0)
                goto error;
        } else if (STREQ(arg, "-bios")) {
            WANT_VALUE();
            if (VIR_ALLOC(def->os.loader) < 0 ||
                VIR_STRDUP(def->os.loader->path, val) < 0)
                goto error;
        } else if (STREQ(arg, "-initrd")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.initrd, val) < 0)
                goto error;
        } else if (STREQ(arg, "-append")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.cmdline, val) < 0)
                goto error;
        } else if (STREQ(arg, "-dtb")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.dtb, val) < 0)
                goto error;
        } else if (STREQ(arg, "-boot")) {
            const char *token = NULL;
            WANT_VALUE();

            if (!strchr(val, ',')) {
                qemuParseCommandLineBootDevs(def, val);
            } else {
                token = val;
                while (token && *token) {
                    if (STRPREFIX(token, "order=")) {
                        token += strlen("order=");
                        qemuParseCommandLineBootDevs(def, token);
                    } else if (STRPREFIX(token, "menu=on")) {
                        def->os.bootmenu = 1;
                    } else if (STRPREFIX(token, "reboot-timeout=")) {
                        int num;
                        char *endptr;
                        if (virStrToLong_i(token + strlen("reboot-timeout="),
                                           &endptr, 10, &num) < 0 ||
                            (*endptr != '\0' && endptr != strchr(token, ','))) {
                            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                           _("cannot parse reboot-timeout value"));
                            goto error;
                        }
                        if (num > 65535)
                            num = 65535;
                        else if (num < -1)
                            num = -1;
                        def->os.bios.rt_delay = num;
                        def->os.bios.rt_set = true;
                    }
                    token = strchr(token, ',');
                    /* This incrementation has to be done here in order to make it
                     * possible to pass the token pointer properly into the loop */
                    if (token)
                        token++;
                }
            }
        } else if (STREQ(arg, "-name")) {
            char *process;
            WANT_VALUE();
            process = strstr(val, ",process=");
            if (process == NULL) {
                if (VIR_STRDUP(def->name, val) < 0)
                    goto error;
            } else {
                if (VIR_STRNDUP(def->name, val, process - val) < 0)
                    goto error;
            }
            if (STREQ(def->name, ""))
                VIR_FREE(def->name);
        } else if (STREQ(arg, "-M") ||
                   STREQ(arg, "-machine")) {
            char *param;
            size_t j = 0;

            /* -machine [type=]name[,prop[=value][,...]]
             * Set os.machine only if first parameter lacks '=' or
             * contains explicit type='...' */
            WANT_VALUE();
            if (!(list = virStringSplit(val, ",", 0)))
                goto error;
            param = list[0];

            if (STRPREFIX(param, "type="))
                param += strlen("type=");
            if (!strchr(param, '=')) {
                if (VIR_STRDUP(def->os.machine, param) < 0)
                    goto error;
                j++;
            }

            /* handle all remaining "-machine" parameters */
            while ((param = list[j++])) {
                if (STRPREFIX(param, "dump-guest-core=")) {
                    param += strlen("dump-guest-core=");
                    def->mem.dump_core = virTristateSwitchTypeFromString(param);
                    if (def->mem.dump_core <= 0)
                        def->mem.dump_core = VIR_TRISTATE_SWITCH_ABSENT;
                } else if (STRPREFIX(param, "mem-merge=off")) {
                    def->mem.nosharepages = true;
                } else if (STRPREFIX(param, "accel=kvm")) {
                    def->virtType = VIR_DOMAIN_VIRT_KVM;
                    def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
                } else if (STRPREFIX(param, "aes-key-wrap=")) {
                    if (STREQ(arg, "-M")) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("aes-key-wrap is not supported with "
                                         "this QEMU binary"));
                        goto error;
                    }
                    param += strlen("aes-key-wrap=");
                    if (!def->keywrap && VIR_ALLOC(def->keywrap) < 0)
                        goto error;
                    def->keywrap->aes = virTristateSwitchTypeFromString(param);
                    if (def->keywrap->aes < 0)
                        def->keywrap->aes = VIR_TRISTATE_SWITCH_ABSENT;
                } else if (STRPREFIX(param, "dea-key-wrap=")) {
                    if (STREQ(arg, "-M")) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("dea-key-wrap is not supported with "
                                         "this QEMU binary"));
                        goto error;
                    }
                    param += strlen("dea-key-wrap=");
                    if (!def->keywrap && VIR_ALLOC(def->keywrap) < 0)
                        goto error;
                    def->keywrap->dea = virTristateSwitchTypeFromString(param);
                    if (def->keywrap->dea < 0)
                        def->keywrap->dea = VIR_TRISTATE_SWITCH_ABSENT;
                }
            }
            virStringListFree(list);
            list = NULL;
        } else if (STREQ(arg, "-serial")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;

                if (!(chr = virDomainChrDefNew(NULL)))
                    goto error;

                if (qemuParseCommandLineChr(chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = def->nserials;
                if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-parallel")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;

                if (!(chr = virDomainChrDefNew(NULL)))
                    goto error;

                if (qemuParseCommandLineChr(chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
                chr->target.port = def->nparallels;
                if (VIR_APPEND_ELEMENT(def->parallels, def->nparallels, chr) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-usbdevice")) {
            WANT_VALUE();
            if (STREQ(val, "tablet") ||
                STREQ(val, "mouse") ||
                STREQ(val, "keyboard")) {
                virDomainInputDefPtr input;
                if (VIR_ALLOC(input) < 0)
                    goto error;
                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(val, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else if (STREQ(val, "mouse"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                else
                    input->type = VIR_DOMAIN_INPUT_TYPE_KBD;

                if (VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input) < 0) {
                    virDomainInputDefFree(input);
                    goto error;
                }
            } else if (STRPREFIX(val, "disk:")) {
                if (!(disk = virDomainDiskDefNew(xmlopt)))
                    goto error;
                if (VIR_STRDUP(disk->src->path, val + strlen("disk:")) < 0)
                    goto error;
                if (STRPREFIX(disk->src->path, "/dev/"))
                    disk->src->type = VIR_STORAGE_TYPE_BLOCK;
                else
                    disk->src->type = VIR_STORAGE_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                disk->bus = VIR_DOMAIN_DISK_BUS_USB;
                disk->removable = VIR_TRISTATE_SWITCH_ABSENT;
                if (VIR_STRDUP(disk->dst, "sda") < 0)
                    goto error;
                if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                    goto error;
            } else {
                virDomainHostdevDefPtr hostdev;
                if (!(hostdev = qemuParseCommandLineUSB(val)))
                    goto error;
                if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
                    virDomainHostdevDefFree(hostdev);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (!STRPREFIX(val, "nic") && STRNEQ(val, "none")) {
                virDomainNetDefPtr net;
                if (!(net = qemuParseCommandLineNet(xmlopt, val, nnics, nics)))
                    goto error;
                if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0) {
                    virDomainNetDefFree(net);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-drive")) {
            WANT_VALUE();
            if (!(disk = qemuParseCommandLineDisk(xmlopt, val, def,
                                                  nvirtiodisk,
                                                  ceph_args != NULL)))
                goto error;
            if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
                nvirtiodisk++;
            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto error;
        } else if (STREQ(arg, "-pcidevice")) {
            virDomainHostdevDefPtr hostdev;
            WANT_VALUE();
            if (!(hostdev = qemuParseCommandLinePCI(val)))
                goto error;
            if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
                virDomainHostdevDefFree(hostdev);
                goto error;
            }
        } else if (STREQ(arg, "-soundhw")) {
            const char *start;
            WANT_VALUE();
            start = val;
            while (start) {
                const char *tmp = strchr(start, ',');
                int type = -1;
                if (STRPREFIX(start, "pcspk")) {
                    type = VIR_DOMAIN_SOUND_MODEL_PCSPK;
                } else if (STRPREFIX(start, "sb16")) {
                    type = VIR_DOMAIN_SOUND_MODEL_SB16;
                } else if (STRPREFIX(start, "es1370")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ES1370;
                } else if (STRPREFIX(start, "ac97")) {
                    type = VIR_DOMAIN_SOUND_MODEL_AC97;
                } else if (STRPREFIX(start, "hda")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ICH6;
                }

                if (type != -1) {
                    virDomainSoundDefPtr snd;
                    if (VIR_ALLOC(snd) < 0)
                        goto error;
                    snd->model = type;
                    if (VIR_APPEND_ELEMENT(def->sounds, def->nsounds, snd) < 0) {
                        VIR_FREE(snd);
                        goto error;
                    }
                }

                start = tmp ? tmp + 1 : NULL;
            }
        } else if (STREQ(arg, "-watchdog")) {
            WANT_VALUE();
            int model = virDomainWatchdogModelTypeFromString(val);

            if (model != -1) {
                virDomainWatchdogDefPtr wd;
                if (VIR_ALLOC(wd) < 0)
                    goto error;
                wd->model = model;
                wd->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;
                def->watchdog = wd;
            }
        } else if (STREQ(arg, "-watchdog-action") && def->watchdog) {
            WANT_VALUE();
            int action = virDomainWatchdogActionTypeFromString(val);

            if (action != -1)
                def->watchdog->action = action;
        } else if (STREQ(arg, "-bootloader")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.bootloader, val) < 0)
                goto error;
        } else if (STREQ(arg, "-vmwarevga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VMVGA;
        } else if (STREQ(arg, "-std-vga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VGA;
        } else if (STREQ(arg, "-vga")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                video = qemuVideoTypeFromString(val);
                if (video < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unknown video adapter type '%s'"), val);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-cpu")) {
            WANT_VALUE();
            if (qemuParseCommandLineCPU(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-domid")) {
            WANT_VALUE();
            /* ignore, generted on the fly */
        } else if (STREQ(arg, "-usb")) {
            if (virDomainDefAddUSBController(def, -1, -1) < 0)
                goto error;
        } else if (STREQ(arg, "-pidfile")) {
            WANT_VALUE();
            if (pidfile)
                if (VIR_STRDUP(*pidfile, val) < 0)
                    goto error;
        } else if (STREQ(arg, "-incoming")) {
            WANT_VALUE();
            /* ignore, used via restore/migrate APIs */
        } else if (STREQ(arg, "-monitor")) {
            WANT_VALUE();
            if (monConfig) {
                virDomainChrSourceDefPtr chr;

                if (VIR_ALLOC(chr) < 0)
                    goto error;

                if (qemuParseCommandLineChr(chr, val) < 0) {
                    virDomainChrSourceDefFree(chr);
                    goto error;
                }

                *monConfig = chr;
            }
        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s3=")) {
            /* We want to parse only the known "-global" parameters,
             * so the ones that we don't know are still added to the
             * namespace */
            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s3=");
            if (STREQ(val, "0")) {
                def->pm.s3 = VIR_TRISTATE_BOOL_YES;
            } else if (STREQ(val, "1")) {
                def->pm.s3 = VIR_TRISTATE_BOOL_NO;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s3 parameter: "
                                 "'%s'"), val);
                goto error;
            }

        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s4=")) {

            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s4=");
            if (STREQ(val, "0")) {
                def->pm.s4 = VIR_TRISTATE_BOOL_YES;
            } else if (STREQ(val, "1")) {
                def->pm.s4 = VIR_TRISTATE_BOOL_NO;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s4 parameter: "
                                 "'%s'"), val);
                goto error;
            }

        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "spapr-nvram.reg=")) {
            WANT_VALUE();

            if (VIR_ALLOC(def->nvram) < 0)
                goto error;

            def->nvram->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
            def->nvram->info.addr.spaprvio.has_reg = true;

            val += strlen("spapr-nvram.reg=");
            if (virStrToLong_ull(val, NULL, 16,
                                 &def->nvram->info.addr.spaprvio.reg) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse nvram's address '%s'"), val);
                goto error;
            }
        } else if (STREQ(arg, "-S") ||
                   STREQ(arg, "-nodefaults") ||
                   STREQ(arg, "-nodefconfig")) {
            /* ignore, always added by libvirt */
        } else if (STREQ(arg, "-device") && progargv[1 + 1]) {
            const char *opts = progargv[i + 1];

            /* NB: we can't do WANT_VALUE until we're sure that we
             * recognize the device, otherwise the !argRecognized
             * logic below will be messed up
             */

            if (STRPREFIX(opts, "virtio-balloon")) {
                WANT_VALUE();
                if (VIR_ALLOC(def->memballoon) < 0)
                    goto error;
                def->memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO;
            } else {
                /* add in new -device's here */

                argRecognized = false;
            }
        } else {
            argRecognized = false;
        }

        if (!argRecognized) {
            char *tmp = NULL;
            /* something we can't yet parse.  Add it to the qemu namespace
             * cmdline/environment advanced options and hope for the best
             */
            VIR_WARN("unknown QEMU argument '%s', adding to the qemu namespace",
                     arg);
            if (VIR_STRDUP(tmp, arg) < 0 ||
                VIR_APPEND_ELEMENT(cmd->args, cmd->num_args, tmp) < 0) {
                VIR_FREE(tmp);
                goto error;
            }
        }
    }

#undef WANT_VALUE
    if (def->ndisks > 0 && ceph_args) {
        char *hosts, *port, *saveptr = NULL, *token;
        virDomainDiskDefPtr first_rbd_disk = NULL;
        for (i = 0; i < def->ndisks; i++) {
            if (def->disks[i]->src->type == VIR_STORAGE_TYPE_NETWORK &&
                def->disks[i]->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
                first_rbd_disk = def->disks[i];
                break;
            }
        }

        if (!first_rbd_disk) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CEPH_ARGS was set without an rbd disk"));
            goto error;
        }

        /* CEPH_ARGS should be: -m host1[:port1][,host2[:port2]]... */
        if (!STRPREFIX(ceph_args, "-m ")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not parse CEPH_ARGS '%s'"), ceph_args);
            goto error;
        }
        if (VIR_STRDUP(hosts, strchr(ceph_args, ' ') + 1) < 0)
            goto error;
        first_rbd_disk->src->nhosts = 0;
        token = strtok_r(hosts, ",", &saveptr);
        while (token != NULL) {
            if (VIR_REALLOC_N(first_rbd_disk->src->hosts,
                              first_rbd_disk->src->nhosts + 1) < 0) {
                VIR_FREE(hosts);
                goto error;
            }
            port = strchr(token, ':');
            if (port) {
                *port++ = '\0';
                if (VIR_STRDUP(port, port) < 0) {
                    VIR_FREE(hosts);
                    goto error;
                }
            }
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].port = port;
            if (VIR_STRDUP(first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].name,
                           token) < 0) {
                VIR_FREE(hosts);
                goto error;
            }
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].socket = NULL;

            first_rbd_disk->src->nhosts++;
            token = strtok_r(NULL, ",", &saveptr);
        }
        VIR_FREE(hosts);

        if (first_rbd_disk->src->nhosts == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("found no rbd hosts in CEPH_ARGS '%s'"), ceph_args);
            goto error;
        }
    }

    if (!def->os.machine) {
        virCapsDomainDataPtr capsdata;

        if (!(capsdata = virCapabilitiesDomainDataLookup(caps, def->os.type,
                def->os.arch, def->virtType, NULL, NULL)))
            goto error;

        if (VIR_STRDUP(def->os.machine, capsdata->machinetype) < 0) {
            VIR_FREE(capsdata);
            goto error;
        }
        VIR_FREE(capsdata);
    }

    if (!nographics && (def->ngraphics == 0 || have_sdl)) {
        virDomainGraphicsDefPtr sdl;
        const char *display = qemuFindEnv(progenv, "DISPLAY");
        const char *xauth = qemuFindEnv(progenv, "XAUTHORITY");
        if (VIR_ALLOC(sdl) < 0)
            goto error;
        sdl->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        sdl->data.sdl.fullscreen = fullscreen;
        if (VIR_STRDUP(sdl->data.sdl.display, display) < 0) {
            VIR_FREE(sdl);
            goto error;
        }
        if (VIR_STRDUP(sdl->data.sdl.xauth, xauth) < 0) {
            VIR_FREE(sdl);
            goto error;
        }

        if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, sdl) < 0) {
            virDomainGraphicsDefFree(sdl);
            goto error;
        }
    }

    if (def->ngraphics) {
        virDomainVideoDefPtr vid;
        if (VIR_ALLOC(vid) < 0)
            goto error;
        if (def->virtType == VIR_DOMAIN_VIRT_XEN)
            vid->type = VIR_DOMAIN_VIDEO_TYPE_XEN;
        else
            vid->type = video;
        if (vid->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
            vid->vgamem = QEMU_QXL_VGAMEM_DEFAULT;
        } else {
            vid->ram = 0;
            vid->vgamem = 0;
        }
        vid->heads = 1;

        if (VIR_APPEND_ELEMENT(def->videos, def->nvideos, vid) < 0) {
            virDomainVideoDefFree(vid);
            goto error;
        }
    }

    /*
     * having a balloon is the default, define one with type="none" to avoid it
     */
    if (!def->memballoon) {
        virDomainMemballoonDefPtr memballoon;
        if (VIR_ALLOC(memballoon) < 0)
            goto error;
        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_NONE;

        def->memballoon = memballoon;
    }

    VIR_FREE(nics);

    if (virDomainDefPostParse(def, caps, 0, xmlopt, NULL) < 0)
        goto error;

    if (cmd->num_args || cmd->num_env) {
        def->ns = *virDomainXMLOptionGetNamespace(xmlopt);
        def->namespaceData = cmd;
    }
    else
        qemuDomainCmdlineDefFree(cmd);

    return def;

 error:
    virDomainDiskDefFree(disk);
    qemuDomainCmdlineDefFree(cmd);
    virDomainDefFree(def);
    virStringListFree(list);
    VIR_FREE(nics);
    if (monConfig) {
        virDomainChrSourceDefFree(*monConfig);
        *monConfig = NULL;
    }
    if (pidfile)
        VIR_FREE(*pidfile);
    return NULL;
}


virDomainDefPtr qemuParseCommandLineString(virCapsPtr caps,
                                           virDomainXMLOptionPtr xmlopt,
                                           const char *args,
                                           char **pidfile,
                                           virDomainChrSourceDefPtr *monConfig,
                                           bool *monJSON)
{
    char **progenv = NULL;
    char **progargv = NULL;
    virDomainDefPtr def = NULL;

    if (qemuStringToArgvEnv(args, &progenv, &progargv) < 0)
        goto cleanup;

    def = qemuParseCommandLine(caps, xmlopt, progenv, progargv,
                               pidfile, monConfig, monJSON);

 cleanup:
    virStringListFree(progargv);
    virStringListFree(progenv);

    return def;
}


static int qemuParseProcFileStrings(int pid_value,
                                    const char *name,
                                    char ***list)
{
    char *path = NULL;
    int ret = -1;
    char *data = NULL;
    ssize_t len;
    char *tmp;
    size_t nstr = 0;
    char **str = NULL;

    if (virAsprintf(&path, "/proc/%d/%s", pid_value, name) < 0)
        goto cleanup;

    if ((len = virFileReadAll(path, 1024*128, &data)) < 0)
        goto cleanup;

    tmp = data;
    while (tmp < (data + len)) {
        if (VIR_EXPAND_N(str, nstr, 1) < 0)
            goto cleanup;

        if (VIR_STRDUP(str[nstr-1], tmp) < 0)
            goto cleanup;
        /* Skip arg */
        tmp += strlen(tmp);
        /* Skip \0 separator */
        tmp++;
    }

    if (VIR_EXPAND_N(str, nstr, 1) < 0)
        goto cleanup;

    str[nstr-1] = NULL;

    ret = nstr-1;
    *list = str;

 cleanup:
    if (ret < 0)
        virStringListFree(str);
    VIR_FREE(data);
    VIR_FREE(path);
    return ret;
}

virDomainDefPtr qemuParseCommandLinePid(virCapsPtr caps,
                                        virDomainXMLOptionPtr xmlopt,
                                        pid_t pid,
                                        char **pidfile,
                                        virDomainChrSourceDefPtr *monConfig,
                                        bool *monJSON)
{
    virDomainDefPtr def = NULL;
    char **progargv = NULL;
    char **progenv = NULL;
    char *exepath = NULL;
    char *emulator;

    /* The parser requires /proc/pid, which only exists on platforms
     * like Linux where pid_t fits in int.  */
    if ((int) pid != pid ||
        qemuParseProcFileStrings(pid, "cmdline", &progargv) < 0 ||
        qemuParseProcFileStrings(pid, "environ", &progenv) < 0)
        goto cleanup;

    if (!(def = qemuParseCommandLine(caps, xmlopt, progenv, progargv,
                                     pidfile, monConfig, monJSON)))
        goto cleanup;

    if (virAsprintf(&exepath, "/proc/%d/exe", (int) pid) < 0)
        goto cleanup;

    if (virFileResolveLink(exepath, &emulator) < 0) {
        virReportSystemError(errno,
                             _("Unable to resolve %s for pid %u"),
                             exepath, (int) pid);
        goto cleanup;
    }
    VIR_FREE(def->emulator);
    def->emulator = emulator;

 cleanup:
    VIR_FREE(exepath);
    virStringListFree(progargv);
    virStringListFree(progenv);
    return def;
}
