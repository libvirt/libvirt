/*
 * qemu_block.c: helper functions for QEMU block subsystem
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

#include "qemu_block.h"
#include "qemu_command.h"
#include "qemu_domain.h"
#include "qemu_alias.h"
#include "qemu_security.h"

#include "storage_source.h"
#include "viralloc.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_block");

/* qemu declares the buffer for node names as a 32 byte array */
static const size_t qemuBlockNodeNameBufSize = 32;

static int
qemuBlockNodeNameValidate(const char *nn)
{
    if (!nn)
        return 0;

    if (strlen(nn) >= qemuBlockNodeNameBufSize) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("node-name '%s' too long for qemu"), nn);
        return -1;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceSupportsConcurrentAccess:
 * @src: disk storage source
 *
 * Returns true if the given storage format supports concurrent access from two
 * separate processes.
 */
bool
qemuBlockStorageSourceSupportsConcurrentAccess(virStorageSource *src)
{
    /* no need to check in backing chain since only RAW storage supports this */
    return src->format == VIR_STORAGE_FILE_RAW;
}


/**
 * qemuBlockStorageSourceGetURI:
 * @src: disk storage source
 *
 * Formats a URI from a virStorageSource.
 */
virURI *
qemuBlockStorageSourceGetURI(virStorageSource *src)
{
    g_autoptr(virURI) uri = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("protocol '%s' accepts only one host"),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    uri = g_new0(virURI, 1);

    if (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {
        uri->port = src->hosts->port;

        uri->scheme = g_strdup(virStorageNetProtocolTypeToString(src->protocol));
    } else {
        uri->scheme = g_strdup_printf("%s+%s",
                                      virStorageNetProtocolTypeToString(src->protocol),
                                      virStorageNetHostTransportTypeToString(src->hosts->transport));
    }

    if (src->path) {
        if (src->volume) {
            uri->path = g_strdup_printf("/%s/%s", src->volume, src->path);
        } else {
            uri->path = g_strdup_printf("%s%s",
                                        g_path_is_absolute(src->path) ? "" : "/",
                                        src->path);
        }
    }

    uri->query = g_strdup(src->query);

    uri->server = g_strdup(src->hosts->name);

    return g_steal_pointer(&uri);
}


/**
 * qemuBlockStorageSourceBuildJSONSocketAddress
 * @host: the virStorageNetHostDef * definition to build
 *
 * Formats @hosts into a json object conforming to the 'SocketAddress' type
 * in qemu.
 *
 * Returns a virJSONValue * for a single server.
 */
static virJSONValue *
qemuBlockStorageSourceBuildJSONSocketAddress(virStorageNetHostDef *host)
{
    g_autoptr(virJSONValue) server = NULL;
    g_autofree char *port = NULL;

    switch ((virStorageNetHostTransport) host->transport) {
    case VIR_STORAGE_NET_HOST_TRANS_TCP:
        port = g_strdup_printf("%u", host->port);

        if (virJSONValueObjectAdd(&server,
                                  "s:type", "inet",
                                  "s:host", host->name,
                                  "s:port", port,
                                  NULL) < 0)
            return NULL;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_UNIX:
        if (virJSONValueObjectAdd(&server,
                                  "s:type", "unix",
                                  "s:path", host->socket,
                                  NULL) < 0)
            return NULL;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_RDMA:
    case VIR_STORAGE_NET_HOST_TRANS_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("transport protocol '%s' is not yet supported"),
                       virStorageNetHostTransportTypeToString(host->transport));
        return NULL;
    }

    return g_steal_pointer(&server);
}


/**
 * qemuBlockStorageSourceBuildHostsJSONSocketAddress:
 * @src: disk storage source
 *
 * Formats src->hosts into a json object conforming to the 'SocketAddress' type
 * in qemu.
 */
static virJSONValue *
qemuBlockStorageSourceBuildHostsJSONSocketAddress(virStorageSource *src)
{
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) server = NULL;
    virStorageNetHostDef *host;
    size_t i;

    servers = virJSONValueNewArray();

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONSocketAddress(host)))
              return NULL;

        if (virJSONValueArrayAppend(servers, &server) < 0)
            return NULL;
    }

    return g_steal_pointer(&servers);
}


/**
 * qemuBlockStorageSourceBuildJSONInetSocketAddress
 * @host: the virStorageNetHostDef * definition to build
 *
 * Formats @hosts into a json object conforming to the 'InetSocketAddress' type
 * in qemu.
 *
 * Returns a virJSONValue *for a single server.
 */
static virJSONValue *
qemuBlockStorageSourceBuildJSONInetSocketAddress(virStorageNetHostDef *host)
{
    virJSONValue *ret = NULL;
    g_autofree char *port = NULL;

    if (host->transport != VIR_STORAGE_NET_HOST_TRANS_TCP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only TCP protocol can be converted to InetSocketAddress"));
        return NULL;
    }

    port = g_strdup_printf("%u", host->port);

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:host", host->name,
                                       "s:port", port,
                                       NULL));

    return ret;
}


/**
 * qemuBlockStorageSourceBuildJSONNFSServer(virStorageNetHostDef *host)
 * @host: the virStorageNetHostDef * definition to build
 *
 * Formats @hosts into a json object conforming to the 'NFSServer' type
 * in qemu.
 *
 * Returns a virJSONValue *for a single server.
 */
static virJSONValue *
qemuBlockStorageSourceBuildJSONNFSServer(virStorageNetHostDef *host)
{
    virJSONValue *ret = NULL;

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:host", host->name,
                                       "s:type", "inet",
                                       NULL));

    return ret;
}


/**
 * qemuBlockStorageSourceBuildHostsJSONInetSocketAddress:
 * @src: disk storage source
 *
 * Formats src->hosts into a json object conforming to the 'InetSocketAddress'
 * type in qemu.
 */
static virJSONValue *
qemuBlockStorageSourceBuildHostsJSONInetSocketAddress(virStorageSource *src)
{
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) server = NULL;
    virStorageNetHostDef *host;
    size_t i;

    servers = virJSONValueNewArray();

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(host)))
            return NULL;

        if (virJSONValueArrayAppend(servers, &server) < 0)
            return NULL;
    }

    return g_steal_pointer(&servers);
}


static virJSONValue *
qemuBlockStorageSourceGetGlusterProps(virStorageSource *src,
                                      bool onlytarget)
{
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(servers = qemuBlockStorageSourceBuildHostsJSONSocketAddress(src)))
        return NULL;

     /* { driver:"gluster",
      *   volume:"testvol",
      *   path:"/a.img",
      *   server :[{type:"tcp", host:"1.2.3.4", port:24007},
      *            {type:"unix", socket:"/tmp/glusterd.socket"}, ...]}
      */
    if (virJSONValueObjectAdd(&props,
                              "s:volume", src->volume,
                              "s:path", src->path,
                              "a:server", &servers, NULL) < 0)
        return NULL;

    if (!onlytarget &&
        src->debug &&
        virJSONValueObjectAdd(&props, "u:debug", src->debugLevel, NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBlockStorageSourceGetVxHSProps(virStorageSource *src,
                                   bool onlytarget)
{
    g_autoptr(virJSONValue) server = NULL;
    const char *tlsAlias = src->tlsAlias;
    virJSONValue *ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VxHS protocol accepts only one host"));
        return NULL;
    }

    if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(&src->hosts[0])))
        return NULL;

    if (onlytarget)
        tlsAlias = NULL;

    /* VxHS disk specification example:
     * { driver:"vxhs",
     *   tls-creds:"objvirtio-disk0_tls0",
     *   vdisk-id:"eb90327c-8302-4725-4e85ed4dc251",
     *   server:{type:"tcp", host:"1.2.3.4", port:9999}}
     */
    ignore_value(virJSONValueObjectAdd(&ret,
                                       "S:tls-creds", tlsAlias,
                                       "s:vdisk-id", src->path,
                                       "a:server", &server, NULL));

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetNFSProps(virStorageSource *src)
{
    g_autoptr(virJSONValue) server = NULL;
    virJSONValue *ret = NULL;

    if (!(server = qemuBlockStorageSourceBuildJSONNFSServer(&src->hosts[0])))
        return NULL;

    /* NFS disk specification example:
     * { driver:"nfs",
     *   user: "0",
     *   group: "0",
     *   path: "/foo/bar/baz",
     *   server: {type:"tcp", host:"1.2.3.4"}}
     */
    if (virJSONValueObjectAdd(&ret,
                              "a:server", &server,
                              "S:path", src->path, NULL) < 0)
        return NULL;

    if (src->nfs_uid != -1 &&
        virJSONValueObjectAdd(&ret, "i:user", src->nfs_uid, NULL) < 0)
        return NULL;

    if (src->nfs_gid != -1 &&
        virJSONValueObjectAdd(&ret, "i:group", src->nfs_gid, NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetCURLProps(virStorageSource *src,
                                   bool onlytarget)
{
    qemuDomainStorageSourcePrivate *srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *passwordalias = NULL;
    const char *cookiealias = NULL;
    const char *username = NULL;
    virJSONValue *ret = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *uristr = NULL;
    g_autofree char *cookiestr = NULL;

    /**
     * Common options:
     * url, readahead, timeout, username, password-secret, proxy-username,
     * proxy-password-secret
     *
     * Options for http transport:
     * cookie, cookie-secret
     *
     * Options for secure transport (ftps, https):
     * sslverify
     */


    if (!(uri = qemuBlockStorageSourceGetURI(src)))
        return NULL;

    if (!(uristr = virURIFormat(uri)))
        return NULL;

    if (!onlytarget) {
        if (src->auth) {
            username = src->auth->username;
            passwordalias = srcPriv->secinfo->alias;
        }

        if (srcPriv &&
            srcPriv->httpcookie)
            cookiealias = srcPriv->httpcookie->alias;
    } else {
        /* format target string along with cookies */
        cookiestr = qemuBlockStorageSourceGetCookieString(src);
    }

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:url", uristr,
                                       "S:username", username,
                                       "S:password-secret", passwordalias,
                                       "T:sslverify", src->sslverify,
                                       "S:cookie", cookiestr,
                                       "S:cookie-secret", cookiealias,
                                       "P:timeout", src->timeout,
                                       "P:readahead", src->readahead,
                                       NULL));

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetISCSIProps(virStorageSource *src,
                                    bool onlytarget)
{
    qemuDomainStorageSourcePrivate *srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autofree char *target = NULL;
    char *lunStr = NULL;
    char *username = NULL;
    char *objalias = NULL;
    g_autofree char *portal = NULL;
    unsigned int lun = 0;
    virJSONValue *ret = NULL;

    /* { driver:"iscsi",
     *   transport:"tcp",  ("iser" also possible)
     *   portal:"example.com",
     *   target:"iqn.2017-04.com.example:iscsi-disks",
     *   lun:1,
     *   user:"username",
     *   password-secret:"secret-alias",
     *   initiator-name:"iqn.2017-04.com.example:client"
     * }
     */

    target = g_strdup(src->path);

    /* Separate the target and lun */
    if ((lunStr = strchr(target, '/'))) {
        *(lunStr++) = '\0';
        if (virStrToLong_ui(lunStr, NULL, 10, &lun) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse target for lunStr '%s'"),
                           target);
            return NULL;
        }
    }

    /* combine host and port into portal */
    if (virSocketAddrNumericFamily(src->hosts[0].name) == AF_INET6) {
        portal = g_strdup_printf("[%s]:%u", src->hosts[0].name,
                                 src->hosts[0].port);
    } else {
        portal = g_strdup_printf("%s:%u", src->hosts[0].name, src->hosts[0].port);
    }

    if (!onlytarget && src->auth) {
        username = src->auth->username;
        objalias = srcPriv->secinfo->alias;
    }

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:portal", portal,
                                       "s:target", target,
                                       "u:lun", lun,
                                       "s:transport", "tcp",
                                       "S:user", username,
                                       "S:password-secret", objalias,
                                       "S:initiator-name", src->initiator.iqn,
                                       NULL));
    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetNBDProps(virStorageSource *src,
                                  bool onlytarget)
{
    g_autoptr(virJSONValue) serverprops = NULL;
    const char *tlsAlias = src->tlsAlias;
    const char *tlsHostname = src->tlsHostname;
    virJSONValue *ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nbd protocol accepts only one host"));
        return NULL;
    }

    if (!(serverprops = qemuBlockStorageSourceBuildJSONSocketAddress(&src->hosts[0])))
        return NULL;

    if (onlytarget) {
        tlsAlias = NULL;
        tlsHostname = NULL;
    }

    if (virJSONValueObjectAdd(&ret,
                              "a:server", &serverprops,
                              "S:export", src->path,
                              "S:tls-creds", tlsAlias,
                              "S:tls-hostname", tlsHostname,
                              "p:reconnect-delay", src->reconnectDelay,
                              "p:open-timeout", src->openTimeout,
                              NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetRBDProps(virStorageSource *src,
                                  bool onlytarget)
{
    qemuDomainStorageSourcePrivate *srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(virJSONValue) servers = NULL;
    virJSONValue *ret = NULL;
    g_autoptr(virJSONValue) encrypt = NULL;
    const char *encformat = NULL;
    const char *username = NULL;
    g_autoptr(virJSONValue) authmodes = NULL;
    const char *keysecret = NULL;

    if (src->nhosts > 0 &&
        !(servers = qemuBlockStorageSourceBuildHostsJSONInetSocketAddress(src)))
        return NULL;

    if (!onlytarget && src->auth) {
        username = srcPriv->secinfo->username;
        keysecret = srcPriv->secinfo->alias;
        /* the auth modes are modelled after our old command line generator */
        if (!(authmodes = virJSONValueFromString("[\"cephx\",\"none\"]")))
            return NULL;
    }

    if (src->encryption &&
        src->encryption->engine == VIR_STORAGE_ENCRYPTION_ENGINE_LIBRBD) {
        switch ((virStorageEncryptionFormatType) src->encryption->format) {
            case VIR_STORAGE_ENCRYPTION_FORMAT_LUKS:
                encformat = "luks";
                break;

            case VIR_STORAGE_ENCRYPTION_FORMAT_LUKS2:
                encformat = "luks2";
                break;

            case VIR_STORAGE_ENCRYPTION_FORMAT_QCOW:
            case VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT:
            case VIR_STORAGE_ENCRYPTION_FORMAT_LAST:
            default:
                break;
        }

        if (virJSONValueObjectAdd(&encrypt,
                                  "s:format", encformat,
                                  "s:key-secret", srcPriv->encinfo->alias,
                                  NULL) < 0)
            return NULL;
    }

    if (virJSONValueObjectAdd(&ret,
                              "s:pool", src->volume,
                              "s:image", src->path,
                              "S:snapshot", src->snapshot,
                              "S:conf", src->configFile,
                              "A:server", &servers,
                              "A:encrypt", &encrypt,
                              "S:user", username,
                              "A:auth-client-required", &authmodes,
                              "S:key-secret", keysecret,
                              NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetSheepdogProps(virStorageSource *src)
{
    g_autoptr(virJSONValue) serverprops = NULL;
    virJSONValue *ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("sheepdog protocol accepts only one host"));
        return NULL;
    }

    if (!(serverprops = qemuBlockStorageSourceBuildJSONSocketAddress(&src->hosts[0])))
        return NULL;

    /* libvirt does not support the 'snap-id' and 'tag' properties */
    if (virJSONValueObjectAdd(&ret,
                              "a:server", &serverprops,
                              "s:vdi", src->path,
                              NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetSshProps(virStorageSource *src)
{
    g_autoptr(virJSONValue) serverprops = NULL;
    virJSONValue *ret = NULL;
    const char *username = NULL;
    g_autoptr(virJSONValue) host_key_check = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("ssh protocol accepts only one host"));
        return NULL;
    }

    serverprops = qemuBlockStorageSourceBuildJSONInetSocketAddress(&src->hosts[0]);
    if (!serverprops)
        return NULL;

    if (src->auth)
        username = src->auth->username;
    else if (src->ssh_user)
        username = src->ssh_user;

    if (src->ssh_host_key_check_disabled &&
        virJSONValueObjectAdd(&host_key_check,
                              "s:mode", "none",
                              NULL) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&ret,
                              "s:path", src->path,
                              "a:server", &serverprops,
                              "S:user", username,
                              "A:host-key-check", &host_key_check,
                              NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetFileProps(virStorageSource *src,
                                   bool onlytarget)
{
    const char *iomode = NULL;
    const char *prManagerAlias = NULL;
    virJSONValue *ret = NULL;

    if (!onlytarget) {
        if (src->pr)
            prManagerAlias = src->pr->mgralias;

        if (src->iomode != VIR_DOMAIN_DISK_IO_DEFAULT)
            iomode = virDomainDiskIoTypeToString(src->iomode);
    }

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:filename", src->path,
                                       "S:aio", iomode,
                                       "S:pr-manager", prManagerAlias,
                                       NULL) < 0);
    return ret;
}


static virJSONValue *
qemuBlockStorageSourceGetVvfatProps(virStorageSource *src,
                                    bool onlytarget)
{
    g_autoptr(virJSONValue) ret = NULL;

    /* libvirt currently does not handle the following attributes:
     * '*fat-type': 'int'
     * '*label': 'str'
     */
    if (virJSONValueObjectAdd(&ret,
                              "s:driver", "vvfat",
                              "s:dir", src->path,
                              "b:floppy", src->floppyimg, NULL) < 0)
        return NULL;

    if (!onlytarget &&
        virJSONValueObjectAdd(&ret, "b:rw", !src->readonly, NULL) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


static virJSONValue *
qemuBlockStorageSourceGetNVMeProps(virStorageSource *src)
{
    const virStorageSourceNVMeDef *nvme = src->nvme;
    g_autofree char *pciAddr = NULL;
    virJSONValue *ret = NULL;

    if (!(pciAddr = virPCIDeviceAddressAsString(&nvme->pciAddr)))
        return NULL;

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:driver", "nvme",
                                       "s:device", pciAddr,
                                       "U:namespace", nvme->namespc,
                                       NULL));
    return ret;
}


static int
qemuBlockStorageSourceGetBlockdevGetCacheProps(virStorageSource *src,
                                               virJSONValue *props)
{
    g_autoptr(virJSONValue) cacheobj = NULL;
    bool direct = false;
    bool noflush = false;

    if (src->cachemode == VIR_DOMAIN_DISK_CACHE_DEFAULT)
        return 0;

    if (qemuDomainDiskCachemodeFlags(src->cachemode, NULL, &direct, &noflush) < 0)
        return -1;

    if (virJSONValueObjectAdd(&cacheobj,
                              "b:direct", direct,
                              "b:no-flush", noflush,
                              NULL) < 0)
        return -1;

    if (virJSONValueObjectAppend(props, "cache", &cacheobj) < 0)
        return -1;

    return 0;
}


/**
 * qemuBlockStorageSourceGetBackendProps:
 * @src: disk source
 * @flags: bitwise-or of qemuBlockStorageSourceBackendPropsFlags
 *
 * Flags:
 *  QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_LEGACY:
 *      use legacy formatting of attributes (for -drive / old qemus)
 *  QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY:
 *      omit any data which does not identify the image itself
 *  QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY:
 *      use the auto-read-only feature of qemu
 *  QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_SKIP_UNMAP:
 *      don't enable 'discard:unmap' option for passing through discards
 *      (note that this is disabled also for _LEGACY and _TARGET_ONLY options)
 *
 * Creates a JSON object describing the underlying storage or protocol of a
 * storage source. Returns NULL on error and reports an appropriate error message.
 */
virJSONValue *
qemuBlockStorageSourceGetBackendProps(virStorageSource *src,
                                      unsigned int flags)
{
    virStorageType actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) fileprops = NULL;
    const char *driver = NULL;
    virTristateBool aro = VIR_TRISTATE_BOOL_ABSENT;
    virTristateBool ro = VIR_TRISTATE_BOOL_ABSENT;
    bool onlytarget = flags & QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY;
    bool legacy = flags & QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_LEGACY;

    if (flags & QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY) {
        aro = VIR_TRISTATE_BOOL_YES;
    } else {
        if (src->readonly)
            ro = VIR_TRISTATE_BOOL_YES;
        else
            ro = VIR_TRISTATE_BOOL_NO;
    }

    switch (actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        if (virStorageSourceIsBlockLocal(src)) {
            if (src->hostcdrom)
                driver = "host_cdrom";
            else
                driver = "host_device";
        } else {
            driver = "file";
        }

        if (!(fileprops = qemuBlockStorageSourceGetFileProps(src, onlytarget)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_DIR:
        /* qemu handles directories by exposing them as a device with emulated
         * FAT filesystem */
        if (!(fileprops = qemuBlockStorageSourceGetVvfatProps(src, onlytarget)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_NVME:
        if (!(fileprops = qemuBlockStorageSourceGetNVMeProps(src)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_VHOST_USER:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to create blockdev props for vhostuser disk type"));
        return NULL;

    case VIR_STORAGE_TYPE_VOLUME:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("storage source pool '%s' volume '%s' is not translated"),
                       src->srcpool->pool, src->srcpool->volume);
        return NULL;

    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportEnumRangeError(virStorageType, actualType);
        return NULL;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            driver = "gluster";
            if (!(fileprops = qemuBlockStorageSourceGetGlusterProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_VXHS:
            driver = "vxhs";
            if (!(fileprops = qemuBlockStorageSourceGetVxHSProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            driver = virStorageNetProtocolTypeToString(src->protocol);
            if (!(fileprops = qemuBlockStorageSourceGetCURLProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
            driver = "iscsi";
            if (!(fileprops = qemuBlockStorageSourceGetISCSIProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
            driver = "nbd";
            if (!(fileprops = qemuBlockStorageSourceGetNBDProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            driver = "rbd";
            if (!(fileprops = qemuBlockStorageSourceGetRBDProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            driver = "sheepdog";
            if (!(fileprops = qemuBlockStorageSourceGetSheepdogProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            driver = "ssh";
            if (!(fileprops = qemuBlockStorageSourceGetSshProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NFS:
            driver = "nfs";
            if (!(fileprops = qemuBlockStorageSourceGetNFSProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportEnumRangeError(virStorageNetProtocol, src->protocol);
            return NULL;
        }
        break;
    }

    if (driver && virJSONValueObjectPrependString(fileprops, "driver", driver) < 0)
        return NULL;

    if (!onlytarget) {
        if (qemuBlockNodeNameValidate(src->nodestorage) < 0 ||
            virJSONValueObjectAdd(&fileprops, "S:node-name", src->nodestorage, NULL) < 0)
            return NULL;

        if (!legacy) {
            if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, fileprops) < 0)
                return NULL;

            if (virJSONValueObjectAdd(&fileprops,
                                      "T:read-only", ro,
                                      "T:auto-read-only", aro,
                                      NULL) < 0)
                return NULL;

            if (!(flags & QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_SKIP_UNMAP) &&
                virJSONValueObjectAdd(&fileprops,
                                      "s:discard", "unmap",
                                      NULL) < 0)
                return NULL;
        }
    }

    return g_steal_pointer(&fileprops);
}


static int
qemuBlockStorageSourceGetFormatLUKSProps(virStorageSource *src,
                                         virJSONValue *props)
{
    qemuDomainStorageSourcePrivate *srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

    if (!srcPriv || !srcPriv->encinfo || !srcPriv->encinfo->alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing secret info for 'luks' driver"));
        return -1;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "luks",
                              "s:key-secret", srcPriv->encinfo->alias,
                              NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceGetFormatRawProps(virStorageSource *src,
                                        virJSONValue *props)
{
    if (virJSONValueObjectAdd(&props, "s:driver", "raw", NULL) < 0)
        return -1;

    /* Currently only storage slices are supported. We'll have to calculate
     * the union of the slices here if we don't want to be adding needless
     * 'raw' nodes. */
    if (src->sliceStorage &&
        virJSONValueObjectAdd(&props,
                              "U:offset", src->sliceStorage->offset,
                              "U:size", src->sliceStorage->size,
                              NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceGetCryptoProps(virStorageSource *src,
                                     virJSONValue **encprops)
{
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *encformat = NULL;

    *encprops = NULL;

    if (!src->encryption ||
        src->encryption->engine != VIR_STORAGE_ENCRYPTION_ENGINE_QEMU ||
        !srcpriv ||
        !srcpriv->encinfo)
        return 0;

    switch ((virStorageEncryptionFormatType) src->encryption->format) {
    case VIR_STORAGE_ENCRYPTION_FORMAT_QCOW:
        encformat = "aes";
        break;

    case VIR_STORAGE_ENCRYPTION_FORMAT_LUKS:
        encformat = "luks";
        break;

    case VIR_STORAGE_ENCRYPTION_FORMAT_LUKS2:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("luks2 is currently not supported by the qemu encryption engine"));
        return -1;

    case VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT:
    case VIR_STORAGE_ENCRYPTION_FORMAT_LAST:
    default:
        virReportEnumRangeError(virStorageEncryptionFormatType,
                                src->encryption->format);
        return -1;
    }

    return virJSONValueObjectAdd(encprops,
                                 "s:format", encformat,
                                 "s:key-secret", srcpriv->encinfo->alias,
                                 NULL);
}


static int
qemuBlockStorageSourceGetFormatQcowGenericProps(virStorageSource *src,
                                                const char *format,
                                                virJSONValue *props)
{
    g_autoptr(virJSONValue) encprops = NULL;

    if (qemuBlockStorageSourceGetCryptoProps(src, &encprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", format,
                              "A:encrypt", &encprops, NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceGetFormatQcow2Props(virStorageSource *src,
                                          virJSONValue *props)
{
    /* currently unhandled qcow2 props:
     *
     * 'lazy-refcounts'
     * 'pass-discard-request'
     * 'pass-discard-snapshot'
     * 'pass-discard-other'
     * 'overlap-check'
     * 'l2-cache-size'
     * 'l2-cache-entry-size'
     * 'refcount-cache-size'
     * 'cache-clean-interval'
     */

    if (qemuBlockStorageSourceGetFormatQcowGenericProps(src, "qcow2", props) < 0)
        return -1;

    /* 'cache-size' controls the maximum size of L2 and refcount caches.
     * see: qemu.git/docs/qcow2-cache.txt
     * https://git.qemu.org/?p=qemu.git;a=blob;f=docs/qcow2-cache.txt
     */
    if (src->metadataCacheMaxSize > 0) {
        if (virJSONValueObjectAdd(&props,
                                  "U:cache-size", src->metadataCacheMaxSize,
                                  NULL) < 0)
            return -1;
    }

    return 0;
}


static virJSONValue *
qemuBlockStorageSourceGetBlockdevFormatCommonProps(virStorageSource *src)
{
    const char *detectZeroes = NULL;
    const char *discard = NULL;
    int detectZeroesMode = virDomainDiskGetDetectZeroesMode(src->discard,
                                                            src->detect_zeroes);
    g_autoptr(virJSONValue) props = NULL;

    if (qemuBlockNodeNameValidate(src->nodeformat) < 0)
        return NULL;

    if (src->discard)
        discard = virDomainDiskDiscardTypeToString(src->discard);

    if (detectZeroesMode)
        detectZeroes = virDomainDiskDetectZeroesTypeToString(detectZeroesMode);

    /* currently unhandled global properties:
     * '*force-share': 'bool'
     */

    if (virJSONValueObjectAdd(&props,
                              "s:node-name", src->nodeformat,
                              "b:read-only", src->readonly,
                              "S:discard", discard,
                              "S:detect-zeroes", detectZeroes,
                              NULL) < 0)
        return NULL;

    if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, props) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBlockStorageSourceGetBlockdevFormatProps(virStorageSource *src)
{
    const char *driver = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatCommonProps(src)))
        return NULL;

    switch ((virStorageFileFormat) src->format) {
    case VIR_STORAGE_FILE_FAT:
        /* The fat layer is emulated by the storage access layer, so we need to
         * put a raw layer on top */
    case VIR_STORAGE_FILE_RAW:
        if (src->encryption &&
            src->encryption->engine == VIR_STORAGE_ENCRYPTION_ENGINE_QEMU &&
            src->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
            if (qemuBlockStorageSourceGetFormatLUKSProps(src, props) < 0)
                return NULL;
        } else {
            if (qemuBlockStorageSourceGetFormatRawProps(src, props) < 0)
                return NULL;
        }
        break;

    case VIR_STORAGE_FILE_QCOW2:
        if (qemuBlockStorageSourceGetFormatQcow2Props(src, props) < 0)
            return NULL;
        break;

    case VIR_STORAGE_FILE_QCOW:
        if (qemuBlockStorageSourceGetFormatQcowGenericProps(src, "qcow", props) < 0)
            return NULL;
        break;

    /* formats without any special parameters */
    case VIR_STORAGE_FILE_PLOOP:
        driver = "parallels";
        break;

    case VIR_STORAGE_FILE_VHD:
        driver = "vhdx";
        break;

    case VIR_STORAGE_FILE_BOCHS:
    case VIR_STORAGE_FILE_CLOOP:
    case VIR_STORAGE_FILE_DMG:
    case VIR_STORAGE_FILE_VDI:
    case VIR_STORAGE_FILE_VPC:
    case VIR_STORAGE_FILE_QED:
    case VIR_STORAGE_FILE_VMDK:
        driver = virStorageFileFormatTypeToString(src->format);
        break;

    case VIR_STORAGE_FILE_AUTO_SAFE:
    case VIR_STORAGE_FILE_AUTO:
    case VIR_STORAGE_FILE_NONE:
    case VIR_STORAGE_FILE_COW:
    case VIR_STORAGE_FILE_ISO:
    case VIR_STORAGE_FILE_DIR:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("mishandled storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        return NULL;

    case VIR_STORAGE_FILE_LAST:
    default:
        virReportEnumRangeError(virStorageFileFormat, src->format);
        return NULL;
    }

    if (driver &&
        virJSONValueObjectAdd(&props, "s:driver", driver, NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


/**
 * qemuBlockStorageSourceGetBlockdevProps:
 *
 * @src: storage source to format
 * @backingStore: a storage source to use as backing of @src
 *
 * Formats @src into a JSON object which can be used with blockdev-add or
 * -blockdev. The formatted object contains both the storage and format layer
 * in nested form including link to the backing chain layer if necessary.
 */
virJSONValue *
qemuBlockStorageSourceGetBlockdevProps(virStorageSource *src,
                                       virStorageSource *backingStore)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *storagenode = src->nodestorage;

    if (qemuBlockStorageSourceNeedsStorageSliceLayer(src))
        storagenode = src->sliceStorage->nodename;

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatProps(src)))
        return NULL;

    if (virJSONValueObjectAppendString(props, "file", storagenode) < 0)
        return NULL;

    if (backingStore) {
        if (src->format >= VIR_STORAGE_FILE_BACKING) {
            if (virStorageSourceIsBacking(backingStore)) {
                if (virJSONValueObjectAppendString(props, "backing",
                                                   backingStore->nodeformat) < 0)
                    return NULL;
            } else {
                /* chain is terminated, indicate that no detection should happen
                 * in qemu */
                if (virJSONValueObjectAppendNull(props, "backing") < 0)
                    return NULL;
            }
        } else {
            if (virStorageSourceIsBacking(backingStore)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("storage format '%s' does not support backing store"),
                               virStorageFileFormatTypeToString(src->format));
                return NULL;
            }
        }
    }

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBlockStorageSourceGetBlockdevStorageSliceProps(virStorageSource *src)
{
    g_autoptr(virJSONValue) props = NULL;

    if (qemuBlockNodeNameValidate(src->sliceStorage->nodename) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "raw",
                              "s:node-name", src->sliceStorage->nodename,
                              "U:offset", src->sliceStorage->offset,
                              "U:size", src->sliceStorage->size,
                              "s:file", src->nodestorage,
                              "b:auto-read-only", true,
                              "s:discard", "unmap",
                              NULL) < 0)
        return NULL;

    if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, props) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


void
qemuBlockStorageSourceAttachDataFree(qemuBlockStorageSourceAttachData *data)
{
    if (!data)
        return;

    virJSONValueFree(data->storageProps);
    virJSONValueFree(data->storageSliceProps);
    virJSONValueFree(data->formatProps);
    virJSONValueFree(data->prmgrProps);
    virJSONValueFree(data->authsecretProps);
    virJSONValueFree(data->httpcookiesecretProps);
    virJSONValueFree(data->encryptsecretProps);
    virJSONValueFree(data->tlsProps);
    virJSONValueFree(data->tlsKeySecretProps);
    g_free(data->tlsAlias);
    g_free(data->tlsKeySecretAlias);
    g_free(data->authsecretAlias);
    g_free(data->encryptsecretAlias);
    g_free(data->httpcookiesecretAlias);
    g_free(data->driveCmd);
    g_free(data->chardevAlias);
    g_free(data);
}


/**
 * qemuBlockStorageSourceAttachPrepareBlockdev:
 * @src: storage source to prepare data from
 * @backingStore: storage source to use as backing of @src
 * @autoreadonly: use 'auto-read-only' feature of qemu
 *
 * Creates a qemuBlockStorageSourceAttachData structure containing data to attach
 * @src to a VM using the blockdev-add approach. Note that this function only
 * creates the data for the storage source itself, any other related
 * authentication/encryption/... objects need to be prepared separately.
 *
 * The changes are then applied using qemuBlockStorageSourceAttachApply.
 *
 * Returns the filled data structure on success or NULL on error and a libvirt
 * error is reported
 */
qemuBlockStorageSourceAttachData *
qemuBlockStorageSourceAttachPrepareBlockdev(virStorageSource *src,
                                            virStorageSource *backingStore,
                                            bool autoreadonly)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;
    unsigned int backendpropsflags = 0;

    if (autoreadonly)
        backendpropsflags |= QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY;

    data = g_new0(qemuBlockStorageSourceAttachData, 1);

    if (!(data->formatProps = qemuBlockStorageSourceGetBlockdevProps(src,
                                                                     backingStore)) ||
        !(data->storageProps = qemuBlockStorageSourceGetBackendProps(src,
                                                                     backendpropsflags)))
        return NULL;

    data->storageNodeName = src->nodestorage;
    data->formatNodeName = src->nodeformat;

    if (qemuBlockStorageSourceNeedsStorageSliceLayer(src)) {
        if (!(data->storageSliceProps = qemuBlockStorageSourceGetBlockdevStorageSliceProps(src)))
            return NULL;

        data->storageSliceNodeName = src->sliceStorage->nodename;
    }

    return g_steal_pointer(&data);
}


static int
qemuBlockStorageSourceAttachApplyStorageDeps(qemuMonitor *mon,
                                             qemuBlockStorageSourceAttachData *data)
{
    if (data->prmgrProps &&
        qemuMonitorAddObject(mon, &data->prmgrProps, &data->prmgrAlias) < 0)
        return -1;

    if (data->authsecretProps &&
        qemuMonitorAddObject(mon, &data->authsecretProps,
                             &data->authsecretAlias) < 0)
        return -1;

    if (data->httpcookiesecretProps &&
        qemuMonitorAddObject(mon, &data->httpcookiesecretProps,
                             &data->httpcookiesecretAlias) < 0)
        return -1;

    if (data->tlsKeySecretProps &&
        qemuMonitorAddObject(mon, &data->tlsKeySecretProps,
                             &data->tlsKeySecretAlias) < 0)
        return -1;

    if (data->tlsProps &&
        qemuMonitorAddObject(mon, &data->tlsProps, &data->tlsAlias) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyStorage(qemuMonitor *mon,
                                         qemuBlockStorageSourceAttachData *data)
{
    if (data->storageProps) {
        if (qemuMonitorBlockdevAdd(mon, &data->storageProps) < 0)
            return -1;

        data->storageAttached = true;
    }

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyFormatDeps(qemuMonitor *mon,
                                            qemuBlockStorageSourceAttachData *data)
{
    if (data->encryptsecretProps &&
        qemuMonitorAddObject(mon, &data->encryptsecretProps,
                             &data->encryptsecretAlias) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyFormat(qemuMonitor *mon,
                                        qemuBlockStorageSourceAttachData *data)
{
    if (data->formatProps) {
        if (qemuMonitorBlockdevAdd(mon, &data->formatProps) < 0)
            return -1;

        data->formatAttached = true;
    }

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyStorageSlice(qemuMonitor *mon,
                                              qemuBlockStorageSourceAttachData *data)
{
    if (data->storageSliceProps) {
        if (qemuMonitorBlockdevAdd(mon, &data->storageSliceProps) < 0)
            return -1;

        data->storageSliceAttached = true;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceAttachApply:
 * @mon: monitor object
 * @data: structure holding data of block device to apply
 *
 * Attaches a virStorageSource definition converted to
 * qemuBlockStorageSourceAttachData to a running VM. This function expects being
 * called after the monitor was entered.
 *
 * Returns 0 on success and -1 on error with a libvirt error reported. If an
 * error occurred, changes which were already applied need to be rolled back by
 * calling qemuBlockStorageSourceAttachRollback.
 */
int
qemuBlockStorageSourceAttachApply(qemuMonitor *mon,
                                  qemuBlockStorageSourceAttachData *data)
{
    if (qemuBlockStorageSourceAttachApplyStorageDeps(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyStorage(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyStorageSlice(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyFormatDeps(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyFormat(mon, data) < 0)
        return -1;

    if (data->chardevDef) {
        if (qemuMonitorAttachCharDev(mon, data->chardevAlias, data->chardevDef) < 0)
            return -1;

        data->chardevAdded = true;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceAttachRollback:
 * @mon: monitor object
 * @data: structure holding data of block device to roll back
 *
 * Attempts a best effort rollback of changes which were made to a running VM by
 * qemuBlockStorageSourceAttachApply. Preserves any existing errors.
 *
 * This function expects being called after the monitor was entered.
 */
void
qemuBlockStorageSourceAttachRollback(qemuMonitor *mon,
                                     qemuBlockStorageSourceAttachData *data)
{
    virErrorPtr orig_err;

    virErrorPreserveLast(&orig_err);

    if (data->chardevAdded) {
        if (qemuMonitorDetachCharDev(mon, data->chardevAlias) < 0) {
            VIR_WARN("Unable to remove chardev %s after failed 'device_add'",
                     data->chardevAlias);
        }
    }

    if (data->formatAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->formatNodeName));

    if (data->storageSliceAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->storageSliceNodeName));

    if (data->storageAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->storageNodeName));

    if (data->prmgrAlias)
        ignore_value(qemuMonitorDelObject(mon, data->prmgrAlias, false));

    if (data->authsecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->authsecretAlias, false));

    if (data->encryptsecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->encryptsecretAlias, false));

    if (data->httpcookiesecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->httpcookiesecretAlias, false));

    if (data->tlsAlias)
        ignore_value(qemuMonitorDelObject(mon, data->tlsAlias, false));

    if (data->tlsKeySecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->tlsKeySecretAlias, false));

    virErrorRestore(&orig_err);
}


/**
 * qemuBlockStorageSourceDetachPrepare:
 * @src: disk source structure
 *
 * Prepare qemuBlockStorageSourceAttachData *for detaching a single source
 * from a VM.
 */
qemuBlockStorageSourceAttachData *
qemuBlockStorageSourceDetachPrepare(virStorageSource *src)
{
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;

    data = g_new0(qemuBlockStorageSourceAttachData, 1);

    data->formatNodeName = src->nodeformat;
    data->formatAttached = true;
    data->storageNodeName = src->nodestorage;
    data->storageAttached = true;

    /* 'raw' format doesn't need the extra 'raw' layer when slicing, thus
     * the nodename is NULL */
    if (src->sliceStorage &&
        src->sliceStorage->nodename) {
        data->storageSliceNodeName = src->sliceStorage->nodename;
        data->storageSliceAttached = true;
    }

    if (src->pr &&
        !virStoragePRDefIsManaged(src->pr))
        data->prmgrAlias = g_strdup(src->pr->mgralias);

    data->tlsAlias = g_strdup(src->tlsAlias);

    if (srcpriv) {
        if (srcpriv->secinfo)
            data->authsecretAlias = g_strdup(srcpriv->secinfo->alias);

        if (srcpriv->encinfo)
            data->encryptsecretAlias = g_strdup(srcpriv->encinfo->alias);

        if (srcpriv->httpcookie)
            data->httpcookiesecretAlias = g_strdup(srcpriv->httpcookie->alias);

        if (srcpriv->tlsKeySecret)
            data->tlsKeySecretAlias = g_strdup(srcpriv->tlsKeySecret->alias);
    }

    return g_steal_pointer(&data);
}


void
qemuBlockStorageSourceChainDataFree(qemuBlockStorageSourceChainData *data)
{
    size_t i;

    if (!data)
        return;

    for (i = 0; i < data->nsrcdata; i++)
        qemuBlockStorageSourceAttachDataFree(data->srcdata[i]);

    virJSONValueFree(data->copyOnReadProps);
    g_free(data->copyOnReadNodename);

    g_free(data->srcdata);
    g_free(data);
}


/**
 * qemuBlockStorageSourceChainDetachPrepareBlockdev
 * @src: storage source chain to remove
 *
 * Prepares qemuBlockStorageSourceChainData *for detaching @src and its
 * backingStore if -blockdev was used.
 */
qemuBlockStorageSourceChainData *
qemuBlockStorageSourceChainDetachPrepareBlockdev(virStorageSource *src)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    virStorageSource *n;

    data = g_new0(qemuBlockStorageSourceChainData, 1);

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (!(backend = qemuBlockStorageSourceDetachPrepare(n)))
            return NULL;

        VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, backend);
    }

    return g_steal_pointer(&data);
}


/**
 * qemuBlockStorageSourceChainDetachPrepareChardev
 * @src: storage source chain to remove
 *
 * Prepares qemuBlockStorageSourceChainData *for detaching @src and its
 * backingStore if -chardev was used.
 */
qemuBlockStorageSourceChainData *
qemuBlockStorageSourceChainDetachPrepareChardev(char *chardevAlias)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    data = g_new0(qemuBlockStorageSourceChainData, 1);
    backend = g_new0(qemuBlockStorageSourceAttachData, 1);

    backend->chardevAlias = chardevAlias;
    backend->chardevAdded = true;

    VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, backend);

    return g_steal_pointer(&data);
}


/**
 * qemuBlockStorageSourceChainAttach:
 * @mon: monitor object
 * @data: storage source chain data
 *
 * Attach a storage source including its backing chain and supporting objects.
 * Caller must enter @mon prior calling this function. In case of error this
 * function returns -1. @data is updated so that qemuBlockStorageSourceChainDetach
 * can be used to roll-back the changes.
 */
int
qemuBlockStorageSourceChainAttach(qemuMonitor *mon,
                                  qemuBlockStorageSourceChainData *data)
{
    size_t i;

    for (i = data->nsrcdata; i > 0; i--) {
        if (qemuBlockStorageSourceAttachApply(mon, data->srcdata[i - 1]) < 0)
            return -1;
    }

    if (data->copyOnReadProps) {
        if (qemuMonitorBlockdevAdd(mon, &data->copyOnReadProps) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceChainDetach:
 * @mon: monitor object
 * @data: storage source chain data
 *
 * Detach a unused storage source including all its backing chain and related
 * objects described by @data.
 */
void
qemuBlockStorageSourceChainDetach(qemuMonitor *mon,
                                  qemuBlockStorageSourceChainData *data)
{
    size_t i;

    if (data->copyOnReadAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->copyOnReadNodename));


    for (i = 0; i < data->nsrcdata; i++)
        qemuBlockStorageSourceAttachRollback(mon, data->srcdata[i]);
}


/**
 * qemuBlockStorageSourceDetachOneBlockdev:
 * @driver: qemu driver object
 * @vm: domain object
 * @asyncJob: currently running async job
 * @src: storage source to detach
 *
 * Detaches one virStorageSource using blockdev-del. Note that this does not
 * detach any authentication/encryption objects. This function enters the
 * monitor internally.
 */
int
qemuBlockStorageSourceDetachOneBlockdev(virDomainObj *vm,
                                        virDomainAsyncJob asyncJob,
                                        virStorageSource *src)
{
    int ret;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorBlockdevDel(qemuDomainGetMonitor(vm), src->nodeformat);

    if (ret == 0)
        ret = qemuMonitorBlockdevDel(qemuDomainGetMonitor(vm), src->nodestorage);

    qemuDomainObjExitMonitor(vm);

    return ret;
}


int
qemuBlockSnapshotAddBlockdev(virJSONValue *actions,
                             virDomainDiskDef *disk,
                             virStorageSource *newsrc)
{
    return qemuMonitorTransactionSnapshotBlockdev(actions,
                                                  disk->src->nodeformat,
                                                  newsrc->nodeformat);
}


/**
 * qemuBlockStorageGetCopyOnReadProps:
 * @disk: disk with copy-on-read enabled
 *
 * Creates blockdev properties for a disk copy-on-read layer.
 */
virJSONValue *
qemuBlockStorageGetCopyOnReadProps(virDomainDiskDef *disk)
{
    qemuDomainDiskPrivate *priv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    virJSONValue *ret = NULL;

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:driver", "copy-on-read",
                                       "s:node-name", priv->nodeCopyOnRead,
                                       "s:file", disk->src->nodeformat,
                                       "s:discard", "unmap",
                                       NULL));

    return ret;
}


/**
 * qemuBlockGetBackingStoreString:
 * @src: storage source to get the string for
 * @pretty: pretty-print the JSON (if applicable, used by tests)
 *
 * Formats a string used in the backing store field of a disk image which
 * supports backing store. Non-local storage may result in use of the json:
 * pseudo protocol for any complex configuration.
 */
char *
qemuBlockGetBackingStoreString(virStorageSource *src,
                               bool pretty)
{
    virStorageType actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) backingProps = NULL;
    g_autoptr(virJSONValue) sliceProps = NULL;
    virJSONValue *props = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *backingJSON = NULL;

    if (!src->sliceStorage) {
        if (virStorageSourceIsLocalStorage(src)) {
            if (src->type == VIR_STORAGE_TYPE_DIR &&
                src->format == VIR_STORAGE_FILE_FAT)
                return g_strdup_printf("fat:%s", src->path);

            return g_strdup(src->path);
        }

        /* generate simplified URIs for the easy cases */
        if (actualType == VIR_STORAGE_TYPE_NETWORK &&
            src->nhosts == 1 &&
            src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP &&
            src->timeout == 0 &&
            src->ncookies == 0 &&
            src->sslverify == VIR_TRISTATE_BOOL_ABSENT &&
            src->timeout == 0 &&
            src->readahead == 0) {

            switch ((virStorageNetProtocol) src->protocol) {
            case VIR_STORAGE_NET_PROTOCOL_NBD:
            case VIR_STORAGE_NET_PROTOCOL_HTTP:
            case VIR_STORAGE_NET_PROTOCOL_HTTPS:
            case VIR_STORAGE_NET_PROTOCOL_FTP:
            case VIR_STORAGE_NET_PROTOCOL_FTPS:
            case VIR_STORAGE_NET_PROTOCOL_TFTP:
            case VIR_STORAGE_NET_PROTOCOL_ISCSI:
            case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
                if (!(uri = qemuBlockStorageSourceGetURI(src)))
                    return NULL;

                return virURIFormat(uri);

            case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            case VIR_STORAGE_NET_PROTOCOL_RBD:
            case VIR_STORAGE_NET_PROTOCOL_VXHS:
            case VIR_STORAGE_NET_PROTOCOL_NFS:
            case VIR_STORAGE_NET_PROTOCOL_SSH:
            case VIR_STORAGE_NET_PROTOCOL_LAST:
            case VIR_STORAGE_NET_PROTOCOL_NONE:
                break;
            }
        }
    }

    /* use json: pseudo protocol otherwise */
    if (!(backingProps = qemuBlockStorageSourceGetBackendProps(src,
                                                               QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY)))
        return NULL;

    props = backingProps;

    if (src->sliceStorage) {
        if (virJSONValueObjectAdd(&sliceProps,
                                  "s:driver", "raw",
                                  "U:offset", src->sliceStorage->offset,
                                  "U:size", src->sliceStorage->size,
                                  "a:file", &backingProps,
                                  NULL) < 0)
            return NULL;

        props = sliceProps;
    }

    if (!(backingJSON = virJSONValueToString(props, pretty)))
        return NULL;

    return g_strdup_printf("json:{\"file\":%s}", backingJSON);
}


static int
qemuBlockStorageSourceCreateAddBacking(virStorageSource *backing,
                                       virJSONValue *props,
                                       bool format)
{
    g_autofree char *backingFileStr = NULL;
    const char *backingFormatStr = NULL;

    if (!virStorageSourceIsBacking(backing))
        return 0;

    if (format) {
        if (backing->format == VIR_STORAGE_FILE_RAW &&
            backing->encryption &&
            backing->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS)
            backingFormatStr = "luks";
        else
            backingFormatStr = virStorageFileFormatTypeToString(backing->format);
    }

    if (!(backingFileStr = qemuBlockGetBackingStoreString(backing, false)))
        return -1;

    if (virJSONValueObjectAdd(&props,
                              "S:backing-file", backingFileStr,
                              "S:backing-fmt", backingFormatStr,
                              NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsGeneric(virStorageSource *src,
                                                  const char *driver,
                                                  virJSONValue **retprops,
                                                  virStorageSource *backing)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", driver,
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              NULL) < 0)
        return -1;

    if (backing &&
        qemuBlockStorageSourceCreateAddBacking(backing, props, false) < 0)
        return -1;

    *retprops = g_steal_pointer(&props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetEncryptionLUKS(virStorageSource *src,
                                              virJSONValue **luksProps)
{
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *cipheralg = NULL;
    const char *keysecret = NULL;

    if (srcpriv &&
        srcpriv->encinfo)
        keysecret = srcpriv->encinfo->alias;

    if (virJSONValueObjectAdd(&props,
                              "s:key-secret", keysecret,
                              NULL) < 0)
        return -1;

    if (src->encryption) {
        if (src->encryption->encinfo.cipher_name) {
            cipheralg = g_strdup_printf("%s-%u",
                                        src->encryption->encinfo.cipher_name,
                                        src->encryption->encinfo.cipher_size);
        }

        if (virJSONValueObjectAdd(&props,
                                  "S:cipher-alg", cipheralg,
                                  "S:cipher-mode", src->encryption->encinfo.cipher_mode,
                                  "S:hash-alg", src->encryption->encinfo.cipher_hash,
                                  "S:ivgen-alg", src->encryption->encinfo.ivgen_name,
                                  "S:ivgen-hash-alg", src->encryption->encinfo.ivgen_hash,
                                  NULL) < 0)
            return -1;
    }

    *luksProps = g_steal_pointer(&props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsLUKS(virStorageSource *src,
                                               virJSONValue **props)
{
    g_autoptr(virJSONValue) luksprops = NULL;

    if (qemuBlockStorageSourceCreateGetEncryptionLUKS(src, &luksprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(&luksprops,
                              "s:driver", "luks",
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              NULL) < 0)
        return -1;

    *props = g_steal_pointer(&luksprops);
    return 0;
}


static int
qemuBlockStorageSourceCreateAddEncryptionQcow(virStorageSource *src,
                                              virJSONValue *props)
{
    g_autoptr(virJSONValue) encryptProps = NULL;

    if (!src->encryption)
        return 0;

    if (src->encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("creation of qcow/qcow2 files supports only 'luks' encryption"));
        return -1;
    }

    if (qemuBlockStorageSourceCreateGetEncryptionLUKS(src, &encryptProps) < 0)
        return -1;

    if (virJSONValueObjectAdd(&encryptProps, "s:format", "luks", NULL) < 0)
        return -1;

    if (virJSONValueObjectAdd(&props, "a:encrypt", &encryptProps, NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQcow2(virStorageSource *src,
                                                virStorageSource *backing,
                                                virJSONValue **props)
{
    g_autoptr(virJSONValue) qcow2props = NULL;
    const char *qcow2version = NULL;
    bool extendedL2 = false;

    if (STREQ_NULLABLE(src->compat, "0.10"))
        qcow2version = "v2";
    else if (STREQ_NULLABLE(src->compat, "1.1"))
        qcow2version = "v3";

    if (src->features)
        extendedL2 = virBitmapIsBitSet(src->features, VIR_STORAGE_FILE_FEATURE_EXTENDED_L2);

    if (virJSONValueObjectAdd(&qcow2props,
                              "s:driver", "qcow2",
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              "S:version", qcow2version,
                              "P:cluster-size", src->clusterSize,
                              "B:extended-l2", extendedL2,
                              NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qcow2props, true) < 0 ||
        qemuBlockStorageSourceCreateAddEncryptionQcow(src, qcow2props) < 0)
        return -1;

    *props = g_steal_pointer(&qcow2props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQcow(virStorageSource *src,
                                               virStorageSource *backing,
                                               virJSONValue **props)
{
    g_autoptr(virJSONValue) qcowprops = NULL;

    if (virJSONValueObjectAdd(&qcowprops,
                              "s:driver", "qcow",
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qcowprops, false) < 0 ||
        qemuBlockStorageSourceCreateAddEncryptionQcow(src, qcowprops) < 0)
        return -1;

    *props = g_steal_pointer(&qcowprops);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQed(virStorageSource *src,
                                              virStorageSource *backing,
                                              virJSONValue **props)
{
    g_autoptr(virJSONValue) qedprops = NULL;

    if (virJSONValueObjectAdd(&qedprops,
                              "s:driver", "qed",
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qedprops, true) < 0)
        return -1;

    *props = g_steal_pointer(&qedprops);
    return 0;
}


/**
 * qemuBlockStorageSourceCreateGetFormatProps:
 * @src: storage source to format
 * @backing: storage source describing backing image of @src (if necessary)
 * @props: filled with props to be used with 'blockdev-create' to format @src
 *
 * @src must be properly initialized to contain node-names of the protocol layer
 * which should be formatted. @props may be NULL with success returned in which
 * case creation of given storage format is not supported. Note that creation
 * of 'raw' storage is also returns NULL as there is nothing to do.
 */
int
qemuBlockStorageSourceCreateGetFormatProps(virStorageSource *src,
                                           virStorageSource *backing,
                                           virJSONValue **props)
{
    switch ((virStorageFileFormat) src->format) {
    case VIR_STORAGE_FILE_RAW:
        if (!src->encryption ||
            src->encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS)
            return 0;

        return qemuBlockStorageSourceCreateGetFormatPropsLUKS(src, props);

    case VIR_STORAGE_FILE_QCOW2:
        return qemuBlockStorageSourceCreateGetFormatPropsQcow2(src, backing, props);

    case VIR_STORAGE_FILE_QCOW:
        return qemuBlockStorageSourceCreateGetFormatPropsQcow(src, backing, props);

    case VIR_STORAGE_FILE_QED:
        return qemuBlockStorageSourceCreateGetFormatPropsQed(src, backing, props);

    case VIR_STORAGE_FILE_VPC:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vpc",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_PLOOP:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "parallels",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VDI:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vdi",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VHD:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vhdx",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VMDK:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vmdk",
                                                                 props, backing);

    /* unsupported by qemu / impossible */
    case VIR_STORAGE_FILE_FAT:
    case VIR_STORAGE_FILE_BOCHS:
    case VIR_STORAGE_FILE_CLOOP:
    case VIR_STORAGE_FILE_DMG:
    case VIR_STORAGE_FILE_COW:
    case VIR_STORAGE_FILE_ISO:
    case VIR_STORAGE_FILE_DIR:
        return 0;

    case VIR_STORAGE_FILE_AUTO_SAFE:
    case VIR_STORAGE_FILE_AUTO:
    case VIR_STORAGE_FILE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("mishandled storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        return -1;

    case VIR_STORAGE_FILE_LAST:
    default:
        break;
    }

    virReportEnumRangeError(virStorageFileFormat, src->format);
    return -1;
}


/**
 * qemuBlockStorageSourceCreateGetStorageProps:
 * @src: storage source to create
 * @props: filled with props to be used with 'blockdev-create' to create @src
 *
 * This function should be used only if @src->type is VIR_STORAGE_TYPE_NETWORK.
 * Note that @props may be NULL if qemu does not support creation storage
 * on given protocol. @src->physical is used as size for the storage.
 */
int
qemuBlockStorageSourceCreateGetStorageProps(virStorageSource *src,
                                            virJSONValue **props)
{
    virStorageType actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) location = NULL;
    const char *driver = NULL;
    const char *filename = NULL;

    switch (actualType) {
    case VIR_STORAGE_TYPE_FILE:
        driver = "file";
        filename = src->path;
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            driver = "gluster";
            if (!(location = qemuBlockStorageSourceGetGlusterProps(src, false)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            driver = "rbd";
            if (!(location = qemuBlockStorageSourceGetRBDProps(src, false)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            driver = "sheepdog";
            if (!(location = qemuBlockStorageSourceGetSheepdogProps(src)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            driver = "ssh";
            if (!(location = qemuBlockStorageSourceGetSshProps(src)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NFS:
            driver = "nfs";
            if (!(location = qemuBlockStorageSourceGetNFSProps(src)))
                return -1;
            break;

            /* unsupported/impossible */
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            return 0;
        }
        break;

    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
        return 0;

    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
         virReportEnumRangeError(virStorageType, actualType);
         return -1;
    }

    if (virJSONValueObjectAdd(props,
                              "s:driver", driver,
                              "S:filename", filename,
                              "A:location", &location,
                              "U:size", src->physical,
                              NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGeneric(virDomainObj *vm,
                                    virJSONValue *createProps,
                                    virStorageSource *src,
                                    virStorageSource *chain,
                                    bool storageCreate,
                                    virDomainAsyncJob asyncJob)
{
    g_autoptr(virJSONValue) props = createProps;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuBlockJobData *job = NULL;
    int ret = -1;
    int rc;

    if (!(job = qemuBlockJobNewCreate(vm, src, chain, storageCreate)))
        return -1;

    qemuBlockJobSyncBegin(job);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuMonitorBlockdevCreate(priv->mon, job->name, &props);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    qemuBlockJobStarted(job, vm);

    qemuBlockJobUpdate(vm, job, asyncJob);
    while (qemuBlockJobIsRunning(job))  {
        if (qemuDomainObjWait(vm) < 0)
            goto cleanup;
        qemuBlockJobUpdate(vm, job, asyncJob);
    }

    if (job->state == QEMU_BLOCKJOB_STATE_FAILED ||
        job->state == QEMU_BLOCKJOB_STATE_CANCELLED) {
        if (job->state == QEMU_BLOCKJOB_STATE_CANCELLED && !job->errmsg) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("blockdev-create job was cancelled"));
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to format image: '%s'"), NULLSTR(job->errmsg));
        }
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuBlockJobStartupFinalize(vm, job);
    return ret;
}


static int
qemuBlockStorageSourceCreateStorage(virDomainObj *vm,
                                    virStorageSource *src,
                                    virStorageSource *chain,
                                    virDomainAsyncJob asyncJob)
{
    virStorageType actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) createstorageprops = NULL;
    int ret;

    /* We create local files directly to be able to apply security labels
     * properly. This is enough for formats which store the capacity of the image
     * in the metadata as they will grow. We must create a correctly sized
     * image for 'raw' and 'luks' though as the image size influences the
     * capacity.
     */
    if (actualType != VIR_STORAGE_TYPE_NETWORK &&
        !(actualType == VIR_STORAGE_TYPE_FILE && src->format == VIR_STORAGE_FILE_RAW))
        return 0;

    if (qemuBlockStorageSourceCreateGetStorageProps(src, &createstorageprops) < 0)
        return -1;

    if (!createstorageprops) {
        /* we can always try opening it to see whether it was existing */
        return 0;
    }

    ret = qemuBlockStorageSourceCreateGeneric(vm, createstorageprops, src, chain,
                                              true, asyncJob);
    createstorageprops = NULL;

    return ret;
}


static int
qemuBlockStorageSourceCreateFormat(virDomainObj *vm,
                                   virStorageSource *src,
                                   virStorageSource *backingStore,
                                   virStorageSource *chain,
                                   virDomainAsyncJob asyncJob)
{
    g_autoptr(virJSONValue) createformatprops = NULL;
    int ret;

    if (src->format == VIR_STORAGE_FILE_RAW &&
        !src->encryption)
        return 0;

    if (qemuBlockStorageSourceCreateGetFormatProps(src, backingStore,
                                                   &createformatprops) < 0)
        return -1;

    if (!createformatprops) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("can't create storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        return -1;
    }

    ret = qemuBlockStorageSourceCreateGeneric(vm, createformatprops, src, chain,
                                              false, asyncJob);
    createformatprops = NULL;

    return ret;
}


/**
 * qemuBlockStorageSourceCreate:
 * @vm: domain object
 * @src: storage source definition to create
 * @backingStore: backingStore of the new image (used only in image metadata)
 * @chain: backing chain to unplug in case of a long-running job failure
 * @data: qemuBlockStorageSourceAttachData for @src so that it can be attached
 * @asyncJob: qemu asynchronous job type
 *
 * Creates and formats a storage volume according to @src and attaches it to @vm.
 * @data must provide attachment data as if @src was existing. @src is attached
 * after successful return of this function. If libvirtd is restarted during
 * the create job @chain is unplugged, otherwise it's left for the caller.
 * If @backingStore is provided, the new image will refer to it as its backing
 * store.
 */
int
qemuBlockStorageSourceCreate(virDomainObj *vm,
                             virStorageSource *src,
                             virStorageSource *backingStore,
                             virStorageSource *chain,
                             qemuBlockStorageSourceAttachData *data,
                             virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;
    int rc;

    if (src->sliceStorage) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("creation of images with slice type='storage' is not supported"));
        return -1;
    }

    /* grant write access to read-only images during formatting */
    if (src->readonly &&
        qemuDomainStorageSourceAccessAllow(priv->driver, vm, src, false,
                                           false, true) < 0)
        return -1;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyStorageDeps(priv->mon, data);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    if (qemuBlockStorageSourceCreateStorage(vm, src, chain, asyncJob) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyStorage(priv->mon, data);

    if (rc == 0)
        rc = qemuBlockStorageSourceAttachApplyFormatDeps(priv->mon, data);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    if (qemuBlockStorageSourceCreateFormat(vm, src, backingStore, chain,
                                           asyncJob) < 0)
        goto cleanup;

    /* revoke write access to read-only images during formatting */
    if (src->readonly &&
        qemuDomainStorageSourceAccessAllow(priv->driver, vm, src, true,
                                           false, true) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyFormat(priv->mon, data);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0 &&
        virDomainObjIsActive(vm) &&
        qemuDomainObjEnterMonitorAsync(vm, asyncJob) == 0) {

        qemuBlockStorageSourceAttachRollback(priv->mon, data);
        qemuDomainObjExitMonitor(vm);
    }

    return ret;
}


/**
 * qemuBlockStorageSourceCreateDetectSize:
 * @blockNamedNodeData: hash table filled with qemuBlockNamedNodeData
 * @src: storage source to update size/capacity on
 * @templ: storage source template
 *
 * When creating a storage source via blockdev-create we need to know the size
 * and capacity of the original volume (e.g. when creating a snapshot or copy).
 * This function updates @src's 'capacity' and 'physical' attributes according
 * to the detected sizes from @templ.
 */
int
qemuBlockStorageSourceCreateDetectSize(GHashTable *blockNamedNodeData,
                                       virStorageSource *src,
                                       virStorageSource *templ)
{
    qemuBlockNamedNodeData *entry;

    if (!(entry = virHashLookup(blockNamedNodeData, templ->nodeformat))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to update capacity data for block node '%s'"),
                       templ->nodeformat);
        return -1;
    }

    /* propagate properties of qcow2 images if possible*/
    if (templ->format == VIR_STORAGE_FILE_QCOW2 &&
        src->format == VIR_STORAGE_FILE_QCOW2) {
        if (src->clusterSize == 0)
            src->clusterSize = entry->clusterSize;

        if (entry->qcow2extendedL2) {
            if (!src->features)
                src->features = virBitmapNew(VIR_STORAGE_FILE_FEATURE_LAST);
            ignore_value(virBitmapSetBit(src->features, VIR_STORAGE_FILE_FEATURE_EXTENDED_L2));
        }
    }

    if (src->format == VIR_STORAGE_FILE_RAW) {
        src->physical = entry->capacity;
    } else {
        src->physical = entry->physical;
    }

    src->capacity = entry->capacity;

    return 0;
}


int
qemuBlockRemoveImageMetadata(virQEMUDriver *driver,
                             virDomainObj *vm,
                             const char *diskTarget,
                             virStorageSource *src)
{
    virStorageSource *n;
    int ret = 0;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (qemuSecurityMoveImageMetadata(driver, vm, n, NULL) < 0) {
            VIR_WARN("Unable to remove disk metadata on "
                     "vm %s from %s (disk target %s)",
                     vm->def->name,
                     NULLSTR(n->path),
                     diskTarget);
            ret = -1;
        }
    }

    return ret;
}


/**
 * qemuBlockNamedNodeDataGetBitmapByName:
 * @blockNamedNodeData: hash table returned by qemuMonitorBlockGetNamedNodeData
 * @src: disk source to find the bitmap for
 * @bitmap: name of the bitmap to find
 *
 * Looks up a bitmap named @bitmap of the @src image.
 */
qemuBlockNamedNodeDataBitmap *
qemuBlockNamedNodeDataGetBitmapByName(GHashTable *blockNamedNodeData,
                                      virStorageSource *src,
                                      const char *bitmap)
{
    qemuBlockNamedNodeData *nodedata;
    size_t i;

    if (!(nodedata = virHashLookup(blockNamedNodeData, src->nodeformat)))
        return NULL;

    for (i = 0; i < nodedata->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmap *bitmapdata = nodedata->bitmaps[i];

        if (STRNEQ(bitmapdata->name, bitmap))
            continue;

        return bitmapdata;
    }

    return NULL;
}


GHashTable *
qemuBlockGetNamedNodeData(virDomainObj *vm,
                          virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    GHashTable *blockNamedNodeData = NULL;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return NULL;

    blockNamedNodeData = qemuMonitorBlockGetNamedNodeData(priv->mon);

    qemuDomainObjExitMonitor(vm);

    return blockNamedNodeData;
}


/**
 * qemuBlockGetBitmapMergeActionsGetBitmaps:
 *
 * Collect a list of bitmaps which need to be handled in
 * qemuBlockGetBitmapMergeActions. The list contains only valid bitmaps in the
 * sub-chain which is being processed.
 *
 * Note that the returned GSList contains bitmap names string pointers borrowed
 * from @blockNamedNodeData so they must not be freed.
 */
static GSList *
qemuBlockGetBitmapMergeActionsGetBitmaps(virStorageSource *topsrc,
                                         const char *bitmapname,
                                         GHashTable *blockNamedNodeData)
{
    g_autoptr(GSList) ret = NULL;
    qemuBlockNamedNodeData *entry;
    size_t i;

    /* for now it doesn't make sense to consider bitmaps which are not present
     * in @topsrc as we can't recreate a bitmap for a layer if it's missing */

    if (!(entry = virHashLookup(blockNamedNodeData, topsrc->nodeformat)))
        return NULL;

    for (i = 0; i < entry->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmap *bitmap = entry->bitmaps[i];

        if (bitmapname &&
            STRNEQ(bitmapname, bitmap->name))
            continue;

        if (!qemuBlockBitmapChainIsValid(topsrc, bitmap->name, blockNamedNodeData))
            continue;

        ret = g_slist_prepend(ret, bitmap->name);
    }

    return g_steal_pointer(&ret);
}


/**
 * qemuBlockGetBitmapMergeActions:
 * @topsrc: top of the chain to merge bitmaps in
 * @basesrc: bottom of the chain to merge bitmaps in (NULL for full chain)
 * @target: destination storage source of the merge (may be part of original chain)
 * @bitmapname: name of bitmap to perform the merge (NULL for all bitmaps)
 * @dstbitmapname: name of destination bitmap of the merge (see below for caveats)
 * @writebitmapsrc: storage source corresponding to the node containing the write temporary bitmap
 * @actions: returns actions for a 'transaction' QMP command for executing the merge
 * @blockNamedNodeData: hash table filled with qemuBlockNamedNodeData
 *
 * Calculate handling of dirty block bitmaps between @topsrc and @basesrc. If
 * @basesrc is NULL the end of the chain is considered. @target is the destination
 * storage source definition of the merge and may or may not be part of the
 * merged chain.
 *
 * Specifically the merging algorithm ensures that each considered bitmap is
 * merged with the appropriate bitmaps so that it properly describes
 * the state of dirty blocks when looked at from @topsrc based on the depth
 * of the backing chain where the bitmap is placed.
 *
 * If @bitmapname is non-NULL only bitmaps with that name are handled, otherwise
 * all bitmaps are considered.
 *
 * If @dstbitmap is non-NULL everything is merged into a bitmap with that name,
 * otherwise each bitmap is merged into a bitmap with the same name into @target.
 * Additionally if @dstbitmap is non-NULL the target bitmap is created as 'inactive'
 * and 'transient' as a special case for the backup operation.
 *
 * If @writebitmapsrc is non-NULL, the 'libvirt-tmp-activewrite' bitmap from
 * given node is merged along with others. This bitmap corresponds to the writes
 * which occurred between an active layer job finished and the rest of the bitmap
 * merging.
 *
 * If the bitmap is not valid somehow (see qemuBlockBitmapChainIsValid) given
 * bitmap is silently skipped, so callers must ensure that given bitmap is valid
 * if they care about it.
 *
 * The resulting 'transaction' QMP command actions are filled in and returned via
 * @actions.
 *
 * Note that @actions may be NULL if no merging is required.
 */
int
qemuBlockGetBitmapMergeActions(virStorageSource *topsrc,
                               virStorageSource *basesrc,
                               virStorageSource *target,
                               const char *bitmapname,
                               const char *dstbitmapname,
                               virStorageSource *writebitmapsrc,
                               virJSONValue **actions,
                               GHashTable *blockNamedNodeData)
{
    g_autoptr(virJSONValue) act = virJSONValueNewArray();
    virStorageSource *n;

    g_autoptr(GSList) bitmaps = NULL;
    GSList *next;

    if (!(bitmaps = qemuBlockGetBitmapMergeActionsGetBitmaps(topsrc, bitmapname,
                                                             blockNamedNodeData)))
        goto done;

    for (next = bitmaps; next; next = next->next) {
        const char *curbitmap = next->data;
        const char *mergebitmapname = dstbitmapname;
        bool mergebitmappersistent = false;
        bool mergebitmapdisabled = true;
        g_autoptr(virJSONValue) merge = virJSONValueNewArray();
        unsigned long long granularity = 0;
        qemuBlockNamedNodeDataBitmap *bitmap;

        /* explicitly named destinations mean that we want a temporary
         * disabled bitmap only, so undo the default for non-explicit cases  */
        if (!mergebitmapname) {
            mergebitmapname = curbitmap;
            mergebitmappersistent = true;
            mergebitmapdisabled = false;
        }

        for (n = topsrc; virStorageSourceIsBacking(n) && n != basesrc; n = n->backingStore) {
            if (!(bitmap = qemuBlockNamedNodeDataGetBitmapByName(blockNamedNodeData,
                                                                 n, curbitmap)))
                continue;

            if (granularity == 0)
                granularity = bitmap->granularity;

            if (qemuMonitorTransactionBitmapMergeSourceAddBitmap(merge,
                                                                 n->nodeformat,
                                                                 bitmap->name) < 0)
                return -1;
        }

        if (dstbitmapname ||
            !(bitmap = qemuBlockNamedNodeDataGetBitmapByName(blockNamedNodeData,
                                                             target, curbitmap))) {

            if (qemuMonitorTransactionBitmapAdd(act,
                                                target->nodeformat,
                                                mergebitmapname,
                                                mergebitmappersistent,
                                                mergebitmapdisabled,
                                                granularity) < 0)
                return -1;
        }

        if (writebitmapsrc &&
            qemuMonitorTransactionBitmapMergeSourceAddBitmap(merge,
                                                             writebitmapsrc->nodeformat,
                                                             "libvirt-tmp-activewrite") < 0)
            return -1;

        if (qemuMonitorTransactionBitmapMerge(act, target->nodeformat,
                                              mergebitmapname, &merge) < 0)
            return -1;
    }

 done:
    if (writebitmapsrc &&
        qemuMonitorTransactionBitmapRemove(act, writebitmapsrc->nodeformat,
                                           "libvirt-tmp-activewrite") < 0)
        return -1;

    if (virJSONValueArraySize(act) > 0)
        *actions = g_steal_pointer(&act);

    return 0;
}


/**
 * qemuBlockBitmapChainIsValid:
 *
 * Validates that the backing chain of @src contains bitmaps which libvirt will
 * consider as properly corresponding to a checkpoint named @bitmapname.
 *
 * The bitmaps need to:
 * 1) start from the top image @src
 * 2) must be present in consecutive layers
 * 3) all must be active, persistent and not inconsistent
 */
bool
qemuBlockBitmapChainIsValid(virStorageSource *src,
                            const char *bitmapname,
                            GHashTable *blockNamedNodeData)
{
    virStorageSource *n;
    bool found = false;
    bool chain_ended = false;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        qemuBlockNamedNodeDataBitmap *bitmap;

        if (!(bitmap = qemuBlockNamedNodeDataGetBitmapByName(blockNamedNodeData,
                                                             n, bitmapname))) {
            /* rule 1, must start from top */
            if (!found)
                return false;

            chain_ended = true;

            continue;
        }

        /* rule 2, no-gaps */
        if (chain_ended)
            return false;

        /* rule 3 */
        if (bitmap->inconsistent || !bitmap->persistent || !bitmap->recording)
            return false;

        found = true;
    }

    return found;
}


/**
 * qemuBlockBitmapsHandleBlockcopy:
 * @src: disk source
 * @mirror: mirror source
 * @blockNamedNodeData: hash table containing data about bitmaps
 * @shallow: whether shallow copy is requested
 * @actions: filled with arguments for a 'transaction' command
 *
 * Calculates which bitmaps to copy and merge during a virDomainBlockCopy job.
 * This is designed to be called when the job is already synchronised as it
 * may result in active bitmaps being created.
 *
 * Returns 0 on success and -1 on error. If @actions is NULL when 0 is returned
 * there are no actions to perform for the given job.
 */
int
qemuBlockBitmapsHandleBlockcopy(virStorageSource *src,
                                virStorageSource *mirror,
                                GHashTable *blockNamedNodeData,
                                bool shallow,
                                virJSONValue **actions)
{
    virStorageSource *base = NULL;

    if (shallow)
        base = src->backingStore;

    if (qemuBlockGetBitmapMergeActions(src, base, mirror, NULL, NULL, mirror, actions,
                                       blockNamedNodeData) < 0)
        return -1;

    return 0;
}


/**
 * @topsrc: virStorageSource representing 'top' of the job
 * @basesrc: virStorageSource representing 'base' of the job
 * @active: commit job is an active layer block-commit
 * @blockNamedNodeData: hash table containing data about bitmaps
 * @actions: filled with arguments for a 'transaction' command
 * @disabledBitmapsBase: bitmap names which were disabled
 *
 * Calculates the necessary bitmap merges/additions/enablements to properly
 * handle commit of images from 'top' into 'base'. The necessary operations
 * in the form of arguments of the 'transaction' command are filled into
 * 'actions' if there is anything to do. Otherwise NULL is returned.
 */
int
qemuBlockBitmapsHandleCommitFinish(virStorageSource *topsrc,
                                   virStorageSource *basesrc,
                                   bool active,
                                   GHashTable *blockNamedNodeData,
                                   virJSONValue **actions)
{
    virStorageSource *writebitmapsrc = NULL;

    if (active)
        writebitmapsrc = basesrc;

    if (qemuBlockGetBitmapMergeActions(topsrc, basesrc, basesrc, NULL, NULL,
                                       writebitmapsrc, actions,
                                       blockNamedNodeData) < 0)
        return -1;

    return 0;
}


int
qemuBlockReopenFormatMon(qemuMonitor *mon,
                         virStorageSource *src)
{
    g_autoptr(virJSONValue) reopenprops = NULL;
    g_autoptr(virJSONValue) srcprops = NULL;
    g_autoptr(virJSONValue) reopenoptions = virJSONValueNewArray();

    if (!(srcprops = qemuBlockStorageSourceGetBlockdevProps(src, src->backingStore)))
        return -1;

    if (virJSONValueArrayAppend(reopenoptions, &srcprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(&reopenprops,
                              "a:options", &reopenoptions,
                              NULL) < 0)
        return -1;

    if (qemuMonitorBlockdevReopen(mon, &reopenprops) < 0)
        return -1;

    return 0;
}


/**
 * qemuBlockReopenFormat:
 * @vm: domain object
 * @src: storage source to reopen
 * @asyncJob: qemu async job type
 *
 * Invokes the 'blockdev-reopen' command on the format layer of @src. This means
 * that @src must be already properly configured for the desired outcome. The
 * nodenames of @src are used to identify the specific image in qemu.
 */
static int
qemuBlockReopenFormat(virDomainObj *vm,
                      virStorageSource *src,
                      virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    /* If we are lacking the object here, qemu might have opened an image with
     * a node name unknown to us */
    if (!src->backingStore) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("can't reopen image with unknown presence of backing store"));
        return -1;
    }

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuBlockReopenFormatMon(priv->mon, src);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    return 0;
}


/**
 * qemuBlockReopenReadWrite:
 * @vm: domain object
 * @src: storage source to reopen
 * @asyncJob: qemu async job type
 *
 * Wrapper that reopens @src read-write. We currently depend on qemu
 * reopening the storage with 'auto-read-only' enabled for us.
 * After successful reopen @src's 'readonly' flag is modified. Does nothing
 * if @src is already read-write.
 */
int
qemuBlockReopenReadWrite(virDomainObj *vm,
                         virStorageSource *src,
                         virDomainAsyncJob asyncJob)
{
    if (!src->readonly)
        return 0;

    src->readonly = false;
    if (qemuBlockReopenFormat(vm, src, asyncJob) < 0) {
        src->readonly = true;
        return -1;
    }

    return 0;
}


/**
 * qemuBlockReopenReadOnly:
 * @vm: domain object
 * @src: storage source to reopen
 * @asyncJob: qemu async job type
 *
 * Wrapper that reopens @src read-only. We currently depend on qemu
 * reopening the storage with 'auto-read-only' enabled for us.
 * After successful reopen @src's 'readonly' flag is modified. Does nothing
 * if @src is already read-only.
 */
int
qemuBlockReopenReadOnly(virDomainObj *vm,
                         virStorageSource *src,
                         virDomainAsyncJob asyncJob)
{
    if (src->readonly)
        return 0;

    src->readonly = true;
    if (qemuBlockReopenFormat(vm, src, asyncJob) < 0) {
        src->readonly = false;
        return -1;
    }

    return 0;
}

/**
 * qemuBlockStorageSourceNeedSliceLayer:
 * @src: source to inspect
 *
 * Returns true if @src requires an extra 'raw' layer for handling of the storage
 * slice.
 */
bool
qemuBlockStorageSourceNeedsStorageSliceLayer(const virStorageSource *src)
{
    if (!src->sliceStorage)
        return false;

    if (src->format != VIR_STORAGE_FILE_RAW)
        return true;

    if (src->encryption &&
        src->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS)
        return true;

    return false;
}


/**
 * qemuBlockStorageSourceGetCookieString:
 * @src: storage source
 *
 * Returns a properly formatted string representing cookies of @src in format
 * accepted by qemu.
 */
char *
qemuBlockStorageSourceGetCookieString(virStorageSource *src)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    for (i = 0; i < src->ncookies; i++) {
        virStorageNetCookieDef *cookie = src->cookies[i];

        virBufferAsprintf(&buf, "%s=%s; ", cookie->name, cookie->value);
    }

    virBufferTrim(&buf, "; ");

    return virBufferContentAndReset(&buf);
}


/**
 * qemuBlockUpdateRelativeBacking:
 * @vm: domain object
 * @src: starting point of the update
 * @topsrc: top level image in the backing chain (used to get security label)
 *
 * Reload data necessary for keeping backing store links starting from @src
 * relative.
 */
int
qemuBlockUpdateRelativeBacking(virDomainObj *vm,
                               virStorageSource *src,
                               virStorageSource *topsrc)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virStorageSource *n;

    for (n = src; virStorageSourceHasBacking(n); n = n->backingStore) {
        int rc;

        if (n->backingStore->relPath)
            break;

        if (!virStorageSourceSupportsBackingChainTraversal(n))
            continue;

        if (qemuDomainStorageFileInit(driver, vm, n, topsrc) < 0)
            return -1;

        rc = virStorageSourceFetchRelativeBackingPath(n, &n->backingStore->relPath);

        virStorageSourceDeinit(n);

        if (rc < 0)
            return rc;
    }

    return 0;
}


virJSONValue *
qemuBlockExportGetNBDProps(const char *nodename,
                           const char *exportname,
                           bool writable,
                           const char **bitmaps)
{
    g_autofree char *exportid = NULL;
    g_autoptr(virJSONValue) bitmapsarr = NULL;
    virJSONValue *ret = NULL;

    exportid = g_strdup_printf("libvirt-nbd-%s", nodename);

    if (bitmaps && *bitmaps) {
        bitmapsarr = virJSONValueNewArray();

        while (*bitmaps) {
            if (virJSONValueArrayAppendString(bitmapsarr, *(bitmaps++)) < 0)
                return NULL;
        }
    }

    if (virJSONValueObjectAdd(&ret,
                              "s:type", "nbd",
                              "s:id", exportid,
                              "s:node-name", nodename,
                              "b:writable", writable,
                              "s:name", exportname,
                              "A:bitmaps", &bitmapsarr,
                              NULL) < 0)
        return NULL;

    return ret;
}


/**
 * qemuBlockExportAddNBD:
 * @vm: domain object
 * @src: disk source to export
 * @exportname: name for the export
 * @writable: whether the NBD export allows writes
 * @bitmap: (optional) block dirty bitmap to export along
 *
 * This function automatically selects the proper invocation of exporting a
 * block backend via NBD in qemu.
 *
 * This function must be called while in the monitor context.
 */
int
qemuBlockExportAddNBD(virDomainObj *vm,
                      virStorageSource *src,
                      const char *exportname,
                      bool writable,
                      const char *bitmap)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) nbdprops = NULL;
    const char *bitmaps[2] = { bitmap, NULL };

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCK_EXPORT_ADD))
        return qemuMonitorNBDServerAdd(priv->mon, src->nodeformat,
                                       exportname, writable, bitmap);

    if (!(nbdprops = qemuBlockExportGetNBDProps(src->nodeformat, exportname,
                                                writable, bitmaps)))
        return -1;

    return qemuMonitorBlockExportAdd(priv->mon, &nbdprops);
}
