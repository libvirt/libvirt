/*
 * proxy.h: common definitions for proxy usage
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */


#ifndef __LIBVIR_PROXY_H__
#define __LIBVIR_PROXY_H__

#include "libvirt/libvirt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROXY_SOCKET_PATH "/tmp/livirt_proxy_conn"
#define PROXY_PROTO_VERSION 1

/*
 * the command allowed though the proxy
 */
typedef enum {
        VIR_PROXY_NONE = 0,
        VIR_PROXY_VERSION = 1,
        VIR_PROXY_NODE_INFO = 2,
        VIR_PROXY_LIST = 3,
        VIR_PROXY_NUM_DOMAIN = 4,
        VIR_PROXY_LOOKUP_ID = 5,
        VIR_PROXY_LOOKUP_UUID = 6,
        VIR_PROXY_LOOKUP_NAME = 7,
        VIR_PROXY_MAX_MEMORY = 8,
        VIR_PROXY_DOMAIN_INFO = 9,
        VIR_PROXY_DOMAIN_XML = 10,
        VIR_PROXY_DOMAIN_OSTYPE = 11,
    VIR_PROXY_GET_CAPABILITIES = 12
} virProxyCommand;

/*
 * structure used by the client to make a request to the proxy
 * and by the proxy when answering the client.
 * the size may not be fixed, it's passed as len.
 */
struct _virProxyPacket {
    unsigned short version;	/* version of the proxy protocol */
    unsigned short command;	/* command number a virProxyCommand */
    unsigned short serial;	/* command serial number */
    unsigned short len;		/* the length of the request */
    union {
        char       string[8];	/* string data */
        int        arg;		/* or int argument */
        long       larg;	/* or long argument */
    } data;
};
typedef struct _virProxyPacket virProxyPacket;
typedef  virProxyPacket *virProxyPacketPtr;

/*
 * If there is extra data sent from the proxy to the client,
 * they are appended after the packet.
 * the size may not be fixed, it's passed as len and includes the
 * extra data.
 */
struct _virProxyFullPacket {
    unsigned short version;	/* version of the proxy protocol */
    unsigned short command;	/* command number a virProxyCommand */
    unsigned short serial;	/* command serial number */
    unsigned short len;		/* the length of the request */
    union {
        char       string[8];	/* string data */
        int        arg;		/* or int argument */
        long       larg;	/* or long argument */
    } data;
    /* that should be aligned on a 16bytes boundary */
    union {
        char       str[4080];   /* extra char array */
        int        arg[1020];   /* extra int array */
        virDomainInfo dinfo;	/* domain information */
        virNodeInfo   ninfo;	/* node information */
    } extra;
};
typedef struct _virProxyFullPacket virProxyFullPacket;
typedef  virProxyFullPacket *virProxyFullPacketPtr;

/* xen_unified makes direct calls or indirect calls through here. */
extern struct xenUnifiedDriver xenProxyDriver;
extern int xenProxyInit (void);

extern virDomainPtr xenProxyLookupByID(virConnectPtr conn, int id);
extern virDomainPtr xenProxyLookupByUUID(virConnectPtr conn,
                                         const unsigned char *uuid);
extern virDomainPtr xenProxyLookupByName(virConnectPtr conn,
                                         const char *domname);

extern char *       xenProxyDomainDumpXML(virDomainPtr domain,
                                          int flags);
#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif /* __LIBVIR_PROXY_H__ */
