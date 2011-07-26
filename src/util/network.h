/*
 * network.h: network helper APIs for libvirt
 *
 * Copyright (C) 2009-2009 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_NETWORK_H__
# define __VIR_NETWORK_H__

# include "internal.h"
# include "buf.h"
# include "util.h"

# include <sys/types.h>
# include <sys/socket.h>
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
# endif
# include <netdb.h>
# include <netinet/in.h>
# include <xml.h>

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_storage stor;
        struct sockaddr_in inet4;
        struct sockaddr_in6 inet6;
# ifdef HAVE_SYS_UN_H
        struct sockaddr_un un;
# endif
    } data;
    socklen_t len;
} virSocketAddr;

# define VIR_SOCKET_HAS_ADDR(s)                 \
    ((s)->data.sa.sa_family != AF_UNSPEC)

# define VIR_SOCKET_IS_FAMILY(s, f)             \
    ((s)->data.sa.sa_family == f)

# define VIR_SOCKET_FAMILY(s)                   \
    ((s)->data.sa.sa_family)

typedef virSocketAddr *virSocketAddrPtr;

typedef struct {
    unsigned long long average;  /* kbytes/s */
    unsigned long long peak;     /* kbytes/s */
    unsigned long long burst;    /* kbytes */
} virRate;

typedef virRate *virRatePtr;

typedef struct {
    virRatePtr in, out;
} virBandwidth;

typedef virBandwidth *virBandwidthPtr;

int virSocketParseAddr    (const char *val,
                           virSocketAddrPtr addr,
                           int hint);

int virSocketParseIpv4Addr(const char *val,
                           virSocketAddrPtr addr);

int virSocketParseIpv6Addr(const char *val,
                           virSocketAddrPtr addr);

char * virSocketFormatAddr(virSocketAddrPtr addr);
char * virSocketFormatAddrFull(virSocketAddrPtr addr,
                               bool withService,
                               const char *separator);

int virSocketSetPort(virSocketAddrPtr addr, int port);

int virSocketGetPort(virSocketAddrPtr addr);

int virSocketGetRange     (virSocketAddrPtr start,
                           virSocketAddrPtr end);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketCheckNetmask (virSocketAddrPtr addr1,
                           virSocketAddrPtr addr2,
                           virSocketAddrPtr netmask);
int virSocketAddrMask     (const virSocketAddrPtr addr,
                           const virSocketAddrPtr netmask,
                           virSocketAddrPtr       network);
int virSocketAddrMaskByPrefix(const virSocketAddrPtr addr,
                              unsigned int           prefix,
                              virSocketAddrPtr       network);
int virSocketAddrBroadcast(const virSocketAddrPtr addr,
                           const virSocketAddrPtr netmask,
                           virSocketAddrPtr       broadcast);
int virSocketAddrBroadcastByPrefix(const virSocketAddrPtr addr,
                                   unsigned int           prefix,
                                   virSocketAddrPtr       broadcast);

int virSocketGetNumNetmaskBits(const virSocketAddrPtr netmask);
int virSocketAddrPrefixToNetmask(unsigned int prefix,
                                 virSocketAddrPtr netmask,
                                 int family);

/* virtualPortProfile utilities */
# ifdef IFLA_VF_PORT_PROFILE_MAX
#  define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX IFLA_VF_PORT_PROFILE_MAX
# else
#  define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX 40
# endif

enum virVirtualPortType {
    VIR_VIRTUALPORT_NONE,
    VIR_VIRTUALPORT_8021QBG,
    VIR_VIRTUALPORT_8021QBH,

    VIR_VIRTUALPORT_TYPE_LAST,
};

VIR_ENUM_DECL(virVirtualPort)

/* profile data for macvtap (VEPA) */
typedef struct _virVirtualPortProfileParams virVirtualPortProfileParams;
typedef virVirtualPortProfileParams *virVirtualPortProfileParamsPtr;
struct _virVirtualPortProfileParams {
    enum virVirtualPortType   virtPortType;
    union {
        struct {
            uint8_t       managerID;
            uint32_t      typeID; /* 24 bit valid */
            uint8_t       typeIDVersion;
            unsigned char instanceID[VIR_UUID_BUFLEN];
        } virtPort8021Qbg;
        struct {
            char          profileID[LIBVIRT_IFLA_VF_PORT_PROFILE_MAX];
        } virtPort8021Qbh;
    } u;
};

int
virVirtualPortProfileParseXML(xmlNodePtr node,
                              virVirtualPortProfileParamsPtr *virtPort);
void
virVirtualPortProfileFormat(virBufferPtr buf,
                            virVirtualPortProfileParamsPtr virtPort,
                            const char *indent);

virBandwidthPtr virBandwidthDefParseNode(xmlNodePtr node);
void virBandwidthDefFree(virBandwidthPtr def);
int virBandwidthDefFormat(virBufferPtr buf,
                          virBandwidthPtr def,
                          const char *indent);

int virBandwidthEnable(virBandwidthPtr bandwidth, const char *iface);
int virBandwidthDisable(const char *iface, bool may_fail);
int virBandwidthCopy(virBandwidthPtr *dest, const virBandwidthPtr src);

#endif /* __VIR_NETWORK_H__ */
