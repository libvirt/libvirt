/*
 * network.h: network helper APIs for libvirt
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

# define VIR_SOCKET_ADDR_VALID(s)               \
    ((s)->data.sa.sa_family != AF_UNSPEC)

# define VIR_SOCKET_ADDR_IS_FAMILY(s, f)        \
    ((s)->data.sa.sa_family == f)

# define VIR_SOCKET_ADDR_FAMILY(s)              \
    ((s)->data.sa.sa_family)

typedef virSocketAddr *virSocketAddrPtr;

typedef struct _virNetDevBandwidthRate virNetDevBandwidthRate;
typedef virNetDevBandwidthRate *virNetDevBandwidthRatePtr;
struct _virNetDevBandwidthRate {
    unsigned long long average;  /* kbytes/s */
    unsigned long long peak;     /* kbytes/s */
    unsigned long long burst;    /* kbytes */
};

typedef struct _virNetDevBandwidth virNetDevBandwidth;
typedef virNetDevBandwidth *virNetDevBandwidthPtr;
struct _virNetDevBandwidth {
    virNetDevBandwidthRatePtr in, out;
};

int virSocketAddrParse(virSocketAddrPtr addr,
                       const char *val,
                       int family);

int virSocketAddrParseIPv4(virSocketAddrPtr addr,
                           const char *val);

int virSocketAddrParseIPv6(virSocketAddrPtr addr,
                           const char *val);

char * virSocketAddrFormat(virSocketAddrPtr addr);
char * virSocketAddrFormatFull(virSocketAddrPtr addr,
                               bool withService,
                               const char *separator);

int virSocketAddrSetPort(virSocketAddrPtr addr, int port);

int virSocketAddrGetPort(virSocketAddrPtr addr);

int virSocketAddrGetRange(virSocketAddrPtr start,
                          virSocketAddrPtr end);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketAddrCheckNetmask(virSocketAddrPtr addr1,
                              virSocketAddrPtr addr2,
                              virSocketAddrPtr netmask);
int virSocketAddrMask(const virSocketAddrPtr addr,
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

int virSocketAddrGetNumNetmaskBits(const virSocketAddrPtr netmask);
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
                            virVirtualPortProfileParamsPtr virtPort);

bool virVirtualPortProfileEqual(virVirtualPortProfileParamsPtr a,
                                virVirtualPortProfileParamsPtr b);

virNetDevBandwidthPtr virNetDevBandwidthParse(xmlNodePtr node)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
void virNetDevBandwidthFree(virNetDevBandwidthPtr def);
int virNetDevBandwidthFormat(virNetDevBandwidthPtr def,
                             virBufferPtr buf)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virNetDevBandwidthSet(const char *ifname, virNetDevBandwidthPtr bandwidth)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthClear(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthCopy(virNetDevBandwidthPtr *dest, const virNetDevBandwidthPtr src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

bool virNetDevBandwidthEqual(virNetDevBandwidthPtr a, virNetDevBandwidthPtr b);


#endif /* __VIR_NETWORK_H__ */
