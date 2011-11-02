/*
 * network.c: network helper APIs for libvirt
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>
#include <arpa/inet.h>

#include "memory.h"
#include "uuid.h"
#include "network.h"
#include "util.h"
#include "virterror_internal.h"
#include "command.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define virSocketError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/*
 * Helpers to extract the IP arrays from the virSocketAddrPtr
 * That part is the less portable of the module
 */
typedef unsigned char virSocketAddrIPv4[4];
typedef virSocketAddrIPv4 *virSocketAddrIPv4Ptr;
typedef unsigned short virSocketAddrIPv6[8];
typedef virSocketAddrIPv6 *virSocketAddrIPv6Ptr;

static int virSocketAddrGetIPv4Addr(virSocketAddrPtr addr, virSocketAddrIPv4Ptr tab) {
    unsigned long val;
    int i;

    if ((addr == NULL) || (tab == NULL) || (addr->data.stor.ss_family != AF_INET))
        return(-1);

    val = ntohl(addr->data.inet4.sin_addr.s_addr);

    for (i = 0;i < 4;i++) {
        (*tab)[3 - i] = val & 0xFF;
        val >>= 8;
    }

    return(0);
}

static int virSocketAddrGetIPv6Addr(virSocketAddrPtr addr, virSocketAddrIPv6Ptr tab) {
    int i;

    if ((addr == NULL) || (tab == NULL) || (addr->data.stor.ss_family != AF_INET6))
        return(-1);

    for (i = 0;i < 8;i++) {
        (*tab)[i] = ((addr->data.inet6.sin6_addr.s6_addr[2 * i] << 8) |
                     addr->data.inet6.sin6_addr.s6_addr[2 * i + 1]);
    }

    return(0);
}

/**
 * virSocketAddrParse:
 * @val: a numeric network address IPv4 or IPv6
 * @addr: where to store the return value, optional.
 * @family: address family to pass down to getaddrinfo
 *
 * Mostly a wrapper for getaddrinfo() extracting the address storage
 * from the numeric string like 1.2.3.4 or 2001:db8:85a3:0:0:8a2e:370:7334
 *
 * Returns the length of the network address or -1 in case of error.
 */
int virSocketAddrParse(virSocketAddrPtr addr, const char *val, int family) {
    int len;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int err;

    if (val == NULL) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s", _("Missing address"));
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST;
    if ((err = getaddrinfo(val, NULL, &hints, &res)) != 0) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("Cannot parse socket address '%s': %s"),
                       val, gai_strerror(err));
        return -1;
    }

    if (res == NULL) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("No socket addresses found for '%s'"),
                       val);
        return -1;
    }

    len = res->ai_addrlen;
    if (addr != NULL) {
        memcpy(&addr->data.stor, res->ai_addr, len);
        addr->len = res->ai_addrlen;
    }

    freeaddrinfo(res);
    return(len);
}

/*
 * virSocketAddrParseIPv4:
 * @val: an IPv4 numeric address
 * @addr: the location to store the result
 *
 * Extract the address storage from an IPv4 numeric address
 *
 * Returns the length of the network address or -1 in case of error.
 */
int
virSocketAddrParseIPv4(virSocketAddrPtr addr, const char *val) {
    return virSocketAddrParse(addr, val, AF_INET);
}

/*
 * virSocketAddrParseIPv6:
 * @val: an IPv6 numeric address
 * @addr: the location to store the result
 *
 * Extract the address storage from an IPv6 numeric address
 *
 * Returns the length of the network address or -1 in case of error.
 */
int
virSocketAddrParseIPv6(virSocketAddrPtr addr, const char *val) {
    return virSocketAddrParse(addr, val, AF_INET6);
}

/*
 * virSocketAddrFormat:
 * @addr: an initialized virSocketAddrPtr
 *
 * Returns a string representation of the given address
 * Returns NULL on any error
 * Caller must free the returned string
 */
char *
virSocketAddrFormat(virSocketAddrPtr addr) {
    return virSocketAddrFormatFull(addr, false, NULL);
}


/*
 * virSocketAddrFormatFull:
 * @addr: an initialized virSocketAddrPtr
 * @withService: if true, then service info is appended
 * @separator: separator between hostname & service.
 *
 * Returns a string representation of the given address
 * Returns NULL on any error
 * Caller must free the returned string
 */
char *
virSocketAddrFormatFull(virSocketAddrPtr addr,
                        bool withService,
                        const char *separator)
{
    char host[NI_MAXHOST], port[NI_MAXSERV];
    char *addrstr;
    int err;

    if (addr == NULL) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s", _("Missing address"));
        return NULL;
    }

    /* Short-circuit since getnameinfo doesn't work
     * nicely for UNIX sockets */
    if (addr->data.sa.sa_family == AF_UNIX) {
        if (withService) {
            if (virAsprintf(&addrstr, "127.0.0.1%s0",
                            separator ? separator : ":") < 0)
                goto no_memory;
        } else {
            if (!(addrstr = strdup("127.0.0.1")))
                goto no_memory;
        }
        return addrstr;
    }

    if ((err = getnameinfo(&addr->data.sa,
                           addr->len,
                           host, sizeof(host),
                           port, sizeof(port),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("Cannot convert socket address to string: %s"),
                       gai_strerror(err));
        return NULL;
    }

    if (withService) {
        if (virAsprintf(&addrstr, "%s%s%s", host, separator, port) == -1)
            goto no_memory;
    } else {
        if (!(addrstr = strdup(host)))
            goto no_memory;
    }

    return addrstr;

no_memory:
    virReportOOMError();
    return NULL;
}


/*
 * virSocketAddrSetPort:
 * @addr: an initialized virSocketAddrPtr
 * @port: the port number to set
 *
 * Set the transport layer port of the given virtSocketAddr
 *
 * Returns 0 on success, -1 on failure
 */
int
virSocketAddrSetPort(virSocketAddrPtr addr, int port) {
    if (addr == NULL)
        return -1;

    port = htons(port);

    if(addr->data.stor.ss_family == AF_INET) {
        addr->data.inet4.sin_port = port;
    }

    else if(addr->data.stor.ss_family == AF_INET6) {
        addr->data.inet6.sin6_port = port;
    }

    else {
        return -1;
    }

    return 0;
}

/*
 * virSocketGetPort:
 * @addr: an initialized virSocketAddrPtr
 *
 * Returns the transport layer port of the given virtSocketAddr
 * Returns -1 if @addr is invalid
 */
int
virSocketAddrGetPort(virSocketAddrPtr addr) {
    if (addr == NULL)
        return -1;

    if(addr->data.stor.ss_family == AF_INET) {
        return ntohs(addr->data.inet4.sin_port);
    }

    else if(addr->data.stor.ss_family == AF_INET6) {
        return ntohs(addr->data.inet6.sin6_port);
    }

    return -1;
}

/**
 * virSocketAddrIsNetmask:
 * @netmask: the netmask address
 *
 * Check that @netmask is a proper network mask
 *
 * Returns 0 in case of success and -1 in case of error
 */
int virSocketAddrIsNetmask(virSocketAddrPtr netmask) {
    int n = virSocketAddrGetNumNetmaskBits(netmask);
    if (n < 0)
        return -1;
    return 0;
}

/**
 * virSocketAddrMask:
 * @addr: address that needs to be masked
 * @netmask: the netmask address
 * @network: where to store the result, can be same as @addr
 *
 * Mask off the host bits of @addr according to @netmask, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrMask(const virSocketAddrPtr addr,
                  const virSocketAddrPtr netmask,
                  virSocketAddrPtr       network)
{
    if (addr->data.stor.ss_family != netmask->data.stor.ss_family) {
        network->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    if (addr->data.stor.ss_family == AF_INET) {
        network->data.inet4.sin_addr.s_addr
            = (addr->data.inet4.sin_addr.s_addr
               & netmask->data.inet4.sin_addr.s_addr);
        network->data.inet4.sin_port = 0;
        network->data.stor.ss_family = AF_INET;
        network->len = addr->len;
        return 0;
    }
    if (addr->data.stor.ss_family == AF_INET6) {
        int ii;
        for (ii = 0; ii < 16; ii++) {
            network->data.inet6.sin6_addr.s6_addr[ii]
                = (addr->data.inet6.sin6_addr.s6_addr[ii]
                   & netmask->data.inet6.sin6_addr.s6_addr[ii]);
        }
        network->data.inet6.sin6_port = 0;
        network->data.stor.ss_family = AF_INET6;
        network->len = addr->len;
        return 0;
    }
    network->data.stor.ss_family = AF_UNSPEC;
    return -1;
}

/**
 * virSocketAddrMaskByPrefix:
 * @addr: address that needs to be masked
 * @prefix: prefix (# of 1 bits) of netmask to apply
 * @network: where to store the result, can be same as @addr
 *
 * Mask off the host bits of @addr according to @prefix, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrMaskByPrefix(const virSocketAddrPtr addr,
                          unsigned int           prefix,
                          virSocketAddrPtr       network)
{
    virSocketAddr netmask;

    if (virSocketAddrPrefixToNetmask(prefix, &netmask,
                                     addr->data.stor.ss_family) < 0) {
        network->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    return virSocketAddrMask(addr, &netmask, network);
}

/**
 * virSocketAddrBroadcast:
 * @addr: address that needs to be turned into broadcast address (IPv4 only)
 * @netmask: the netmask address
 * @broadcast: virSocketAddr to recieve the broadcast address
 *
 * Mask ON the host bits of @addr according to @netmask, turning it
 * into a broadcast address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrBroadcast(const virSocketAddrPtr addr,
                       const virSocketAddrPtr netmask,
                       virSocketAddrPtr       broadcast)
{
    if ((addr->data.stor.ss_family != AF_INET) ||
        (netmask->data.stor.ss_family != AF_INET)) {
        broadcast->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    broadcast->data.stor.ss_family = AF_INET;
    broadcast->len = addr->len;
    broadcast->data.inet4.sin_addr.s_addr
        = (addr->data.inet4.sin_addr.s_addr
           | ~netmask->data.inet4.sin_addr.s_addr);
    return 0;
}

/**
 * virSocketAddrBroadcastByPrefix:
 * @addr: address that needs to be turned into broadcast address (IPv4 only)
 * @prefix: prefix (# of 1 bits) of netmask to apply
 * @broadcast: virSocketAddr to recieve the broadcast address
 *
 * Mask off the host bits of @addr according to @prefix, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrBroadcastByPrefix(const virSocketAddrPtr addr,
                               unsigned int           prefix,
                               virSocketAddrPtr       broadcast)
{
    virSocketAddr netmask;

    if (virSocketAddrPrefixToNetmask(prefix, &netmask,
                                     addr->data.stor.ss_family) < 0)
        return -1;

    return virSocketAddrBroadcast(addr, &netmask, broadcast);
}

/**
 * virSocketCheckNetmask:
 * @addr1: a first network address
 * @addr2: a second network address
 * @netmask: the netmask address
 *
 * Check that @addr1 and @addr2 pertain to the same @netmask address
 * range and returns the size of the range
 *
 * Returns 1 in case of success and 0 in case of failure and
 *         -1 in case of error
 */
int virSocketAddrCheckNetmask(virSocketAddrPtr addr1, virSocketAddrPtr addr2,
                              virSocketAddrPtr netmask) {
    int i;

    if ((addr1 == NULL) || (addr2 == NULL) || (netmask == NULL))
        return(-1);
    if ((addr1->data.stor.ss_family != addr2->data.stor.ss_family) ||
        (addr1->data.stor.ss_family != netmask->data.stor.ss_family))
        return(-1);

    if (virSocketAddrIsNetmask(netmask) != 0)
        return(-1);

    if (addr1->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 t1, t2, tm;

        if ((virSocketAddrGetIPv4Addr(addr1, &t1) < 0) ||
            (virSocketAddrGetIPv4Addr(addr2, &t2) < 0) ||
            (virSocketAddrGetIPv4Addr(netmask, &tm) < 0))
            return(-1);

        for (i = 0;i < 4;i++) {
            if ((t1[i] & tm[i]) != (t2[i] & tm[i]))
                return(0);
        }

    } else if (addr1->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 t1, t2, tm;

        if ((virSocketAddrGetIPv6Addr(addr1, &t1) < 0) ||
            (virSocketAddrGetIPv6Addr(addr2, &t2) < 0) ||
            (virSocketAddrGetIPv6Addr(netmask, &tm) < 0))
            return(-1);

        for (i = 0;i < 8;i++) {
            if ((t1[i] & tm[i]) != (t2[i] & tm[i]))
                return(0);
        }

    } else {
        return(-1);
    }
    return(1);
}

/**
 * virSocketGetRange:
 * @start: start of an IP range
 * @end: end of an IP range
 *
 * Check the order of the 2 addresses and compute the range, this
 * will return 1 for identical addresses. Errors can come from incompatible
 * addresses type, excessive range (>= 2^^16) where the two addresses are
 * unrelated or inverted start and end.
 *
 * Returns the size of the range or -1 in case of failure
 */
int virSocketAddrGetRange(virSocketAddrPtr start, virSocketAddrPtr end) {
    int ret = 0, i;

    if ((start == NULL) || (end == NULL))
        return(-1);
    if (start->data.stor.ss_family != end->data.stor.ss_family)
        return(-1);

    if (start->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 t1, t2;

        if ((virSocketAddrGetIPv4Addr(start, &t1) < 0) ||
            (virSocketAddrGetIPv4Addr(end, &t2) < 0))
            return(-1);

        for (i = 0;i < 2;i++) {
            if (t1[i] != t2[i])
                return(-1);
        }
        ret = (t2[2] - t1[2]) * 256 + (t2[3] - t1[3]);
        if (ret < 0)
            return(-1);
        ret++;
    } else if (start->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 t1, t2;

        if ((virSocketAddrGetIPv6Addr(start, &t1) < 0) ||
            (virSocketAddrGetIPv6Addr(end, &t2) < 0))
            return(-1);

        for (i = 0;i < 7;i++) {
            if (t1[i] != t2[i])
                return(-1);
        }
        ret = t2[7] - t1[7];
        if (ret < 0)
            return(-1);
        ret++;
    } else {
        return(-1);
    }
    return(ret);
}


/**
 * virSocketAddrGetNumNetmaskBits
 * @netmask: the presumed netmask
 *
 * Get the number of netmask bits in a netmask.
 *
 * Returns the number of bits in the netmask or -1 if an error occurred
 * or the netmask is invalid.
 */
int virSocketAddrGetNumNetmaskBits(const virSocketAddrPtr netmask)
{
    int i, j;
    int c = 0;

    if (netmask->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 tm;
        uint8_t bit;

        if (virSocketAddrGetIPv4Addr(netmask, &tm) < 0)
            return -1;

        for (i = 0; i < 4; i++)
            if (tm[i] == 0xff)
                c += 8;
            else
                break;

        if (c == 8 * 4)
            return c;

        j = i << 3;
        while (j < (8 * 4)) {
            bit = 1 << (7 - (j & 7));
            if ((tm[j >> 3] & bit)) {
                c++;
            } else
                break;
            j++;
        }

        while (j < (8 * 4)) {
            bit = 1 << (7 - (j & 7));
            if ((tm[j >> 3] & bit))
                return -1;
            j++;
        }

        return c;
    } else if (netmask->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 tm;
        uint16_t bit;

        if (virSocketAddrGetIPv6Addr(netmask, &tm) < 0)
            return -1;

        for (i = 0; i < 8; i++)
            if (tm[i] == 0xffff)
                c += 16;
            else
                break;

        if (c == 16 * 8)
            return c;

        j = i << 4;
        while (j < (16 * 8)) {
            bit = 1 << (15 - (j & 0xf));
            if ((tm[j >> 4] & bit)) {
                c++;
            } else
                break;
            j++;
        }

        while (j < (16 * 8)) {
            bit = 1 << (15 - (j & 0xf));
            if ((tm[j >> 4]) & bit)
                return -1;
            j++;
        }

        return c;
    }
    return -1;
}

/**
 * virSocketPrefixToNetmask:
 * @prefix: number of 1 bits to put in the netmask
 * @netmask: address to fill in with the desired netmask
 * @family: family of the address (AF_INET or AF_INET6 only)
 *
 * given @prefix and @family, fill in @netmask with a netmask
 * (eg 255.255.255.0).
 *
 * Returns 0 on success or -1 on error.
 */

int
virSocketAddrPrefixToNetmask(unsigned int prefix,
                             virSocketAddrPtr netmask,
                             int family)
{
    int result = -1;

    netmask->data.stor.ss_family = AF_UNSPEC; /* assume failure */

    if (family == AF_INET) {
        int ip;

        if (prefix > 32)
            goto error;

        ip = prefix ? ~((1 << (32 - prefix)) - 1) : 0;
        netmask->data.inet4.sin_addr.s_addr = htonl(ip);
        netmask->data.stor.ss_family = AF_INET;
        result = 0;

    } else if (family == AF_INET6) {
        int ii = 0;

        if (prefix > 128)
            goto error;

        while (prefix >= 8) {
            /* do as much as possible an entire byte at a time */
            netmask->data.inet6.sin6_addr.s6_addr[ii++] = 0xff;
            prefix -= 8;
        }
        if (prefix > 0) {
            /* final partial byte */
            netmask->data.inet6.sin6_addr.s6_addr[ii++]
                = ~((1 << (8 - prefix)) -1);
        }
        while (ii < 16) {
            /* zerofill remainder in case it wasn't initialized */
            netmask->data.inet6.sin6_addr.s6_addr[ii++] = 0;
        }
        netmask->data.stor.ss_family = AF_INET6;
        result = 0;
    }

error:
    return result;
}

/* virtualPortProfile utilities */

VIR_ENUM_IMPL(virVirtualPort, VIR_VIRTUALPORT_TYPE_LAST,
              "none",
              "802.1Qbg",
              "802.1Qbh")

int
virVirtualPortProfileParseXML(xmlNodePtr node,
                              virVirtualPortProfileParamsPtr *def)
{
    int ret = -1;
    char *virtPortType;
    char *virtPortManagerID = NULL;
    char *virtPortTypeID = NULL;
    char *virtPortTypeIDVersion = NULL;
    char *virtPortInstanceID = NULL;
    char *virtPortProfileID = NULL;
    virVirtualPortProfileParamsPtr virtPort = NULL;
    xmlNodePtr cur = node->children;

    if (VIR_ALLOC(virtPort) < 0) {
        virReportOOMError();
        return -1;
    }

    virtPortType = virXMLPropString(node, "type");
    if (!virtPortType) {
        virSocketError(VIR_ERR_XML_ERROR, "%s",
                             _("missing virtualportprofile type"));
        goto error;
    }

    while (cur != NULL) {
        if (xmlStrEqual(cur->name, BAD_CAST "parameters")) {

            virtPortManagerID = virXMLPropString(cur, "managerid");
            virtPortTypeID = virXMLPropString(cur, "typeid");
            virtPortTypeIDVersion = virXMLPropString(cur, "typeidversion");
            virtPortInstanceID = virXMLPropString(cur, "instanceid");
            virtPortProfileID = virXMLPropString(cur, "profileid");

            break;
        }

        cur = cur->next;
    }

    virtPort->virtPortType = VIR_VIRTUALPORT_NONE;

    switch (virVirtualPortTypeFromString(virtPortType)) {

    case VIR_VIRTUALPORT_8021QBG:
        if (virtPortManagerID     != NULL && virtPortTypeID     != NULL &&
            virtPortTypeIDVersion != NULL) {
            unsigned int val;

            if (virStrToLong_ui(virtPortManagerID, NULL, 0, &val)) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of managerid parameter"));
                goto error;
            }

            if (val > 0xff) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("value of managerid out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.managerID = (uint8_t)val;

            if (virStrToLong_ui(virtPortTypeID, NULL, 0, &val)) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of typeid parameter"));
                goto error;
            }

            if (val > 0xffffff) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("value for typeid out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.typeID = (uint32_t)val;

            if (virStrToLong_ui(virtPortTypeIDVersion, NULL, 0, &val)) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of typeidversion parameter"));
                goto error;
            }

            if (val > 0xff) {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("value of typeidversion out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.typeIDVersion = (uint8_t)val;

            if (virtPortInstanceID != NULL) {
                if (virUUIDParse(virtPortInstanceID,
                                 virtPort->u.virtPort8021Qbg.instanceID)) {
                    virSocketError(VIR_ERR_XML_ERROR, "%s",
                                         _("cannot parse instanceid parameter as a uuid"));
                    goto error;
                }
            } else {
                if (virUUIDGenerate(virtPort->u.virtPort8021Qbg.instanceID)) {
                    virSocketError(VIR_ERR_XML_ERROR, "%s",
                                         _("cannot generate a random uuid for instanceid"));
                    goto error;
                }
            }

            virtPort->virtPortType = VIR_VIRTUALPORT_8021QBG;

        } else {
                    virSocketError(VIR_ERR_XML_ERROR, "%s",
                                         _("a parameter is missing for 802.1Qbg description"));
            goto error;
        }
    break;

    case VIR_VIRTUALPORT_8021QBH:
        if (virtPortProfileID != NULL) {
            if (virStrcpyStatic(virtPort->u.virtPort8021Qbh.profileID,
                                virtPortProfileID) != NULL) {
                virtPort->virtPortType = VIR_VIRTUALPORT_8021QBH;
            } else {
                virSocketError(VIR_ERR_XML_ERROR, "%s",
                                     _("profileid parameter too long"));
                goto error;
            }
        } else {
            virSocketError(VIR_ERR_XML_ERROR, "%s",
                                 _("profileid parameter is missing for 802.1Qbh descripion"));
            goto error;
        }
    break;


    default:
    case VIR_VIRTUALPORT_NONE:
    case VIR_VIRTUALPORT_TYPE_LAST:
         virSocketError(VIR_ERR_XML_ERROR, "%s",
                              _("unknown virtualport type"));
        goto error;
    break;
    }

    ret = 0;
    *def = virtPort;
    virtPort = NULL;
error:
    VIR_FREE(virtPort);
    VIR_FREE(virtPortManagerID);
    VIR_FREE(virtPortTypeID);
    VIR_FREE(virtPortTypeIDVersion);
    VIR_FREE(virtPortInstanceID);
    VIR_FREE(virtPortProfileID);
    VIR_FREE(virtPortType);

    return ret;
}

bool
virVirtualPortProfileEqual(virVirtualPortProfileParamsPtr a, virVirtualPortProfileParamsPtr b)
{
    /* NULL resistant */
    if (!a && !b)
        return true;

    if (!a || !b)
        return false;

    if (a->virtPortType != b->virtPortType)
        return false;

    switch (a->virtPortType) {
    case VIR_VIRTUALPORT_NONE:
        break;

    case VIR_VIRTUALPORT_8021QBG:
        if (a->u.virtPort8021Qbg.managerID != b->u.virtPort8021Qbg.managerID ||
            a->u.virtPort8021Qbg.typeID != b->u.virtPort8021Qbg.typeID ||
            a->u.virtPort8021Qbg.typeIDVersion != b->u.virtPort8021Qbg.typeIDVersion ||
            memcmp(a->u.virtPort8021Qbg.instanceID, b->u.virtPort8021Qbg.instanceID, VIR_UUID_BUFLEN) != 0)
            return false;
        break;

    case VIR_VIRTUALPORT_8021QBH:
        if (STRNEQ(a->u.virtPort8021Qbh.profileID, b->u.virtPort8021Qbh.profileID))
            return false;
        break;

    default:
        break;
    }

    return true;
}

void
virVirtualPortProfileFormat(virBufferPtr buf,
                            virVirtualPortProfileParamsPtr virtPort)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!virtPort || virtPort->virtPortType == VIR_VIRTUALPORT_NONE)
        return;

    virBufferAsprintf(buf, "<virtualport type='%s'>\n",
                      virVirtualPortTypeToString(virtPort->virtPortType));

    switch (virtPort->virtPortType) {
    case VIR_VIRTUALPORT_NONE:
    case VIR_VIRTUALPORT_TYPE_LAST:
        break;

    case VIR_VIRTUALPORT_8021QBG:
        virUUIDFormat(virtPort->u.virtPort8021Qbg.instanceID,
                      uuidstr);
        virBufferAsprintf(buf,
                          "  <parameters managerid='%d' typeid='%d' "
                          "typeidversion='%d' instanceid='%s'/>\n",
                          virtPort->u.virtPort8021Qbg.managerID,
                          virtPort->u.virtPort8021Qbg.typeID,
                          virtPort->u.virtPort8021Qbg.typeIDVersion,
                          uuidstr);
        break;

    case VIR_VIRTUALPORT_8021QBH:
        virBufferAsprintf(buf,
                          "  <parameters profileid='%s'/>\n",
                          virtPort->u.virtPort8021Qbh.profileID);
        break;
    }

    virBufferAddLit(buf, "</virtualport>\n");
}

static int
virNetDevBandwidthParseRate(xmlNodePtr node, virNetDevBandwidthRatePtr rate)
{
    int ret = -1;
    char *average = NULL;
    char *peak = NULL;
    char *burst = NULL;

    if (!node || !rate) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        return -1;
    }

    average = virXMLPropString(node, "average");
    peak = virXMLPropString(node, "peak");
    burst = virXMLPropString(node, "burst");

    if (average) {
        if (virStrToLong_ull(average, NULL, 10, &rate->average) < 0) {
            virSocketError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("could not convert %s"),
                           average);
            goto cleanup;
        }
    } else {
        virSocketError(VIR_ERR_XML_DETAIL, "%s",
                       _("Missing mandatory average attribute"));
        goto cleanup;
    }

    if (peak && virStrToLong_ull(peak, NULL, 10, &rate->peak) < 0) {
        virSocketError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert %s"),
                       peak);
        goto cleanup;
    }

    if (burst && virStrToLong_ull(burst, NULL, 10, &rate->burst) < 0) {
        virSocketError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert %s"),
                       burst);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(average);
    VIR_FREE(peak);
    VIR_FREE(burst);

    return ret;
}

/**
 * virNetDevBandwidthParse:
 * @node: XML node
 *
 * Parse bandwidth XML and return pointer to structure
 *
 * Returns !NULL on success, NULL on error.
 */
virNetDevBandwidthPtr
virNetDevBandwidthParse(xmlNodePtr node)
{
    virNetDevBandwidthPtr def = NULL;
    xmlNodePtr cur = node->children;
    xmlNodePtr in = NULL, out = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (!node || !xmlStrEqual(node->name, BAD_CAST "bandwidth")) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        goto error;
    }

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "inbound")) {
                if (in) {
                    virSocketError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <inbound> "
                                     "element allowed"));
                    goto error;
                }
                in = cur;
            } else if (xmlStrEqual(cur->name, BAD_CAST "outbound")) {
                if (out) {
                    virSocketError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <outbound> "
                                     "element allowed"));
                    goto error;
                }
                out = cur;
            }
            /* Silently ignore unknown elements */
        }
        cur = cur->next;
    }

    if (in) {
        if (VIR_ALLOC(def->in) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virNetDevBandwidthParseRate(in, def->in) < 0) {
            /* helper reported error for us */
            goto error;
        }
    }

    if (out) {
        if (VIR_ALLOC(def->out) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virNetDevBandwidthParseRate(out, def->out) < 0) {
            /* helper reported error for us */
            goto error;
        }
    }

    return def;

error:
    virNetDevBandwidthFree(def);
    return NULL;
}

void
virNetDevBandwidthFree(virNetDevBandwidthPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->in);
    VIR_FREE(def->out);
    VIR_FREE(def);
}

static int
virNetDevBandwidthRateFormat(virNetDevBandwidthRatePtr def,
                             virBufferPtr buf,
                             const char *elem_name)
{
    if (!buf || !elem_name)
        return -1;
    if (!def)
        return 0;

    if (def->average) {
        virBufferAsprintf(buf, "  <%s average='%llu'", elem_name,
                          def->average);

        if (def->peak)
            virBufferAsprintf(buf, " peak='%llu'", def->peak);

        if (def->burst)
            virBufferAsprintf(buf, " burst='%llu'", def->burst);
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

/**
 * virNetDevBandwidthDefFormat:
 * @def: Data source
 * @buf: Buffer to print to
 *
 * Formats bandwidth and prepend each line with @indent.
 * @buf may use auto-indentation.
 *
 * Returns 0 on success, else -1.
 */
int
virNetDevBandwidthFormat(virNetDevBandwidthPtr def, virBufferPtr buf)
{
    int ret = -1;

    if (!buf)
        goto cleanup;

    if (!def) {
        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(buf, "<bandwidth>\n");
    if (virNetDevBandwidthRateFormat(def->in, buf, "inbound") < 0 ||
        virNetDevBandwidthRateFormat(def->out, buf, "outbound") < 0)
        goto cleanup;
    virBufferAddLit(buf, "</bandwidth>\n");

    ret = 0;

cleanup:
    return ret;
}

/**
 * virNetDevBandwidthSet:
 * @ifname: on which interface
 * @bandwidth: rates to set (may be NULL)
 *
 * This function enables QoS on specified interface
 * and set given traffic limits for both, incoming
 * and outgoing traffic. Any previous setting get
 * overwritten.
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthSet(const char *ifname,
                      virNetDevBandwidthPtr bandwidth)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *average = NULL;
    char *peak = NULL;
    char *burst = NULL;

    if (!bandwidth) {
        /* nothing to be enabled */
        ret = 0;
        goto cleanup;
    }

    ignore_value(virNetDevBandwidthClear(ifname));

    if (bandwidth->in) {
        if (virAsprintf(&average, "%llukbps", bandwidth->in->average) < 0)
            goto cleanup;
        if (bandwidth->in->peak &&
            (virAsprintf(&peak, "%llukbps", bandwidth->in->peak) < 0))
            goto cleanup;
        if (bandwidth->in->burst &&
            (virAsprintf(&burst, "%llukb", bandwidth->in->burst) < 0))
            goto cleanup;

        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "qdisc", "add", "dev", ifname, "root",
                             "handle", "1:", "htb", "default", "1", NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
            virCommandAddArgList(cmd,"class", "add", "dev", ifname, "parent",
                                 "1:", "classid", "1:1", "htb", NULL);
        virCommandAddArgList(cmd, "rate", average, NULL);

        if (peak)
            virCommandAddArgList(cmd, "ceil", peak, NULL);
        if (burst)
            virCommandAddArgList(cmd, "burst", burst, NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
            virCommandAddArgList(cmd,"filter", "add", "dev", ifname, "parent",
                                 "1:0", "protocol", "ip", "handle", "1", "fw",
                                 "flowid", "1", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        VIR_FREE(average);
        VIR_FREE(peak);
        VIR_FREE(burst);
    }

    if (bandwidth->out) {
        if (virAsprintf(&average, "%llukbps", bandwidth->out->average) < 0)
            goto cleanup;
        if (virAsprintf(&burst, "%llukb", bandwidth->out->burst ?
                        bandwidth->out->burst : bandwidth->out->average) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
            virCommandAddArgList(cmd, "qdisc", "add", "dev", ifname,
                                 "ingress", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = virCommandNew(TC);
        virCommandAddArgList(cmd, "filter", "add", "dev", ifname, "parent",
                             "ffff:", "protocol", "ip", "u32", "match", "ip",
                             "src", "0.0.0.0/0", "police", "rate", average,
                             "burst", burst, "mtu", burst, "drop", "flowid",
                             ":1", NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(average);
    VIR_FREE(peak);
    VIR_FREE(burst);
    return ret;
}

/**
 * virNetDevBandwidthClear:
 * @ifname: on which interface
 *
 * This function tries to disable QoS on specified interface
 * by deleting root and ingress qdisc. However, this may fail
 * if we try to remove the default one.
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevBandwidthClear(const char *ifname)
{
    int ret = 0;
    virCommandPtr cmd = NULL;

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc", "del", "dev", ifname, "root", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);

    cmd = virCommandNew(TC);
    virCommandAddArgList(cmd, "qdisc",  "del", "dev", ifname, "ingress", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    virCommandFree(cmd);

    return ret;
}

/*
 * virNetDevBandwidthCopy:
 * @dest: destination
 * @src:  source (may be NULL)
 *
 * Returns -1 on OOM error (which gets reported),
 * 0 otherwise.
 */
int
virNetDevBandwidthCopy(virNetDevBandwidthPtr *dest,
                       const virNetDevBandwidthPtr src)
{
    int ret = -1;

    *dest = NULL;
    if (!src) {
        /* nothing to be copied */
        return 0;
    }

    if (VIR_ALLOC(*dest) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (src->in) {
        if (VIR_ALLOC((*dest)->in) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        memcpy((*dest)->in, src->in, sizeof(*src->in));
    }

    if (src->out) {
        if (VIR_ALLOC((*dest)->out) < 0) {
            virReportOOMError();
            VIR_FREE((*dest)->in);
            goto cleanup;
        }
        memcpy((*dest)->out, src->out, sizeof(*src->out));
    }

    ret = 0;

cleanup:
    if (ret < 0) {
        virNetDevBandwidthFree(*dest);
        *dest = NULL;
    }
    return ret;
}

bool
virNetDevBandwidthEqual(virNetDevBandwidthPtr a,
                        virNetDevBandwidthPtr b)
{
        if (!a && !b)
            return true;

        if (!a || !b)
            return false;

        /* in */
        if (a->in->average != b->in->average ||
            a->in->peak != b->in->peak ||
            a->in->burst != b->in->burst)
            return false;

        /*out*/
        if (a->out->average != b->out->average ||
            a->out->peak != b->out->peak ||
            a->out->burst != b->out->burst)
            return false;

        return true;
}
