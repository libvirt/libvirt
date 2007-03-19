/*
 * protocol.h: wire protocol message format & data structures
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef QEMUD_PROTOCOL_H__
#define QEMUD_PROTOCOL_H__

#include <stdint.h>
#include <net/if.h> /* for IF_NAMESIZE */

/* List of different packet types which can be sent */
enum qemud_packet_type {
    QEMUD_PKT_FAILURE = 0,
    QEMUD_PKT_GET_VERSION,
    QEMUD_PKT_GET_NODEINFO,
    QEMUD_PKT_LIST_DOMAINS,
    QEMUD_PKT_NUM_DOMAINS,
    QEMUD_PKT_DOMAIN_CREATE,
    QEMUD_PKT_DOMAIN_LOOKUP_BY_ID,
    QEMUD_PKT_DOMAIN_LOOKUP_BY_UUID,
    QEMUD_PKT_DOMAIN_LOOKUP_BY_NAME,
    QEMUD_PKT_DOMAIN_SUSPEND,
    QEMUD_PKT_DOMAIN_RESUME,
    QEMUD_PKT_DOMAIN_DESTROY,
    QEMUD_PKT_DOMAIN_GET_INFO,
    QEMUD_PKT_DOMAIN_SAVE,
    QEMUD_PKT_DOMAIN_RESTORE,
    QEMUD_PKT_DUMP_XML,
    QEMUD_PKT_LIST_DEFINED_DOMAINS,
    QEMUD_PKT_NUM_DEFINED_DOMAINS,
    QEMUD_PKT_DOMAIN_START,
    QEMUD_PKT_DOMAIN_DEFINE,
    QEMUD_PKT_DOMAIN_UNDEFINE,
    QEMUD_PKT_NUM_NETWORKS,
    QEMUD_PKT_LIST_NETWORKS,
    QEMUD_PKT_NUM_DEFINED_NETWORKS,
    QEMUD_PKT_LIST_DEFINED_NETWORKS,
    QEMUD_PKT_NETWORK_LOOKUP_BY_UUID,
    QEMUD_PKT_NETWORK_LOOKUP_BY_NAME,
    QEMUD_PKT_NETWORK_CREATE,
    QEMUD_PKT_NETWORK_DEFINE,
    QEMUD_PKT_NETWORK_UNDEFINE,
    QEMUD_PKT_NETWORK_START,
    QEMUD_PKT_NETWORK_DESTROY,
    QEMUD_PKT_NETWORK_DUMP_XML,
    QEMUD_PKT_NETWORK_GET_BRIDGE_NAME,
    QEMUD_PKT_DOMAIN_GET_AUTOSTART,
    QEMUD_PKT_DOMAIN_SET_AUTOSTART,
    QEMUD_PKT_NETWORK_GET_AUTOSTART,
    QEMUD_PKT_NETWORK_SET_AUTOSTART,
    QEMUD_PKT_GET_CAPABILITIES,

    QEMUD_PKT_MAX,
};


#define QEMUD_PROTOCOL_VERSION_MAJOR 1
#define QEMUD_PROTOCOL_VERSION_MINOR 0

#define QEMUD_UUID_RAW_LEN 16
#define QEMUD_MAX_NAME_LEN 50
#define QEMUD_MAX_XML_LEN 4096
#define QEMUD_MAX_IFNAME_LEN IF_NAMESIZE
#define QEMUD_MAX_NUM_DOMAINS 100
#define QEMUD_MAX_NUM_NETWORKS 100
#define QEMUD_MAX_ERROR_LEN 1024

/* Possible guest VM states */
enum qemud_domain_runstate {
    QEMUD_STATE_RUNNING = 1,
    QEMUD_STATE_PAUSED,
    QEMUD_STATE_STOPPED,
};

/* Each packets has at least a fixed size header.
 *
 * All data required to be network byte order
 * to 32-bit boundaries */
struct qemud_packet_header {
    uint32_t type;
    /* Stores the size of the data struct matching
       the type arg.
       Must be <= sizeof(union qemudPacketData) */
    uint32_t dataSize;
};

/* Most packets also have some message specific data
 * All data required to be network byte order, padded
 * to 32-bit boundaries */
union qemud_packet_data {
    struct {
        int32_t code;
        char message[QEMUD_MAX_ERROR_LEN];
    } failureReply;
    struct {
        int32_t version;
    } getVersionReply;
    struct {
        char model[32];
        uint32_t memory;
        uint32_t cpus;
        uint32_t mhz;
        uint32_t nodes;
        uint32_t sockets;
        uint32_t cores;
        uint32_t threads;
    } getNodeInfoReply;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } getCapabilitiesReply;
    struct {
        int32_t numDomains;
        int32_t domains[QEMUD_MAX_NUM_DOMAINS];
    } listDomainsReply;
    struct {
        int32_t numDomains;
    } numDomainsReply;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } domainCreateRequest;
    struct {
        int32_t id;
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        char name[QEMUD_MAX_NAME_LEN];
    } domainCreateReply;
    struct {
        int32_t id;
    } domainLookupByIDRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        char name[QEMUD_MAX_NAME_LEN];
    } domainLookupByIDReply;
    struct {
        char name[QEMUD_MAX_NAME_LEN];
    } domainLookupByNameRequest;
    struct {
        int32_t id;
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainLookupByNameReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainLookupByUUIDRequest;
    struct {
        int32_t id;
        char name[QEMUD_MAX_NAME_LEN];
    } domainLookupByUUIDReply;
    struct {
        int32_t id;
    } domainSuspendRequest;
    struct {
        int32_t id;
    } domainResumeRequest;
    struct {
    } domainResumeReply;
    struct {
        int32_t id;
    } domainDestroyRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainGetInfoRequest;
    struct {
        uint64_t cpuTime;
        int32_t runstate;
        uint32_t memory;
        uint32_t maxmem;
        uint32_t nrVirtCpu;
    } domainGetInfoReply;
    struct {
        int32_t id;
        char file[PATH_MAX];
    } domainSaveRequest;
    struct {
        char file[PATH_MAX];
    } domainRestoreRequest;
    struct {
        int32_t id;
    } domainRestoreReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainDumpXMLRequest;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } domainDumpXMLReply;
    struct {
        int32_t numDomains;
        char domains[QEMUD_MAX_NUM_DOMAINS][QEMUD_MAX_NAME_LEN];
    } listDefinedDomainsReply;
    struct {
        int32_t numDomains;
    } numDefinedDomainsReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainStartRequest;
    struct {
        int32_t id;
    } domainStartReply;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } domainDefineRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        char name[QEMUD_MAX_NAME_LEN];
    } domainDefineReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainUndefineRequest;
    struct {
        int32_t numNetworks;
    } numNetworksReply;
    struct {
        int32_t numNetworks;
        char networks[QEMUD_MAX_NUM_NETWORKS][QEMUD_MAX_NAME_LEN];
    } listNetworksReply;
    struct {
        int32_t numNetworks;
    } numDefinedNetworksReply;
    struct {
        int32_t numNetworks;
        char networks[QEMUD_MAX_NUM_NETWORKS][QEMUD_MAX_NAME_LEN];
    } listDefinedNetworksReply;
    struct {
        char name[QEMUD_MAX_NAME_LEN];
    } networkLookupByNameRequest;
    struct {
        int32_t id;
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkLookupByNameReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkLookupByUUIDRequest;
    struct {
        int32_t id;
        char name[QEMUD_MAX_NAME_LEN];
    } networkLookupByUUIDReply;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } networkCreateRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        char name[QEMUD_MAX_NAME_LEN];
    } networkCreateReply;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } networkDefineRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        char name[QEMUD_MAX_NAME_LEN];
    } networkDefineReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkUndefineRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkStartRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkDestroyRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkDumpXMLRequest;
    struct {
        char xml[QEMUD_MAX_XML_LEN];
    } networkDumpXMLReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkGetBridgeNameRequest;
    struct {
        char ifname[QEMUD_MAX_IFNAME_LEN];
    } networkGetBridgeNameReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } domainGetAutostartRequest;
    struct {
        int autostart;
    } domainGetAutostartReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        unsigned int autostart : 1;
    } domainSetAutostartRequest;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
    } networkGetAutostartRequest;
    struct {
        unsigned int autostart : 1;
    } networkGetAutostartReply;
    struct {
        unsigned char uuid[QEMUD_UUID_RAW_LEN];
        unsigned int autostart : 1;
    } networkSetAutostartRequest;
};

/* Each packet has header & data */
struct qemud_packet {
    struct qemud_packet_header header;
    union qemud_packet_data data;
};


#endif


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
