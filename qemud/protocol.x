/* -*- c -*-
 * protocol_xdr.x: wire protocol message format & data structures
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

const QEMUD_UUID_RAW_LEN = 16;
const QEMUD_MAX_NAME_LEN = 50;
const QEMUD_MAX_XML_LEN = 4096;
/*#define QEMUD_MAX_IFNAME_LEN IF_NAMESIZE */
const QEMUD_MAX_IFNAME_LEN = 50;

const QEMUD_MAX_NUM_DOMAINS = 100;
const QEMUD_MAX_NUM_NETWORKS = 100;

/*
 * Damn, we can't do multiplcation when declaring
 * constants with XDR !
 * These two should be  QEMUD_MAX_NUM_DOMAIN * QEMUD_MAX_NAME_LEN
 */
const QEMUD_MAX_DOMAINS_NAME_BUF = 5000;
const QEMUD_MAX_NETWORKS_NAME_BUF = 5000;

const QEMUD_MAX_ERROR_LEN = 1024;

/* Possible guest VM states */
enum qemud_domain_runstate {
    QEMUD_STATE_RUNNING = 1,
    QEMUD_STATE_PAUSED,
    QEMUD_STATE_STOPPED
};

/* Message sent by a client */
enum qemud_packet_client_data_type {
    QEMUD_CLIENT_PKT_GET_VERSION,
    QEMUD_CLIENT_PKT_GET_NODEINFO,
    QEMUD_CLIENT_PKT_LIST_DOMAINS,
    QEMUD_CLIENT_PKT_NUM_DOMAINS,
    QEMUD_CLIENT_PKT_DOMAIN_CREATE,
    QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_ID,
    QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_UUID,
    QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_NAME,
    QEMUD_CLIENT_PKT_DOMAIN_SUSPEND,
    QEMUD_CLIENT_PKT_DOMAIN_RESUME,
    QEMUD_CLIENT_PKT_DOMAIN_DESTROY,
    QEMUD_CLIENT_PKT_DOMAIN_GET_INFO,
    QEMUD_CLIENT_PKT_DOMAIN_SAVE,
    QEMUD_CLIENT_PKT_DOMAIN_RESTORE,
    QEMUD_CLIENT_PKT_DUMP_XML,
    QEMUD_CLIENT_PKT_LIST_DEFINED_DOMAINS,
    QEMUD_CLIENT_PKT_NUM_DEFINED_DOMAINS,
    QEMUD_CLIENT_PKT_DOMAIN_START,
    QEMUD_CLIENT_PKT_DOMAIN_DEFINE,
    QEMUD_CLIENT_PKT_DOMAIN_UNDEFINE,
    QEMUD_CLIENT_PKT_NUM_NETWORKS,
    QEMUD_CLIENT_PKT_LIST_NETWORKS,
    QEMUD_CLIENT_PKT_NUM_DEFINED_NETWORKS,
    QEMUD_CLIENT_PKT_LIST_DEFINED_NETWORKS,
    QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_UUID,
    QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_NAME,
    QEMUD_CLIENT_PKT_NETWORK_CREATE,
    QEMUD_CLIENT_PKT_NETWORK_DEFINE,
    QEMUD_CLIENT_PKT_NETWORK_UNDEFINE,
    QEMUD_CLIENT_PKT_NETWORK_START,
    QEMUD_CLIENT_PKT_NETWORK_DESTROY,
    QEMUD_CLIENT_PKT_NETWORK_DUMP_XML,
    QEMUD_CLIENT_PKT_NETWORK_GET_BRIDGE_NAME,
    QEMUD_CLIENT_PKT_DOMAIN_GET_AUTOSTART,
    QEMUD_CLIENT_PKT_DOMAIN_SET_AUTOSTART,
    QEMUD_CLIENT_PKT_NETWORK_GET_AUTOSTART,
    QEMUD_CLIENT_PKT_NETWORK_SET_AUTOSTART,
    QEMUD_CLIENT_PKT_GET_CAPABILITIES,

    QEMUD_CLIENT_PKT_MAX
};

/* Messages sent by a server */
enum qemud_packet_server_data_type {
    QEMUD_SERVER_PKT_FAILURE = 0,
    QEMUD_SERVER_PKT_GET_VERSION,
    QEMUD_SERVER_PKT_GET_NODEINFO,
    QEMUD_SERVER_PKT_LIST_DOMAINS,
    QEMUD_SERVER_PKT_NUM_DOMAINS,
    QEMUD_SERVER_PKT_DOMAIN_CREATE,
    QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_ID,
    QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_UUID,
    QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_NAME,
    QEMUD_SERVER_PKT_DOMAIN_SUSPEND,
    QEMUD_SERVER_PKT_DOMAIN_RESUME,
    QEMUD_SERVER_PKT_DOMAIN_DESTROY,
    QEMUD_SERVER_PKT_DOMAIN_GET_INFO,
    QEMUD_SERVER_PKT_DOMAIN_SAVE,
    QEMUD_SERVER_PKT_DOMAIN_RESTORE,
    QEMUD_SERVER_PKT_DUMP_XML,
    QEMUD_SERVER_PKT_LIST_DEFINED_DOMAINS,
    QEMUD_SERVER_PKT_NUM_DEFINED_DOMAINS,
    QEMUD_SERVER_PKT_DOMAIN_START,
    QEMUD_SERVER_PKT_DOMAIN_DEFINE,
    QEMUD_SERVER_PKT_DOMAIN_UNDEFINE,
    QEMUD_SERVER_PKT_NUM_NETWORKS,
    QEMUD_SERVER_PKT_LIST_NETWORKS,
    QEMUD_SERVER_PKT_NUM_DEFINED_NETWORKS,
    QEMUD_SERVER_PKT_LIST_DEFINED_NETWORKS,
    QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_UUID,
    QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_NAME,
    QEMUD_SERVER_PKT_NETWORK_CREATE,
    QEMUD_SERVER_PKT_NETWORK_DEFINE,
    QEMUD_SERVER_PKT_NETWORK_UNDEFINE,
    QEMUD_SERVER_PKT_NETWORK_START,
    QEMUD_SERVER_PKT_NETWORK_DESTROY,
    QEMUD_SERVER_PKT_NETWORK_DUMP_XML,
    QEMUD_SERVER_PKT_NETWORK_GET_BRIDGE_NAME,
    QEMUD_SERVER_PKT_DOMAIN_GET_AUTOSTART,
    QEMUD_SERVER_PKT_DOMAIN_SET_AUTOSTART,
    QEMUD_SERVER_PKT_NETWORK_GET_AUTOSTART,
    QEMUD_SERVER_PKT_NETWORK_SET_AUTOSTART,
    QEMUD_SERVER_PKT_GET_CAPABILITIES,

    QEMUD_SERVER_PKT_MAX
};



struct qemud_packet_failure_reply {
  uint32_t code;
  char message[QEMUD_MAX_ERROR_LEN];
};

struct qemud_packet_get_version_reply {
  uint32_t versionNum;
};

struct qemud_packet_get_node_info_reply {
  char model[32];
  uint32_t memory;
  uint32_t cpus;
  uint32_t mhz;
  uint32_t nodes;
  uint32_t sockets;
  uint32_t cores;
  uint32_t threads;
};

struct qemud_packet_get_capabilities_reply {
  char xml[QEMUD_MAX_XML_LEN];
};

struct qemud_packet_list_domains_reply {
  int32_t numDomains;
  int32_t domains[QEMUD_MAX_NUM_DOMAINS];
};

struct qemud_packet_num_domains_reply{
  int32_t numDomains;
};

struct qemud_packet_domain_create_request {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_domain_create_reply {
  int32_t id;
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_domain_lookup_by_id_request {
  int32_t id;
};

struct qemud_packet_domain_lookup_by_id_reply {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  char name[QEMUD_MAX_NAME_LEN];
};

struct qemud_packet_domain_lookup_by_name_request {
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_domain_lookup_by_name_reply {
  int32_t id;
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_domain_lookup_by_uuid_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};

struct qemud_packet_domain_lookup_by_uuid_reply {
  int32_t id;
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_domain_suspend_request {
  int32_t id;
};
struct qemud_packet_domain_resume_request {
  int32_t id;
};
struct qemud_packet_domain_destroy_request {
  int32_t id;
};
struct qemud_packet_domain_get_info_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_domain_get_info_reply {
  uint64_t cpuTime;
  uint32_t runstate;
  uint32_t memory;
  uint32_t maxmem;
  uint32_t nrVirtCpu;
};
struct qemud_packet_domain_save_request {
  int32_t id;
  char file[PATH_MAX];
};
struct qemud_packet_domain_restore_request {
  char file[PATH_MAX];
};
struct qemud_packet_domain_restore_reply {
  int32_t id;
};
struct qemud_packet_domain_dump_xml_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_domain_dump_xml_reply {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_list_defined_domains_reply{
  uint32_t numDomains;
  char domains[QEMUD_MAX_DOMAINS_NAME_BUF];
};
struct qemud_packet_num_defined_domains_reply{
  uint32_t numDomains;
};
struct qemud_packet_domain_start_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_domain_start_reply {
  int32_t id;
};
struct qemud_packet_domain_define_request {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_domain_define_reply {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_domain_undefine_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_num_networks_reply {
  uint32_t numNetworks;
};

struct qemud_packet_list_networks_reply {
  uint32_t numNetworks;
  char networks[QEMUD_MAX_NETWORKS_NAME_BUF];
};

struct qemud_packet_num_defined_networks_reply {
  uint32_t numNetworks;
};

struct qemud_packet_list_defined_networks_reply {
  uint32_t numNetworks;
  char networks[QEMUD_MAX_NETWORKS_NAME_BUF];
};
struct qemud_packet_network_lookup_by_name_request {
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_network_lookup_by_name_reply {
  int32_t id;
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_lookup_by_uuid_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_lookup_by_uuid_reply {
  int32_t id;
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_network_create_request {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_network_create_reply {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_network_define_request {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_network_define_reply {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  char name[QEMUD_MAX_NAME_LEN];
};
struct qemud_packet_network_undefine_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_start_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_destroy_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_dump_xml_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_dump_xml_reply {
  char xml[QEMUD_MAX_XML_LEN];
};
struct qemud_packet_network_get_bridge_name_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_get_bridge_name_reply {
  char ifname[QEMUD_MAX_IFNAME_LEN];
};
struct qemud_packet_domain_get_autostart_request{
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_domain_get_autostart_reply {
  uint32_t autostart;
};
struct qemud_packet_domain_set_autostart_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  uint32_t autostart;
};

struct qemud_packet_network_get_autostart_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
};
struct qemud_packet_network_get_autostart_reply {
  uint32_t autostart;
};
struct qemud_packet_network_set_autostart_request {
  unsigned char uuid[QEMUD_UUID_RAW_LEN];
  uint32_t autostart;
};

union qemud_packet_client_data switch (qemud_packet_client_data_type type) {
    case QEMUD_CLIENT_PKT_GET_VERSION:
      void;

    case QEMUD_CLIENT_PKT_GET_NODEINFO:
      void;

    case QEMUD_CLIENT_PKT_LIST_DOMAINS:
      void;

    case QEMUD_CLIENT_PKT_NUM_DOMAINS:
      void;

    case QEMUD_CLIENT_PKT_DOMAIN_CREATE:
      qemud_packet_domain_create_request domainCreateRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_ID:
      qemud_packet_domain_lookup_by_id_request domainLookupByIDRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_UUID:
      qemud_packet_domain_lookup_by_uuid_request domainLookupByUUIDRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_NAME:
      qemud_packet_domain_lookup_by_name_request domainLookupByNameRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_SUSPEND:
      qemud_packet_domain_suspend_request domainSuspendRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_RESUME:
      qemud_packet_domain_resume_request domainResumeRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_DESTROY:
      qemud_packet_domain_destroy_request domainDestroyRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_GET_INFO:
      qemud_packet_domain_get_info_request domainGetInfoRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_SAVE:
      qemud_packet_domain_save_request domainSaveRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_RESTORE:
      qemud_packet_domain_restore_request domainRestoreRequest;

    case QEMUD_CLIENT_PKT_DUMP_XML:
      qemud_packet_domain_dump_xml_request domainDumpXMLRequest;

    case QEMUD_CLIENT_PKT_LIST_DEFINED_DOMAINS:
      void;

    case QEMUD_CLIENT_PKT_NUM_DEFINED_DOMAINS:
      void;

    case QEMUD_CLIENT_PKT_DOMAIN_START:
      qemud_packet_domain_start_request domainStartRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_DEFINE:
      qemud_packet_domain_define_request domainDefineRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_UNDEFINE:
      qemud_packet_domain_undefine_request domainUndefineRequest;

    case QEMUD_CLIENT_PKT_NUM_NETWORKS:
      void;

    case QEMUD_CLIENT_PKT_LIST_NETWORKS:
      void;

    case QEMUD_CLIENT_PKT_NUM_DEFINED_NETWORKS:
      void;

    case QEMUD_CLIENT_PKT_LIST_DEFINED_NETWORKS:
      void;

    case QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_UUID:
      qemud_packet_network_lookup_by_uuid_request networkLookupByUUIDRequest;

    case QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_NAME:
      qemud_packet_network_lookup_by_name_request networkLookupByNameRequest;

    case QEMUD_CLIENT_PKT_NETWORK_CREATE:
      qemud_packet_network_create_request networkCreateRequest;

    case QEMUD_CLIENT_PKT_NETWORK_DEFINE:
      qemud_packet_network_define_request networkDefineRequest;

    case QEMUD_CLIENT_PKT_NETWORK_UNDEFINE:
      qemud_packet_network_undefine_request networkUndefineRequest;

    case QEMUD_CLIENT_PKT_NETWORK_START:
      qemud_packet_network_start_request networkStartRequest;

    case QEMUD_CLIENT_PKT_NETWORK_DESTROY:
      qemud_packet_network_destroy_request networkDestroyRequest;

    case QEMUD_CLIENT_PKT_NETWORK_DUMP_XML:
      qemud_packet_network_dump_xml_request networkDumpXMLRequest;

    case QEMUD_CLIENT_PKT_NETWORK_GET_BRIDGE_NAME:
      qemud_packet_network_get_bridge_name_request networkGetBridgeNameRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_GET_AUTOSTART:
      qemud_packet_domain_get_autostart_request domainGetAutostartRequest;

    case QEMUD_CLIENT_PKT_DOMAIN_SET_AUTOSTART:
      qemud_packet_domain_set_autostart_request domainSetAutostartRequest;

    case QEMUD_CLIENT_PKT_NETWORK_GET_AUTOSTART:
      qemud_packet_network_get_autostart_request networkGetAutostartRequest;

    case QEMUD_CLIENT_PKT_NETWORK_SET_AUTOSTART:
      qemud_packet_network_set_autostart_request networkSetAutostartRequest;

    case QEMUD_CLIENT_PKT_GET_CAPABILITIES:
      void;

};

union qemud_packet_server_data switch (qemud_packet_server_data_type type) {
    case QEMUD_SERVER_PKT_FAILURE:
      qemud_packet_failure_reply failureReply;

    case QEMUD_SERVER_PKT_GET_VERSION:
      qemud_packet_get_version_reply getVersionReply;

    case QEMUD_SERVER_PKT_GET_NODEINFO:
      qemud_packet_get_node_info_reply getNodeInfoReply;

    case QEMUD_SERVER_PKT_LIST_DOMAINS:
      qemud_packet_list_domains_reply listDomainsReply;

    case QEMUD_SERVER_PKT_NUM_DOMAINS:
      qemud_packet_num_domains_reply numDomainsReply;

    case QEMUD_SERVER_PKT_DOMAIN_CREATE:
      qemud_packet_domain_create_reply domainCreateReply;

    case QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_ID:
      qemud_packet_domain_lookup_by_id_reply domainLookupByIDReply;

    case QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_UUID:
      qemud_packet_domain_lookup_by_uuid_reply domainLookupByUUIDReply;

    case QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_NAME:
      qemud_packet_domain_lookup_by_name_reply domainLookupByNameReply;

    case QEMUD_SERVER_PKT_DOMAIN_SUSPEND:
      void;

    case QEMUD_SERVER_PKT_DOMAIN_RESUME:
      void;

    case QEMUD_SERVER_PKT_DOMAIN_DESTROY:
      void;

    case QEMUD_SERVER_PKT_DOMAIN_GET_INFO:
      qemud_packet_domain_get_info_reply domainGetInfoReply;

    case QEMUD_SERVER_PKT_DOMAIN_SAVE:
      void;

    case QEMUD_SERVER_PKT_DOMAIN_RESTORE:
      qemud_packet_domain_restore_reply domainRestoreReply;

    case QEMUD_SERVER_PKT_DUMP_XML:
      qemud_packet_domain_dump_xml_reply domainDumpXMLReply;

    case QEMUD_SERVER_PKT_LIST_DEFINED_DOMAINS:
      qemud_packet_list_defined_domains_reply listDefinedDomainsReply;

    case QEMUD_SERVER_PKT_NUM_DEFINED_DOMAINS:
      qemud_packet_num_defined_domains_reply numDefinedDomainsReply;

    case QEMUD_SERVER_PKT_DOMAIN_START:
      qemud_packet_domain_start_reply domainStartReply;

    case QEMUD_SERVER_PKT_DOMAIN_DEFINE:
      qemud_packet_domain_define_reply domainDefineReply;

    case QEMUD_SERVER_PKT_DOMAIN_UNDEFINE:
      void;

    case QEMUD_SERVER_PKT_NUM_NETWORKS:
      qemud_packet_num_networks_reply numNetworksReply;

    case QEMUD_SERVER_PKT_LIST_NETWORKS:
      qemud_packet_list_networks_reply listNetworksReply;

    case QEMUD_SERVER_PKT_NUM_DEFINED_NETWORKS:
      qemud_packet_num_defined_networks_reply numDefinedNetworksReply;

    case QEMUD_SERVER_PKT_LIST_DEFINED_NETWORKS:
      qemud_packet_list_defined_networks_reply listDefinedNetworksReply;

    case QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_UUID:
      qemud_packet_network_lookup_by_uuid_reply networkLookupByUUIDReply;

    case QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_NAME:
      qemud_packet_network_lookup_by_name_reply networkLookupByNameReply;

    case QEMUD_SERVER_PKT_NETWORK_CREATE:
      qemud_packet_network_create_reply networkCreateReply;

    case QEMUD_SERVER_PKT_NETWORK_DEFINE:
      qemud_packet_network_define_reply networkDefineReply;

    case QEMUD_SERVER_PKT_NETWORK_UNDEFINE:
      void;

    case QEMUD_SERVER_PKT_NETWORK_START:
      void;

    case QEMUD_SERVER_PKT_NETWORK_DESTROY:
      void;

    case QEMUD_SERVER_PKT_NETWORK_DUMP_XML:
      qemud_packet_network_dump_xml_reply networkDumpXMLReply;

    case QEMUD_SERVER_PKT_NETWORK_GET_BRIDGE_NAME:
      qemud_packet_network_get_bridge_name_reply networkGetBridgeNameReply;

    case QEMUD_SERVER_PKT_DOMAIN_GET_AUTOSTART:
      qemud_packet_domain_get_autostart_reply domainGetAutostartReply;

    case QEMUD_SERVER_PKT_DOMAIN_SET_AUTOSTART:
      void;

    case QEMUD_SERVER_PKT_NETWORK_GET_AUTOSTART:
      qemud_packet_network_get_autostart_reply networkGetAutostartReply;

    case QEMUD_SERVER_PKT_NETWORK_SET_AUTOSTART:
      void;

    case QEMUD_SERVER_PKT_GET_CAPABILITIES:
      qemud_packet_get_capabilities_reply getCapabilitiesReply;
};

struct qemud_packet_client {
  uint32_t serial;
  struct qemud_packet_client_data data;
};

struct qemud_packet_server {
  uint32_t serial;
  uint32_t inReplyTo;
  struct qemud_packet_server_data data;
};

/* The first two words in the messages are length and program number
 * (previously called "magic").  This makes the protocol compatible
 * with the remote protocol, although beyond the first two words
 * the protocols are completely different.
 *
 * Note the length is the total number of bytes in the message
 * _including_ the length and program number.
 */

const QEMUD_PROGRAM = 0x20001A64;
const QEMUD_PKT_HEADER_XDR_LEN = 8;

struct qemud_packet_header {
  uint32_t length;
  uint32_t prog;
};
