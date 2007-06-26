/* -*- c -*-
 * remote_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2006-2007 Red Hat, Inc.
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
 * Author: Richard Jones <rjones@redhat.com>
 */

/* Notes:
 *
 * (1) The protocol is internal and may change at any time, without
 * notice.  Do not use it.  Instead link to libvirt and use the remote
 * driver.
 *
 * (2) See bottom of this file for a description of the home-brew RPC.
 *
 * (3) Authentication/encryption is done outside this protocol.
 *
 * (4) For namespace reasons, all exported names begin 'remote_' or
 * 'REMOTE_'.  This makes names quite long.
 */

%#include "libvirt/libvirt.h"

/*----- Data types. -----*/

/* Maximum total message size (serialised). */
const REMOTE_MESSAGE_MAX = 262144;

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const REMOTE_STRING_MAX = 65536;

/* A long string, which may NOT be NULL. */
typedef string remote_nonnull_string<REMOTE_STRING_MAX>;

/* A long string, which may be NULL. */
typedef remote_nonnull_string *remote_string;

/* This just places an upper limit on the length of lists of
 * domain IDs which may be sent via the protocol.
 */
const REMOTE_DOMAIN_ID_LIST_MAX = 16384;

/* Upper limit on lists of domain names. */
const REMOTE_DOMAIN_NAME_LIST_MAX = 1024;

/* Upper limit on cpumap (bytes) passed to virDomainPinVcpu. */
const REMOTE_CPUMAP_MAX = 256;

/* Upper limit on number of info fields returned by virDomainGetVcpus. */
const REMOTE_VCPUINFO_MAX = 2048;

/* Upper limit on cpumaps (bytes) passed to virDomainGetVcpus. */
const REMOTE_CPUMAPS_MAX = 16384;

/* Upper limit on lists of network names. */
const REMOTE_NETWORK_NAME_LIST_MAX = 256;

/* Upper limit on list of scheduler parameters. */
const REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX = 16;

/* UUID.  VIR_UUID_BUFLEN definition comes from libvirt.h */
typedef opaque remote_uuid[VIR_UUID_BUFLEN];

/* A domain which may not be NULL. */
struct remote_nonnull_domain {
    remote_nonnull_string name;
    remote_uuid uuid;
    int id;
};

/* A network which may not be NULL. */
struct remote_nonnull_network {
    remote_nonnull_string name;
    remote_uuid uuid;
};

/* A domain or network which may be NULL. */
typedef remote_nonnull_domain *remote_domain;
typedef remote_nonnull_network *remote_network;

/* Error message. See <virterror.h> for explanation of fields. */

/* NB. Fields "code", "domain" and "level" are really enums.  The
 * numeric value should remain compatible between libvirt and
 * libvirtd.  This means, no changing or reordering the enums as
 * defined in <virterror.h> (but we don't do that anyway, for separate
 * ABI reasons).
 */
struct remote_error {
    int code;
    int domain;
    remote_string message;
    int level;
    remote_domain dom;
    remote_string str1;
    remote_string str2;
    remote_string str3;
    int int1;
    int int2;
    remote_network net;
};

/* Wire encoding of virVcpuInfo. */
struct remote_vcpu_info {
    unsigned int number;
    int state;
    unsigned hyper cpu_time;
    int cpu;
};

/* Wire encoding of virDomainSchedParameter.
 * Note the enum (type) which must remain binary compatible.
 */
union remote_sched_param_value switch (int type) {
 case VIR_DOMAIN_SCHED_FIELD_INT:
     int i;
 case VIR_DOMAIN_SCHED_FIELD_UINT:
     unsigned int ui;
 case VIR_DOMAIN_SCHED_FIELD_LLONG:
     hyper l;
 case VIR_DOMAIN_SCHED_FIELD_ULLONG:
     unsigned hyper ul;
 case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
     double d;
 case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
     int b;
};

struct remote_sched_param {
    remote_nonnull_string field;
    remote_sched_param_value value;
};

/*----- Calls. -----*/

/* For each call we may have a 'remote_CALL_args' and 'remote_CALL_ret'
 * type.  These are omitted when they are void.  The virConnectPtr
 * is not passed at all (it is inferred on the remote server from the
 * connection).  Errors are returned implicitly in the RPC protocol.
 *
 * Please follow the naming convention carefully - this file is
 * parsed by 'remote_generate_stubs.pl'.
 */

struct remote_open_args {
    /* NB. "name" might be NULL although in practice you can't
     * yet do that using the remote_internal driver.
     */
    remote_string name;
    int flags;
};

struct remote_get_type_ret {
    remote_nonnull_string type;
};

struct remote_get_version_ret {
    hyper hv_ver;
};

struct remote_get_hostname_ret {
    remote_nonnull_string hostname;
};

struct remote_get_max_vcpus_args {
    /* The only backend which supports this call is Xen HV, and
     * there the type is ignored so it could be NULL.
     */
    remote_string type;
};

struct remote_get_max_vcpus_ret {
    int max_vcpus;
};

struct remote_node_get_info_ret {
    char model[32];
    hyper memory;
    int cpus;
    int mhz;
    int nodes;
    int sockets;
    int cores;
    int threads;
};

struct remote_get_capabilities_ret {
    remote_nonnull_string capabilities;
};

struct remote_domain_get_scheduler_type_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_scheduler_type_ret {
    remote_nonnull_string type;
    int nparams;
};

struct remote_domain_get_scheduler_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
};

struct remote_domain_get_scheduler_parameters_ret {
    remote_sched_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>;
};

struct remote_domain_set_scheduler_parameters_args {
    remote_nonnull_domain dom;
    remote_sched_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>;
};

struct remote_list_domains_args {
    int maxids;
};

struct remote_list_domains_ret {
    int ids<REMOTE_DOMAIN_ID_LIST_MAX>;
};

struct remote_num_of_domains_ret {
    int num;
};

struct remote_domain_create_linux_args {
    remote_nonnull_string xml_desc;
    int flags;
};

struct remote_domain_create_linux_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_lookup_by_id_args {
    int id;
};

struct remote_domain_lookup_by_id_ret {
    /* XXX "Not found" semantic is ill-defined. */
    remote_nonnull_domain dom;
};

struct remote_domain_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_domain_lookup_by_uuid_ret {
    /* XXX "Not found" semantic is ill-defined. */
    remote_nonnull_domain dom;
};

struct remote_domain_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_domain_lookup_by_name_ret {
    /* XXX "Not found" semantic is ill-defined. */
    remote_nonnull_domain dom;
};

struct remote_domain_suspend_args {
    remote_nonnull_domain dom;
};

struct remote_domain_resume_args {
    remote_nonnull_domain dom;
};

struct remote_domain_shutdown_args {
    remote_nonnull_domain dom;
};

struct remote_domain_reboot_args {
    remote_nonnull_domain dom;
    int flags;
};

struct remote_domain_destroy_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_os_type_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_os_type_ret {
    remote_nonnull_string type;
};

struct remote_domain_get_max_memory_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_max_memory_ret {
    unsigned hyper memory;
};

struct remote_domain_set_max_memory_args {
    remote_nonnull_domain dom;
    unsigned hyper memory;
};

struct remote_domain_set_memory_args {
    remote_nonnull_domain dom;
    unsigned hyper memory;
};

struct remote_domain_get_info_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_info_ret {
    unsigned char state;
    unsigned hyper max_mem;
    unsigned hyper memory;
    unsigned short nr_virt_cpu;
    unsigned hyper cpu_time;
};

struct remote_domain_save_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
};

struct remote_domain_restore_args {
    remote_nonnull_string from;
};

struct remote_domain_core_dump_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
    int flags;
};

struct remote_domain_dump_xml_args {
    remote_nonnull_domain dom;
    int flags;
};

struct remote_domain_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_list_defined_domains_args {
    int maxnames;
};

struct remote_list_defined_domains_ret {
    remote_nonnull_string names<REMOTE_DOMAIN_NAME_LIST_MAX>;
};

struct remote_num_of_defined_domains_ret {
    int num;
};

struct remote_domain_create_args {
    remote_nonnull_domain dom;
};

struct remote_domain_define_xml_args {
    remote_nonnull_string xml;
};

struct remote_domain_define_xml_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_undefine_args {
    remote_nonnull_domain dom;
};

struct remote_domain_set_vcpus_args {
    remote_nonnull_domain dom;
    int nvcpus;
};

struct remote_domain_pin_vcpu_args {
    remote_nonnull_domain dom;
    int vcpu;
    opaque cpumap<REMOTE_CPUMAP_MAX>;
};

struct remote_domain_get_vcpus_args {
    remote_nonnull_domain dom;
    int maxinfo;
    int maplen;
};

struct remote_domain_get_vcpus_ret {
    remote_vcpu_info info<REMOTE_VCPUINFO_MAX>;
    opaque cpumaps<REMOTE_CPUMAPS_MAX>;
};

struct remote_domain_get_max_vcpus_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_max_vcpus_ret {
    int num;
};

struct remote_domain_attach_device_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
};

struct remote_domain_detach_device_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
};

struct remote_domain_get_autostart_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_autostart_ret {
    int autostart;
};

struct remote_domain_set_autostart_args {
    remote_nonnull_domain dom;
    int autostart;
};

/* Network calls: */

struct remote_num_of_networks_ret {
    int num;
};

struct remote_list_networks_args {
    int maxnames;
};

struct remote_list_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_NAME_LIST_MAX>;
};

struct remote_num_of_defined_networks_ret {
    int num;
};

struct remote_list_defined_networks_args {
    int maxnames;
};

struct remote_list_defined_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_NAME_LIST_MAX>;
};

struct remote_network_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_network_lookup_by_uuid_ret {
    /* XXX "Not found" semantic is ill-defined. */
    remote_nonnull_network net;
};

struct remote_network_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_network_lookup_by_name_ret {
    /* XXX "Not found" semantic is ill-defined. */
    remote_nonnull_network net;
};

struct remote_network_create_xml_args {
    remote_nonnull_string xml;
};

struct remote_network_create_xml_ret {
    remote_nonnull_network net;
};

struct remote_network_define_xml_args {
    remote_nonnull_string xml;
};

struct remote_network_define_xml_ret {
    remote_nonnull_network net;
};

struct remote_network_undefine_args {
    remote_nonnull_network net;
};

struct remote_network_create_args {
    remote_nonnull_network net;
};

struct remote_network_destroy_args {
    remote_nonnull_network net;
};

struct remote_network_dump_xml_args {
    remote_nonnull_network net;
    int flags;
};

struct remote_network_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_network_get_bridge_name_args {
    remote_nonnull_network net;
};

struct remote_network_get_bridge_name_ret {
    remote_nonnull_string name;
};

struct remote_network_get_autostart_args {
    remote_nonnull_network net;
};

struct remote_network_get_autostart_ret {
    int autostart;
};

struct remote_network_set_autostart_args {
    remote_nonnull_network net;
    int autostart;
};

/*----- Protocol. -----*/

/* Define the program number, protocol version and procedure numbers here. */
const REMOTE_PROGRAM = 0x20008086;
const REMOTE_PROTOCOL_VERSION = 1;

enum remote_procedure {
    REMOTE_PROC_OPEN = 1,
    REMOTE_PROC_CLOSE = 2,
    REMOTE_PROC_GET_TYPE = 3,
    REMOTE_PROC_GET_VERSION = 4,
    REMOTE_PROC_GET_MAX_VCPUS = 5,
    REMOTE_PROC_NODE_GET_INFO = 6,
    REMOTE_PROC_GET_CAPABILITIES = 7,
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE = 8,
    REMOTE_PROC_DOMAIN_CREATE = 9,
    REMOTE_PROC_DOMAIN_CREATE_LINUX = 10,
    REMOTE_PROC_DOMAIN_DEFINE_XML = 11,
    REMOTE_PROC_DOMAIN_DESTROY = 12,
    REMOTE_PROC_DOMAIN_DETACH_DEVICE = 13,
    REMOTE_PROC_DOMAIN_DUMP_XML = 14,
    REMOTE_PROC_DOMAIN_GET_AUTOSTART = 15,
    REMOTE_PROC_DOMAIN_GET_INFO = 16,
    REMOTE_PROC_DOMAIN_GET_MAX_MEMORY = 17,
    REMOTE_PROC_DOMAIN_GET_MAX_VCPUS = 18,
    REMOTE_PROC_DOMAIN_GET_OS_TYPE = 19,
    REMOTE_PROC_DOMAIN_GET_VCPUS = 20,
    REMOTE_PROC_LIST_DEFINED_DOMAINS = 21,
    REMOTE_PROC_DOMAIN_LOOKUP_BY_ID = 22,
    REMOTE_PROC_DOMAIN_LOOKUP_BY_NAME = 23,
    REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID = 24,
    REMOTE_PROC_NUM_OF_DEFINED_DOMAINS = 25,
    REMOTE_PROC_DOMAIN_PIN_VCPU = 26,
    REMOTE_PROC_DOMAIN_REBOOT = 27,
    REMOTE_PROC_DOMAIN_RESUME = 28,
    REMOTE_PROC_DOMAIN_SET_AUTOSTART = 29,
    REMOTE_PROC_DOMAIN_SET_MAX_MEMORY = 30,
    REMOTE_PROC_DOMAIN_SET_MEMORY = 31,
    REMOTE_PROC_DOMAIN_SET_VCPUS = 32,
    REMOTE_PROC_DOMAIN_SHUTDOWN = 33,
    REMOTE_PROC_DOMAIN_SUSPEND = 34,
    REMOTE_PROC_DOMAIN_UNDEFINE = 35,
    REMOTE_PROC_LIST_DEFINED_NETWORKS = 36,
    REMOTE_PROC_LIST_DOMAINS = 37,
    REMOTE_PROC_LIST_NETWORKS = 38,
    REMOTE_PROC_NETWORK_CREATE = 39,
    REMOTE_PROC_NETWORK_CREATE_XML = 40,
    REMOTE_PROC_NETWORK_DEFINE_XML = 41,
    REMOTE_PROC_NETWORK_DESTROY = 42,
    REMOTE_PROC_NETWORK_DUMP_XML = 43,
    REMOTE_PROC_NETWORK_GET_AUTOSTART = 44,
    REMOTE_PROC_NETWORK_GET_BRIDGE_NAME = 45,
    REMOTE_PROC_NETWORK_LOOKUP_BY_NAME = 46,
    REMOTE_PROC_NETWORK_LOOKUP_BY_UUID = 47,
    REMOTE_PROC_NETWORK_SET_AUTOSTART = 48,
    REMOTE_PROC_NETWORK_UNDEFINE = 49,
    REMOTE_PROC_NUM_OF_DEFINED_NETWORKS = 50,
    REMOTE_PROC_NUM_OF_DOMAINS = 51,
    REMOTE_PROC_NUM_OF_NETWORKS = 52,
    REMOTE_PROC_DOMAIN_CORE_DUMP = 53,
    REMOTE_PROC_DOMAIN_RESTORE = 54,
    REMOTE_PROC_DOMAIN_SAVE = 55,
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE = 56,
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS = 57,
    REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS = 58,
    REMOTE_PROC_GET_HOSTNAME = 59
};

/* Custom RPC structure. */
/* Each message consists of:
 *    int length               Number of bytes in message _including_ length.
 *    remote_message_header    Header.
 * then either: args           Arguments (for REMOTE_CALL).
 *          or: ret            Return (for REMOTE_REPLY, status = REMOTE_OK)
 *          or: remote_error   Error (for REMOTE_REPLY, status = REMOTE_ERROR)
 *
 * The first two words (length, program number) are meant to be compatible
 * with the qemud protocol (qemud/protocol.x), although the rest of the
 * messages are completely different.
 */

enum remote_message_direction {
    REMOTE_CALL = 0,            /* client -> server */
    REMOTE_REPLY = 1,           /* server -> client */
    REMOTE_MESSAGE = 2          /* server -> client, asynchronous [NYI] */
};

enum remote_message_status {
    /* Status is always REMOTE_OK for calls.
     * For replies, indicates no error.
     */
    REMOTE_OK = 0,

    /* For replies, indicates that an error happened, and a struct
     * remote_error follows.
     */
    REMOTE_ERROR = 1
};

struct remote_message_header {
    unsigned prog;              /* REMOTE_PROGRAM */
    unsigned vers;              /* REMOTE_PROTOCOL_VERSION */
    remote_procedure proc;      /* REMOTE_PROC_x */
    remote_message_direction direction;
    unsigned serial;            /* Serial number of message. */
    remote_message_status status;
};


/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
