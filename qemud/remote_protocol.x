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

%#include <config.h>
%#include "internal.h"
%#include "socketcompat.h"

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

/* Upper limit on migrate cookie. */
const REMOTE_MIGRATE_COOKIE_MAX = 256;

/* Upper limit on lists of network names. */
const REMOTE_NETWORK_NAME_LIST_MAX = 256;

/* Upper limit on lists of storage pool names. */
const REMOTE_STORAGE_POOL_NAME_LIST_MAX = 256;

/* Upper limit on lists of storage vol names. */
const REMOTE_STORAGE_VOL_NAME_LIST_MAX = 1024;

/* Upper limit on list of scheduler parameters. */
const REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX = 16;

/* Upper limit on number of NUMA cells */
const REMOTE_NODE_MAX_CELLS = 1024;

/* Upper limit on SASL auth negotiation packet */
const REMOTE_AUTH_SASL_DATA_MAX = 65536;

/* Maximum number of auth types */
const REMOTE_AUTH_TYPE_LIST_MAX = 20;

/* Maximum length of a block peek buffer message.
 * Note applications need to be aware of this limit and issue multiple
 * requests for large amounts of data.
 */
const REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX = 65536;

/* Maximum length of a memory peek buffer message.
 * Note applications need to be aware of this limit and issue multiple
 * requests for large amounts of data.
 */
const REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX = 65536;

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

/* A storage pool which may not be NULL. */
struct remote_nonnull_storage_pool {
    remote_nonnull_string name;
    remote_uuid uuid;
};

/* A storage vol which may not be NULL. */
struct remote_nonnull_storage_vol {
    remote_nonnull_string pool;
    remote_nonnull_string name;
    remote_nonnull_string key;
};

/* A domain or network which may be NULL. */
typedef remote_nonnull_domain *remote_domain;
typedef remote_nonnull_network *remote_network;
typedef remote_nonnull_storage_pool *remote_storage_pool;
typedef remote_nonnull_storage_vol *remote_storage_vol;

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

/* Authentication types available thus far.... */
enum remote_auth_type {
    REMOTE_AUTH_NONE = 0,
    REMOTE_AUTH_SASL = 1,
    REMOTE_AUTH_POLKIT = 2
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

struct remote_supports_feature_args {
    int feature;
};

struct remote_supports_feature_ret {
    int supported;
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

struct remote_node_get_cells_free_memory_args {
    int startCell;
    int maxCells;
};

struct remote_node_get_cells_free_memory_ret {
    hyper freeMems<REMOTE_NODE_MAX_CELLS>;
};

struct remote_node_get_free_memory_ret {
    hyper freeMem;
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

struct remote_domain_block_stats_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
};

struct remote_domain_block_stats_ret {
    hyper rd_req;
    hyper rd_bytes;
    hyper wr_req;
    hyper wr_bytes;
    hyper errs;
};

struct remote_domain_interface_stats_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
};

struct remote_domain_interface_stats_ret {
    hyper rx_bytes;
    hyper rx_packets;
    hyper rx_errs;
    hyper rx_drop;
    hyper tx_bytes;
    hyper tx_packets;
    hyper tx_errs;
    hyper tx_drop;
};

struct remote_domain_block_peek_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned hyper offset;
    unsigned size;
    unsigned flags;
};

struct remote_domain_block_peek_ret {
    opaque buffer<REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX>;
};

struct remote_domain_memory_peek_args {
    remote_nonnull_domain dom;
    unsigned hyper offset;
    unsigned size;
    unsigned flags;
};

struct remote_domain_memory_peek_ret {
    opaque buffer<REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX>;
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
    remote_nonnull_domain dom;
};

struct remote_domain_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_domain_lookup_by_uuid_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_domain_lookup_by_name_ret {
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

struct remote_domain_migrate_prepare_args {
    remote_string uri_in;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
};

struct remote_domain_migrate_prepare_ret {
    opaque cookie<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string uri_out;
};

struct remote_domain_migrate_perform_args {
    remote_nonnull_domain dom;
    opaque cookie<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_nonnull_string uri;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
};

struct remote_domain_migrate_finish_args {
    remote_nonnull_string dname;
    opaque cookie<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_nonnull_string uri;
    unsigned hyper flags;
};

struct remote_domain_migrate_finish_ret {
    remote_nonnull_domain ddom;
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
    remote_nonnull_network net;
};

struct remote_network_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_network_lookup_by_name_ret {
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


struct remote_auth_list_ret {
    remote_auth_type types<REMOTE_AUTH_TYPE_LIST_MAX>;
};

struct remote_auth_sasl_init_ret {
    remote_nonnull_string mechlist;
};

struct remote_auth_sasl_start_args {
    remote_nonnull_string mech;
    int nil;
    char data<REMOTE_AUTH_SASL_DATA_MAX>;
};

struct remote_auth_sasl_start_ret {
    int complete;
    int nil;
    char data<REMOTE_AUTH_SASL_DATA_MAX>;
};

struct remote_auth_sasl_step_args {
    int nil;
    char data<REMOTE_AUTH_SASL_DATA_MAX>;
};

struct remote_auth_sasl_step_ret {
    int complete;
    int nil;
    char data<REMOTE_AUTH_SASL_DATA_MAX>;
};

struct remote_auth_polkit_ret {
    int complete;
};



/* Storage pool calls: */

struct remote_num_of_storage_pools_ret {
    int num;
};

struct remote_list_storage_pools_args {
    int maxnames;
};

struct remote_list_storage_pools_ret {
    remote_nonnull_string names<REMOTE_STORAGE_POOL_NAME_LIST_MAX>;
};

struct remote_num_of_defined_storage_pools_ret {
    int num;
};

struct remote_list_defined_storage_pools_args {
    int maxnames;
};

struct remote_list_defined_storage_pools_ret {
    remote_nonnull_string names<REMOTE_STORAGE_POOL_NAME_LIST_MAX>;
};

struct remote_find_storage_pool_sources_args {
    remote_nonnull_string type;
    remote_string srcSpec;
    unsigned flags;
};

struct remote_find_storage_pool_sources_ret {
    remote_nonnull_string xml;
};

struct remote_storage_pool_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_storage_pool_lookup_by_uuid_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_storage_pool_lookup_by_name_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_lookup_by_volume_args {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_pool_lookup_by_volume_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_create_xml_args {
    remote_nonnull_string xml;
    unsigned flags;
};

struct remote_storage_pool_create_xml_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_define_xml_args {
    remote_nonnull_string xml;
    unsigned flags;
};

struct remote_storage_pool_define_xml_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_build_args {
    remote_nonnull_storage_pool pool;
    unsigned flags;
};

struct remote_storage_pool_undefine_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_create_args {
    remote_nonnull_storage_pool pool;
    unsigned flags;
};

struct remote_storage_pool_destroy_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_delete_args {
    remote_nonnull_storage_pool pool;
    unsigned flags;
};

struct remote_storage_pool_refresh_args {
    remote_nonnull_storage_pool pool;
    unsigned flags;
};

struct remote_storage_pool_dump_xml_args {
    remote_nonnull_storage_pool pool;
    unsigned flags;
};

struct remote_storage_pool_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_storage_pool_get_info_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_get_info_ret {
    unsigned char state;
    unsigned hyper capacity;
    unsigned hyper allocation;
    unsigned hyper available;
};

struct remote_storage_pool_get_autostart_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_get_autostart_ret {
    int autostart;
};

struct remote_storage_pool_set_autostart_args {
    remote_nonnull_storage_pool pool;
    int autostart;
};

struct remote_storage_pool_num_of_volumes_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_num_of_volumes_ret {
    int num;
};

struct remote_storage_pool_list_volumes_args {
    remote_nonnull_storage_pool pool;
    int maxnames;
};

struct remote_storage_pool_list_volumes_ret {
    remote_nonnull_string names<REMOTE_STORAGE_VOL_NAME_LIST_MAX>;
};



/* Storage vol calls: */

struct remote_storage_vol_lookup_by_name_args {
    remote_nonnull_storage_pool pool;
    remote_nonnull_string name;
};

struct remote_storage_vol_lookup_by_name_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_lookup_by_key_args {
    remote_nonnull_string key;
};

struct remote_storage_vol_lookup_by_key_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_lookup_by_path_args {
    remote_nonnull_string path;
};

struct remote_storage_vol_lookup_by_path_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_create_xml_args {
    remote_nonnull_storage_pool pool;
    remote_nonnull_string xml;
    unsigned flags;
};

struct remote_storage_vol_create_xml_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_delete_args {
    remote_nonnull_storage_vol vol;
    unsigned flags;
};

struct remote_storage_vol_dump_xml_args {
    remote_nonnull_storage_vol vol;
    unsigned flags;
};

struct remote_storage_vol_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_storage_vol_get_info_args {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_get_info_ret {
    char type;
    unsigned hyper capacity;
    unsigned hyper allocation;
};

struct remote_storage_vol_get_path_args {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_get_path_ret {
    remote_nonnull_string name;
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
    REMOTE_PROC_GET_HOSTNAME = 59,
    REMOTE_PROC_SUPPORTS_FEATURE = 60,

    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE = 61,
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM = 62,
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH = 63,
    REMOTE_PROC_DOMAIN_BLOCK_STATS = 64,
    REMOTE_PROC_DOMAIN_INTERFACE_STATS = 65,
    REMOTE_PROC_AUTH_LIST = 66,
    REMOTE_PROC_AUTH_SASL_INIT = 67,
    REMOTE_PROC_AUTH_SASL_START = 68,
    REMOTE_PROC_AUTH_SASL_STEP = 69,
    REMOTE_PROC_AUTH_POLKIT = 70,

    REMOTE_PROC_NUM_OF_STORAGE_POOLS = 71,
    REMOTE_PROC_LIST_STORAGE_POOLS = 72,
    REMOTE_PROC_NUM_OF_DEFINED_STORAGE_POOLS = 73,
    REMOTE_PROC_LIST_DEFINED_STORAGE_POOLS = 74,
    REMOTE_PROC_FIND_STORAGE_POOL_SOURCES = 75,
    REMOTE_PROC_STORAGE_POOL_CREATE_XML = 76,
    REMOTE_PROC_STORAGE_POOL_DEFINE_XML = 77,
    REMOTE_PROC_STORAGE_POOL_CREATE = 78,
    REMOTE_PROC_STORAGE_POOL_BUILD = 79,
    REMOTE_PROC_STORAGE_POOL_DESTROY = 80,

    REMOTE_PROC_STORAGE_POOL_DELETE = 81,
    REMOTE_PROC_STORAGE_POOL_UNDEFINE = 82,
    REMOTE_PROC_STORAGE_POOL_REFRESH = 83,
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME = 84,
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID = 85,
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_VOLUME = 86,
    REMOTE_PROC_STORAGE_POOL_GET_INFO = 87,
    REMOTE_PROC_STORAGE_POOL_DUMP_XML = 88,
    REMOTE_PROC_STORAGE_POOL_GET_AUTOSTART = 89,
    REMOTE_PROC_STORAGE_POOL_SET_AUTOSTART = 90,

    REMOTE_PROC_STORAGE_POOL_NUM_OF_VOLUMES = 91,
    REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES = 92,
    REMOTE_PROC_STORAGE_VOL_CREATE_XML = 93,
    REMOTE_PROC_STORAGE_VOL_DELETE = 94,
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME = 95,
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_KEY = 96,
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_PATH = 97,
    REMOTE_PROC_STORAGE_VOL_GET_INFO = 98,
    REMOTE_PROC_STORAGE_VOL_DUMP_XML = 99,
    REMOTE_PROC_STORAGE_VOL_GET_PATH = 100,

    REMOTE_PROC_NODE_GET_CELLS_FREE_MEMORY = 101,
    REMOTE_PROC_NODE_GET_FREE_MEMORY = 102,

    REMOTE_PROC_DOMAIN_BLOCK_PEEK = 103,
    REMOTE_PROC_DOMAIN_MEMORY_PEEK = 104
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

/* 4 byte length word per header */
const REMOTE_MESSAGE_HEADER_XDR_LEN = 4;

struct remote_message_header {
    unsigned prog;              /* REMOTE_PROGRAM */
    unsigned vers;              /* REMOTE_PROTOCOL_VERSION */
    remote_procedure proc;      /* REMOTE_PROC_x */
    remote_message_direction direction;
    unsigned serial;            /* Serial number of message. */
    remote_message_status status;
};
