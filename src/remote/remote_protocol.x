/* -*- c -*-
 * remote_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

%#include "internal.h"
%#include <arpa/inet.h>

/* cygwin's xdr implementation defines xdr_u_int64_t instead of xdr_uint64_t
 * and lacks IXDR_PUT_INT32 and IXDR_GET_INT32
 */
%#ifdef HAVE_XDR_U_INT64_T
%# define xdr_uint64_t xdr_u_int64_t
%#endif
%#ifndef IXDR_PUT_INT32
%# define IXDR_PUT_INT32 IXDR_PUT_LONG
%#endif
%#ifndef IXDR_GET_INT32
%# define IXDR_GET_INT32 IXDR_GET_LONG
%#endif
%#ifndef IXDR_PUT_U_INT32
%# define IXDR_PUT_U_INT32 IXDR_PUT_U_LONG
%#endif
%#ifndef IXDR_GET_U_INT32
%# define IXDR_GET_U_INT32 IXDR_GET_U_LONG
%#endif

/*----- Data types. -----*/

/* Maximum total message size (serialised). */
const REMOTE_MESSAGE_MAX = 262144;

/* Size of struct remote_message_header (serialized)*/
const REMOTE_MESSAGE_HEADER_MAX = 24;

/* Size of message payload */
const REMOTE_MESSAGE_PAYLOAD_MAX = 262120;

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

/* Upper limit on lists of interface names. */
const REMOTE_INTERFACE_NAME_LIST_MAX = 256;

/* Upper limit on lists of defined interface names. */
const REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX = 256;

/* Upper limit on lists of storage pool names. */
const REMOTE_STORAGE_POOL_NAME_LIST_MAX = 256;

/* Upper limit on lists of storage vol names. */
const REMOTE_STORAGE_VOL_NAME_LIST_MAX = 1024;

/* Upper limit on lists of node device names. */
const REMOTE_NODE_DEVICE_NAME_LIST_MAX = 16384;

/* Upper limit on lists of node device capabilities. */
const REMOTE_NODE_DEVICE_CAPS_LIST_MAX = 16384;

/* Upper limit on lists of network filter names. */
const REMOTE_NWFILTER_NAME_LIST_MAX = 1024;

/* Upper limit on list of scheduler parameters. */
const REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX = 16;

/* Upper limit on list of blkio parameters. */
const REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX = 16;

/* Upper limit on list of memory parameters. */
const REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX = 16;

/* Upper limit on number of NUMA cells */
const REMOTE_NODE_MAX_CELLS = 1024;

/* Upper limit on SASL auth negotiation packet */
const REMOTE_AUTH_SASL_DATA_MAX = 65536;

/* Maximum number of auth types */
const REMOTE_AUTH_TYPE_LIST_MAX = 20;

/* Upper limit on list of memory stats */
const REMOTE_DOMAIN_MEMORY_STATS_MAX = 1024;

/* Upper limit on lists of domain snapshots. */
const REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX = 1024;

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

/*
 * Maximum length of a security model field.
 */
const REMOTE_SECURITY_MODEL_MAX = VIR_SECURITY_MODEL_BUFLEN;

/*
 * Maximum length of a security label field.
 */
const REMOTE_SECURITY_LABEL_MAX = VIR_SECURITY_LABEL_BUFLEN;

/*
 * Maximum length of a security DOI field.
 */
const REMOTE_SECURITY_DOI_MAX = VIR_SECURITY_DOI_BUFLEN;

/*
 * Maximum size of a secret value.
 */
const REMOTE_SECRET_VALUE_MAX = 65536;

/*
 * Upper limit on list of secrets.
 */
const REMOTE_SECRET_UUID_LIST_MAX = 16384;

/*
 * Upper limit on list of CPUs accepted when computing a baseline CPU.
 */
const REMOTE_CPU_BASELINE_MAX = 256;

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

/* A network filter which may not be NULL. */
struct remote_nonnull_nwfilter {
    remote_nonnull_string name;
    remote_uuid uuid;
};

/* An interface which may not be NULL. */
struct remote_nonnull_interface {
    remote_nonnull_string name;
    remote_nonnull_string mac;
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

/* A node device which may not be NULL. */
struct remote_nonnull_node_device {
    remote_nonnull_string name;
};

/* A secret which may not be null. */
struct remote_nonnull_secret {
    remote_uuid uuid;
    int usageType;
    remote_nonnull_string usageID;
};

/* A snapshot which may not be NULL. */
struct remote_nonnull_domain_snapshot {
    remote_nonnull_string name;
    remote_nonnull_domain domain;
};

/* A domain or network which may be NULL. */
typedef remote_nonnull_domain *remote_domain;
typedef remote_nonnull_network *remote_network;
typedef remote_nonnull_nwfilter *remote_nwfilter;
typedef remote_nonnull_storage_pool *remote_storage_pool;
typedef remote_nonnull_storage_vol *remote_storage_vol;
typedef remote_nonnull_node_device *remote_node_device;

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

union remote_blkio_param_value switch (int type) {
 case VIR_DOMAIN_BLKIO_PARAM_INT:
     int i;
 case VIR_DOMAIN_BLKIO_PARAM_UINT:
     unsigned int ui;
 case VIR_DOMAIN_BLKIO_PARAM_LLONG:
     hyper l;
 case VIR_DOMAIN_BLKIO_PARAM_ULLONG:
     unsigned hyper ul;
 case VIR_DOMAIN_BLKIO_PARAM_DOUBLE:
     double d;
 case VIR_DOMAIN_BLKIO_PARAM_BOOLEAN:
     int b;
};

struct remote_blkio_param {
    remote_nonnull_string field;
    remote_blkio_param_value value;
};

union remote_memory_param_value switch (int type) {
 case VIR_DOMAIN_MEMORY_PARAM_INT:
     int i;
 case VIR_DOMAIN_MEMORY_PARAM_UINT:
     unsigned int ui;
 case VIR_DOMAIN_MEMORY_PARAM_LLONG:
     hyper l;
 case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
     unsigned hyper ul;
 case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
     double d;
 case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
     int b;
};

struct remote_memory_param {
    remote_nonnull_string field;
    remote_memory_param_value value;
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

struct remote_get_lib_version_ret {
    hyper lib_ver;
};

struct remote_get_hostname_ret {
    remote_nonnull_string hostname;
};

struct remote_get_sysinfo_args {
    unsigned int flags;
};

struct remote_get_sysinfo_ret {
    remote_nonnull_string sysinfo;
};

struct remote_get_uri_ret {
    remote_nonnull_string uri;
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

struct remote_domain_set_blkio_parameters_args {
    remote_nonnull_domain dom;
    remote_blkio_param params<REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_blkio_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_blkio_parameters_ret {
    remote_blkio_param params<REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_set_memory_parameters_args {
    remote_nonnull_domain dom;
    remote_memory_param params<REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_memory_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_memory_parameters_ret {
    remote_memory_param params<REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX>;
    int nparams;
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

struct remote_domain_memory_stats_args {
        remote_nonnull_domain dom;
        u_int maxStats;
        u_int flags;
};

struct remote_domain_memory_stat {
    int tag;
    unsigned hyper val;
};

struct remote_domain_memory_stats_ret {
    remote_domain_memory_stat stats<REMOTE_DOMAIN_MEMORY_STATS_MAX>;
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

struct remote_domain_get_block_info_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned flags;
};

struct remote_domain_get_block_info_ret {
    unsigned hyper allocation;
    unsigned hyper capacity;
    unsigned hyper physical;
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

struct remote_domain_create_xml_args {
    remote_nonnull_string xml_desc;
    int flags;
};

struct remote_domain_create_xml_ret {
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

struct remote_domain_set_memory_flags_args {
    remote_nonnull_domain dom;
    unsigned hyper memory;
    unsigned int flags;
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

struct remote_domain_migrate_prepare2_args {
    remote_string uri_in;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
    remote_nonnull_string dom_xml;
};

struct remote_domain_migrate_prepare2_ret {
    opaque cookie<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string uri_out;
};

struct remote_domain_migrate_finish2_args {
    remote_nonnull_string dname;
    opaque cookie<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_nonnull_string uri;
    unsigned hyper flags;
    int retcode;
};

struct remote_domain_migrate_finish2_ret {
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

struct remote_domain_create_with_flags_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_create_with_flags_ret {
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

struct remote_domain_set_vcpus_flags_args {
    remote_nonnull_domain dom;
    unsigned int nvcpus;
    unsigned int flags;
};

struct remote_domain_get_vcpus_flags_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_vcpus_flags_ret {
    int num;
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

struct remote_domain_get_security_label_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_security_label_ret {
    char label<REMOTE_SECURITY_LABEL_MAX>;
    int enforcing;
};

struct remote_node_get_security_model_ret {
    char model<REMOTE_SECURITY_MODEL_MAX>;
    char doi<REMOTE_SECURITY_DOI_MAX>;
};

struct remote_domain_attach_device_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
};

struct remote_domain_attach_device_flags_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_domain_detach_device_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
};

struct remote_domain_detach_device_flags_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_domain_update_device_flags_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml;
    unsigned int flags;
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

/* network filter calls */

struct remote_num_of_nwfilters_ret {
    int num;
};

struct remote_list_nwfilters_args {
    int maxnames;
};

struct remote_list_nwfilters_ret {
    remote_nonnull_string names<REMOTE_NWFILTER_NAME_LIST_MAX>;
};

struct remote_nwfilter_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_nwfilter_lookup_by_uuid_ret {
    remote_nonnull_nwfilter nwfilter;
};

struct remote_nwfilter_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_nwfilter_lookup_by_name_ret {
    remote_nonnull_nwfilter nwfilter;
};

struct remote_nwfilter_define_xml_args {
    remote_nonnull_string xml;
};

struct remote_nwfilter_define_xml_ret {
    remote_nonnull_nwfilter nwfilter;
};

struct remote_nwfilter_undefine_args {
    remote_nonnull_nwfilter nwfilter;
};

struct remote_nwfilter_get_xml_desc_args {
    remote_nonnull_nwfilter nwfilter;
    int flags;
};

struct remote_nwfilter_get_xml_desc_ret {
    remote_nonnull_string xml;
};


/* Interface calls: */

struct remote_num_of_interfaces_ret {
    int num;
};

struct remote_list_interfaces_args {
    int maxnames;
};

struct remote_list_interfaces_ret {
    remote_nonnull_string names<REMOTE_INTERFACE_NAME_LIST_MAX>;
};

struct remote_num_of_defined_interfaces_ret {
    int num;
};

struct remote_list_defined_interfaces_args {
    int maxnames;
};

struct remote_list_defined_interfaces_ret {
    remote_nonnull_string names<REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX>;
};

struct remote_interface_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_interface_lookup_by_name_ret {
    remote_nonnull_interface iface;
};

struct remote_interface_lookup_by_mac_string_args {
    remote_nonnull_string mac;
};

struct remote_interface_lookup_by_mac_string_ret {
    remote_nonnull_interface iface;
};

struct remote_interface_get_xml_desc_args {
    remote_nonnull_interface iface;
    unsigned int flags;
};

struct remote_interface_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_interface_define_xml_args {
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_interface_define_xml_ret {
    remote_nonnull_interface iface;
};

struct remote_interface_undefine_args {
    remote_nonnull_interface iface;
};

struct remote_interface_create_args {
    remote_nonnull_interface iface;
    unsigned int flags;
};

struct remote_interface_destroy_args {
    remote_nonnull_interface iface;
    unsigned int flags;
};


/* Auth calls: */

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

struct remote_storage_vol_create_xml_from_args {
    remote_nonnull_storage_pool pool;
    remote_nonnull_string xml;
    remote_nonnull_storage_vol clonevol;
    unsigned flags;
};

struct remote_storage_vol_create_xml_from_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_delete_args {
    remote_nonnull_storage_vol vol;
    unsigned flags;
};

struct remote_storage_vol_wipe_args {
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

/* Node driver calls: */

struct remote_node_num_of_devices_args {
    remote_string cap;
    unsigned flags;
};

struct remote_node_num_of_devices_ret {
    int num;
};

struct remote_node_list_devices_args {
    remote_string cap;
    int maxnames;
    unsigned flags;
};

struct remote_node_list_devices_ret {
    remote_nonnull_string names<REMOTE_NODE_DEVICE_NAME_LIST_MAX>;
};

struct remote_node_device_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_node_device_lookup_by_name_ret {
    remote_nonnull_node_device dev;
};

struct remote_node_device_dump_xml_args {
    remote_nonnull_string name;
    unsigned flags;
};

struct remote_node_device_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_node_device_get_parent_args {
    remote_nonnull_string name;
};

struct remote_node_device_get_parent_ret {
    remote_string parent;
};

struct remote_node_device_num_of_caps_args {
    remote_nonnull_string name;
};

struct remote_node_device_num_of_caps_ret {
    int num;
};

struct remote_node_device_list_caps_args {
    remote_nonnull_string name;
    int maxnames;
};

struct remote_node_device_list_caps_ret {
    remote_nonnull_string names<REMOTE_NODE_DEVICE_CAPS_LIST_MAX>;
};

struct remote_node_device_dettach_args {
    remote_nonnull_string name;
};

struct remote_node_device_re_attach_args {
    remote_nonnull_string name;
};

struct remote_node_device_reset_args {
    remote_nonnull_string name;
};

struct remote_node_device_create_xml_args {
    remote_nonnull_string xml_desc;
    int flags;
};

struct remote_node_device_create_xml_ret {
    remote_nonnull_node_device dev;
};

struct remote_node_device_destroy_args {
    remote_nonnull_string name;
};


/**
 * Events Register/Deregister:
 * It would seem rpcgen does not like both args, and ret
 * to be null. It will not generate the prototype otherwise.
 * Pass back a redundant boolean to force prototype generation.
 */
struct remote_domain_events_register_ret {
    int cb_registered;
};

struct remote_domain_events_deregister_ret {
    int cb_registered;
};

struct remote_domain_event_lifecycle_msg {
    remote_nonnull_domain dom;
    int event;
    int detail;
};


struct remote_domain_xml_from_native_args {
    remote_nonnull_string nativeFormat;
    remote_nonnull_string nativeConfig;
    unsigned flags;
};

struct remote_domain_xml_from_native_ret {
    remote_nonnull_string domainXml;
};


struct remote_domain_xml_to_native_args {
    remote_nonnull_string nativeFormat;
    remote_nonnull_string domainXml;
    unsigned flags;
};

struct remote_domain_xml_to_native_ret {
    remote_nonnull_string nativeConfig;
};


struct remote_num_of_secrets_ret {
    int num;
};

struct remote_list_secrets_args {
    int maxuuids;
};

struct remote_list_secrets_ret {
    remote_nonnull_string uuids<REMOTE_SECRET_UUID_LIST_MAX>;
};

struct remote_secret_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_secret_lookup_by_uuid_ret {
    remote_nonnull_secret secret;
};

struct remote_secret_define_xml_args {
    remote_nonnull_string xml;
    unsigned flags;
};

struct remote_secret_define_xml_ret {
    remote_nonnull_secret secret;
};

struct remote_secret_get_xml_desc_args {
    remote_nonnull_secret secret;
    unsigned flags;
};

struct remote_secret_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_secret_set_value_args {
    remote_nonnull_secret secret;
    opaque value<REMOTE_SECRET_VALUE_MAX>;
    unsigned flags;
};

struct remote_secret_get_value_args {
    remote_nonnull_secret secret;
    unsigned flags;
};

struct remote_secret_get_value_ret {
    opaque value<REMOTE_SECRET_VALUE_MAX>;
};

struct remote_secret_undefine_args {
    remote_nonnull_secret secret;
};

struct remote_secret_lookup_by_usage_args {
    int usageType;
    remote_nonnull_string usageID;
};

struct remote_secret_lookup_by_usage_ret {
    remote_nonnull_secret secret;
};

struct remote_domain_migrate_prepare_tunnel_args {
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
    remote_nonnull_string dom_xml;
};


struct remote_is_secure_ret {
    int secure;
};


struct remote_domain_is_active_args {
    remote_nonnull_domain dom;
};

struct remote_domain_is_active_ret {
    int active;
};


struct remote_domain_is_persistent_args {
    remote_nonnull_domain dom;
};

struct remote_domain_is_persistent_ret {
    int persistent;
};

struct remote_domain_is_updated_args {
    remote_nonnull_domain dom;
};

struct remote_domain_is_updated_ret {
    int updated;
};

struct remote_network_is_active_args {
    remote_nonnull_network net;
};

struct remote_network_is_active_ret {
    int active;
};

struct remote_network_is_persistent_args {
    remote_nonnull_network net;
};

struct remote_network_is_persistent_ret {
    int persistent;
};


struct remote_storage_pool_is_active_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_is_active_ret {
    int active;
};

struct remote_storage_pool_is_persistent_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_is_persistent_ret {
    int persistent;
};


struct remote_interface_is_active_args {
    remote_nonnull_interface iface;
};

struct remote_interface_is_active_ret {
    int active;
};


struct remote_cpu_compare_args {
    remote_nonnull_string xml;
    unsigned flags;
};

struct remote_cpu_compare_ret {
    int result;
};


struct remote_cpu_baseline_args {
    remote_nonnull_string xmlCPUs<REMOTE_CPU_BASELINE_MAX>;
    unsigned flags;
};

struct remote_cpu_baseline_ret {
    remote_nonnull_string cpu;
};


struct remote_domain_get_job_info_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_job_info_ret {
    int type;

    unsigned hyper timeElapsed;
    unsigned hyper timeRemaining;

    unsigned hyper dataTotal;
    unsigned hyper dataProcessed;
    unsigned hyper dataRemaining;

    unsigned hyper memTotal;
    unsigned hyper memProcessed;
    unsigned hyper memRemaining;

    unsigned hyper fileTotal;
    unsigned hyper fileProcessed;
    unsigned hyper fileRemaining;
};


struct remote_domain_abort_job_args {
    remote_nonnull_domain dom;
};


struct remote_domain_migrate_set_max_downtime_args {
    remote_nonnull_domain dom;
    unsigned hyper downtime;
    unsigned flags;
};

struct remote_domain_migrate_set_max_speed_args {
    remote_nonnull_domain dom;
    unsigned hyper bandwidth;
    unsigned flags;
};

struct remote_domain_events_register_any_args {
    int eventID;
};

struct remote_domain_events_deregister_any_args {
    int eventID;
};

struct remote_domain_event_reboot_msg {
    remote_nonnull_domain dom;
};

struct remote_domain_event_rtc_change_msg {
    remote_nonnull_domain dom;
    hyper offset;
};

struct remote_domain_event_watchdog_msg {
    remote_nonnull_domain dom;
    int action;
};

struct remote_domain_event_io_error_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string srcPath;
    remote_nonnull_string devAlias;
    int action;
};

struct remote_domain_event_io_error_reason_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string srcPath;
    remote_nonnull_string devAlias;
    int action;
    remote_nonnull_string reason;
};

struct remote_domain_event_graphics_address {
    int family;
    remote_nonnull_string node;
    remote_nonnull_string service;
};

const REMOTE_DOMAIN_EVENT_GRAPHICS_IDENTITY_MAX = 20;

struct remote_domain_event_graphics_identity {
    remote_nonnull_string type;
    remote_nonnull_string name;
};

struct remote_domain_event_graphics_msg {
    remote_nonnull_domain dom;
    int phase;
    remote_domain_event_graphics_address local;
    remote_domain_event_graphics_address remote;
    remote_nonnull_string authScheme;
    remote_domain_event_graphics_identity subject<REMOTE_DOMAIN_EVENT_GRAPHICS_IDENTITY_MAX>;
};

struct remote_domain_managed_save_args {
    remote_nonnull_domain dom;
    unsigned flags;
};

struct remote_domain_has_managed_save_image_args {
    remote_nonnull_domain dom;
    unsigned flags;
};

struct remote_domain_has_managed_save_image_ret {
    int ret;
};

struct remote_domain_managed_save_remove_args {
    remote_nonnull_domain dom;
    unsigned flags;
};

struct remote_domain_snapshot_create_xml_args {
    remote_nonnull_domain domain;
    remote_nonnull_string xml_desc;
    int flags;
};

struct remote_domain_snapshot_create_xml_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_snapshot_dump_xml_args {
    remote_nonnull_domain_snapshot snap;
    int flags;
};

struct remote_domain_snapshot_dump_xml_ret {
    remote_nonnull_string xml;
};

struct remote_domain_snapshot_num_args {
    remote_nonnull_domain domain;
    int flags;
};

struct remote_domain_snapshot_num_ret {
    int num;
};

struct remote_domain_snapshot_list_names_args {
    remote_nonnull_domain domain;
    int nameslen;
    int flags;
};

struct remote_domain_snapshot_list_names_ret {
    remote_nonnull_string names<REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX>;
};

struct remote_domain_snapshot_lookup_by_name_args {
    remote_nonnull_domain domain;
    remote_nonnull_string name;
    int flags;
};

struct remote_domain_snapshot_lookup_by_name_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_has_current_snapshot_args {
    remote_nonnull_domain domain;
    int flags;
};

struct remote_domain_has_current_snapshot_ret {
    int result;
};

struct remote_domain_snapshot_current_args {
    remote_nonnull_domain domain;
    int flags;
};

struct remote_domain_snapshot_current_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_revert_to_snapshot_args {
    remote_nonnull_domain_snapshot snap;
    int flags;
};

struct remote_domain_snapshot_delete_args {
    remote_nonnull_domain_snapshot snap;
    int flags;
};

struct remote_domain_open_console_args {
    remote_nonnull_domain domain;
    remote_string devname;
    unsigned int flags;
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
    REMOTE_PROC_DOMAIN_CREATE_XML = 10,

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
    REMOTE_PROC_DOMAIN_MEMORY_PEEK = 104,
    REMOTE_PROC_DOMAIN_EVENTS_REGISTER = 105,
    REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER = 106,
    REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE = 107,
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE2 = 108,
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH2 = 109,
    REMOTE_PROC_GET_URI = 110,

    REMOTE_PROC_NODE_NUM_OF_DEVICES = 111,
    REMOTE_PROC_NODE_LIST_DEVICES = 112,
    REMOTE_PROC_NODE_DEVICE_LOOKUP_BY_NAME = 113,
    REMOTE_PROC_NODE_DEVICE_DUMP_XML = 114,
    REMOTE_PROC_NODE_DEVICE_GET_PARENT = 115,
    REMOTE_PROC_NODE_DEVICE_NUM_OF_CAPS = 116,
    REMOTE_PROC_NODE_DEVICE_LIST_CAPS = 117,
    REMOTE_PROC_NODE_DEVICE_DETTACH = 118,
    REMOTE_PROC_NODE_DEVICE_RE_ATTACH = 119,
    REMOTE_PROC_NODE_DEVICE_RESET = 120,

    REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL = 121,
    REMOTE_PROC_NODE_GET_SECURITY_MODEL = 122,
    REMOTE_PROC_NODE_DEVICE_CREATE_XML = 123,
    REMOTE_PROC_NODE_DEVICE_DESTROY = 124,
    REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM = 125,
    REMOTE_PROC_NUM_OF_INTERFACES = 126,
    REMOTE_PROC_LIST_INTERFACES = 127,
    REMOTE_PROC_INTERFACE_LOOKUP_BY_NAME = 128,
    REMOTE_PROC_INTERFACE_LOOKUP_BY_MAC_STRING = 129,
    REMOTE_PROC_INTERFACE_GET_XML_DESC = 130,

    REMOTE_PROC_INTERFACE_DEFINE_XML = 131,
    REMOTE_PROC_INTERFACE_UNDEFINE = 132,
    REMOTE_PROC_INTERFACE_CREATE = 133,
    REMOTE_PROC_INTERFACE_DESTROY = 134,
    REMOTE_PROC_DOMAIN_XML_FROM_NATIVE = 135,
    REMOTE_PROC_DOMAIN_XML_TO_NATIVE = 136,
    REMOTE_PROC_NUM_OF_DEFINED_INTERFACES = 137,
    REMOTE_PROC_LIST_DEFINED_INTERFACES = 138,
    REMOTE_PROC_NUM_OF_SECRETS = 139,
    REMOTE_PROC_LIST_SECRETS = 140,

    REMOTE_PROC_SECRET_LOOKUP_BY_UUID = 141,
    REMOTE_PROC_SECRET_DEFINE_XML = 142,
    REMOTE_PROC_SECRET_GET_XML_DESC = 143,
    REMOTE_PROC_SECRET_SET_VALUE = 144,
    REMOTE_PROC_SECRET_GET_VALUE = 145,
    REMOTE_PROC_SECRET_UNDEFINE = 146,
    REMOTE_PROC_SECRET_LOOKUP_BY_USAGE = 147,
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL = 148,
    REMOTE_PROC_IS_SECURE = 149,
    REMOTE_PROC_DOMAIN_IS_ACTIVE = 150,

    REMOTE_PROC_DOMAIN_IS_PERSISTENT = 151,
    REMOTE_PROC_NETWORK_IS_ACTIVE = 152,
    REMOTE_PROC_NETWORK_IS_PERSISTENT = 153,
    REMOTE_PROC_STORAGE_POOL_IS_ACTIVE = 154,
    REMOTE_PROC_STORAGE_POOL_IS_PERSISTENT = 155,
    REMOTE_PROC_INTERFACE_IS_ACTIVE = 156,
    REMOTE_PROC_GET_LIB_VERSION = 157,
    REMOTE_PROC_CPU_COMPARE = 158,
    REMOTE_PROC_DOMAIN_MEMORY_STATS = 159,
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS = 160,

    REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS = 161,
    REMOTE_PROC_CPU_BASELINE = 162,
    REMOTE_PROC_DOMAIN_GET_JOB_INFO = 163,
    REMOTE_PROC_DOMAIN_ABORT_JOB = 164,
    REMOTE_PROC_STORAGE_VOL_WIPE = 165,
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_DOWNTIME = 166,
    REMOTE_PROC_DOMAIN_EVENTS_REGISTER_ANY = 167,
    REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER_ANY = 168,
    REMOTE_PROC_DOMAIN_EVENT_REBOOT = 169,
    REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE = 170,

    REMOTE_PROC_DOMAIN_EVENT_WATCHDOG = 171,
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR = 172,
    REMOTE_PROC_DOMAIN_EVENT_GRAPHICS = 173,
    REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS = 174,
    REMOTE_PROC_NWFILTER_LOOKUP_BY_NAME = 175,
    REMOTE_PROC_NWFILTER_LOOKUP_BY_UUID = 176,
    REMOTE_PROC_NWFILTER_GET_XML_DESC = 177,
    REMOTE_PROC_NUM_OF_NWFILTERS = 178,
    REMOTE_PROC_LIST_NWFILTERS = 179,
    REMOTE_PROC_NWFILTER_DEFINE_XML = 180,

    REMOTE_PROC_NWFILTER_UNDEFINE = 181,
    REMOTE_PROC_DOMAIN_MANAGED_SAVE = 182,
    REMOTE_PROC_DOMAIN_HAS_MANAGED_SAVE_IMAGE = 183,
    REMOTE_PROC_DOMAIN_MANAGED_SAVE_REMOVE = 184,
    REMOTE_PROC_DOMAIN_SNAPSHOT_CREATE_XML = 185,
    REMOTE_PROC_DOMAIN_SNAPSHOT_DUMP_XML = 186,
    REMOTE_PROC_DOMAIN_SNAPSHOT_NUM = 187,
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_NAMES = 188,
    REMOTE_PROC_DOMAIN_SNAPSHOT_LOOKUP_BY_NAME = 189,
    REMOTE_PROC_DOMAIN_HAS_CURRENT_SNAPSHOT = 190,

    REMOTE_PROC_DOMAIN_SNAPSHOT_CURRENT = 191,
    REMOTE_PROC_DOMAIN_REVERT_TO_SNAPSHOT = 192,
    REMOTE_PROC_DOMAIN_SNAPSHOT_DELETE = 193,
    REMOTE_PROC_DOMAIN_GET_BLOCK_INFO = 194,
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON = 195,
    REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS = 196,
    REMOTE_PROC_DOMAIN_SET_MEMORY_PARAMETERS = 197,
    REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS = 198,
    REMOTE_PROC_DOMAIN_SET_VCPUS_FLAGS = 199,
    REMOTE_PROC_DOMAIN_GET_VCPUS_FLAGS = 200,

    REMOTE_PROC_DOMAIN_OPEN_CONSOLE = 201,
    REMOTE_PROC_DOMAIN_IS_UPDATED = 202,
    REMOTE_PROC_GET_SYSINFO = 203,
    REMOTE_PROC_DOMAIN_SET_MEMORY_FLAGS = 204,
    REMOTE_PROC_DOMAIN_SET_BLKIO_PARAMETERS = 205,
    REMOTE_PROC_DOMAIN_GET_BLKIO_PARAMETERS = 206,
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_SPEED = 207

    /*
     * Notice how the entries are grouped in sets of 10 ?
     * Nice isn't it. Please keep it this way when adding more.
     */
};

/*
 * RPC wire format
 *
 * Each message consists of:
 *
 *    Name    | Type                  | Description
 * -----------+-----------------------+------------------
 *    Length  | int                   | Total number of bytes in message _including_ length.
 *    Header  | remote_message_header | Control information about procedure call
 *    Payload | -                     | Variable payload data per procedure
 *
 * In header, the 'serial' field varies according to:
 *
 *  - type == REMOTE_CALL
 *      * serial is set by client, incrementing by 1 each time
 *
 *  - type == REMOTE_REPLY
 *      * serial matches that from the corresponding REMOTE_CALL
 *
 *  - type == REMOTE_MESSAGE
 *      * serial is always zero
 *
 *  - type == REMOTE_STREAM
 *      * serial matches that from the corresponding REMOTE_CALL
 *
 * and the 'status' field varies according to:
 *
 *  - type == REMOTE_CALL
 *     * REMOTE_OK always
 *
 *  - type == REMOTE_REPLY
 *     * REMOTE_OK if RPC finished successfully
 *     * REMOTE_ERROR if something failed
 *
 *  - type == REMOTE_MESSAGE
 *     * REMOTE_OK always
 *
 *  - type == REMOTE_STREAM
 *     * REMOTE_CONTINUE if more data is following
 *     * REMOTE_OK if stream is complete
 *     * REMOTE_ERROR if stream had an error
 *
 * Payload varies according to type and status:
 *
 *  - type == REMOTE_CALL
 *          XXX_args  for procedure
 *
 *  - type == REMOTE_REPLY
 *     * status == REMOTE_OK
 *          XXX_ret         for procedure
 *     * status == REMOTE_ERROR
 *          remote_error    Error information
 *
 *  - type == REMOTE_MESSAGE
 *     * status == REMOTE_OK
 *          XXX_args        for procedure
 *     * status == REMOTE_ERROR
 *          remote_error    Error information
 *
 *  - type == REMOTE_STREAM
 *     * status == REMOTE_CONTINUE
 *          byte[]       raw stream data
 *     * status == REMOTE_ERROR
 *          remote_error error information
 *     * status == REMOTE_OK
 *          <empty>
 */
enum remote_message_type {
    /* client -> server. args from a method call */
    REMOTE_CALL = 0,
    /* server -> client. reply/error from a method call */
    REMOTE_REPLY = 1,
    /* either direction. async notification */
    REMOTE_MESSAGE = 2,
    /* either direction. stream data packet */
    REMOTE_STREAM = 3
};

enum remote_message_status {
    /* Status is always REMOTE_OK for calls.
     * For replies, indicates no error.
     */
    REMOTE_OK = 0,

    /* For replies, indicates that an error happened, and a struct
     * remote_error follows.
     */
    REMOTE_ERROR = 1,

    /* For streams, indicates that more data is still expected
     */
    REMOTE_CONTINUE = 2
};

/* 4 byte length word per header */
const REMOTE_MESSAGE_HEADER_XDR_LEN = 4;

struct remote_message_header {
    unsigned prog;              /* REMOTE_PROGRAM */
    unsigned vers;              /* REMOTE_PROTOCOL_VERSION */
    int proc;      /* REMOTE_PROC_x */
    remote_message_type type;
    unsigned serial;            /* Serial number of message. */
    remote_message_status status;
};
