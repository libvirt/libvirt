/* -*- c -*-
 * remote_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

%#include <libvirt/libvirt.h>
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
const REMOTE_MIGRATE_COOKIE_MAX = 16384;

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

/* Upper limit on list of blockio tuning parameters. */
const REMOTE_DOMAIN_BLOCK_IO_TUNE_PARAMETERS_MAX = 16;

/* Upper limit on list of numa parameters. */
const REMOTE_DOMAIN_NUMA_PARAMETERS_MAX = 16;

/* Upper limit on list of node cpu stats. */
const REMOTE_NODE_CPU_STATS_MAX = 16;

/* Upper limit on list of node memory stats. */
const REMOTE_NODE_MEMORY_STATS_MAX = 16;

/* Upper limit on list of block stats. */
const REMOTE_DOMAIN_BLOCK_STATS_PARAMETERS_MAX = 16;

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

/*
 * Max number of sending keycodes.
 */
const REMOTE_DOMAIN_SEND_KEY_MAX = 16;

/*
 * Upper limit on list of interface parameters
 */
const REMOTE_DOMAIN_INTERFACE_PARAMETERS_MAX = 16;

/*
 * Upper limit on cpus involved in per-cpu stats
 */
const REMOTE_DOMAIN_GET_CPU_STATS_NCPUS_MAX = 128;

/*
 * Upper limit on list of per-cpu stats:
 *  REMOTE_NODE_CPU_STATS_MAX * REMOTE_DOMAIN_GET_CPU_STATS_MAX
 */
const REMOTE_DOMAIN_GET_CPU_STATS_MAX = 2048;

/*
 * Upper limit on number of disks with errors
 */
const REMOTE_DOMAIN_DISK_ERRORS_MAX = 256;

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
    remote_nonnull_domain dom;
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

/* Wire encoding of virTypedParameter.
 * Note the enum (type) which must remain binary compatible.
 */
union remote_typed_param_value switch (int type) {
 case VIR_TYPED_PARAM_INT:
     int i;
 case VIR_TYPED_PARAM_UINT:
     unsigned int ui;
 case VIR_TYPED_PARAM_LLONG:
     hyper l;
 case VIR_TYPED_PARAM_ULLONG:
     unsigned hyper ul;
 case VIR_TYPED_PARAM_DOUBLE:
     double d;
 case VIR_TYPED_PARAM_BOOLEAN:
     int b;
 case VIR_TYPED_PARAM_STRING:
     remote_nonnull_string s;
};

struct remote_typed_param {
    remote_nonnull_string field;
    remote_typed_param_value value;
};

struct remote_node_get_cpu_stats {
    remote_nonnull_string field;
    unsigned hyper value;
};

struct remote_node_get_memory_stats {
    remote_nonnull_string field;
    unsigned hyper value;
};

struct remote_domain_disk_error {
    remote_nonnull_string disk;
    int error;
};

/*----- Calls. -----*/

/* For each call we may have a 'remote_CALL_args' and 'remote_CALL_ret'
 * type.  These are omitted when they are void.  The virConnectPtr
 * is not passed at all (it is inferred on the remote server from the
 * connection).  Errors are returned implicitly in the RPC protocol.
 *
 * Please follow the naming convention carefully - this file is
 * parsed by 'gendispatch.pl'.
 *
 * 'remote_CALL_ret' members that are filled via call-by-reference must be
 * annotated with a insert@<offset> comment to indicate the offset in the
 * parameter list of the function to be called.
 *
 * If the 'remote_CALL_ret' maps to a struct in the public API then it is
 * also filled via call-by-reference and must be annotated with a
 * insert@<offset> comment to indicate the offset in the parameter list of
 * the function to be called.
 *
 * Dynamic opaque and remote_nonnull_string arrays can be annotated with an
 * optional typecast */

struct remote_open_args {
    /* NB. "name" might be NULL although in practice you can't
     * yet do that using the remote_internal driver.
     */
    remote_string name;
    unsigned int flags;
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
    unsigned hyper hv_ver;
};

struct remote_get_lib_version_ret {
    unsigned hyper lib_ver;
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

struct remote_node_get_info_ret { /* insert@1 */
    char model[32];
    unsigned hyper memory;
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

struct remote_node_get_cpu_stats_args {
    int cpuNum;
    int nparams;
    unsigned int flags;
};

struct remote_node_get_cpu_stats_ret {
    remote_node_get_cpu_stats params<REMOTE_NODE_CPU_STATS_MAX>;
    int nparams;
};

struct remote_node_get_memory_stats_args {
    int nparams;
    int cellNum;
    unsigned int flags;
};

struct remote_node_get_memory_stats_ret {
    remote_node_get_memory_stats params<REMOTE_NODE_MEMORY_STATS_MAX>;
    int nparams;
};

struct remote_node_get_cells_free_memory_args {
    int startCell;
    int maxcells;
};

struct remote_node_get_cells_free_memory_ret {
    unsigned hyper cells<REMOTE_NODE_MAX_CELLS>; /* insert@1 */
};

struct remote_node_get_free_memory_ret {
    unsigned hyper freeMem;
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
    int nparams; /* call-by-reference */
};

struct remote_domain_get_scheduler_parameters_ret {
    remote_typed_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>; /* insert@1 */
};

struct remote_domain_get_scheduler_parameters_flags_args {
    remote_nonnull_domain dom;
    int nparams; /* call-by-reference */
    unsigned int flags;
};

struct remote_domain_get_scheduler_parameters_flags_ret {
    remote_typed_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>; /* insert@1 */
};

struct remote_domain_set_scheduler_parameters_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>;
};

struct remote_domain_set_scheduler_parameters_flags_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_set_blkio_parameters_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_blkio_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_blkio_parameters_ret {
    remote_typed_param params<REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_set_memory_parameters_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_memory_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_memory_parameters_ret {
    remote_typed_param params<REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_block_resize_args {
    remote_nonnull_domain dom;
    remote_nonnull_string disk;
    unsigned hyper size;
    unsigned int flags;
};

struct remote_domain_set_numa_parameters_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_NUMA_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_numa_parameters_args {
    remote_nonnull_domain dom;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_numa_parameters_ret {
    remote_typed_param params<REMOTE_DOMAIN_NUMA_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_block_stats_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
};

struct remote_domain_block_stats_ret { /* insert@2 */
    hyper rd_req;
    hyper rd_bytes;
    hyper wr_req;
    hyper wr_bytes;
    hyper errs;
};

struct remote_domain_block_stats_flags_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    int nparams;
    unsigned int flags;
};

struct remote_domain_block_stats_flags_ret {
    remote_typed_param params<REMOTE_DOMAIN_BLOCK_STATS_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_interface_stats_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
};

struct remote_domain_interface_stats_ret { /* insert@2 */
    hyper rx_bytes;
    hyper rx_packets;
    hyper rx_errs;
    hyper rx_drop;
    hyper tx_bytes;
    hyper tx_packets;
    hyper tx_errs;
    hyper tx_drop;
};

struct remote_domain_set_interface_parameters_args {
    remote_nonnull_domain dom;
    remote_nonnull_string device;
    remote_typed_param params<REMOTE_DOMAIN_INTERFACE_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_interface_parameters_args {
    remote_nonnull_domain dom;
    remote_nonnull_string device;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_interface_parameters_ret {
    remote_typed_param params<REMOTE_DOMAIN_INTERFACE_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_memory_stats_args {
    remote_nonnull_domain dom;
    unsigned int maxStats;
    unsigned int flags;
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
    unsigned int size;
    unsigned int flags;
};

struct remote_domain_block_peek_ret {
    opaque buffer<REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX>;
};

struct remote_domain_memory_peek_args {
    remote_nonnull_domain dom;
    unsigned hyper offset;
    unsigned int size;
    unsigned int flags;
};

struct remote_domain_memory_peek_ret {
    opaque buffer<REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX>;
};

struct remote_domain_get_block_info_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned int flags;
};

struct remote_domain_get_block_info_ret { /* insert@2 */
    unsigned hyper allocation;
    unsigned hyper capacity;
    unsigned hyper physical;
};

struct remote_list_domains_args {
    int maxids;
};

struct remote_list_domains_ret {
    int ids<REMOTE_DOMAIN_ID_LIST_MAX>; /* insert@1 */
};

struct remote_num_of_domains_ret {
    int num;
};

struct remote_domain_create_xml_args {
    remote_nonnull_string xml_desc;
    unsigned int flags;
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

struct remote_domain_pm_suspend_for_duration_args {
    remote_nonnull_domain dom;
    unsigned int target;
    unsigned hyper duration;
    unsigned int flags;
};

struct remote_domain_pm_wakeup_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_shutdown_args {
    remote_nonnull_domain dom;
};

struct remote_domain_reboot_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_reset_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_destroy_args {
    remote_nonnull_domain dom;
};

struct remote_domain_destroy_flags_args {
    remote_nonnull_domain dom;
    unsigned int flags;
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

struct remote_domain_get_info_ret { /* insert@1 */
    unsigned char state;
    unsigned hyper maxMem;
    unsigned hyper memory;
    unsigned short nrVirtCpu;
    unsigned hyper cpuTime;
};

struct remote_domain_save_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
};

struct remote_domain_save_flags_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
    remote_string dxml;
    unsigned int flags;
};

struct remote_domain_restore_args {
    remote_nonnull_string from;
};

struct remote_domain_restore_flags_args {
    remote_nonnull_string from;
    remote_string dxml;
    unsigned int flags;
};

struct remote_domain_save_image_get_xml_desc_args {
    remote_nonnull_string file;
    unsigned int flags;
};

struct remote_domain_save_image_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_domain_save_image_define_xml_args {
    remote_nonnull_string file;
    remote_nonnull_string dxml;
    unsigned int flags;
};

struct remote_domain_core_dump_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
    unsigned int flags;
};

struct remote_domain_screenshot_args {
    remote_nonnull_domain dom;
    unsigned int screen;
    unsigned int flags;
};

struct remote_domain_screenshot_ret {
    remote_string mime;
};

struct remote_domain_get_xml_desc_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_xml_desc_ret {
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
    remote_nonnull_string names<REMOTE_DOMAIN_NAME_LIST_MAX>; /* insert@1 */
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

struct remote_domain_undefine_flags_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_inject_nmi_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_send_key_args {
    remote_nonnull_domain dom;
    unsigned int codeset;
    unsigned int holdtime;
    unsigned int keycodes<REMOTE_DOMAIN_SEND_KEY_MAX>;
    unsigned int flags;
};

struct remote_domain_set_vcpus_args {
    remote_nonnull_domain dom;
    unsigned int nvcpus;
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
    unsigned int vcpu;
    opaque cpumap<REMOTE_CPUMAP_MAX>; /* (unsigned char *) */
};

struct remote_domain_pin_vcpu_flags_args {
    remote_nonnull_domain dom;
    unsigned int vcpu;
    opaque cpumap<REMOTE_CPUMAP_MAX>; /* (unsigned char *) */
    unsigned int flags;
};

struct remote_domain_get_vcpu_pin_info_args {
    remote_nonnull_domain dom;
    int ncpumaps;
    int maplen;
    unsigned int flags;
};

struct remote_domain_get_vcpu_pin_info_ret {
    opaque cpumaps<REMOTE_CPUMAPS_MAX>;
    int num;
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

struct remote_domain_set_metadata_args {
    remote_nonnull_domain dom;
    int type;
    remote_string metadata;
    remote_string key;
    remote_string uri;
    unsigned int flags;
};

struct remote_domain_get_metadata_args {
    remote_nonnull_domain dom;
    int type;
    remote_string uri;
    unsigned int flags;
};

struct remote_domain_get_metadata_ret {
    remote_nonnull_string metadata;
};

struct remote_domain_block_job_abort_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned int flags;
};

struct remote_domain_get_block_job_info_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned int flags;
};

struct remote_domain_get_block_job_info_ret {
    int found;
    int type;
    unsigned hyper bandwidth;
    unsigned hyper cur;
    unsigned hyper end;
};

struct remote_domain_block_job_set_speed_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned hyper bandwidth;
    unsigned int flags;
};

struct remote_domain_block_pull_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    unsigned hyper bandwidth;
    unsigned int flags;
};
struct remote_domain_block_rebase_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    remote_string base;
    unsigned hyper bandwidth;
    unsigned int flags;
};

struct remote_domain_set_block_io_tune_args {
    remote_nonnull_domain dom;
    remote_nonnull_string disk;
    remote_typed_param params<REMOTE_DOMAIN_BLOCK_IO_TUNE_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_block_io_tune_args {
    remote_nonnull_domain dom;
    remote_string disk;
    int nparams;
    unsigned int flags;
};

struct remote_domain_get_block_io_tune_ret {
    remote_typed_param params<REMOTE_DOMAIN_BLOCK_IO_TUNE_PARAMETERS_MAX>;
    int nparams;
};

struct remote_domain_get_cpu_stats_args {
    remote_nonnull_domain dom;
    unsigned int nparams;
    int          start_cpu;
    unsigned int ncpus;
    unsigned int flags;
};

struct remote_domain_get_cpu_stats_ret {
    remote_typed_param params<REMOTE_DOMAIN_GET_CPU_STATS_MAX>;
    int nparams;
};

/* Network calls: */

struct remote_num_of_networks_ret {
    int num;
};

struct remote_list_networks_args {
    int maxnames;
};

struct remote_list_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_NAME_LIST_MAX>; /* insert@1 */
};

struct remote_num_of_defined_networks_ret {
    int num;
};

struct remote_list_defined_networks_args {
    int maxnames;
};

struct remote_list_defined_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_NAME_LIST_MAX>; /* insert@1 */
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

struct remote_network_get_xml_desc_args {
    remote_nonnull_network net;
    unsigned int flags;
};

struct remote_network_get_xml_desc_ret {
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
    remote_nonnull_string names<REMOTE_NWFILTER_NAME_LIST_MAX>; /* insert@1 */
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
    unsigned int flags;
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
    remote_nonnull_string names<REMOTE_INTERFACE_NAME_LIST_MAX>; /* insert@1 */
};

struct remote_num_of_defined_interfaces_ret {
    int num;
};

struct remote_list_defined_interfaces_args {
    int maxnames;
};

struct remote_list_defined_interfaces_ret {
    remote_nonnull_string names<REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX>; /* insert@1 */
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

struct remote_interface_change_begin_args {
    unsigned int flags;
};

struct remote_interface_change_commit_args {
    unsigned int flags;
};

struct remote_interface_change_rollback_args {
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
    remote_nonnull_string names<REMOTE_STORAGE_POOL_NAME_LIST_MAX>; /* insert@1 */
};

struct remote_num_of_defined_storage_pools_ret {
    int num;
};

struct remote_list_defined_storage_pools_args {
    int maxnames;
};

struct remote_list_defined_storage_pools_ret {
    remote_nonnull_string names<REMOTE_STORAGE_POOL_NAME_LIST_MAX>; /* insert@1 */
};

struct remote_find_storage_pool_sources_args {
    remote_nonnull_string type;
    remote_string srcSpec;
    unsigned int flags;
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
    unsigned int flags;
};

struct remote_storage_pool_create_xml_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_define_xml_args {
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_storage_pool_define_xml_ret {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_build_args {
    remote_nonnull_storage_pool pool;
    unsigned int flags;
};

struct remote_storage_pool_undefine_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_create_args {
    remote_nonnull_storage_pool pool;
    unsigned int flags;
};

struct remote_storage_pool_destroy_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_delete_args {
    remote_nonnull_storage_pool pool;
    unsigned int flags;
};

struct remote_storage_pool_refresh_args {
    remote_nonnull_storage_pool pool;
    unsigned int flags;
};

struct remote_storage_pool_get_xml_desc_args {
    remote_nonnull_storage_pool pool;
    unsigned int flags;
};

struct remote_storage_pool_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_storage_pool_get_info_args {
    remote_nonnull_storage_pool pool;
};

struct remote_storage_pool_get_info_ret { /* insert@1 */
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
    remote_nonnull_string names<REMOTE_STORAGE_VOL_NAME_LIST_MAX>; /* insert@1 */
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
    unsigned int flags;
};

struct remote_storage_vol_create_xml_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_create_xml_from_args {
    remote_nonnull_storage_pool pool;
    remote_nonnull_string xml;
    remote_nonnull_storage_vol clonevol;
    unsigned int flags;
};

struct remote_storage_vol_create_xml_from_ret {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_delete_args {
    remote_nonnull_storage_vol vol;
    unsigned int flags;
};

struct remote_storage_vol_wipe_args {
    remote_nonnull_storage_vol vol;
    unsigned int flags;
};

struct remote_storage_vol_wipe_pattern_args {
    remote_nonnull_storage_vol vol;
    unsigned int algorithm;
    unsigned int flags;
};

struct remote_storage_vol_get_xml_desc_args {
    remote_nonnull_storage_vol vol;
    unsigned int flags;
};

struct remote_storage_vol_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_storage_vol_get_info_args {
    remote_nonnull_storage_vol vol;
};

struct remote_storage_vol_get_info_ret { /* insert@1 */
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

struct remote_storage_vol_resize_args {
    remote_nonnull_storage_vol vol;
    unsigned hyper capacity;
    unsigned int flags;
};

/* Node driver calls: */

struct remote_node_num_of_devices_args {
    remote_string cap;
    unsigned int flags;
};

struct remote_node_num_of_devices_ret {
    int num;
};

struct remote_node_list_devices_args {
    remote_string cap;
    int maxnames;
    unsigned int flags;
};

struct remote_node_list_devices_ret {
    remote_nonnull_string names<REMOTE_NODE_DEVICE_NAME_LIST_MAX>; /* insert@2 */
};

struct remote_node_device_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_node_device_lookup_by_name_ret {
    remote_nonnull_node_device dev;
};

struct remote_node_device_get_xml_desc_args {
    remote_nonnull_string name;
    unsigned int flags;
};

struct remote_node_device_get_xml_desc_ret {
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
    remote_nonnull_string names<REMOTE_NODE_DEVICE_CAPS_LIST_MAX>; /* insert@1 */
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
    unsigned int flags;
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
    unsigned int flags;
};

struct remote_domain_xml_from_native_ret {
    remote_nonnull_string domainXml;
};


struct remote_domain_xml_to_native_args {
    remote_nonnull_string nativeFormat;
    remote_nonnull_string domainXml;
    unsigned int flags;
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
    remote_nonnull_string uuids<REMOTE_SECRET_UUID_LIST_MAX>; /* insert@1 */
};

struct remote_secret_lookup_by_uuid_args {
    remote_uuid uuid;
};

struct remote_secret_lookup_by_uuid_ret {
    remote_nonnull_secret secret;
};

struct remote_secret_define_xml_args {
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_secret_define_xml_ret {
    remote_nonnull_secret secret;
};

struct remote_secret_get_xml_desc_args {
    remote_nonnull_secret secret;
    unsigned int flags;
};

struct remote_secret_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_secret_set_value_args {
    remote_nonnull_secret secret;
    opaque value<REMOTE_SECRET_VALUE_MAX>; /* (const unsigned char *) */
    unsigned int flags;
};

struct remote_secret_get_value_args {
    remote_nonnull_secret secret;
    unsigned int flags;
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
    unsigned int flags;
};

struct remote_cpu_compare_ret {
    int result;
};


struct remote_cpu_baseline_args {
    remote_nonnull_string xmlCPUs<REMOTE_CPU_BASELINE_MAX>; /* (const char **) */
    unsigned int flags;
};

struct remote_cpu_baseline_ret {
    remote_nonnull_string cpu;
};


struct remote_domain_get_job_info_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_job_info_ret { /* insert@1 */
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
    unsigned int flags;
};

struct remote_domain_migrate_set_max_speed_args {
    remote_nonnull_domain dom;
    unsigned hyper bandwidth;
    unsigned int flags;
};

struct remote_domain_migrate_get_max_speed_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_migrate_get_max_speed_ret {
     unsigned hyper bandwidth; /* insert@1 */
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

struct remote_domain_event_block_job_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    int type;
    int status;
};

struct remote_domain_event_disk_change_msg {
    remote_nonnull_domain dom;
    remote_string oldSrcPath;
    remote_string newSrcPath;
    remote_nonnull_string devAlias;
    int reason;
};

struct remote_domain_event_tray_change_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string devAlias;
    int reason;
};

struct remote_domain_event_pmwakeup_msg {
    remote_nonnull_domain dom;
};

struct remote_domain_event_pmsuspend_msg {
    remote_nonnull_domain dom;
};

struct remote_domain_managed_save_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_has_managed_save_image_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_has_managed_save_image_ret {
    int result;
};

struct remote_domain_managed_save_remove_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_snapshot_create_xml_args {
    remote_nonnull_domain dom;
    remote_nonnull_string xml_desc;
    unsigned int flags;
};

struct remote_domain_snapshot_create_xml_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_snapshot_get_xml_desc_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_get_xml_desc_ret {
    remote_nonnull_string xml;
};

struct remote_domain_snapshot_num_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_snapshot_num_ret {
    int num;
};

struct remote_domain_snapshot_list_names_args {
    remote_nonnull_domain dom;
    int maxnames;
    unsigned int flags;
};

struct remote_domain_snapshot_list_names_ret {
    remote_nonnull_string names<REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX>; /* insert@1 */
};

struct remote_domain_snapshot_num_children_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_num_children_ret {
    int num;
};

struct remote_domain_snapshot_list_children_names_args {
    remote_nonnull_domain_snapshot snap;
    int maxnames;
    unsigned int flags;
};

struct remote_domain_snapshot_list_children_names_ret {
    remote_nonnull_string names<REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX>; /* insert@1 */
};

struct remote_domain_snapshot_lookup_by_name_args {
    remote_nonnull_domain dom;
    remote_nonnull_string name;
    unsigned int flags;
};

struct remote_domain_snapshot_lookup_by_name_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_has_current_snapshot_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_has_current_snapshot_ret {
    int result;
};

struct remote_domain_snapshot_get_parent_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_get_parent_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_snapshot_current_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_snapshot_current_ret {
    remote_nonnull_domain_snapshot snap;
};

struct remote_domain_revert_to_snapshot_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_delete_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_open_console_args {
    remote_nonnull_domain dom;
    remote_string dev_name;
    unsigned int flags;
};

struct remote_storage_vol_upload_args {
    remote_nonnull_storage_vol vol;
    unsigned hyper offset;
    unsigned hyper length;
    unsigned int flags;
};

struct remote_storage_vol_download_args {
    remote_nonnull_storage_vol vol;
    unsigned hyper offset;
    unsigned hyper length;
    unsigned int flags;
};

struct remote_domain_get_state_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_state_ret {
    int state;
    int reason;
};

struct remote_domain_migrate_begin3_args {
    remote_nonnull_domain dom;
    remote_string xmlin;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
};

struct remote_domain_migrate_begin3_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_nonnull_string xml;
};

struct remote_domain_migrate_prepare3_args {
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string uri_in;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
    remote_nonnull_string dom_xml;
};

struct remote_domain_migrate_prepare3_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string uri_out;
};

struct remote_domain_migrate_prepare_tunnel3_args {
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
    remote_nonnull_string dom_xml;
};

struct remote_domain_migrate_prepare_tunnel3_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>; /* insert@3 */
};

struct remote_domain_migrate_perform3_args {
    remote_nonnull_domain dom;
    remote_string xmlin;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string dconnuri;
    remote_string uri;
    unsigned hyper flags;
    remote_string dname;
    unsigned hyper resource;
};

struct remote_domain_migrate_perform3_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
};

struct remote_domain_migrate_finish3_args {
    remote_nonnull_string dname;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string dconnuri;
    remote_string uri;
    unsigned hyper flags;
    int cancelled;
};

struct remote_domain_migrate_finish3_ret {
    remote_nonnull_domain dom;
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
};

struct remote_domain_migrate_confirm3_args {
    remote_nonnull_domain dom;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned hyper flags;
    int cancelled;
};

struct remote_domain_event_control_error_msg {
    remote_nonnull_domain dom;
};

struct remote_domain_get_control_info_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_control_info_ret { /* insert@1 */
    unsigned int state;
    unsigned int details;
    unsigned hyper stateTime;
};

struct remote_domain_open_graphics_args {
    remote_nonnull_domain dom;
    unsigned int idx;
    unsigned int flags;
};

struct remote_node_suspend_for_duration_args {
    unsigned int target;
    unsigned hyper duration;
    unsigned int flags;
};

struct remote_domain_shutdown_flags_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_disk_errors_args {
    remote_nonnull_domain dom;
    unsigned int maxerrors;
    unsigned int flags;
};

struct remote_domain_get_disk_errors_ret {
    remote_domain_disk_error errors<REMOTE_DOMAIN_DISK_ERRORS_MAX>;
    int nerrors;
};


/*----- Protocol. -----*/

/* Define the program number, protocol version and procedure numbers here. */
const REMOTE_PROGRAM = 0x20008086;
const REMOTE_PROTOCOL_VERSION = 1;

enum remote_procedure {
    /* Each function must have a three-word comment.  The first word is
     * whether gendispatch.pl handles daemon, the second whether
     * it handles src/remote.  Additional flags can be specified after a
     * pipe.
     * The last argument describes priority of API. There are two accepted
     * values: low, high; Each API that might eventually access hypervisor's
     * monitor (and thus block) MUST fall into low priority. However, there
     * are some exceptions to this rule, e.g. domainDestroy. Other APIs MAY
     * be marked as high priority. If in doubt, it's safe to choose low.
     * Low is taken as default, and thus can be left out.
     *
     * The (readstream|writestream)@<offset> flag lets daemon and src/remote
     * create a stream.  The direction is defined from the src/remote point
     * of view.  A readstream transfers data from daemon to src/remote.  The
     * <offset> specifies at which offset the stream parameter is inserted
     * in the function parameter list. */
    REMOTE_PROC_OPEN = 1, /* skipgen skipgen priority:high */
    REMOTE_PROC_CLOSE = 2, /* skipgen skipgen priority:high */
    REMOTE_PROC_GET_TYPE = 3, /* autogen skipgen priority:high */
    REMOTE_PROC_GET_VERSION = 4, /* autogen autogen priority:high */
    REMOTE_PROC_GET_MAX_VCPUS = 5, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_GET_INFO = 6, /* autogen autogen priority:high */
    REMOTE_PROC_GET_CAPABILITIES = 7, /* autogen autogen */
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE = 8, /* autogen autogen */
    REMOTE_PROC_DOMAIN_CREATE = 9, /* autogen skipgen */
    REMOTE_PROC_DOMAIN_CREATE_XML = 10, /* autogen autogen */

    REMOTE_PROC_DOMAIN_DEFINE_XML = 11, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_DESTROY = 12, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_DETACH_DEVICE = 13, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_XML_DESC = 14, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_AUTOSTART = 15, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_GET_INFO = 16, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_MAX_MEMORY = 17, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_GET_MAX_VCPUS = 18, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_GET_OS_TYPE = 19, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_GET_VCPUS = 20, /* skipgen skipgen priority:high */

    REMOTE_PROC_LIST_DEFINED_DOMAINS = 21, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_ID = 22, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_NAME = 23, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID = 24, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_DEFINED_DOMAINS = 25, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_PIN_VCPU = 26, /* autogen autogen */
    REMOTE_PROC_DOMAIN_REBOOT = 27, /* autogen autogen */
    REMOTE_PROC_DOMAIN_RESUME = 28, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SET_AUTOSTART = 29, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SET_MAX_MEMORY = 30, /* autogen autogen priority:high */

    REMOTE_PROC_DOMAIN_SET_MEMORY = 31, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SET_VCPUS = 32, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SHUTDOWN = 33, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SUSPEND = 34, /* autogen autogen */
    REMOTE_PROC_DOMAIN_UNDEFINE = 35, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_DEFINED_NETWORKS = 36, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_DOMAINS = 37, /* autogen skipgen priority:high */
    REMOTE_PROC_LIST_NETWORKS = 38, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_CREATE = 39, /* autogen autogen */
    REMOTE_PROC_NETWORK_CREATE_XML = 40, /* autogen autogen */

    REMOTE_PROC_NETWORK_DEFINE_XML = 41, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_DESTROY = 42, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_GET_XML_DESC = 43, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_GET_AUTOSTART = 44, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_GET_BRIDGE_NAME = 45, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_LOOKUP_BY_NAME = 46, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_LOOKUP_BY_UUID = 47, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_SET_AUTOSTART = 48, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_UNDEFINE = 49, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_DEFINED_NETWORKS = 50, /* autogen autogen priority:high */

    REMOTE_PROC_NUM_OF_DOMAINS = 51, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_NETWORKS = 52, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_CORE_DUMP = 53, /* autogen autogen */
    REMOTE_PROC_DOMAIN_RESTORE = 54, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SAVE = 55, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE = 56, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS = 57, /* skipgen autogen */
    REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS = 58, /* autogen autogen */
    REMOTE_PROC_GET_HOSTNAME = 59, /* autogen autogen priority:high */
    REMOTE_PROC_SUPPORTS_FEATURE = 60, /* skipgen autogen priority:high */

    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE = 61, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM = 62, /* autogen autogen */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH = 63, /* autogen autogen */
    REMOTE_PROC_DOMAIN_BLOCK_STATS = 64, /* autogen autogen */
    REMOTE_PROC_DOMAIN_INTERFACE_STATS = 65, /* autogen autogen priority:high */
    REMOTE_PROC_AUTH_LIST = 66, /* skipgen skipgen priority:high */
    REMOTE_PROC_AUTH_SASL_INIT = 67, /* skipgen skipgen priority:high */
    REMOTE_PROC_AUTH_SASL_START = 68, /* skipgen skipgen priority:high */
    REMOTE_PROC_AUTH_SASL_STEP = 69, /* skipgen skipgen priority:high */
    REMOTE_PROC_AUTH_POLKIT = 70, /* skipgen skipgen priority:high */

    REMOTE_PROC_NUM_OF_STORAGE_POOLS = 71, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_STORAGE_POOLS = 72, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_DEFINED_STORAGE_POOLS = 73, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_DEFINED_STORAGE_POOLS = 74, /* autogen autogen priority:high */
    REMOTE_PROC_FIND_STORAGE_POOL_SOURCES = 75, /* autogen skipgen */
    REMOTE_PROC_STORAGE_POOL_CREATE_XML = 76, /* autogen autogen */
    REMOTE_PROC_STORAGE_POOL_DEFINE_XML = 77, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_CREATE = 78, /* autogen autogen */
    REMOTE_PROC_STORAGE_POOL_BUILD = 79, /* autogen autogen */
    REMOTE_PROC_STORAGE_POOL_DESTROY = 80, /* autogen autogen priority:high */

    REMOTE_PROC_STORAGE_POOL_DELETE = 81, /* autogen autogen */
    REMOTE_PROC_STORAGE_POOL_UNDEFINE = 82, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_REFRESH = 83, /* autogen autogen */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME = 84, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID = 85, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_VOLUME = 86, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_GET_INFO = 87, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_GET_XML_DESC = 88, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_GET_AUTOSTART = 89, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_SET_AUTOSTART = 90, /* autogen autogen priority:high */

    REMOTE_PROC_STORAGE_POOL_NUM_OF_VOLUMES = 91, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES = 92, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_CREATE_XML = 93, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_DELETE = 94, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME = 95, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_KEY = 96, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_PATH = 97, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_GET_INFO = 98, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_GET_XML_DESC = 99, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_GET_PATH = 100, /* autogen autogen priority:high */

    REMOTE_PROC_NODE_GET_CELLS_FREE_MEMORY = 101, /* autogen skipgen priority:high */
    REMOTE_PROC_NODE_GET_FREE_MEMORY = 102, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_BLOCK_PEEK = 103, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MEMORY_PEEK = 104, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_EVENTS_REGISTER = 105, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER = 106, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE = 107, /* autogen autogen */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE2 = 108, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH2 = 109, /* autogen autogen */
    REMOTE_PROC_GET_URI = 110, /* autogen skipgen priority:high */

    REMOTE_PROC_NODE_NUM_OF_DEVICES = 111, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_LIST_DEVICES = 112, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_DEVICE_LOOKUP_BY_NAME = 113, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_DEVICE_GET_XML_DESC = 114, /* autogen autogen */
    REMOTE_PROC_NODE_DEVICE_GET_PARENT = 115, /* skipgen autogen priority:high */
    REMOTE_PROC_NODE_DEVICE_NUM_OF_CAPS = 116, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_DEVICE_LIST_CAPS = 117, /* autogen autogen priority:high */
    REMOTE_PROC_NODE_DEVICE_DETTACH = 118, /* autogen skipgen */
    REMOTE_PROC_NODE_DEVICE_RE_ATTACH = 119, /* autogen skipgen */
    REMOTE_PROC_NODE_DEVICE_RESET = 120, /* autogen skipgen */

    REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL = 121, /* skipgen skipgen priority:high */
    REMOTE_PROC_NODE_GET_SECURITY_MODEL = 122, /* skipgen skipgen priority:high */
    REMOTE_PROC_NODE_DEVICE_CREATE_XML = 123, /* autogen autogen */
    REMOTE_PROC_NODE_DEVICE_DESTROY = 124, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM = 125, /* autogen autogen */
    REMOTE_PROC_NUM_OF_INTERFACES = 126, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_INTERFACES = 127, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_LOOKUP_BY_NAME = 128, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_LOOKUP_BY_MAC_STRING = 129, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_GET_XML_DESC = 130, /* autogen autogen */

    REMOTE_PROC_INTERFACE_DEFINE_XML = 131, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_UNDEFINE = 132, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_CREATE = 133, /* autogen autogen */
    REMOTE_PROC_INTERFACE_DESTROY = 134, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_XML_FROM_NATIVE = 135, /* autogen autogen */
    REMOTE_PROC_DOMAIN_XML_TO_NATIVE = 136, /* autogen autogen */
    REMOTE_PROC_NUM_OF_DEFINED_INTERFACES = 137, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_DEFINED_INTERFACES = 138, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_SECRETS = 139, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_SECRETS = 140, /* autogen autogen priority:high */

    REMOTE_PROC_SECRET_LOOKUP_BY_UUID = 141, /* autogen autogen priority:high */
    REMOTE_PROC_SECRET_DEFINE_XML = 142, /* autogen autogen priority:high */
    REMOTE_PROC_SECRET_GET_XML_DESC = 143, /* autogen autogen priority:high */
    REMOTE_PROC_SECRET_SET_VALUE = 144, /* autogen autogen priority:high */
    REMOTE_PROC_SECRET_GET_VALUE = 145, /* skipgen skipgen priority:high */
    REMOTE_PROC_SECRET_UNDEFINE = 146, /* autogen autogen priority:high */
    REMOTE_PROC_SECRET_LOOKUP_BY_USAGE = 147, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL = 148, /* autogen autogen | writestream@1 */
    REMOTE_PROC_IS_SECURE = 149, /* autogen skipgen priority:high */
    REMOTE_PROC_DOMAIN_IS_ACTIVE = 150, /* autogen autogen priority:high */

    REMOTE_PROC_DOMAIN_IS_PERSISTENT = 151, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_IS_ACTIVE = 152, /* autogen autogen priority:high */
    REMOTE_PROC_NETWORK_IS_PERSISTENT = 153, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_IS_ACTIVE = 154, /* autogen autogen priority:high */
    REMOTE_PROC_STORAGE_POOL_IS_PERSISTENT = 155, /* autogen autogen priority:high */
    REMOTE_PROC_INTERFACE_IS_ACTIVE = 156, /* autogen autogen priority:high */
    REMOTE_PROC_GET_LIB_VERSION = 157, /* autogen autogen priority:high */
    REMOTE_PROC_CPU_COMPARE = 158, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_MEMORY_STATS = 159, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS = 160, /* autogen autogen */

    REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS = 161, /* autogen autogen */
    REMOTE_PROC_CPU_BASELINE = 162, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_JOB_INFO = 163, /* autogen autogen */
    REMOTE_PROC_DOMAIN_ABORT_JOB = 164, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_WIPE = 165, /* autogen autogen */
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_DOWNTIME = 166, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENTS_REGISTER_ANY = 167, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER_ANY = 168, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_EVENT_REBOOT = 169, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE = 170, /* autogen autogen */

    REMOTE_PROC_DOMAIN_EVENT_WATCHDOG = 171, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR = 172, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_GRAPHICS = 173, /* autogen autogen */
    REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS = 174, /* autogen autogen */
    REMOTE_PROC_NWFILTER_LOOKUP_BY_NAME = 175, /* autogen autogen priority:high */
    REMOTE_PROC_NWFILTER_LOOKUP_BY_UUID = 176, /* autogen autogen priority:high */
    REMOTE_PROC_NWFILTER_GET_XML_DESC = 177, /* autogen autogen priority:high */
    REMOTE_PROC_NUM_OF_NWFILTERS = 178, /* autogen autogen priority:high */
    REMOTE_PROC_LIST_NWFILTERS = 179, /* autogen autogen priority:high */
    REMOTE_PROC_NWFILTER_DEFINE_XML = 180, /* autogen autogen priority:high */

    REMOTE_PROC_NWFILTER_UNDEFINE = 181, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_MANAGED_SAVE = 182, /* autogen autogen */
    REMOTE_PROC_DOMAIN_HAS_MANAGED_SAVE_IMAGE = 183, /* autogen autogen */
    REMOTE_PROC_DOMAIN_MANAGED_SAVE_REMOVE = 184, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SNAPSHOT_CREATE_XML = 185, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SNAPSHOT_GET_XML_DESC = 186, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SNAPSHOT_NUM = 187, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_NAMES = 188, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LOOKUP_BY_NAME = 189, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_HAS_CURRENT_SNAPSHOT = 190, /* autogen autogen */

    REMOTE_PROC_DOMAIN_SNAPSHOT_CURRENT = 191, /* autogen autogen */
    REMOTE_PROC_DOMAIN_REVERT_TO_SNAPSHOT = 192, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SNAPSHOT_DELETE = 193, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_BLOCK_INFO = 194, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON = 195, /* autogen autogen */
    REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS = 196, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SET_MEMORY_PARAMETERS = 197, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS = 198, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SET_VCPUS_FLAGS = 199, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_VCPUS_FLAGS = 200, /* autogen autogen */

    REMOTE_PROC_DOMAIN_OPEN_CONSOLE = 201, /* autogen autogen | readstream@2 */
    REMOTE_PROC_DOMAIN_IS_UPDATED = 202, /* autogen autogen priority:high */
    REMOTE_PROC_GET_SYSINFO = 203, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SET_MEMORY_FLAGS = 204, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SET_BLKIO_PARAMETERS = 205, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_BLKIO_PARAMETERS = 206, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_SPEED = 207, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_UPLOAD = 208, /* autogen autogen | writestream@1 */
    REMOTE_PROC_STORAGE_VOL_DOWNLOAD = 209, /* autogen autogen | readstream@1 */
    REMOTE_PROC_DOMAIN_INJECT_NMI = 210, /* autogen autogen */

    REMOTE_PROC_DOMAIN_SCREENSHOT = 211, /* autogen autogen | readstream@1 */
    REMOTE_PROC_DOMAIN_GET_STATE = 212, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3 = 213, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE3 = 214, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3 = 215, /* autogen skipgen | writestream@1 */
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3 = 216, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH3 = 217, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_CONFIRM3 = 218, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS_FLAGS = 219, /* autogen autogen */
    REMOTE_PROC_INTERFACE_CHANGE_BEGIN = 220, /* autogen autogen */

    REMOTE_PROC_INTERFACE_CHANGE_COMMIT = 221, /* autogen autogen */
    REMOTE_PROC_INTERFACE_CHANGE_ROLLBACK = 222, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS_FLAGS = 223, /* skipgen autogen */
    REMOTE_PROC_DOMAIN_EVENT_CONTROL_ERROR = 224, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_PIN_VCPU_FLAGS = 225, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SEND_KEY = 226, /* autogen autogen */
    REMOTE_PROC_NODE_GET_CPU_STATS = 227, /* skipgen skipgen priority:high */
    REMOTE_PROC_NODE_GET_MEMORY_STATS = 228, /* skipgen skipgen priority:high */
    REMOTE_PROC_DOMAIN_GET_CONTROL_INFO = 229, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_GET_VCPU_PIN_INFO = 230, /* skipgen skipgen */

    REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS = 231, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SAVE_FLAGS = 232, /* autogen autogen */
    REMOTE_PROC_DOMAIN_RESTORE_FLAGS = 233, /* autogen autogen */
    REMOTE_PROC_DOMAIN_DESTROY_FLAGS = 234, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SAVE_IMAGE_GET_XML_DESC = 235, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SAVE_IMAGE_DEFINE_XML = 236, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_BLOCK_JOB_ABORT = 237, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_BLOCK_JOB_INFO = 238, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_BLOCK_JOB_SET_SPEED = 239, /* autogen autogen */
    REMOTE_PROC_DOMAIN_BLOCK_PULL = 240, /* autogen autogen */

    REMOTE_PROC_DOMAIN_EVENT_BLOCK_JOB = 241, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_MIGRATE_GET_MAX_SPEED = 242, /* autogen autogen */
    REMOTE_PROC_DOMAIN_BLOCK_STATS_FLAGS = 243, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SNAPSHOT_GET_PARENT = 244, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_RESET = 245, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SNAPSHOT_NUM_CHILDREN = 246, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_CHILDREN_NAMES = 247, /* autogen autogen priority:high */
    REMOTE_PROC_DOMAIN_EVENT_DISK_CHANGE = 248, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_OPEN_GRAPHICS = 249, /* skipgen skipgen */
    REMOTE_PROC_NODE_SUSPEND_FOR_DURATION = 250, /* autogen autogen */

    REMOTE_PROC_DOMAIN_BLOCK_RESIZE = 251, /* autogen autogen */
    REMOTE_PROC_DOMAIN_SET_BLOCK_IO_TUNE = 252, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_BLOCK_IO_TUNE = 253, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SET_NUMA_PARAMETERS = 254, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_NUMA_PARAMETERS = 255, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SET_INTERFACE_PARAMETERS = 256, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_INTERFACE_PARAMETERS = 257, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SHUTDOWN_FLAGS = 258, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_WIPE_PATTERN = 259, /* autogen autogen */
    REMOTE_PROC_STORAGE_VOL_RESIZE = 260, /* autogen autogen */

    REMOTE_PROC_DOMAIN_PM_SUSPEND_FOR_DURATION = 261, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_CPU_STATS = 262, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_GET_DISK_ERRORS = 263, /* skipgen skipgen */
    REMOTE_PROC_DOMAIN_SET_METADATA = 264, /* autogen autogen */
    REMOTE_PROC_DOMAIN_GET_METADATA = 265, /* autogen autogen */
    REMOTE_PROC_DOMAIN_BLOCK_REBASE = 266, /* autogen autogen */
    REMOTE_PROC_DOMAIN_PM_WAKEUP = 267, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_TRAY_CHANGE = 268, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_PMWAKEUP = 269, /* autogen autogen */
    REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND = 270 /* autogen autogen */

    /*
     * Notice how the entries are grouped in sets of 10 ?
     * Nice isn't it. Please keep it this way when adding more.
     *
     * Each function must have a three-word comment.  The first word is
     * whether gendispatch.pl handles daemon, the second whether
     * it handles src/remote.  Additional flags can be specified after a
     * pipe.
     * The last argument describes priority of API. There are two accepted
     * values: low, high; Each API that might eventually access hypervisor's
     * monitor (and thus block) MUST fall into low priority. However, there
     * are some exceptions to this rule, e.g. domainDestroy. Other APIs MAY
     * be marked as high priority. If in doubt, it's safe to choose low.
     * Low is taken as default, and thus can be left out.
     *
     * The (readstream|writestream)@<offset> flag lets daemon and src/remote
     * create a stream.  The direction is defined from the src/remote point
     * of view.  A readstream transfers data from daemon to src/remote.  The
     * <offset> specifies at which offset the stream parameter is inserted
     * in the function parameter list. */
};
