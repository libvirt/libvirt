/* -*- c -*-
 * remote_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
%#include "virxdrdefs.h"
%#include <arpa/inet.h>

/*----- Data types. -----*/

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const REMOTE_STRING_MAX = 4194304;

/* A long string, which may NOT be NULL. */
typedef string remote_nonnull_string<REMOTE_STRING_MAX>;

/* A long string, which may be NULL. */
typedef remote_nonnull_string *remote_string;

/* Upper limit on lists of domains. */
const REMOTE_DOMAIN_LIST_MAX = 16384;

/* Upper limit on cpumap (bytes) passed to virDomainPinVcpu. */
const REMOTE_CPUMAP_MAX = 2048;

/* Upper limit on number of info fields returned by virDomainGetVcpus. */
const REMOTE_VCPUINFO_MAX = 16384;

/* Upper limit on cpumaps (bytes) passed to virDomainGetVcpus. */
const REMOTE_CPUMAPS_MAX = 8388608;

/* Upper limit on number of info fields returned by virDomainGetIOThreads. */
const REMOTE_IOTHREAD_INFO_MAX = 16384;

/* Upper limit on migrate cookie. */
const REMOTE_MIGRATE_COOKIE_MAX = 4194304;

/* Upper limit on lists of networks. */
const REMOTE_NETWORK_LIST_MAX = 16384;

/* Upper limit on lists of interfaces. */
const REMOTE_INTERFACE_LIST_MAX = 16384;

/* Upper limit on lists of storage pools. */
const REMOTE_STORAGE_POOL_LIST_MAX = 4096;

/* Upper limit on lists of storage vols. */
const REMOTE_STORAGE_VOL_LIST_MAX = 16384;

/* Upper limit on lists of node devices. */
const REMOTE_NODE_DEVICE_LIST_MAX = 16384;

/* Upper limit on lists of node device capabilities. */
const REMOTE_NODE_DEVICE_CAPS_LIST_MAX = 65536;

/* Upper limit on lists of network filters. */
const REMOTE_NWFILTER_LIST_MAX = 1024;

/* Upper limit on list of scheduler parameters. */
const REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX = 16;

/* Upper limit on list of blkio parameters. */
const REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX = 16;

/* Upper limit on list of memory parameters. */
const REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX = 16;

/* Upper limit on list of blockio tuning parameters. */
const REMOTE_DOMAIN_BLOCK_IO_TUNE_PARAMETERS_MAX = 32;

/* Upper limit on list of numa parameters. */
const REMOTE_DOMAIN_NUMA_PARAMETERS_MAX = 16;

/* Upper limit on list of perf events. */
const REMOTE_DOMAIN_PERF_EVENTS_MAX = 64;

/* Upper limit on block copy tunable parameters. */
const REMOTE_DOMAIN_BLOCK_COPY_PARAMETERS_MAX = 16;

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
const REMOTE_DOMAIN_SNAPSHOT_LIST_MAX = 1024;

/* Maximum length of a block peek buffer message.
 * Note applications need to be aware of this limit and issue multiple
 * requests for large amounts of data.
 */
const REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX = 4194304;

/* Maximum length of a memory peek buffer message.
 * Note applications need to be aware of this limit and issue multiple
 * requests for large amounts of data.
 */
const REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX = 4194304;

/*
 * Maximum length of a security label list.
 */
const REMOTE_SECURITY_LABEL_LIST_MAX=64;

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
const REMOTE_SECRET_LIST_MAX = 16384;

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

/*
 * Upper limit on number of memory parameters
 */
const REMOTE_NODE_MEMORY_PARAMETERS_MAX = 64;

/* Upper limit on migrate parameters */
const REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX = 64;

/* Upper limit on number of job stats */
const REMOTE_DOMAIN_JOB_STATS_MAX = 64;

/* Upper limit on number of CPU models */
const REMOTE_CONNECT_CPU_MODELS_MAX = 8192;

/* Upper limit on number of mountpoints to frozen */
const REMOTE_DOMAIN_FSFREEZE_MOUNTPOINTS_MAX = 256;

/* Upper limit on the maximum number of leases in one lease file */
const REMOTE_NETWORK_DHCP_LEASES_MAX = 65536;

/* Upper limit on count of parameters returned via bulk stats API */
const REMOTE_CONNECT_GET_ALL_DOMAIN_STATS_MAX = 4096;

/* Upper limit of message size for tunable event. */
const REMOTE_DOMAIN_EVENT_TUNABLE_MAX = 2048;

/* Upper limit on number of mountpoints in fsinfo */
const REMOTE_DOMAIN_FSINFO_MAX = 256;

/* Upper limit on number of disks per mountpoint in fsinfo */
const REMOTE_DOMAIN_FSINFO_DISKS_MAX = 256;

/* Upper limit on number of interfaces per domain */
const REMOTE_DOMAIN_INTERFACE_MAX = 2048;

/* Upper limit on number of IP addresses per interface */
const REMOTE_DOMAIN_IP_ADDR_MAX = 2048;

/* Upper limit on number of guest vcpu information entries */
const REMOTE_DOMAIN_GUEST_VCPU_PARAMS_MAX = 64;

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
 * For cases where the API allocates memory and fills the arguments (mostly
 * typed parameters) a similar comment indicates the type and offset
 * of the variable to be filled with the count of returned elements.
 * alloc@<offset>@unsigned int@<count offset>
 *
 * Dynamic opaque and remote_nonnull_string arrays can be annotated with an
 * optional typecast */

struct remote_connect_open_args {
    /* NB. "name" might be NULL although in practice you can't
     * yet do that using the remote_internal driver.
     */
    remote_string name;
    unsigned int flags;
};

struct remote_connect_supports_feature_args {
    int feature;
};

struct remote_connect_supports_feature_ret {
    int supported;
};

struct remote_connect_get_type_ret {
    remote_nonnull_string type;
};

struct remote_connect_get_version_ret {
    unsigned hyper hv_ver;
};

struct remote_connect_get_lib_version_ret {
    unsigned hyper lib_ver;
};

struct remote_connect_get_hostname_ret {
    remote_nonnull_string hostname;
};

struct remote_connect_get_sysinfo_args {
    unsigned int flags;
};

struct remote_connect_get_sysinfo_ret {
    remote_nonnull_string sysinfo;
};

struct remote_connect_get_uri_ret {
    remote_nonnull_string uri;
};

struct remote_connect_get_max_vcpus_args {
    /* The only backend which supports this call is Xen HV, and
     * there the type is ignored so it could be NULL.
     */
    remote_string type;
};

struct remote_connect_get_max_vcpus_ret {
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

struct remote_connect_get_capabilities_ret {
    remote_nonnull_string capabilities;
};

struct remote_connect_get_domain_capabilities_args {
    remote_string emulatorbin;
    remote_string arch;
    remote_string machine;
    remote_string virttype;
    unsigned int flags;
};

struct remote_connect_get_domain_capabilities_ret {
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

struct remote_domain_set_perf_events_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_PERF_EVENTS_MAX>;
    unsigned int flags;
};

struct remote_domain_get_perf_events_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_perf_events_ret {
    remote_typed_param params<REMOTE_DOMAIN_PERF_EVENTS_MAX>;
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

struct remote_connect_list_domains_args {
    int maxids;
};

struct remote_connect_list_domains_ret {
    int ids<REMOTE_DOMAIN_LIST_MAX>; /* insert@1 */
};

struct remote_connect_num_of_domains_ret {
    int num;
};

struct remote_domain_create_xml_args {
    remote_nonnull_string xml_desc;
    unsigned int flags;
};

struct remote_domain_create_xml_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_create_xml_with_files_args {
    remote_nonnull_string xml_desc;
    unsigned int flags;
};

struct remote_domain_create_xml_with_files_ret {
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

struct remote_domain_set_memory_stats_period_args {
    remote_nonnull_domain dom;
    int period;
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

struct remote_domain_core_dump_with_format_args {
    remote_nonnull_domain dom;
    remote_nonnull_string to;
    unsigned int dumpformat;
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

struct remote_connect_list_defined_domains_args {
    int maxnames;
};

struct remote_connect_list_defined_domains_ret {
    remote_nonnull_string names<REMOTE_DOMAIN_LIST_MAX>; /* insert@1 */
};

struct remote_connect_num_of_defined_domains_ret {
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

struct remote_domain_create_with_files_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_create_with_files_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_define_xml_args {
    remote_nonnull_string xml;
};

struct remote_domain_define_xml_ret {
    remote_nonnull_domain dom;
};

struct remote_domain_define_xml_flags_args {
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_domain_define_xml_flags_ret {
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

struct remote_domain_send_process_signal_args {
    remote_nonnull_domain dom;
    hyper pid_value;
    unsigned int signum;
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

struct remote_domain_pin_emulator_args {
    remote_nonnull_domain dom;
    opaque cpumap<REMOTE_CPUMAP_MAX>; /* (unsigned char *) */
    unsigned int flags;
};

struct remote_domain_get_emulator_pin_info_args {
    remote_nonnull_domain dom;
    int maplen;
    unsigned int flags;
};

struct remote_domain_get_emulator_pin_info_ret {
    opaque cpumaps<REMOTE_CPUMAPS_MAX>;
    int ret;
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

struct remote_domain_iothread_info {
    unsigned int iothread_id;
    opaque cpumap<REMOTE_CPUMAP_MAX>;
};

struct remote_domain_get_iothread_info_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_iothread_info_ret {
    remote_domain_iothread_info info<REMOTE_IOTHREAD_INFO_MAX>;
    unsigned int ret;
};

struct remote_domain_pin_iothread_args {
    remote_nonnull_domain dom;
    unsigned int iothreads_id;
    opaque cpumap<REMOTE_CPUMAP_MAX>; /* (unsigned char *) */
    unsigned int flags;
};

struct remote_domain_add_iothread_args {
    remote_nonnull_domain dom;
    unsigned int iothread_id;
    unsigned int flags;
};

struct remote_domain_del_iothread_args {
    remote_nonnull_domain dom;
    unsigned int iothread_id;
    unsigned int flags;
};

struct remote_domain_get_security_label_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_security_label_ret {
    char label<REMOTE_SECURITY_LABEL_MAX>;
    int enforcing;
};

struct remote_domain_get_security_label_list_args {
    remote_nonnull_domain dom;
};

struct remote_domain_get_security_label_list_ret {
    remote_domain_get_security_label_ret labels<REMOTE_SECURITY_LABEL_LIST_MAX>;
    int ret;
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
struct remote_domain_block_copy_args {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    remote_nonnull_string destxml;
    remote_typed_param params<REMOTE_DOMAIN_BLOCK_COPY_PARAMETERS_MAX>;
    unsigned int flags;
};
struct remote_domain_block_commit_args {
    remote_nonnull_domain dom;
    remote_nonnull_string disk;
    remote_string base;
    remote_string top;
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

struct remote_domain_get_hostname_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_hostname_ret {
    remote_nonnull_string hostname;
};

/* Network calls: */

struct remote_connect_num_of_networks_ret {
    int num;
};

struct remote_connect_list_networks_args {
    int maxnames;
};

struct remote_connect_list_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_LIST_MAX>; /* insert@1 */
};

struct remote_connect_num_of_defined_networks_ret {
    int num;
};

struct remote_connect_list_defined_networks_args {
    int maxnames;
};

struct remote_connect_list_defined_networks_ret {
    remote_nonnull_string names<REMOTE_NETWORK_LIST_MAX>; /* insert@1 */
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

struct remote_network_update_args {
    remote_nonnull_network net;
    unsigned int command;
    unsigned int section;
    int parentIndex;
    remote_nonnull_string xml;
    unsigned int flags;
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

struct remote_connect_num_of_nwfilters_ret {
    int num;
};

struct remote_connect_list_nwfilters_args {
    int maxnames;
};

struct remote_connect_list_nwfilters_ret {
    remote_nonnull_string names<REMOTE_NWFILTER_LIST_MAX>; /* insert@1 */
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

struct remote_connect_num_of_interfaces_ret {
    int num;
};

struct remote_connect_list_interfaces_args {
    int maxnames;
};

struct remote_connect_list_interfaces_ret {
    remote_nonnull_string names<REMOTE_INTERFACE_LIST_MAX>; /* insert@1 */
};

struct remote_connect_num_of_defined_interfaces_ret {
    int num;
};

struct remote_connect_list_defined_interfaces_args {
    int maxnames;
};

struct remote_connect_list_defined_interfaces_ret {
    remote_nonnull_string names<REMOTE_INTERFACE_LIST_MAX>; /* insert@1 */
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

struct remote_connect_num_of_storage_pools_ret {
    int num;
};

struct remote_connect_list_storage_pools_args {
    int maxnames;
};

struct remote_connect_list_storage_pools_ret {
    remote_nonnull_string names<REMOTE_STORAGE_POOL_LIST_MAX>; /* insert@1 */
};

struct remote_connect_num_of_defined_storage_pools_ret {
    int num;
};

struct remote_connect_list_defined_storage_pools_args {
    int maxnames;
};

struct remote_connect_list_defined_storage_pools_ret {
    remote_nonnull_string names<REMOTE_STORAGE_POOL_LIST_MAX>; /* insert@1 */
};

struct remote_connect_find_storage_pool_sources_args {
    remote_nonnull_string type;
    remote_string srcSpec;
    unsigned int flags;
};

struct remote_connect_find_storage_pool_sources_ret {
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
    remote_nonnull_string names<REMOTE_STORAGE_VOL_LIST_MAX>; /* insert@1 */
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

struct remote_storage_vol_get_info_flags_args {
    remote_nonnull_storage_vol vol;
    unsigned int flags;
};

struct remote_storage_vol_get_info_flags_ret { /* insert@1 */
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
    remote_nonnull_string names<REMOTE_NODE_DEVICE_LIST_MAX>; /* insert@2 */
};

struct remote_node_device_lookup_by_name_args {
    remote_nonnull_string name;
};

struct remote_node_device_lookup_by_name_ret {
    remote_nonnull_node_device dev;
};

struct remote_node_device_lookup_scsi_host_by_wwn_args {
    remote_nonnull_string wwnn;
    remote_nonnull_string wwpn;
    unsigned int flags;
};

struct remote_node_device_lookup_scsi_host_by_wwn_ret {
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

struct remote_node_device_detach_flags_args {
    remote_nonnull_string name;
    remote_string driverName;
    unsigned int flags;
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


/*
 * Events Register/Deregister:
 * It would seem rpcgen does not like both args and ret
 * to be null. It will not generate the prototype otherwise.
 * Pass back a redundant boolean to force prototype generation.
 */
struct remote_connect_domain_event_register_ret {
    int cb_registered;
};

struct remote_connect_domain_event_deregister_ret {
    int cb_registered;
};

struct remote_domain_event_lifecycle_msg {
    remote_nonnull_domain dom;
    int event;
    int detail;
};
struct remote_domain_event_callback_lifecycle_msg {
    int callbackID;
    remote_domain_event_lifecycle_msg msg;
};


struct remote_connect_domain_xml_from_native_args {
    remote_nonnull_string nativeFormat;
    remote_nonnull_string nativeConfig;
    unsigned int flags;
};

struct remote_connect_domain_xml_from_native_ret {
    remote_nonnull_string domainXml;
};


struct remote_connect_domain_xml_to_native_args {
    remote_nonnull_string nativeFormat;
    remote_nonnull_string domainXml;
    unsigned int flags;
};

struct remote_connect_domain_xml_to_native_ret {
    remote_nonnull_string nativeConfig;
};


struct remote_connect_num_of_secrets_ret {
    int num;
};

struct remote_connect_list_secrets_args {
    int maxuuids;
};

struct remote_connect_list_secrets_ret {
    remote_nonnull_string uuids<REMOTE_SECRET_LIST_MAX>; /* insert@1 */
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


struct remote_connect_is_secure_ret {
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


struct remote_connect_compare_cpu_args {
    remote_nonnull_string xml;
    unsigned int flags;
};

struct remote_connect_compare_cpu_ret {
    int result;
};


struct remote_connect_baseline_cpu_args {
    remote_nonnull_string xmlCPUs<REMOTE_CPU_BASELINE_MAX>; /* (const char **) */
    unsigned int flags;
};

struct remote_connect_baseline_cpu_ret {
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


struct remote_domain_get_job_stats_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_job_stats_ret {
    int type;
    remote_typed_param params<REMOTE_DOMAIN_JOB_STATS_MAX>;
};


struct remote_domain_abort_job_args {
    remote_nonnull_domain dom;
};


struct remote_domain_migrate_set_max_downtime_args {
    remote_nonnull_domain dom;
    unsigned hyper downtime;
    unsigned int flags;
};

struct remote_domain_migrate_get_compression_cache_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_migrate_get_compression_cache_ret {
    unsigned hyper cacheSize; /* insert@1 */
};

struct remote_domain_migrate_set_compression_cache_args {
    remote_nonnull_domain dom;
    unsigned hyper cacheSize;
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


struct remote_connect_domain_event_register_any_args {
    int eventID;
};

struct remote_connect_domain_event_deregister_any_args {
    int eventID;
};

struct remote_connect_domain_event_callback_register_any_args {
    int eventID;
    remote_domain dom;
};

struct remote_connect_domain_event_callback_register_any_ret {
    int callbackID;
};

struct remote_connect_domain_event_callback_deregister_any_args {
    int callbackID;
};

struct remote_domain_event_reboot_msg {
    remote_nonnull_domain dom;
};
struct remote_domain_event_callback_reboot_msg {
    int callbackID;
    remote_domain_event_reboot_msg msg;
};

struct remote_domain_event_rtc_change_msg {
    remote_nonnull_domain dom;
    hyper offset;
};
struct remote_domain_event_callback_rtc_change_msg {
    int callbackID;
    remote_domain_event_rtc_change_msg msg;
};

struct remote_domain_event_watchdog_msg {
    remote_nonnull_domain dom;
    int action;
};
struct remote_domain_event_callback_watchdog_msg {
    int callbackID;
    remote_domain_event_watchdog_msg msg;
};

struct remote_domain_event_io_error_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string srcPath;
    remote_nonnull_string devAlias;
    int action;
};
struct remote_domain_event_callback_io_error_msg {
    int callbackID;
    remote_domain_event_io_error_msg msg;
};

struct remote_domain_event_io_error_reason_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string srcPath;
    remote_nonnull_string devAlias;
    int action;
    remote_nonnull_string reason;
};
struct remote_domain_event_callback_io_error_reason_msg {
    int callbackID;
    remote_domain_event_io_error_reason_msg msg;
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
struct remote_domain_event_callback_graphics_msg {
    int callbackID;
    remote_domain_event_graphics_msg msg;
};

struct remote_domain_event_block_job_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string path;
    int type;
    int status;
};
struct remote_domain_event_callback_block_job_msg {
    int callbackID;
    remote_domain_event_block_job_msg msg;
};

struct remote_domain_event_disk_change_msg {
    remote_nonnull_domain dom;
    remote_string oldSrcPath;
    remote_string newSrcPath;
    remote_nonnull_string devAlias;
    int reason;
};
struct remote_domain_event_callback_disk_change_msg {
    int callbackID;
    remote_domain_event_disk_change_msg msg;
};

struct remote_domain_event_tray_change_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string devAlias;
    int reason;
};
struct remote_domain_event_callback_tray_change_msg {
    int callbackID;
    remote_domain_event_tray_change_msg msg;
};

struct remote_domain_event_pmwakeup_msg {
    remote_nonnull_domain dom;
};
struct remote_domain_event_callback_pmwakeup_msg {
    int callbackID;
    int reason;
    remote_domain_event_pmwakeup_msg msg;
};

struct remote_domain_event_pmsuspend_msg {
    remote_nonnull_domain dom;
};
struct remote_domain_event_callback_pmsuspend_msg {
    int callbackID;
    int reason;
    remote_domain_event_pmsuspend_msg msg;
};

struct remote_domain_event_balloon_change_msg {
    remote_nonnull_domain dom;
    unsigned hyper actual;
};
struct remote_domain_event_callback_balloon_change_msg {
    int callbackID;
    remote_domain_event_balloon_change_msg msg;
};

struct remote_domain_event_pmsuspend_disk_msg {
    remote_nonnull_domain dom;
};
struct remote_domain_event_callback_pmsuspend_disk_msg {
    int callbackID;
    int reason;
    remote_domain_event_pmsuspend_disk_msg msg;
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
    remote_nonnull_string names<REMOTE_DOMAIN_SNAPSHOT_LIST_MAX>; /* insert@1 */
};

struct remote_domain_list_all_snapshots_args {
    remote_nonnull_domain dom;
    int need_results;
    unsigned int flags;
};

struct remote_domain_list_all_snapshots_ret { /* insert@1 */
    remote_nonnull_domain_snapshot snapshots<REMOTE_DOMAIN_SNAPSHOT_LIST_MAX>;
    int ret;
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
    remote_nonnull_string names<REMOTE_DOMAIN_SNAPSHOT_LIST_MAX>; /* insert@1 */
};

struct remote_domain_snapshot_list_all_children_args {
    remote_nonnull_domain_snapshot snapshot;
    int need_results;
    unsigned int flags;
};

struct remote_domain_snapshot_list_all_children_ret { /* insert@1 */
    remote_nonnull_domain_snapshot snapshots<REMOTE_DOMAIN_SNAPSHOT_LIST_MAX>;
    int ret;
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

struct remote_domain_snapshot_is_current_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_is_current_ret {
    int current;
};

struct remote_domain_snapshot_has_metadata_args {
    remote_nonnull_domain_snapshot snap;
    unsigned int flags;
};

struct remote_domain_snapshot_has_metadata_ret {
    int metadata;
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

struct remote_domain_open_channel_args {
    remote_nonnull_domain dom;
    remote_string name;
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
struct remote_domain_event_callback_control_error_msg {
    int callbackID;
    remote_domain_event_control_error_msg msg;
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

struct remote_domain_open_graphics_fd_args {
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

struct remote_connect_list_all_domains_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_domains_ret { /* insert@1 */
    remote_nonnull_domain domains<REMOTE_DOMAIN_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_storage_pools_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_storage_pools_ret { /* insert@1 */
    remote_nonnull_storage_pool pools<REMOTE_STORAGE_POOL_LIST_MAX>;
    unsigned int ret;
};

struct remote_storage_pool_list_all_volumes_args {
    remote_nonnull_storage_pool pool;
    int need_results;
    unsigned int flags;
};

struct remote_storage_pool_list_all_volumes_ret { /* insert@1 */
    remote_nonnull_storage_vol vols<REMOTE_STORAGE_VOL_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_networks_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_networks_ret { /* insert@1 */
    remote_nonnull_network nets<REMOTE_NETWORK_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_interfaces_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_interfaces_ret { /* insert@1 */
    remote_nonnull_interface ifaces<REMOTE_INTERFACE_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_node_devices_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_node_devices_ret { /* insert@1 */
    remote_nonnull_node_device devices<REMOTE_NODE_DEVICE_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_nwfilters_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_nwfilters_ret { /* insert@1 */
    remote_nonnull_nwfilter filters<REMOTE_NWFILTER_LIST_MAX>;
    unsigned int ret;
};

struct remote_connect_list_all_secrets_args {
    int need_results;
    unsigned int flags;
};

struct remote_connect_list_all_secrets_ret { /* insert@1 */
    remote_nonnull_secret secrets<REMOTE_SECRET_LIST_MAX>;
    unsigned int ret;
};

struct remote_node_set_memory_parameters_args {
    remote_typed_param params<REMOTE_NODE_MEMORY_PARAMETERS_MAX>;
    unsigned int flags;
};

struct remote_node_get_memory_parameters_args {
    int nparams;
    unsigned int flags;
};

struct remote_node_get_memory_parameters_ret {
    remote_typed_param params<REMOTE_NODE_MEMORY_PARAMETERS_MAX>;
    int nparams;
};

struct remote_node_get_cpu_map_args {
    int need_map;
    int need_online;
    unsigned int flags;
};

struct remote_node_get_cpu_map_ret {
    opaque cpumap<REMOTE_CPUMAP_MAX>;
    unsigned int online;
    int ret;
};

struct remote_domain_fstrim_args {
    remote_nonnull_domain dom;
    remote_string mountPoint;
    unsigned hyper minimum;
    unsigned int flags;
};

struct remote_domain_get_time_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_time_ret {
    hyper seconds;
    unsigned int nseconds;
};

struct remote_domain_set_time_args {
    remote_nonnull_domain dom;
    hyper seconds;
    unsigned int nseconds;
    unsigned int flags;
};

struct remote_domain_migrate_begin3_params_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    unsigned int flags;
};

struct remote_domain_migrate_begin3_params_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_nonnull_string xml;
};

struct remote_domain_migrate_prepare3_params_args {
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned int flags;
};

struct remote_domain_migrate_prepare3_params_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
    remote_string uri_out;
};

struct remote_domain_migrate_prepare_tunnel3_params_args {
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned int flags;
};

struct remote_domain_migrate_prepare_tunnel3_params_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
};

struct remote_domain_migrate_perform3_params_args {
    remote_nonnull_domain dom;
    remote_string dconnuri;
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned int flags;
};

struct remote_domain_migrate_perform3_params_ret {
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
};

struct remote_domain_migrate_finish3_params_args {
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned int flags;
    int cancelled;
};

struct remote_domain_migrate_finish3_params_ret {
    remote_nonnull_domain dom;
    opaque cookie_out<REMOTE_MIGRATE_COOKIE_MAX>;
};

struct remote_domain_migrate_confirm3_params_args {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX>;
    opaque cookie_in<REMOTE_MIGRATE_COOKIE_MAX>;
    unsigned int flags;
    int cancelled;
};

/* The device removed event is the last event where we have to support
 * dual forms for back-compat to older clients; all future events can
 * use just the modern form with callbackID.  */
struct remote_domain_event_device_removed_msg {
    remote_nonnull_domain dom;
    remote_nonnull_string devAlias;
};
struct remote_domain_event_callback_device_removed_msg {
    int callbackID;
    remote_domain_event_device_removed_msg msg;
};

struct remote_domain_event_block_job_2_msg {
    int callbackID;
    remote_nonnull_domain dom;
    remote_nonnull_string dst;
    int type;
    int status;
};

struct remote_domain_event_callback_tunable_msg {
    int callbackID;
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_EVENT_TUNABLE_MAX>;
};

struct remote_domain_event_callback_device_added_msg {
    int callbackID;
    remote_nonnull_domain dom;
    remote_nonnull_string devAlias;
};

struct remote_connect_event_connection_closed_msg {
    int reason;
};

struct remote_connect_get_cpu_model_names_args {
    remote_nonnull_string arch;
    int need_results;
    unsigned int flags;
};

struct remote_connect_get_cpu_model_names_ret {
    remote_nonnull_string models<REMOTE_CONNECT_CPU_MODELS_MAX>;
    int ret;
};

struct remote_connect_network_event_register_any_args {
    int eventID;
    remote_network net;
};

struct remote_connect_network_event_register_any_ret {
    int callbackID;
};

struct remote_connect_network_event_deregister_any_args {
    int callbackID;
};

struct remote_network_event_lifecycle_msg {
    int callbackID;
    remote_nonnull_network net;
    int event;
    int detail;
};

struct remote_connect_storage_pool_event_register_any_args {
    int eventID;
    remote_storage_pool pool;
};

struct remote_connect_storage_pool_event_register_any_ret {
    int callbackID;
};

struct remote_connect_storage_pool_event_deregister_any_args {
    int callbackID;
};

struct remote_storage_pool_event_lifecycle_msg {
    int callbackID;
    remote_nonnull_storage_pool pool;
    int event;
    int detail;
};

struct remote_storage_pool_event_refresh_msg {
    int callbackID;
    remote_nonnull_storage_pool pool;
};

struct remote_connect_node_device_event_register_any_args {
    int eventID;
    remote_node_device dev;
};

struct remote_connect_node_device_event_register_any_ret {
    int callbackID;
};

struct remote_connect_node_device_event_deregister_any_args {
    int callbackID;
};

struct remote_node_device_event_lifecycle_msg {
    int callbackID;
    remote_nonnull_node_device dev;
    int event;
    int detail;
};

struct remote_node_device_event_update_msg {
    int callbackID;
    remote_nonnull_node_device dev;
};

struct remote_domain_fsfreeze_args {
    remote_nonnull_domain dom;
    remote_nonnull_string mountpoints<REMOTE_DOMAIN_FSFREEZE_MOUNTPOINTS_MAX>; /* (const char **) */
    unsigned int flags;
};

struct remote_domain_fsfreeze_ret {
    int filesystems;
};

struct remote_domain_fsthaw_args {
    remote_nonnull_domain dom;
    remote_nonnull_string mountpoints<REMOTE_DOMAIN_FSFREEZE_MOUNTPOINTS_MAX>; /* (const char **) */
    unsigned int flags;
};

struct remote_domain_fsthaw_ret {
    int filesystems;
};

struct remote_node_get_free_pages_args {
    unsigned int pages<REMOTE_NODE_MAX_CELLS>;
    int startCell;
    unsigned int cellCount;
    unsigned int flags;
};

struct remote_node_get_free_pages_ret {
    unsigned hyper counts<REMOTE_NODE_MAX_CELLS>;
};

struct remote_node_alloc_pages_args {
    unsigned int pageSizes<REMOTE_NODE_MAX_CELLS>;
    unsigned hyper pageCounts<REMOTE_NODE_MAX_CELLS>;
    int startCell;
    unsigned int cellCount;
    unsigned int flags;
};

struct remote_node_alloc_pages_ret {
    int ret;
};

struct remote_network_dhcp_lease {
    remote_nonnull_string iface;
    hyper expirytime;
    int type;
    remote_string mac;
    remote_string iaid;
    remote_nonnull_string ipaddr;
    unsigned int prefix;
    remote_string hostname;
    remote_string clientid;
};

struct remote_network_get_dhcp_leases_args {
    remote_nonnull_network net;
    remote_string mac;
    int need_results;
    unsigned int flags;
};

struct remote_network_get_dhcp_leases_ret {
    remote_network_dhcp_lease leases<REMOTE_NETWORK_DHCP_LEASES_MAX>;
    unsigned int ret;
};

struct remote_domain_stats_record {
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_CONNECT_GET_ALL_DOMAIN_STATS_MAX>;
};

struct remote_connect_get_all_domain_stats_args {
    remote_nonnull_domain doms<REMOTE_DOMAIN_LIST_MAX>;
    unsigned int stats;
    unsigned int flags;
};

struct remote_domain_event_callback_agent_lifecycle_msg {
    int callbackID;
    remote_nonnull_domain dom;

    int state;
    int reason;
};

struct remote_connect_get_all_domain_stats_ret {
    remote_domain_stats_record retStats<REMOTE_DOMAIN_LIST_MAX>;
};

struct remote_domain_fsinfo {
    remote_nonnull_string mountpoint;
    remote_nonnull_string name;
    remote_nonnull_string fstype;
    remote_nonnull_string dev_aliases<REMOTE_DOMAIN_FSINFO_DISKS_MAX>; /* (const char **) */
};

struct remote_domain_get_fsinfo_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_fsinfo_ret {
    remote_domain_fsinfo info<REMOTE_DOMAIN_FSINFO_MAX>;
    unsigned int ret;
};

struct remote_domain_ip_addr {
    int type;
    remote_nonnull_string addr;
    unsigned int prefix;
};

struct remote_domain_interface {
    remote_nonnull_string name;
    remote_string hwaddr;
    remote_domain_ip_addr addrs<REMOTE_DOMAIN_IP_ADDR_MAX>;
};

struct remote_domain_interface_addresses_args {
    remote_nonnull_domain dom;
    unsigned int source;
    unsigned int flags;
};

struct remote_domain_interface_addresses_ret {
    remote_domain_interface ifaces<REMOTE_DOMAIN_INTERFACE_MAX>;
};

struct remote_domain_set_user_password_args {
    remote_nonnull_domain dom;
    remote_string user;
    remote_string password;
    unsigned int flags;
};

struct remote_domain_rename_args {
    remote_nonnull_domain dom;
    remote_string new_name;
    unsigned int flags;
};

struct remote_domain_rename_ret {
    int retcode;
};

struct remote_domain_event_callback_migration_iteration_msg {
    int callbackID;
    remote_nonnull_domain dom;
    int iteration;
};

struct remote_domain_event_callback_job_completed_msg {
    int callbackID;
    remote_nonnull_domain dom;
    remote_typed_param params<REMOTE_DOMAIN_JOB_STATS_MAX>;
};

struct remote_domain_migrate_start_post_copy_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_event_callback_device_removal_failed_msg {
    int callbackID;
    remote_nonnull_domain dom;
    remote_nonnull_string devAlias;
};

struct remote_domain_get_guest_vcpus_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};

struct remote_domain_get_guest_vcpus_ret {
    remote_typed_param params<REMOTE_DOMAIN_GUEST_VCPU_PARAMS_MAX>; /* alloc@1@unsigned int@2 */
};

struct remote_domain_set_guest_vcpus_args {
    remote_nonnull_domain dom;
    remote_nonnull_string cpumap;
    int state;
    unsigned int flags;
};


/*----- Protocol. -----*/

/* Define the program number, protocol version and procedure numbers here. */
const REMOTE_PROGRAM = 0x20008086;
const REMOTE_PROTOCOL_VERSION = 1;

enum remote_procedure {
    /* Each function must be preceded by a comment providing one or
     * more annotations:
     *
     * - @generate: none|client|server|both
     *
     *   Whether to generate the dispatch stubs for the server
     *   and/or client code.
     *
     * - @readstream: paramnumber
     * - @writestream: paramnumber
     *
     *   The @readstream or @writestream annotations let daemon and src/remote
     *   create a stream.  The direction is defined from the src/remote point
     *   of view.  A readstream transfers data from daemon to src/remote.  The
     *   <paramnumber> specifies at which offset the stream parameter is inserted
     *   in the function parameter list.
     *
     * - @priority: low|high
     *
     *   Each API that might eventually access hypervisor's monitor (and thus
     *   block) MUST fall into low priority. However, there are some exceptions
     *   to this rule, e.g. domainDestroy. Other APIs MAY be marked as high
     *   priority. If in doubt, it's safe to choose low. Low is taken as default,
     *   and thus can be left out.
     *
     * - @acl: <object>:<permission>
     * - @acl: <object>:<permission>:<flagname>
     *
     *   Declare the access control requirements for the API. May be repeated
     *   multiple times, if multiple rules are required.
     *
     *     <object> is one of 'connect', 'domain', 'network', 'storagepool',
     *              'interface', 'nodedev', 'secret'.
     *     <permission> is one of the permissions in access/viraccessperm.h
     *     <flagname> indicates the rule only applies if the named flag
     *     is set in the API call
     *
     * - @aclfilter: <object>:<permission>
     *
     *   Declare an access control filter that will be applied to a list
     *   of objects being returned by an API. This allows the returned
     *   list to be filtered to only show those the user has permissions
     *   against
     */

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_OPEN = 1,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_CONNECT_CLOSE = 2,

    /**
     * @generate: server
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_GET_TYPE = 3,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_GET_VERSION = 4,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_GET_MAX_VCPUS = 5,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_INFO = 6,

    /**
     * @generate: both
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_GET_CAPABILITIES = 7,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE = 8,

    /**
     * @generate: server
     * @acl: domain:start
     */
    REMOTE_PROC_DOMAIN_CREATE = 9,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:start
     */
    REMOTE_PROC_DOMAIN_CREATE_XML = 10,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:write
     * @acl: domain:save
     */
    REMOTE_PROC_DOMAIN_DEFINE_XML = 11,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:stop
     */
    REMOTE_PROC_DOMAIN_DESTROY = 12,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_DETACH_DEVICE = 13,

    /**
     * @generate: both
     * @acl: domain:read
     * @acl: domain:read_secure:VIR_DOMAIN_XML_SECURE
     * @acl: domain:read_secure:VIR_DOMAIN_XML_MIGRATABLE
     */
    REMOTE_PROC_DOMAIN_GET_XML_DESC = 14,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_AUTOSTART = 15,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_INFO = 16,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_MAX_MEMORY = 17,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_MAX_VCPUS = 18,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_OS_TYPE = 19,

    /**
     * @generate: none
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_VCPUS = 20,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_LIST_DEFINED_DOMAINS = 21,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:getattr
     */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_ID = 22,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:getattr
     */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_NAME = 23,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:getattr
     */
    REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID = 24,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_DEFINED_DOMAINS = 25,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_PIN_VCPU = 26,

    /**
     * @generate: both
     * @acl: domain:init_control
     * @acl: domain:write:VIR_DOMAIN_REBOOT_GUEST_AGENT
     */
    REMOTE_PROC_DOMAIN_REBOOT = 27,

    /**
     * @generate: both
     * @acl: domain:suspend
     */
    REMOTE_PROC_DOMAIN_RESUME = 28,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_AUTOSTART = 29,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_MAX_MEMORY = 30,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_MEMORY = 31,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_VCPUS = 32,

    /**
     * @generate: both
     * @acl: domain:init_control
     */
    REMOTE_PROC_DOMAIN_SHUTDOWN = 33,

    /**
     * @generate: both
     * @acl: domain:suspend
     */
    REMOTE_PROC_DOMAIN_SUSPEND = 34,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:delete
     */
    REMOTE_PROC_DOMAIN_UNDEFINE = 35,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_LIST_DEFINED_NETWORKS = 36,

    /**
     * @generate: server
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_LIST_DOMAINS = 37,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_LIST_NETWORKS = 38,

    /**
     * @generate: both
     * @acl: network:start
     */
    REMOTE_PROC_NETWORK_CREATE = 39,

    /**
     * @generate: both
     * @acl: network:write
     * @acl: network:start
     */
    REMOTE_PROC_NETWORK_CREATE_XML = 40,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:write
     * @acl: network:save
     */
    REMOTE_PROC_NETWORK_DEFINE_XML = 41,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:stop
     */
    REMOTE_PROC_NETWORK_DESTROY = 42,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_GET_XML_DESC = 43,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_GET_AUTOSTART = 44,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_GET_BRIDGE_NAME = 45,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:getattr
     */
    REMOTE_PROC_NETWORK_LOOKUP_BY_NAME = 46,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:getattr
     */
    REMOTE_PROC_NETWORK_LOOKUP_BY_UUID = 47,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:write
     */
    REMOTE_PROC_NETWORK_SET_AUTOSTART = 48,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:delete
     */
    REMOTE_PROC_NETWORK_UNDEFINE = 49,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_DEFINED_NETWORKS = 50,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_DOMAINS = 51,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_NETWORKS = 52,

    /**
     * @generate: both
     * @acl: domain:core_dump
     */
    REMOTE_PROC_DOMAIN_CORE_DUMP = 53,

    /**
     * @generate: both
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_RESTORE = 54,

    /**
     * @generate: both
     * @acl: domain:hibernate
     */
    REMOTE_PROC_DOMAIN_SAVE = 55,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE = 56,

    /**
     * @generate: client
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS = 57,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS = 58,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_GET_HOSTNAME = 59,

    /**
     * @generate: client
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_SUPPORTS_FEATURE = 60,

    /**
     * @generate: none
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE = 61,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM = 62,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH = 63,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_BLOCK_STATS = 64,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_INTERFACE_STATS = 65,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_AUTH_LIST = 66,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_AUTH_SASL_INIT = 67,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_AUTH_SASL_START = 68,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_AUTH_SASL_STEP = 69,

    /**
     * @generate: none
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_AUTH_POLKIT = 70,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_STORAGE_POOLS = 71,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_LIST_STORAGE_POOLS = 72,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_DEFINED_STORAGE_POOLS = 73,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_LIST_DEFINED_STORAGE_POOLS = 74,

    /**
     * @generate: server
     * @acl: connect:detect_storage_pools
     */
    REMOTE_PROC_CONNECT_FIND_STORAGE_POOL_SOURCES = 75,

    /**
     * @generate: both
     * @acl: storage_pool:start
     * @acl: storage_pool:write
     */
    REMOTE_PROC_STORAGE_POOL_CREATE_XML = 76,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:write
     * @acl: storage_pool:save
     */
    REMOTE_PROC_STORAGE_POOL_DEFINE_XML = 77,

    /**
     * @generate: both
     * @acl: storage_pool:start
     */
    REMOTE_PROC_STORAGE_POOL_CREATE = 78,

    /**
     * @generate: both
     * @acl: storage_pool:format
     */
    REMOTE_PROC_STORAGE_POOL_BUILD = 79,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:stop
     */
    REMOTE_PROC_STORAGE_POOL_DESTROY = 80,

    /**
     * @generate: both
     * @acl: storage_pool:format
     */
    REMOTE_PROC_STORAGE_POOL_DELETE = 81,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:delete
     */
    REMOTE_PROC_STORAGE_POOL_UNDEFINE = 82,

    /**
     * @generate: both
     * @acl: storage_pool:refresh
     */
    REMOTE_PROC_STORAGE_POOL_REFRESH = 83,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:getattr
     */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME = 84,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:getattr
     */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID = 85,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:getattr
     */
    REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_VOLUME = 86,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:read
     */
    REMOTE_PROC_STORAGE_POOL_GET_INFO = 87,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:read
     */
    REMOTE_PROC_STORAGE_POOL_GET_XML_DESC = 88,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:read
     */
    REMOTE_PROC_STORAGE_POOL_GET_AUTOSTART = 89,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:write
     */
    REMOTE_PROC_STORAGE_POOL_SET_AUTOSTART = 90,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:search_storage_vols
     * @aclfilter: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_POOL_NUM_OF_VOLUMES = 91,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:search_storage_vols
     * @aclfilter: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES = 92,

    /**
     * @generate: both
     * @acl: storage_vol:create
     */
    REMOTE_PROC_STORAGE_VOL_CREATE_XML = 93,

    /**
     * @generate: both
     * @acl: storage_vol:delete
     */
    REMOTE_PROC_STORAGE_VOL_DELETE = 94,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME = 95,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_KEY = 96,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_PATH = 97,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:read
     */
    REMOTE_PROC_STORAGE_VOL_GET_INFO = 98,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:read
     */
    REMOTE_PROC_STORAGE_VOL_GET_XML_DESC = 99,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_vol:read
     */
    REMOTE_PROC_STORAGE_VOL_GET_PATH = 100,

    /**
     * @generate: server
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_CELLS_FREE_MEMORY = 101,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_FREE_MEMORY = 102,

    /**
     * @generate: none
     * @acl: domain:block_read
     */
    REMOTE_PROC_DOMAIN_BLOCK_PEEK = 103,

    /**
     * @generate: none
     * @acl: domain:mem_read
     */
    REMOTE_PROC_DOMAIN_MEMORY_PEEK = 104,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_REGISTER = 105,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_DEREGISTER = 106,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE = 107,

    /**
     * @generate: none
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE2 = 108,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH2 = 109,

    /**
     * @generate: server
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_GET_URI = 110,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_node_devices
     * @aclfilter: node_device:getattr
     */
    REMOTE_PROC_NODE_NUM_OF_DEVICES = 111,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_node_devices
     * @aclfilter: node_device:getattr
     */
    REMOTE_PROC_NODE_LIST_DEVICES = 112,

    /**
     * @generate: both
     * @priority: high
     * @acl: node_device:getattr
     */
    REMOTE_PROC_NODE_DEVICE_LOOKUP_BY_NAME = 113,

    /**
     * @generate: both
     * @acl: node_device:read
     */
    REMOTE_PROC_NODE_DEVICE_GET_XML_DESC = 114,

    /**
     * @generate: client
     * @priority: high
     * @acl: node_device:read
     */
    REMOTE_PROC_NODE_DEVICE_GET_PARENT = 115,

    /**
     * @generate: both
     * @priority: high
     * @acl: node_device:read
     */
    REMOTE_PROC_NODE_DEVICE_NUM_OF_CAPS = 116,

    /**
     * @generate: both
     * @priority: high
     * @acl: node_device:read
     */
    REMOTE_PROC_NODE_DEVICE_LIST_CAPS = 117,

    /**
     * @generate: server
     * @acl: node_device:detach
     */
    REMOTE_PROC_NODE_DEVICE_DETTACH = 118,

    /**
     * @generate: server
     * @acl: node_device:detach
     */
    REMOTE_PROC_NODE_DEVICE_RE_ATTACH = 119,

    /**
     * @generate: server
     * @acl: node_device:detach
     */
    REMOTE_PROC_NODE_DEVICE_RESET = 120,

    /**
     * @generate: none
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL = 121,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_SECURITY_MODEL = 122,

    /**
     * @generate: both
     * @acl: node_device:write
     * @acl: node_device:start
     */
    REMOTE_PROC_NODE_DEVICE_CREATE_XML = 123,

    /**
     * @generate: both
     * @priority: high
     * @acl: node_device:stop
     */
    REMOTE_PROC_NODE_DEVICE_DESTROY = 124,

    /**
     * @generate: both
     * @acl: storage_vol:create
     */
    REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM = 125,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_interfaces
     * @aclfilter: interface:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_INTERFACES = 126,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_interfaces
     * @aclfilter: interface:getattr
     */
    REMOTE_PROC_CONNECT_LIST_INTERFACES = 127,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:getattr
     */
    REMOTE_PROC_INTERFACE_LOOKUP_BY_NAME = 128,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:getattr
     */
    REMOTE_PROC_INTERFACE_LOOKUP_BY_MAC_STRING = 129,

    /**
     * @generate: both
     * @acl: interface:read
     */
    REMOTE_PROC_INTERFACE_GET_XML_DESC = 130,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:write
     * @acl: interface:save
     */
    REMOTE_PROC_INTERFACE_DEFINE_XML = 131,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:delete
     */
    REMOTE_PROC_INTERFACE_UNDEFINE = 132,

    /**
     * @generate: both
     * @acl: interface:start
     */
    REMOTE_PROC_INTERFACE_CREATE = 133,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:stop
     */
    REMOTE_PROC_INTERFACE_DESTROY = 134,

    /**
     * @generate: both
     * @acl: connect:write
     */
    REMOTE_PROC_CONNECT_DOMAIN_XML_FROM_NATIVE = 135,

    /**
     * @generate: both
     * @acl: connect:write
     */
    REMOTE_PROC_CONNECT_DOMAIN_XML_TO_NATIVE = 136,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_interfaces
     * @aclfilter: interface:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_DEFINED_INTERFACES = 137,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_interfaces
     * @aclfilter: interface:getattr
     */
    REMOTE_PROC_CONNECT_LIST_DEFINED_INTERFACES = 138,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_secrets
     * @aclfilter: secret:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_SECRETS = 139,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_secrets
     * @aclfilter: secret:getattr
     */
    REMOTE_PROC_CONNECT_LIST_SECRETS = 140,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:getattr
     */
    REMOTE_PROC_SECRET_LOOKUP_BY_UUID = 141,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:write
     * @acl: secret:save
     */
    REMOTE_PROC_SECRET_DEFINE_XML = 142,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:read
     */
    REMOTE_PROC_SECRET_GET_XML_DESC = 143,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:write
     */
    REMOTE_PROC_SECRET_SET_VALUE = 144,

    /**
     * @generate: none
     * @priority: high
     * @acl: secret:read_secure
     */
    REMOTE_PROC_SECRET_GET_VALUE = 145,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:delete
     */
    REMOTE_PROC_SECRET_UNDEFINE = 146,

    /**
     * @generate: both
     * @priority: high
     * @acl: secret:getattr
     */
    REMOTE_PROC_SECRET_LOOKUP_BY_USAGE = 147,

    /**
     * @generate: both
     * @writestream: 1
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL = 148,

    /**
     * @generate: server
     * @priority: high
     * @acl: none
     */
    REMOTE_PROC_CONNECT_IS_SECURE = 149,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_IS_ACTIVE = 150,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_IS_PERSISTENT = 151,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_IS_ACTIVE = 152,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_IS_PERSISTENT = 153,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:read
     */
    REMOTE_PROC_STORAGE_POOL_IS_ACTIVE = 154,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:read
     */
    REMOTE_PROC_STORAGE_POOL_IS_PERSISTENT = 155,

    /**
     * @generate: both
     * @priority: high
     * @acl: interface:read
     */
    REMOTE_PROC_INTERFACE_IS_ACTIVE = 156,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_GET_LIB_VERSION = 157,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_COMPARE_CPU = 158,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_MEMORY_STATS = 159,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS = 160,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS = 161,

    /**
     * @generate: both
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_BASELINE_CPU = 162,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_JOB_INFO = 163,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_ABORT_JOB = 164,

    /**
     * @generate: both
     * @acl: storage_vol:format
     */
    REMOTE_PROC_STORAGE_VOL_WIPE = 165,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_DOWNTIME = 166,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_REGISTER_ANY = 167,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_DEREGISTER_ANY = 168,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_REBOOT = 169,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE = 170,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_WATCHDOG = 171,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR = 172,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_GRAPHICS = 173,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS = 174,

    /**
     * @generate: both
     * @priority: high
     * @acl: nwfilter:getattr
     */
    REMOTE_PROC_NWFILTER_LOOKUP_BY_NAME = 175,

    /**
     * @generate: both
     * @priority: high
     * @acl: nwfilter:getattr
     */
    REMOTE_PROC_NWFILTER_LOOKUP_BY_UUID = 176,

    /**
     * @generate: both
     * @priority: high
     * @acl: nwfilter:read
     */
    REMOTE_PROC_NWFILTER_GET_XML_DESC = 177,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_nwfilters
     * @aclfilter: nwfilter:getattr
     */
    REMOTE_PROC_CONNECT_NUM_OF_NWFILTERS = 178,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_nwfilters
     * @aclfilter: nwfilter:getattr
     */
    REMOTE_PROC_CONNECT_LIST_NWFILTERS = 179,

    /**
     * @generate: both
     * @priority: high
     * @acl: nwfilter:write
     * @acl: nwfilter:save
     */
    REMOTE_PROC_NWFILTER_DEFINE_XML = 180,

    /**
     * @generate: both
     * @priority: high
     * @acl: nwfilter:delete
     */
    REMOTE_PROC_NWFILTER_UNDEFINE = 181,

    /**
     * @generate: both
     * @acl: domain:hibernate
     */
    REMOTE_PROC_DOMAIN_MANAGED_SAVE = 182,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_HAS_MANAGED_SAVE_IMAGE = 183,

    /**
     * @generate: both
     * @acl: domain:hibernate
     */
    REMOTE_PROC_DOMAIN_MANAGED_SAVE_REMOVE = 184,

    /**
     * @generate: both
     * @acl: domain:snapshot
     * @acl: domain:fs_freeze:VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_CREATE_XML = 185,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     * @acl: domain:read_secure:VIR_DOMAIN_XML_SECURE
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_GET_XML_DESC = 186,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_NUM = 187,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_NAMES = 188,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LOOKUP_BY_NAME = 189,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_HAS_CURRENT_SNAPSHOT = 190,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_CURRENT = 191,

    /**
     * @generate: both
     * @acl: domain:snapshot
     */
    REMOTE_PROC_DOMAIN_REVERT_TO_SNAPSHOT = 192,

    /**
     * @generate: both
     * @acl: domain:snapshot
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_DELETE = 193,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_BLOCK_INFO = 194,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON = 195,

    /**
     * @generate: server
     * @acl: domain:start
     */
    REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS = 196,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_MEMORY_PARAMETERS = 197,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS = 198,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     * @acl: domain:write:VIR_DOMAIN_VCPU_GUEST
     */
    REMOTE_PROC_DOMAIN_SET_VCPUS_FLAGS = 199,

    /**
     * @generate: both
     * @acl: domain:read
     * @acl: domain:write:VIR_DOMAIN_VCPU_GUEST
     */
    REMOTE_PROC_DOMAIN_GET_VCPUS_FLAGS = 200,

    /**
     * @generate: both
     * @readstream: 2
     * @acl: domain:open_device
     */
    REMOTE_PROC_DOMAIN_OPEN_CONSOLE = 201,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_IS_UPDATED = 202,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_GET_SYSINFO = 203,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_MEMORY_FLAGS = 204,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_BLKIO_PARAMETERS = 205,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_BLKIO_PARAMETERS = 206,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_SPEED = 207,

    /**
     * @generate: both
     * @writestream: 1
     * @acl: storage_vol:data_write
     */
    REMOTE_PROC_STORAGE_VOL_UPLOAD = 208,

    /**
     * @generate: both
     * @readstream: 1
     * @acl: storage_vol:data_read
     */
    REMOTE_PROC_STORAGE_VOL_DOWNLOAD = 209,

    /**
     * @generate: both
     * @acl: domain:inject_nmi
     */
    REMOTE_PROC_DOMAIN_INJECT_NMI = 210,

    /**
     * @generate: both
     * @readstream: 1
     * @acl: domain:screenshot
     */
    REMOTE_PROC_DOMAIN_SCREENSHOT = 211,

    /**
     * @generate: none
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_STATE = 212,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3 = 213,

    /**
     * @generate: none
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE3 = 214,

    /**
     * @generate: server
     * @writestream: 1
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3 = 215,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3 = 216,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH3 = 217,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_CONFIRM3 = 218,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS_FLAGS = 219,

    /**
     * @generate: both
     * @acl: connect:interface_transaction
     */
    REMOTE_PROC_INTERFACE_CHANGE_BEGIN = 220,

    /**
     * @generate: both
     * @acl: connect:interface_transaction
     */
    REMOTE_PROC_INTERFACE_CHANGE_COMMIT = 221,

    /**
     * @generate: both
     * @acl: connect:interface_transaction
     */
    REMOTE_PROC_INTERFACE_CHANGE_ROLLBACK = 222,

    /**
     * @generate: client
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS_FLAGS = 223,

    /**
     * @generate: none
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CONTROL_ERROR = 224,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_PIN_VCPU_FLAGS = 225,

    /**
     * @generate: both
     * @acl: domain:send_input
     */
    REMOTE_PROC_DOMAIN_SEND_KEY = 226,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_CPU_STATS = 227,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_MEMORY_STATS = 228,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_CONTROL_INFO = 229,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_VCPU_PIN_INFO = 230,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:delete
     */
    REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS = 231,

    /**
     * @generate: both
     * @acl: domain:hibernate
     */
    REMOTE_PROC_DOMAIN_SAVE_FLAGS = 232,

    /**
     * @generate: both
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_RESTORE_FLAGS = 233,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:stop
     */
    REMOTE_PROC_DOMAIN_DESTROY_FLAGS = 234,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     * @acl: domain:read_secure:VIR_DOMAIN_XML_SECURE
     */
    REMOTE_PROC_DOMAIN_SAVE_IMAGE_GET_XML_DESC = 235,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:write
     * @acl: domain:hibernate
     */
    REMOTE_PROC_DOMAIN_SAVE_IMAGE_DEFINE_XML = 236,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_BLOCK_JOB_ABORT = 237,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_BLOCK_JOB_INFO = 238,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_BLOCK_JOB_SET_SPEED = 239,

    /**
     * @generate: both
     * @acl: domain:block_write
     */
    REMOTE_PROC_DOMAIN_BLOCK_PULL = 240,

    /**
     * @generate: none
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_BLOCK_JOB = 241,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_GET_MAX_SPEED = 242,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_BLOCK_STATS_FLAGS = 243,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_GET_PARENT = 244,

    /**
     * @generate: both
     * @acl: domain:reset
     */
    REMOTE_PROC_DOMAIN_RESET = 245,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_NUM_CHILDREN = 246,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_CHILDREN_NAMES = 247,

    /**
     * @generate: none
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_DISK_CHANGE = 248,

    /**
     * @generate: none
     * @acl: domain:open_graphics
     */
    REMOTE_PROC_DOMAIN_OPEN_GRAPHICS = 249,

    /**
     * @generate: both
     * @acl: connect:pm_control
     */
    REMOTE_PROC_NODE_SUSPEND_FOR_DURATION = 250,

    /**
     * @generate: both
     * @acl: domain:block_write
     */
    REMOTE_PROC_DOMAIN_BLOCK_RESIZE = 251,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_BLOCK_IO_TUNE = 252,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_BLOCK_IO_TUNE = 253,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_NUMA_PARAMETERS = 254,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_NUMA_PARAMETERS = 255,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_INTERFACE_PARAMETERS = 256,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_INTERFACE_PARAMETERS = 257,

    /**
     * @generate: both
     * @acl: domain:init_control
     * @acl: domain:write:VIR_DOMAIN_SHUTDOWN_GUEST_AGENT
     */
    REMOTE_PROC_DOMAIN_SHUTDOWN_FLAGS = 258,

    /**
     * @generate: both
     * @acl: storage_vol:format
     */
    REMOTE_PROC_STORAGE_VOL_WIPE_PATTERN = 259,

    /**
     * @generate: both
     * @acl: storage_vol:resize
     */
    REMOTE_PROC_STORAGE_VOL_RESIZE = 260,

    /**
     * @generate: both
     * @acl: domain:pm_control
     */
    REMOTE_PROC_DOMAIN_PM_SUSPEND_FOR_DURATION = 261,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_CPU_STATS = 262,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_DISK_ERRORS = 263,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_METADATA = 264,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_METADATA = 265,

    /**
     * @generate: both
     * @acl: domain:block_write
     */
    REMOTE_PROC_DOMAIN_BLOCK_REBASE = 266,

    /**
     * @generate: both
     * @acl: domain:pm_control
     */
    REMOTE_PROC_DOMAIN_PM_WAKEUP = 267,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_TRAY_CHANGE = 268,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_PMWAKEUP = 269,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND = 270,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_IS_CURRENT = 271,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_HAS_METADATA = 272,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS = 273,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_LIST_ALL_SNAPSHOTS = 274,

    /**
     * @generate: both
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_ALL_CHILDREN = 275,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_BALLOON_CHANGE = 276,

    /**
     * @generate: both
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_HOSTNAME = 277,

    /**
     * @generate: none
     * @priority: high
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL_LIST = 278,

    /**
     * @generate: none
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_PIN_EMULATOR = 279,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_EMULATOR_PIN_INFO = 280,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_STORAGE_POOLS = 281,

    /**
     * @generate: both
     * @priority: high
     * @acl: storage_pool:search_storage_vols
     * @aclfilter: storage_vol:getattr
     */
    REMOTE_PROC_STORAGE_POOL_LIST_ALL_VOLUMES = 282,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_NETWORKS = 283,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_interfaces
     * @aclfilter: interface:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_INTERFACES = 284,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_node_devices
     * @aclfilter: node_device:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_NODE_DEVICES = 285,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_nwfilters
     * @aclfilter: nwfilter:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_NWFILTERS = 286,

    /**
     * @generate: both
     * @priority: high
     * @acl: connect:search_secrets
     * @aclfilter: secret:getattr
     */
    REMOTE_PROC_CONNECT_LIST_ALL_SECRETS = 287,

    /**
     * @generate: both
     * @acl: connect:write
     */
    REMOTE_PROC_NODE_SET_MEMORY_PARAMETERS = 288,

    /**
     * @generate: none
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_MEMORY_PARAMETERS = 289,

    /**
     * @generate: both
     * @acl: domain:block_write
     */
    REMOTE_PROC_DOMAIN_BLOCK_COMMIT = 290,

    /**
     * @generate: both
     * @priority: high
     * @acl: network:write
     * @acl: network:save:!VIR_NETWORK_UPDATE_AFFECT_CONFIG|VIR_NETWORK_UPDATE_AFFECT_LIVE
     * @acl: network:save:VIR_NETWORK_UPDATE_AFFECT_CONFIG
     */
    REMOTE_PROC_NETWORK_UPDATE = 291,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND_DISK = 292,

    /**
     * @generate: none
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_CPU_MAP = 293,

    /**
     * @generate: both
     * @acl: domain:fs_trim
     */
    REMOTE_PROC_DOMAIN_FSTRIM = 294,

    /**
     * @generate: both
     * @acl: domain:send_signal
     */
    REMOTE_PROC_DOMAIN_SEND_PROCESS_SIGNAL = 295,

    /**
     * @generate: both
     * @readstream: 2
     * @acl: domain:open_device
     */
    REMOTE_PROC_DOMAIN_OPEN_CHANNEL = 296,

    /**
     * @generate: both
     * @priority: high
     * @acl: node_device:getattr
     */
    REMOTE_PROC_NODE_DEVICE_LOOKUP_SCSI_HOST_BY_WWN = 297,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_JOB_STATS = 298,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_GET_COMPRESSION_CACHE = 299,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_SET_COMPRESSION_CACHE = 300,

    /**
     * @generate: server
     * @acl: node_device:detach
     */
    REMOTE_PROC_NODE_DEVICE_DETACH_FLAGS = 301,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3_PARAMS = 302,

    /**
     * @generate: none
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE3_PARAMS = 303,

    /**
     * @generate: none
     * @acl: domain:migrate
     * @acl: domain:start
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3_PARAMS = 304,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3_PARAMS = 305,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_FINISH3_PARAMS = 306,

    /**
     * @generate: none
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_CONFIRM3_PARAMS = 307,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_SET_MEMORY_STATS_PERIOD = 308,

    /**
     * @generate: none
     * @acl: domain:write
     * @acl: domain:start
     */
    REMOTE_PROC_DOMAIN_CREATE_XML_WITH_FILES = 309,

    /**
     * @generate: none
     * @acl: domain:start
     */
    REMOTE_PROC_DOMAIN_CREATE_WITH_FILES = 310,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_DEVICE_REMOVED = 311,

    /**
     * @generate: none
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_GET_CPU_MODEL_NAMES = 312,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_networks
     * @aclfilter: network:getattr
     */
    REMOTE_PROC_CONNECT_NETWORK_EVENT_REGISTER_ANY = 313,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_NETWORK_EVENT_DEREGISTER_ANY = 314,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_NETWORK_EVENT_LIFECYCLE = 315,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_domains
     * @aclfilter: domain:getattr
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY = 316,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_DEREGISTER_ANY = 317,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE = 318,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_REBOOT = 319,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_RTC_CHANGE = 320,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_WATCHDOG = 321,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_IO_ERROR = 322,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_GRAPHICS = 323,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_IO_ERROR_REASON = 324,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_CONTROL_ERROR = 325,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_BLOCK_JOB = 326,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_DISK_CHANGE = 327,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_TRAY_CHANGE = 328,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_PMWAKEUP = 329,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_PMSUSPEND = 330,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_BALLOON_CHANGE = 331,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_PMSUSPEND_DISK = 332,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_DEVICE_REMOVED = 333,

    /**
     * @generate: both
     * @acl: domain:core_dump
     */
    REMOTE_PROC_DOMAIN_CORE_DUMP_WITH_FORMAT = 334,

    /**
     * @generate: both
     * @acl: domain:fs_freeze
     */
    REMOTE_PROC_DOMAIN_FSFREEZE = 335,

    /**
     * @generate: both
     * @acl: domain:fs_freeze
     */
    REMOTE_PROC_DOMAIN_FSTHAW = 336,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_TIME = 337,

    /**
     * @generate: both
     * @acl: domain:set_time
     */
    REMOTE_PROC_DOMAIN_SET_TIME = 338,

    /**
     * @generate: none
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_BLOCK_JOB_2 = 339,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_NODE_GET_FREE_PAGES = 340,

    /**
     * @generate: none
     * @acl: network:read
     */
    REMOTE_PROC_NETWORK_GET_DHCP_LEASES = 341,

    /**
     * @generate: both
     * @acl: connect:write
     */
    REMOTE_PROC_CONNECT_GET_DOMAIN_CAPABILITIES = 342,

    /**
     * @generate: none
     * @acl: domain:open_graphics
     */
    REMOTE_PROC_DOMAIN_OPEN_GRAPHICS_FD = 343,

    /**
     * @generate: none
     * @acl: connect:search_domains
     * @aclfilter: domain:read
     */
    REMOTE_PROC_CONNECT_GET_ALL_DOMAIN_STATS = 344,

    /**
     * @generate: both
     * @acl: domain:block_write
     */
    REMOTE_PROC_DOMAIN_BLOCK_COPY = 345,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_TUNABLE = 346,

    /**
     * @generate: none
     * @acl: connect:write
     */
    REMOTE_PROC_NODE_ALLOC_PAGES = 347,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_AGENT_LIFECYCLE = 348,

    /**
     * @generate: none
     * @acl: domain:fs_freeze
     */
    REMOTE_PROC_DOMAIN_GET_FSINFO = 349,

    /**
     * @priority: high
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save
     */
    REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS = 350,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_IOTHREAD_INFO = 351,

    /**
     * @generate: both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_PIN_IOTHREAD = 352,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_INTERFACE_ADDRESSES = 353,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_DEVICE_ADDED = 354,

    /**
     * @generate:both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_ADD_IOTHREAD = 355,

    /**
     * @generate:both
     * @acl: domain:write
     * @acl: domain:save:!VIR_DOMAIN_AFFECT_CONFIG|VIR_DOMAIN_AFFECT_LIVE
     * @acl: domain:save:VIR_DOMAIN_AFFECT_CONFIG
     */
    REMOTE_PROC_DOMAIN_DEL_IOTHREAD = 356,

    /**
     * @generate:both
     * @acl: domain:set_password
     */
    REMOTE_PROC_DOMAIN_SET_USER_PASSWORD = 357,

    /**
     * @generate: server
     * @acl: domain:write
     * @acl: domain:save
     */
    REMOTE_PROC_DOMAIN_RENAME = 358,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_MIGRATION_ITERATION = 359,

    /**
     * @generate: none
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_REGISTER_CLOSE_CALLBACK = 360,

    /**
     * @generate: none
     * @acl: connect:getattr
     */
    REMOTE_PROC_CONNECT_UNREGISTER_CLOSE_CALLBACK = 361,

    /**
     * @generate: none
     * @acl: none
     */
    REMOTE_PROC_CONNECT_EVENT_CONNECTION_CLOSED = 362,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_JOB_COMPLETED = 363,

    /**
     * @generate: both
     * @acl: domain:migrate
     */
    REMOTE_PROC_DOMAIN_MIGRATE_START_POST_COPY = 364,

    /**
     * @generate: none
     * @acl: domain:read
     */
    REMOTE_PROC_DOMAIN_GET_PERF_EVENTS = 365,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_PERF_EVENTS = 366,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_DOMAIN_EVENT_CALLBACK_DEVICE_REMOVAL_FAILED = 367,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_storage_pools
     * @aclfilter: storage_pool:getattr
     */
    REMOTE_PROC_CONNECT_STORAGE_POOL_EVENT_REGISTER_ANY = 368,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_STORAGE_POOL_EVENT_DEREGISTER_ANY = 369,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_STORAGE_POOL_EVENT_LIFECYCLE = 370,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_GET_GUEST_VCPUS = 371,

    /**
     * @generate: both
     * @acl: domain:write
     */
    REMOTE_PROC_DOMAIN_SET_GUEST_VCPUS = 372,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_STORAGE_POOL_EVENT_REFRESH = 373,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:search_node_devices
     * @aclfilter: node_device:getattr
     */
    REMOTE_PROC_CONNECT_NODE_DEVICE_EVENT_REGISTER_ANY = 374,

    /**
     * @generate: none
     * @priority: high
     * @acl: connect:read
     */
    REMOTE_PROC_CONNECT_NODE_DEVICE_EVENT_DEREGISTER_ANY = 375,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_NODE_DEVICE_EVENT_LIFECYCLE = 376,

    /**
     * @generate: both
     * @acl: none
     */
    REMOTE_PROC_NODE_DEVICE_EVENT_UPDATE = 377,

    /**
     * @generate: none
     * @priority: high
     * @acl: storage_vol:read
     */
    REMOTE_PROC_STORAGE_VOL_GET_INFO_FLAGS = 378
};
