/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <glib-object.h>
#include "virthread.h"
#include "vircgroup.h"
#include "virperf.h"
#include "domain_addr.h"
#include "domain_conf.h"
#include "snapshot_conf.h"
#include "qemu_monitor.h"
#include "qemu_agent.h"
#include "qemu_blockjob.h"
#include "qemu_domainjob.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_migration_params.h"
#include "qemu_slirp.h"
#include "virmdev.h"
#include "virchrdev.h"
#include "virobject.h"
#include "logging/log_manager.h"
#include "virdomainmomentobjlist.h"
#include "virenum.h"
#include "vireventthread.h"

#define QEMU_DOMAIN_FORMAT_LIVE_FLAGS \
    (VIR_DOMAIN_XML_SECURE)

#if ULONG_MAX == 4294967295
/* QEMU has a 64-bit limit, but we are limited by our historical choice of
 * representing bandwidth in a long instead of a 64-bit int.  */
# define QEMU_DOMAIN_MIG_BANDWIDTH_MAX ULONG_MAX
#else
# define QEMU_DOMAIN_MIG_BANDWIDTH_MAX (INT64_MAX / (1024 * 1024))
#endif

typedef void (*qemuDomainCleanupCallback)(virQEMUDriverPtr driver,
                                          virDomainObjPtr vm);

#define QEMU_DOMAIN_MASTER_KEY_LEN 32  /* 32 bytes for 256 bit random key */

void
qemuDomainObjSaveStatus(virQEMUDriverPtr driver,
                        virDomainObjPtr obj);

void qemuDomainSaveStatus(virDomainObjPtr obj);
void qemuDomainSaveConfig(virDomainObjPtr obj);


/* helper data types for async device unplug */
typedef enum {
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_NONE = 0,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_OK,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED,
} qemuDomainUnpluggingDeviceStatus;

typedef struct _qemuDomainUnpluggingDevice qemuDomainUnpluggingDevice;
typedef qemuDomainUnpluggingDevice *qemuDomainUnpluggingDevicePtr;
struct _qemuDomainUnpluggingDevice {
    const char *alias;
    qemuDomainUnpluggingDeviceStatus status;
    bool eventSeen; /* True if DEVICE_DELETED event arrived. */
};


#define QEMU_PROC_MOUNTS "/proc/mounts"
#define QEMU_DEVPREFIX "/dev/"
#define QEMU_DEV_VFIO "/dev/vfio/vfio"
#define QEMU_DEV_SEV "/dev/sev"
#define QEMU_DEVICE_MAPPER_CONTROL_PATH "/dev/mapper/control"


/* Type of domain secret */
typedef enum {
    VIR_DOMAIN_SECRET_INFO_TYPE_PLAIN = 0,
    VIR_DOMAIN_SECRET_INFO_TYPE_AES,  /* utilize GNUTLS_CIPHER_AES_256_CBC */

    VIR_DOMAIN_SECRET_INFO_TYPE_LAST
} qemuDomainSecretInfoType;

typedef struct _qemuDomainSecretPlain qemuDomainSecretPlain;
typedef struct _qemuDomainSecretPlain *qemuDomainSecretPlainPtr;
struct _qemuDomainSecretPlain {
    char *username;
    uint8_t *secret;
    size_t secretlen;
};

#define QEMU_DOMAIN_AES_IV_LEN 16   /* 16 bytes for 128 bit random */
                                    /*    initialization vector */
typedef struct _qemuDomainSecretAES qemuDomainSecretAES;
typedef struct _qemuDomainSecretAES *qemuDomainSecretAESPtr;
struct _qemuDomainSecretAES {
    char *username;
    char *alias;      /* generated alias for secret */
    char *iv;         /* base64 encoded initialization vector */
    char *ciphertext; /* encoded/encrypted secret */
};

typedef struct _qemuDomainSecretInfo qemuDomainSecretInfo;
typedef qemuDomainSecretInfo *qemuDomainSecretInfoPtr;
struct _qemuDomainSecretInfo {
    qemuDomainSecretInfoType type;
    union {
        qemuDomainSecretPlain plain;
        qemuDomainSecretAES aes;
    } s;
};

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    virQEMUDriverPtr driver;

    qemuDomainJobObj job;

    virBitmapPtr namespaces;

    virEventThread *eventThread;

    qemuMonitorPtr mon;
    virDomainChrSourceDefPtr monConfig;
    bool monError;
    unsigned long long monStart;
    int agentTimeout;

    qemuAgentPtr agent;
    bool agentError;

    bool beingDestroyed;
    char *pidfile;

    virDomainPCIAddressSetPtr pciaddrs;
    virDomainUSBAddressSetPtr usbaddrs;

    virQEMUCapsPtr qemuCaps;
    char *lockState;

    bool fakeReboot;
    bool pausedShutdown;
    virTristateBool allowReboot;

    int jobs_queued;

    unsigned long migMaxBandwidth;
    char *origname;
    int nbdPort; /* Port used for migration with NBD */
    unsigned short migrationPort;
    int preMigrationState;

    virChrdevsPtr devs;

    qemuDomainCleanupCallback *cleanupCallbacks;
    size_t ncleanupCallbacks;
    size_t ncleanupCallbacks_max;

    virCgroupPtr cgroup;

    virPerfPtr perf;

    qemuDomainUnpluggingDevice unplug;

    char **qemuDevices; /* NULL-terminated list of devices aliases known to QEMU */

    bool hookRun;  /* true if there was a hook run over this domain */

    /* Bitmaps below hold data from the auto NUMA feature */
    virBitmapPtr autoNodeset;
    virBitmapPtr autoCpuset;

    bool signalIOError; /* true if the domain condition should be signalled on
                           I/O error */
    bool signalStop; /* true if the domain condition should be signalled on
                        QMP STOP event */
    char *machineName;
    char *libDir;            /* base path for per-domain files */
    char *channelTargetDir;  /* base path for per-domain channel targets */

    /* random masterKey and length for encryption (not to be saved in our */
    /* private XML) - need to restore at process reconnect */
    uint8_t *masterKey;
    size_t masterKeyLen;

    /* note whether memory device alias does not correspond to slot number */
    bool memAliasOrderMismatch;

    /* for migrations using TLS with a secret (not to be saved in our */
    /* private XML). */
    qemuDomainSecretInfoPtr migSecinfo;

    /* CPU def used to start the domain when it differs from the one actually
     * provided by QEMU. */
    virCPUDefPtr origCPU;

    /* If true virtlogd is used as stdio handler for character devices. */
    bool chardevStdioLogd;

    /* Tracks blockjob state for vm. Valid only while reconnecting to qemu. */
    virTristateBool reconnectBlockjobs;

    /* Migration capabilities. Rechecked on reconnect, not to be saved in
     * private XML. */
    virBitmapPtr migrationCaps;

    /* true if qemu-pr-helper process is running for the domain */
    bool prDaemonRunning;

    /* counter for generating node names for qemu disks */
    unsigned long long nodenameindex;

    /* qemuProcessStartCPUs stores the reason for starting vCPUs here for the
     * RESUME event handler to use it */
    virDomainRunningReason runningReason;

    /* qemuProcessStopCPUs stores the reason for pausing vCPUs here for the
     * STOP event handler to use it */
    virDomainPausedReason pausedReason;

    /* true if libvirt remembers the original owner for files */
    bool rememberOwner;

    /* true if global -mem-prealloc appears on cmd line */
    bool memPrealloc;

    /* running block jobs */
    GHashTable *blockjobs;

    bool disableSlirp;

    /* Until we add full support for backing chains for pflash drives, these
     * pointers hold the temporary virStorageSources for creating the -blockdev
     * commandline for pflash drives. */
    virStorageSourcePtr pflash0;
    virStorageSourcePtr pflash1;

    /* running backup job */
    virDomainBackupDefPtr backup;

    bool dbusDaemonRunning;

    /* list of Ids to migrate */
    char **dbusVMStateIds;
    /* true if -object dbus-vmstate was added */
    bool dbusVMState;

    /* prevent deletion of <transient> disk overlay files between startup and
     * succesful setup of the overlays */
    bool inhibitDiskTransientDelete;
};

#define QEMU_DOMAIN_PRIVATE(vm) \
    ((qemuDomainObjPrivatePtr) (vm)->privateData)

#define QEMU_DOMAIN_DISK_PRIVATE(disk) \
    ((qemuDomainDiskPrivatePtr) (disk)->privateData)

typedef struct _qemuDomainDiskPrivate qemuDomainDiskPrivate;
typedef qemuDomainDiskPrivate *qemuDomainDiskPrivatePtr;
struct _qemuDomainDiskPrivate {
    virObject parent;

    /* ideally we want a smarter way to interlock block jobs on single qemu disk
     * in the future, but for now we just disallow any concurrent job on a
     * single disk */
    qemuBlockJobDataPtr blockjob;

    bool migrating; /* the disk is being migrated */
    virStorageSourcePtr migrSource; /* disk source object used for NBD migration */

    /* information about the device */
    bool tray; /* device has tray */
    bool removable; /* device media can be removed/changed */

    char *qomName; /* QOM path of the disk (also refers to the block backend) */
    char *nodeCopyOnRead; /* nodename of the disk-wide copy-on-read blockdev layer */
};

#define QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src) \
    ((qemuDomainStorageSourcePrivatePtr) (src)->privateData)

typedef struct _qemuDomainStorageSourcePrivate qemuDomainStorageSourcePrivate;
typedef qemuDomainStorageSourcePrivate *qemuDomainStorageSourcePrivatePtr;
struct _qemuDomainStorageSourcePrivate {
    virObject parent;

    /* data required for authentication to the storage source */
    qemuDomainSecretInfoPtr secinfo;

    /* data required for decryption of encrypted storage source */
    qemuDomainSecretInfoPtr encinfo;

    /* secure passthrough of the http cookie */
    qemuDomainSecretInfoPtr httpcookie;

    /* key for decrypting TLS certificate */
    qemuDomainSecretInfoPtr tlsKeySecret;
};

virObjectPtr qemuDomainStorageSourcePrivateNew(void);
qemuDomainStorageSourcePrivatePtr
qemuDomainStorageSourcePrivateFetch(virStorageSourcePtr src);

typedef struct _qemuDomainVcpuPrivate qemuDomainVcpuPrivate;
typedef qemuDomainVcpuPrivate *qemuDomainVcpuPrivatePtr;
struct _qemuDomainVcpuPrivate {
    virObject parent;

    pid_t tid; /* vcpu thread id */
    int enable_id; /* order in which the vcpus were enabled in qemu */
    int qemu_id; /* ID reported by qemu as 'CPU' in query-cpus */
    char *alias;
    virTristateBool halted;

    /* copy of the data that qemu returned */
    virJSONValuePtr props;

    /* information for hotpluggable cpus */
    char *type;
    int socket_id;
    int core_id;
    int thread_id;
    int node_id;
    int vcpus;
};

#define QEMU_DOMAIN_VCPU_PRIVATE(vcpu) \
    ((qemuDomainVcpuPrivatePtr) (vcpu)->privateData)


struct qemuDomainDiskInfo {
    bool removable;
    bool tray;
    bool tray_open;
    bool empty;
    int io_status;
    char *nodename;
};

#define QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev) \
    ((qemuDomainChrSourcePrivatePtr) (dev)->privateData)

typedef struct _qemuDomainChrSourcePrivate qemuDomainChrSourcePrivate;
typedef qemuDomainChrSourcePrivate *qemuDomainChrSourcePrivatePtr;
struct _qemuDomainChrSourcePrivate {
    virObject parent;

    /* for char devices using secret
     * NB: *not* to be written to qemu domain object XML */
    qemuDomainSecretInfoPtr secinfo;
};


typedef struct _qemuDomainVsockPrivate qemuDomainVsockPrivate;
typedef qemuDomainVsockPrivate *qemuDomainVsockPrivatePtr;
struct _qemuDomainVsockPrivate {
    virObject parent;

    int vhostfd;
};


#define QEMU_DOMAIN_VIDEO_PRIVATE(dev) \
    ((qemuDomainVideoPrivatePtr) (dev)->privateData)

typedef struct _qemuDomainVideoPrivate qemuDomainVideoPrivate;
typedef qemuDomainVideoPrivate *qemuDomainVideoPrivatePtr;
struct _qemuDomainVideoPrivate {
    virObject parent;

    int vhost_user_fd;
};


#define QEMU_DOMAIN_GRAPHICS_PRIVATE(dev) \
    ((qemuDomainGraphicsPrivatePtr) (dev)->privateData)

typedef struct _qemuDomainGraphicsPrivate qemuDomainGraphicsPrivate;
typedef qemuDomainGraphicsPrivate *qemuDomainGraphicsPrivatePtr;
struct _qemuDomainGraphicsPrivate {
    virObject parent;

    char *tlsAlias;
    qemuDomainSecretInfoPtr secinfo;
};


#define QEMU_DOMAIN_NETWORK_PRIVATE(dev) \
    ((qemuDomainNetworkPrivatePtr) (dev)->privateData)

typedef struct _qemuDomainNetworkPrivate qemuDomainNetworkPrivate;
typedef qemuDomainNetworkPrivate *qemuDomainNetworkPrivatePtr;
struct _qemuDomainNetworkPrivate {
    virObject parent;

    qemuSlirpPtr slirp;
};


#define QEMU_DOMAIN_FS_PRIVATE(dev) \
    ((qemuDomainFSPrivatePtr) (dev)->privateData)

typedef struct _qemuDomainFSPrivate qemuDomainFSPrivate;
typedef qemuDomainFSPrivate *qemuDomainFSPrivatePtr;
struct _qemuDomainFSPrivate {
    virObject parent;

    char *vhostuser_fs_sock;
};


typedef enum {
    QEMU_PROCESS_EVENT_WATCHDOG = 0,
    QEMU_PROCESS_EVENT_GUESTPANIC,
    QEMU_PROCESS_EVENT_DEVICE_DELETED,
    QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED,
    QEMU_PROCESS_EVENT_SERIAL_CHANGED,
    QEMU_PROCESS_EVENT_BLOCK_JOB,
    QEMU_PROCESS_EVENT_JOB_STATUS_CHANGE,
    QEMU_PROCESS_EVENT_MONITOR_EOF,
    QEMU_PROCESS_EVENT_PR_DISCONNECT,
    QEMU_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED,
    QEMU_PROCESS_EVENT_GUEST_CRASHLOADED,

    QEMU_PROCESS_EVENT_LAST
} qemuProcessEventType;

struct qemuProcessEvent {
    virDomainObjPtr vm;
    qemuProcessEventType eventType;
    int action;
    int status;
    void *data;
};

void qemuProcessEventFree(struct qemuProcessEvent *event);

#define QEMU_TYPE_DOMAIN_LOG_CONTEXT qemu_domain_log_context_get_type()
G_DECLARE_FINAL_TYPE(qemuDomainLogContext, qemu_domain_log_context, QEMU, DOMAIN_LOG_CONTEXT, GObject);
typedef qemuDomainLogContext *qemuDomainLogContextPtr;

typedef struct _qemuDomainSaveCookie qemuDomainSaveCookie;
typedef qemuDomainSaveCookie *qemuDomainSaveCookiePtr;
struct _qemuDomainSaveCookie {
    virObject parent;

    virCPUDefPtr cpu;
    bool slirpHelper;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSaveCookie, virObjectUnref);

typedef struct _qemuDomainXmlNsDef qemuDomainXmlNsDef;
typedef qemuDomainXmlNsDef *qemuDomainXmlNsDefPtr;
struct _qemuDomainXmlNsDef {
    size_t num_args;
    char **args;

    unsigned int num_env;
    char **env_name;
    char **env_value;

    size_t ncapsadd;
    char **capsadd;

    size_t ncapsdel;
    char **capsdel;
};

typedef struct _qemuDomainJobPrivate qemuDomainJobPrivate;
typedef qemuDomainJobPrivate *qemuDomainJobPrivatePtr;
struct _qemuDomainJobPrivate {
    bool spiceMigration;                /* we asked for spice migration and we
                                         * should wait for it to finish */
    bool spiceMigrated;                 /* spice migration completed */
    bool dumpCompleted;                 /* dump completed */
    qemuMigrationParamsPtr migParams;
};

int qemuDomainObjStartWorker(virDomainObjPtr dom);
void qemuDomainObjStopWorker(virDomainObjPtr dom);

virDomainObjPtr qemuDomainObjFromDomain(virDomainPtr domain);

qemuDomainSaveCookiePtr qemuDomainSaveCookieNew(virDomainObjPtr vm);

void qemuDomainEventFlush(int timer, void *opaque);

qemuMonitorPtr qemuDomainGetMonitor(virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjEnterMonitor(virQEMUDriverPtr driver,
                               virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainObjExitMonitor(virQEMUDriverPtr driver,
                             virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjEnterMonitorAsync(virQEMUDriverPtr driver,
                                   virDomainObjPtr obj,
                                   qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;


qemuAgentPtr qemuDomainObjEnterAgent(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitAgent(virDomainObjPtr obj, qemuAgentPtr agent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


void qemuDomainObjEnterRemote(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
int qemuDomainObjExitRemote(virDomainObjPtr obj,
                            bool checkActive)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

virDomainDefPtr qemuDomainDefCopy(virQEMUDriverPtr driver,
                                  virQEMUCapsPtr qemuCaps,
                                  virDomainDefPtr src,
                                  unsigned int flags);

int qemuDomainDefFormatBuf(virQEMUDriverPtr driver,
                           virQEMUCapsPtr qemuCaps,
                           virDomainDefPtr vm,
                           unsigned int flags,
                           virBuffer *buf);

char *qemuDomainDefFormatXML(virQEMUDriverPtr driver,
                             virQEMUCapsPtr qemuCaps,
                             virDomainDefPtr vm,
                             unsigned int flags);

char *qemuDomainFormatXML(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          unsigned int flags);

char *qemuDomainDefFormatLive(virQEMUDriverPtr driver,
                              virQEMUCapsPtr qemuCaps,
                              virDomainDefPtr def,
                              virCPUDefPtr origCPU,
                              bool inactive,
                              bool compatible);

void qemuDomainObjTaint(virQEMUDriverPtr driver,
                        virDomainObjPtr obj,
                        virDomainTaintFlags taint,
                        qemuDomainLogContextPtr logCtxt);

void qemuDomainObjCheckTaint(virQEMUDriverPtr driver,
                             virDomainObjPtr obj,
                             qemuDomainLogContextPtr logCtxt,
                             bool incomingMigration);
void qemuDomainObjCheckDiskTaint(virQEMUDriverPtr driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 qemuDomainLogContextPtr logCtxt);
void qemuDomainObjCheckHostdevTaint(virQEMUDriverPtr driver,
                                    virDomainObjPtr obj,
                                    virDomainHostdevDefPtr disk,
                                    qemuDomainLogContextPtr logCtxt);
void qemuDomainObjCheckNetTaint(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                qemuDomainLogContextPtr logCtxt);

typedef enum {
    QEMU_DOMAIN_LOG_CONTEXT_MODE_START,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_ATTACH,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_STOP,
} qemuDomainLogContextMode;

qemuDomainLogContextPtr qemuDomainLogContextNew(virQEMUDriverPtr driver,
                                                virDomainObjPtr vm,
                                                qemuDomainLogContextMode mode);
int qemuDomainLogContextWrite(qemuDomainLogContextPtr ctxt,
                              const char *fmt, ...) G_GNUC_PRINTF(2, 3);
ssize_t qemuDomainLogContextRead(qemuDomainLogContextPtr ctxt,
                                 char **msg);
int qemuDomainLogContextGetWriteFD(qemuDomainLogContextPtr ctxt);
void qemuDomainLogContextMarkPosition(qemuDomainLogContextPtr ctxt);

virLogManagerPtr qemuDomainLogContextGetManager(qemuDomainLogContextPtr ctxt);

int qemuDomainLogAppendMessage(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               const char *fmt,
                               ...) G_GNUC_PRINTF(3, 4);

const char *qemuFindQemuImgBinary(virQEMUDriverPtr driver);

int qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                    virDomainMomentObjPtr snapshot,
                                    virDomainXMLOptionPtr xmlopt,
                                    const char *snapshotDir);

int qemuDomainSnapshotForEachQcow2(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMomentObjPtr snap,
                                   const char *op,
                                   bool try_all);

int qemuDomainSnapshotDiscard(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainMomentObjPtr snap,
                              bool update_current,
                              bool metadata_only);

typedef struct _virQEMUMomentRemove virQEMUMomentRemove;
typedef virQEMUMomentRemove *virQEMUMomentRemovePtr;
struct _virQEMUMomentRemove {
    virQEMUDriverPtr driver;
    virDomainObjPtr vm;
    int err;
    bool metadata_only;
    virDomainMomentObjPtr current;
    bool found;
    int (*momentDiscard)(virQEMUDriverPtr, virDomainObjPtr,
                         virDomainMomentObjPtr, bool, bool);
};

int qemuDomainMomentDiscardAll(void *payload,
                               const char *name,
                               void *data);

int qemuDomainSnapshotDiscardAllMetadata(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm);

void qemuDomainRemoveInactive(virQEMUDriverPtr driver,
                              virDomainObjPtr vm);

void qemuDomainSetFakeReboot(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             bool value);

int qemuDomainCheckDiskStartupPolicy(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     size_t diskIndex,
                                     bool cold_boot);

int qemuDomainCheckDiskPresence(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                unsigned int flags);

int qemuDomainStorageSourceValidateDepth(virStorageSourcePtr src,
                                         int add,
                                         const char *diskdst);

int qemuDomainDetermineDiskChain(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk,
                                 virStorageSourcePtr disksrc,
                                 bool report_broken);

bool qemuDomainDiskChangeSupported(virDomainDiskDefPtr disk,
                                   virDomainDiskDefPtr orig_disk);

void qemuDomainGetImageIds(virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           virStorageSourcePtr src,
                           virStorageSourcePtr parentSrc,
                           uid_t *uid,
                           gid_t *gid);

int qemuDomainStorageFileInit(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStorageSourcePtr src,
                              virStorageSourcePtr parent);
char *qemuDomainStorageAlias(const char *device, int depth);

const char *
qemuDomainDiskGetTopNodename(virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1);

int qemuDomainDiskGetBackendAlias(virDomainDiskDefPtr disk,
                                  virQEMUCapsPtr qemuCaps,
                                  char **backendAlias)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3) G_GNUC_WARN_UNUSED_RESULT;

int qemuDomainStorageSourceChainAccessAllow(virQEMUDriverPtr driver,
                                            virDomainObjPtr vm,
                                            virStorageSourcePtr src);
int qemuDomainStorageSourceChainAccessRevoke(virQEMUDriverPtr driver,
                                             virDomainObjPtr vm,
                                             virStorageSourcePtr src);

void qemuDomainStorageSourceAccessRevoke(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm,
                                         virStorageSourcePtr elem);
int qemuDomainStorageSourceAccessAllow(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virStorageSourcePtr elem,
                                       bool readonly,
                                       bool newSource,
                                       bool chainTop);

int qemuDomainPrepareStorageSourceBlockdev(virDomainDiskDefPtr disk,
                                           virStorageSourcePtr src,
                                           qemuDomainObjPrivatePtr priv,
                                           virQEMUDriverConfigPtr cfg);

int qemuDomainCleanupAdd(virDomainObjPtr vm,
                         qemuDomainCleanupCallback cb);
void qemuDomainCleanupRemove(virDomainObjPtr vm,
                             qemuDomainCleanupCallback cb);
void qemuDomainCleanupRun(virQEMUDriverPtr driver,
                          virDomainObjPtr vm);

void qemuDomainObjPrivateDataClear(qemuDomainObjPrivatePtr priv);

extern virDomainXMLPrivateDataCallbacks virQEMUDriverPrivateDataCallbacks;
extern virXMLNamespace virQEMUDriverDomainXMLNamespace;
extern virDomainDefParserConfig virQEMUDriverDomainDefParserConfig;
extern virDomainABIStability virQEMUDriverDomainABIStability;
extern virSaveCookieCallbacks virQEMUDriverDomainSaveCookie;

int qemuDomainUpdateDeviceList(virQEMUDriverPtr driver,
                               virDomainObjPtr vm, int asyncJob);

int qemuDomainUpdateMemoryDeviceInfo(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     int asyncJob);

bool qemuDomainDefCheckABIStability(virQEMUDriverPtr driver,
                                    virQEMUCapsPtr qemuCaps,
                                    virDomainDefPtr src,
                                    virDomainDefPtr dst);

bool qemuDomainCheckABIStability(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDefPtr dst);

bool qemuDomainAgentAvailable(virDomainObjPtr vm,
                              bool reportError);

bool qemuDomainDiskBlockJobIsActive(virDomainDiskDefPtr disk);
bool qemuDomainHasBlockjob(virDomainObjPtr vm, bool copy_only)
    ATTRIBUTE_NONNULL(1);

int qemuDomainAlignMemorySizes(virDomainDefPtr def);
int qemuDomainMemoryDeviceAlignSize(virDomainDefPtr def,
                                    virDomainMemoryDefPtr mem);

virDomainChrDefPtr qemuFindAgentConfig(virDomainDefPtr def);

/* You should normally avoid these functions and use the variant that
 * doesn't have "Machine" in the name instead. */
bool qemuDomainMachineIsARMVirt(const char *machine,
                                const virArch arch);
bool qemuDomainMachineIsPSeries(const char *machine,
                                const virArch arch);
bool qemuDomainMachineHasBuiltinIDE(const char *machine,
                                    const virArch arch);

bool qemuDomainIsQ35(const virDomainDef *def);
bool qemuDomainIsI440FX(const virDomainDef *def);
bool qemuDomainIsS390CCW(const virDomainDef *def);
bool qemuDomainIsARMVirt(const virDomainDef *def);
bool qemuDomainIsRISCVVirt(const virDomainDef *def);
bool qemuDomainIsPSeries(const virDomainDef *def);
bool qemuDomainHasPCIRoot(const virDomainDef *def);
bool qemuDomainHasPCIeRoot(const virDomainDef *def);
bool qemuDomainHasBuiltinIDE(const virDomainDef *def);
bool qemuDomainHasBuiltinESP(const virDomainDef *def);
bool qemuDomainNeedsFDC(const virDomainDef *def);
bool qemuDomainSupportsPCI(virDomainDefPtr def,
                           virQEMUCapsPtr qemuCaps);

void qemuDomainUpdateCurrentMemorySize(virDomainObjPtr vm);

unsigned long long qemuDomainGetMemLockLimitBytes(virDomainDefPtr def,
                                                  bool forceVFIO);
int qemuDomainAdjustMaxMemLock(virDomainObjPtr vm,
                               bool forceVFIO);
int qemuDomainAdjustMaxMemLockHostdev(virDomainObjPtr vm,
                                      virDomainHostdevDefPtr hostdev);

int qemuDomainDefValidateMemoryHotplug(const virDomainDef *def,
                                       virQEMUCapsPtr qemuCaps,
                                       const virDomainMemoryDef *mem);

bool qemuDomainSupportsNewVcpuHotplug(virDomainObjPtr vm);
bool qemuDomainHasVcpuPids(virDomainObjPtr vm);
pid_t qemuDomainGetVcpuPid(virDomainObjPtr vm, unsigned int vcpuid);
int qemuDomainValidateVcpuInfo(virDomainObjPtr vm);
int qemuDomainRefreshVcpuInfo(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              int asyncJob,
                              bool state);
bool qemuDomainGetVcpuHalted(virDomainObjPtr vm, unsigned int vcpu);
int qemuDomainRefreshVcpuHalted(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                int asyncJob);

bool qemuDomainSupportsNicdev(virDomainDefPtr def,
                              virDomainNetDefPtr net);

bool qemuDomainNetSupportsMTU(virDomainNetType type);

int qemuDomainSetPrivatePaths(virQEMUDriverPtr driver,
                              virDomainObjPtr vm);

virDomainDiskDefPtr qemuDomainDiskByName(virDomainDefPtr def, const char *name);

char *qemuDomainGetMasterKeyFilePath(const char *libDir);

int qemuDomainMasterKeyReadFile(qemuDomainObjPrivatePtr priv);

int qemuDomainWriteMasterKeyFile(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm);

int qemuDomainMasterKeyCreate(virDomainObjPtr vm);

void qemuDomainMasterKeyRemove(qemuDomainObjPrivatePtr priv);

bool qemuDomainSupportsEncryptedSecret(qemuDomainObjPrivatePtr priv);

void qemuDomainSecretInfoFree(qemuDomainSecretInfoPtr secinfo)
    ATTRIBUTE_NONNULL(1);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSecretInfo, qemuDomainSecretInfoFree);

void qemuDomainSecretInfoDestroy(qemuDomainSecretInfoPtr secinfo);

void qemuDomainSecretDiskDestroy(virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainStorageSourceHasAuth(virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1);

qemuDomainSecretInfoPtr
qemuDomainSecretInfoTLSNew(qemuDomainObjPrivatePtr priv,
                           const char *srcAlias,
                           const char *secretUUID);

void qemuDomainSecretHostdevDestroy(virDomainHostdevDefPtr disk)
    ATTRIBUTE_NONNULL(1);

void qemuDomainSecretChardevDestroy(virDomainChrSourceDefPtr dev)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretChardevPrepare(virQEMUDriverConfigPtr cfg,
                                   qemuDomainObjPrivatePtr priv,
                                   const char *chrAlias,
                                   virDomainChrSourceDefPtr dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

void qemuDomainSecretDestroy(virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretPrepare(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuDomainDefValidateDiskLunSource(const virStorageSource *src)
    ATTRIBUTE_NONNULL(1);

int qemuDomainDeviceDefValidateDisk(const virDomainDiskDef *disk,
                                    virQEMUCapsPtr qemuCaps);

int qemuDomainPrepareChannel(virDomainChrDefPtr chr,
                             const char *domainChannelTargetDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSourceTLS(virDomainChrSourceDefPtr source,
                                       virQEMUDriverConfigPtr cfg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSource(virDomainDefPtr def,
                                    virQEMUDriverConfigPtr cfg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void  qemuDomainPrepareShmemChardev(virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainVcpuHotplugIsInOrder(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

void qemuDomainVcpuPersistOrder(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

int qemuDomainCheckMonitor(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob);

bool qemuDomainSupportsVideoVga(virDomainVideoDefPtr video,
                                virQEMUCapsPtr qemuCaps);

bool qemuDomainNeedsVFIO(const virDomainDef *def);

int qemuDomainGetHostdevPath(virDomainHostdevDefPtr dev,
                             char **path,
                             int *perms);

virDomainDiskDefPtr qemuDomainDiskLookupByNodename(virDomainDefPtr def,
                                                   const char *nodename,
                                                   virStorageSourcePtr *src);

char *qemuDomainDiskBackingStoreGetName(virDomainDiskDefPtr disk,
                                        unsigned int idx);

virStorageSourcePtr qemuDomainGetStorageSourceByDevstr(const char *devstr,
                                                       virDomainDefPtr def);

int
qemuDomainUpdateCPU(virDomainObjPtr vm,
                    virCPUDefPtr cpu,
                    virCPUDefPtr *origCPU);

int
qemuDomainFixupCPUs(virDomainObjPtr vm,
                    virCPUDefPtr *origCPU);

char *
qemuDomainGetMachineName(virDomainObjPtr vm);

void
qemuDomainObjPrivateXMLFormatAllowReboot(virBufferPtr buf,
                                         virTristateBool allowReboot);

int
qemuDomainObjPrivateXMLParseAllowReboot(xmlXPathContextPtr ctxt,
                                        virTristateBool *allowReboot);

bool
qemuDomainCheckCCWS390AddressSupport(const virDomainDef *def,
                                     const virDomainDeviceInfo *info,
                                     virQEMUCapsPtr qemuCaps,
                                     const char *devicename);

void
qemuDomainPrepareDiskSourceData(virDomainDiskDefPtr disk,
                                virStorageSourcePtr src);


int
qemuDomainValidateStorageSource(virStorageSourcePtr src,
                                virQEMUCapsPtr qemuCaps,
                                bool maskBlockdev);


int
qemuDomainPrepareDiskSource(virDomainDiskDefPtr disk,
                            qemuDomainObjPrivatePtr priv,
                            virQEMUDriverConfigPtr cfg);

int
qemuDomainDiskCachemodeFlags(int cachemode,
                             bool *writeback,
                             bool *direct,
                             bool *noflush);

int
qemuDomainPrepareHostdev(virDomainHostdevDefPtr hostdev,
                         qemuDomainObjPrivatePtr priv);

char * qemuDomainGetManagedPRSocketPath(qemuDomainObjPrivatePtr priv);

bool qemuDomainDefHasManagedPR(virDomainObjPtr vm);

unsigned int qemuDomainStorageIdNew(qemuDomainObjPrivatePtr priv);
void qemuDomainStorageIdReset(qemuDomainObjPrivatePtr priv);

virDomainEventResumedDetailType
qemuDomainRunningReasonToResumeEvent(virDomainRunningReason reason);

bool
qemuDomainIsUsingNoShutdown(qemuDomainObjPrivatePtr priv);

bool
qemuDomainDiskIsMissingLocalOptional(virDomainDiskDefPtr disk);

void
qemuDomainNVRAMPathFormat(virQEMUDriverConfigPtr cfg,
                            virDomainDefPtr def,
                            char **path);

void
qemuDomainNVRAMPathGenerate(virQEMUDriverConfigPtr cfg,
                            virDomainDefPtr def);

virDomainEventSuspendedDetailType
qemuDomainPausedReasonToSuspendedEvent(virDomainPausedReason reason);

int
qemuDomainValidateActualNetDef(const virDomainNetDef *net,
                               virQEMUCapsPtr qemuCaps);

int
qemuDomainSupportsCheckpointsBlockjobs(virDomainObjPtr vm)
    G_GNUC_WARN_UNUSED_RESULT;

int
qemuDomainMakeCPUMigratable(virCPUDefPtr cpu);

int
qemuDomainInitializePflashStorageSource(virDomainObjPtr vm);

bool
qemuDomainDiskBlockJobIsSupported(virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk);

int
qemuDomainDefNumaCPUsRectify(virDomainDefPtr def,
                             virQEMUCapsPtr qemuCaps);

void qemuDomainRemoveInactiveJob(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm);

void qemuDomainRemoveInactiveJobLocked(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm);

int virQEMUFileOpenAs(uid_t fallback_uid,
                      gid_t fallback_gid,
                      bool dynamicOwnership,
                      const char *path,
                      int oflags,
                      bool *needUnlink);

int
qemuDomainOpenFile(virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   const char *path,
                   int oflags,
                   bool *needUnlink);

int
qemuDomainFileWrapperFDClose(virDomainObjPtr vm,
                             virFileWrapperFdPtr fd);

int
qemuDomainInterfaceSetDefaultQDisc(virQEMUDriverPtr driver,
                                   virDomainNetDefPtr net);

int
qemuDomainNamePathsCleanup(virQEMUDriverConfigPtr cfg,
                           const char *name,
                           bool bestEffort);
