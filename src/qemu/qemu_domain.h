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

typedef void (*qemuDomainCleanupCallback)(virQEMUDriver *driver,
                                          virDomainObj *vm);

#define QEMU_DOMAIN_MASTER_KEY_LEN 32  /* 32 bytes for 256 bit random key */

void
qemuDomainObjSaveStatus(virQEMUDriver *driver,
                        virDomainObj *obj);

void qemuDomainSaveStatus(virDomainObj *obj);
void qemuDomainSaveConfig(virDomainObj *obj);


/* helper data types for async device unplug */
typedef enum {
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_NONE = 0,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_OK,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED,
} qemuDomainUnpluggingDeviceStatus;

typedef struct _qemuDomainUnpluggingDevice qemuDomainUnpluggingDevice;
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
struct _qemuDomainSecretPlain {
    char *username;
    uint8_t *secret;
    size_t secretlen;
};

#define QEMU_DOMAIN_AES_IV_LEN 16   /* 16 bytes for 128 bit random */
                                    /*    initialization vector */
typedef struct _qemuDomainSecretAES qemuDomainSecretAES;
struct _qemuDomainSecretAES {
    char *username;
    char *alias;      /* generated alias for secret */
    char *iv;         /* base64 encoded initialization vector */
    char *ciphertext; /* encoded/encrypted secret */
};

typedef struct _qemuDomainSecretInfo qemuDomainSecretInfo;
struct _qemuDomainSecretInfo {
    qemuDomainSecretInfoType type;
    union {
        qemuDomainSecretPlain plain;
        qemuDomainSecretAES aes;
    } s;
};

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
struct _qemuDomainObjPrivate {
    virQEMUDriver *driver;

    qemuDomainJobObj job;

    virBitmap *namespaces;

    virEventThread *eventThread;

    qemuMonitor *mon;
    virDomainChrSourceDef *monConfig;
    bool monError;
    unsigned long long monStart;
    int agentTimeout;

    qemuAgent *agent;
    bool agentError;

    bool beingDestroyed;
    char *pidfile;

    virDomainPCIAddressSet *pciaddrs;
    virDomainUSBAddressSet *usbaddrs;

    virQEMUCaps *qemuCaps;
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

    virChrdevs *devs;

    qemuDomainCleanupCallback *cleanupCallbacks;
    size_t ncleanupCallbacks;
    size_t ncleanupCallbacks_max;

    virCgroup *cgroup;

    virPerf *perf;

    qemuDomainUnpluggingDevice unplug;

    char **qemuDevices; /* NULL-terminated list of devices aliases known to QEMU */

    bool hookRun;  /* true if there was a hook run over this domain */

    /* Bitmaps below hold data from the auto NUMA feature */
    virBitmap *autoNodeset;
    virBitmap *autoCpuset;

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
    qemuDomainSecretInfo *migSecinfo;

    /* CPU def used to start the domain when it differs from the one actually
     * provided by QEMU. */
    virCPUDef *origCPU;

    /* If true virtlogd is used as stdio handler for character devices. */
    bool chardevStdioLogd;

    /* Tracks blockjob state for vm. Valid only while reconnecting to qemu. */
    virTristateBool reconnectBlockjobs;

    /* Migration capabilities. Rechecked on reconnect, not to be saved in
     * private XML. */
    virBitmap *migrationCaps;

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
    virStorageSource *pflash0;
    virStorageSource *pflash1;

    /* running backup job */
    virDomainBackupDef *backup;

    bool dbusDaemonRunning;

    /* list of Ids to migrate */
    GSList *dbusVMStateIds;
    /* true if -object dbus-vmstate was added */
    bool dbusVMState;
};

#define QEMU_DOMAIN_PRIVATE(vm) \
    ((qemuDomainObjPrivate *) (vm)->privateData)

#define QEMU_DOMAIN_DISK_PRIVATE(disk) \
    ((qemuDomainDiskPrivate *) (disk)->privateData)

typedef struct _qemuDomainDiskPrivate qemuDomainDiskPrivate;
struct _qemuDomainDiskPrivate {
    virObject parent;

    /* ideally we want a smarter way to interlock block jobs on single qemu disk
     * in the future, but for now we just disallow any concurrent job on a
     * single disk */
    qemuBlockJobData *blockjob;

    bool migrating; /* the disk is being migrated */
    virStorageSource *migrSource; /* disk source object used for NBD migration */

    /* information about the device */
    bool tray; /* device has tray */
    bool removable; /* device media can be removed/changed */

    char *qomName; /* QOM path of the disk (also refers to the block backend) */
    char *nodeCopyOnRead; /* nodename of the disk-wide copy-on-read blockdev layer */

    unsigned int effectiveBootindex; /* boot index of the disk based on one
                                        of the two ways we use to select a boot
                                        device */

    bool transientOverlayCreated; /* the overlay image of a transient disk was
                                     created and the definition was updated */
};

#define QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src) \
    ((qemuDomainStorageSourcePrivate *) (src)->privateData)

typedef struct _qemuDomainStorageSourcePrivate qemuDomainStorageSourcePrivate;
struct _qemuDomainStorageSourcePrivate {
    virObject parent;

    /* data required for authentication to the storage source */
    qemuDomainSecretInfo *secinfo;

    /* data required for decryption of encrypted storage source */
    qemuDomainSecretInfo *encinfo;

    /* secure passthrough of the http cookie */
    qemuDomainSecretInfo *httpcookie;

    /* key for decrypting TLS certificate */
    qemuDomainSecretInfo *tlsKeySecret;
};

virObject *qemuDomainStorageSourcePrivateNew(void);
qemuDomainStorageSourcePrivate *
qemuDomainStorageSourcePrivateFetch(virStorageSource *src);

typedef struct _qemuDomainVcpuPrivate qemuDomainVcpuPrivate;
struct _qemuDomainVcpuPrivate {
    virObject parent;

    pid_t tid; /* vcpu thread id */
    int enable_id; /* order in which the vcpus were enabled in qemu */
    int qemu_id; /* ID reported by qemu as 'CPU' in query-cpus */
    char *alias;
    virTristateBool halted;

    /* copy of the data that qemu returned */
    virJSONValue *props;

    /* information for hotpluggable cpus */
    char *type;
    int socket_id;
    int core_id;
    int thread_id;
    int node_id;
    int vcpus;
};

#define QEMU_DOMAIN_VCPU_PRIVATE(vcpu) \
    ((qemuDomainVcpuPrivate *) (vcpu)->privateData)


struct qemuDomainDiskInfo {
    bool removable;
    bool tray;
    bool tray_open;
    bool empty;
    int io_status;
    char *nodename;
};

#define QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev) \
    ((qemuDomainChrSourcePrivate *) (dev)->privateData)

typedef struct _qemuDomainChrSourcePrivate qemuDomainChrSourcePrivate;
struct _qemuDomainChrSourcePrivate {
    virObject parent;

    /* for char devices using secret
     * NB: *not* to be written to qemu domain object XML */
    qemuDomainSecretInfo *secinfo;
};


typedef struct _qemuDomainVsockPrivate qemuDomainVsockPrivate;
struct _qemuDomainVsockPrivate {
    virObject parent;

    int vhostfd;
};


#define QEMU_DOMAIN_VIDEO_PRIVATE(dev) \
    ((qemuDomainVideoPrivate *) (dev)->privateData)

typedef struct _qemuDomainVideoPrivate qemuDomainVideoPrivate;
struct _qemuDomainVideoPrivate {
    virObject parent;

    int vhost_user_fd;
};


#define QEMU_DOMAIN_GRAPHICS_PRIVATE(dev) \
    ((qemuDomainGraphicsPrivate *) (dev)->privateData)

typedef struct _qemuDomainGraphicsPrivate qemuDomainGraphicsPrivate;
struct _qemuDomainGraphicsPrivate {
    virObject parent;

    char *tlsAlias;
    qemuDomainSecretInfo *secinfo;
};


#define QEMU_DOMAIN_NETWORK_PRIVATE(dev) \
    ((qemuDomainNetworkPrivate *) (dev)->privateData)

typedef struct _qemuDomainNetworkPrivate qemuDomainNetworkPrivate;
struct _qemuDomainNetworkPrivate {
    virObject parent;

    qemuSlirp *slirp;
};


#define QEMU_DOMAIN_FS_PRIVATE(dev) \
    ((qemuDomainFSPrivate *) (dev)->privateData)

typedef struct _qemuDomainFSPrivate qemuDomainFSPrivate;
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
    virDomainObj *vm;
    qemuProcessEventType eventType;
    int action;
    int status;
    void *data;
};

void qemuProcessEventFree(struct qemuProcessEvent *event);

#define QEMU_TYPE_DOMAIN_LOG_CONTEXT qemu_domain_log_context_get_type()
G_DECLARE_FINAL_TYPE(qemuDomainLogContext, qemu_domain_log_context, QEMU, DOMAIN_LOG_CONTEXT, GObject);

typedef struct _qemuDomainSaveCookie qemuDomainSaveCookie;
struct _qemuDomainSaveCookie {
    virObject parent;

    virCPUDef *cpu;
    bool slirpHelper;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSaveCookie, virObjectUnref);

typedef struct _qemuDomainXmlNsDef qemuDomainXmlNsDef;
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

    /* We deliberately keep this as a string so that it's parsed only when
     * starting the VM to avoid any form of errors in the parser or when
     * changing qemu versions. The knob is mainly for development/CI purposes */
    char *deprecationBehavior;
};


typedef struct _qemuDomainJobPrivateMigrateTempBitmap qemuDomainJobPrivateMigrateTempBitmap;
struct _qemuDomainJobPrivateMigrateTempBitmap {
    char *nodename;
    char *bitmapname;
};

void
qemuDomainJobPrivateMigrateTempBitmapFree(qemuDomainJobPrivateMigrateTempBitmap *bmp);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainJobPrivateMigrateTempBitmap, qemuDomainJobPrivateMigrateTempBitmapFree);


typedef struct _qemuDomainJobPrivate qemuDomainJobPrivate;
struct _qemuDomainJobPrivate {
    bool spiceMigration;                /* we asked for spice migration and we
                                         * should wait for it to finish */
    bool spiceMigrated;                 /* spice migration completed */
    bool dumpCompleted;                 /* dump completed */
    qemuMigrationParams *migParams;
    GSList *migTempBitmaps;  /* temporary block dirty bitmaps - qemuDomainJobPrivateMigrateTempBitmap */
};

int qemuDomainObjStartWorker(virDomainObj *dom);
void qemuDomainObjStopWorker(virDomainObj *dom);

virDomainObj *qemuDomainObjFromDomain(virDomainPtr domain);

qemuDomainSaveCookie *qemuDomainSaveCookieNew(virDomainObj *vm);

void qemuDomainEventFlush(int timer, void *opaque);

qemuMonitor *qemuDomainGetMonitor(virDomainObj *vm)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjEnterMonitor(virQEMUDriver *driver,
                               virDomainObj *obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainObjExitMonitor(virQEMUDriver *driver,
                             virDomainObj *obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjEnterMonitorAsync(virQEMUDriver *driver,
                                   virDomainObj *obj,
                                   qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;


qemuAgent *qemuDomainObjEnterAgent(virDomainObj *obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitAgent(virDomainObj *obj, qemuAgent *agent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


void qemuDomainObjEnterRemote(virDomainObj *obj)
    ATTRIBUTE_NONNULL(1);
int qemuDomainObjExitRemote(virDomainObj *obj,
                            bool checkActive)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

virDomainDef *qemuDomainDefCopy(virQEMUDriver *driver,
                                  virQEMUCaps *qemuCaps,
                                  virDomainDef *src,
                                  unsigned int flags);

int qemuDomainDefFormatBuf(virQEMUDriver *driver,
                           virQEMUCaps *qemuCaps,
                           virDomainDef *vm,
                           unsigned int flags,
                           virBuffer *buf);

char *qemuDomainDefFormatXML(virQEMUDriver *driver,
                             virQEMUCaps *qemuCaps,
                             virDomainDef *vm,
                             unsigned int flags);

char *qemuDomainFormatXML(virQEMUDriver *driver,
                          virDomainObj *vm,
                          unsigned int flags);

char *qemuDomainDefFormatLive(virQEMUDriver *driver,
                              virQEMUCaps *qemuCaps,
                              virDomainDef *def,
                              virCPUDef *origCPU,
                              bool inactive,
                              bool compatible);

void qemuDomainObjTaint(virQEMUDriver *driver,
                        virDomainObj *obj,
                        virDomainTaintFlags taint,
                        qemuDomainLogContext *logCtxt);

void qemuDomainObjTaintMsg(virQEMUDriver *driver,
                           virDomainObj *obj,
                           virDomainTaintFlags taint,
                           qemuDomainLogContext *logCtxt,
                           const char *msg,
                           ...) G_GNUC_PRINTF(5, 6);

char **qemuDomainObjGetTainting(virQEMUDriver *driver,
                                virDomainObj *obj);

void qemuDomainObjCheckTaint(virQEMUDriver *driver,
                             virDomainObj *obj,
                             qemuDomainLogContext *logCtxt,
                             bool incomingMigration);
void qemuDomainObjCheckDiskTaint(virQEMUDriver *driver,
                                 virDomainObj *obj,
                                 virDomainDiskDef *disk,
                                 qemuDomainLogContext *logCtxt);
void qemuDomainObjCheckHostdevTaint(virQEMUDriver *driver,
                                    virDomainObj *obj,
                                    virDomainHostdevDef *disk,
                                    qemuDomainLogContext *logCtxt);
void qemuDomainObjCheckNetTaint(virQEMUDriver *driver,
                                virDomainObj *obj,
                                virDomainNetDef *net,
                                qemuDomainLogContext *logCtxt);

typedef enum {
    QEMU_DOMAIN_LOG_CONTEXT_MODE_START,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_ATTACH,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_STOP,
} qemuDomainLogContextMode;

qemuDomainLogContext *qemuDomainLogContextNew(virQEMUDriver *driver,
                                                virDomainObj *vm,
                                                qemuDomainLogContextMode mode);
int qemuDomainLogContextWrite(qemuDomainLogContext *ctxt,
                              const char *fmt, ...) G_GNUC_PRINTF(2, 3);
ssize_t qemuDomainLogContextRead(qemuDomainLogContext *ctxt,
                                 char **msg);
int qemuDomainLogContextGetWriteFD(qemuDomainLogContext *ctxt);
void qemuDomainLogContextMarkPosition(qemuDomainLogContext *ctxt);

virLogManager *qemuDomainLogContextGetManager(qemuDomainLogContext *ctxt);

int qemuDomainLogAppendMessage(virQEMUDriver *driver,
                               virDomainObj *vm,
                               const char *fmt,
                               ...) G_GNUC_PRINTF(3, 4);

const char *qemuFindQemuImgBinary(virQEMUDriver *driver);

int qemuDomainSnapshotWriteMetadata(virDomainObj *vm,
                                    virDomainMomentObj *snapshot,
                                    virDomainXMLOption *xmlopt,
                                    const char *snapshotDir);

int qemuDomainSnapshotForEachQcow2(virQEMUDriver *driver,
                                   virDomainDef *def,
                                   virDomainMomentObj *snap,
                                   const char *op,
                                   bool try_all);

int qemuDomainSnapshotDiscard(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainMomentObj *snap,
                              bool update_current,
                              bool metadata_only);

typedef struct _virQEMUMomentRemove virQEMUMomentRemove;
struct _virQEMUMomentRemove {
    virQEMUDriver *driver;
    virDomainObj *vm;
    int err;
    bool metadata_only;
    virDomainMomentObj *current;
    bool found;
    int (*momentDiscard)(virQEMUDriver *, virDomainObj *,
                         virDomainMomentObj *, bool, bool);
};

int qemuDomainMomentDiscardAll(void *payload,
                               const char *name,
                               void *data);

int qemuDomainSnapshotDiscardAllMetadata(virQEMUDriver *driver,
                                         virDomainObj *vm);

void qemuDomainRemoveInactive(virQEMUDriver *driver,
                              virDomainObj *vm);

void qemuDomainSetFakeReboot(virQEMUDriver *driver,
                             virDomainObj *vm,
                             bool value);

int qemuDomainCheckDiskStartupPolicy(virQEMUDriver *driver,
                                     virDomainObj *vm,
                                     size_t diskIndex,
                                     bool cold_boot);

int qemuDomainCheckDiskPresence(virQEMUDriver *driver,
                                virDomainObj *vm,
                                unsigned int flags);

int qemuDomainStorageSourceValidateDepth(virStorageSource *src,
                                         int add,
                                         const char *diskdst);

int qemuDomainDetermineDiskChain(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 virDomainDiskDef *disk,
                                 virStorageSource *disksrc,
                                 bool report_broken);

bool qemuDomainDiskChangeSupported(virDomainDiskDef *disk,
                                   virDomainDiskDef *orig_disk);

void qemuDomainGetImageIds(virQEMUDriverConfig *cfg,
                           virDomainObj *vm,
                           virStorageSource *src,
                           virStorageSource *parentSrc,
                           uid_t *uid,
                           gid_t *gid);

int qemuDomainStorageFileInit(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virStorageSource *src,
                              virStorageSource *parent);
char *qemuDomainStorageAlias(const char *device, int depth);

const char *
qemuDomainDiskGetTopNodename(virDomainDiskDef *disk)
    ATTRIBUTE_NONNULL(1);

int qemuDomainDiskGetBackendAlias(virDomainDiskDef *disk,
                                  virQEMUCaps *qemuCaps,
                                  char **backendAlias)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3) G_GNUC_WARN_UNUSED_RESULT;

int qemuDomainStorageSourceChainAccessAllow(virQEMUDriver *driver,
                                            virDomainObj *vm,
                                            virStorageSource *src);
int qemuDomainStorageSourceChainAccessRevoke(virQEMUDriver *driver,
                                             virDomainObj *vm,
                                             virStorageSource *src);

void qemuDomainStorageSourceAccessRevoke(virQEMUDriver *driver,
                                         virDomainObj *vm,
                                         virStorageSource *elem);
int qemuDomainStorageSourceAccessAllow(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       virStorageSource *elem,
                                       bool readonly,
                                       bool newSource,
                                       bool chainTop);

int qemuDomainPrepareStorageSourceBlockdev(virDomainDiskDef *disk,
                                           virStorageSource *src,
                                           qemuDomainObjPrivate *priv,
                                           virQEMUDriverConfig *cfg);

int qemuDomainCleanupAdd(virDomainObj *vm,
                         qemuDomainCleanupCallback cb);
void qemuDomainCleanupRemove(virDomainObj *vm,
                             qemuDomainCleanupCallback cb);
void qemuDomainCleanupRun(virQEMUDriver *driver,
                          virDomainObj *vm);

void qemuDomainObjPrivateDataClear(qemuDomainObjPrivate *priv);

extern virDomainXMLPrivateDataCallbacks virQEMUDriverPrivateDataCallbacks;
extern virXMLNamespace virQEMUDriverDomainXMLNamespace;
extern virDomainDefParserConfig virQEMUDriverDomainDefParserConfig;
extern virDomainABIStability virQEMUDriverDomainABIStability;
extern virSaveCookieCallbacks virQEMUDriverDomainSaveCookie;

int qemuDomainUpdateDeviceList(virQEMUDriver *driver,
                               virDomainObj *vm, int asyncJob);

int qemuDomainUpdateMemoryDeviceInfo(virQEMUDriver *driver,
                                     virDomainObj *vm,
                                     int asyncJob);

bool qemuDomainDefCheckABIStability(virQEMUDriver *driver,
                                    virQEMUCaps *qemuCaps,
                                    virDomainDef *src,
                                    virDomainDef *dst);

bool qemuDomainCheckABIStability(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 virDomainDef *dst);

bool qemuDomainAgentAvailable(virDomainObj *vm,
                              bool reportError);

bool qemuDomainDiskBlockJobIsActive(virDomainDiskDef *disk);
bool qemuDomainHasBlockjob(virDomainObj *vm, bool copy_only)
    ATTRIBUTE_NONNULL(1);

int qemuDomainAlignMemorySizes(virDomainDef *def);
int qemuDomainMemoryDeviceAlignSize(virDomainDef *def,
                                    virDomainMemoryDef *mem);

virDomainChrDef *qemuFindAgentConfig(virDomainDef *def);

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
bool qemuDomainSupportsPCI(virDomainDef *def,
                           virQEMUCaps *qemuCaps);

void qemuDomainUpdateCurrentMemorySize(virDomainObj *vm);

unsigned long long qemuDomainGetMemLockLimitBytes(virDomainDef *def,
                                                  bool forceVFIO);
int qemuDomainAdjustMaxMemLock(virDomainObj *vm,
                               bool forceVFIO);
int qemuDomainAdjustMaxMemLockHostdev(virDomainObj *vm,
                                      virDomainHostdevDef *hostdev);

int qemuDomainDefValidateMemoryHotplug(const virDomainDef *def,
                                       const virDomainMemoryDef *mem);

bool qemuDomainSupportsNewVcpuHotplug(virDomainObj *vm);
bool qemuDomainHasVcpuPids(virDomainObj *vm);
pid_t qemuDomainGetVcpuPid(virDomainObj *vm, unsigned int vcpuid);
int qemuDomainValidateVcpuInfo(virDomainObj *vm);
int qemuDomainRefreshVcpuInfo(virQEMUDriver *driver,
                              virDomainObj *vm,
                              int asyncJob,
                              bool state);
bool qemuDomainGetVcpuHalted(virDomainObj *vm, unsigned int vcpu);
int qemuDomainRefreshVcpuHalted(virQEMUDriver *driver,
                                virDomainObj *vm,
                                int asyncJob);

bool qemuDomainSupportsNicdev(virDomainDef *def,
                              virDomainNetDef *net);

bool qemuDomainNetSupportsMTU(virDomainNetType type);

int qemuDomainSetPrivatePaths(virQEMUDriver *driver,
                              virDomainObj *vm);

virDomainDiskDef *qemuDomainDiskByName(virDomainDef *def, const char *name);

char *qemuDomainGetMasterKeyFilePath(const char *libDir);

int qemuDomainMasterKeyReadFile(qemuDomainObjPrivate *priv);

int qemuDomainWriteMasterKeyFile(virQEMUDriver *driver,
                                 virDomainObj *vm);

int qemuDomainMasterKeyCreate(virDomainObj *vm);

void qemuDomainMasterKeyRemove(qemuDomainObjPrivate *priv);

bool qemuDomainSupportsEncryptedSecret(qemuDomainObjPrivate *priv);

void qemuDomainSecretInfoFree(qemuDomainSecretInfo *secinfo)
    ATTRIBUTE_NONNULL(1);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSecretInfo, qemuDomainSecretInfoFree);

void qemuDomainSecretInfoDestroy(qemuDomainSecretInfo *secinfo);

void qemuDomainSecretDiskDestroy(virDomainDiskDef *disk)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainStorageSourceHasAuth(virStorageSource *src)
    ATTRIBUTE_NONNULL(1);

qemuDomainSecretInfo *
qemuDomainSecretInfoTLSNew(qemuDomainObjPrivate *priv,
                           const char *srcAlias,
                           const char *secretUUID);

void qemuDomainSecretHostdevDestroy(virDomainHostdevDef *disk)
    ATTRIBUTE_NONNULL(1);

void qemuDomainSecretChardevDestroy(virDomainChrSourceDef *dev)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretChardevPrepare(virQEMUDriverConfig *cfg,
                                   qemuDomainObjPrivate *priv,
                                   const char *chrAlias,
                                   virDomainChrSourceDef *dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

void qemuDomainSecretDestroy(virDomainObj *vm)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretPrepare(virQEMUDriver *driver,
                            virDomainObj *vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuDomainDefValidateDiskLunSource(const virStorageSource *src)
    ATTRIBUTE_NONNULL(1);

int qemuDomainDeviceDefValidateDisk(const virDomainDiskDef *disk,
                                    virQEMUCaps *qemuCaps);

int qemuDomainPrepareChannel(virDomainChrDef *chr,
                             const char *domainChannelTargetDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSourceTLS(virDomainChrSourceDef *source,
                                       virQEMUDriverConfig *cfg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSource(virDomainDef *def,
                                    virQEMUDriverConfig *cfg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void  qemuDomainPrepareShmemChardev(virDomainShmemDef *shmem)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainVcpuHotplugIsInOrder(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

void qemuDomainVcpuPersistOrder(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

int qemuDomainCheckMonitor(virQEMUDriver *driver,
                           virDomainObj *vm,
                           qemuDomainAsyncJob asyncJob);

bool qemuDomainSupportsVideoVga(const virDomainVideoDef *video,
                                virQEMUCaps *qemuCaps);

bool qemuDomainNeedsVFIO(const virDomainDef *def);

int qemuDomainGetHostdevPath(virDomainHostdevDef *dev,
                             char **path,
                             int *perms);

virDomainDiskDef *qemuDomainDiskLookupByNodename(virDomainDef *def,
                                                   virDomainBackupDef *backupdef,
                                                   const char *nodename,
                                                   virStorageSource **src);

char *qemuDomainDiskBackingStoreGetName(virDomainDiskDef *disk,
                                        unsigned int idx);

virStorageSource *qemuDomainGetStorageSourceByDevstr(const char *devstr,
                                                       virDomainDef *def,
                                                       virDomainBackupDef *backupdef);

int
qemuDomainUpdateCPU(virDomainObj *vm,
                    virCPUDef *cpu,
                    virCPUDef **origCPU);

int
qemuDomainFixupCPUs(virDomainObj *vm,
                    virCPUDef **origCPU);

char *
qemuDomainGetMachineName(virDomainObj *vm);

void
qemuDomainObjPrivateXMLFormatAllowReboot(virBuffer *buf,
                                         virTristateBool allowReboot);

int
qemuDomainObjPrivateXMLParseAllowReboot(xmlXPathContextPtr ctxt,
                                        virTristateBool *allowReboot);

void
qemuDomainPrepareDiskSourceData(virDomainDiskDef *disk,
                                virStorageSource *src);


int
qemuDomainValidateStorageSource(virStorageSource *src,
                                virQEMUCaps *qemuCaps,
                                bool maskBlockdev);


int
qemuDomainPrepareDiskSource(virDomainDiskDef *disk,
                            qemuDomainObjPrivate *priv,
                            virQEMUDriverConfig *cfg);

int
qemuDomainDiskCachemodeFlags(int cachemode,
                             bool *writeback,
                             bool *direct,
                             bool *noflush);

int
qemuDomainPrepareHostdev(virDomainHostdevDef *hostdev,
                         qemuDomainObjPrivate *priv);

char * qemuDomainGetManagedPRSocketPath(qemuDomainObjPrivate *priv);

bool qemuDomainDefHasManagedPR(virDomainObj *vm);

unsigned int qemuDomainStorageIdNew(qemuDomainObjPrivate *priv);
void qemuDomainStorageIdReset(qemuDomainObjPrivate *priv);

virDomainEventResumedDetailType
qemuDomainRunningReasonToResumeEvent(virDomainRunningReason reason);

bool
qemuDomainIsUsingNoShutdown(qemuDomainObjPrivate *priv);

bool
qemuDomainDiskIsMissingLocalOptional(virDomainDiskDef *disk);

void
qemuDomainNVRAMPathFormat(virQEMUDriverConfig *cfg,
                            virDomainDef *def,
                            char **path);

void
qemuDomainNVRAMPathGenerate(virQEMUDriverConfig *cfg,
                            virDomainDef *def);

virDomainEventSuspendedDetailType
qemuDomainPausedReasonToSuspendedEvent(virDomainPausedReason reason);

int
qemuDomainValidateActualNetDef(const virDomainNetDef *net,
                               virQEMUCaps *qemuCaps);

int
qemuDomainSupportsCheckpointsBlockjobs(virDomainObj *vm)
    G_GNUC_WARN_UNUSED_RESULT;

int
qemuDomainMakeCPUMigratable(virCPUDef *cpu);

int
qemuDomainInitializePflashStorageSource(virDomainObj *vm);

bool
qemuDomainDiskBlockJobIsSupported(virDomainObj *vm,
                                  virDomainDiskDef *disk);

int
qemuDomainDefNumaCPUsRectify(virDomainDef *def,
                             virQEMUCaps *qemuCaps);

void qemuDomainRemoveInactiveJob(virQEMUDriver *driver,
                                 virDomainObj *vm);

void qemuDomainRemoveInactiveJobLocked(virQEMUDriver *driver,
                                       virDomainObj *vm);

int virQEMUFileOpenAs(uid_t fallback_uid,
                      gid_t fallback_gid,
                      bool dynamicOwnership,
                      const char *path,
                      int oflags,
                      bool *needUnlink);

int
qemuDomainOpenFile(virQEMUDriver *driver,
                   virDomainObj *vm,
                   const char *path,
                   int oflags,
                   bool *needUnlink);

int
qemuDomainFileWrapperFDClose(virDomainObj *vm,
                             virFileWrapperFd *fd);

int
qemuDomainInterfaceSetDefaultQDisc(virQEMUDriver *driver,
                                   virDomainNetDef *net);

int
qemuDomainNamePathsCleanup(virQEMUDriverConfig *cfg,
                           const char *name,
                           bool bestEffort);
