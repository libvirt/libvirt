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
#include "vircgroup.h"
#include "virperf.h"
#include "domain_addr.h"
#include "domain_conf.h"
#include "qemu_monitor.h"
#include "qemu_agent.h"
#include "qemu_blockjob.h"
#include "qemu_domainjob.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_logcontext.h"
#include "qemu_migration_params.h"
#include "qemu_nbdkit.h"
#include "qemu_slirp.h"
#include "qemu_fd.h"
#include "virchrdev.h"
#include "virobject.h"
#include "virdomainmomentobjlist.h"
#include "virenum.h"
#include "vireventthread.h"
#include "storage_source_conf.h"

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
#define QEMU_DEV_SGX_VEPVC "/dev/sgx_vepc"
#define QEMU_DEV_SGX_PROVISION "/dev/sgx_provision"
#define QEMU_DEVICE_MAPPER_CONTROL_PATH "/dev/mapper/control"
#define QEMU_DEV_UDMABUF "/dev/udmabuf"


#define QEMU_DOMAIN_AES_IV_LEN 16   /* 16 bytes for 128 bit random */
                                    /*    initialization vector */

typedef struct _qemuDomainSecretInfo qemuDomainSecretInfo;
struct _qemuDomainSecretInfo {
    char *username;
    char *alias;      /* generated alias for secret */
    char *iv;         /* base64 encoded initialization vector */
    char *ciphertext; /* encoded/encrypted secret */
};

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
struct _qemuDomainObjPrivate {
    virQEMUDriver *driver;

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
    /* allowReboot:
     *
     * Unused with new QEMU versions which have QEMU_CAPS_SET_ACTION.
     *
     * Otherwise if it's set to VIR_TRISTATE_BOOL_YES, QEMU was started with
     * -no-shutdown, and if set to VIR_TRISTATE_BOOL_NO qemu was started with
     * -no-reboot instead.
     */
    virTristateBool allowReboot;

    unsigned long migMaxBandwidth;
    char *origname;
    int nbdPort; /* Port used for migration with NBD */
    unsigned short migrationPort;
    int preMigrationState;
    unsigned long long preMigrationMemlock; /* Original RLIMIT_MEMLOCK in case
                                               it was changed for the current
                                               migration job. */

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

    /* counter for generating IDs of fdsets */
    unsigned int fdsetindex;
    bool fdsetindexParsed;

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

    /* running backup job */
    virDomainBackupDef *backup;

    bool dbusDaemonRunning;

    /* list of Ids to migrate */
    GSList *dbusVMStateIds;
    /* true if -object dbus-vmstate was added */
    bool dbusVMState;

    unsigned long long originalMemlock; /* Original RLIMIT_MEMLOCK, zero if no
                                         * restore will be required later */

    GHashTable *statsSchema; /* (name, data) pair for stats */

    /* Info on dummy process for schedCore. A short lived process used only
     * briefly when starting a guest. Don't save/parse into XML. */
    pid_t schedCoreChildPID;
    pid_t schedCoreChildFD;

    GSList *threadContextAliases; /* List of IDs of thread-context objects */

    /* named file descriptor groups associated with the VM */
    GHashTable *fds;
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
    size_t enccount;
    qemuDomainSecretInfo **encinfo;

    /* secure passthrough of the http cookie */
    qemuDomainSecretInfo *httpcookie;

    /* key for decrypting TLS certificate */
    qemuDomainSecretInfo *tlsKeySecret;

    /* file descriptors if user asks for FDs to be passed */
    qemuFDPass *fdpass;

    /* an nbdkit process for serving network storage sources */
    qemuNbdkitProcess *nbdkitProcess;
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

    char *qomPath;
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

    qemuFDPass *sourcefd;
    qemuFDPass *logfd;
    qemuFDPassDirect *directfd;
    bool wait; /* wait for incoming connections on chardev */

    char *tlsCertPath; /* path to certificates if TLS is requested */
    bool tlsVerify; /* whether server should verify client certificates */

    char *tlsCredsAlias; /* alias of the x509 tls credentials object */
};


void
qemuDomainChrSourcePrivateClearFDPass(qemuDomainChrSourcePrivate *priv);

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

    /* True if the device was created by us. Otherwise we should
     * avoid removing it. Currently only used for
     * VIR_DOMAIN_NET_TYPE_DIRECT. */
    bool created;

    qemuSlirp *slirp;

    /* file descriptor transfer helpers */
    qemuFDPassDirect *slirpfd;
    GSList *tapfds; /* qemuFDPassDirect */
    GSList *vhostfds; /* qemuFDPassDirect */
    qemuFDPass *vdpafd;
};


#define QEMU_DOMAIN_TPM_PRIVATE(dev) \
    ((qemuDomainTPMPrivate *) (dev)->privateData)

typedef struct _qemuDomainTPMPrivate qemuDomainTPMPrivate;
struct _qemuDomainTPMPrivate {
    virObject parent;

    struct {
        bool can_migrate_shared_storage;
    } swtpm;
};


void
qemuDomainNetworkPrivateClearFDs(qemuDomainNetworkPrivate *priv);

typedef enum {
    QEMU_PROCESS_EVENT_WATCHDOG = 0,
    QEMU_PROCESS_EVENT_GUESTPANIC,
    QEMU_PROCESS_EVENT_DEVICE_DELETED,
    QEMU_PROCESS_EVENT_NETDEV_STREAM_DISCONNECTED,
    QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED,
    QEMU_PROCESS_EVENT_SERIAL_CHANGED,
    QEMU_PROCESS_EVENT_JOB_STATUS_CHANGE,
    QEMU_PROCESS_EVENT_MONITOR_EOF,
    QEMU_PROCESS_EVENT_PR_DISCONNECT,
    QEMU_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED,
    QEMU_PROCESS_EVENT_GUEST_CRASHLOADED,
    QEMU_PROCESS_EVENT_MEMORY_DEVICE_SIZE_CHANGE,
    QEMU_PROCESS_EVENT_UNATTENDED_MIGRATION,
    QEMU_PROCESS_EVENT_RESET,
    QEMU_PROCESS_EVENT_NBDKIT_EXITED,

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

typedef struct _qemuDomainSaveCookie qemuDomainSaveCookie;
struct _qemuDomainSaveCookie {
    virObject parent;

    virCPUDef *cpu;
    bool slirpHelper;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSaveCookie, virObjectUnref);

typedef struct _qemuDomainXmlNsEnvTuple qemuDomainXmlNsEnvTuple;
struct _qemuDomainXmlNsEnvTuple {
    char *name;
    char *value;
};


typedef enum {
    QEMU_DOMAIN_XML_NS_OVERRIDE_NONE,
    QEMU_DOMAIN_XML_NS_OVERRIDE_STRING,
    QEMU_DOMAIN_XML_NS_OVERRIDE_SIGNED,
    QEMU_DOMAIN_XML_NS_OVERRIDE_UNSIGNED,
    QEMU_DOMAIN_XML_NS_OVERRIDE_BOOL,
    QEMU_DOMAIN_XML_NS_OVERRIDE_REMOVE,

    QEMU_DOMAIN_XML_NS_OVERRIDE_LAST
} qemuDomainXmlNsOverrideType;
VIR_ENUM_DECL(qemuDomainXmlNsOverride);

typedef struct _qemuDomainXmlNsOverrideProperty qemuDomainXmlNsOverrideProperty;
struct _qemuDomainXmlNsOverrideProperty {
    char *name;
    qemuDomainXmlNsOverrideType type;
    char *value;
    virJSONValue *json;
};

typedef struct _qemuDomainXmlNsDeviceOverride qemuDomainXmlNsDeviceOverride;
struct _qemuDomainXmlNsDeviceOverride {
    char *alias;

    size_t nfrontend;
    qemuDomainXmlNsOverrideProperty *frontend;
};


typedef struct _qemuDomainXmlNsDef qemuDomainXmlNsDef;
struct _qemuDomainXmlNsDef {
    char **args;

    unsigned int num_env;
    qemuDomainXmlNsEnvTuple *env;

    char **capsadd;

    char **capsdel;

    /* We deliberately keep this as a string so that it's parsed only when
     * starting the VM to avoid any form of errors in the parser or when
     * changing qemu versions. The knob is mainly for development/CI purposes */
    char *deprecationBehavior;

    size_t ndeviceOverride;
    qemuDomainXmlNsDeviceOverride *deviceOverride;
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
    bool snapshotDelete;                /* indicate that snapshot job is
                                         * deleting snapshot */
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
void qemuDomainObjEnterMonitor(virDomainObj *obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitMonitor(virDomainObj *obj)
    ATTRIBUTE_NONNULL(1);
int qemuDomainObjEnterMonitorAsync(virDomainObj *obj,
                                   virDomainAsyncJob asyncJob)
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
                        qemuLogContext *logCtxt);

char **qemuDomainObjGetTainting(virQEMUDriver *driver,
                                virDomainObj *obj);

void qemuDomainObjCheckTaint(virQEMUDriver *driver,
                             virDomainObj *obj,
                             qemuLogContext *logCtxt,
                             bool incomingMigration);
void qemuDomainObjCheckDiskTaint(virQEMUDriver *driver,
                                 virDomainObj *obj,
                                 virDomainDiskDef *disk,
                                 qemuLogContext *logCtxt);
void qemuDomainObjCheckHostdevTaint(virQEMUDriver *driver,
                                    virDomainObj *obj,
                                    virDomainHostdevDef *disk,
                                    qemuLogContext *logCtxt);
void qemuDomainObjCheckNetTaint(virQEMUDriver *driver,
                                virDomainObj *obj,
                                virDomainNetDef *net,
                                qemuLogContext *logCtxt);

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

void qemuDomainRemoveInactive(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainUndefineFlagsValues flags,
                              bool outgoingMigration);

void
qemuDomainRemoveInactiveLocked(virQEMUDriver *driver,
                               virDomainObj *vm);

void qemuDomainSetFakeReboot(virDomainObj *vm,
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
                                 virStorageSource *disksrc);

bool qemuDomainDiskChangeSupported(virDomainDiskDef *disk,
                                   virDomainDiskDef *orig_disk);

void qemuDomainGetImageIds(virQEMUDriverConfig *cfg,
                           virDomainDef *def,
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
                                  char **backendAlias)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

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

int qemuDomainPrepareStorageSourceBlockdevNodename(virDomainDiskDef *disk,
                                                   virStorageSource *src,
                                                   const char *nodenameprefix,
                                                   qemuDomainObjPrivate *priv,
                                                   virQEMUDriverConfig *cfg);
int qemuDomainPrepareStorageSourceBlockdev(virDomainDiskDef *disk,
                                           virStorageSource *src,
                                           qemuDomainObjPrivate *priv,
                                           virQEMUDriverConfig *cfg);

void qemuDomainCleanupAdd(virDomainObj *vm,
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
extern virDomainJobObjConfig virQEMUDriverDomainJobConfig;

int qemuDomainUpdateDeviceList(virDomainObj *vm, int asyncJob);

int qemuDomainUpdateMemoryDeviceInfo(virDomainObj *vm,
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
bool qemuDomainIsMipsMalta(const virDomainDef *def);
bool qemuDomainHasPCIRoot(const virDomainDef *def);
bool qemuDomainHasPCIeRoot(const virDomainDef *def);
bool qemuDomainHasBuiltinIDE(const virDomainDef *def);
bool qemuDomainHasBuiltinESP(const virDomainDef *def);
bool qemuDomainNeedsFDC(const virDomainDef *def);
bool qemuDomainSupportsPCI(virDomainDef *def,
                           virQEMUCaps *qemuCaps);

void qemuDomainUpdateCurrentMemorySize(virDomainObj *vm);

unsigned long long qemuDomainGetMemLockLimitBytes(virDomainDef *def);
int qemuDomainAdjustMaxMemLock(virDomainObj *vm);
int qemuDomainAdjustMaxMemLockHostdev(virDomainObj *vm,
                                      virDomainHostdevDef *hostdev);
int qemuDomainAdjustMaxMemLockNVMe(virDomainObj *vm,
                                   virStorageSource *src);
int qemuDomainSetMaxMemLock(virDomainObj *vm,
                            unsigned long long limit,
                            unsigned long long *origPtr);

int qemuDomainDefValidateMemoryHotplug(const virDomainDef *def,
                                       const virDomainMemoryDef *mem);

bool qemuDomainSupportsVcpuHotplug(virDomainObj *vm);
bool qemuDomainHasVcpuPids(virDomainObj *vm);
pid_t qemuDomainGetVcpuPid(virDomainObj *vm, unsigned int vcpuid);
int qemuDomainValidateVcpuInfo(virDomainObj *vm);
int qemuDomainRefreshVcpuInfo(virDomainObj *vm,
                              int asyncJob,
                              bool state);
bool qemuDomainGetVcpuHalted(virDomainObj *vm, unsigned int vcpu);
int qemuDomainRefreshVcpuHalted(virDomainObj *vm,
                                int asyncJob);

bool qemuDomainSupportsNicdev(virDomainDef *def,
                              virDomainNetDef *net);

bool qemuDomainNetSupportsMTU(virDomainNetType type,
                              virDomainNetBackendType backend);

int qemuDomainSetPrivatePaths(virQEMUDriver *driver,
                              virDomainObj *vm);

virDomainDiskDef *qemuDomainDiskByName(virDomainDef *def, const char *name);

char *qemuDomainGetMasterKeyFilePath(const char *libDir);

int qemuDomainMasterKeyReadFile(qemuDomainObjPrivate *priv);

int qemuDomainWriteMasterKeyFile(virQEMUDriver *driver,
                                 virDomainObj *vm);

int qemuDomainMasterKeyCreate(virDomainObj *vm);

void qemuDomainMasterKeyRemove(qemuDomainObjPrivate *priv);

void qemuDomainSecretInfoFree(qemuDomainSecretInfo *secinfo)
    ATTRIBUTE_NONNULL(1);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainSecretInfo, qemuDomainSecretInfoFree);

void qemuDomainSecretInfoDestroy(qemuDomainSecretInfo *secinfo);

void qemuDomainSecretDiskDestroy(virDomainDiskDef *disk)
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

void qemuDomainCleanupStorageSourceFD(virStorageSource *src);

void qemuDomainStartupCleanup(virDomainObj *vm);

int qemuDomainSecretPrepare(virQEMUDriver *driver,
                            virDomainObj *vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuDomainDeviceDefValidateDisk(const virDomainDiskDef *disk,
                                    virQEMUCaps *qemuCaps);

int qemuDomainDeviceDiskDefPostParse(virDomainDiskDef *disk,
                                     unsigned int parseFlags);

int qemuDomainPrepareChannel(virDomainChrDef *chr,
                             const char *domainChannelTargetDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

struct qemuDomainPrepareChardevSourceData {
    virQEMUDriverConfig *cfg;
    bool hotplug;
};

int
qemuDomainPrepareChardevSourceOne(virDomainDeviceDef *dev,
                                  virDomainChrSourceDef *charsrc,
                                  void *opaque);

void  qemuDomainPrepareShmemChardev(virDomainShmemDef *shmem)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainVcpuHotplugIsInOrder(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

void qemuDomainVcpuPersistOrder(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

int qemuDomainCheckMonitor(virDomainObj *vm,
                           virDomainAsyncJob asyncJob);

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
                                virQEMUCaps *qemuCaps);


int
qemuDomainPrepareDiskSource(virDomainDiskDef *disk,
                            qemuDomainObjPrivate *priv,
                            virQEMUDriverConfig *cfg);

bool
qemuDomainDiskCachemodeFlags(virDomainDiskCache cachemode,
                             bool *writeback,
                             bool *direct,
                             bool *noflush);

int
qemuDomainPrepareHostdev(virDomainHostdevDef *hostdev,
                         qemuDomainObjPrivate *priv);

char * qemuDomainGetManagedPRSocketPath(qemuDomainObjPrivate *priv);

bool qemuDomainDefHasManagedPR(virDomainObj *vm);

unsigned int qemuDomainFDSetIDNew(qemuDomainObjPrivate *priv);

virDomainEventResumedDetailType
qemuDomainRunningReasonToResumeEvent(virDomainRunningReason reason);

bool
qemuDomainDiskIsMissingLocalOptional(virDomainDiskDef *disk);

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
qemuDomainInitializePflashStorageSource(virDomainObj *vm,
                                        virQEMUDriverConfig *cfg);

bool
qemuDomainDiskBlockJobIsSupported(virDomainDiskDef *disk);

int
qemuDomainDefNumaCPUsRectify(virDomainDef *def,
                             virQEMUCaps *qemuCaps);

int virQEMUFileOpenAs(uid_t fallback_uid,
                      gid_t fallback_gid,
                      bool dynamicOwnership,
                      const char *path,
                      int oflags,
                      bool *needUnlink);

int
qemuDomainOpenFile(virQEMUDriverConfig *cfg,
                   const virDomainDef *def,
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

char *
qemuDomainGetVHostUserFSSocketPath(qemuDomainObjPrivate *priv,
                                   const virDomainFSDef *fs);

typedef int (*qemuDomainDeviceBackendChardevForeachCallback)(virDomainDeviceDef *dev,
                                                             virDomainChrSourceDef *charsrc,
                                                             void *opaque);
int
qemuDomainDeviceBackendChardevForeachOne(virDomainDeviceDef *dev,
                                         qemuDomainDeviceBackendChardevForeachCallback cb,
                                         void *opaque);
int
qemuDomainDeviceBackendChardevForeach(virDomainDef *def,
                                      qemuDomainDeviceBackendChardevForeachCallback cb,
                                      void *opaque);

int
qemuDomainRemoveLogs(virQEMUDriver *driver,
                     const char *name);

int
qemuDomainObjWait(virDomainObj *vm);

int
qemuDomainRefreshStatsSchema(virDomainObj *dom);

int
qemuDomainSyncRxFilter(virDomainObj *vm,
                       virDomainNetDef *def,
                       virDomainAsyncJob asyncJob);

int
qemuDomainSchedCoreStart(virQEMUDriverConfig *cfg,
                         virDomainObj *vm);

void
qemuDomainSchedCoreStop(qemuDomainObjPrivate *priv);

virBitmap *
qemuDomainEvaluateCPUMask(const virDomainDef *def,
                          virBitmap *cpumask,
                          virBitmap *autoCpuset);

void
qemuDomainNumatuneMaybeFormatNodesetUnion(virDomainObj *vm,
                                          virBitmap **nodeset,
                                          char **nodesetStr);
