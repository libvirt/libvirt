/*
 * qemu_nbdkit.c: helpers for using nbdkit
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
 */

#include <config.h>
#include <glib.h>
#if WITH_NBDKIT
# include <libnbd.h>
#endif
#include <sys/syscall.h>

#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virtime.h"
#include "virutil.h"
#include "qemu_block.h"
#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_extdevice.h"
#include "qemu_nbdkit.h"
#define LIBVIRT_QEMU_NBDKITPRIV_H_ALLOW
#include "qemu_nbdkitpriv.h"
#include "qemu_process.h"
#include "qemu_security.h"

#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.nbdkit");

#if WITH_NBDKIT
# define WITHOUT_NBDKIT_UNUSED
#else
# define WITHOUT_NBDKIT_UNUSED G_GNUC_UNUSED
#endif

VIR_ENUM_IMPL(qemuNbdkitCaps,
    QEMU_NBDKIT_CAPS_LAST,
    /* 0 */
    "plugin-curl", /* QEMU_NBDKIT_CAPS_PLUGIN_CURL */
    "plugin-ssh", /* QEMU_NBDKIT_CAPS_PLUGIN_SSH */
    "filter-readahead", /* QEMU_NBDKIT_CAPS_FILTER_READAHEAD */
);

struct _qemuNbdkitCaps {
    GObject parent;

    char *path;
    char *version;
    char *filterDir;
    char *pluginDir;

    time_t ctime;
    time_t libvirtCtime;
    time_t pluginDirMtime;
    time_t filterDirMtime;
    unsigned int libvirtVersion;

    virBitmap *flags;
};
G_DEFINE_TYPE(qemuNbdkitCaps, qemu_nbdkit_caps, G_TYPE_OBJECT);


static void
qemuNbdkitCheckCommandCap(qemuNbdkitCaps *nbdkit,
                          virCommand *cmd,
                          qemuNbdkitCapsFlags cap)
{
    if (virCommandRun(cmd, NULL) != 0)
        return;

    VIR_DEBUG("Setting nbdkit capability %i", cap);
    ignore_value(virBitmapSetBit(nbdkit->flags, cap));
}


static void
qemuNbdkitQueryFilter(qemuNbdkitCaps *nbdkit,
                      const char *filter,
                      qemuNbdkitCapsFlags cap)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(nbdkit->path,
                                                     "--version",
                                                     NULL);

    virCommandAddArgPair(cmd, "--filter", filter);

    /* use null plugin to check for filter */
    virCommandAddArg(cmd, "null");

    qemuNbdkitCheckCommandCap(nbdkit, cmd, cap);
}


static void
qemuNbdkitQueryPlugin(qemuNbdkitCaps *nbdkit,
                      const char *plugin,
                      qemuNbdkitCapsFlags cap)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(nbdkit->path,
                                                     plugin,
                                                     "--version",
                                                     NULL);

    qemuNbdkitCheckCommandCap(nbdkit, cmd, cap);
}


static void
qemuNbdkitCapsQueryPlugins(qemuNbdkitCaps *nbdkit)
{
    qemuNbdkitQueryPlugin(nbdkit, "curl", QEMU_NBDKIT_CAPS_PLUGIN_CURL);
    qemuNbdkitQueryPlugin(nbdkit, "ssh", QEMU_NBDKIT_CAPS_PLUGIN_SSH);
}


static void
qemuNbdkitCapsQueryFilters(qemuNbdkitCaps *nbdkit)
{
    qemuNbdkitQueryFilter(nbdkit, "readahead",
                          QEMU_NBDKIT_CAPS_FILTER_READAHEAD);
}


static int
qemuNbdkitCapsQueryBuildConfig(qemuNbdkitCaps *nbdkit)
{
    size_t i;
    g_autofree char *output = NULL;
    g_auto(GStrv) lines = NULL;
    const char *line;
    g_autoptr(virCommand) cmd = virCommandNewArgList(nbdkit->path,
                                                     "--dump-config",
                                                     NULL);

    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) != 0)
        return -1;

    lines = g_strsplit(output, "\n", 0);
    if (!lines)
        return -1;

    for (i = 0; (line = lines[i]); i++) {
        const char *key;
        const char *val;
        char *p;

        p = strchr(line, '=');
        if (!p)
            continue;

        *p = '\0';
        key = line;
        val = p + 1;

        VIR_DEBUG("Got nbdkit config value %s=%s", key, val);

        if (STREQ(key, "version"))
            nbdkit->version = g_strdup(val);
        else if (STREQ(key, "filterdir"))
            nbdkit->filterDir = g_strdup(val);
        else if (STREQ(key, "plugindir"))
            nbdkit->pluginDir = g_strdup(val);
    }
    return 0;
}


static void
qemuNbdkitCapsFinalize(GObject *object)
{
    qemuNbdkitCaps *nbdkit = QEMU_NBDKIT_CAPS(object);

    g_clear_pointer(&nbdkit->path, g_free);
    g_clear_pointer(&nbdkit->version, g_free);
    g_clear_pointer(&nbdkit->filterDir, g_free);
    g_clear_pointer(&nbdkit->pluginDir, g_free);
    g_clear_pointer(&nbdkit->flags, virBitmapFree);

    G_OBJECT_CLASS(qemu_nbdkit_caps_parent_class)->finalize(object);
}


void
qemu_nbdkit_caps_init(qemuNbdkitCaps *caps)
{
    caps->flags = virBitmapNew(QEMU_NBDKIT_CAPS_LAST);
    caps->version = NULL;
}


static void
qemu_nbdkit_caps_class_init(qemuNbdkitCapsClass *klass)
{
    GObjectClass *obj = G_OBJECT_CLASS(klass);

    obj->finalize = qemuNbdkitCapsFinalize;
}


qemuNbdkitCaps *
qemuNbdkitCapsNew(const char *path)
{
    qemuNbdkitCaps *caps = g_object_new(QEMU_TYPE_NBDKIT_CAPS, NULL);
    caps->path = g_strdup(path);

    return caps;
}


static time_t
qemuNbdkitGetDirMtime(const char *moddir)
{
    struct stat st;

    if (stat(moddir, &st) < 0) {
        VIR_DEBUG("Failed to stat nbdkit module directory '%s': %s",
                  moddir,
                  g_strerror(errno));
        return 0;
    }

    return st.st_mtime;
}


static void
qemuNbdkitCapsQuery(qemuNbdkitCaps *caps)
{
    struct stat st;

    if (stat(caps->path, &st) < 0) {
        VIR_DEBUG("Failed to stat nbdkit binary '%s': %s",
                  caps->path,
                  g_strerror(errno));
        caps->ctime  = 0;
        return;
    }

    qemuNbdkitCapsQueryBuildConfig(caps);
    qemuNbdkitCapsQueryPlugins(caps);
    qemuNbdkitCapsQueryFilters(caps);

    caps->ctime = st.st_ctime;
    caps->filterDirMtime = qemuNbdkitGetDirMtime(caps->filterDir);
    caps->pluginDirMtime = qemuNbdkitGetDirMtime(caps->pluginDir);
    caps->libvirtCtime = virGetSelfLastChanged();
    caps->libvirtVersion = LIBVIR_VERSION_NUMBER;
}


bool
qemuNbdkitCapsGet(qemuNbdkitCaps *nbdkitCaps,
                  qemuNbdkitCapsFlags flag)
{
    return virBitmapIsBitSet(nbdkitCaps->flags, flag);
}


void
qemuNbdkitCapsSet(qemuNbdkitCaps *nbdkitCaps,
                  qemuNbdkitCapsFlags flag)
{
    ignore_value(virBitmapSetBit(nbdkitCaps->flags, flag));
}


static bool
virNbkditCapsCheckModdir(const char *moddir,
                         time_t expectedMtime)
{
    time_t mtime = qemuNbdkitGetDirMtime(moddir);

    if (mtime != expectedMtime) {
        VIR_DEBUG("Outdated capabilities for nbdkit: module directory '%s' changed (%lld vs %lld)",
                  moddir, (long long)mtime, (long long)expectedMtime);
        return false;
    }
    return true;
}


static bool
virNbdkitCapsIsValid(void *data,
                     void *privData)
{
    qemuNbdkitCaps *nbdkitCaps = data;
    struct stat st;
    /* when run under test, we will use privData as a signal to indicate that
     * we shouldn't touch the filesystem */
    bool skipValidation = (privData != NULL);

    if (skipValidation)
        return true;

    if (!nbdkitCaps->path)
        return true;

    if (!virNbkditCapsCheckModdir(nbdkitCaps->pluginDir, nbdkitCaps->pluginDirMtime))
        return false;
    if (!virNbkditCapsCheckModdir(nbdkitCaps->filterDir, nbdkitCaps->filterDirMtime))
        return false;

    if (nbdkitCaps->libvirtCtime != virGetSelfLastChanged() ||
        nbdkitCaps->libvirtVersion != LIBVIR_VERSION_NUMBER) {
        VIR_DEBUG("Outdated capabilities for '%s': libvirt changed (%lld vs %lld, %lu vs %lu)",
                  nbdkitCaps->path,
                  (long long)nbdkitCaps->libvirtCtime,
                  (long long)virGetSelfLastChanged(),
                  (unsigned long)nbdkitCaps->libvirtVersion,
                  (unsigned long)LIBVIR_VERSION_NUMBER);
        return false;
    }

    if (stat(nbdkitCaps->path, &st) < 0) {
        VIR_DEBUG("Failed to stat nbdkit binary '%s': %s",
                  nbdkitCaps->path,
                  g_strerror(errno));
        return false;
    }

    if (st.st_ctime != nbdkitCaps->ctime) {
        VIR_DEBUG("Outdated capabilities for '%s': nbdkit binary changed (%lld vs %lld)",
                  nbdkitCaps->path,
                  (long long)st.st_ctime, (long long)nbdkitCaps->ctime);
        return false;
    }

    return true;
}


static void*
virNbdkitCapsNewData(const char *binary,
                     void *privData)
{
    /* when run under test, we will use privData as a signal to indicate that
     * we shouldn't touch the filesystem */
    bool skipNewData = (privData != NULL);
    qemuNbdkitCaps *caps = NULL;

    if (skipNewData)
        return NULL;

    caps = qemuNbdkitCapsNew(binary);
    qemuNbdkitCapsQuery(caps);

    return caps;
}


static int
qemuNbdkitCapsValidateBinary(qemuNbdkitCaps *nbdkitCaps,
                             xmlXPathContextPtr ctxt)
{
    g_autofree char *str = NULL;

    if (!(str = virXPathString("string(./path)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing path in nbdkit capabilities cache"));
        return -1;
    }

    if (STRNEQ(str, nbdkitCaps->path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expected caps for '%1$s' but saw '%2$s'"),
                       nbdkitCaps->path, str);
        return -1;
    }

    return 0;
}


static int
qemuNbdkitCapsParseFlags(qemuNbdkitCaps *nbdkitCaps,
                         xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    if ((n = virXPathNodeSet("./flag", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities flags"));
        return -1;
    }

    VIR_DEBUG("Got flags %d", n);
    for (i = 0; i < n; i++) {
        unsigned int flag;

        if (virXMLPropEnum(nodes[i], "name", qemuNbdkitCapsTypeFromString,
                           VIR_XML_PROP_REQUIRED, &flag) < 0)
            return -1;

        qemuNbdkitCapsSet(nbdkitCaps, flag);
    }

    return 0;
}


/*
 * Parsing a doc that looks like
 *
 * <nbdkitCaps>
 *   <path>/some/path</path>
 *   <nbdkitctime>234235253</nbdkitctime>
 *   <plugindirmtime>234235253</plugindirmtime>
 *   <filterdirmtime>234235253</filterdirmtime>
 *   <selfctime>234235253</selfctime>
 *   <selfvers>1002016</selfvers>
 *   <flag name='foo'/>
 *   <flag name='bar'/>
 *   ...
 * </nbdkitCaps>
 *
 * Returns 0 on success, 1 if outdated, -1 on error
 */
static int
qemuNbdkitCapsLoadCache(qemuNbdkitCaps *nbdkitCaps,
                        const char *filename)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    long long int l;

    if (!(doc = virXMLParse(filename, NULL, NULL, "nbdkitCaps", &ctxt, NULL, false)))
        return -1;

    if (virXPathLongLong("string(./selfctime)", ctxt, &l) < 0) {
        VIR_DEBUG("missing selfctime in nbdkit capabilities XML");
        return -1;
    }
    nbdkitCaps->libvirtCtime = (time_t)l;

    nbdkitCaps->libvirtVersion = 0;
    virXPathUInt("string(./selfvers)", ctxt, &nbdkitCaps->libvirtVersion);

    if (nbdkitCaps->libvirtCtime != virGetSelfLastChanged() ||
        nbdkitCaps->libvirtVersion != LIBVIR_VERSION_NUMBER) {
        VIR_DEBUG("Outdated capabilities in %s: libvirt changed (%lld vs %lld, %lu vs %lu), stopping load",
                  nbdkitCaps->path,
                  (long long)nbdkitCaps->libvirtCtime,
                  (long long)virGetSelfLastChanged(),
                  (unsigned long)nbdkitCaps->libvirtVersion,
                  (unsigned long)LIBVIR_VERSION_NUMBER);
        return 1;
    }

    if (qemuNbdkitCapsValidateBinary(nbdkitCaps, ctxt) < 0)
        return -1;

    if (virXPathLongLong("string(./nbdkitctime)", ctxt, &l) < 0) {
        VIR_DEBUG("missing nbdkitctime in nbdkit capabilities XML");
        return -1;
    }
    nbdkitCaps->ctime = (time_t)l;

    if ((nbdkitCaps->pluginDir = virXPathString("string(./plugindir)", ctxt)) == NULL) {
        VIR_DEBUG("missing plugindir in nbdkit capabilities cache");
        return -1;
    }

    if (virXPathLongLong("string(./plugindirmtime)", ctxt, &l) < 0) {
        VIR_DEBUG("missing plugindirmtime in nbdkit capabilities XML");
        return -1;
    }
    nbdkitCaps->pluginDirMtime = (time_t)l;

    if ((nbdkitCaps->filterDir = virXPathString("string(./filterdir)", ctxt)) == NULL) {
        VIR_DEBUG("missing filterdir in nbdkit capabilities cache");
        return -1;
    }

    if (virXPathLongLong("string(./filterdirmtime)", ctxt, &l) < 0) {
        VIR_DEBUG("missing filterdirmtime in nbdkit capabilities XML");
        return -1;
    }
    nbdkitCaps->filterDirMtime = (time_t)l;

    if (qemuNbdkitCapsParseFlags(nbdkitCaps, ctxt) < 0)
        return -1;

    if ((nbdkitCaps->version = virXPathString("string(./version)", ctxt)) == NULL) {
        VIR_DEBUG("missing version in nbdkit capabilities cache");
        return -1;
    }

    return 0;
}


static void*
virNbdkitCapsLoadFile(const char *filename,
                      const char *binary,
                      void *privData G_GNUC_UNUSED,
                      bool *outdated)
{
    g_autoptr(qemuNbdkitCaps) nbdkitCaps = qemuNbdkitCapsNew(binary);
    int ret;

    if (!nbdkitCaps)
        return NULL;

    ret = qemuNbdkitCapsLoadCache(nbdkitCaps, filename);
    if (ret < 0)
        return NULL;
    if (ret == 1) {
        *outdated = true;
        return NULL;
    }

    return g_steal_pointer(&nbdkitCaps);
}


static char*
qemuNbdkitCapsFormatCache(qemuNbdkitCaps *nbdkitCaps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAddLit(&buf, "<nbdkitCaps>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<path>%s</path>\n",
                          nbdkitCaps->path);
    virBufferAsprintf(&buf, "<nbdkitctime>%lu</nbdkitctime>\n",
                      nbdkitCaps->ctime);
    virBufferEscapeString(&buf, "<plugindir>%s</plugindir>\n",
                          nbdkitCaps->pluginDir);
    virBufferAsprintf(&buf, "<plugindirmtime>%lu</plugindirmtime>\n",
                      nbdkitCaps->pluginDirMtime);
    virBufferEscapeString(&buf, "<filterdir>%s</filterdir>\n",
                          nbdkitCaps->filterDir);
    virBufferAsprintf(&buf, "<filterdirmtime>%lu</filterdirmtime>\n",
                      nbdkitCaps->filterDirMtime);
    virBufferAsprintf(&buf, "<selfctime>%lu</selfctime>\n",
                      nbdkitCaps->libvirtCtime);
    virBufferAsprintf(&buf, "<selfvers>%u</selfvers>\n",
                      nbdkitCaps->libvirtVersion);

    for (i = 0; i < QEMU_NBDKIT_CAPS_LAST; i++) {
        if (qemuNbdkitCapsGet(nbdkitCaps, i)) {
            virBufferAsprintf(&buf, "<flag name='%s'/>\n",
                              qemuNbdkitCapsTypeToString(i));
        }
    }

    virBufferAsprintf(&buf, "<version>%s</version>\n",
                      nbdkitCaps->version);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</nbdkitCaps>\n");

    return virBufferContentAndReset(&buf);
}


static int
virNbdkitCapsSaveFile(void *data,
                      const char *filename,
                      void *privData G_GNUC_UNUSED)
{
    qemuNbdkitCaps *nbdkitCaps = data;
    g_autofree char *xml = NULL;

    xml = qemuNbdkitCapsFormatCache(nbdkitCaps);

    if (virFileWriteStr(filename, xml, 0600) < 0) {
        virReportSystemError(errno,
                             _("Failed to save '%1$s' for '%2$s'"),
                             filename, nbdkitCaps->path);
        return -1;
    }

    VIR_DEBUG("Saved caps '%s' for '%s' with (%lu, %lu)",
              filename, nbdkitCaps->path,
              nbdkitCaps->ctime,
              nbdkitCaps->libvirtCtime);

    return 0;
}


virFileCacheHandlers nbdkitCapsCacheHandlers = {
    .isValid = virNbdkitCapsIsValid,
    .newData = virNbdkitCapsNewData,
    .loadFile = virNbdkitCapsLoadFile,
    .saveFile = virNbdkitCapsSaveFile,
    .privFree = NULL,
};


virFileCache*
qemuNbdkitCapsCacheNew(const char *cachedir)
{
    g_autofree char *dir = g_build_filename(cachedir, "nbdkitcapabilities", NULL);
    return virFileCacheNew(dir, "xml", &nbdkitCapsCacheHandlers);
}


int
qemuNbdkitProcessRestart(qemuNbdkitProcess *proc,
                         virDomainObj *vm)
{
    qemuDomainObjPrivate *vmpriv = vm->privateData;
    virQEMUDriver *driver = vmpriv->driver;

    /* clean up resources associated with process */
    qemuNbdkitProcessStop(proc, vm);

    return qemuNbdkitProcessStart(proc, vm, driver);
}


#if WITH_NBDKIT
typedef struct {
    qemuNbdkitProcess *proc;
    virDomainObj *vm;
} qemuNbdkitProcessEventData;


static qemuNbdkitProcessEventData*
qemuNbdkitProcessEventDataNew(qemuNbdkitProcess *proc,
                              virDomainObj *vm)
{
    qemuNbdkitProcessEventData *d = g_new(qemuNbdkitProcessEventData, 1);
    d->proc = proc;
    d->vm = virObjectRef(vm);
    return d;
}


static void
qemuNbdkitProcessEventDataFree(qemuNbdkitProcessEventData *d)
{
    virObjectUnref(d->vm);
    g_free(d);
}


static void
qemuNbdkitProcessPidfdCb(int watch G_GNUC_UNUSED,
                         int fd,
                         int events G_GNUC_UNUSED,
                         void *opaque)
{
    qemuNbdkitProcessEventData *d = opaque;

    VIR_FORCE_CLOSE(fd);
    /* submit an event so that it is handled in the per-vm event thread */
    qemuProcessHandleNbdkitExit(d->proc, d->vm);
}
#endif /* WITH_NBDKIT */


static int
qemuNbdkitProcessStartMonitor(qemuNbdkitProcess *proc WITHOUT_NBDKIT_UNUSED,
                              virDomainObj *vm WITHOUT_NBDKIT_UNUSED)
{
#if WITH_NBDKIT
    int pidfd;
    qemuNbdkitProcessEventData *data;

    pidfd = syscall(SYS_pidfd_open, proc->pid, 0);
    if (pidfd < 0) {
        virReportSystemError(errno, _("pidfd_open failed for %1$i"), proc->pid);
        return -1;
    }

    data = qemuNbdkitProcessEventDataNew(proc, vm);
    if ((proc->eventwatch = virEventAddHandle(pidfd,
                                              VIR_EVENT_HANDLE_READABLE,
                                              qemuNbdkitProcessPidfdCb,
                                              data,
                                              (virFreeCallback)qemuNbdkitProcessEventDataFree)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to monitor nbdkit process %1$i"),
                       proc->pid);
        VIR_FORCE_CLOSE(pidfd);
        qemuNbdkitProcessEventDataFree(data);
        return -1;
    }

    VIR_DEBUG("Monitoring nbdkit process %i for exit", proc->pid);

    return 0;
#else
    /* This should not be reachable */
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("nbdkit support is not enabled"));
    return -1;
#endif /* WITH_NBDKIT */
}


static void
qemuNbdkitProcessStopMonitor(qemuNbdkitProcess *proc WITHOUT_NBDKIT_UNUSED)
{
#if WITH_NBDKIT
    if (proc->eventwatch > 0) {
        virEventRemoveHandle(proc->eventwatch);
        proc->eventwatch = 0;
    }
#endif /* WITH_NBDKIT */
}


static qemuNbdkitProcess *
qemuNbdkitProcessNew(virStorageSource *source,
                     const char *pidfile,
                     const char *socketfile)
{
    qemuNbdkitProcess *nbdkit = g_new0(qemuNbdkitProcess, 1);
    /* weak reference -- source owns this object, so it will always outlive us */
    nbdkit->source = source;
    nbdkit->user = -1;
    nbdkit->group = -1;
    nbdkit->pid = -1;
    nbdkit->pidfile = g_strdup(pidfile);
    nbdkit->socketfile = g_strdup(socketfile);

    return nbdkit;
}

/**
 * qemuNbdkitReconnectStorageSource:
 * @source: a storage source
 * @pidfile: a pidfile for an nbdkit process
 * @socketfile: the socket file associated with the nbdkit process
 *
 * This function constructs a new qemuNbdkitProcess object with the given values for @pidfile and
 * @socketfile and stores it in @source. This is intended to be called when the libvirt daemon is
 * restarted and tries to reconnect to all currently-running domains. Since this function is called
 * from the code that parses the current daemon state, it should not perform any filesystem
 * operations, or anything else that might fail. Additional initialization will be done later by
 * calling qemuNbdkitStorageSourceManageProcess().
 */
void
qemuNbdkitReconnectStorageSource(virStorageSource *source,
                                 const char *pidfile,
                                 const char *socketfile)
{
    qemuDomainStorageSourcePrivate *srcpriv = qemuDomainStorageSourcePrivateFetch(source);

    if (srcpriv->nbdkitProcess) {
        VIR_WARN("source already has an nbdkit process");
        return;
    }

    srcpriv->nbdkitProcess = qemuNbdkitProcessNew(source, pidfile, socketfile);
}


static int
qemuNbdkitStorageSourceManageProcessOne(virStorageSource *source,
                                        virDomainObj *vm)
{
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(source);
    qemuDomainObjPrivate *vmpriv = vm->privateData;
    qemuNbdkitProcess *proc;

    if (!srcpriv)
        return 0;

    proc = srcpriv->nbdkitProcess;

    if (!proc)
        return 0;

    if (!proc->caps)
        proc->caps = qemuGetNbdkitCaps(vmpriv->driver);

    if (proc->pid <= 0) {
        if (virPidFileReadPath(proc->pidfile, &proc->pid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to read pidfile '%1$s'"),
                           proc->pidfile);
            return -1;
        }
    }

    if (virProcessKill(proc->pid, 0) < 0) {
        VIR_DEBUG("nbdkit process %i is not alive", proc->pid);
        return qemuNbdkitProcessRestart(proc, vm);
    }

    return qemuNbdkitProcessStartMonitor(proc, vm);
}

/**
 * qemuNbdkitStorageSourceManageProcess:
 * @source: a storage source
 * @vm: the vm that owns this storage source
 *
 * This function re-enables monitoring of any nbdkit processes associated with the backing chain of
 * @source. It is intended to be called after libvirt restarts and has loaded its current state from
 * disk and is attempting to re-connect to active domains.
 */
int
qemuNbdkitStorageSourceManageProcess(virStorageSource *source,
                                     virDomainObj *vm)
{
    virStorageSource *backing;
    for (backing = source; backing != NULL; backing = backing->backingStore)
        if (qemuNbdkitStorageSourceManageProcessOne(backing, vm) < 0)
            return -1;

    return 0;
}


bool
qemuNbdkitInitStorageSource(qemuNbdkitCaps *caps WITHOUT_NBDKIT_UNUSED,
                            virStorageSource *source WITHOUT_NBDKIT_UNUSED,
                            char *statedir WITHOUT_NBDKIT_UNUSED,
                            const char *alias WITHOUT_NBDKIT_UNUSED,
                            uid_t user WITHOUT_NBDKIT_UNUSED,
                            gid_t group WITHOUT_NBDKIT_UNUSED)
{
#if !WITH_NBDKIT
    /* if nbdkit support is not enabled, don't construct the object so the
     * calling function will fall back to qemu storage drivers */
    return false;
#else
    qemuDomainStorageSourcePrivate *srcPriv = qemuDomainStorageSourcePrivateFetch(source);
    g_autofree char *pidname = g_strdup_printf("nbdkit-%s.pid", alias);
    g_autofree char *socketname = g_strdup_printf("nbdkit-%s.socket", alias);
    g_autofree char *pidfile = g_build_filename(statedir, pidname, NULL);
    g_autofree char *socketfile = g_build_filename(statedir, socketname, NULL);
    qemuNbdkitProcess *proc;

    if (srcPriv->nbdkitProcess)
        return false;

    switch (source->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            if (!virBitmapIsBitSet(caps->flags, QEMU_NBDKIT_CAPS_PLUGIN_CURL))
                return false;
            break;
        case VIR_STORAGE_NET_PROTOCOL_SSH:
            if (!virBitmapIsBitSet(caps->flags, QEMU_NBDKIT_CAPS_PLUGIN_SSH))
                return false;
            break;
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_NFS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            return false;
    }

    proc = qemuNbdkitProcessNew(source, pidfile, socketfile);
    proc->caps = g_object_ref(caps);
    proc->user = user;
    proc->group = group;

    srcPriv->nbdkitProcess = proc;

    return true;
#endif /* WITH_NBDKIT */
}


int
qemuNbdkitStartStorageSource(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virStorageSource *src)
{
    virStorageSource *backing;

    for (backing = src; backing != NULL; backing = backing->backingStore) {
        qemuDomainStorageSourcePrivate *priv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

        if (priv && priv->nbdkitProcess &&
            qemuNbdkitProcessStart(priv->nbdkitProcess, vm, driver) < 0)
            return -1;
    }

    return 0;
}


void
qemuNbdkitStopStorageSource(virStorageSource *src,
                            virDomainObj *vm)
{
    virStorageSource *backing;

    for (backing = src; backing != NULL; backing = backing->backingStore) {
        qemuDomainStorageSourcePrivate *priv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

        if (priv && priv->nbdkitProcess &&
            qemuNbdkitProcessStop(priv->nbdkitProcess, vm) < 0)
            VIR_WARN("Unable to stop nbdkit for storage source '%s'", qemuBlockStorageSourceGetStorageNodename(src));
    }
}


static int
qemuNbdkitCommandPassDataByPipe(virCommand *cmd,
                                const char *argName,
                                unsigned char **buf,
                                size_t buflen)
{
    g_autofree char *fdfmt = NULL;
    int fd = virCommandSetSendBuffer(cmd, buf, buflen);

    if (fd < 0)
        return -1;

    /* some nbdkit arguments accept a variation where nbdkit will read the data
     * from a file descriptor, e.g. password=-FD */
    fdfmt = g_strdup_printf("-%i", fd);
    virCommandAddArgPair(cmd, argName, fdfmt);

    virCommandDoAsyncIO(cmd);

    return 0;
}


static int
qemuNbdkitProcessBuildCommandAuth(virStorageAuthDef *authdef,
                                  virCommand *cmd)
{
    g_autoptr(virConnect) conn = NULL;
    g_autofree uint8_t *secret = NULL;
    size_t secretlen = 0;
    int secrettype;

    if (!authdef)
        return 0;

    if ((secrettype = virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid secret type %1$s"),
                       authdef->secrettype);
        return -1;
    }

    conn = virGetConnectSecret();
    if (!conn)
        return -1;

    if (virSecretGetSecretString(conn,
                                 &authdef->seclookupdef,
                                 secrettype,
                                 &secret,
                                 &secretlen) < 0)
        return -1;

    virCommandAddArgPair(cmd, "user", authdef->username);

    if (qemuNbdkitCommandPassDataByPipe(cmd, "password",
                                        &secret, secretlen) < 0)
        return -1;

    return 0;
}


static int
qemuNbdkitProcessBuildCommandCurl(qemuNbdkitProcess *proc,
                                  virCommand *cmd)
{
    g_autoptr(virURI) uri = qemuBlockStorageSourceGetURI(proc->source);
    g_autofree char *uristring = virURIFormat(uri);

    /* nbdkit plugin name */
    virCommandAddArg(cmd, "curl");
    if (proc->source->protocol == VIR_STORAGE_NET_PROTOCOL_HTTP) {
        /* allow http to be upgraded to https via e.g. redirect */
        virCommandAddArgPair(cmd, "protocols", "http,https");
    } else {
        virCommandAddArgPair(cmd, "protocols",
                             virStorageNetProtocolTypeToString(proc->source->protocol));
    }
    virCommandAddArgPair(cmd, "url", uristring);

    if (proc->source->auth && qemuNbdkitProcessBuildCommandAuth(proc->source->auth, cmd) < 0)
        return -1;

    /* Create a pipe to send the cookies to the nbdkit process. */
    if (proc->source->ncookies) {
        g_autofree char *cookies = qemuBlockStorageSourceGetCookieString(proc->source);

        if (qemuNbdkitCommandPassDataByPipe(cmd, "cookie",
                                            (unsigned char**)&cookies,
                                            strlen(cookies)) < 0)
            return -1;
    }

    if (proc->source->sslverify == VIR_TRISTATE_BOOL_NO) {
        virCommandAddArgPair(cmd, "sslverify", "false");
    }

    if (proc->source->timeout > 0) {
        g_autofree char *timeout = g_strdup_printf("%llu", proc->source->timeout);
        virCommandAddArgPair(cmd, "timeout", timeout);
    }

    return 0;
}


static int
qemuNbdkitProcessBuildCommandSSH(qemuNbdkitProcess *proc,
                                 virCommand *cmd)
{
    virStorageNetHostDef *host = &proc->source->hosts[0];
    g_autofree char *portstr = g_strdup_printf("%u", host->port);

    /* nbdkit plugin name */
    virCommandAddArg(cmd, "ssh");

    virCommandAddArgPair(cmd, "host", host->name);
    virCommandAddArgPair(cmd, "port", portstr);
    virCommandAddArgPair(cmd, "path", proc->source->path);

    if (proc->source->auth) {
        if (qemuNbdkitProcessBuildCommandAuth(proc->source->auth, cmd) < 0)
            return -1;
    } else {
        if (proc->source->ssh_keyfile)
            virCommandAddArgPair(cmd, "identity", proc->source->ssh_keyfile);

        if (proc->source->ssh_user)
            virCommandAddArgPair(cmd, "user", proc->source->ssh_user);
    }

    if (proc->source->ssh_agent)
        virCommandAddEnvPair(cmd, "SSH_AUTH_SOCK", proc->source->ssh_agent);

    if (proc->source->ssh_host_key_check_disabled)
        virCommandAddArgPair(cmd, "verify-remote-host", "false");

    if (proc->source->ssh_known_hosts_file)
        virCommandAddArgPair(cmd, "known-hosts", proc->source->ssh_known_hosts_file);

    return 0;
}


virCommand *
qemuNbdkitProcessBuildCommand(qemuNbdkitProcess *proc)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(proc->caps->path,
                                                     "--unix",
                                                     proc->socketfile,
                                                     "--foreground",
                                                     NULL);

    if (proc->source->readonly)
        virCommandAddArg(cmd, "--readonly");

    if (qemuNbdkitCapsGet(proc->caps, QEMU_NBDKIT_CAPS_FILTER_READAHEAD) &&
        proc->source->readahead > 0)
        virCommandAddArgPair(cmd, "--filter", "readahead");

    switch (proc->source->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            if (qemuNbdkitProcessBuildCommandCurl(proc, cmd) < 0)
                return NULL;
            break;
        case VIR_STORAGE_NET_PROTOCOL_SSH:
            if (qemuNbdkitProcessBuildCommandSSH(proc, cmd) < 0)
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_NFS:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_NO_SUPPORT,
                           _("protocol '%1$s' is not supported by nbdkit"),
                           virStorageNetProtocolTypeToString(proc->source->protocol));
            return NULL;
    }

    virCommandDaemonize(cmd);

    return g_steal_pointer(&cmd);
}


void
qemuNbdkitProcessFree(qemuNbdkitProcess *proc)
{
    qemuNbdkitProcessStopMonitor(proc);

    g_clear_pointer(&proc->pidfile, g_free);
    g_clear_pointer(&proc->socketfile, g_free);
    g_clear_object(&proc->caps);
    g_free(proc);
}


int
qemuNbdkitProcessSetupCgroup(qemuNbdkitProcess *proc,
                             virCgroup *cgroup)
{
    return virCgroupAddProcess(cgroup, proc->pid);
}


int
qemuNbdkitProcessStart(qemuNbdkitProcess *proc,
                       virDomainObj *vm,
                       virQEMUDriver *driver)
{
    g_autoptr(virCommand) cmd = NULL;
    int rc;
    int exitstatus = 0;
    g_autofree char *errbuf = NULL;
    virTimeBackOffVar timebackoff;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *uristring = NULL;
    g_autofree char *basename = g_strdup_printf("%s-nbdkit-%i", vm->def->name, proc->source->id);
    int logfd = -1;
    g_autoptr(qemuLogContext) logContext = NULL;
#if WITH_NBDKIT
    struct nbd_handle *nbd = NULL;
#endif

    if (!(cmd = qemuNbdkitProcessBuildCommand(proc)))
        return -1;

    if (!(logContext = qemuLogContextNew(driver, vm, basename))) {
        virLastErrorPrefixMessage("%s", _("can't connect to virtlogd"));
        return -1;
    }

    logfd = qemuLogContextGetWriteFD(logContext);

    VIR_DEBUG("starting nbdkit process for %s", qemuBlockStorageSourceGetStorageNodename(proc->source));
    virCommandSetErrorFD(cmd, &logfd);
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetPidFile(cmd, proc->pidfile);

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "nbdkit") < 0)
        goto error;

    if (proc->source->ssh_keyfile &&
        qemuSecurityDomainSetPathLabel(driver, vm, proc->source->ssh_keyfile, false) < 0)
        goto error;

    if (proc->source->ssh_agent &&
        qemuSecurityDomainSetPathLabel(driver, vm, proc->source->ssh_agent, false) < 0)
        goto error;

    if (proc->source->ssh_known_hosts_file &&
        qemuSecurityDomainSetPathLabel(driver, vm, proc->source->ssh_known_hosts_file, false) < 0)
        goto error;

    if (qemuSecurityCommandRun(driver, vm, cmd, proc->user, proc->group, true, &exitstatus) < 0)
        goto error;

    if (exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'nbdkit'. exitstatus: %1$d"), exitstatus);
        goto error;
    }

    if ((rc = virPidFileReadPath(proc->pidfile, &proc->pid)) < 0) {
        virReportSystemError(-rc,
                             _("Failed to read pidfile %1$s"),
                             proc->pidfile);
        goto error;
    }

    if (virTimeBackOffStart(&timebackoff, 1, 1000) < 0)
        goto error;

    while (virTimeBackOffWait(&timebackoff)) {
        if (virFileExists(proc->socketfile)) {
#if WITH_NBDKIT
            /* if the disk source was misconfigured, nbdkit will not produce an error
             * until somebody connects to the socket and tries to access the nbd
             * export. This results in poor user experience because the only error we
             * would get from qemu is something like "Requested export not available".
             * So let's try to access it ourselves so that we can error out early and
             * provide a useful message to the user.
             */
            nbd = nbd_create();
            if (nbd_connect_unix(nbd, proc->socketfile) < 0) {
                VIR_WARN("nbd_connect_unix failed: %s", nbd_get_error());
                nbd_close(nbd);
                goto errorlog;
            }
            nbd_close(nbd);

#endif
            if (qemuNbdkitProcessStartMonitor(proc, vm) < 0)
                goto error;
            return 0;
        }

        if (virProcessKill(proc->pid, 0) == 0)
            continue;

        VIR_WARN("nbdkit died unexpectedly");
        goto errorlog;
    }

    VIR_WARN("nbdkit socket did not show up");

 errorlog:
    if ((uri = qemuBlockStorageSourceGetURI(proc->source)))
        uristring = virURIFormat(uri);

    if (qemuLogContextReadFiltered(logContext, &errbuf, 1024) < 0)
        VIR_WARN("Unable to read from nbdkit log");

    virReportError(VIR_ERR_OPERATION_FAILED,
                   _("Failed to connect to nbdkit for '%1$s': %2$s"),
                   NULLSTR(uristring), NULLSTR(errbuf));

 error:
    qemuNbdkitProcessStop(proc, vm);
    return -1;
}


int
qemuNbdkitProcessStop(qemuNbdkitProcess *proc,
                      virDomainObj *vm)
{
    qemuDomainObjPrivate *vmpriv = vm->privateData;
    virQEMUDriver *driver = vmpriv->driver;

    qemuNbdkitProcessStopMonitor(proc);

    if (proc->source->ssh_known_hosts_file)
        qemuSecurityDomainRestorePathLabel(driver, vm, proc->source->ssh_known_hosts_file);

    if (proc->source->ssh_keyfile)
        qemuSecurityDomainRestorePathLabel(driver, vm, proc->source->ssh_keyfile);

    if (proc->source->ssh_agent)
        qemuSecurityDomainRestorePathLabel(driver, vm, proc->source->ssh_agent);

    if (proc->pid < 0)
        return 0;

    VIR_DEBUG("Stopping nbdkit process %i", proc->pid);
    virProcessKill(proc->pid, SIGTERM);

    unlink(proc->pidfile);
    unlink(proc->socketfile);
    proc->pid = -1;

    return 0;
}
