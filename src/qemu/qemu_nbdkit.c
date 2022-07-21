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

#include "configmake.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virutil.h"
#include "qemu_block.h"
#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_extdevice.h"
#include "qemu_nbdkit.h"
#include "qemu_security.h"

#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.nbdkit");

#define NBDKIT_MODDIR LIBDIR "/nbdkit"
#define NBDKIT_PLUGINDIR NBDKIT_MODDIR "/plugins"
#define NBDKIT_FILTERDIR NBDKIT_MODDIR "/filters"

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
qemuNbdkitCapsQueryVersion(qemuNbdkitCaps *nbdkit)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(nbdkit->path,
                                                     "--version",
                                                     NULL);

    virCommandSetOutputBuffer(cmd, &nbdkit->version);

    if (virCommandRun(cmd, NULL) != 0)
        return -1;

    VIR_DEBUG("Got nbdkit version %s", nbdkit->version);
    return 0;
}


static void
qemuNbdkitCapsFinalize(GObject *object)
{
    qemuNbdkitCaps *nbdkit = QEMU_NBDKIT_CAPS(object);

    g_clear_pointer(&nbdkit->path, g_free);
    g_clear_pointer(&nbdkit->version, g_free);
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

    caps->ctime = st.st_ctime;
    caps->filterDirMtime = qemuNbdkitGetDirMtime(NBDKIT_FILTERDIR);
    caps->pluginDirMtime = qemuNbdkitGetDirMtime(NBDKIT_PLUGINDIR);
    caps->libvirtCtime = virGetSelfLastChanged();
    caps->libvirtVersion = LIBVIR_VERSION_NUMBER;

    qemuNbdkitCapsQueryPlugins(caps);
    qemuNbdkitCapsQueryFilters(caps);
    qemuNbdkitCapsQueryVersion(caps);
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
                     void *privData G_GNUC_UNUSED)
{
    qemuNbdkitCaps *nbdkitCaps = data;
    struct stat st;

    if (!nbdkitCaps->path)
        return true;

    if (!virNbkditCapsCheckModdir(NBDKIT_PLUGINDIR, nbdkitCaps->pluginDirMtime))
        return false;
    if (!virNbkditCapsCheckModdir(NBDKIT_FILTERDIR, nbdkitCaps->filterDirMtime))
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
                     void *privData G_GNUC_UNUSED)
{
    qemuNbdkitCaps *caps = qemuNbdkitCapsNew(binary);
    qemuNbdkitCapsQuery(caps);

    return caps;
}


virFileCacheHandlers nbdkitCapsCacheHandlers = {
    .isValid = virNbdkitCapsIsValid,
    .newData = virNbdkitCapsNewData,
    .loadFile = NULL,
    .saveFile = NULL,
    .privFree = NULL,
};


virFileCache*
qemuNbdkitCapsCacheNew(const char *cachedir)
{
    g_autofree char *dir = g_build_filename(cachedir, "nbdkitcapabilities", NULL);
    return virFileCacheNew(dir, "xml", &nbdkitCapsCacheHandlers);
}
