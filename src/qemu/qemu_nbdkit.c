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


G_GNUC_UNUSED static void
qemuNbdkitCapsQuery(qemuNbdkitCaps *caps)
{
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
