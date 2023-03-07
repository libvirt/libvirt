/*
 * virdnsmasq.c: Helper APIs for managing dnsmasq
 *
 * Copyright (C) 2007-2013 Red Hat, Inc.
 * Copyright (C) 2010 Satoru SATOH <satoru.satoh@gmail.com>
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
 * Based on iptables.c
 */

#include <config.h>

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "internal.h"
#include "virdnsmasq.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("util.dnsmasq");

#define DNSMASQ "dnsmasq"
#define DNSMASQ_HOSTSFILE_SUFFIX "hostsfile"
#define DNSMASQ_ADDNHOSTSFILE_SUFFIX "addnhosts"

#define DNSMASQ_MIN_MAJOR 2
#define DNSMASQ_MIN_MINOR 67

static void
dhcphostFreeContent(dnsmasqDhcpHost *host)
{
    g_free(host->host);
}

static void
addnhostFreeContent(dnsmasqAddnHost *host)
{
    size_t i;

    for (i = 0; i < host->nhostnames; i++)
        g_free(host->hostnames[i]);
    g_free(host->hostnames);
    g_free(host->ip);
}

static void
addnhostsFree(dnsmasqAddnHostsfile *addnhostsfile)
{
    size_t i;

    if (addnhostsfile->hosts) {
        for (i = 0; i < addnhostsfile->nhosts; i++)
            addnhostFreeContent(&addnhostsfile->hosts[i]);

        g_free(addnhostsfile->hosts);

        addnhostsfile->nhosts = 0;
    }

    g_free(addnhostsfile->path);

    g_free(addnhostsfile);
}

static int
addnhostsAdd(dnsmasqAddnHostsfile *addnhostsfile,
             virSocketAddr *ip,
             const char *name)
{
    char *ipstr = NULL;
    int idx = -1;
    size_t i;

    if (!(ipstr = virSocketAddrFormat(ip)))
        return -1;

    for (i = 0; i < addnhostsfile->nhosts; i++) {
        if (STREQ((const char *)addnhostsfile->hosts[i].ip, (const char *)ipstr)) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        VIR_REALLOC_N(addnhostsfile->hosts, addnhostsfile->nhosts + 1);

        idx = addnhostsfile->nhosts;
        addnhostsfile->hosts[idx].hostnames = g_new0(char *, 1);

        addnhostsfile->hosts[idx].ip = g_strdup(ipstr);

        addnhostsfile->hosts[idx].nhostnames = 0;
        addnhostsfile->nhosts++;
    }

    VIR_REALLOC_N(addnhostsfile->hosts[idx].hostnames, addnhostsfile->hosts[idx].nhostnames + 1);

    addnhostsfile->hosts[idx].hostnames[addnhostsfile->hosts[idx].nhostnames] = g_strdup(name);

    VIR_FREE(ipstr);

    addnhostsfile->hosts[idx].nhostnames++;

    return 0;
}

static dnsmasqAddnHostsfile *
addnhostsNew(const char *name,
             const char *config_dir)
{
    dnsmasqAddnHostsfile *addnhostsfile;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    addnhostsfile = g_new0(dnsmasqAddnHostsfile, 1);

    addnhostsfile->hosts = NULL;
    addnhostsfile->nhosts = 0;

    virBufferAsprintf(&buf, "%s", config_dir);
    virBufferEscapeString(&buf, "/%s", name);
    virBufferAsprintf(&buf, ".%s", DNSMASQ_ADDNHOSTSFILE_SUFFIX);

    if (!(addnhostsfile->path = virBufferContentAndReset(&buf)))
        goto error;

    return addnhostsfile;

 error:
    addnhostsFree(addnhostsfile);
    return NULL;
}

static int
addnhostsWrite(const char *path,
               dnsmasqAddnHost *hosts,
               unsigned int nhosts)
{
    g_autofree char *tmp = NULL;
    FILE *f;
    bool istmp = true;
    size_t i, j;
    int rc = 0;

    /* even if there are 0 hosts, create a 0 length file, to allow
     * for runtime addition.
     */

    tmp = g_strdup_printf("%s.new", path);

    if (!(f = fopen(tmp, "w"))) {
        istmp = false;
        if (!(f = fopen(path, "w")))
            return -errno;
    }

    for (i = 0; i < nhosts; i++) {
        if (fputs(hosts[i].ip, f) == EOF || fputc('\t', f) == EOF) {
            rc = -errno;
            VIR_FORCE_FCLOSE(f);

            if (istmp)
                unlink(tmp);

            return rc;
        }

        for (j = 0; j < hosts[i].nhostnames; j++) {
            if (fputs(hosts[i].hostnames[j], f) == EOF || fputc('\t', f) == EOF) {
                rc = -errno;
                VIR_FORCE_FCLOSE(f);

                if (istmp)
                    unlink(tmp);

                return rc;
            }
        }

        if (fputc('\n', f) == EOF) {
            rc = -errno;
            VIR_FORCE_FCLOSE(f);

            if (istmp)
                unlink(tmp);

            return rc;
        }
    }

    if (VIR_FCLOSE(f) == EOF)
        return -errno;

    if (istmp && rename(tmp, path) < 0) {
        rc = -errno;
        unlink(tmp);
        return rc;
    }

    return 0;
}

static int
addnhostsSave(dnsmasqAddnHostsfile *addnhostsfile)
{
    int err = addnhostsWrite(addnhostsfile->path, addnhostsfile->hosts,
                             addnhostsfile->nhosts);

    if (err < 0) {
        virReportSystemError(-err, _("cannot write config file '%1$s'"),
                             addnhostsfile->path);
        return -1;
    }

    return 0;
}

static int
genericFileDelete(char *path)
{
    if (!virFileExists(path))
        return 0;

    if (unlink(path) < 0) {
        virReportSystemError(errno, _("cannot remove config file '%1$s'"),
                             path);
        return -1;
    }

    return 0;
}

static void
hostsfileFree(dnsmasqHostsfile *hostsfile)
{
    size_t i;

    if (hostsfile->hosts) {
        for (i = 0; i < hostsfile->nhosts; i++)
            dhcphostFreeContent(&hostsfile->hosts[i]);

        g_free(hostsfile->hosts);

        hostsfile->nhosts = 0;
    }

    g_free(hostsfile->path);

    g_free(hostsfile);
}

/* Note:  There are many additional dhcp-host specifications
 * supported by dnsmasq.  There are only the basic ones.
 */
static int
hostsfileAdd(dnsmasqHostsfile *hostsfile,
             const char *mac,
             virSocketAddr *ip,
             const char *name,
             const char *id,
             const char *leasetime,
             bool ipv6)
{
    g_autofree char *ipstr = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    VIR_REALLOC_N(hostsfile->hosts, hostsfile->nhosts + 1);

    if (!(ipstr = virSocketAddrFormat(ip)))
        return -1;

    /* the first test determines if it is a dhcpv6 host */
    if (ipv6) {
        if (name && id) {
            virBufferAsprintf(&buf, "id:%s,%s", id, name);
        } else if (name && !id) {
            virBufferAsprintf(&buf, "%s", name);
        } else if (!name && id) {
            virBufferAsprintf(&buf, "id:%s", id);
        }
        virBufferAsprintf(&buf, ",[%s]", ipstr);
    } else if (name && mac) {
        virBufferAsprintf(&buf, "%s,%s,%s", mac, ipstr, name);
    } else if (name && !mac) {
        virBufferAsprintf(&buf, "%s,%s", name, ipstr);
    } else {
        virBufferAsprintf(&buf, "%s,%s", mac, ipstr);
    }

    if (leasetime)
        virBufferAsprintf(&buf, ",%s", leasetime);

    if (!(hostsfile->hosts[hostsfile->nhosts].host = virBufferContentAndReset(&buf)))
        return -1;

    hostsfile->nhosts++;

    return 0;
}

static dnsmasqHostsfile *
hostsfileNew(const char *name,
             const char *config_dir)
{
    dnsmasqHostsfile *hostsfile;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    hostsfile = g_new0(dnsmasqHostsfile, 1);

    hostsfile->hosts = NULL;
    hostsfile->nhosts = 0;

    virBufferAsprintf(&buf, "%s", config_dir);
    virBufferEscapeString(&buf, "/%s", name);
    virBufferAsprintf(&buf, ".%s", DNSMASQ_HOSTSFILE_SUFFIX);

    if (!(hostsfile->path = virBufferContentAndReset(&buf)))
        goto error;
    return hostsfile;

 error:
    hostsfileFree(hostsfile);
    return NULL;
}

static int
hostsfileWrite(const char *path,
               dnsmasqDhcpHost *hosts,
               unsigned int nhosts)
{
    g_autofree char *tmp = NULL;
    FILE *f;
    bool istmp = true;
    size_t i;
    int rc = 0;

    /* even if there are 0 hosts, create a 0 length file, to allow
     * for runtime addition.
     */

    tmp = g_strdup_printf("%s.new", path);

    if (!(f = fopen(tmp, "w"))) {
        istmp = false;
        if (!(f = fopen(path, "w")))
            return -errno;
    }

    for (i = 0; i < nhosts; i++) {
        if (fputs(hosts[i].host, f) == EOF || fputc('\n', f) == EOF) {
            rc = -errno;
            VIR_FORCE_FCLOSE(f);

            if (istmp)
                unlink(tmp);

            return rc;
        }
    }

    if (VIR_FCLOSE(f) == EOF)
        return -errno;

    if (istmp && rename(tmp, path) < 0) {
        rc = -errno;
        unlink(tmp);
        return rc;
    }

    return 0;
}

static int
hostsfileSave(dnsmasqHostsfile *hostsfile)
{
    int err = hostsfileWrite(hostsfile->path, hostsfile->hosts,
                             hostsfile->nhosts);

    if (err < 0) {
        virReportSystemError(-err, _("cannot write config file '%1$s'"),
                             hostsfile->path);
        return -1;
    }

    return 0;
}

/**
 * dnsmasqContextNew:
 *
 * Create a new Dnsmasq context
 *
 * Returns a pointer to the new structure or NULL in case of error
 */
dnsmasqContext *
dnsmasqContextNew(const char *network_name,
                  const char *config_dir)
{
    dnsmasqContext *ctx;

    ctx = g_new0(dnsmasqContext, 1);

    ctx->config_dir = g_strdup(config_dir);

    if (!(ctx->hostsfile = hostsfileNew(network_name, config_dir)))
        goto error;
    if (!(ctx->addnhostsfile = addnhostsNew(network_name, config_dir)))
        goto error;

    return ctx;

 error:
    dnsmasqContextFree(ctx);
    return NULL;
}

/**
 * dnsmasqContextFree:
 * @ctx: pointer to the dnsmasq context
 *
 * Free the resources associated with a dnsmasq context
 */
void
dnsmasqContextFree(dnsmasqContext *ctx)
{
    if (!ctx)
        return;

    g_free(ctx->config_dir);

    if (ctx->hostsfile)
        hostsfileFree(ctx->hostsfile);
    if (ctx->addnhostsfile)
        addnhostsFree(ctx->addnhostsfile);

    g_free(ctx);
}

/**
 * dnsmasqAddDhcpHost:
 * @ctx: pointer to the dnsmasq context for each network
 * @mac: pointer to the string contains mac address of the host
 * @ip: pointer to the socket address contains ip of the host
 * @name: pointer to the string contains hostname of the host or NULL
 *
 * Add dhcp-host entry.
 */
int
dnsmasqAddDhcpHost(dnsmasqContext *ctx,
                   const char *mac,
                   virSocketAddr *ip,
                   const char *name,
                   const char *id,
                   const char *leasetime,
                   bool ipv6)
{
    return hostsfileAdd(ctx->hostsfile, mac, ip, name, id, leasetime, ipv6);
}

/*
 * dnsmasqAddHost:
 * @ctx: pointer to the dnsmasq context for each network
 * @ip: pointer to the socket address contains ip of the host
 * @name: pointer to the string contains hostname of the host
 *
 * Add additional host entry.
 */

int
dnsmasqAddHost(dnsmasqContext *ctx,
               virSocketAddr *ip,
               const char *name)
{
    return addnhostsAdd(ctx->addnhostsfile, ip, name);
}

/**
 * dnsmasqSave:
 * @ctx: pointer to the dnsmasq context for each network
 *
 * Saves all the configurations associated with a context to disk.
 */
int
dnsmasqSave(const dnsmasqContext *ctx)
{
    int ret = 0;

    if (g_mkdir_with_parents(ctx->config_dir, 0777) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             ctx->config_dir);
        return -1;
    }

    if (ctx->hostsfile)
        ret = hostsfileSave(ctx->hostsfile);
    if (ret == 0) {
        if (ctx->addnhostsfile)
            ret = addnhostsSave(ctx->addnhostsfile);
    }

    return ret;
}


/**
 * dnsmasqDelete:
 * @ctx: pointer to the dnsmasq context for each network
 *
 * Delete all the configuration files associated with a context.
 */
int
dnsmasqDelete(const dnsmasqContext *ctx)
{
    int ret = 0;

    if (ctx->hostsfile)
        ret = genericFileDelete(ctx->hostsfile->path);
    if (ctx->addnhostsfile)
        ret = genericFileDelete(ctx->addnhostsfile->path);

    return ret;
}

/**
 * dnsmasqReload:
 * @pid: the pid of the target dnsmasq process
 *
 * Reloads all the configurations associated to a context
 */
int
dnsmasqReload(pid_t pid G_GNUC_UNUSED)
{
#ifndef WIN32
    if (kill(pid, SIGHUP) != 0) {
        virReportSystemError(errno,
                             _("Failed to make dnsmasq (PID: %1$d) reload config files."),
                             pid);
        return -1;
    }
#endif /* WIN32 */

    return 0;
}

/*
 * dnsmasqCapabilities functions - provide useful information about the
 * version of dnsmasq on this machine.
 *
 */
struct _dnsmasqCaps {
    virObject parent;
    char *binaryPath;
};

static virClass *dnsmasqCapsClass;

static void
dnsmasqCapsDispose(void *obj)
{
    dnsmasqCaps *caps = obj;

    g_free(caps->binaryPath);
}

static int dnsmasqCapsOnceInit(void)
{
    if (!VIR_CLASS_NEW(dnsmasqCaps, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(dnsmasqCaps);


#define DNSMASQ_VERSION_STR "Dnsmasq version "

static int
dnsmasqCapsSetFromBuffer(dnsmasqCaps *caps, const char *buf)
{
    int len;
    const char *p;
    unsigned long long version;

    p = STRSKIP(buf, DNSMASQ_VERSION_STR);
    if (!p)
       goto error;

    virSkipToDigit(&p);

    if (virStringParseVersion(&version, p, true) < 0)
        goto error;

    if (version < DNSMASQ_MIN_MAJOR * 1000000 + DNSMASQ_MIN_MINOR * 1000) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("dnsmasq version >= %1$u.%2$u required but %3$llu.%4$llu found"),
                       DNSMASQ_MIN_MAJOR, DNSMASQ_MIN_MINOR,
                       version / 1000000,
                       version % 1000000 / 1000);
        goto error;
    }

    VIR_INFO("dnsmasq version is %d.%d",
             (int)version / 1000000,
             (int)(version % 1000000) / 1000);
    return 0;

 error:
    p = strchr(buf, '\n');
    if (!p)
        len = strlen(buf);
    else
        len = p - buf;
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse %1$s version number in '%3$.*2$s'"),
                   caps->binaryPath, len, buf);
    return -1;

}

static int
dnsmasqCapsRefreshInternal(dnsmasqCaps *caps)
{
    g_autoptr(virCommand) vercmd = NULL;
    g_autofree char *version = NULL;

    vercmd = virCommandNewArgList(caps->binaryPath, "--version", NULL);
    virCommandSetOutputBuffer(vercmd, &version);
    virCommandAddEnvPassCommon(vercmd);
    virCommandClearCaps(vercmd);
    if (virCommandRun(vercmd, NULL) < 0)
        return -1;

    return dnsmasqCapsSetFromBuffer(caps, version);
}

dnsmasqCaps *
dnsmasqCapsNewFromBinary(void)
{
    g_autoptr(dnsmasqCaps) caps = NULL;

    if (dnsmasqCapsInitialize() < 0)
        return NULL;

    if (!(caps = virObjectNew(dnsmasqCapsClass)))
        return NULL;

    if (!(caps->binaryPath = virFindFileInPath(DNSMASQ))) {
        virReportSystemError(ENOENT, "%s",
                             _("Unable to find 'dnsmasq' binary in $PATH"));
        return NULL;
    }

    if (dnsmasqCapsRefreshInternal(caps) < 0)
        return NULL;

    return g_steal_pointer(&caps);
}

const char *
dnsmasqCapsGetBinaryPath(dnsmasqCaps *caps)
{
    return caps->binaryPath;
}

/** dnsmasqDhcpHostsToString:
 *
 *   Turns a vector of dnsmasqDhcpHost into the string that is ought to be
 *   stored in the hostsfile, this functionality is split to make hostsfiles
 *   testable. Returns NULL if nhosts is 0.
 */
char *
dnsmasqDhcpHostsToString(dnsmasqDhcpHost *hosts,
                         unsigned int nhosts)
{
    size_t i;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    for (i = 0; i < nhosts; i++)
        virBufferAsprintf(&buf, "%s\n", hosts[i].host);

    return virBufferContentAndReset(&buf);
}
