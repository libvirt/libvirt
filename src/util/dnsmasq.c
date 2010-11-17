/*
 * Copyright (C) 2007-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Based on iptables.c
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#include "internal.h"
#include "datatypes.h"
#include "dnsmasq.h"
#include "util.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK
#define DNSMASQ_HOSTSFILE_SUFFIX "hostsfile"

static void
dhcphostFree(dnsmasqDhcpHost *host)
{
    VIR_FREE(host->host);
}

static void
hostsfileFree(dnsmasqHostsfile *hostsfile)
{
    unsigned int i;

    if (hostsfile->hosts) {
        for (i = 0; i < hostsfile->nhosts; i++)
            dhcphostFree(&hostsfile->hosts[i]);

        VIR_FREE(hostsfile->hosts);

        hostsfile->nhosts = 0;
    }

    VIR_FREE(hostsfile->path);

    VIR_FREE(hostsfile);
}

static int
hostsfileAdd(dnsmasqHostsfile *hostsfile,
             const char *mac,
             virSocketAddr *ip,
             const char *name)
{
    char *ipstr = NULL;
    if (VIR_REALLOC_N(hostsfile->hosts, hostsfile->nhosts + 1) < 0)
        goto alloc_error;

    if (!(ipstr = virSocketFormatAddr(ip)))
        return -1;

    if (name) {
        if (virAsprintf(&hostsfile->hosts[hostsfile->nhosts].host, "%s,%s,%s",
                        mac, ipstr, name) < 0) {
            goto alloc_error;
        }
    } else {
        if (virAsprintf(&hostsfile->hosts[hostsfile->nhosts].host, "%s,%s",
                        mac, ipstr) < 0) {
            goto alloc_error;
        }
    }
    VIR_FREE(ipstr);

    hostsfile->nhosts++;

    return 0;

 alloc_error:
    virReportOOMError();
    VIR_FREE(ipstr);
    return -1;
}

static dnsmasqHostsfile *
hostsfileNew(const char *name,
             const char *config_dir)
{
    int err;
    dnsmasqHostsfile *hostsfile;

    if (VIR_ALLOC(hostsfile) < 0) {
        virReportOOMError();
        return NULL;
    }

    hostsfile->hosts = NULL;
    hostsfile->nhosts = 0;

    if (virAsprintf(&hostsfile->path, "%s/%s.%s", config_dir, name,
                    DNSMASQ_HOSTSFILE_SUFFIX) < 0) {
        virReportOOMError();
        goto error;
    }

    if ((err = virFileMakePath(config_dir))) {
        virReportSystemError(err, _("cannot create config directory '%s'"),
                             config_dir);
        goto error;
    }

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
    char *tmp;
    FILE *f;
    bool istmp = true;
    unsigned int i;
    int rc = 0;

    if (nhosts == 0)
        return rc;

    if (virAsprintf(&tmp, "%s.new", path) < 0)
        return ENOMEM;

    if (!(f = fopen(tmp, "w"))) {
        istmp = false;
        if (!(f = fopen(path, "w"))) {
            rc = errno;
            goto cleanup;
        }
    }

    for (i = 0; i < nhosts; i++) {
        if (fputs(hosts[i].host, f) == EOF || fputc('\n', f) == EOF) {
            rc = errno;
            VIR_FORCE_FCLOSE(f);

            if (istmp)
                unlink(tmp);

            goto cleanup;
        }
    }

    if (VIR_FCLOSE(f) == EOF) {
        rc = errno;
        goto cleanup;
    }

    if (istmp) {
        if (rename(tmp, path) < 0) {
            rc = errno;
            unlink(tmp);
            goto cleanup;
        }

        if (unlink(tmp) < 0) {
            rc = errno;
            goto cleanup;
        }
    }

 cleanup:
    VIR_FREE(tmp);

    return rc;
}

static int
hostsfileSave(dnsmasqHostsfile *hostsfile)
{
    int err = hostsfileWrite(hostsfile->path, hostsfile->hosts,
                             hostsfile->nhosts);

    if (err < 0) {
        virReportSystemError(err, _("cannot write config file '%s'"),
                             hostsfile->path);
        return -1;
    }

    return 0;
}

static int
hostsfileDelete(dnsmasqHostsfile *hostsfile)
{
    if (!virFileExists(hostsfile->path))
        return 0;

    if (unlink(hostsfile->path) < 0) {
        virReportSystemError(errno, _("cannot remove config file '%s'"),
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

    if (VIR_ALLOC(ctx) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (!(ctx->hostsfile = hostsfileNew(network_name, config_dir)))
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
 * Free the resources associated with an dnsmasq context
 */
void
dnsmasqContextFree(dnsmasqContext *ctx)
{
    if (!ctx)
        return;

    if (ctx->hostsfile)
        hostsfileFree(ctx->hostsfile);

    VIR_FREE(ctx);
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
void
dnsmasqAddDhcpHost(dnsmasqContext *ctx,
                   const char *mac,
                   virSocketAddr *ip,
                   const char *name)
{
    if (ctx->hostsfile)
        hostsfileAdd(ctx->hostsfile, mac, ip, name);
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
    if (ctx->hostsfile)
        return hostsfileSave(ctx->hostsfile);

    return 0;
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
    if (ctx->hostsfile)
        return hostsfileDelete(ctx->hostsfile);

    return 0;
}

/**
 * dnsmasqReload:
 * @pid: the pid of the target dnsmasq process
 *
 * Reloads all the configurations associated to a context
 */
int
dnsmasqReload(pid_t pid ATTRIBUTE_UNUSED)
{
#ifndef WIN32
    if (kill(pid, SIGHUP) != 0) {
        virReportSystemError(errno,
            _("Failed to make dnsmasq (PID: %d) reload config files."),
            pid);
        return -1;
    }
#endif /* WIN32 */

    return 0;
}
