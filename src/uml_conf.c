/*
 * uml_conf.c: UML driver configuration
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#if HAVE_NUMACTL
#define NUMA_VERSION1_COMPATIBILITY 1
#include <numa.h>
#endif

#include "uml_conf.h"
#include "uuid.h"
#include "buf.h"
#include "conf.h"
#include "util.h"
#include "memory.h"
#include "verify.h"


#define umlLog(level, msg...) fprintf(stderr, msg)



#if HAVE_NUMACTL
#define MAX_CPUS 4096
#define MAX_CPUS_MASK_SIZE (sizeof(unsigned long))
#define MAX_CPUS_MASK_BITS (MAX_CPUS_MASK_SIZE * 8)
#define MAX_CPUS_MASK_LEN (MAX_CPUS / (MAX_CPUS_MASK_BITS))

#define MASK_CPU_ISSET(mask, cpu) \
    (((mask)[((cpu) / MAX_CPUS_MASK_BITS)] >> ((cpu) % MAX_CPUS_MASK_BITS)) & 1)

static int
umlCapsInitNUMA(virCapsPtr caps)
{
    int n, i;
    unsigned long *mask = NULL;
    int ncpus;
    int *cpus = NULL;
    int ret = -1;

    if (numa_available() < 0)
        return 0;

    if (VIR_ALLOC_N(mask, MAX_CPUS_MASK_LEN) < 0)
        goto cleanup;

    for (n = 0 ; n <= numa_max_node() ; n++) {

        if (numa_node_to_cpus(n, mask, MAX_CPUS_MASK_LEN) < 0)
            goto cleanup;

        for (ncpus = 0, i = 0 ; i < MAX_CPUS ; i++)
            if (MASK_CPU_ISSET(mask, i))
                ncpus++;

        if (VIR_ALLOC_N(cpus, ncpus) < 0)
            goto cleanup;

        for (ncpus = 0, i = 0 ; i < MAX_CPUS ; i++)
            if (MASK_CPU_ISSET(mask, i))
                cpus[ncpus++] = i;

        if (virCapabilitiesAddHostNUMACell(caps,
                                           n,
                                           ncpus,
                                           cpus) < 0)
            goto cleanup;

        VIR_FREE(cpus);
    }

    ret = 0;

cleanup:
    VIR_FREE(cpus);
    VIR_FREE(mask);
    return ret;
}
#else
static int umlCapsInitNUMA(virCapsPtr caps ATTRIBUTE_UNUSED) { return 0; }
#endif

virCapsPtr umlCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    if (umlCapsInitNUMA(caps) < 0)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "uml",
                                         utsname.machine,
                                         STREQ(utsname.machine, "x86_64") ? 64 : 32,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "uml",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;

    return caps;

 no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}


static char *
umlBuildCommandLineChr(virConnectPtr conn,
                       virDomainChrDefPtr def,
                       const char *dev)
{
    char *ret;

    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        if (asprintf(&ret, "%s%d=null", dev, def->dstPort) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (asprintf(&ret, "%s%d=pts", dev, def->dstPort) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (asprintf(&ret, "%s%d=tty:%s", dev, def->dstPort,
                     def->data.file.path) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        if (asprintf(&ret, "%s%d=fd:0,fd:1", dev, def->dstPort) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (def->data.tcp.listen != 1) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("only TCP listen is supported for chr device"));
            return NULL;
        }

        if (asprintf(&ret, "%s%d=port:%s", dev, def->dstPort,
                     def->data.tcp.service) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        /* XXX could open the file/pipe & just pass the FDs */

    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_UNIX:
    default:
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("unsupported chr device type %d"), def->type);
        break;
    }

    return ret;
}

/*
 * Constructs a argv suitable for launching uml with config defined
 * for a given virtual machine.
 */
int umlBuildCommandLine(virConnectPtr conn,
                        struct uml_driver *driver ATTRIBUTE_UNUSED,
                        virDomainObjPtr vm,
                        const char ***retargv,
                        const char ***retenv,
                        int **tapfds,
                        int *ntapfds) {
    int i, j;
    char memory[50];
    struct utsname ut;
    int qargc = 0, qarga = 0;
    const char **qargv = NULL;
    int qenvc = 0, qenva = 0;
    const char **qenv = NULL;

    uname(&ut);

#define ADD_ARG_SPACE                                                   \
    do {                                                                \
        if (qargc == qarga) {                                           \
            qarga += 10;                                                \
            if (VIR_REALLOC_N(qargv, qarga) < 0)                        \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ARG(thisarg)                                                \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        qargv[qargc++] = thisarg;                                       \
    } while (0)

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        if ((qargv[qargc++] = strdup(thisarg)) == NULL)                 \
            goto no_memory;                                             \
    } while (0)

#define ADD_ARG_PAIR(key,val)                                           \
    do {                                                                \
        char *arg;                                                      \
        ADD_ARG_SPACE;                                                  \
        if (asprintf(&arg, "%s=%s", key, val) < 0)                      \
            goto no_memory;                                             \
        qargv[qargc++] = arg;                                            \
    } while (0)


#define ADD_ENV_SPACE                                                   \
    do {                                                                \
        if (qenvc == qenva) {                                           \
            qenva += 10;                                                \
            if (VIR_REALLOC_N(qenv, qenva) < 0)                         \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ENV(thisarg)                                                \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        qenv[qenvc++] = thisarg;                                        \
    } while (0)

#define ADD_ENV_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        if ((qenv[qenvc++] = strdup(thisarg)) == NULL)                  \
            goto no_memory;                                             \
    } while (0)

#define ADD_ENV_COPY(envname)                                           \
    do {                                                                \
        char *val = getenv(envname);                                    \
        char *envval;                                                   \
        ADD_ENV_SPACE;                                                  \
        if (val != NULL) {                                              \
            if (asprintf(&envval, "%s=%s", envname, val) < 0)           \
                goto no_memory;                                         \
            qenv[qenvc++] = envval;                                     \
        }                                                               \
    } while (0)

    snprintf(memory, sizeof(memory), "%luK", vm->def->memory);

    ADD_ENV_LIT("LC_ALL=C");

    ADD_ENV_COPY("LD_PRELOAD");
    ADD_ENV_COPY("LD_LIBRARY_PATH");
    ADD_ENV_COPY("PATH");
    ADD_ENV_COPY("HOME");
    ADD_ENV_COPY("USER");
    ADD_ENV_COPY("LOGNAME");
    ADD_ENV_COPY("TMPDIR");

    ADD_ARG_LIT(vm->def->os.kernel);
    //ADD_ARG_PAIR("con0", "fd:0,fd:1");
    ADD_ARG_PAIR("mem", memory);
    ADD_ARG_PAIR("umid", vm->def->name);

    if (vm->def->os.root)
        ADD_ARG_PAIR("root", vm->def->os.root);

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if (!STRPREFIX(disk->dst, "ubd")) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                           _("unsupported disk type '%s'"), disk->dst);
            goto error;
        }

        ADD_ARG_PAIR(disk->dst, disk->src);
    }

    for (i = 0 ; i < UML_MAX_CHAR_DEVICE ; i++) {
        char *ret;
        if (i == 0 && vm->def->console)
            ret = umlBuildCommandLineChr(conn, vm->def->console, "con");
        else
            if (asprintf(&ret, "con%d=none", i) < 0)
                goto no_memory;
        ADD_ARG(ret);
    }

    for (i = 0 ; i < UML_MAX_CHAR_DEVICE ; i++) {
        virDomainChrDefPtr chr = NULL;
        char *ret;
        for (j = 0 ; j < vm->def->nserials ; j++)
            if (vm->def->serials[j]->dstPort == i)
                chr = vm->def->serials[j];
        if (chr)
            ret = umlBuildCommandLineChr(conn, chr, "ssl");
        else
            if (asprintf(&ret, "ssl%d=none", i) < 0)
                goto no_memory;
        ADD_ARG(ret);
    }

    ADD_ARG(NULL);
    ADD_ENV(NULL);

    *retargv = qargv;
    *retenv = qenv;
    return 0;

 no_memory:
    umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for argv string"));
 error:
    if (tapfds &&
        *tapfds) {
        for (i = 0; i < *ntapfds; i++)
            close((*tapfds)[i]);
        VIR_FREE(*tapfds);
        *ntapfds = 0;
    }
    if (qargv) {
        for (i = 0 ; i < qargc ; i++)
            VIR_FREE((qargv)[i]);
        VIR_FREE(qargv);
    }
    if (qenv) {
        for (i = 0 ; i < qenvc ; i++)
            VIR_FREE((qenv)[i]);
        VIR_FREE(qenv);
    }
    return -1;

#undef ADD_ARG
#undef ADD_ARG_LIT
#undef ADD_ARG_SPACE
#undef ADD_USBDISK
#undef ADD_ENV
#undef ADD_ENV_COPY
#undef ADD_ENV_LIT
#undef ADD_ENV_SPACE
}
