/*
 * libxl_domain.h: libxl domain object private state
 *
 * Copyright (C) 2011-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <libxl.h>

#include "domain_conf.h"
#include "libxl_conf.h"
#include "virchrdev.h"
#include "virenum.h"
#include "domain_job.h"

/* Only 1 job is allowed at any time
 * A job includes *all* libxl.so api, even those just querying
 * information, not merely actions */
enum libxlDomainJob {
    LIBXL_JOB_NONE = 0,      /* Always set to 0 for easy if (jobActive) conditions */
    LIBXL_JOB_QUERY,         /* Doesn't change any state */
    LIBXL_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    LIBXL_JOB_MODIFY,        /* May change state */

    LIBXL_JOB_LAST
};
VIR_ENUM_DECL(libxlDomainJob);


struct libxlDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum libxlDomainJob active;         /* Currently running job */
    int owner;                          /* Thread which set current job */
    unsigned long long started;         /* When the job started */
    virDomainJobData *current;        /* Statistics for the current job */
};

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
struct _libxlDomainObjPrivate {
    /* console */
    virChrdevs *devs;
    libxl_evgen_domain_death *deathW;
    virThread *migrationDstReceiveThr;
    unsigned short migrationPort;
    char *lockState;
    bool lockProcessRunning;

    struct libxlDomainJobObj job;

    bool hookRun;  /* true if there was a hook run over this domain */
};


extern virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks;
extern virDomainDefParserConfig libxlDomainDefParserConfig;
extern virXMLNamespace libxlDriverDomainXMLNamespace;
extern const struct libxl_event_hooks ev_hooks;

int
libxlDomainObjPrivateInitCtx(virDomainObj *vm);

int
libxlDomainObjBeginJob(libxlDriverPrivate *driver,
                       virDomainObj *obj,
                       enum libxlDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;

void
libxlDomainObjEndJob(libxlDriverPrivate *driver,
                     virDomainObj *obj);

int
libxlDomainJobUpdateTime(struct libxlDomainJobObj *job)
    G_GNUC_WARN_UNUSED_RESULT;

char *
libxlDomainManagedSavePath(libxlDriverPrivate *driver,
                           virDomainObj *vm);

int
libxlDomainSaveImageOpen(libxlDriverPrivate *driver,
                         const char *from,
                         virDomainDef **ret_def,
                         libxlSavefileHeader *ret_hdr)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
libxlDomainHookRun(libxlDriverPrivate *driver,
                   virDomainDef *def,
                   unsigned int def_fmtflags,
                   int hookop,
                   int hooksubop,
                   char **output);

int
libxlDomainDestroyInternal(libxlDriverPrivate *driver,
                           virDomainObj *vm);

void
libxlDomainCleanup(libxlDriverPrivate *driver,
                   virDomainObj *vm);

void
libxlDomainEventHandler(void *data, libxl_event *event);

int
libxlDomainAutoCoreDump(libxlDriverPrivate *driver,
                        virDomainObj *vm);

int
libxlDomainStartNew(libxlDriverPrivate *driver,
                    virDomainObj *vm,
                    bool start_paused);

int
libxlDomainStartRestore(libxlDriverPrivate *driver,
                        virDomainObj *vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver);

bool
libxlDomainDefCheckABIStability(libxlDriverPrivate *driver,
                                virDomainDef *src,
                                virDomainDef *dst);
