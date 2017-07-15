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
 *
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 */

#ifndef LIBXL_DOMAIN_H
# define LIBXL_DOMAIN_H

# include <libxl.h>

# include "domain_conf.h"
# include "libxl_conf.h"
# include "virchrdev.h"

# define JOB_MASK(job)                  (job == 0 ? 0 : 1 << (job - 1))
# define DEFAULT_JOB_MASK               \
    (JOB_MASK(LIBXL_JOB_DESTROY) |      \
     JOB_MASK(LIBXL_JOB_ABORT))

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
VIR_ENUM_DECL(libxlDomainJob)


struct libxlDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum libxlDomainJob active;         /* Currently running job */
    int owner;                          /* Thread which set current job */
    unsigned long long started;         /* When the job started */
    virDomainJobInfoPtr current;        /* Statistics for the current job */
};

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    virObjectLockable parent;

    /* console */
    virChrdevsPtr devs;
    libxl_evgen_domain_death *deathW;
    unsigned short migrationPort;
    char *lockState;

    struct libxlDomainJobObj job;

    bool hookRun;  /* true if there was a hook run over this domain */
};


extern virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks;
extern virDomainDefParserConfig libxlDomainDefParserConfig;
extern const struct libxl_event_hooks ev_hooks;

int
libxlDomainObjPrivateInitCtx(virDomainObjPtr vm);

int
libxlDomainObjBeginJob(libxlDriverPrivatePtr driver,
                       virDomainObjPtr obj,
                       enum libxlDomainJob job)
    ATTRIBUTE_RETURN_CHECK;

void
libxlDomainObjEndJob(libxlDriverPrivatePtr driver,
                     virDomainObjPtr obj);

int
libxlDomainJobUpdateTime(struct libxlDomainJobObj *job)
    ATTRIBUTE_RETURN_CHECK;

void
libxlDomainEventQueue(libxlDriverPrivatePtr driver,
                      virObjectEventPtr event);

char *
libxlDomainManagedSavePath(libxlDriverPrivatePtr driver,
                           virDomainObjPtr vm);

int
libxlDomainSaveImageOpen(libxlDriverPrivatePtr driver,
                         libxlDriverConfigPtr cfg,
                         const char *from,
                         virDomainDefPtr *ret_def,
                         libxlSavefileHeaderPtr ret_hdr)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

int
libxlDomainDestroyInternal(libxlDriverPrivatePtr driver,
                           virDomainObjPtr vm);

void
libxlDomainCleanup(libxlDriverPrivatePtr driver,
                   virDomainObjPtr vm);

/*
 * Note: Xen 4.3 removed the const from the event handler signature.
 * Detect which signature to use based on
 * LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG.
 */
# ifdef LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG
#  define VIR_LIBXL_EVENT_CONST /* empty */
# else
#  define VIR_LIBXL_EVENT_CONST const
# endif

void
libxlDomainEventHandler(void *data,
                        VIR_LIBXL_EVENT_CONST libxl_event *event);

int
libxlDomainAutoCoreDump(libxlDriverPrivatePtr driver,
                        virDomainObjPtr vm);

int
libxlDomainSetVcpuAffinities(libxlDriverPrivatePtr driver,
                             virDomainObjPtr vm);

int
libxlDomainStartNew(libxlDriverPrivatePtr driver,
                    virDomainObjPtr vm,
                    bool start_paused);

int
libxlDomainStartRestore(libxlDriverPrivatePtr driver,
                        virDomainObjPtr vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver);

bool
libxlDomainDefCheckABIStability(libxlDriverPrivatePtr driver,
                                virDomainDefPtr src,
                                virDomainDefPtr dst);

#endif /* LIBXL_DOMAIN_H */
