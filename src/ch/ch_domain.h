/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_domain.h: header file for domain manager's Cloud-Hypervisor driver functions
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

#include "ch_conf.h"
#include "ch_monitor.h"
#include "virchrdev.h"

/* Give up waiting for mutex after 30 seconds */
#define CH_JOB_WAIT_TIME (1000ull * 30)

/* Only 1 job is allowed at any time
 * A job includes *all* ch.so api, even those just querying
 * information, not merely actions */

enum virCHDomainJob {
    CH_JOB_NONE = 0,      /* Always set to 0 for easy if (jobActive) conditions */
    CH_JOB_QUERY,         /* Doesn't change any state */
    CH_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    CH_JOB_MODIFY,        /* May change state */
    CH_JOB_LAST
};
VIR_ENUM_DECL(virCHDomainJob);


struct virCHDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum virCHDomainJob active;        /* Currently running job */
    int owner;                          /* Thread which set current job */
};


typedef struct _virCHDomainObjPrivate virCHDomainObjPrivate;
struct _virCHDomainObjPrivate {
    struct virCHDomainJobObj job;

    virCHMonitor *monitor;

     virChrdevs *chrdevs;
};

extern virDomainXMLPrivateDataCallbacks virCHDriverPrivateDataCallbacks;
extern virDomainDefParserConfig virCHDriverDomainDefParserConfig;

int
virCHDomainObjBeginJob(virDomainObj *obj, enum virCHDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;

void
virCHDomainObjEndJob(virDomainObj *obj);
