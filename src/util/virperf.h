/*
 * virperf.h: methods for managing perf events
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
 *  Ren Qiaowei <qiaowei.ren@intel.com>
 */

#ifndef __VIR_PERF_H__
# define __VIR_PERF_H__

# include "virutil.h"

/* Some Intel processor families introduced some RDT (Resource Director
 * Technology) features to monitor or control shared resource based on
 * the perf framework in the linux kernel. */
typedef enum {
    VIR_PERF_EVENT_CMT,    /* Cache Monitoring Technology */
    VIR_PERF_EVENT_MBMT,   /* Memory Bandwidth Monitoring Total */
    VIR_PERF_EVENT_MBML,   /* Memory Bandwidth Monitor Limit for controller */

    VIR_PERF_EVENT_CPU_CYCLES,       /* Count of CPU Cycles (total/elapsed) */
    VIR_PERF_EVENT_INSTRUCTIONS,     /* Count of instructions for application */
    VIR_PERF_EVENT_CACHE_REFERENCES, /* Cache hits by applications */
    VIR_PERF_EVENT_CACHE_MISSES,     /* Cache misses by applications */
    VIR_PERF_EVENT_BRANCH_INSTRUCTIONS, /* Count of branch instructions
                                           for applications */
    VIR_PERF_EVENT_BRANCH_MISSES,  /* Count of branch misses for applications */
    VIR_PERF_EVENT_BUS_CYCLES,       /* Count of bus cycles for applications*/
    VIR_PERF_EVENT_STALLED_CYCLES_FRONTEND, /* Count of stalled cpu cycles in
                                               the frontend of the instruction
                                               processor pipeline */
    VIR_PERF_EVENT_STALLED_CYCLES_BACKEND, /* Count of stalled cpu cycles in
                                              the backend of the instruction
                                              processor pipeline */
    VIR_PERF_EVENT_REF_CPU_CYCLES,   /* Count of ref cpu cycles */
    VIR_PERF_EVENT_CPU_CLOCK,   /* Count of cpu clock time*/
    VIR_PERF_EVENT_TASK_CLOCK,   /* Count of task clock time*/
    VIR_PERF_EVENT_PAGE_FAULTS,   /* Count of total page faults */
    VIR_PERF_EVENT_CONTEXT_SWITCHES,   /* Count of context switches */
    VIR_PERF_EVENT_CPU_MIGRATIONS,   /* Count of cpu migrations */

    VIR_PERF_EVENT_LAST
} virPerfEventType;

VIR_ENUM_DECL(virPerfEvent);

struct virPerf;
typedef struct virPerf *virPerfPtr;

virPerfPtr virPerfNew(void);

void virPerfFree(virPerfPtr perf);

int virPerfEventEnable(virPerfPtr perf,
                       virPerfEventType type,
                       pid_t pid);

int virPerfEventDisable(virPerfPtr perf,
                        virPerfEventType type);

bool virPerfEventIsEnabled(virPerfPtr perf,
                           virPerfEventType type);

int virPerfReadEvent(virPerfPtr perf,
                     virPerfEventType type,
                     uint64_t *value);

#endif /* __VIR_PERF_H__ */
