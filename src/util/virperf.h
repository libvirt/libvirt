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

typedef enum {
    VIR_PERF_EVENT_CMT,
    VIR_PERF_EVENT_MBMT,
    VIR_PERF_EVENT_MBML,

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
