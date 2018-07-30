/*
 * vircgrouppriv.h: methods for managing control cgroups
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
 * Copyright IBM Corp. 2008
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
 *  Dan Smith <danms@us.ibm.com>
 */

#ifndef __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__
# error "vircgrouppriv.h may only be included by vircgroup.c or its test suite"
#endif

#ifndef __VIR_CGROUP_PRIV_H__
# define __VIR_CGROUP_PRIV_H__

# include "vircgroup.h"

struct virCgroupController {
    int type;
    char *mountPoint;
    /* If mountPoint holds several controllers co-mounted,
     * then linkPoint is path of the symlink to the mountPoint
     * for just the one controller
     */
    char *linkPoint;
    char *placement;
};

struct virCgroup {
    char *path;

    struct virCgroupController controllers[VIR_CGROUP_CONTROLLER_LAST];
};

int virCgroupDetectMountsFromFile(virCgroupPtr group,
                                  const char *path,
                                  bool checkLinks);

#endif /* __VIR_CGROUP_PRIV_H__ */
