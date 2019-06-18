/*
 * vsh-table.h: table printing helper
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "vsh.h"

typedef struct _vshTable vshTable;
typedef struct _vshTableRow vshTableRow;
typedef vshTable *vshTablePtr;
typedef vshTableRow *vshTableRowPtr;

void vshTableFree(vshTablePtr table);
vshTablePtr vshTableNew(const char *format, ...);
int vshTableRowAppend(vshTablePtr table, const char *arg, ...);
void vshTablePrintToStdout(vshTablePtr table, vshControl *ctl);
char *vshTablePrintToString(vshTablePtr table, bool header);
