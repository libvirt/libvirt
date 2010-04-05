/*
 * nwfilter_params.h: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2010 IBM Corporation
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
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef NWFILTER_PARAMS_H
# define NWFILTER_PARAMS_H

# include "hash.h"

typedef struct _virNWFilterHashTable virNWFilterHashTable;
typedef virNWFilterHashTable *virNWFilterHashTablePtr;
struct _virNWFilterHashTable {
    virHashTablePtr hashTable;

    int nNames;
    char **names;
};


virNWFilterHashTablePtr virNWFilterParseParamAttributes(xmlNodePtr cur);
char * virNWFilterFormatParamAttributes(virNWFilterHashTablePtr table,
                                        const char *indent);

virNWFilterHashTablePtr virNWFilterHashTableCreate(int n);
void virNWFilterHashTableFree(virNWFilterHashTablePtr table);
int virNWFilterHashTablePut(virNWFilterHashTablePtr table,
                            const char *name,
                            char *val,
                            int freeName);
int virNWFilterHashTableRemoveEntry(virNWFilterHashTablePtr table,
                                    const char *name);
int virNWFilterHashTablePutAll(virNWFilterHashTablePtr src,
                               virNWFilterHashTablePtr dest);

# define VALID_VARNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# define VALID_VARVALUE \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:"

#endif /* NWFILTER_PARAMS_H */
