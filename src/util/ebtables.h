/*
 * Copyright (C) 2009 IBM Corp.
 * Copyright (C) 2007, 2008 Red Hat, Inc.
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
 * based on iptables.h
 * Authors:
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#ifndef __QEMUD_EBTABLES_H__
# define __QEMUD_EBTABLES_H__

typedef struct
{
    char  *rule;
    const char **argv;
    int    command_idx;
} ebtRule;

typedef struct
{
    char  *table;
    char  *chain;

    int      nrules;
    ebtRule *rules;

} ebtRules;

typedef struct _ebtablesContext ebtablesContext;

ebtablesContext *ebtablesContextNew              (const char *driver);
void             ebtablesContextFree             (ebtablesContext *ctx);

void             ebtablesSaveRules               (ebtablesContext *ctx);

int              ebtablesAddForwardAllowIn       (ebtablesContext *ctx,
                                                  const char *iface,
                                                  const unsigned char *mac);
int              ebtablesRemoveForwardAllowIn    (ebtablesContext *ctx,
                                                  const char *iface,
                                                  const unsigned char *mac);

int              ebtablesAddForwardPolicyReject(ebtablesContext *ctx);

int              ebtablesRemoveForwardPolicyReject(ebtablesContext *ctx);

int              ebtablesForwardPolicyReject(ebtablesContext *ctx,
                                                  int action);

#endif /* __QEMUD_ebtabLES_H__ */
