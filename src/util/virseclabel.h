/*
 * virseclabel.h: security label utility functions
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

typedef enum {
    VIR_DOMAIN_SECLABEL_DEFAULT,
    VIR_DOMAIN_SECLABEL_NONE,
    VIR_DOMAIN_SECLABEL_DYNAMIC,
    VIR_DOMAIN_SECLABEL_STATIC,

    VIR_DOMAIN_SECLABEL_LAST
} virDomainSeclabelType;

/* Security configuration for domain */
typedef struct _virSecurityLabelDef virSecurityLabelDef;
struct _virSecurityLabelDef {
    char *model;        /* name of security model */
    char *label;        /* security label string */
    char *imagelabel;   /* security image label string */
    char *baselabel;    /* base name of label string */
    virDomainSeclabelType type; /* virDomainSeclabelType */
    bool relabel;       /* true (default) for allowing relabels */
    bool implicit;      /* true if seclabel is auto-added */
};


/* Security configuration for device */
typedef struct _virSecurityDeviceLabelDef virSecurityDeviceLabelDef;
struct _virSecurityDeviceLabelDef {
    char *model;
    char *label;        /* image label string */
    bool relabel;       /* true (default) for allowing relabels */
    bool labelskip;     /* live-only; true if skipping failed label attempt */
};

virSecurityLabelDef *
virSecurityLabelDefNew(const char *model);

virSecurityDeviceLabelDef *
virSecurityDeviceLabelDefNew(const char *model);

virSecurityDeviceLabelDef *
virSecurityDeviceLabelDefCopy(const virSecurityDeviceLabelDef *src)
    ATTRIBUTE_NONNULL(1);

void virSecurityLabelDefFree(virSecurityLabelDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSecurityLabelDef, virSecurityLabelDefFree);

void virSecurityDeviceLabelDefFree(virSecurityDeviceLabelDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSecurityDeviceLabelDef, virSecurityDeviceLabelDefFree);
