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

#ifndef LIBVIRT_VIRSECLABEL_H
# define LIBVIRT_VIRSECLABEL_H

typedef enum {
    VIR_DOMAIN_SECLABEL_DEFAULT,
    VIR_DOMAIN_SECLABEL_NONE,
    VIR_DOMAIN_SECLABEL_DYNAMIC,
    VIR_DOMAIN_SECLABEL_STATIC,

    VIR_DOMAIN_SECLABEL_LAST
} virDomainSeclabelType;

/* Security configuration for domain */
typedef struct _virSecurityLabelDef virSecurityLabelDef;
typedef virSecurityLabelDef *virSecurityLabelDefPtr;
struct _virSecurityLabelDef {
    char *model;        /* name of security model */
    char *label;        /* security label string */
    char *imagelabel;   /* security image label string */
    char *baselabel;    /* base name of label string */
    int type;           /* virDomainSeclabelType */
    bool relabel;       /* true (default) for allowing relabels */
    bool implicit;      /* true if seclabel is auto-added */
};


/* Security configuration for device */
typedef struct _virSecurityDeviceLabelDef virSecurityDeviceLabelDef;
typedef virSecurityDeviceLabelDef *virSecurityDeviceLabelDefPtr;
struct _virSecurityDeviceLabelDef {
    char *model;
    char *label;        /* image label string */
    bool relabel;       /* true (default) for allowing relabels */
    bool labelskip;     /* live-only; true if skipping failed label attempt */
};

virSecurityLabelDefPtr
virSecurityLabelDefNew(const char *model);

virSecurityDeviceLabelDefPtr
virSecurityDeviceLabelDefNew(const char *model);

virSecurityDeviceLabelDefPtr
virSecurityDeviceLabelDefCopy(const virSecurityDeviceLabelDef *src)
    ATTRIBUTE_NONNULL(1);

void virSecurityLabelDefFree(virSecurityLabelDefPtr def);
void virSecurityDeviceLabelDefFree(virSecurityDeviceLabelDefPtr def);

#endif /* LIBVIRT_VIRSECLABEL_H */
