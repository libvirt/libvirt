/*
 * xen_sxpr.c: Xen SEXPR parsing functions
 *
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
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

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virlog.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_sxpr.h"
#include "virstoragefile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SEXPR

VIR_LOG_INIT("xenconfig.xen_sxpr");

/* Get a domain id from a S-expression string */
int xenGetDomIdFromSxprString(const char *sexpr, int *id)
{
    struct sexpr *root = string2sexpr(sexpr);
    int ret;

    *id = -1;

    if (!root)
        return -1;

    ret = xenGetDomIdFromSxpr(root, id);
    sexpr_free(root);
    return ret;
}

/* Get a domain id from a S-expression */
int xenGetDomIdFromSxpr(const struct sexpr *root, int *id)
{
    const char * tmp = sexpr_node(root, "domain/domid");

    *id = tmp ? sexpr_int(root, "domain/domid") : -1;
    return 0;
}


/**
  * xenParseSxprChar:
  * @value: A string describing a character device.
  * @tty: the console pty path
  *
  * Parse the xend S-expression for description of a character device.
  *
  * Returns a character device object or NULL in case of failure.
  */
virDomainChrDefPtr
xenParseSxprChar(const char *value,
                 const char *tty)
{
    const char *prefix;
    char *tmp;
    virDomainChrDefPtr def;

    if (!(def = virDomainChrDefNew(NULL)))
        return NULL;

    prefix = value;

    if (value[0] == '/') {
        def->source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        if (VIR_STRDUP(def->source->data.file.path, value) < 0)
            goto error;
    } else {
        if ((tmp = strchr(value, ':')) != NULL) {
            *tmp = '\0';
            value = tmp + 1;
        }

        if (STRPREFIX(prefix, "telnet")) {
            def->source->type = VIR_DOMAIN_CHR_TYPE_TCP;
            def->source->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else {
            if ((def->source->type = virDomainChrTypeFromString(prefix)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown chr device type '%s'"), prefix);
                goto error;
            }
        }
    }

    switch (def->source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (VIR_STRDUP(def->source->data.file.path, tty) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (VIR_STRDUP(def->source->data.file.path, value) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2;

        if (offset == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            VIR_STRNDUP(def->source->data.tcp.host, value, offset - value) < 0)
            goto error;

        offset2 = strchr(offset, ',');
        offset++;
        if (VIR_STRNDUP(def->source->data.tcp.service, offset,
                        offset2 ? offset2 - offset : -1) < 0)
            goto error;

        if (offset2 && strstr(offset2, ",server"))
            def->source->data.tcp.listen = true;
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            VIR_STRNDUP(def->source->data.udp.connectHost, value, offset - value) < 0)
            goto error;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if (VIR_STRNDUP(def->source->data.udp.connectService,
                            offset + 1, offset2 - offset - 1) < 0)
                goto error;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                VIR_STRNDUP(def->source->data.udp.bindHost,
                            offset2 + 1, offset3 - offset2 - 1) < 0)
                goto error;

            if (VIR_STRDUP(def->source->data.udp.bindService, offset3 + 1) < 0)
                goto error;
        } else {
            if (VIR_STRDUP(def->source->data.udp.connectService, offset + 1) < 0)
                goto error;
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (VIR_STRNDUP(def->source->data.nix.path, value,
                        offset ? offset - value : -1) < 0)
            goto error;

        if (offset != NULL &&
            strstr(offset, ",server") != NULL)
            def->source->data.nix.listen = true;
    }
    break;
    }

    return def;

 error:
    virDomainChrDefFree(def);
    return NULL;
}
