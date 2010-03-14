
/*
 * authhelper.c: authentication related utility functions
 *
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#include <config.h>

#include "authhelper.h"
#include "util.h"
#include "memory.h"


char *
virRequestUsername(virConnectAuthPtr auth, const char *defaultUsername,
                   const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt;

    memset(&cred, 0, sizeof (virConnectCredential));

    if (defaultUsername != NULL) {
        if (virAsprintf(&prompt, _("Enter username for %s [%s]"), hostname,
                        defaultUsername) < 0) {
            return NULL;
        }
    } else {
        if (virAsprintf(&prompt, _("Enter username for %s"), hostname) < 0) {
            return NULL;
        }
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_AUTHNAME) {
            continue;
        }

        cred.type = VIR_CRED_AUTHNAME;
        cred.prompt = prompt;
        cred.challenge = hostname;
        cred.defresult = defaultUsername;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            VIR_FREE(cred.result);
        }

        break;
    }

    VIR_FREE(prompt);

    return cred.result;
}



char *
virRequestPassword(virConnectAuthPtr auth, const char *username,
                   const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt;

    memset(&cred, 0, sizeof (virConnectCredential));

    if (virAsprintf(&prompt, _("Enter %s's password for %s"), username,
                    hostname) < 0) {
        return NULL;
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_PASSPHRASE &&
            auth->credtype[ncred] != VIR_CRED_NOECHOPROMPT) {
            continue;
        }

        cred.type = auth->credtype[ncred];
        cred.prompt = prompt;
        cred.challenge = hostname;
        cred.defresult = NULL;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            VIR_FREE(cred.result);
        }

        break;
    }

    VIR_FREE(prompt);

    return cred.result;
}
