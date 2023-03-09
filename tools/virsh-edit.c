/*
 * virsh-edit.c: Implementation of generic virsh *-edit intelligence
 *
 * Copyright (C) 2012, 2015 Red Hat, Inc.
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
 * Usage:
 * Define macros:
 * EDIT_GET_XML - expression which produces a pointer to XML string, e.g:
 *      #define EDIT_GET_XML virDomainGetXMLDesc(dom, flags)
 *
 * EDIT_NOT_CHANGED - this action is taken if the XML wasn't changed.
 *      Note, that you don't want to jump to cleanup but edit_cleanup label
 *      where temporary variables are free()-d and temporary file is deleted:
 *      #define EDIT_NOT_CHANGED vshPrintExtra (ctl, _("Domain %1$s XML not changed"), \
 *                                              virDomainGetName(dom)); \
 *                               ret = true; goto edit_cleanup;
 *      Note that this is a statement.
 *
 * EDIT_DEFINE - expression which redefines the object. The edited XML from
 *      user is in 'doc_edited' variable. Don't overwrite the pointer to the
 *      object, as we may iterate once more over and therefore the pointer
 *      would be invalid. Hence assign object to a different variable.
 *      Moreover, this needs to be an expression where:
 *      - 0 is taken as error (our virDefine* APIs often return NULL on error)
 *      - everything else is taken as success
 *      For example:
 *      #define EDIT_DEFINE (dom_edited = virDomainDefineXML(ctl->conn, doc_edited))
 */

#ifndef EDIT_GET_XML
# error Missing EDIT_GET_XML definition
#endif

#ifndef EDIT_NOT_CHANGED
# error Missing EDIT_NOT_CHANGED definition
#endif

#ifndef EDIT_DEFINE
# error Missing EDIT_DEFINE definition
#endif

do {
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;
    const char *msg = NULL;
    bool edit_success = false;
    bool relax_avail = false;

    /* Get the XML configuration of the object. */
    doc = (EDIT_GET_XML);
    if (!doc)
        goto edit_cleanup;

    /* Create and open the temporary file. */
    tmp = vshEditWriteToTempFile(ctl, doc);
    if (!tmp)
        goto edit_cleanup;

 reedit:

#ifdef EDIT_RELAX
    relax_avail = true;
#endif

    /* Start the editor. */
    if (vshEditFile(ctl, tmp) == -1)
        goto edit_cleanup;

    /* Read back the edited file. */
    VIR_FREE(doc_edited);
    doc_edited = vshEditReadBackFile(ctl, tmp);
    if (!doc_edited)
        goto edit_cleanup;

    /* Compare original XML with edited.  Has it changed at all? */
    if (STREQ(doc, doc_edited))
        EDIT_NOT_CHANGED;

 redefine:
    msg = NULL;

    /* Now re-read the object XML.  Did someone else change it while
     * it was being edited?  This also catches problems such as us
     * losing a connection or the object going away.
     */
    VIR_FREE(doc_reread);
    doc_reread = (EDIT_GET_XML);
    if (!doc_reread)
        goto edit_cleanup;

    if (STRNEQ(doc, doc_reread)) {
        msg = _("The XML configuration was changed by another user.");
        VIR_FREE(doc);
        doc = doc_reread;
        doc_reread = NULL;
    }

    /* Everything checks out, so redefine the object. */
    if (!msg && !(EDIT_DEFINE))
        msg = _("Failed.");

    if (msg) {
        int c = vshAskReedit(ctl, msg, relax_avail);
        switch (c) {
        case 'y':
            goto reedit;
            break;

        case 'f':
            goto redefine;
            break;

        case 'n':
            goto edit_cleanup;
            break;

#ifdef EDIT_RELAX
        case 'i':
            if (relax_avail) {
                EDIT_RELAX;
                relax_avail = false;
                goto redefine;
            }
            G_GNUC_FALLTHROUGH;
#endif

        default:
            vshError(ctl, "%s", msg);
            break;
        }
    }

    edit_success = true;

 edit_cleanup:
    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    VIR_FREE(doc_reread);
    if (tmp) {
        unlink(tmp);
        VIR_FREE(tmp);
    }

    if (!edit_success)
        goto cleanup;

} while (0);


#undef EDIT_GET_XML
#undef EDIT_NOT_CHANGED
#undef EDIT_DEFINE
