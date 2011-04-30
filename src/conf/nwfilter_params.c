/*
 * nwfilter_params.c: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2011 Red Hat, Inc.
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

#include <config.h>

#include "internal.h"

#include "memory.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "domain_conf.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

static void
hashDataFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}


/**
 * virNWFilterHashTablePut:
 * @table: Pointer to a virNWFilterHashTable
 * @name: name of the key to enter
 * @val: The value associated with the key
 * @freeName: Whether the name must be freed on table destruction
 *
 * Returns 0 on success, 1 on failure.
 *
 * Put an entry into the hashmap replacing and freeing an existing entry
 * if one existed.
 */
int
virNWFilterHashTablePut(virNWFilterHashTablePtr table,
                        const char *name,
                        char *val,
                        int copyName)
{
    if (!virHashLookup(table->hashTable, name)) {
        if (copyName) {
            name = strdup(name);
            if (!name)
                return 1;

            if (VIR_REALLOC_N(table->names, table->nNames + 1) < 0) {
                VIR_FREE(name);
                return 1;
            }
            table->names[table->nNames++] = (char *)name;
        }

        if (virHashAddEntry(table->hashTable, name, val) != 0) {
            if (copyName) {
                VIR_FREE(name);
                table->nNames--;
            }
            return 1;
        }
    } else {
        if (virHashUpdateEntry(table->hashTable, name, val) != 0) {
            return 1;
        }
    }
    return 0;
}


/**
 * virNWFilterHashTableFree:
 * @table: Pointer to virNWFilterHashTable
 *
 * Free a hashtable de-allocating memory for all its entries.
 *
 * All hash tables within the NWFilter driver must use this
 * function to deallocate and free their content.
 */
void
virNWFilterHashTableFree(virNWFilterHashTablePtr table)
{
    int i;
    if (!table)
        return;
    virHashFree(table->hashTable);

    for (i = 0; i < table->nNames; i++)
        VIR_FREE(table->names[i]);
    VIR_FREE(table->names);
    VIR_FREE(table);
}


virNWFilterHashTablePtr
virNWFilterHashTableCreate(int n) {
    virNWFilterHashTablePtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }
    ret->hashTable = virHashCreate(n, hashDataFree);
    if (!ret->hashTable) {
        VIR_FREE(ret);
        return NULL;
    }
    return ret;
}


int
virNWFilterHashTableRemoveEntry(virNWFilterHashTablePtr ht,
                                const char *entry)
{
    int i;
    int rc = virHashRemoveEntry(ht->hashTable, entry);

    if (rc == 0) {
        for (i = 0; i < ht->nNames; i++) {
            if (STREQ(ht->names[i], entry)) {
                VIR_FREE(ht->names[i]);
                ht->names[i] = ht->names[--ht->nNames];
                ht->names[ht->nNames] = NULL;
                break;
            }
        }
    }
    return rc;
}


struct addToTableStruct {
    virNWFilterHashTablePtr target;
    int errOccurred;
};


static void
addToTable(void *payload, const void *name, void *data)
{
    struct addToTableStruct *atts = (struct addToTableStruct *)data;
    char *val;

    if (atts->errOccurred)
        return;

    val = strdup((char *)payload);
    if (!val) {
        virReportOOMError();
        atts->errOccurred = 1;
        return;
    }

    if (virNWFilterHashTablePut(atts->target, (const char *)name, val, 1) != 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not put variable '%s' into hashmap"),
                               (const char *)name);
        atts->errOccurred = 1;
        VIR_FREE(val);
    }
}


int
virNWFilterHashTablePutAll(virNWFilterHashTablePtr src,
                           virNWFilterHashTablePtr dest)
{
    struct addToTableStruct atts = {
        .target = dest,
        .errOccurred = 0,
    };

    virHashForEach(src->hashTable, addToTable, &atts);
    if (atts.errOccurred)
        goto err_exit;

    return 0;

err_exit:
    return 1;
}


static bool
isValidVarName(const char *var)
{
    return var[strspn(var, VALID_VARNAME)] == 0;
}


static bool
isValidVarValue(const char *value)
{
    return value[strspn(value, VALID_VARVALUE)] == 0;
}


virNWFilterHashTablePtr
virNWFilterParseParamAttributes(xmlNodePtr cur)
{
    char *nam, *val;

    virNWFilterHashTablePtr table = virNWFilterHashTableCreate(0);
    if (!table) {
        virReportOOMError();
        return NULL;
    }

    cur = cur->children;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "parameter")) {
                nam = virXMLPropString(cur, "name");
                val = virXMLPropString(cur, "value");
                if (nam != NULL && val != NULL) {
                    if (!isValidVarName(nam))
                        goto skip_entry;
                    if (!isValidVarValue(nam))
                        goto skip_entry;
                    if (virNWFilterHashTablePut(table, nam, val, 1)) {
                        VIR_FREE(nam);
                        VIR_FREE(val);
                        virNWFilterHashTableFree(table);
                        return NULL;
                    }
                    val = NULL;
                }
skip_entry:
                VIR_FREE(nam);
                VIR_FREE(val);
            }
        }
        cur = cur->next;
    }
    return table;
}


struct formatterParam {
    virBufferPtr buf;
    const char *indent;
};


static void
_formatParameterAttrs(void *payload, const void *name, void *data)
{
    struct formatterParam *fp = (struct formatterParam *)data;

    virBufferAsprintf(fp->buf, "%s<parameter name='%s' value='%s'/>\n",
                      fp->indent,
                      (const char *)name,
                      (char *)payload);
}


char *
virNWFilterFormatParamAttributes(virNWFilterHashTablePtr table,
                                 const char *indent)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    struct formatterParam fp = {
        .buf = &buf,
        .indent = indent,
    };

    virHashForEach(table->hashTable, _formatParameterAttrs, &fp);

    if (virBufferError(&buf)) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}
