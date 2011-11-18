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

static bool isValidVarValue(const char *value);


static void
virNWFilterVarValueFree(virNWFilterVarValuePtr val)
{
    unsigned i;

    if (!val)
        return;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        VIR_FREE(val->u.simple.value);
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        for (i = 0; i < val->u.array.nValues; i++)
            VIR_FREE(val->u.array.values[i]);
        VIR_FREE(val->u.array.values);
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }
    VIR_FREE(val);
}

static virNWFilterVarValuePtr
virNWFilterVarValueCopy(const virNWFilterVarValuePtr val)
{
    virNWFilterVarValuePtr res;
    unsigned i;
    char *str;

    if (VIR_ALLOC(res) < 0) {
        virReportOOMError();
        return NULL;
    }
    res->valType = val->valType;

    switch (res->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        if (val->u.simple.value) {
            res->u.simple.value = strdup(val->u.simple.value);
            if (!res->u.simple.value)
                goto err_exit;
        }
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        if (VIR_ALLOC_N(res->u.array.values, val->u.array.nValues))
            goto err_exit;
        res->u.array.nValues = val->u.array.nValues;
        for (i = 0; i < val->u.array.nValues; i++) {
            str = strdup(val->u.array.values[i]);
            if (!str)
                goto err_exit;
            res->u.array.values[i] = str;
        }
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;

err_exit:
    virReportOOMError();
    virNWFilterVarValueFree(res);
    return NULL;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimple(char *value)
{
    virNWFilterVarValuePtr val;

    if (!isValidVarValue(value)) {
        virNWFilterReportError(VIR_ERR_INVALID_ARG,
                               _("Variable value contains invalid character"));
        return NULL;
    }

    if (VIR_ALLOC(val) < 0) {
        virReportOOMError();
        return NULL;
    }

    val->valType = NWFILTER_VALUE_TYPE_SIMPLE;
    val->u.simple.value = value;

    return val;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimpleCopyValue(const char *value)
{
    char *val = strdup(value);

    if (!val) {
        virReportOOMError();
        return NULL;
    }
    return virNWFilterVarValueCreateSimple(val);
}

const char *
virNWFilterVarValueGetSimple(const virNWFilterVarValuePtr val)
{
    if (val->valType == NWFILTER_VALUE_TYPE_SIMPLE)
        return val->u.simple.value;
    return NULL;
}

const char *
virNWFilterVarValueGetNthValue(virNWFilterVarValuePtr val, unsigned int idx)
{
    const char *res = NULL;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        if (idx == 0)
            res = val->u.simple.value;
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        if (idx < val->u.array.nValues)
            res = val->u.array.values[idx];
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;
}

unsigned int
virNWFilterVarValueGetCardinality(const virNWFilterVarValuePtr val)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return 1;
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        return val->u.array.nValues;
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        return 0;
    }
    return 0;
}

int
virNWFilterVarValueAddValue(virNWFilterVarValuePtr val, char *value)
{
    char *tmp;
    int rc = -1;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        /* switch to array */
        tmp = val->u.simple.value;
        if (VIR_ALLOC_N(val->u.array.values, 2) < 0) {
            val->u.simple.value = tmp;
            virReportOOMError();
            return -1;
        }
        val->valType = NWFILTER_VALUE_TYPE_ARRAY;
        val->u.array.nValues = 2;
        val->u.array.values[0] = tmp;
        val->u.array.values[1] = value;
        rc  = 0;
        break;

    case NWFILTER_VALUE_TYPE_ARRAY:
        if (VIR_EXPAND_N(val->u.array.values,
                         val->u.array.nValues, 1) < 0) {
            virReportOOMError();
            return -1;
        }
        val->u.array.values[val->u.array.nValues - 1] = value;
        rc = 0;
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return rc;
}

static void
hashDataFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    virNWFilterVarValueFree(payload);
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
                        virNWFilterVarValuePtr val,
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
    virNWFilterVarValuePtr val;

    if (atts->errOccurred)
        return;

    val = virNWFilterVarValueCopy((virNWFilterVarValuePtr)payload);
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
        virNWFilterVarValueFree(val);
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

static virNWFilterVarValuePtr
virNWFilterParseVarValue(const char *val)
{
    return virNWFilterVarValueCreateSimpleCopyValue(val);
}

virNWFilterHashTablePtr
virNWFilterParseParamAttributes(xmlNodePtr cur)
{
    char *nam, *val;
    virNWFilterVarValuePtr value;

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
                value = NULL;
                if (nam != NULL && val != NULL) {
                    if (!isValidVarName(nam))
                        goto skip_entry;
                    value = virNWFilterParseVarValue(val);
                    if (!value)
                        goto skip_entry;
                    if (virNWFilterHashTablePut(table, nam, value, 1)) {
                        VIR_FREE(nam);
                        VIR_FREE(val);
                        virNWFilterVarValueFree(value);
                        virNWFilterHashTableFree(table);
                        return NULL;
                    }
                    value = NULL;
                }
skip_entry:
                virNWFilterVarValueFree(value);
                VIR_FREE(nam);
                VIR_FREE(val);
            }
        }
        cur = cur->next;
    }
    return table;
}


static void
_formatParameterAttrs(void *payload, const void *name, void *data)
{
    virBufferPtr buf = data;

    virBufferAsprintf(buf, "  <parameter name='%s' value='%s'/>\n",
                      (const char *)name,
                      (char *)payload);
}


int
virNWFilterFormatParamAttributes(virBufferPtr buf,
                                 virNWFilterHashTablePtr table,
                                 const char *filterref)
{
    int count = virHashSize(table->hashTable);

    if (count < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing filter parameter table"));
        return -1;
    }
    virBufferAsprintf(buf, "<filterref filter='%s'", filterref);
    if (count) {
        virBufferAddLit(buf, ">\n");
        virHashForEach(table->hashTable, _formatParameterAttrs, buf);
        virBufferAddLit(buf, "</filterref>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    return 0;
}
