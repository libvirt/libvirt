/*
 * nwfilter_params.c: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "internal.h"

#include "viralloc.h"
#include "virerror.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "domain_conf.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("conf.nwfilter_params");

static bool isValidVarValue(const char *value);
static void virNWFilterVarAccessSetIntIterId(virNWFilterVarAccessPtr,
                                             unsigned int);
static unsigned int virNWFilterVarAccessGetIntIterId(const virNWFilterVarAccess *);

void
virNWFilterVarValueFree(virNWFilterVarValuePtr val)
{
    size_t i;

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

virNWFilterVarValuePtr
virNWFilterVarValueCopy(const virNWFilterVarValue *val)
{
    virNWFilterVarValuePtr res;
    size_t i;
    char *str;

    if (VIR_ALLOC(res) < 0)
        return NULL;
    res->valType = val->valType;

    switch (res->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        if (VIR_STRDUP(res->u.simple.value, val->u.simple.value) < 0)
            goto err_exit;
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        if (VIR_ALLOC_N(res->u.array.values, val->u.array.nValues) < 0)
            goto err_exit;
        res->u.array.nValues = val->u.array.nValues;
        for (i = 0; i < val->u.array.nValues; i++) {
            if (VIR_STRDUP(str, val->u.array.values[i]) < 0)
                goto err_exit;
            res->u.array.values[i] = str;
        }
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;

 err_exit:
    virNWFilterVarValueFree(res);
    return NULL;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimple(char *value)
{
    virNWFilterVarValuePtr val;

    if (!isValidVarValue(value)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Variable value contains invalid character"));
        return NULL;
    }

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->valType = NWFILTER_VALUE_TYPE_SIMPLE;
    val->u.simple.value = value;

    return val;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimpleCopyValue(const char *value)
{
    char *val;

    if (VIR_STRDUP(val, value) < 0)
        return NULL;
    return virNWFilterVarValueCreateSimple(val);
}

const char *
virNWFilterVarValueGetSimple(const virNWFilterVarValue *val)
{
    if (val->valType == NWFILTER_VALUE_TYPE_SIMPLE)
        return val->u.simple.value;
    return NULL;
}

const char *
virNWFilterVarValueGetNthValue(const virNWFilterVarValue* val, unsigned int idx)
{
    const char *res = NULL;

    if (!val)
        return NULL;

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
virNWFilterVarValueGetCardinality(const virNWFilterVarValue *val)
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

bool
virNWFilterVarValueEqual(const virNWFilterVarValue *a,
                         const virNWFilterVarValue *b)
{
    unsigned int card;
    size_t i, j;
    const char *s;

    if (!a || !b)
        return false;

    card = virNWFilterVarValueGetCardinality(a);
    if (card != virNWFilterVarValueGetCardinality(b))
        return false;

    /* brute force O(n^2) comparison */
    for (i = 0; i < card; i++) {
        bool eq = false;

        s = virNWFilterVarValueGetNthValue(a, i);
        for (j = 0; j < card; j++) {
            if (STREQ_NULLABLE(s, virNWFilterVarValueGetNthValue(b, j))) {
                 eq = true;
                 break;
            }
        }
        if (!eq)
            return false;
    }
    return true;
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
                         val->u.array.nValues, 1) < 0)
            return -1;
        val->u.array.values[val->u.array.nValues - 1] = value;
        rc = 0;
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return rc;
}

static int
virNWFilterVarValueDelNthValue(virNWFilterVarValuePtr val, unsigned int pos)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return -1;

    case NWFILTER_VALUE_TYPE_ARRAY:
        if (pos < val->u.array.nValues) {
            VIR_FREE(val->u.array.values[pos]);
            VIR_DELETE_ELEMENT(val->u.array.values, pos, val->u.array.nValues);
            return 0;
        }
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return -1;
}

int
virNWFilterVarValueDelValue(virNWFilterVarValuePtr val, const char *value)
{
    size_t i;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return -1;

    case NWFILTER_VALUE_TYPE_ARRAY:
        for (i = 0; i < val->u.array.nValues; i++)
            if (STREQ(value, val->u.array.values[i]))
                return virNWFilterVarValueDelNthValue(val, i);
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return -1;
}

void
virNWFilterVarCombIterFree(virNWFilterVarCombIterPtr ci)
{
    size_t i;

    if (!ci)
        return;

    for (i = 0; i < ci->nIter; i++)
        VIR_FREE(ci->iter[i].varNames);

    VIR_FREE(ci);
}

static int
virNWFilterVarCombIterGetIndexByIterId(virNWFilterVarCombIterPtr ci,
                                       unsigned int iterId)
{
    size_t i;

    for (i = 0; i < ci->nIter; i++)
        if (ci->iter[i].iterId == iterId)
            return i;

    return -1;
}

static void
virNWFilterVarCombIterEntryInit(virNWFilterVarCombIterEntryPtr cie,
                                unsigned int iterId)
{
    memset(cie, 0, sizeof(*cie));
    cie->iterId = iterId;
}

static int
virNWFilterVarCombIterAddVariable(virNWFilterVarCombIterEntryPtr cie,
                                  virNWFilterHashTablePtr hash,
                                  const virNWFilterVarAccess *varAccess)
{
    virNWFilterVarValuePtr varValue;
    unsigned int maxValue = 0, minValue = 0;
    const char *varName = virNWFilterVarAccessGetVarName(varAccess);

    varValue = virHashLookup(hash->hashTable, varName);
    if (varValue == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find value for variable '%s'"),
                       varName);
        return -1;
    }

    switch (virNWFilterVarAccessGetType(varAccess)) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        maxValue = virNWFilterVarAccessGetIndex(varAccess);
        minValue = maxValue;
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        maxValue = virNWFilterVarValueGetCardinality(varValue) - 1;
        minValue = 0;
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return -1;
    }

    if (cie->nVarNames == 0) {
        cie->maxValue = maxValue;
        cie->minValue = minValue;
        cie->curValue = minValue;
    } else {
        if (cie->maxValue != maxValue) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cardinality of list items must be "
                             "the same for processing them in "
                             "parallel"));
            return -1;
        }
    }

    if (VIR_EXPAND_N(cie->varNames, cie->nVarNames, 1) < 0)
        return -1;

    cie->varNames[cie->nVarNames - 1] = varName;

    return 0;
}

/*
 * Test whether the iterator entry points to a distinguished set of entries
 * that have not been seen before at one of the previous iterations.
 *
 * The point of this function is to eliminate duplicates.
 * Example with two lists:
 *
 * list1 = [1,2,1]
 * list2 = [1,3,1]
 *
 * The 1st iteration would take the 1st items of each list -> 1,1
 * The 2nd iteration would take the 2nd items of each list -> 2,3
 * The 3rd iteration would take the 3rd items of each list -> 1,1 but
 * skip them since this pair has already been encountered in the 1st iteration
 */
static bool
virNWFilterVarCombIterEntryAreUniqueEntries(virNWFilterVarCombIterEntryPtr cie,
                                            virNWFilterHashTablePtr hash)
{
    size_t i, j;
    virNWFilterVarValuePtr varValue, tmp;
    const char *value;

    varValue = virHashLookup(hash->hashTable, cie->varNames[0]);
    if (!varValue) {
        /* caller's error */
        VIR_ERROR(_("hash lookup resulted in NULL pointer"));
        return true;
    }

    value = virNWFilterVarValueGetNthValue(varValue, cie->curValue);
    if (!value) {
        VIR_ERROR(_("Lookup of value at index %u resulted in a NULL "
                  "pointer"), cie->curValue);
        return true;
    }

    for (i = 0; i < cie->curValue; i++) {
        if (STREQ(value, virNWFilterVarValueGetNthValue(varValue, i))) {
            bool isSame = true;
            for (j = 1; j < cie->nVarNames; j++) {
                tmp = virHashLookup(hash->hashTable, cie->varNames[j]);
                if (!tmp) {
                    /* should never occur to step on a NULL here */
                    return true;
                }
                if (!STREQ(virNWFilterVarValueGetNthValue(tmp, cie->curValue),
                           virNWFilterVarValueGetNthValue(tmp, i))) {
                    isSame = false;
                    break;
                }
            }
            if (isSame)
                return false;
        }
    }

    return true;
}

/*
 * Create an iterator over the contents of the given variables. All variables
 * must have entries in the hash table.
 * The iterator that is created processes all given variables in parallel,
 * meaning it will access $ITEM1[0] and $ITEM2[0] then $ITEM1[1] and $ITEM2[1]
 * up to $ITEM1[n] and $ITEM2[n]. For this to work, the cardinality of all
 * processed lists must be the same.
 * The notation $ITEM1 and $ITEM2 (in one rule) therefore will always have to
 * process the items in parallel. This will be an implicit notation for
 * $ITEM1[@0] and $ITEM2[@0] to 'lock' the two together. Future notations of
 * $ITEM1[@1] and $ITEM2[@2] will make them be processed independently,
 * which then would cause all combinations of the items of the two lists to
 * be created.
 */
virNWFilterVarCombIterPtr
virNWFilterVarCombIterCreate(virNWFilterHashTablePtr hash,
                             virNWFilterVarAccessPtr *varAccess,
                             size_t nVarAccess)
{
    virNWFilterVarCombIterPtr res;
    size_t i;
    unsigned int iterId;
    int iterIndex = -1;
    unsigned int nextIntIterId = VIR_NWFILTER_MAX_ITERID + 1;

    if (VIR_ALLOC_VAR(res, virNWFilterVarCombIterEntry, 1 + nVarAccess) < 0)
        return NULL;

    res->hashTable = hash;

    /* create the default iterator to support @0 */
    iterId = 0;

    res->nIter = 1;
    virNWFilterVarCombIterEntryInit(&res->iter[0], iterId);

    for (i = 0; i < nVarAccess; i++) {
        switch (virNWFilterVarAccessGetType(varAccess[i])) {
        case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
            iterId = virNWFilterVarAccessGetIterId(varAccess[i]);
            iterIndex = virNWFilterVarCombIterGetIndexByIterId(res, iterId);
            if (iterIndex < 0) {
                iterIndex = res->nIter;
                virNWFilterVarCombIterEntryInit(&res->iter[iterIndex], iterId);
                res->nIter++;
            }
            break;
        case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
            iterIndex = res->nIter;
            virNWFilterVarAccessSetIntIterId(varAccess[i], nextIntIterId);
            virNWFilterVarCombIterEntryInit(&res->iter[iterIndex],
                                            nextIntIterId);
            nextIntIterId++;
            res->nIter++;
            break;
        case VIR_NWFILTER_VAR_ACCESS_LAST:
            goto err_exit;
        }

        if (virNWFilterVarCombIterAddVariable(&res->iter[iterIndex],
                                              hash, varAccess[i]) < 0)
            goto err_exit;
    }

    return res;

 err_exit:
    virNWFilterVarCombIterFree(res);
    return NULL;
}

virNWFilterVarCombIterPtr
virNWFilterVarCombIterNext(virNWFilterVarCombIterPtr ci)
{
    size_t i;

    for (i = 0; i < ci->nIter; i++) {
 next:
        ci->iter[i].curValue++;
        if (ci->iter[i].curValue <= ci->iter[i].maxValue) {
            if (!virNWFilterVarCombIterEntryAreUniqueEntries(
                                              &ci->iter[i], ci->hashTable))
                goto next;
            break;
        } else {
            ci->iter[i].curValue = ci->iter[i].minValue;
        }
    }

    if (ci->nIter == i)
        return NULL;

    return ci;
}

const char *
virNWFilterVarCombIterGetVarValue(virNWFilterVarCombIterPtr ci,
                                  const virNWFilterVarAccess *vap)
{
    size_t i;
    unsigned int iterId;
    bool found = false;
    const char *res = NULL;
    virNWFilterVarValuePtr value;
    int iterIndex = -1;
    const char *varName = virNWFilterVarAccessGetVarName(vap);

    switch (virNWFilterVarAccessGetType(vap)) {
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        iterId = virNWFilterVarAccessGetIterId(vap);
        iterIndex = virNWFilterVarCombIterGetIndexByIterId(ci, iterId);
        if (iterIndex < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get iterator index for "
                             "iterator ID %u"), iterId);
            return NULL;
        }
        break;
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        iterId = virNWFilterVarAccessGetIntIterId(vap);
        iterIndex = virNWFilterVarCombIterGetIndexByIterId(ci, iterId);
        if (iterIndex < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get iterator index for "
                             "(internal) iterator ID %u"), iterId);
            return NULL;
        }
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return NULL;
    }

    for (i = 0; i < ci->iter[iterIndex].nVarNames; i++) {
        if (STREQ(ci->iter[iterIndex].varNames[i], varName)) {
            found = true;
            break;
        }
    }

    if (!found) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find variable '%s' in iterator"),
                       varName);
        return NULL;
    }

    value = virHashLookup(ci->hashTable->hashTable, varName);
    if (!value) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find value for variable '%s'"),
                       varName);
        return NULL;
    }

    res = virNWFilterVarValueGetNthValue(value, ci->iter[iterIndex].curValue);
    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get nth (%u) value of "
                         "variable '%s'"),
                       ci->iter[iterIndex].curValue, varName);
        return NULL;
    }

    return res;
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
 * Returns 0 on success, -1 on failure.
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
        char *newName;
        if (copyName) {
            if (VIR_STRDUP(newName, name) < 0)
                return -1;

            if (VIR_APPEND_ELEMENT_COPY(table->names,
                                        table->nNames, newName) < 0) {
                VIR_FREE(newName);
                return -1;
            }
        }

        if (virHashAddEntry(table->hashTable, name, val) < 0) {
            if (copyName) {
                VIR_FREE(newName);
                table->nNames--;
            }
            return -1;
        }
    } else {
        if (virHashUpdateEntry(table->hashTable, name, val) < 0) {
            return -1;
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
    size_t i;
    if (!table)
        return;
    virHashFree(table->hashTable);

    for (i = 0; i < table->nNames; i++)
        VIR_FREE(table->names[i]);
    VIR_FREE(table->names);
    VIR_FREE(table);
}


virNWFilterHashTablePtr
virNWFilterHashTableCreate(int n)
{
    virNWFilterHashTablePtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;
    ret->hashTable = virHashCreate(n, hashDataFree);
    if (!ret->hashTable) {
        VIR_FREE(ret);
        return NULL;
    }
    return ret;
}


void *
virNWFilterHashTableRemoveEntry(virNWFilterHashTablePtr ht,
                                const char *entry)
{
    size_t i;
    void *value = virHashSteal(ht->hashTable, entry);

    if (value) {
        for (i = 0; i < ht->nNames; i++) {
            if (STREQ(ht->names[i], entry)) {
                VIR_FREE(ht->names[i]);
                ht->names[i] = ht->names[--ht->nNames];
                ht->names[ht->nNames] = NULL;
                break;
            }
        }
    }
    return value;
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
        atts->errOccurred = 1;
        return;
    }

    if (virNWFilterHashTablePut(atts->target, (const char *)name, val, 1) < 0){
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    return -1;
}

/* The general purpose function virNWFilterVarValueEqual returns a
 * bool, but the comparison callback for virHashEqual (called below)
 * needs to return an int of 0 for == and non-0 for !=
 */
static int
virNWFilterVarValueCompare(const void *a, const void *b)
{
    return virNWFilterVarValueEqual((const virNWFilterVarValue *) a,
                                    (const virNWFilterVarValue *) b) ? 0 : 1;
}

bool
virNWFilterHashTableEqual(virNWFilterHashTablePtr a,
                          virNWFilterHashTablePtr b)
{
    if (!(a || b))
        return true;
    if (!(a && b))
        return false;
    return virHashEqual(a->hashTable, b->hashTable, virNWFilterVarValueCompare);
}

static bool
isValidVarName(const char *var)
{
    return var[strspn(var, VALID_VARNAME)] == 0;
}


static bool
isValidVarValue(const char *value)
{
    return (value[strspn(value, VALID_VARVALUE)] == 0) && (strlen(value) != 0);
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
    if (!table)
        return NULL;

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
                    if (!isValidVarValue(val))
                        goto skip_entry;
                    value = virHashLookup(table->hashTable, nam);
                    if (value) {
                        /* add value to existing value -> list */
                        if (virNWFilterVarValueAddValue(value, val) < 0) {
                            value = NULL;
                            goto err_exit;
                        }
                        val = NULL;
                    } else {
                        value = virNWFilterParseVarValue(val);
                        if (!value)
                            goto skip_entry;
                        if (virNWFilterHashTablePut(table, nam, value, 1) < 0)
                            goto err_exit;
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

 err_exit:
    VIR_FREE(nam);
    VIR_FREE(val);
    virNWFilterVarValueFree(value);
    virNWFilterHashTableFree(table);
    return NULL;
}


static int
virNWFilterFormatParameterNameSorter(const virHashKeyValuePair *a,
                                     const virHashKeyValuePair *b)
{
    return strcmp(a->key, b->key);
}

int
virNWFilterFormatParamAttributes(virBufferPtr buf,
                                 virNWFilterHashTablePtr table,
                                 const char *filterref)
{
    virHashKeyValuePairPtr items;
    size_t i, j;
    int card, numKeys;

    numKeys = virHashSize(table->hashTable);

    if (numKeys < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing filter parameter table"));
        return -1;
    }

    items = virHashGetItems(table->hashTable,
                            virNWFilterFormatParameterNameSorter);
    if (!items)
        return -1;

    virBufferAsprintf(buf, "<filterref filter='%s'", filterref);
    if (numKeys) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < numKeys; i++) {
            const virNWFilterVarValue *value = items[i].value;

            card = virNWFilterVarValueGetCardinality(value);

            for (j = 0; j < card; j++)
                virBufferAsprintf(buf,
                                  "<parameter name='%s' value='%s'/>\n",
                                  (const char *)items[i].key,
                                  virNWFilterVarValueGetNthValue(value, j));

        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</filterref>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    VIR_FREE(items);

    return 0;
}

void
virNWFilterVarAccessFree(virNWFilterVarAccessPtr varAccess)
{
    if (!varAccess)
        return;

    VIR_FREE(varAccess->varName);
    VIR_FREE(varAccess);
}

bool
virNWFilterVarAccessEqual(const virNWFilterVarAccess *a,
                          const virNWFilterVarAccess *b)
{
    if (a->accessType != b->accessType)
        return false;

    if (STRNEQ(a->varName, b->varName))
        return false;

    switch (a->accessType) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        return (a->u.index.index == b->u.index.index &&
                a->u.index.intIterId == b->u.index.intIterId);
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        return a->u.iterId == b->u.iterId;
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        break;
    }
    return false;
}

/*
 * Parse a variable access like
 * IP, IP[@2], IP[3]
 */
virNWFilterVarAccessPtr
virNWFilterVarAccessParse(const char *varAccess)
{
    size_t idx, varNameLen;
    virNWFilterVarAccessPtr dest;
    const char *input = varAccess;

    if (VIR_ALLOC(dest) < 0)
        return NULL;

    idx = strspn(input, VALID_VARNAME);

    if (input[idx] == '\0') {
        /* in the form 'IP', which is equivalent to IP[@0] */
        if (VIR_STRNDUP(dest->varName, input, idx) < 0)
            goto err_exit;
        dest->accessType = VIR_NWFILTER_VAR_ACCESS_ITERATOR;
        dest->u.iterId = 0;
        return dest;
    }

    if (input[idx] == '[') {
        char *end_ptr;
        unsigned int result;
        bool parseError = false;

        varNameLen = idx;

        if (VIR_STRNDUP(dest->varName, input, varNameLen) < 0)
            goto err_exit;

        input += idx + 1;
        virSkipSpaces(&input);

        if (*input == '@') {
            /* in the form 'IP[@<number>] -> iterator */
            dest->accessType = VIR_NWFILTER_VAR_ACCESS_ITERATOR;
            input++;
        } else {
            /* in the form 'IP[<number>] -> element */
            dest->accessType = VIR_NWFILTER_VAR_ACCESS_ELEMENT;
        }

        if (virStrToLong_ui(input, &end_ptr, 10, &result) < 0)
            parseError = true;
        if (!parseError) {
            input = end_ptr;
            virSkipSpaces(&input);
            if (*input != ']')
                parseError = true;
        }
        if (parseError) {
            if (dest->accessType == VIR_NWFILTER_VAR_ACCESS_ELEMENT)
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("Malformatted array index"));
            else
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("Malformatted iterator id"));
            goto err_exit;
        }

        switch (dest->accessType) {
        case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
            dest->u.index.index = result;
            dest->u.index.intIterId = ~0;
            break;
        case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
            if (result > VIR_NWFILTER_MAX_ITERID) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Iterator ID exceeds maximum ID "
                                 "of %u"), VIR_NWFILTER_MAX_ITERID);
                goto err_exit;
            }
            dest->u.iterId = result;
            break;
        case VIR_NWFILTER_VAR_ACCESS_LAST:
            goto err_exit;
        }

        return dest;
    } else {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Malformatted variable"));
    }

 err_exit:
    virNWFilterVarAccessFree(dest);

    return NULL;
}

void
virNWFilterVarAccessPrint(virNWFilterVarAccessPtr vap, virBufferPtr buf)
{
    virBufferAdd(buf, vap->varName, -1);
    switch (vap->accessType) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        virBufferAsprintf(buf, "[%u]", vap->u.index.index);
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        if (vap->u.iterId != 0)
            virBufferAsprintf(buf, "[@%u]", vap->u.iterId);
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        break;
    }
}

const char *
virNWFilterVarAccessGetVarName(const virNWFilterVarAccess *vap)
{
    return vap->varName;
}

enum virNWFilterVarAccessType
virNWFilterVarAccessGetType(const virNWFilterVarAccess *vap)
{
    return vap->accessType;
}

unsigned int
virNWFilterVarAccessGetIterId(const virNWFilterVarAccess *vap)
{
    return vap->u.iterId;
}

unsigned int
virNWFilterVarAccessGetIndex(const virNWFilterVarAccess *vap)
{
    return vap->u.index.index;
}

static void
virNWFilterVarAccessSetIntIterId(virNWFilterVarAccessPtr vap,
                                 unsigned int intIterId)
{
    vap->u.index.intIterId = intIterId;
}

static unsigned int
virNWFilterVarAccessGetIntIterId(const virNWFilterVarAccess *vap)
{
    return vap->u.index.intIterId;
}

bool
virNWFilterVarAccessIsAvailable(const virNWFilterVarAccess *varAccess,
                                const virNWFilterHashTable *hash)
{
    const char *varName = virNWFilterVarAccessGetVarName(varAccess);
    const char *res;
    unsigned int idx;
    virNWFilterVarValuePtr varValue;

    varValue = virHashLookup(hash->hashTable, varName);
    if (!varValue)
        return false;

    switch (virNWFilterVarAccessGetType(varAccess)) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        idx = virNWFilterVarAccessGetIndex(varAccess);
        res = virNWFilterVarValueGetNthValue(varValue, idx);
        if (res == NULL)
            return false;
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return false;
    }

    return true;
}
