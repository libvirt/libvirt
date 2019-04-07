/*
 * vsh-table.c: table printing helper
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
#include "vsh-table.h"

#include <stdarg.h>
#include <stddef.h>
#include <wchar.h>
#include <wctype.h>
#include "c-ctype.h"

#include "viralloc.h"
#include "virbuffer.h"
#include "virstring.h"
#include "virsh-util.h"

#define HEX_ENCODE_LENGTH 4 /* represents length of '\xNN' */

struct _vshTableRow {
    char **cells;
    size_t ncells;
};


struct _vshTable {
    vshTableRowPtr *rows;
    size_t nrows;
};


static void
vshTableRowFree(vshTableRowPtr row)
{
    size_t i;

    if (!row)
        return;

    for (i = 0; i < row->ncells; i++)
        VIR_FREE(row->cells[i]);

    VIR_FREE(row->cells);
    VIR_FREE(row);
}


void
vshTableFree(vshTablePtr table)
{
    size_t i;

    if (!table)
        return;

    for (i = 0; i < table->nrows; i++)
        vshTableRowFree(table->rows[i]);
    VIR_FREE(table->rows);
    VIR_FREE(table);
}


/**
 * vshTableRowNew:
 * @arg: the first argument.
 * @ap: list of variadic arguments
 *
 * Create a new row in the table. Each argument passed
 * represents a cell in the row.
 *
 * Return: pointer to vshTableRowPtr row or NULL.
 */
static vshTableRowPtr
vshTableRowNew(const char *arg, va_list ap)
{
    vshTableRowPtr row = NULL;

    if (!arg) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Table row cannot be empty"));
        goto error;
    }

    if (VIR_ALLOC(row) < 0)
        goto error;

    while (arg) {
        char *tmp = NULL;

        if (VIR_STRDUP(tmp, arg) < 0)
            goto error;

        if (VIR_APPEND_ELEMENT(row->cells, row->ncells, tmp) < 0) {
            VIR_FREE(tmp);
            goto error;
        }

        arg = va_arg(ap, const char *);
    }

    return row;

 error:
    vshTableRowFree(row);
    return NULL;
}


/**
 * vshTableNew:
 * @arg: List of column names (NULL terminated)
 *
 * Create a new table.
 *
 * Returns: pointer to table or NULL.
 */
vshTablePtr
vshTableNew(const char *arg, ...)
{
    vshTablePtr table = NULL;
    vshTableRowPtr header = NULL;
    va_list ap;

    if (VIR_ALLOC(table) < 0)
        goto error;

    va_start(ap, arg);
    header = vshTableRowNew(arg, ap);
    va_end(ap);

    if (!header)
        goto error;

    if (VIR_APPEND_ELEMENT(table->rows, table->nrows, header) < 0)
        goto error;

    return table;
 error:
    vshTableRowFree(header);
    vshTableFree(table);
    return NULL;
}


/**
 * vshTableRowAppend:
 * @table: table to append to
 * @arg: cells of the row (NULL terminated)
 *
 * Append new row into the @table. The number of cells in the row has
 * to be equal to the number of cells in the table header.
 *
 * Returns: 0 if succeeded, -1 if failed.
 */
int
vshTableRowAppend(vshTablePtr table, const char *arg, ...)
{
    vshTableRowPtr row = NULL;
    size_t ncolumns = table->rows[0]->ncells;
    va_list ap;
    int ret = -1;

    va_start(ap, arg);
    row = vshTableRowNew(arg, ap);
    va_end(ap);

    if (!row)
        goto cleanup;

    if (ncolumns != row->ncells) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Incorrect number of cells in a table row"));
        goto cleanup;
    }

    if (VIR_APPEND_ELEMENT(table->rows, table->nrows, row) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    vshTableRowFree(row);
    return ret;
}


/**
 * Function pulled from util-linux
 *
 * Function's name in util-linux: mbs_safe_encode_to_buffer
 *
 * Returns allocated string where all control and non-printable chars are
 * replaced with \x?? hex sequence, or NULL.
 */
static char *
vshTableSafeEncode(const char *s, size_t *width)
{
    const char *p = s;
    size_t sz = s ? strlen(s) : 0;
    char *buf;
    char *ret;
    mbstate_t st;

    memset(&st, 0, sizeof(st));

    if (VIR_ALLOC_N(buf, (sz * HEX_ENCODE_LENGTH) + 1) < 0)
        return NULL;

    ret = buf;
    *width = 0;

    while (p && *p) {
        if ((*p == '\\' && *(p + 1) == 'x') ||
            c_iscntrl(*p)) {
            snprintf(buf, HEX_ENCODE_LENGTH + 1, "\\x%02x", *p);
            buf += HEX_ENCODE_LENGTH;
            *width += HEX_ENCODE_LENGTH;
            p++;
        } else {
            wchar_t wc;
            size_t len = mbrtowc(&wc, p, MB_CUR_MAX, &st);

            if (len == 0)
                break;		/* end of string */

            if (len == (size_t) -1 || len == (size_t) -2) {
                len = 1;
                /*
                 * Not valid multibyte sequence -- maybe it's
                 * printable char according to the current locales.
                 */
                if (!c_isprint(*p)) {
                    snprintf(buf, HEX_ENCODE_LENGTH + 1, "\\x%02x", *p);
                    buf += HEX_ENCODE_LENGTH;
                    *width += HEX_ENCODE_LENGTH;
                } else {
                    *buf++ = *p;
                    (*width)++;
                }
            } else if (!iswprint(wc)) {
                size_t i;
                for (i = 0; i < len; i++) {
                    snprintf(buf, HEX_ENCODE_LENGTH + 1, "\\x%02x", p[i]);
                    buf += HEX_ENCODE_LENGTH;
                    *width += HEX_ENCODE_LENGTH;
                }
            } else {
                memcpy(buf, p, len);
                buf += len;
                *width += wcwidth(wc);
            }
            p += len;
        }
    }

    *buf = '\0';
    return ret;
}


/**
 * vshTableGetColumnsWidths:
 * @table: table
 * @maxwidths: maximum count of characters for each columns
 * @widths: count of characters for each cell in the table
 *
 * Fill passed @maxwidths and @widths arrays with maximum number
 * of characters for columns and number of character per each
 * table cell, respectively.
 * Handle unicode strings (user must have multibyte locale)
 *
 * Return 0 in case of success, -1 otherwise.
 */
static int
vshTableGetColumnsWidths(vshTablePtr table,
                         size_t *maxwidths,
                         size_t **widths,
                         bool header)
{
    size_t i;

    i = header? 0 : 1;
    for (; i < table->nrows; i++) {
        vshTableRowPtr row = table->rows[i];
        size_t j;

        for (j = 0; j < row->ncells; j++) {
            size_t size = 0;
            /* need to replace nonprintable and control characters,
             * because width of some of those characters (e.g. \t, \v, \b ...)
             * cannot be counted properly */
            char *tmp = vshTableSafeEncode(row->cells[j], &size);
            if (!tmp)
                return -1;

            VIR_FREE(row->cells[j]);
            row->cells[j] = tmp;
            widths[i][j] = size;

            if (widths[i][j] > maxwidths[j])
                maxwidths[j] = widths[i][j];
        }
    }

    return 0;
}


/**
 * vshTableRowPrint:
 * @row: table to append to
 * @maxwidths: maximum count of characters for each columns
 * @widths: count of character for each cell in this row
 * @buf: buffer to store table (only if @toStdout == true)
 */
static void
vshTableRowPrint(vshTableRowPtr row,
                 size_t *maxwidths,
                 size_t *widths,
                 virBufferPtr buf)
{
    size_t i;
    size_t j;

    for (i = 0; i < row->ncells; i++) {
        virBufferAsprintf(buf, " %s", row->cells[i]);

        if (i < (row->ncells - 1)) {
            for (j = 0; j < maxwidths[i] - widths[i] + 2; j++)
                virBufferAddChar(buf, ' ');
        }
    }
    virBufferAddChar(buf, '\n');
}


/**
 * vshTablePrint:
 * @table: table to print
 * @header: whetever to print to header (true) or not (false)
 * this argument is relevant only if @ctl == NULL
 *
 * Get table. To get an alignment of columns right, function
 * fills 2d array @widths with count of characters in each cell and
 * array @maxwidths maximum count of character in each column.
 * Function then prints tables header and content.
 *
 * Return string containing table, or NULL
 */
static char *
vshTablePrint(vshTablePtr table, bool header)
{
    size_t i;
    size_t j;
    size_t *maxwidths;
    size_t **widths;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;

    if (VIR_ALLOC_N(maxwidths, table->rows[0]->ncells))
        goto cleanup;

    if (VIR_ALLOC_N(widths, table->nrows))
        goto cleanup;

    /* retrieve widths of columns */
    for (i = 0; i < table->nrows; i++) {
        if (VIR_ALLOC_N(widths[i], table->rows[0]->ncells))
            goto cleanup;
    }

    if (vshTableGetColumnsWidths(table, maxwidths, widths, header) < 0)
        goto cleanup;

    if (header) {
        /* print header */
        vshTableRowPrint(table->rows[0], maxwidths, widths[0], &buf);

        /* print dividing line  */
        for (i = 0; i < table->rows[0]->ncells; i++) {
            for (j = 0; j < maxwidths[i] + 3; j++)
                virBufferAddChar(&buf, '-');
        }
        virBufferAddChar(&buf, '\n');
    }
    /* print content */
    for (i = 1; i < table->nrows; i++)
        vshTableRowPrint(table->rows[i], maxwidths, widths[i], &buf);

    ret = virBufferContentAndReset(&buf);

 cleanup:
    VIR_FREE(maxwidths);
    for (i = 0; i < table->nrows; i++)
        VIR_FREE(widths[i]);
    VIR_FREE(widths);
    return ret;
}


/**
 * vshTablePrintToStdout:
 * @table: table to print
 * @ctl virtshell control structure
 *
 * Print table returned in string to stdout.
 * If effect on vshControl structure on printing function changes in future
 * (apart from quiet mode) this code may need update
 */
void
vshTablePrintToStdout(vshTablePtr table, vshControl *ctl)
{
    bool header;
    char *out;

    header = ctl ? !ctl->quiet : true;

    out = vshTablePrintToString(table, header);
    if (out)
        vshPrint(ctl, "%s", out);

    VIR_FREE(out);
}


/**
 * vshTablePrintToString:
 * @table: table to print
 * @header: whetever to print to header (true) or not (false)
 *
 * Return string containing table, or NULL if table was printed to
 * stdout. User will have to free returned string.
 */
char *
vshTablePrintToString(vshTablePtr table, bool header)
{
    return vshTablePrint(table, header);
}
