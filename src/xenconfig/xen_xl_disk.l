/*
 * xen_xl_disk.l - parser for disk specification strings
 *
 * Copyright (C) 2011      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

/*
 * Parsing the old xm/xend/xl-4.1 disk specs is a tricky problem,
 * because the target string might in theory contain "," which is the
 * delimiter we use for stripping off things on the RHS, and ":",
 * which is the delimiter we use for stripping off things on the LHS.
 *
 * In this parser we do not support such target strings in the old
 * syntax; if the target string has to contain "," or ":" the new
 * syntax's "target=" should be used.
 */
%{
# include <config.h>

# include <stdio.h>

# include "viralloc.h"
# include "virstoragefile.h"
# include "virstring.h"
# include "domain_conf.h"
# include "xen_xl.h"
# include "xen_xl_disk_i.h"

#define YY_NO_INPUT
#define VIR_FROM_THIS VIR_FROM_NONE

/* Some versions of flex have a bug (Fedora bugzilla 612465) which causes
 * it to fail to declare these functions, which it defines.  So declare
 * them ourselves.  Hopefully we won't have to simultaneously support
 * a flex version which declares these differently somehow. */
int xl_disk_lexget_column(yyscan_t yyscanner);
void xl_disk_lexset_column(int  column_no, yyscan_t yyscanner);


/*----- useful macros and functions used in actions -----
 * we use macros in the actual rules to keep the actions short
 * and particularly to avoid repeating boilerplate values such as
 * DPC->disk, yytext, etc. */

/* For actions whose patterns contain '=', finds the start of the value */
#define FROMEQUALS (strchr(yytext,'=')+1)

/* Chops the delimiter off, modifying yytext and yyleng. */
#define STRIP(delim) do{                                                \
	if (yyleng>0 && yytext[yyleng-1]==(delim))                      \
	    yytext[--yyleng] = 0;                                       \
    }while(0)

/* Sets a string value, checking it hasn't been set already. */
#define SAVESTRING(what,loc,val) do{					\
	savestring(DPC, what " respecified", &DPC->disk->loc, (val));	\
    }while(0)


static void
savestring(xenXLDiskParserContext *dpc,
           const char *what_respecified,
           char **update,
           const char *value)
{
    if (*update) {
        if (**update) {
            xenXLDiskParserError(dpc, value, what_respecified);
            return;
        }

        VIR_FREE(*update); /* do not complain about overwriting empty strings */
    }

    ignore_value(VIR_STRDUP(*update, value));
}

#define DPC dpc /* our convention in lexer helper functions */

/* Sets ->readwrite from the string. */
static void
setaccess(xenXLDiskParserContext *dpc, const char *str)
{
    if (STREQ(str, "rw") || STREQ(str, "w")) {
        dpc->disk->src->readonly = 0;
    } else if (STREQ(str, "r") || STREQ(str, "ro")) {
        dpc->disk->src->readonly = 1;
    } else if (STREQ(str, "w!") || STREQ(str, "!")) {
        dpc->disk->src->readonly = 0;
	dpc->disk->src->shared = 1;
    } else {
        xenXLDiskParserError(dpc, str, "unknown value for access");
    }
    dpc->access_set = 1;
}

/* Sets ->format from the string.  IDL should provide something for this. */
static void
setformat(xenXLDiskParserContext *dpc, const char *str)
{
    if (STREQ(str, "") || STREQ(str, "raw"))
        virDomainDiskSetFormat(dpc->disk, VIR_STORAGE_FILE_RAW);
    else if (STREQ(str, "qcow"))
        virDomainDiskSetFormat(dpc->disk, VIR_STORAGE_FILE_QCOW);
    else if (STREQ(str, "qcow2"))
        virDomainDiskSetFormat(dpc->disk, VIR_STORAGE_FILE_QCOW2);
    else if (STREQ(str, "vhd"))
        virDomainDiskSetFormat(dpc->disk, VIR_STORAGE_FILE_VHD);
    else
        xenXLDiskParserError(dpc, str, "unknown value for format");
}


/* Sets ->backend from the string.  IDL should provide something for this. */
static void
setdrivertype(xenXLDiskParserContext *dpc, const char *str)
{
    if (STREQ(str, "phy"))
        ignore_value(virDomainDiskSetDriver(dpc->disk, "phy"));
    else if (STREQ(str, "tap"))
        ignore_value(virDomainDiskSetDriver(dpc->disk, "tap"));
    else if (STREQ(str, "file") || STREQ(str, ""))
        ignore_value(virDomainDiskSetDriver(dpc->disk, "qemu"));
    else
        xenXLDiskParserError(dpc, str, "unknown value for backendtype");
}


/* Handles a vdev positional parameter which includes a devtype. */
static int
vdev_and_devtype(xenXLDiskParserContext *dpc, char *str)
{
    /* returns 1 if it was <vdev>:<devtype>, 0 (doing nothing) otherwise */
    char *colon = strrchr(str, ':');
    if (!colon)
        return 0;

    *colon++ = 0;
    SAVESTRING("vdev", dst, str);

    if (STREQ(colon,"cdrom")) {
        DPC->disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
    } else if (STREQ(colon, "disk")) {
        DPC->disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    } else {
        xenXLDiskParserError(DPC, colon, "unknown deprecated type");
    }
    return 1;
}

#undef DPC /* needs to be defined differently the actual lexer */
#define DPC ((xenXLDiskParserContext*)yyextra)

%}

%option warn
%option nodefault
%option batch
%option 8bit
%option noyywrap
%option reentrant
%option nounput

%x LEXERR

%%

 /*----- the scanner rules which do the parsing -----*/

[ \t\n]+/([^ \t\n].*)? { /* ignore whitespace before parameters */ }

 /* ordinary parameters setting enums or strings */

format=[^,]*,?	{ STRIP(','); setformat(DPC, FROMEQUALS); }

cdrom,?		{ DPC->disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM; }
devtype=cdrom,?	{ DPC->disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM; }
devtype=disk,?	{ DPC->disk->device = VIR_DOMAIN_DISK_DEVICE_DISK; }
devtype=[^,]*,?	{ xenXLDiskParserError(DPC, yytext,"unknown value for type"); }

access=[^,]*,?	{ STRIP(','); setaccess(DPC, FROMEQUALS); }
backendtype=[^,]*,? { STRIP(','); setdrivertype(DPC, FROMEQUALS); }

vdev=[^,]*,?	{ STRIP(','); SAVESTRING("vdev", dst, FROMEQUALS); }

 /* the target magic parameter, eats the rest of the string */

target=.*	{ STRIP(','); SAVESTRING("target", src->path, FROMEQUALS); }

 /* unknown parameters */

[a-z][-a-z0-9]*=[^,],? { xenXLDiskParserError(DPC, yytext, "unknown parameter"); }

  /* the "/.*" in these patterns ensures that they count as if they
   * matched the whole string, so these patterns take precedence */

(raw|qcow2?|vhd):/.* {
                    STRIP(':');
                    DPC->had_depr_prefix=1;
                    setformat(DPC, yytext);
                 }

tapdisk:/.*	{ DPC->had_depr_prefix=1; }
tap2?:/.*	{ DPC->had_depr_prefix=1; }
aio:/.*		{ DPC->had_depr_prefix=1; }
ioemu:/.*	{ DPC->had_depr_prefix=1; }
file:/.*	{ DPC->had_depr_prefix=1; }
phy:/.*		{ DPC->had_depr_prefix=1; }
[a-z][a-z0-9]*:/([^a-z0-9].*)? {
		  xenXLDiskParserError(DPC, yytext, "unknown deprecated disk prefix");
		  return 0;
		}

 /* positional parameters */

[^=,]*,|[^=,]+,?  {
    STRIP(',');

    if (DPC->err) {
        /* previous errors may just lead to subsequent ones */
    } else if (!DPC->disk->src->path) {
        SAVESTRING("target", src->path, yytext);
    } else if (DPC->disk->src->format == VIR_STORAGE_FILE_LAST){
        setformat(DPC, yytext);
    }
     else if (!DPC->disk->dst) {
        if (!vdev_and_devtype(DPC, yytext))
            SAVESTRING("vdev", dst, yytext);
    } else if (!DPC->access_set) {
        DPC->access_set = 1;
        setaccess(DPC, yytext);
    } else {
        xenXLDiskParserError(DPC, yytext, "too many positional parameters");
        return 0; /* don't print any more errors */
    }
}

. {
    BEGIN(LEXERR);
    yymore();
}
<LEXERR>.* {
    xenXLDiskParserError(DPC, yytext, "bad disk syntax");
    return 0;
}
