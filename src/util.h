/*
 * utils.h: common, generic utility functions
 *
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 * File created Jul 18, 2007 - Shuveb Hussain <shuveb@binarykarma.com>
 */

#ifndef __VIR_UTIL_H__
#define __VIR_UTIL_H__

#include "internal.h"
#include "util-lib.h"

int virExec(virConnectPtr conn, char **argv, int *retpid,
	    int infd, int *outfd, int *errfd);
int virExecNonBlock(virConnectPtr conn, char **argv, int *retpid,
		    int infd, int *outfd, int *errfd);
int virRun(virConnectPtr conn, char **argv, int *status);

int __virFileReadAll(const char *path,
		     int maxlen,
		     char **buf);
#define virFileReadAll(p,m,b) __virFileReadAll((p),(m),(b))

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix);

int virFileHasSuffix(const char *str,
                     const char *suffix);

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest);

int virFileExists(const char *path);

int virFileMakePath(const char *path);

int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen);


int __virStrToLong_i(char const *s,
                     char **end_ptr,
                     int base,
                     int *result);
#define virStrToLong_i(s,e,b,r) __virStrToLong_i((s),(e),(b),(r))

int virStrToLong_ui(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned int *result);
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result);
int __virStrToLong_ull(char const *s,
		       char **end_ptr,
		       int base,
		       unsigned long long *result);
#define virStrToLong_ull(s,e,b,r) __virStrToLong_ull((s),(e),(b),(r))

int __virMacAddrCompare (const char *mac1, const char *mac2);
#define virMacAddrCompare(mac1,mac2) __virMacAddrCompare((mac1),(mac2))

void virSkipSpaces(const char **str);
int virParseNumber(const char **str);

int virParseMacAddr(const char* str, unsigned char *addr);

#endif /* __VIR_UTIL_H__ */
