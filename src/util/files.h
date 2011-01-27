/*
 * files.h: safer file handling
 *
 * Copyright (C) 2010-2011 RedHat, Inc.
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
 * Copyright (C) 2010 Eric Blake
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


#ifndef __VIR_FILES_H_
# define __VIR_FILES_H_

# include <stdbool.h>
# include <stdio.h>

# include "internal.h"
# include "ignore-value.h"


/* Don't call these directly - use the macros below */
int virClose(int *fdptr, bool preserve_errno) ATTRIBUTE_RETURN_CHECK;
int virFclose(FILE **file, bool preserve_errno) ATTRIBUTE_RETURN_CHECK;
FILE *virFdopen(int *fdptr, const char *mode) ATTRIBUTE_RETURN_CHECK;

/* For use on normal paths; caller must check return value,
   and failure sets errno per close. */
# define VIR_CLOSE(FD) virClose(&(FD), false)
# define VIR_FCLOSE(FILE) virFclose(&(FILE), false)

/* Wrapper around fdopen that consumes fd on success. */
# define VIR_FDOPEN(FD, MODE) virFdopen(&(FD), MODE)

/* For use on cleanup paths; errno is unaffected by close,
   and no return value to worry about. */
# define VIR_FORCE_CLOSE(FD) ignore_value(virClose(&(FD), true))
# define VIR_FORCE_FCLOSE(FILE) ignore_value(virFclose(&(FILE), true))

#endif /* __VIR_FILES_H */
