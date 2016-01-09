/*
 * virxdrdefs.h
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#ifndef __VIR_XDRDEFS_H__
# define __VIR_XDRDEFS_H__

/* cygwin's xdr implementation defines xdr_u_int64_t instead of xdr_uint64_t
 * and lacks IXDR_PUT_INT32 and IXDR_GET_INT32
 */
# ifdef HAVE_XDR_U_INT64_T
#  define xdr_uint64_t xdr_u_int64_t
# endif
# ifndef IXDR_PUT_INT32
#  define IXDR_PUT_INT32 IXDR_PUT_LONG
# endif
# ifndef IXDR_GET_INT32
#  define IXDR_GET_INT32 IXDR_GET_LONG
# endif
# ifndef IXDR_PUT_U_INT32
#  define IXDR_PUT_U_INT32 IXDR_PUT_U_LONG
# endif
# ifndef IXDR_GET_U_INT32
#  define IXDR_GET_U_INT32 IXDR_GET_U_LONG
# endif

#endif /* __VIR_XDRDEFS_H__ */
