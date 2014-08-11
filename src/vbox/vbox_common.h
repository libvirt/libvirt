/*
 * Copyright 2014, Taowei Luo (uaedante@gmail.com)
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

#ifndef VBOX_COMMON_H
# define VBOX_COMMON_H

# ifdef ___VirtualBox_CXPCOM_h
#  error this file should not be included after vbox_CAPI_v*.h
# endif

# include "internal.h"
# include <stddef.h>
# include "wchar.h"

/* This file extracts some symbols defined in
 * vbox_CAPI_v*.h. It tells the vbox_common.c
 * how to treat with this symbols. This file
 * can't be included with files such as
 * vbox_CAPI_v*.h, or it would casue multiple
 * definitions.
 *
 * You can see the more informations in vbox_api.h
 */

/* Copied definitions from vbox_CAPI_*.h.
 * We must MAKE SURE these codes are compatible. */

typedef unsigned char PRUint8;
# if (defined(HPUX) && defined(__cplusplus) \
     && !defined(__GNUC__) && __cplusplus < 199707L) \
    || (defined(SCO) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus == 1L)
typedef char PRInt8;
# else
typedef signed char PRInt8;
# endif

# define PR_INT8_MAX 127
# define PR_INT8_MIN (-128)
# define PR_UINT8_MAX 255U

typedef unsigned short PRUint16;
typedef short PRInt16;

# define PR_INT16_MAX 32767
# define PR_INT16_MIN (-32768)
# define PR_UINT16_MAX 65535U

typedef unsigned int PRUint32;
typedef int PRInt32;
# define PR_INT32(x)  x
# define PR_UINT32(x) x ## U

# define PR_INT32_MAX PR_INT32(2147483647)
# define PR_INT32_MIN (-PR_INT32_MAX - 1)
# define PR_UINT32_MAX PR_UINT32(4294967295)

typedef long PRInt64;
typedef unsigned long PRUint64;
typedef int PRIntn;
typedef unsigned int PRUintn;

typedef double          PRFloat64;
typedef size_t PRSize;

typedef ptrdiff_t PRPtrdiff;

typedef unsigned long PRUptrdiff;

typedef PRIntn PRBool;

# define PR_TRUE 1
# define PR_FALSE 0

typedef PRUint8 PRPackedBool;

/*
** Status code used by some routines that have a single point of failure or
** special status return.
*/
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;

# ifndef __PRUNICHAR__
#  define __PRUNICHAR__
#  if defined(WIN32) || defined(XP_MAC)
typedef wchar_t PRUnichar;
#  else
typedef PRUint16 PRUnichar;
#  endif
# endif

typedef long PRWord;
typedef unsigned long PRUword;

# define nsnull 0
typedef PRUint32 nsresult;

# if defined(__GNUC__) && (__GNUC__ > 2)
#  define NS_LIKELY(x)    (__builtin_expect((x), 1))
#  define NS_UNLIKELY(x)  (__builtin_expect((x), 0))
# else
#  define NS_LIKELY(x)    (x)
#  define NS_UNLIKELY(x)  (x)
# endif

# define NS_FAILED(_nsresult) (NS_UNLIKELY((_nsresult) & 0x80000000))
# define NS_SUCCEEDED(_nsresult) (NS_LIKELY(!((_nsresult) & 0x80000000)))

/**
 * An "interface id" which can be used to uniquely identify a given
 * interface.
 * A "unique identifier". This is modeled after OSF DCE UUIDs.
 */

struct nsID {
  PRUint32 m0;
  PRUint16 m1;
  PRUint16 m2;
  PRUint8 m3[8];
};

typedef struct nsID nsID;
typedef nsID nsIID;

typedef struct _vboxArray vboxArray;

# ifdef WIN32

struct _vboxArray {
    void **items;
    size_t count;
    void *handle;
};
#  define VBOX_ARRAY_INITIALIZER { NULL, 0, NULL }

# else /* !WIN32 */

struct _vboxArray {
    void **items;
    size_t count;
};
#  define VBOX_ARRAY_INITIALIZER { NULL, 0 }

# endif /* !WIN32 */

/* Simplied definitions in vbox_CAPI_*.h */

typedef void const *PCVBOXXPCOM;
typedef struct nsISupports nsISupports;
typedef nsISupports IVirtualBox;
typedef nsISupports ISession;
typedef nsISupports IConsole;
typedef nsISupports IProgress;
typedef nsISupports IMachine;

#endif /* VBOX_COMMON_H */
