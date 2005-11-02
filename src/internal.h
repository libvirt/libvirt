/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __XEN_INTERNAL_H__
#define __XEN_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((unused))
#endif
#else
#define ATTRIBUTE_UNUSED
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XEN_INTERNAL_H__ */
