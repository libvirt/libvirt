/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __XEN_INTERNAL_H__
#define __XEN_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
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

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    fprintf(stderr, "Unimplemented block at %s:%d\n",			\
            __FILE__, __LINE__);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XEN_INTERNAL_H__ */
