/** @file vbox_V5_2.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION 5002000
/** Version specific prefix. */
#define NAME(name) vbox52##name

#include "vbox_tmpl.c"
