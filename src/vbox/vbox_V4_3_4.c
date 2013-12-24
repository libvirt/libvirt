/** @file vbox_V4_3_4.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    4003004
/** Version specific prefix. */
#define NAME(name)  vbox43_4##name

#include "vbox_tmpl.c"
