/** @file vbox_V4_0.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    4001
/** Version specific prefix. */
#define NAME(name)  vbox41##name

#include "vbox_tmpl.c"
