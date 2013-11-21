/** @file vbox_V4_3.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    4003
/** Version specific prefix. */
#define NAME(name)  vbox43##name

#include "vbox_tmpl.c"
