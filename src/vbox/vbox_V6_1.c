/** @file vbox_V6_1.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION 6001000
/** Version specific prefix. */
#define NAME(name) vbox61##name

#include "vbox_tmpl.c"
