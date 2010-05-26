/** @file vbox_V3_2.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    3002
/** Version specific prefix. */
#define NAME(name)  vbox32##name

#include "vbox_tmpl.c"
