/** @file vbox_V4_2_20.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    4002020
/** Version specific prefix. */
#define NAME(name)  vbox42_20##name

#include "vbox_tmpl.c"
