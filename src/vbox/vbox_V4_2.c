/** @file vbox_V4_2.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
 */

#include <config.h>

/** The API Version */
#define VBOX_API_VERSION    4002000
/** Version specific prefix. */
#define NAME(name)  vbox42##name

#include "vbox_tmpl.c"
