/*
 * plugin.c: Wireshark's plugin registration
 *
 * The registration routines were generated using wireshark's
 * make-dissector-reg script (found under wirshark.git/tools/):
 *
 * libvirt.git/tools/wireshark/src $ \
 *   /path/to/wireshark.git/tools/make-dissector-reg \
 *   . plugin packet-libvirt.c
 *
 */

#include <config.h>

#include <gmodule.h>

/* plugins are DLLs */
#define WS_BUILD_DLL
#include <wireshark/ws_symbol_export.h>

#include "packet-libvirt.h"

/* In 1.12 wireshark WS_DLL_PUBLIC_NOEXTERN was substitued with
 * WS_DLL_PUBLIC_DEF. See wireshark's commit
 * 5d87a8c46171f572568db5a47c093423482e342f for more info. */
#ifndef WS_DLL_PUBLIC_NOEXTERN
# define WS_DLL_PUBLIC_NOEXTERN WS_DLL_PUBLIC_DEF
#endif

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_NOEXTERN const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_NOEXTERN void
plugin_register(void)
{
  proto_register_libvirt();
}
WS_DLL_PUBLIC_NOEXTERN void
plugin_reg_handoff(void)
{
  proto_reg_handoff_libvirt();
}
#endif
