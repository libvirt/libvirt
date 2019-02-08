/*
 * plugin.c: Wireshark's plugin registration
 *
 * The registration routines were generated using wireshark's
 * make-plugin-reg.py script (found under wirshark.git/tools/):
 *
 * libvirt.git/tools/wireshark/src $ \
 *   /path/to/wireshark.git/tools/make-plugin-reg.py \
 *   . plugin packet-libvirt.c
 *
 */

#include <config.h>

#include <gmodule.h>

#include <wireshark/config.h>
#include <wireshark/epan/proto.h>
/* plugins are DLLs */
#define WS_BUILD_DLL
#include <wireshark/ws_symbol_export.h>

#include "packet-libvirt.h"

/* Let the plugin version be the version of libvirt */
#define PLUGIN_VERSION VERSION

#define WIRESHARK_VERSION \
    ((VERSION_MAJOR * 1000 * 1000) + \
     (VERSION_MINOR * 1000) + \
     (VERSION_MICRO))

#if WIRESHARK_VERSION < 2005000

WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
  proto_register_libvirt();
}
WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
  proto_reg_handoff_libvirt();
}

#elif WIRESHARK_VERSION < 2009000

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION_RELEASE;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_libvirt;

    plug_libvirt.register_protoinfo = proto_register_libvirt;
    plug_libvirt.register_handoff = proto_reg_handoff_libvirt;
    proto_register_plugin(&plug_libvirt);
}

#else /* WIRESHARK_VERSION >= 2009000 */

void proto_register_libvirt(void);
void proto_reg_handoff_libvirt(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_libvirt;

    plug_libvirt.register_protoinfo = proto_register_libvirt;
    plug_libvirt.register_handoff = proto_reg_handoff_libvirt;
    proto_register_plugin(&plug_libvirt);
}

#endif
