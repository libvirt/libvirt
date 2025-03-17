=====================
Adoption of GLib APIs
=====================

Libvirt has adopted use of the `GLib
library <https://developer.gnome.org/glib/stable/>`__. Due to
libvirt's long history of development, there are many APIs in
libvirt, for which GLib provides an alternative solution. The
general rule to follow is that the standard GLib solution will be
preferred over historical libvirt APIs. Existing code will be
ported over to use GLib APIs over time, but new code should use
the GLib APIs straight away where possible.

The following is a list of libvirt APIs that should no longer be
used in new code, and their suggested GLib replacements:

Array operations
   ``VIR_APPEND_ELEMENT``, ``VIR_INSERT_ELEMENT``, ``VIR_DELETE_ELEMENT``

   https://developer.gnome.org/glib/stable/glib-Arrays.html

   Instead of using plain C arrays, it is preferable to use one of
   the GLib types, ``GArray``, ``GPtrArray`` or ``GByteArray``.
   These all use a struct to track the array memory and size
   together and efficiently resize.

Objects
   ``virObject``

   https://developer.gnome.org/gobject/stable/gobject-The-Base-Object-Type.html

   Prefer ``GObject`` instead.
