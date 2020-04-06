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

``VIR_ALLOC``, ``VIR_REALLOC``, ``VIR_RESIZE_N``, ``VIR_EXPAND_N``, ``VIR_SHRINK_N``, ``VIR_FREE``, ``VIR_APPEND_ELEMENT``, ``VIR_INSERT_ELEMENT``, ``VIR_DELETE_ELEMENT``
   Prefer the GLib APIs ``g_new0``/``g_renew``/ ``g_free`` in most
   cases. There should rarely be a need to use
   ``g_malloc``/``g_realloc``. Instead of using plain C arrays, it
   is preferrable to use one of the GLib types, ``GArray``,
   ``GPtrArray`` or ``GByteArray``. These all use a struct to
   track the array memory and size together and efficiently
   resize. **NEVER MIX** use of the classic libvirt memory
   allocation APIs and GLib APIs within a single method. Keep the
   style consistent, converting existing code to GLib style in a
   separate, prior commit.
``virStrerror``
   The GLib ``g_strerror()`` function should be used instead,
   which has a simpler calling convention as an added benefit.

The following libvirt APIs have been deleted already:

``VIR_AUTOPTR``, ``VIR_AUTOCLEAN``, ``VIR_AUTOFREE``
   The GLib macros ``g_autoptr``, ``g_auto`` and ``g_autofree``
   must be used instead in all new code. In existing code, the
   GLib macros must never be mixed with libvirt macros within a
   method, nor should they be mixed with ``VIR_FREE``. If
   introducing GLib macros to an existing method, any use of
   libvirt macros must be converted in an independent commit.
``VIR_DEFINE_AUTOPTR_FUNC``, ``VIR_DEFINE_AUTOCLEAN_FUNC``
   The GLib macros ``G_DEFINE_AUTOPTR_CLEANUP_FUNC`` and
   ``G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC`` must be used in all new
   code. Existing code should be converted to the new macros where
   relevant. It is permissible to use ``g_autoptr``, ``g_auto`` on
   an object whose cleanup function is declared with the libvirt
   macros and vice-versa.
``VIR_AUTOUNREF``
   The GLib macros ``g_autoptr`` and
   ``G_DEFINE_AUTOPTR_CLEANUP_FUNC`` should be used to manage
   autoclean of virObject classes. This matches usage with GObject
   classes.
``VIR_STRDUP``, ``VIR_STRNDUP``
   Prefer the GLib APIs ``g_strdup`` and ``g_strndup``.

+-------------------------------+--------------------------------------+-------------------------------------------+
| deleted version               | GLib version                         | Notes                                     |
+===============================+======================================+===========================================+
| ``VIR_AUTOPTR``               | ``g_autoptr``                        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOCLEAN``             | ``g_auto``                           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOFREE``              | ``g_autofree``                       | The GLib version does not use parentheses |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOUNREF``             | ``g_autoptr``                        | The cleanup function needs to be defined  |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_DEFINE_AUTOPTR_FUNC``   | ``G_DEFINE_AUTOPTR_CLEANUP_FUNC``    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_DEFINE_AUTOCLEAN_FUNC`` | ``G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC`` |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STEAL_PTR``             | ``g_steal_pointer``                  | ``a = f(&b)`` instead of ``f(a, b)``      |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_RETURN_PTR``            | ``return g_steal_pointer``           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ARRAY_CARDINALITY``         | ``G_N_ELEMENTS``                     |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_FALLTHROUGH``     | ``G_GNUC_FALLTHROUGH``               |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_FMT_PRINTF``      | ``G_GNUC_PRINTF``                    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_NOINLINE``        | ``G_GNUC_NO_INLINE``                 |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_NORETURN``        | ``G_GNUC_NORETURN``                  |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_RETURN_CHECK``    | ``G_GNUC_WARN_UNUSED_RESULT``        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_SENTINEL``        | ``G_GNUC_NULL_TERMINATED``           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_UNUSED``          | ``G_GNUC_UNUSED``                    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STRDUP``                | ``g_strdup``                         |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STRNDUP``               | ``g_strndup``                        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``virStrerror``               | ``g_strerror``                       |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
