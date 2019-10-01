/*
 * virautoclean.h: automatic scope-based memory clearing helper macros for
 *                 use in header files
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

/**
 * DEPRECATION WARNING
 *
 * The macros in this file should not be used in newly written code.
 * Use the equivalent GLib macros instead.
 *
 * For existing code, use of the libvirt and GLib macros must NEVER
 * be mixed within a single method.
 *
 * The use of the libvirt VIR_FREE macros should also not be mixed
 * with GLib auto-free macros and vice-verca.
 *
 * Existing code should be converted to the new GLib macros and
 * g_free APIs as needed.
 */

/**
 * VIR_DEFINE_AUTOPTR_FUNC:
 * @type: type of the variable to be freed automatically
 * @func: cleanup function to be automatically called
 *
 * This macro defines a function for automatic freeing of
 * resources allocated to a variable of type @type. This newly
 * defined function works as a necessary wrapper around @func.
 */
#define VIR_DEFINE_AUTOPTR_FUNC(t, f) \
    G_DEFINE_AUTOPTR_CLEANUP_FUNC(t, f)

/**
 * VIR_DEFINE_AUTOCLEAN_FUNC:
 * @type: type of the variable to be cleared automatically
 * @func: cleanup function to be automatically called
 *
 * This macro defines a function for automatic clearing of
 * resources in a stack'd variable of type @type. Note that @func must
 * take pointer to @type.
 */
#define VIR_DEFINE_AUTOCLEAN_FUNC(type, func) \
    G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(type, func)

/**
 * VIR_AUTOPTR:
 * @type: type of the variable to be freed automatically
 *
 * Macro to automatically free the memory allocated to
 * the variable declared with it by calling the function
 * defined by VIR_DEFINE_AUTOPTR_FUNC when the variable
 * goes out of scope.
 *
 * Note that this macro must NOT be used with vectors! The freeing function
 * will not free any elements beyond the first.
 */
#define VIR_AUTOPTR(type) g_autoptr(type)

/**
 * VIR_AUTOCLEAN:
 * @type: type of the variable to be cleared automatically
 *
 * Macro to automatically call clearing function registered for variable of @type
 * when the variable goes out of scope.
 * The cleanup function is registered by VIR_DEFINE_AUTOCLEAN_FUNC macro for
 * the given type.
 *
 * Note that this macro must NOT be used with vectors! The cleaning function
 * will not clean any elements beyond the first.
 */
#define VIR_AUTOCLEAN(type) g_auto(type)
