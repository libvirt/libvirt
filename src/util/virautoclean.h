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

#define VIR_AUTOPTR_FUNC_NAME(type) type##AutoPtrFree

/**
 * VIR_DEFINE_AUTOPTR_FUNC:
 * @type: type of the variable to be freed automatically
 * @func: cleanup function to be automatically called
 *
 * This macro defines a function for automatic freeing of
 * resources allocated to a variable of type @type. This newly
 * defined function works as a necessary wrapper around @func.
 */
#define VIR_DEFINE_AUTOPTR_FUNC(type, func) \
    static inline void VIR_AUTOPTR_FUNC_NAME(type)(type **_ptr) \
    { \
        if (*_ptr) \
            (func)(*_ptr); \
        *_ptr = NULL; \
    }

#define VIR_AUTOCLEAN_FUNC_NAME(type) type##AutoClean

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
    static inline void VIR_AUTOCLEAN_FUNC_NAME(type)(type *_ptr) \
    { \
        (func)(_ptr); \
    }

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
#define VIR_AUTOPTR(type) \
    __attribute__((cleanup(VIR_AUTOPTR_FUNC_NAME(type)))) type *

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
#define VIR_AUTOCLEAN(type) \
    __attribute__((cleanup(VIR_AUTOCLEAN_FUNC_NAME(type)))) type
