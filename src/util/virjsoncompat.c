/*
 * virjsoncompat.c: JSON object parsing/formatting
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include <config.h>

#include "virthread.h"
#include "virerror.h"
#define VIR_JSON_COMPAT_IMPL
#include "virjsoncompat.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#if WITH_JANSSON

# include <dlfcn.h>

json_t *(*json_array_ptr)(void);
int (*json_array_append_new_ptr)(json_t *array, json_t *value);
json_t *(*json_array_get_ptr)(const json_t *array, size_t index);
size_t (*json_array_size_ptr)(const json_t *array);
void (*json_delete_ptr)(json_t *json);
char *(*json_dumps_ptr)(const json_t *json, size_t flags);
json_t *(*json_false_ptr)(void);
json_t *(*json_integer_ptr)(json_int_t value);
json_int_t (*json_integer_value_ptr)(const json_t *integer);
json_t *(*json_loads_ptr)(const char *input, size_t flags, json_error_t *error);
json_t *(*json_null_ptr)(void);
json_t *(*json_object_ptr)(void);
void *(*json_object_iter_ptr)(json_t *object);
const char *(*json_object_iter_key_ptr)(void *iter);
void *(*json_object_iter_next_ptr)(json_t *object, void *iter);
json_t *(*json_object_iter_value_ptr)(void *iter);
void *(*json_object_key_to_iter_ptr)(const char *key);
int (*json_object_set_new_ptr)(json_t *object, const char *key, json_t *value);
json_t *(*json_real_ptr)(double value);
double (*json_real_value_ptr)(const json_t *real);
json_t *(*json_string_ptr)(const char *value);
const char *(*json_string_value_ptr)(const json_t *string);
json_t *(*json_true_ptr)(void);


static int
virJSONJanssonOnceInit(void)
{
    void *handle = dlopen("libjansson.so.4", RTLD_LAZY|RTLD_LOCAL|RTLD_NODELETE);
    if (!handle) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("libjansson.so.4 JSON library not available: %s"), dlerror());
        return -1;
    }

# define LOAD(name) \
    do { \
        if (!(name ## _ptr = dlsym(handle, #name))) { \
            virReportError(VIR_ERR_NO_SUPPORT, \
                           _("missing symbol '%s' in libjansson.so.4: %s"), #name, dlerror()); \
            return -1; \
        } \
    } while (0)

    LOAD(json_array);
    LOAD(json_array_append_new);
    LOAD(json_array_get);
    LOAD(json_array_size);
    LOAD(json_delete);
    LOAD(json_dumps);
    LOAD(json_false);
    LOAD(json_integer);
    LOAD(json_integer_value);
    LOAD(json_loads);
    LOAD(json_null);
    LOAD(json_object);
    LOAD(json_object_iter);
    LOAD(json_object_iter_key);
    LOAD(json_object_iter_next);
    LOAD(json_object_iter_value);
    LOAD(json_object_key_to_iter);
    LOAD(json_object_set_new);
    LOAD(json_real);
    LOAD(json_real_value);
    LOAD(json_string);
    LOAD(json_string_value);
    LOAD(json_true);

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virJSONJansson);

int
virJSONInitialize(void)
{
    return virJSONJanssonInitialize();
}

json_t *
json_array_impl(void)
{
    return json_array_ptr();
}


int
json_array_append_new_impl(json_t *array, json_t *value)
{
    return json_array_append_new_ptr(array, value);
}


json_t *
json_array_get_impl(const json_t *array, size_t index)
{
    return json_array_get_ptr(array, index);
}


size_t
json_array_size_impl(const json_t *array)
{
    return json_array_size_ptr(array);
}


void
json_delete_impl(json_t *json)
{
    return json_delete_ptr(json);
}


char *
json_dumps_impl(const json_t *json, size_t flags)
{
    return json_dumps_ptr(json, flags);
}


json_t *
json_false_impl(void)
{
    return json_false_ptr();
}


json_t *
json_integer_impl(json_int_t value)
{
    return json_integer_ptr(value);
}


json_int_t
json_integer_value_impl(const json_t *integer)
{
    return json_integer_value_ptr(integer);
}


json_t *
json_loads_impl(const char *input, size_t flags, json_error_t *error)
{
    return json_loads_ptr(input, flags, error);
}


json_t *
json_null_impl(void)
{
    return json_null_ptr();
}


json_t *
json_object_impl(void)
{
    return json_object_ptr();
}


void *
json_object_iter_impl(json_t *object)
{
    return json_object_iter_ptr(object);
}


const char *
json_object_iter_key_impl(void *iter)
{
    return json_object_iter_key_ptr(iter);
}


void *
json_object_iter_next_impl(json_t *object, void *iter)
{
    return json_object_iter_next_ptr(object, iter);
}


json_t *
json_object_iter_value_impl(void *iter)
{
    return json_object_iter_value_ptr(iter);
}


void *
json_object_key_to_iter_impl(const char *key)
{
    return json_object_key_to_iter_ptr(key);
}


int
json_object_set_new_impl(json_t *object, const char *key, json_t *value)
{
    return json_object_set_new_ptr(object, key, value);
}


json_t *
json_real_impl(double value)
{
    return json_real_ptr(value);
}


double
json_real_value_impl(const json_t *real)
{
    return json_real_value_ptr(real);
}


json_t *
json_string_impl(const char *value)
{
    return json_string_ptr(value);
}


const char *
json_string_value_impl(const json_t *string)
{
    return json_string_value_ptr(string);
}


json_t *
json_true_impl(void)
{
    return json_true_ptr();
}


#else /* !WITH_JANSSON */


int
virJSONInitialize(void)
{
    return 0;
}


#endif /* !WITH_JANSSON */
