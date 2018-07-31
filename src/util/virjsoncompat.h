/*
 * virjsoncompat.h: JSON object parsing/formatting
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


#ifndef __VIR_JSON_COMPAT_H_
# define __VIR_JSON_COMPAT_H_

# if WITH_JANSSON
#  ifndef VIR_JSON_COMPAT_IMPL

#   define json_array json_array_impl
#   define json_array_append_new json_array_append_new_impl
#   define json_array_get json_array_get_impl
#   define json_array_size json_array_size_impl
#   define json_delete json_delete_impl
#   define json_dumps json_dumps_impl
#   define json_false json_false_impl
#   define json_integer json_integer_impl
#   define json_integer_value json_integer_value_impl
#   define json_loads json_loads_impl
#   define json_null json_null_impl
#   define json_object json_object_impl
#   define json_object_iter json_object_iter_impl
#   define json_object_iter_key json_object_iter_key_impl
#   define json_object_iter_next json_object_iter_next_impl
#   define json_object_iter_value json_object_iter_value_impl
#   define json_object_key_to_iter json_object_key_to_iter_impl
#   define json_object_set_new json_object_set_new_impl
#   define json_real json_real_impl
#   define json_real_value json_real_value_impl
#   define json_string json_string_impl
#   define json_string_value json_string_value_impl
#   define json_true json_true_impl

#  endif /* ! VIR_JSON_COMPAT_IMPL */

#  include <jansson.h>

#  ifdef VIR_JSON_COMPAT_IMPL

json_t *json_array_impl(void);
int json_array_append_new_impl(json_t *array, json_t *value);
json_t *json_array_get_impl(const json_t *array, size_t index);
size_t json_array_size_impl(const json_t *array);
void json_delete_impl(json_t *json);
char *json_dumps_impl(const json_t *json, size_t flags);
json_t *json_false_impl(void);
json_t *json_integer_impl(json_int_t value);
json_int_t json_integer_value_impl(const json_t *integer);
json_t *json_loads_impl(const char *input, size_t flags, json_error_t *error);
json_t *json_null_impl(void);
json_t *json_object_impl(void);
void *json_object_iter_impl(json_t *object);
const char *json_object_iter_key_impl(void *iter);
void *json_object_iter_next_impl(json_t *object, void *iter);
json_t *json_object_iter_value_impl(void *iter);
void *json_object_key_to_iter_impl(const char *key);
int json_object_set_new_impl(json_t *object, const char *key, json_t *value);
json_t *json_real_impl(double value);
double json_real_value_impl(const json_t *real);
json_t *json_string_impl(const char *value);
const char *json_string_value_impl(const json_t *string);
json_t *json_true_impl(void);

#  endif /* VIR_JSON_COMPAT_IMPL */
# endif /* WITH_JANSSON */

int virJSONInitialize(void);

#endif /* __VIR_JSON_COMPAT_H_ */
