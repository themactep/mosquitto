/*
 * Compatibility shim: map mosquitto__ (2.0.x) names to mosquitto_ (2.1.x) names.
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#ifndef MEMORY_MOSQ_H
#define MEMORY_MOSQ_H

#include "mosquitto/libcommon_memory.h"

#define mosquitto__calloc  mosquitto_calloc
#define mosquitto__malloc  mosquitto_malloc
#define mosquitto__realloc mosquitto_realloc
#define mosquitto__free    mosquitto_free
#define mosquitto__strdup  mosquitto_strdup

#endif /* MEMORY_MOSQ_H */
