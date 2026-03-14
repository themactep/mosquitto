/*
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#ifndef TLS_MBEDTLS_H
#define TLS_MBEDTLS_H

#include "config.h"

#ifdef WITH_TLS_MBEDTLS

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

struct mosquitto;

struct mosq_mbedtls {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca_chain;
	mbedtls_x509_crt client_cert;
	mbedtls_pk_context client_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	bool configured;
	bool has_client_cert;
};

int mosquitto__mbedtls_init(struct mosquitto *mosq);
void mosquitto__mbedtls_cleanup(struct mosquitto *mosq);
int mosquitto__mbedtls_connect(struct mosquitto *mosq, const char *host);
ssize_t mosquitto__mbedtls_read(struct mosquitto *mosq, void *buf, size_t count);
ssize_t mosquitto__mbedtls_write(struct mosquitto *mosq, const void *buf, size_t count);

#endif

#endif
