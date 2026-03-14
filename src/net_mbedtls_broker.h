#ifndef NET_MBEDTLS_BROKER_H
#define NET_MBEDTLS_BROKER_H
#include "config.h"

#ifdef WITH_TLS_MBEDTLS
#include <stdbool.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>

struct mosquitto__listener;
struct mosquitto;

struct mosq_broker_tls {
mbedtls_ssl_config           conf;
mbedtls_x509_crt             srvcert;
mbedtls_pk_context           pkey;
mbedtls_x509_crt             ca_chain;
mbedtls_x509_crl             ca_crl;
mbedtls_entropy_context      entropy;
mbedtls_ctr_drbg_context     ctr_drbg;
bool                         require_cert;
};

int  net__broker_tls_server_ctx(struct mosquitto__listener *listener);
int  net__broker_tls_load_verify(struct mosquitto__listener *listener);
int  net__broker_tls_load_certificates(struct mosquitto__listener *listener);
int  net__broker_tls_accept(struct mosquitto *context);
void net__broker_tls_cleanup(struct mosquitto__listener *listener);

#define LISTENER_HAS_TLS(l) ((l)->tls_cfg != NULL)
#define CONTEXT_HAS_TLS(c)  ((c)->mbedtls != NULL)

#elif defined(WITH_TLS_OPENSSL)

#define LISTENER_HAS_TLS(l) ((l)->ssl_ctx != NULL)
#define CONTEXT_HAS_TLS(c)  ((c)->ssl != NULL)

#else

#define LISTENER_HAS_TLS(l) (0)
#define CONTEXT_HAS_TLS(c)  (0)

#endif /* WITH_TLS_MBEDTLS */

#endif /* NET_MBEDTLS_BROKER_H */
