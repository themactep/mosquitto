/*
 * Mosquitto broker - mbedTLS TLS support
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include "config.h"

#ifdef WITH_TLS_MBEDTLS

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#  include <sys/socket.h>
#endif

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "logging_mosq.h"
#include "net_mbedtls_broker.h"
#include "tls_mbedtls.h"

static int broker_tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
struct mosquitto *mosq = ctx;
int rc;

errno = 0;
rc = (int)send(mosq->sock, (const char *)buf, (int)len, MSG_NOSIGNAL);
if(rc < 0){
if(errno == EWOULDBLOCK || errno == EAGAIN) return MBEDTLS_ERR_SSL_WANT_WRITE;
return MBEDTLS_ERR_NET_SEND_FAILED;
}
return rc;
}

static int broker_tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
struct mosquitto *mosq = ctx;
int rc;

errno = 0;
rc = (int)recv(mosq->sock, (char *)buf, (int)len, 0);
if(rc < 0){
if(errno == EWOULDBLOCK || errno == EAGAIN) return MBEDTLS_ERR_SSL_WANT_READ;
return MBEDTLS_ERR_NET_RECV_FAILED;
}
if(rc == 0) return MBEDTLS_ERR_NET_CONN_RESET;
return rc;
}

int net__broker_tls_server_ctx(struct mosquitto__listener *listener)
{
struct mosq_broker_tls *btls;
static const unsigned char pers[] = "thingino-mosquitto-broker";
int rc;

btls = mosquitto__calloc(1, sizeof(struct mosq_broker_tls));
if(!btls){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory setting up TLS.");
return 1;
}

mbedtls_ssl_config_init(&btls->conf);
mbedtls_x509_crt_init(&btls->srvcert);
mbedtls_pk_init(&btls->pkey);
mbedtls_x509_crt_init(&btls->ca_chain);
mbedtls_x509_crl_init(&btls->ca_crl);
mbedtls_entropy_init(&btls->entropy);
mbedtls_ctr_drbg_init(&btls->ctr_drbg);

rc = mbedtls_ctr_drbg_seed(&btls->ctr_drbg, mbedtls_entropy_func,
&btls->entropy, pers, sizeof(pers)-1);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: mbedtls_ctr_drbg_seed failed: -0x%04x", -rc);
net__broker_tls_cleanup(listener);
mosquitto__free(btls);
return 1;
}

rc = mbedtls_ssl_config_defaults(&btls->conf,
MBEDTLS_SSL_IS_SERVER,
MBEDTLS_SSL_TRANSPORT_STREAM,
MBEDTLS_SSL_PRESET_DEFAULT);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: mbedtls_ssl_config_defaults failed: -0x%04x", -rc);
net__broker_tls_cleanup(listener);
mosquitto__free(btls);
return 1;
}

/* Set TLS version constraints */
if(listener->tls_version){
if(!strcmp(listener->tls_version, "tlsv1.3")){
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
mbedtls_ssl_conf_min_tls_version(&btls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
mbedtls_ssl_conf_max_tls_version(&btls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
mbedtls_ssl_conf_min_version(&btls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
mbedtls_ssl_conf_max_version(&btls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
#endif
}else{
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
mbedtls_ssl_conf_min_tls_version(&btls->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
mbedtls_ssl_conf_min_version(&btls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif
}
}else{
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
mbedtls_ssl_conf_min_tls_version(&btls->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
mbedtls_ssl_conf_min_version(&btls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif
}

btls->require_cert = listener->require_certificate;
if(listener->require_certificate){
mbedtls_ssl_conf_authmode(&btls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}else{
mbedtls_ssl_conf_authmode(&btls->conf, MBEDTLS_SSL_VERIFY_NONE);
}

mbedtls_ssl_conf_rng(&btls->conf, mbedtls_ctr_drbg_random, &btls->ctr_drbg);

log__printf(NULL, MOSQ_LOG_INFO, "Using mbedTLS for TLS support.");

listener->tls_cfg = btls;
return 0;
}

int net__broker_tls_load_certificates(struct mosquitto__listener *listener)
{
struct mosq_broker_tls *btls = listener->tls_cfg;
int rc;

if(!btls) return 1;

rc = mbedtls_x509_crt_parse_file(&btls->srvcert, listener->certfile);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server certificate '%s': -0x%04x",
listener->certfile, -rc);
return 1;
}

rc = mbedtls_pk_parse_keyfile(&btls->pkey, listener->keyfile,
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
NULL, mbedtls_ctr_drbg_random, &btls->ctr_drbg
#else
NULL
#endif
);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server private key '%s': -0x%04x",
listener->keyfile, -rc);
return 1;
}

rc = mbedtls_ssl_conf_own_cert(&btls->conf, &btls->srvcert, &btls->pkey);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: mbedtls_ssl_conf_own_cert failed: -0x%04x", -rc);
return 1;
}

return 0;
}

int net__broker_tls_load_verify(struct mosquitto__listener *listener)
{
struct mosq_broker_tls *btls = listener->tls_cfg;
mbedtls_x509_crl *crl_ptr = NULL;
int rc;

if(!btls) return 1;

if(listener->cafile){
rc = mbedtls_x509_crt_parse_file(&btls->ca_chain, listener->cafile);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificate '%s': -0x%04x",
listener->cafile, -rc);
return 1;
}
}

if(listener->crlfile){
rc = mbedtls_x509_crl_parse_file(&btls->ca_crl, listener->crlfile);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CRL file '%s': -0x%04x",
listener->crlfile, -rc);
return 1;
}
crl_ptr = &btls->ca_crl;
}

if(listener->cafile){
mbedtls_ssl_conf_ca_chain(&btls->conf, &btls->ca_chain, crl_ptr);
if(listener->require_certificate){
mbedtls_ssl_conf_authmode(&btls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}else{
mbedtls_ssl_conf_authmode(&btls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
}
}

return net__broker_tls_load_certificates(listener);
}

int net__broker_tls_accept(struct mosquitto *context)
{
struct mosq_broker_tls *btls = context->listener->tls_cfg;
int rc;

context->mbedtls = mosquitto__calloc(1, sizeof(struct mosq_mbedtls));
if(!context->mbedtls){
log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory in TLS accept.");
return 1;
}

mbedtls_ssl_init(&context->mbedtls->ssl);

rc = mbedtls_ssl_setup(&context->mbedtls->ssl, &btls->conf);
if(rc != 0){
log__printf(NULL, MOSQ_LOG_ERR, "Error: mbedtls_ssl_setup failed: -0x%04x", -rc);
mosquitto__free(context->mbedtls);
context->mbedtls = NULL;
return 1;
}

mbedtls_ssl_set_bio(&context->mbedtls->ssl, context,
broker_tls_bio_send, broker_tls_bio_recv, NULL);

rc = mbedtls_ssl_handshake(&context->mbedtls->ssl);
if(rc != 0){
if(rc == MBEDTLS_ERR_SSL_WANT_READ){
/* Normal - will retry on next read */
}else if(rc == MBEDTLS_ERR_SSL_WANT_WRITE){
context->want_write = true;
}else{
char errbuf[256];
mbedtls_strerror(rc, errbuf, sizeof(errbuf));
if(db.config->connection_messages == true){
log__printf(NULL, MOSQ_LOG_NOTICE,
"Client connection from %s failed TLS handshake: %s.",
context->address, errbuf);
}
mbedtls_ssl_free(&context->mbedtls->ssl);
mosquitto__free(context->mbedtls);
context->mbedtls = NULL;
return 1;
}
}

context->want_write = true;
return 0;
}

void net__broker_tls_cleanup(struct mosquitto__listener *listener)
{
struct mosq_broker_tls *btls = listener->tls_cfg;

if(!btls) return;

mbedtls_ssl_config_free(&btls->conf);
mbedtls_x509_crt_free(&btls->srvcert);
mbedtls_pk_free(&btls->pkey);
mbedtls_x509_crt_free(&btls->ca_chain);
mbedtls_x509_crl_free(&btls->ca_crl);
mbedtls_entropy_free(&btls->entropy);
mbedtls_ctr_drbg_free(&btls->ctr_drbg);

mosquitto__free(btls);
listener->tls_cfg = NULL;
}

#endif /* WITH_TLS_MBEDTLS */
