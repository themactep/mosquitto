
#ifdef WITH_TLS_MBEDTLS

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#endif

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/version.h>

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "tls_mbedtls.h"

static void mosquitto__mbedtls_log_error(struct mosquitto *mosq, int code);

static const char *const g_mosquitto_mbedtls_env_cafile_vars[] = {
	"SSL_CERT_FILE",
	"OPENSSL_CAFILE",
	"X509_CERT_FILE",
	NULL
};

static const char *const g_mosquitto_mbedtls_default_ca_files[] = {
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/pki/tls/cacert.pem",
	"/etc/ssl/ca-bundle.pem",
	"/etc/ssl/certs/ca-bundle.crt",
	"/usr/local/share/certs/ca-bundle.crt",
	NULL
};

#if defined(MBEDTLS_X509_CRT_PARSE_PATH)
static const char *const g_mosquitto_mbedtls_env_capath_vars[] = {
	"SSL_CERT_DIR",
	"X509_CERT_DIR",
	NULL
};

static const char *const g_mosquitto_mbedtls_default_ca_dirs[] = {
	"/etc/ssl/certs",
	"/usr/local/share/certs",
	"/usr/share/ca-certificates",
	"/etc/pki/tls/certs",
	"/etc/pki/ca-trust/extracted/pem",
	NULL
};
#endif

static const unsigned char g_mbedtls_personalization[] = "thingino-mosquitto";

static int mosquitto__mbedtls_try_load_ca_file(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *path)
{
	int ret;

	if(!path || !path[0]){
		return MBEDTLS_ERR_X509_FILE_IO_ERROR;
	}

	ret = mbedtls_x509_crt_parse_file(&tls->ca_chain, path);
	if(ret != 0 && ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		mosquitto__mbedtls_log_error(mosq, ret);
	}

	return ret;
}

static int mosquitto__mbedtls_try_load_cafile_list(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *const *files)
{
	int ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
	size_t i;

	if(!files){
		return ret;
	}

	for(i=0; files[i]; i++){
		ret = mosquitto__mbedtls_try_load_ca_file(tls, mosq, files[i]);
		if(ret == 0){
			return 0;
		}
		if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
			return ret;
		}
	}

	return ret;
}

static int mosquitto__mbedtls_try_env_cafile(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *const *env_vars)
{
	int ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
	size_t i;

	if(!env_vars){
		return ret;
	}

	for(i=0; env_vars[i]; i++){
		const char *value = getenv(env_vars[i]);
		if(!value || !value[0]){
			continue;
		}
		ret = mosquitto__mbedtls_try_load_ca_file(tls, mosq, value);
		if(ret == 0){
			return 0;
		}
		if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
			return ret;
		}
	}

	return ret;
}

#if defined(MBEDTLS_X509_CRT_PARSE_PATH)
static int mosquitto__mbedtls_try_load_ca_path(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *path)
{
	int ret;

	if(!path || !path[0]){
		return MBEDTLS_ERR_X509_FILE_IO_ERROR;
	}

	ret = mbedtls_x509_crt_parse_path(&tls->ca_chain, path);
	if(ret != 0 && ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		mosquitto__mbedtls_log_error(mosq, ret);
	}

	return ret;
}

static int mosquitto__mbedtls_try_load_capath_list(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *const *paths)
{
	int ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
	size_t i;

	if(!paths){
		return ret;
	}

	for(i=0; paths[i]; i++){
		ret = mosquitto__mbedtls_try_load_ca_path(tls, mosq, paths[i]);
		if(ret == 0){
			return 0;
		}
		if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
			return ret;
		}
	}

	return ret;
}

static int mosquitto__mbedtls_try_env_capath(struct mosq_mbedtls *tls, struct mosquitto *mosq, const char *const *env_vars)
{
	int ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
	size_t i;

	if(!env_vars){
		return ret;
	}

	for(i=0; env_vars[i]; i++){
		const char *value = getenv(env_vars[i]);
		if(!value || !value[0]){
			continue;
		}
		ret = mosquitto__mbedtls_try_load_ca_path(tls, mosq, value);
		if(ret == 0){
			return 0;
		}
		if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
			return ret;
		}
	}

	return ret;
}
#endif

static int mosquitto__mbedtls_load_os_certs(struct mosq_mbedtls *tls, struct mosquitto *mosq)
{
	int ret;

	ret = mosquitto__mbedtls_try_env_cafile(tls, mosq, g_mosquitto_mbedtls_env_cafile_vars);
	if(ret == 0){
		return 0;
	}
	if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		return ret;
	}

	ret = mosquitto__mbedtls_try_load_cafile_list(tls, mosq, g_mosquitto_mbedtls_default_ca_files);
	if(ret == 0){
		return 0;
	}
	if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		return ret;
	}

#if defined(MBEDTLS_X509_CRT_PARSE_PATH)
	ret = mosquitto__mbedtls_try_env_capath(tls, mosq, g_mosquitto_mbedtls_env_capath_vars);
	if(ret == 0){
		return 0;
	}
	if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		return ret;
	}

	ret = mosquitto__mbedtls_try_load_capath_list(tls, mosq, g_mosquitto_mbedtls_default_ca_dirs);
	if(ret == 0){
		return 0;
	}
	if(ret != MBEDTLS_ERR_X509_FILE_IO_ERROR){
		return ret;
	}
#endif

	log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates from the operating system certificate store.");
	return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

static int mosquitto__mbedtls_seed(struct mosq_mbedtls *tls)
{
	int ret;

	mbedtls_entropy_init(&tls->entropy);
	mbedtls_ctr_drbg_init(&tls->ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&tls->ctr_drbg, mbedtls_entropy_func, &tls->entropy,
			g_mbedtls_personalization,
			sizeof(g_mbedtls_personalization));
	return ret;
}

static int mosquitto__mbedtls_configure(struct mosquitto *mosq)
{
	int ret;
	struct mosq_mbedtls *tls = mosq->mbedtls;

	if(mosq->tls_engine || mosq->tls_engine_kpass_sha1 || mosq->tls_keyform == mosq_k_engine){
		log__printf(mosq, MOSQ_LOG_WARNING, "Warning: TLS engine options are not supported with the mbedTLS backend and will be ignored.");
	}
	if(mosq->tls_ciphers){
		log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Custom cipher lists are not yet supported with the mbedTLS backend.");
	}

	if(!tls->configured){
		mbedtls_ssl_init(&tls->ssl);
		mbedtls_ssl_config_init(&tls->conf);
		mbedtls_x509_crt_init(&tls->ca_chain);
		mbedtls_x509_crt_init(&tls->client_cert);
		mbedtls_pk_init(&tls->client_key);

		ret = mosquitto__mbedtls_seed(tls);
		if(ret != 0){
			return ret;
		}

		ret = mbedtls_ssl_config_defaults(&tls->conf, MBEDTLS_SSL_IS_CLIENT,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
		if(ret != 0){
			return ret;
		}

		mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg);
		mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->ca_chain, NULL);
		mbedtls_ssl_conf_read_timeout(&tls->conf, 0);

		if(mosq->tls_insecure || mosq->tls_cert_reqs == 0){
			mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		}else{
			mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		}

		if(mosq->tls_alpn){
			const char *alpn[2] = { mosq->tls_alpn, NULL };
			mbedtls_ssl_conf_alpn_protocols(&tls->conf, alpn);
		}

		if(mosq->tls_version){
			if(!strcmp(mosq->tls_version, "tlsv1.3")){
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
				mbedtls_ssl_conf_min_version(&tls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
				mbedtls_ssl_conf_max_version(&tls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
#else
				return MBEDTLS_ERR_SSL_BAD_CONFIG;
#endif
			}else if(!strcmp(mosq->tls_version, "tlsv1.2")){
				mbedtls_ssl_conf_min_version(&tls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
				mbedtls_ssl_conf_max_version(&tls->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
			}
		}

		tls->configured = true;
	}

	if(mosq->tls_cafile){
		ret = mbedtls_x509_crt_parse_file(&tls->ca_chain, mosq->tls_cafile);
		if(ret != 0){
			return ret;
		}
	}else if(mosq->tls_use_os_certs){
		ret = mosquitto__mbedtls_load_os_certs(tls, mosq);
		if(ret != 0){
			return ret;
		}
	}else if(!mosq->tls_insecure && mosq->tls_cert_reqs != 0){
		return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
	}

	if(mosq->tls_capath){
		log__printf(mosq, MOSQ_LOG_WARNING, "Warning: tls-capath is not yet supported with the mbedTLS backend.");
	}

		if(mosq->tls_certfile){
		ret = mbedtls_x509_crt_parse_file(&tls->client_cert, mosq->tls_certfile);
		if(ret != 0){
			return ret;
		}
			if(mosq->tls_keyfile){
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
				ret = mbedtls_pk_parse_keyfile(&tls->client_key, mosq->tls_keyfile, NULL,
					mbedtls_ctr_drbg_random, &tls->ctr_drbg);
#else
				ret = mbedtls_pk_parse_keyfile(&tls->client_key, mosq->tls_keyfile, NULL);
#endif
			if(ret != 0){
				return ret;
			}
			ret = mbedtls_ssl_conf_own_cert(&tls->conf, &tls->client_cert, &tls->client_key);
			if(ret != 0){
				return ret;
			}
					
			tls->has_client_cert = true;
		}
	}

	return 0;
}

static int mosquitto__mbedtls_bio_send(void *context, const unsigned char *buf, size_t len)
{
	struct mosquitto *mosq = context;
	int rc;

	errno = 0;
	if(!mosq) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	rc = (int)send(mosq->sock, (const char *)buf, len, MSG_NOSIGNAL);
	if(rc < 0){
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EWOULDBLOCK || errno == EAGAIN){
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return rc;
}

static int mosquitto__mbedtls_bio_recv(void *context, unsigned char *buf, size_t len)
{
	struct mosquitto *mosq = context;
	int rc;

	errno = 0;
	if(!mosq) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	rc = (int)recv(mosq->sock, (char *)buf, len, 0);
	if(rc == 0){
		return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	}else if(rc < 0){
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EWOULDBLOCK || errno == EAGAIN){
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return rc;
}

int mosquitto__mbedtls_init(struct mosquitto *mosq)
{
	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->mbedtls) return MOSQ_ERR_SUCCESS;

	mosq->mbedtls = mosquitto__calloc(1, sizeof(struct mosq_mbedtls));
	if(!mosq->mbedtls){
		return MOSQ_ERR_NOMEM;
	}
	mbedtls_ssl_init(&mosq->mbedtls->ssl);

	return MOSQ_ERR_SUCCESS;
}

void mosquitto__mbedtls_cleanup(struct mosquitto *mosq)
{
	struct mosq_mbedtls *tls;

	if(!mosq || !mosq->mbedtls) return;

	tls = mosq->mbedtls;
	mbedtls_ssl_free(&tls->ssl);
	mbedtls_ssl_config_free(&tls->conf);
	mbedtls_x509_crt_free(&tls->ca_chain);
	mbedtls_x509_crt_free(&tls->client_cert);
	mbedtls_pk_free(&tls->client_key);
	mbedtls_ctr_drbg_free(&tls->ctr_drbg);
	mbedtls_entropy_free(&tls->entropy);
	mosquitto__free(mosq->mbedtls);
	mosq->mbedtls = NULL;
}

static void mosquitto__mbedtls_log_error(struct mosquitto *mosq, int code)
{
	char buf[128];

	mbedtls_strerror(code, buf, sizeof(buf));
	log__printf(mosq, MOSQ_LOG_ERR, "mbedTLS error: %s (%d)", buf, code);
}

int mosquitto__mbedtls_connect(struct mosquitto *mosq, const char *host)
{
	int ret;

	if(!mosq) return MOSQ_ERR_INVAL;

	ret = mosquitto__mbedtls_init(mosq);
	if(ret != MOSQ_ERR_SUCCESS){
		return ret;
	}

	ret = mosquitto__mbedtls_configure(mosq);
	if(ret != 0){
		mosquitto__mbedtls_log_error(mosq, ret);
		return MOSQ_ERR_TLS;
	}

	mbedtls_ssl_free(&mosq->mbedtls->ssl);
	mbedtls_ssl_init(&mosq->mbedtls->ssl);
	ret = mbedtls_ssl_setup(&mosq->mbedtls->ssl, &mosq->mbedtls->conf);
	if(ret != 0){
		mosquitto__mbedtls_log_error(mosq, ret);
		return MOSQ_ERR_TLS;
	}

	mbedtls_ssl_set_bio(&mosq->mbedtls->ssl, mosq, mosquitto__mbedtls_bio_send,
			mosquitto__mbedtls_bio_recv, NULL);

	if(host && !mosq->tls_insecure){
		ret = mbedtls_ssl_set_hostname(&mosq->mbedtls->ssl, host);
		if(ret != 0){
			mosquitto__mbedtls_log_error(mosq, ret);
			return MOSQ_ERR_TLS;
		}
	}

	do {
		ret = mbedtls_ssl_handshake(&mosq->mbedtls->ssl);
	} while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if(ret != 0){
		mosquitto__mbedtls_log_error(mosq, ret);
		return MOSQ_ERR_TLS;
	}

	if(!mosq->tls_insecure && mosq->tls_cert_reqs != 0){
		uint32_t flags = mbedtls_ssl_get_verify_result(&mosq->mbedtls->ssl);
		if(flags != 0){
			char info[256];
			mbedtls_x509_crt_verify_info(info, sizeof(info), "  ", flags);
			log__printf(mosq, MOSQ_LOG_ERR, "Error: TLS certificate verification failed: %s", info);
			return MOSQ_ERR_TLS;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

ssize_t mosquitto__mbedtls_read(struct mosquitto *mosq, void *buf, size_t count)
{
	int ret;

	if(!mosq || !mosq->mbedtls) return -1;

	errno = 0;
	ret = mbedtls_ssl_read(&mosq->mbedtls->ssl, buf, count);
	if(ret > 0){
		return ret;
	}
	if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
		errno = EAGAIN;
		return -1;
	}
	if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
		errno = ECONNRESET;
		return -1;
	}
	mosquitto__mbedtls_log_error(mosq, ret);
	errno = EPROTO;
	return -1;
}

ssize_t mosquitto__mbedtls_write(struct mosquitto *mosq, const void *buf, size_t count)
{
	int ret;

	if(!mosq || !mosq->mbedtls) return -1;

	errno = 0;
	ret = mbedtls_ssl_write(&mosq->mbedtls->ssl, buf, count);
	if(ret >= 0){
		return ret;
	}
	if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
		mosq->want_write = (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		errno = EAGAIN;
		return -1;
	}
	 errno = EPROTO;
	return -1;
}

#endif /* WITH_TLS_MBEDTLS */
