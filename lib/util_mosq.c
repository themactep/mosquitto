/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#else
#  include <sys/stat.h>
#endif

#ifdef WITH_TLS_OPENSSL
#  include <openssl/bn.h>
#endif

#ifdef WITH_BROKER
#include "mosquitto_broker_internal.h"
#else
#  include "callbacks.h"
#endif

#include "mosquitto.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

#if defined(WITH_WEBSOCKETS) && WITH_WEBSOCKETS == WS_IS_LWS
#include <libwebsockets.h>
#endif


int mosquitto__check_keepalive(struct mosquitto *mosq)
{
	time_t next_msg_out;
	time_t last_msg_in;
	time_t now;
#ifndef WITH_BROKER
	int rc;
#endif
	enum mosquitto_client_state state;

	assert(mosq);
#ifdef WITH_BROKER
	now = db.now_s;
#else
	now = mosquitto_time();
#endif

#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	/* Check if a lazy bridge should be timed out due to idle. */
	if(mosq->bridge && mosq->bridge->start_type == bst_lazy
			&& net__is_connected(mosq)
			&& now - mosq->next_msg_out - mosq->keepalive >= mosq->bridge->idle_timeout){

		log__printf(mosq, MOSQ_LOG_NOTICE, "Bridge connection %s has exceeded idle timeout, disconnecting.", mosq->id);
		net__socket_close(mosq);
		return MOSQ_ERR_SUCCESS;
	}
#endif
	COMPAT_pthread_mutex_lock(&mosq->msgtime_mutex);
	next_msg_out = mosq->next_msg_out;
	last_msg_in = mosq->last_msg_in;
	COMPAT_pthread_mutex_unlock(&mosq->msgtime_mutex);
	if(mosq->keepalive && net__is_connected(mosq) &&
			(now >= next_msg_out || now - last_msg_in >= mosq->keepalive)){

		state = mosquitto__get_state(mosq);
		if(state == mosq_cs_active && mosq->ping_t == 0){
			send__pingreq(mosq);
			/* Reset last msg times to give the server time to send a pingresp */
			COMPAT_pthread_mutex_lock(&mosq->msgtime_mutex);
			mosq->last_msg_in = now;
			mosq->next_msg_out = now + mosq->keepalive;
			COMPAT_pthread_mutex_unlock(&mosq->msgtime_mutex);
		}else{
#ifdef WITH_BROKER
#  ifdef WITH_BRIDGE
			if(mosq->bridge){
				context__send_will(mosq);
			}
#  endif
			net__socket_close(mosq);
#else
			net__socket_close(mosq);
			state = mosquitto__get_state(mosq);
			if(state == mosq_cs_disconnecting){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				rc = MOSQ_ERR_KEEPALIVE;
			}
			callback__on_disconnect(mosq, rc, NULL);

			return rc;
#endif
		}
	}
	return MOSQ_ERR_SUCCESS;
}


uint16_t mosquitto__mid_generate(struct mosquitto *mosq)
{
	/* FIXME - this would be better with atomic increment, but this is safer
	 * for now for a bug fix release.
	 *
	 * If this is changed to use atomic increment, callers of this function
	 * will have to be aware that they may receive a 0 result, which may not be
	 * used as a mid.
	 */
	uint16_t mid;
	assert(mosq);

	COMPAT_pthread_mutex_lock(&mosq->mid_mutex);
	mosq->last_mid++;
	if(mosq->last_mid == 0){
		mosq->last_mid++;
	}
	mid = mosq->last_mid;
	COMPAT_pthread_mutex_unlock(&mosq->mid_mutex);

	return mid;
}


#if defined(WITH_TLS_OPENSSL) || defined(WITH_TLS_MBEDTLS)
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif


int mosquitto__hex2bin_sha1(const char *hex, unsigned char **bin)
{
	unsigned char *sha, tmp[SHA_DIGEST_LENGTH];

	if(mosquitto__hex2bin(hex, tmp, SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH){
		return MOSQ_ERR_INVAL;
	}

	sha = mosquitto_malloc(SHA_DIGEST_LENGTH);
	if(!sha){
		return MOSQ_ERR_NOMEM;
	}
	memcpy(sha, tmp, SHA_DIGEST_LENGTH);
	*bin = sha;
	return MOSQ_ERR_SUCCESS;
}


int mosquitto__hex2bin(const char *hex, unsigned char *bin, int bin_max_len)
{
	int len = 0;
	size_t hexlen = strlen(hex);
	size_t i;
	unsigned char val;
	char c;

	if(hexlen % 2 != 0) return 0;
	if((int)(hexlen / 2) > bin_max_len) return 0;

	for(i = 0; i < hexlen; i++){
		c = hex[i];
		if(c >= '0' && c <= '9') val = (unsigned char)(c - '0');
		else if(c >= 'a' && c <= 'f') val = (unsigned char)(c - 'a' + 10);
		else if(c >= 'A' && c <= 'F') val = (unsigned char)(c - 'A' + 10);
		else return 0;
		if(i % 2 == 0){
			bin[len] = (unsigned char)(val << 4);
		} else {
			bin[len] |= val;
			len++;
		}
	}
	return len;
}
#endif


void util__increment_receive_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_in.inflight_quota < mosq->msgs_in.inflight_maximum){
		mosq->msgs_in.inflight_quota++;
	}
}


void util__increment_send_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_out.inflight_quota < mosq->msgs_out.inflight_maximum){
		mosq->msgs_out.inflight_quota++;
	}
}


void util__decrement_receive_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_in.inflight_quota > 0){
		mosq->msgs_in.inflight_quota--;
	}
}


void util__decrement_send_quota(struct mosquitto *mosq)
{
	if(mosq->msgs_out.inflight_quota > 0){
		mosq->msgs_out.inflight_quota--;
	}
}


int mosquitto__set_state(struct mosquitto *mosq, enum mosquitto_client_state state)
{
	COMPAT_pthread_mutex_lock(&mosq->state_mutex);
#ifdef WITH_BROKER
	if(mosq->state != mosq_cs_disused)
#endif
	{
		mosq->state = state;
	}
	COMPAT_pthread_mutex_unlock(&mosq->state_mutex);

	return MOSQ_ERR_SUCCESS;
}

enum mosquitto_client_state mosquitto__get_state(struct mosquitto *mosq)
{
	enum mosquitto_client_state state;

	COMPAT_pthread_mutex_lock(&mosq->state_mutex);
	state = mosq->state;
	COMPAT_pthread_mutex_unlock(&mosq->state_mutex);

	return state;
}

#ifndef WITH_BROKER


void mosquitto__set_request_disconnect(struct mosquitto *mosq, bool request_disconnect)
{
	COMPAT_pthread_mutex_lock(&mosq->state_mutex);
	mosq->request_disconnect = request_disconnect;
	COMPAT_pthread_mutex_unlock(&mosq->state_mutex);
}


bool mosquitto__get_request_disconnect(struct mosquitto *mosq)
{
	bool request_disconnect;

	COMPAT_pthread_mutex_lock(&mosq->state_mutex);
	request_disconnect = mosq->request_disconnect;
	COMPAT_pthread_mutex_unlock(&mosq->state_mutex);

	return request_disconnect;
}
#endif
