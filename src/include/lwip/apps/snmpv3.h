/**
 * @file
 * Additional SNMPv3 functionality RFC3414 and RFC3826.
 */

/*
 * Copyright (c) 2016 Elias Oenal.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Elias Oenal <lwip@eliasoenal.com>
 */

#ifndef LWIP_HDR_APPS_SNMP_V3_H
#define LWIP_HDR_APPS_SNMP_V3_H

#include "lwip/apps/snmp_opts.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP && LWIP_SNMP_V3

#define SNMP_V3_AUTH_FLAG      0x01
#define SNMP_V3_PRIV_FLAG      0x02

/* Security levels */
#define SNMP_V3_NOAUTHNOPRIV   0x00
#define SNMP_V3_AUTHNOPRIV     SNMP_V3_AUTH_FLAG
#define SNMP_V3_AUTHPRIV       (SNMP_V3_AUTH_FLAG | SNMP_V3_PRIV_FLAG)

#define SNMP_MAX_TIME_BOOT 2147483647UL

typedef enum
{
  SNMP_V3_AUTH_ALGO_INVAL 		= 0,
  SNMP_V3_AUTH_ALGO_MD5   		= 1,
  SNMP_V3_AUTH_ALGO_SHA   		= 2,
  SNMP_V3_AUTH_ALGO_SHA256   	= 3,
  SNMP_V3_AUTH_ALGO_SHA512   	= 4,
  SNMP_V3_AUTH_END
} snmpv3_auth_algo_t;

typedef enum
{
  SNMP_V3_PRIV_ALGO_INVAL 		= 0,
  SNMP_V3_PRIV_ALGO_DES   		= 1,
  SNMP_V3_PRIV_ALGO_AES   		= 2,
  SNMP_V3_PRIV_ALGO_AES192 		= 3,
  SNMP_V3_PRIV_ALGO_AES256 		= 4,
  SNMP_V3_PRIV_END
} snmpv3_priv_algo_t;

typedef enum
{
  SNMP_V3_USER_STORAGETYPE_OTHER       = 1,
  SNMP_V3_USER_STORAGETYPE_VOLATILE    = 2,
  SNMP_V3_USER_STORAGETYPE_NONVOLATILE = 3,
  SNMP_V3_USER_STORAGETYPE_PERMANENT   = 4,
  SNMP_V3_USER_STORAGETYPE_READONLY    = 5
} snmpv3_user_storagetype_t;

typedef enum
{
	/* Security Model Reserved for ANY */
    ANY_SECUTIRY_MODEL=0x00,
	/* Security Model reserved fro SNMP version 1 */
    SNMPV1_SECURITY_MODEL=0X01,
	/* Community Security Model reserved for SNMP version 2 */
    SNMPV2C_SECURITY_MODEL=0X02,
	/* User based security model reserved for SNMP version 3 */
    SNMPV3_USM_SECURITY_MODEL=0X03
    /* Values between 1 to 255, inclusive, are reserved for standards-track
         Security Models  and are managed by IANA.*/
}snmpv3_security_model_t;

/*
 * The following callback functions must be implemented by the application.
 * There is a dummy implementation in snmpv3_dummy.c.
 */

void snmpv3_get_engine_id(const char **id, u8_t *len);
err_t snmpv3_set_engine_id(const char* id, u8_t len);

u32_t snmpv3_get_engine_boots(void);
void snmpv3_set_engine_boots(u32_t boots);

u32_t snmpv3_get_engine_time(void);
void snmpv3_reset_engine_time(void);

err_t snmpv3_get_user(const char* username, snmpv3_auth_algo_t *auth_algo, u8_t **auth_key, snmpv3_priv_algo_t *priv_algo, u8_t **priv_key);
u8_t snmpv3_get_amount_of_users(void);
err_t snmpv3_get_user_storagetype(const char *username, snmpv3_user_storagetype_t *storagetype);
err_t snmpv3_get_username(char *username, u8_t index);

/* The following functions are provided by the SNMPv3 agent */

void snmpv3_engine_id_changed(void);
s32_t snmpv3_get_engine_time_internal(void);

void snmpv3_password_to_key_md5(
    const u8_t *password,     /* IN */
    size_t      passwordlen,  /* IN */
    const u8_t *engineID,     /* IN  - pointer to snmpEngineID  */
    u8_t        engineLength, /* IN  - length of snmpEngineID */
    u8_t       *key);         /* OUT - pointer to caller 16-octet buffer */

void snmpv3_password_to_key_sha(
    const u8_t *password,     /* IN */
    size_t      passwordlen,  /* IN */
    const u8_t *engineID,     /* IN  - pointer to snmpEngineID  */
    u8_t        engineLength, /* IN  - length of snmpEngineID */
    u8_t       *key);         /* OUT - pointer to caller 64-octet buffer */

void snmpv3_password_to_key_sha256(
    const u8_t *password,     /* IN */
    size_t      passwordlen,  /* IN */
    const u8_t *engineID,     /* IN  - pointer to snmpEngineID  */
    u8_t        engineLength, /* IN  - length of snmpEngineID */
    u8_t       *key);         /* OUT - pointer to caller 64-octet buffer */

void snmpv3_password_to_key_sha512(
    const u8_t *password,     /* IN */
    size_t      passwordlen,  /* IN */
    const u8_t *engineID,     /* IN  - pointer to snmpEngineID  */
    u8_t        engineLength, /* IN  - length of snmpEngineID */
    u8_t       *key);         /* OUT - pointer to caller 64-octet buffer */


#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_SNMP_V3_H */
