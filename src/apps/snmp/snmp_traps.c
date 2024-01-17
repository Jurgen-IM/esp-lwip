/**
 * @file
 * SNMPv1 traps implementation.
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Martin Hentschel
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include <string.h>


#include "lwip/snmp.h"
#include "lwip/sys.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/prot/iana.h"
#include "lwip/ip_addr.h"
#include "lwip/udp.h"
#include "lwip/ip.h"
#include "snmp_msg.h"
#include "snmp_asn1.h"
#include "snmp_core_priv.h"
#include "snmpv3_priv.h"

static const struct snmp_obj_id  snmp_device_enterprise_traps_oid = {SNMP_DEVICE_ENTERPRISE_TRAPS_OID_LEN, SNMP_DEVICE_ENTERPRISE_TRAPS_OID};

static const u32_t mib2_sysUpTime[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
static const  u32_t  mib2_snmpTrapOID[]  = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

static u8_t snmp_auth_traps_enabled = 0;

struct snmp_msg_trap {

  /* source enterprise ID (sysObjectID) */
  const struct snmp_obj_id *enterprise;

  void *netif;
  s8_t rstatus;

  /* source IP address, raw network order format */
  ip_addr_t sip;
  /* generic trap code */
  u32_t gen_trap;
  /* specific trap code */
  u32_t spc_trap;
  /* timestamp */
  u32_t ts;
  /* snmp_version */
  u8_t snmp_version;

  /* output trap lengths used in ASN encoding */
#if LWIP_SNMP_V3
  const char* username;
  snmpv3_auth_algo_t authType;
  u8_t *authKey;
  snmpv3_priv_algo_t privType;
  u8_t *privKey;
  u8_t sec_parameters_seq_length;
  u8_t sec_parameters_str_length;
  u8_t global_header_length;
  u16_t scope_pdulen;
  u8_t scope_pdulen_padd;
  u16_t scope_pdu_str_len;
  u16_t msg_authentication_parameters_offset;
  u16_t msg_privacy_parameters_offset;
  u16_t msg_scope_pdu_str_offset;
  u32_t msg_authoritative_engine_boots;
  u32_t msg_authoritative_engine_time;
#endif
  /* encoding pdu length */
  u16_t pdulen;
  /* encoding sequence length */
  u16_t seqlen;

  u8_t iplen;
  /* encoding community length */
  u8_t comlen;

  /* encoding varbinds sequence length */
  u16_t vbseqlen;
};

static u16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds);
static void snmp_trap_header_sum_add(struct snmp_msg_trap *trap, u16_t *tot_len);
static u16_t snmp_trap_source_ip_length(struct snmp_msg_trap *trap);
static err_t snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds);
static err_t snmp_trap_scope_pdu_padd_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_scope_pdu_crypt(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, u16_t frameLen);

err_t snmpv3_traps_get_user(const char** username, snmpv3_auth_algo_t *auth_algo, u8_t **auth_key, snmpv3_priv_algo_t *priv_algo, u8_t **priv_key);

#define BUILD_EXEC(code) \
  if ((code) != ERR_OK) { \
    LWIP_DEBUGF(SNMP_DEBUG, ("SNMP error during creation of outbound trap frame!")); \
    return ERR_ARG; \
  }

/** Agent community string for sending traps */
extern char snmp_community_trap[SNMP_MAX_COMMUNITY_STR_LEN+1];

void *snmp_traps_handle;

static u32_t _snmp_msg_id=1;

/**
 * @ingroup snmp_traps
 * Enable/disable authentication traps
 */
void
snmp_set_auth_traps_enabled(u8_t enable)
{
  snmp_auth_traps_enabled = enable;
}

/**
 * @ingroup snmp_traps
 * Get authentication traps enabled state
 */
u8_t
snmp_get_auth_traps_enabled(void)
{
  return snmp_auth_traps_enabled;
}

/**
 * @ingroup snmp_traps
 * Send generic SNMP trap
 */
err_t snmp_send_trap_generic(s32_t generic_trap)
{
  static const struct snmp_obj_id oid = { 7, { 1, 3, 6, 1, 2, 1, 11 } };
  return snmp_send_trap(&oid, generic_trap, 0, NULL);
}

/**
 * @ingroup snmp_traps
 * Send specific SNMP trap with variable bindings
 */
err_t snmp_send_trap_specific(s32_t specific_trap, struct snmp_varbind *varbinds)
{
  return snmp_send_trap(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap, varbinds);
}

/**
 * @ingroup snmp_traps
 * Send authentication failure trap (used internally by agent)
 */
void snmp_authfail_trap(void)
{
  if (snmp_auth_traps_enabled != 0) {
    snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
  }
}

s8_t snmp_get_netif_ip_for_dst(void *handle, struct snmp_msg_trap *trap_msg, const ip_addr_t *dst)
{
	struct udp_pcb *udp_pcb = (struct udp_pcb *)handle;
	struct netif *netif = NULL;

	if(trap_msg->rstatus == (-1))
	{
		return -1;
	}

	if(trap_msg->rstatus == 0)
	{
		netif = ip_route_no_default(&udp_pcb->local_ip, dst);
		if(netif != NULL)
		{
			trap_msg->rstatus = -1;
			trap_msg->netif = netif;
			ip_addr_copy(trap_msg->sip, *ip4_netif_get_local_ip(netif));
			return 0;
		}
		trap_msg->netif = NULL;
		trap_msg->rstatus = 1;
	}
	netif=netif_get_next_active(trap_msg->netif);
	if(netif==NULL)
	{
		trap_msg->rstatus = 0;
		return (-1);
	}
	trap_msg->netif = netif;
	ip_addr_copy(trap_msg->sip, *ip4_netif_get_local_ip(netif));
	return 0;
}


/**
 * @ingroup snmp_traps
 * Sends a generic or enterprise specific trap message.
 *
 * @param eoid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */

err_t snmp_send_trap(const struct snmp_obj_id *eoid, s32_t generic_trap, s32_t specific_trap, struct snmp_varbind *varbinds)
{
	struct snmp_msg_trap trap_msg;
	struct snmp_varbind vb_sysUpTime;
	struct snmp_varbind vb_TrapOID;
	struct pbuf *p;
	u16_t i;
	const ip_addr_t *dst;
	err_t err = ERR_OK;

	LWIP_ASSERT_CORE_LOCKED();

	if(snmp_traps_handle == NULL)
	{
		return ERR_ARG;
	}

	trap_msg.snmp_version = snmp_trap_version_get();

	if(trap_msg.snmp_version == SNMP_VERSION_NONE)
		return ERR_ARG;

	bool noIp=true;
	for(i=0;i<SNMP_TRAPS_DESTINATIONS;i++)
	{
		dst = snmp_get_trap_address(i);
		if (!ip_addr_isany(dst))
		{
			noIp=false;
			break;
		}
	}
	if(noIp)
		return ERR_ARG;

	//prepear trap data
	if(eoid == NULL)
	{
		trap_msg.enterprise = &snmp_device_enterprise_traps_oid;
	}
	else
	{
		trap_msg.enterprise = eoid;
	}
	trap_msg.gen_trap = generic_trap;
	if (trap_msg.gen_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC)
	{
		trap_msg.spc_trap = specific_trap;
	}
	else
	{
		trap_msg.spc_trap = 0;
	}

	MIB2_COPY_SYSUPTIME_TO(&trap_msg.ts);

	if(trap_msg.snmp_version == SNMP_VERSION_2c
#if LWIP_SNMP_V3
			|| trap_msg.snmp_version == SNMP_VERSION_3
#endif
	)
	{
		//sysUpTime
		vb_sysUpTime.next = &vb_TrapOID;
		snmp_oid_assign(&vb_sysUpTime.oid, mib2_sysUpTime, LWIP_ARRAYSIZE(mib2_sysUpTime));
		vb_sysUpTime.type = SNMP_ASN1_TYPE_TIMETICKS;
		vb_sysUpTime.value = &trap_msg.ts;
		vb_sysUpTime.value_len = sizeof (u32_t);

		//snmpTrapOID
		varbinds->prev = &vb_TrapOID;
		vb_TrapOID.next = varbinds;
		if (trap_msg.gen_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC)
		{
			snmp_oid_assign(&vb_TrapOID.oid, mib2_snmpTrapOID, LWIP_ARRAYSIZE(mib2_snmpTrapOID));
		}
		else
		{
			memcpy(&vb_TrapOID.oid, trap_msg.enterprise, sizeof(struct snmp_obj_id));
			vb_TrapOID.oid.id[vb_TrapOID.oid.len++]=trap_msg.gen_trap;
		}
		vb_TrapOID.type = SNMP_ASN1_TYPE_OBJECT_ID;
		vb_TrapOID.value = (void*)trap_msg.enterprise->id;
		vb_TrapOID.value_len = trap_msg.enterprise->len*sizeof(u32_t);

		varbinds = &vb_sysUpTime;
	}
#if LWIP_SNMP_V3
	if(trap_msg.snmp_version == SNMP_VERSION_3)
	{
		if(snmpv3_traps_get_user(&trap_msg.username, &trap_msg.authType, &trap_msg.authKey, &trap_msg.privType, &trap_msg.privKey) != ERR_OK)
		{
			return ERR_ARG;
		}
		trap_msg.msg_authoritative_engine_boots = snmpv3_get_engine_boots();
		trap_msg.msg_authoritative_engine_time = snmpv3_get_engine_time();
	}
#endif

	/* pass 0, calculate length fields */
	u16_t tot_len = snmp_trap_varbind_sum(&trap_msg, varbinds);
	snmp_trap_header_sum_add(&trap_msg, &tot_len);

	u8_t trapIf = snmp_trap_send_if_get();

	for(i=0;i<SNMP_TRAPS_DESTINATIONS;i++)
	{
		dst = snmp_get_trap_address(i);

		if (ip_addr_isany(dst))
		{
			continue;
		}
		trap_msg.rstatus = 0;
		while(1)
		{
			if(trapIf)
			{
				if(snmp_get_netif_ip_for_dst(snmp_traps_handle, &trap_msg, dst) < 0)
				{
					break;
				}
			}
			else
			{
				/* lookup current source address for this dst */
				if (!snmp_get_local_ip_for_dst(snmp_traps_handle, dst, &trap_msg.sip))
				{
					err = ERR_RTE;
					break;
				}
			}

			u16_t  ip_len = snmp_trap_source_ip_length(&trap_msg);
			u16_t frameLen = tot_len+ip_len;

			/* allocate pbuf(s) */
			p = pbuf_alloc(PBUF_TRANSPORT, frameLen, PBUF_RAM);
			if (p != NULL)
			{
				struct snmp_pbuf_stream pbuf_stream;
				snmp_pbuf_stream_init(&pbuf_stream, p, 0, frameLen);

				/* pass 1, encode packet into the pbuf(s) */
				snmp_trap_header_enc(&trap_msg, &pbuf_stream);
				snmp_trap_varbind_enc(&trap_msg, &pbuf_stream, varbinds);
				snmp_trap_scope_pdu_padd_enc(&trap_msg, &pbuf_stream);
				snmp_trap_scope_pdu_crypt(&trap_msg, &pbuf_stream, frameLen);

				snmp_stats.outtraps++;
				snmp_stats.outpkts++;

				/** send to the TRAP destination */
				if(trapIf)
				{
					snmp_sendto_if(snmp_traps_handle, p, dst, LWIP_IANA_PORT_SNMP_TRAP, trap_msg.netif);
					pbuf_free(p);
				}
				else
				{
					snmp_sendto(snmp_traps_handle, p, dst, LWIP_IANA_PORT_SNMP_TRAP);
					pbuf_free(p);
					break;
				}
			}
			else
			{
				err = ERR_MEM;
				break;
			}
		}
	}
	_snmp_msg_id++;
	return err;
}

static u16_t
snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds)
{
  struct snmp_varbind *varbind;
  u16_t tot_len;
  u8_t tot_len_len;

  tot_len = 0;
  varbind = varbinds;
  while (varbind != NULL) {
    struct snmp_varbind_len len;

    if (snmp_varbind_length(varbind, &len) == ERR_OK) {
      tot_len += 1 + len.vb_len_len + len.vb_value_len;
    }
    varbind = varbind->next;
  }

  trap->vbseqlen = tot_len;
  snmp_asn1_enc_length_cnt(trap->vbseqlen, &tot_len_len);
  tot_len += 1 + tot_len_len;

  return tot_len;
}

/**
 * Sums trap header field lengths from tail to head and
 * returns trap_header_lengths for second encoding pass.
 *
 * @param trap Trap message
 * @param vb_len varbind-list length
 * @return the required length for encoding the trap header
 */
static void
snmp_trap_header_sum_add(struct snmp_msg_trap *trap, u16_t *tot_len)
{
	u16_t len;
	u8_t lenlen;

	if(tot_len == NULL)
		return;
	//calculating lenght from bottom to top of trap frame
	if(trap->snmp_version == SNMP_VERSION_1)
	{
		//timestamp length
		snmp_asn1_enc_u32t_cnt(trap->ts, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//specific trap code length
		snmp_asn1_enc_s32t_cnt(trap->spc_trap, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//generic trap code length
		snmp_asn1_enc_s32t_cnt(trap->gen_trap, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//source ip length
		//----

		//enterprice oid length
		snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;
	}
	else if(trap->snmp_version == SNMP_VERSION_2c
#if LWIP_SNMP_V3
			|| trap->snmp_version == SNMP_VERSION_3
#endif
	)
	{
		// Similarly put error index.
		snmp_asn1_enc_s32t_cnt(0, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		// Put error status.
		snmp_asn1_enc_s32t_cnt(0, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//snmp_msg_id
		snmp_asn1_enc_s32t_cnt(_snmp_msg_id, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;
	}
#if LWIP_SNMP_V3
	if(trap->snmp_version == SNMP_VERSION_3)
	{
		//trap pdu length
		trap->pdulen = *tot_len;
		*tot_len += 1 + 3;

		/* contextName */
		snmp_asn1_enc_length_cnt(0, &lenlen);
		*tot_len += 1 + lenlen + 0;

		/* contextEngineID */
		snmp_asn1_enc_length_cnt(0, &lenlen);
		*tot_len += 1 + lenlen + 0;

		//Scoped PDU
		trap->scope_pdulen = *tot_len;
		*tot_len += 1 + 3;

		trap->scope_pdulen_padd = 0;
#if LWIP_SNMP_V3_CRYPTO
	  /* Calculate padding for encryption */
		if (trap->snmp_version == SNMP_VERSION_3 && (trap->privType != SNMP_V3_PRIV_ALGO_INVAL))
		{
			if(trap->privType == SNMP_V3_PRIV_ALGO_DES){
				trap->scope_pdulen_padd = (8 - (u8_t)(trap->scope_pdulen & 0x07)) & 0x07;
			}else {
				trap->scope_pdulen_padd = (16 - (u8_t)(trap->scope_pdulen & 0x0f)) & 0x0f;
			}
			*tot_len += trap->scope_pdulen_padd;
			trap->scope_pdulen += trap->scope_pdulen_padd;

			//Scoped String
			trap->scope_pdu_str_len = *tot_len;
			*tot_len += 1 + 3;

		}
#endif
		u16_t sec_parameters_seq_length = *tot_len;
#if LWIP_SNMP_V3_CRYPTO
		/* msgPrivacyParameters */
		if (trap->privType != SNMP_V3_PRIV_ALGO_INVAL)
		{
			snmp_asn1_enc_length_cnt(SNMP_V3_MAX_PRIV_PARAM_LENGTH, &lenlen);
			*tot_len += 1 + lenlen + SNMP_V3_MAX_PRIV_PARAM_LENGTH;
		} else
#endif
		{
			*tot_len += 1 + 1;
		}
#if LWIP_SNMP_V3_CRYPTO
		/* msgAuthenticationParameters */
		if (trap->authType != SNMP_V3_AUTH_ALGO_INVAL)
		{
			len = snmpv3_get_auth_param_len(trap->authType);
			snmp_asn1_enc_length_cnt(len, &lenlen);
			*tot_len += 1 + len + lenlen;
		}else
#endif
		{
			*tot_len += 1 + 1;
		}

		//username length
		trap->comlen = (u16_t)LWIP_MIN(strlen(trap->username), 0xFFFF);
		snmp_asn1_enc_length_cnt(trap->comlen, &lenlen);
		*tot_len += 1 + lenlen + trap->comlen;

		//engine time length
		snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_time, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//engine boots length
		snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_boots, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//engine id length
		const char *eid;
		u8_t eln;
		snmpv3_get_engine_id(&eid, &eln);
		snmp_asn1_enc_length_cnt(eln, &lenlen);
		*tot_len += 1 + eln + lenlen;

		// parameters seq length
		trap->sec_parameters_seq_length = (*tot_len)-sec_parameters_seq_length;
		snmp_asn1_enc_length_cnt(trap->sec_parameters_seq_length, &lenlen);
		*tot_len += 1  + lenlen;
		// parameters str length
		trap->sec_parameters_str_length = (*tot_len)-sec_parameters_seq_length;
		snmp_asn1_enc_length_cnt(trap->sec_parameters_str_length, &lenlen);
		*tot_len += 1 + lenlen;


		/* end of msgGlobalData */
		trap->global_header_length = *tot_len;

		//snmp security model
		len = 1; //security model length = 1;
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//snmp message flags
		len = 1; //message flags length = 1
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//snmp message maxSize
		snmp_asn1_enc_s32t_cnt(SNMP_MESSAGE_MAX_SIZE, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//snmp_msg_id
		snmp_asn1_enc_s32t_cnt(_snmp_msg_id, &len);
		snmp_asn1_enc_length_cnt(len, &lenlen);
		*tot_len += 1 + len + lenlen;

		//trap global header length
		trap->global_header_length = *tot_len-trap->global_header_length;
		snmp_asn1_enc_length_cnt(trap->global_header_length, &lenlen);
		*tot_len += 1 + lenlen;
	}
	else
#endif
	{
		//trap pdu length
		trap->pdulen = *tot_len;
		*tot_len += 1 + 3;

		//trap v1 community length
		trap->comlen = (u16_t)LWIP_MIN(strlen(snmp_community_trap), 0xFFFF);
		snmp_asn1_enc_length_cnt(trap->comlen, &lenlen);
		*tot_len += 1 + lenlen + trap->comlen;
	}

	//trap version length
	snmp_asn1_enc_s32t_cnt(trap->snmp_version, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	*tot_len += 1 + len + lenlen;

	//all trap data length
	trap->seqlen = *tot_len;
	snmp_asn1_enc_length_cnt(trap->seqlen, &lenlen);
	*tot_len += 1 + lenlen;
}

static u16_t
snmp_trap_source_ip_length(struct snmp_msg_trap *trap)
{
	u8_t len, lenlen;
	if(trap->snmp_version == SNMP_VERSION_1)
	{
		//source ip length
		if (IP_IS_V6_VAL(trap->sip)) {
	#if LWIP_IPV6
			len = sizeof(ip_2_ip6(&trap->sip)->addr);
	#endif
		} else {
	#if LWIP_IPV4
			len = sizeof(ip_2_ip4(&trap->sip)->addr);
	#endif
		}
		snmp_asn1_enc_length_cnt(len, &lenlen);
		trap->iplen = 1 + len + lenlen;
	}
	else
	{
		trap->iplen = 0;
	}
	return trap->iplen;
}

static err_t
snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds)
{
  struct snmp_asn1_tlv tlv;
  struct snmp_varbind *varbind;

  varbind = varbinds;

  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->vbseqlen);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

  while (varbind != NULL) {
    snmp_append_outbound_varbind(pbuf_stream, varbind);
    varbind = varbind->next;
  }

  return ERR_OK;
}


static err_t
snmp_trap_scope_pdu_padd_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream)
{
#if LWIP_SNMP_V3
	if(trap->snmp_version == SNMP_VERSION_3)
	{
		for (int i = 0; i < trap->scope_pdulen_padd; i++)
		{
			BUILD_EXEC( snmp_pbuf_stream_write(pbuf_stream, 0) );
		}
	}
#endif
	return ERR_OK;
}


static err_t
snmp_trap_scope_pdu_crypt(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, u16_t frameLen)
{
#if LWIP_SNMP_V3 && LWIP_SNMP_V3_CRYPTO
	if(trap->snmp_version == SNMP_VERSION_3)
	{
		struct snmp_pbuf_stream out_stream;
		if(trap->privType != SNMP_V3_PRIV_ALGO_INVAL)
		{
			u8_t msg_privacy_parameters[SNMP_V3_MAX_PRIV_PARAM_LENGTH];
			snmpv3_build_priv_param(msg_privacy_parameters);
			BUILD_EXEC(snmp_pbuf_stream_init(&out_stream, pbuf_stream->pbuf, 0, frameLen));
			BUILD_EXEC(snmp_pbuf_stream_seek_abs(&out_stream, trap->msg_scope_pdu_str_offset));
			BUILD_EXEC(snmpv3_crypt(&out_stream, trap->scope_pdulen, trap->privKey,
					msg_privacy_parameters, trap->msg_authoritative_engine_boots,
					trap->msg_authoritative_engine_time, trap->privType, SNMP_V3_PRIV_MODE_ENCRYPT));

			BUILD_EXEC(snmp_pbuf_stream_init(&out_stream, pbuf_stream->pbuf, 0, frameLen));
			BUILD_EXEC(snmp_pbuf_stream_seek_abs(&out_stream, trap->msg_privacy_parameters_offset));
			BUILD_EXEC(snmp_asn1_enc_raw(&out_stream, (u8_t *)msg_privacy_parameters, SNMP_V3_MAX_PRIV_PARAM_LENGTH));
		}
		if(trap->authType != SNMP_V3_AUTH_ALGO_INVAL)
		{
			u8_t len = snmpv3_get_auth_param_len(trap->authType);
			u8_t msg_authentication_parameters[LWIP_MAX(SNMP_V3_LOCALIZED_PASSWORD_KEY_LEN,SNMP_V3_MAX_AUTH_PARAM_LENGTH)];
			BUILD_EXEC(snmp_pbuf_stream_init(&out_stream, pbuf_stream->pbuf, 0, frameLen));
			BUILD_EXEC(snmpv3_auth(&out_stream, frameLen, trap->authKey, trap->authType, msg_authentication_parameters));

			BUILD_EXEC(snmp_pbuf_stream_init(&out_stream, pbuf_stream->pbuf, 0, frameLen));
			BUILD_EXEC(snmp_pbuf_stream_seek_abs(&out_stream, trap->msg_authentication_parameters_offset));
			BUILD_EXEC(snmp_asn1_enc_raw(&out_stream, (u8_t *)msg_authentication_parameters, len));
		}
	}
#endif
	return ERR_OK;
}

/**
 * Encodes trap header from head to tail.
 */
static err_t snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream)
{
	struct snmp_asn1_tlv tlv;

	/* 'Message' sequence */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->seqlen+trap->iplen);
	BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

	/* version */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->snmp_version, &tlv.value_len);
	BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
	BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->snmp_version) );

#if LWIP_SNMP_V3
	if(trap->snmp_version == SNMP_VERSION_3)
	{
		/* global header */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->global_header_length);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

		//snmp_msg_id
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(_snmp_msg_id, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, _snmp_msg_id) );

		//snmp message maxSize
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(SNMP_MESSAGE_MAX_SIZE, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, SNMP_MESSAGE_MAX_SIZE) );

		//snmp message flags
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 1);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		u8_t flags=0;
		if((trap->authType > SNMP_V3_AUTH_ALGO_INVAL && trap->authType < SNMP_V3_AUTH_END) && (trap->privType > SNMP_V3_PRIV_ALGO_INVAL && trap->privType < SNMP_V3_PRIV_END))
		{
			flags = SNMP_V3_AUTHPRIV;
		}
		else if((trap->authType > SNMP_V3_AUTH_ALGO_INVAL && trap->authType < SNMP_V3_AUTH_END) && (trap->privType == SNMP_V3_PRIV_ALGO_INVAL))
		{
			flags = SNMP_V3_AUTHNOPRIV;
		}
		else
		{
			flags = SNMP_V3_NOAUTHNOPRIV;
		}
		BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, &flags, 1));

		//snmp security model
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(SNMPV3_USM_SECURITY_MODEL, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, SNMPV3_USM_SECURITY_MODEL));

		/* security parameters seq */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->sec_parameters_str_length);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

		/* security parameters str */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->sec_parameters_seq_length);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

		//engine id length
		const char *eid;
		u8_t len;
		snmpv3_get_engine_id(&eid, &len);
	    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, len);
	    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, (u8_t *)eid, len));

		//engine boots length
	    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	    snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_boots, &tlv.value_len);
	    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_authoritative_engine_boots));

		//engine time length
	    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	    snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_time, &tlv.value_len);
	    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_authoritative_engine_time));

		//username length
	    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->comlen);
	    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, (u8_t *)trap->username, trap->comlen));

#if LWIP_SNMP_V3_CRYPTO
	    /* msgAuthenticationParameters */
	    if (trap->authType != SNMP_V3_AUTH_ALGO_INVAL) {
	    	len = snmpv3_get_auth_param_len(trap->authType);
	    	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, len);
	    	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    	trap->msg_authentication_parameters_offset = pbuf_stream->offset;
	    	for(int i=0;i<len;i++)
	    	{
	    		BUILD_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0));
	    	}
	    }else
#endif
	    {
	      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
	      BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	    }
#if LWIP_SNMP_V3_CRYPTO
	    /* msgPrivacyParameters */
		if (trap->privType != SNMP_V3_PRIV_ALGO_INVAL)
		{
			SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, SNMP_V3_MAX_PRIV_PARAM_LENGTH);
			BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
			trap->msg_privacy_parameters_offset = pbuf_stream->offset;
			for(int i=0;i<SNMP_V3_MAX_PRIV_PARAM_LENGTH;i++)
			{
				BUILD_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0));
			}
		} else
#endif
		{
		      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
		      BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
		}

		//Scoped PDU
#if LWIP_SNMP_V3_CRYPTO
		if (trap->privType != SNMP_V3_PRIV_ALGO_INVAL)
		{
			SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 3, trap->scope_pdu_str_len);
			BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
		}
#endif
		trap->msg_scope_pdu_str_offset = pbuf_stream->offset;

		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, trap->scope_pdulen);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

		/* contextEngineID */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

		/* contextName */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	}
	else
#endif
	{
		/* community */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->comlen);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream,  (const u8_t *)snmp_community_trap, trap->comlen) );
	}

	if(trap->snmp_version == SNMP_VERSION_1)
	{
		/* 'PDU' sequence */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT | SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_TRAP), 3, trap->pdulen+trap->iplen);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

		/* enterprise object ID */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OBJECT_ID, 0, 0);
		snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_oid(pbuf_stream, trap->enterprise->id, trap->enterprise->len) );

		/* IP addr */
		if (IP_IS_V6_VAL(trap->sip)) {
#if LWIP_IPV6
			SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0, sizeof(ip_2_ip6(&trap->sip)->addr));
			BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
			BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t *)&ip_2_ip6(&trap->sip)->addr, sizeof(ip_2_ip6(&trap->sip)->addr)) );
#endif
		} else {
#if LWIP_IPV4
			SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0, sizeof(ip_2_ip4(&trap->sip)->addr));
			BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
			BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t *)&ip_2_ip4(&trap->sip)->addr, sizeof(ip_2_ip4(&trap->sip)->addr)) );
#endif
		}
		/* generic trap */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(trap->gen_trap, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->gen_trap) );

		/* specific trap */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(trap->spc_trap, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->spc_trap) );

		/* timestamp */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_TIMETICKS, 0, 0);
		snmp_asn1_enc_s32t_cnt(trap->ts, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->ts) );
	}
	else if(trap->snmp_version == SNMP_VERSION_2c
#if LWIP_SNMP_V3
			|| trap->snmp_version == SNMP_VERSION_3
#endif
		)
	{
		/* 'PDU' sequence */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT | SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_V2_TRAP), 3, trap->pdulen+trap->iplen);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

		/* snmp_msg_id */
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(_snmp_msg_id, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, _snmp_msg_id) );

		// Put error status.
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(0, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, 0) );

		// Similarly put error index.
		SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
		snmp_asn1_enc_s32t_cnt(0, &tlv.value_len);
		BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
		BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, 0) );
	}
	return ERR_OK;
}

#endif /* LWIP_SNMP */
