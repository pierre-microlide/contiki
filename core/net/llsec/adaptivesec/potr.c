/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Practical On-the-fly Rejection (POTR).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/adaptivesec/potr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/llsec802154.h"
#include "net/llsec/anti-replay.h"
#include "lib/aes-128.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "net/mac/contikimac/contikimac-framer.h"
#include "net/llsec/ccm-star-packetbuf.h"
#include "net/mac/contikimac/secrdc.h"
#include <string.h>

#ifdef POTR_CONF_KEY
#define POTR_KEY POTR_CONF_KEY
#else /* POTR_CONF_KEY */
#define POTR_KEY { 0x00 , 0x01 , 0x02 , 0x03 , \
                   0x04 , 0x05 , 0x06 , 0x07 , \
                   0x08 , 0x09 , 0x0A , 0x0B , \
                   0x0C , 0x0D , 0x0E , 0x0F }
#endif /* POTR_CONF_KEY */

#define WITH_AUTHENTIC_ACKNOWLEDGEMENTS SECRDC_WITH_SECURE_PHASE_LOCK
#define MAX_CACHED_OTPS AKES_NBR_MAX_TENTATIVES

#ifdef POTR_CONF_WITH_CONTIKIMAC_FRAMER
#define WITH_CONTIKIMAC_FRAMER POTR_CONF_WITH_CONTIKIMAC_FRAMER
#else /* POTR_CONF_WITH_CONTIKIMAC_FRAMER */
#define WITH_CONTIKIMAC_FRAMER 0
#endif /* POTR_CONF_WITH_CONTIKIMAC_FRAMER */

#define HELLO_LEN (POTR_HEADER_LEN \
    + (WITH_CONTIKIMAC_FRAMER ? CONTIKIMAC_FRAMER_HEADER_LEN : 0) \
    + 1 \
    + AKES_NBR_CHALLENGE_LEN \
    + (AKES_NBR_WITH_PAIRWISE_KEYS ? 0 : ADAPTIVESEC_BROADCAST_MIC_LEN))

#if WITH_CONTIKIMAC_FRAMER && (HELLO_LEN < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE)
#undef HELLO_LEN
#define HELLO_LEN CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE
#endif /* WITH_CONTIKIMAC_FRAMER && (HELLO_LEN < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE) */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if POTR_ENABLED
static void read_otp(void);

static uint8_t potr_key[16] = POTR_KEY;
static potr_otp_t cached_otps[MAX_CACHED_OTPS];
static uint8_t cached_otps_index;

/*---------------------------------------------------------------------------*/
static void
write_frame_counter(uint8_t *p)
{
  frame802154_frame_counter_t frame_counter;

  frame_counter.u16[0] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1);
  frame_counter.u16[1] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3);
  memcpy(p, frame_counter.u8, 4);
}
/*---------------------------------------------------------------------------*/
static int
shall_send_acknowledgement(enum potr_frame_type type)
{
#if WITH_AUTHENTIC_ACKNOWLEDGEMENTS
  return type <= POTR_FRAME_TYPE_UNICAST_COMMAND;
#else /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */
  return type <= POTR_FRAME_TYPE_ACK;
#endif /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */
}
/*---------------------------------------------------------------------------*/
static int
length_of(enum potr_frame_type type)
{
#if WITH_AUTHENTIC_ACKNOWLEDGEMENTS
  return POTR_HEADER_LEN + (shall_send_acknowledgement(type) ? 1 : 0);
#else /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */
  return POTR_HEADER_LEN;
#endif /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */
}
/*---------------------------------------------------------------------------*/
static int
length(void)
{
  return length_of(packetbuf_holds_broadcast()
      ? POTR_FRAME_TYPE_BROADCAST_DATA
      : POTR_FRAME_TYPE_UNICAST_DATA);
}
/*---------------------------------------------------------------------------*/
void
potr_create_special_otp(potr_otp_t *result, const linkaddr_t *src, uint8_t *challenge)
{
  uint8_t block[AES_128_BLOCK_SIZE];

  memcpy(block, src->u8, LINKADDR_SIZE);
  memcpy(block + LINKADDR_SIZE, challenge, AKES_NBR_CHALLENGE_LEN);
  memset(block + LINKADDR_SIZE + AKES_NBR_CHALLENGE_LEN,
      0,
      AES_128_BLOCK_SIZE - LINKADDR_SIZE - AKES_NBR_CHALLENGE_LEN);

  AES_128_GET_LOCK();
  ADAPTIVESEC_SET_KEY(potr_key);
  AES_128.encrypt(block);
  AES_128_RELEASE_LOCK();
  memcpy(result->u8, block, POTR_OTP_LEN);
}
/*---------------------------------------------------------------------------*/
static void
create_normal_otp(uint8_t *p, uint8_t *group_key)
{
  uint8_t block[AES_128_BLOCK_SIZE];
  uint8_t key[AKES_NBR_KEY_LEN];
  uint8_t i;

  if(packetbuf_holds_broadcast()) {
    memset(block, 0xFF, LINKADDR_SIZE);
  } else {
    memcpy(block, packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8, LINKADDR_SIZE);
  }
  write_frame_counter(block + LINKADDR_SIZE);
  memset(block + LINKADDR_SIZE + 4, 0, AES_128_BLOCK_SIZE - LINKADDR_SIZE - 4);
  for(i = 0; i < AKES_NBR_KEY_LEN; i++) {
    key[i] = group_key[i] ^ potr_key[i];
  }
  AES_128_GET_LOCK();
  ADAPTIVESEC_SET_KEY(key);
  AES_128.encrypt(block);
  AES_128_RELEASE_LOCK();
  memcpy(p, block, POTR_OTP_LEN);
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  enum potr_frame_type type;
  uint8_t cmd_id;
  uint8_t *p;
  struct akes_nbr_entry *entry;

  /* Frame Type */
  switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
  case FRAME802154_DATAFRAME:
    type = packetbuf_holds_broadcast() ? POTR_FRAME_TYPE_BROADCAST_DATA : POTR_FRAME_TYPE_UNICAST_DATA;
    break;
  case FRAME802154_CMDFRAME:
    cmd_id = adaptivesec_get_cmd_id();
    switch(cmd_id) {
    case POTR_FRAME_TYPE_HELLO:
    case POTR_FRAME_TYPE_HELLOACK:
    case POTR_FRAME_TYPE_HELLOACK_P:
    case POTR_FRAME_TYPE_ACK:
      type = cmd_id;
      break;
    default:
      type = packetbuf_holds_broadcast() ? POTR_FRAME_TYPE_BROADCAST_COMMAND : POTR_FRAME_TYPE_UNICAST_COMMAND;
    }
    break;
  default:
    return FRAMER_FAILED;
  }
  if(!packetbuf_hdralloc(length_of(type))) {
    PRINTF("potr: packetbuf_hdralloc failed\n");
    return FRAMER_FAILED;
  }
  p = packetbuf_hdrptr();
  entry = akes_nbr_get_receiver_entry();
  p[0] = type;
  p += 1;

  /* Source Address */
  memcpy(p, linkaddr_node_addr.u8, LINKADDR_SIZE);
  p += LINKADDR_SIZE;

  /* Frame Counter */
#if LLSEC802154_USES_AUX_HEADER
  write_frame_counter(p);
  p += 4;
#else /* LLSEC802154_USES_AUX_HEADER */
  p[0] = (uint8_t) packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
  p += 1;
#endif /* LLSEC802154_USES_AUX_HEADER */

  /* OTP */
  switch(type) {
  case POTR_FRAME_TYPE_HELLOACK:
  case POTR_FRAME_TYPE_HELLOACK_P:
    if(!entry || !entry->tentative) {
      PRINTF("potr: Could not create HELLOACK OTP\n");
      return FRAMER_FAILED;
    }
    memcpy(p, entry->tentative->otp.u8, POTR_OTP_LEN);
    /* create ACK OTP */
    potr_create_special_otp(&entry->tentative->otp,
        packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
        ((uint8_t *) packetbuf_dataptr()) + 1);
    break;
  case POTR_FRAME_TYPE_ACK:
    if(!entry || !entry->permanent) {
      PRINTF("potr: Could not create ACK OTP\n");
      return FRAMER_FAILED;
    }
    memcpy(p, entry->permanent->otp.u8, POTR_OTP_LEN);
    break;
  default:
    create_normal_otp(p, adaptivesec_group_key);
    break;
  }
  p += POTR_OTP_LEN;

#if WITH_AUTHENTIC_ACKNOWLEDGEMENTS
  /* Strobe Index */
  if(shall_send_acknowledgement(type)) {
    p[0] = 0;
  }
#endif /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */

  return length_of(type);
}
/*---------------------------------------------------------------------------*/
void
potr_clear_cached_otps(void)
{
  cached_otps_index = 0;
}
/*---------------------------------------------------------------------------*/
int
potr_parse_and_validate(void)
{
  uint8_t *p;
  enum potr_frame_type type;
  linkaddr_t addr;
  struct akes_nbr_entry *entry;
  potr_otp_t otp;
  uint8_t i;

  p = packetbuf_hdrptr();
  type = p[0];

  /* Frame Length */
#if WITH_CONTIKIMAC_FRAMER
  if(packetbuf_datalen() < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE) {
#else /* WITH_CONTIKIMAC_FRAMER */
  if(packetbuf_datalen() <= length_of(type)) {
#endif /* WITH_CONTIKIMAC_FRAMER */
    PRINTF("potr: invalid length\n");
    return FRAMER_FAILED;
  }

  /* Frame Type */
  if(type <= POTR_FRAME_TYPE_ACK) {
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_node_addr);
  } else if(type <= POTR_FRAME_TYPE_HELLO) {
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_null);
  } else {
    PRINTF("potr: unknown frame type %02x\n", type);
    return FRAMER_FAILED;
  }
  switch(type) {
  case POTR_FRAME_TYPE_BROADCAST_DATA:
  case POTR_FRAME_TYPE_UNICAST_DATA:
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
    break;
  default:
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_CMDFRAME);
    break;
  }
  p += 1;

  /* Source Address */
  memcpy(addr.u8, p, LINKADDR_SIZE);
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &addr);
  entry = akes_nbr_get_sender_entry();
  p += LINKADDR_SIZE;

  /* Frame Counter */
#if LLSEC802154_USES_AUX_HEADER
  anti_replay_parse_counter(p);
  p += 4;
#else /* LLSEC802154_USES_AUX_HEADER */
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, p[0]);
  p += 1;
#endif /* LLSEC802154_USES_AUX_HEADER */
#if ANTI_REPLAY_WITH_SUPPRESSION
  if(entry && entry->permanent) {
    anti_replay_restore_counter(&entry->permanent->anti_replay_info);
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */

  /* OTP */
  switch(type) {
  case POTR_FRAME_TYPE_HELLOACK:
  case POTR_FRAME_TYPE_HELLOACK_P:
    if(cached_otps_index >= MAX_CACHED_OTPS) {
      PRINTF("potr: Too many HELLOACK OTPs cached\n");
      return FRAMER_FAILED;
    }

    /* create HELLOACK OTP */
    potr_create_special_otp(&cached_otps[cached_otps_index],
        packetbuf_addr(PACKETBUF_ADDR_SENDER),
        akes_hello_challenge);
    read_otp();
    if(memcmp(cached_otps[cached_otps_index].u8, p, POTR_OTP_LEN)) {
      PRINTF("potr: Invalid HELLOACK OTP\n");
      return FRAMER_FAILED;
    }

    for(i = 0; i < cached_otps_index; i++) {
      if(!memcmp(cached_otps[i].u8, cached_otps[cached_otps_index].u8, POTR_OTP_LEN)) {
        PRINTF("potr: Replayed HELLOACK OTP\n");
        return FRAMER_FAILED;
      }
    }

    cached_otps_index++;
    break;
  case POTR_FRAME_TYPE_ACK:
    read_otp();
    if(!akes_is_acceptable_ack(entry)) {
      PRINTF("potr: Unacceptable ACK\n");
      return FRAMER_FAILED;
    } else if(memcmp(entry->tentative->otp.u8, p, POTR_OTP_LEN)) {
      PRINTF("potr: Invalid ACK OTP\n");
      return FRAMER_FAILED;
    } else {
      /* TODO prevent replay */
    }
    break;
  case POTR_FRAME_TYPE_HELLO:
    if((packetbuf_totlen() != HELLO_LEN)
        || !akes_is_acceptable_hello(entry)) {
      PRINTF("potr: Rejected HELLO\n");
      return FRAMER_FAILED;
    }
    /* intentionally no break; */
  default:
    if(!entry || !entry->permanent) {
      if(type == POTR_FRAME_TYPE_HELLO) {
        read_otp();
        break;
      }
      PRINTF("potr: Sender is not permanent\n");
      return FRAMER_FAILED;
    }

    create_normal_otp(otp.u8, entry->permanent->group_key);
    read_otp();
    if(memcmp(otp.u8, p, POTR_OTP_LEN)) {
      if(type == POTR_FRAME_TYPE_HELLO) {
        break;
      }
      PRINTF("potr: Invalid OTP\n");
      return FRAMER_FAILED;
    }
    if(anti_replay_was_replayed(&entry->permanent->anti_replay_info)) {
      PRINTF("potr: Replayed OTP\n");
      return FRAMER_FAILED;
    }
    break;
  }

  return length_of(type);
}
/*---------------------------------------------------------------------------*/
extern int cc2538_rf_read_payload(uint8_t bytes);
static void
read_otp(void)
{
  cc2538_rf_read_payload(POTR_OTP_LEN);
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  enum potr_frame_type type;

  type = ((uint8_t *) packetbuf_hdrptr())[0];
  if(!packetbuf_hdrreduce(length_of(type))) {
    PRINTF("potr: packetbuf_hdrreduce failed\n");
    return FRAMER_FAILED;
  }

#if WITH_AUTHENTIC_ACKNOWLEDGEMENTS
  if(shall_send_acknowledgement(type)) {
    uint8_t *dataptr = packetbuf_dataptr();
    /* Strobe Index */
    dataptr[-1] = 0;
  }
#endif /* WITH_AUTHENTIC_ACKNOWLEDGEMENTS */

  return length_of(type);
}
/*---------------------------------------------------------------------------*/
int
potr_shall_send_acknowledgement(void)
{
  return shall_send_acknowledgement(((uint8_t *) packetbuf_hdrptr())[0]);
}
/*---------------------------------------------------------------------------*/
const struct framer potr_framer = {
  length,
  create,
  parse
};
/*---------------------------------------------------------------------------*/
#endif /* POTR_ENABLED */
