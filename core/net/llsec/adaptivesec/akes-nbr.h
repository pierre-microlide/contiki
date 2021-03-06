/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 *         Neighbor management.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AKES_NBR_H_
#define AKES_NBR_H_

#include "net/llsec/anti-replay.h"
#include "net/linkaddr.h"
#include "net/nbr-table.h"
#include "lib/aes-128.h"
#include "sys/clock.h"
#include "sys/ctimer.h"
#include "net/llsec/adaptivesec/potr.h"
#include "net/mac/contikimac/secrdc.h"

#ifdef AKES_NBR_CONF_MAX_TENTATIVES
#define AKES_NBR_MAX_TENTATIVES         AKES_NBR_CONF_MAX_TENTATIVES
#else /* AKES_NBR_CONF_MAX_TENTATIVES */
#define AKES_NBR_MAX_TENTATIVES         5
#endif /* AKES_NBR_CONF_MAX_TENTATIVES */

#ifdef AKES_NBR_CONF_MAX
#define AKES_NBR_MAX                    AKES_NBR_CONF_MAX
#else /* AKES_NBR_CONF_MAX */
#define AKES_NBR_MAX                    (NBR_TABLE_MAX_NEIGHBORS + 1)
#endif /* AKES_NBR_CONF_MAX */

#ifdef AKES_NBR_CONF_KEY_LEN
#define AKES_NBR_KEY_LEN                AKES_NBR_CONF_KEY_LEN
#else /* AKES_NBR_CONF_KEY_LEN */
#define AKES_NBR_KEY_LEN                AES_128_KEY_LENGTH
#endif /* AKES_NBR_CONF_KEY_LEN */

#ifdef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_WITH_PAIRWISE_KEYS     AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#else /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */
#define AKES_NBR_WITH_PAIRWISE_KEYS     0
#endif /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */

#ifdef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_WITH_GROUP_KEYS        AKES_NBR_CONF_WITH_GROUP_KEYS
#else /* AKES_NBR_CONF_WITH_GROUP_KEYS */
#define AKES_NBR_WITH_GROUP_KEYS        1
#endif /* AKES_NBR_CONF_WITH_GROUP_KEYS */

#ifdef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_WITH_INDICES           AKES_NBR_CONF_WITH_INDICES
#else /* AKES_NBR_CONF_WITH_INDICES */
#define AKES_NBR_WITH_INDICES           ANTI_REPLAY_WITH_SUPPRESSION
#endif /* AKES_NBR_CONF_WITH_INDICES */

#ifndef AKES_NBR_CONF_WITH_LOCKING
#define AKES_NBR_CONF_WITH_LOCKING 0
#endif /* AKES_NBR_CONF_WITH_LOCKING */
#if AKES_NBR_CONF_WITH_LOCKING
volatile int akes_nbr_locked;
#define AKES_NBR_GET_LOCK()             akes_nbr_locked++
#define AKES_NBR_RELEASE_LOCK()         akes_nbr_locked--
#else /* AKES_NBR_CONF_WITH_LOCKING */
#define AKES_NBR_GET_LOCK()
#define AKES_NBR_RELEASE_LOCK()
#endif /* AKES_NBR_CONF_WITH_LOCKING */

#define AKES_NBR_CHALLENGE_LEN          8

enum akes_nbr_status {
  AKES_NBR_PERMANENT = 0,
  /** HELLO received */
  AKES_NBR_TENTATIVE,
  /** HELLOACK sent */
  AKES_NBR_TENTATIVE_AWAITING_ACK
};

struct akes_nbr_entry {
#if AKES_NBR_WITH_INDICES
  uint8_t local_index;
#endif /* AKES_NBR_WITH_INDICES */
  union {
    struct akes_nbr *refs[AKES_NBR_TENTATIVE_AWAITING_ACK];
    struct {
      struct akes_nbr *permanent;
      struct akes_nbr *tentative;
    };
  };
};

struct akes_nbr {
  struct anti_replay_info anti_replay_info;
  clock_time_t expiration_time;
  uint8_t sent_authentic_hello;
#if POTR_ENABLED
  potr_otp_t otp;
#endif /* POTR_ENABLED */
#if SECRDC_ENABLED && SECRDC_WITH_PHASE_LOCK
  struct secrdc_phase phase;
#endif /* SECRDC_ENABLED && SECRDC_WITH_PHASE_LOCK */

  union {
    /* permanent */
    struct {
#if AKES_NBR_WITH_PAIRWISE_KEYS
      uint8_t pairwise_key[AKES_NBR_KEY_LEN];
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
#if AKES_NBR_WITH_GROUP_KEYS
      uint8_t group_key[AKES_NBR_KEY_LEN];
#endif /* AKES_NBR_WITH_GROUP_KEYS */
#if ANTI_REPLAY_WITH_SUPPRESSION
      uint8_t last_was_broadcast;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if AKES_NBR_WITH_INDICES
      uint8_t foreign_index;
#endif /* AKES_NBR_WITH_INDICES */
    };

    /* tentative */
    struct {
      union {
        struct {
          uint8_t challenge[AKES_NBR_CHALLENGE_LEN];
          struct ctimer wait_timer;
        };

        struct {
          uint8_t tentative_pairwise_key[AKES_NBR_KEY_LEN];
        };
      };

      enum akes_nbr_status status;
    };
  };
};

void akes_nbr_copy_challenge(uint8_t *dest, uint8_t *source);
void akes_nbr_copy_key(uint8_t *dest, uint8_t *source);
linkaddr_t *akes_nbr_get_addr(struct akes_nbr_entry *entry);
struct akes_nbr_entry *akes_nbr_head(void);
struct akes_nbr_entry *akes_nbr_next(struct akes_nbr_entry *current);
int akes_nbr_count(enum akes_nbr_status status);
int akes_nbr_free_slots(void);
struct akes_nbr_entry *akes_nbr_new(enum akes_nbr_status status);
void akes_nbr_update(struct akes_nbr *nbr, uint8_t *data, int with_group_key);
void akes_nbr_do_prolong(struct akes_nbr *nbr, uint16_t seconds);
void akes_nbr_prolong(struct akes_nbr *nbr);
struct akes_nbr_entry *akes_nbr_get_sender_entry(void);
struct akes_nbr_entry *akes_nbr_get_receiver_entry(void);
void akes_nbr_delete(struct akes_nbr_entry *entry, enum akes_nbr_status status);
int akes_nbr_is_expired(struct akes_nbr *nbr);
void akes_nbr_delete_expired_tentatives(void);
void akes_nbr_init(void);

#endif /* AKES_NBR_H_ */
